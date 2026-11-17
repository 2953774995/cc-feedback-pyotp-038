"""Batch TOTP verification with replay protection and clock-drift reporting.

This module is a layer on top of :class:`pyotp.totp.TOTP`: the OTP algorithm
(HMAC, dynamic truncation, timecode handling) is reused unchanged, while batch
handling, input classification, replay bookkeeping and drift statistics live
here.

Example::

    from pyotp import audit

    result = audit.verify_batch(
        [{"user_id": "u1", "secret": secret, "code": "123456"}],
        at=now,
        nonce_store=store,  # any object with seen(key) / mark(key)
    )
    result.items[0].reason  # "ok", "wrong_code", "replay", ...
"""

from __future__ import annotations

import datetime
import time
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, Protocol

from . import utils
from .totp import TOTP

#: Classification of a single batch entry.
Reason = Literal["ok", "wrong_code", "bad_secret", "malformed", "replay", "expired_window"]

#: Digit lengths accepted from users. Six digits is the default; an
#: eight-digit entry may either be a genuinely eight-digit OTP or a six-digit
#: OTP that was zero-padded for display.
_CODE_LENGTHS = (6, 8)

#: Refuse absurdly long inputs before normalization (same bound as
#: ``pyotp.utils.strings_equal``).
_MAX_CODE_INPUT = 1024

#: How many steps beyond the accepted window to scan when deciding whether a
#: well-formed, correct code merely arrived too late (``expired_window``).
_DRIFT_SCAN = 5

_TIMESTAMP = int | float | datetime.datetime


class NonceStore(Protocol):
    """Replay ledger interface required by :func:`verify_batch`."""

    def seen(self, key: tuple[Any, int]) -> bool: ...

    def mark(self, key: tuple[Any, int]) -> None: ...


@dataclass
class BatchItem:
    """Outcome for one entry of a :func:`verify_batch` call.

    Items support attribute access (``item.ok``) as well as mapping-style
    access (``item["ok"]``, ``"ok" in item``).
    """

    index: int
    ok: bool
    reason: Reason
    offset: int | None

    _FIELDS: ClassVar[tuple[str, ...]] = ("index", "ok", "reason", "offset")

    def __getitem__(self, key: str) -> Any:
        if key not in self._FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __contains__(self, key: object) -> bool:
        return key in self._FIELDS

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key) if key in self._FIELDS else default

    def keys(self) -> tuple[str, ...]:
        return self._FIELDS


@dataclass
class BatchResult:
    """Result of :func:`verify_batch`: per-entry items plus aggregate stats."""

    items: list[BatchItem] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=lambda: {"ok": 0, "bad": 0, "by_reason": {}, "by_offset": {}})

    _FIELDS: ClassVar[tuple[str, ...]] = ("items", "stats")

    def __getitem__(self, key: str) -> Any:
        if key not in self._FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __contains__(self, key: object) -> bool:
        return key in self._FIELDS

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key) if key in self._FIELDS else default

    def keys(self) -> tuple[str, ...]:
        return self._FIELDS


def _normalize_code(code: object) -> str | None:
    """Strip separators and validate the shape of a user supplied code.

    Whitespace and hyphens are ignored, so codes copied from SMS or formatted
    as ``"123 456"`` / ``"123-456"`` are accepted. Fullwidth digits are folded
    to ASCII (matching the NFKC normalization used by ``TOTP.verify``). Only 6
    or 8 digits are well formed; the value stays a string so leading zeros
    survive.
    """
    if not isinstance(code, str):
        return None
    if len(code) > _MAX_CODE_INPUT:
        return None
    folded = unicodedata.normalize("NFKC", code)
    cleaned = "".join(ch for ch in folded if not ch.isspace() and ch != "-")
    if len(cleaned) not in _CODE_LENGTHS:
        return None
    if not (cleaned.isascii() and cleaned.isdecimal()):
        return None
    return cleaned


def _step_offsets(window: int) -> Iterator[int]:
    """Yield candidate offsets nearest-first: current step, then past, then future."""
    yield 0
    for distance in range(1, window + 1):
        yield -distance
        yield distance


class _SecretCache:
    """Cache TOTP handlers, including construction failures, per secret."""

    def __init__(self) -> None:
        self._handlers: dict[Any, TOTP | None] = {}
        self._eight_digit: dict[Any, TOTP | None] = {}

    @staticmethod
    def _build(secret: Any, digits: int) -> TOTP | None:
        try:
            return TOTP(secret, digits=digits)
        except (ValueError, TypeError):
            # Non-Base32, under-length or otherwise unusable secrets are a
            # per-entry failure, never a batch failure.
            return None

    def get(self, secret: Any) -> TOTP | None:
        try:
            return self._handlers[secret]
        except (KeyError, TypeError):
            pass
        handler = self._build(secret, 6)
        try:
            self._handlers[secret] = handler
        except TypeError:  # unhashable secret; still usable this once
            pass
        return handler

    def get_eight_digit(self, secret: Any) -> TOTP | None:
        try:
            return self._eight_digit[secret]
        except (KeyError, TypeError):
            pass
        handler = self._build(secret, 8)
        try:
            self._eight_digit[secret] = handler
        except TypeError:
            pass
        return handler


def _matches(handler: TOTP, code: str, timecode: int, cache: _SecretCache, secret: Any) -> bool:
    """Check one timecode against the TOTP HMAC output.

    Six-digit codes compare directly. Eight-digit codes are compared both as a
    zero-padded six-digit code and against a native eight-digit TOTP.
    """
    if timecode < 0:  # generate_otp rejects negative counters
        return False
    generated = handler.generate_otp(timecode)
    if len(code) == 6:
        return utils.strings_equal(code, generated)
    if utils.strings_equal(code, generated.zfill(8)):
        return True
    native = cache.get_eight_digit(secret)
    return native is not None and utils.strings_equal(code, native.generate_otp(timecode))


def _find_match(
    code: str, handler: TOTP, base_timecode: int, window: int, cache: _SecretCache, secret: Any
) -> int | None:
    for offset in _step_offsets(window):
        if _matches(handler, code, base_timecode + offset, cache, secret):
            return offset
    return None


def _find_out_of_window(
    code: str, handler: TOTP, base_timecode: int, window: int, cache: _SecretCache, secret: Any
) -> bool:
    """Look just outside the accepted window for a code that is simply late."""
    for distance in range(window + 1, window + _DRIFT_SCAN + 1):
        for offset in (-distance, distance):
            if _matches(handler, code, base_timecode + offset, cache, secret):
                return True
    return False


def verify_batch(
    entries: Iterable[Mapping[str, Any]],
    at: _TIMESTAMP | None = None,
    window: int = 1,
    nonce_store: NonceStore | None = None,
) -> BatchResult:
    """Verify a batch of TOTP submissions.

    Each entry is a mapping with ``secret`` (Base32), ``code`` (6 or 8 digits;
    whitespace and hyphens allowed) and an optional ``user_id``. One bad entry
    never aborts the batch.

    :param entries: submissions to verify
    :param at: time to verify at (defaults to now)
    :param window: accept the current time step plus/minus this many steps.
        Defaults to 1; must not be negative.
    :param nonce_store: optional replay ledger with ``seen(key)`` / ``mark(key)``.
        Keys are ``(user_id or secret, time step)``; successful entries are marked.
    :returns: one :class:`BatchItem` per entry plus aggregate stats
    :raises ValueError: if window is negative
    """
    if window < 0:
        raise ValueError("window cannot be negative")
    if at is None:
        at = time.time()

    cache = _SecretCache()
    items: list[BatchItem] = []
    by_reason: dict[str, int] = {}
    by_offset: dict[int, int] = {}
    ok_count = 0

    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            reason: Reason = "malformed"
            offset: int | None = None
        else:
            secret = entry.get("secret")
            code = _normalize_code(entry.get("code"))
            handler = cache.get(secret)
            offset = None
            if code is None:
                reason = "malformed"
            elif handler is None:
                reason = "bad_secret"
            else:
                base_timecode = handler.timecode(at)
                offset = _find_match(code, handler, base_timecode, window, cache, secret)
                if offset is not None:
                    reason = "ok"
                    if nonce_store is not None:
                        user_id = entry.get("user_id")
                        key = (user_id if user_id is not None else secret, base_timecode + offset)
                        if nonce_store.seen(key):
                            reason = "replay"
                        else:
                            nonce_store.mark(key)
                else:
                    late = _find_out_of_window(code, handler, base_timecode, window, cache, secret)
                    reason = "expired_window" if late else "wrong_code"

        ok = reason == "ok"
        if ok:
            ok_count += 1
            assert offset is not None
            by_offset[offset] = by_offset.get(offset, 0) + 1
        elif reason != "replay":
            # The accepted-step offset is reported for successes and replays;
            # every other outcome has no matched step.
            offset = None
        by_reason[reason] = by_reason.get(reason, 0) + 1
        items.append(BatchItem(index=index, ok=ok, reason=reason, offset=offset))

    return BatchResult(
        items=items,
        stats={
            "ok": ok_count,
            "bad": len(items) - ok_count,
            "by_reason": by_reason,
            "by_offset": by_offset,
        },
    )


def estimate_drift(
    secret: str,
    code: str,
    at: _TIMESTAMP | None = None,
    window: int = 5,
) -> int | None:
    """Return the time-step offset that validates ``code``, or ``None``.

    Intended for flagging devices whose clock is off: ``0`` means in sync,
    negative means the device clock lags, positive means it runs ahead.
    Unusable inputs (bad secret, malformed code) return ``None`` instead of
    raising, so the result can be used purely as a diagnostic.

    :param secret: Base32 secret for the user
    :param code: 6 or 8 digit TOTP submitted by the user
    :param at: time to verify at (defaults to now)
    :param window: how many steps in either direction to search. Defaults to 5.
    :returns: the matched offset, or ``None`` when no step matches
    :raises ValueError: if window is negative
    """
    if window < 0:
        raise ValueError("window cannot be negative")

    normalized = _normalize_code(code)
    if normalized is None:
        return None
    cache = _SecretCache()
    handler = cache.get(secret)
    if handler is None:
        return None
    if at is None:
        at = time.time()
    base_timecode = handler.timecode(at)
    return _find_match(normalized, handler, base_timecode, window, cache, secret)
