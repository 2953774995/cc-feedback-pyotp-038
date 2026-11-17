"""Tests for pyotp.audit: batch verification, replay protection and drift."""

from __future__ import annotations

import base64
import time
import unittest

import pyotp
from pyotp import audit

# 160-bit secrets: the library enforces a 112-bit minimum (NIST SP 800-63B-4).
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
OTHER_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def code(secret: str = SECRET, at: int | None = None, offset: int = 0, digits: int = 6) -> str:
    return pyotp.TOTP(secret, digits=digits).at(at, counter_offset=offset)


class MemoryNonceStore:
    def __init__(self) -> None:
        self.keys: set[tuple[object, int]] = set()

    def seen(self, key: tuple[object, int]) -> bool:
        return key in self.keys

    def mark(self, key: tuple[object, int]) -> None:
        self.keys.add(key)


class VerifyBatchTest(unittest.TestCase):
    NOW = 1_700_000_000

    def verify(self, entries, **kwargs):
        kwargs.setdefault("at", self.NOW)
        return audit.verify_batch(entries, **kwargs)

    def test_success_items_and_fields(self):
        entries = [{"secret": SECRET, "code": code(at=self.NOW), "user_id": f"u{i}"} for i in range(3)]
        out = self.verify(entries)
        self.assertEqual(len(out.items), 3)
        for index, item in enumerate(out.items):
            self.assertEqual(item.index, index)
            self.assertTrue(item.ok)
            self.assertEqual(item.reason, "ok")
            self.assertEqual(item.offset, 0)
            # Mapping-style access is supported for convenience.
            self.assertEqual(item["reason"], "ok")
            self.assertIn("offset", item)
            self.assertIsNone(item.get("missing"))

    def test_window_offsets(self):
        prev_code = code(at=self.NOW, offset=-1)
        next_code = code(at=self.NOW, offset=1)
        self.assertEqual(self.verify([{"secret": SECRET, "code": prev_code}]).items[0].offset, -1)
        self.assertEqual(self.verify([{"secret": SECRET, "code": next_code}]).items[0].offset, 1)
        self.assertFalse(self.verify([{"secret": SECRET, "code": next_code}], window=0).items[0].ok)
        self.assertTrue(self.verify([{"secret": SECRET, "code": code(at=self.NOW)}], window=0).items[0].ok)
        far = self.verify([{"secret": SECRET, "code": code(at=self.NOW, offset=-3)}], window=3)
        self.assertEqual(far.items[0].offset, -3)

    def test_window_validation(self):
        with self.assertRaises(ValueError):
            audit.verify_batch([], window=-1)
        with self.assertRaises(ValueError):
            audit.estimate_drift(SECRET, code(at=self.NOW), at=self.NOW, window=-1)

    def test_wrong_code_and_out_of_window(self):
        out = self.verify([{"secret": SECRET, "code": code(OTHER_SECRET, self.NOW)}])
        self.assertEqual(out.items[0].reason, "wrong_code")
        self.assertIsNone(out.items[0].offset)

        far = self.verify([{"secret": SECRET, "code": code(at=self.NOW, offset=6)}])
        self.assertFalse(far.items[0].ok)
        self.assertEqual(far.items[0].reason, "expired_window")
        self.assertIsNone(far.items[0].offset)

        # Beyond the drift scan horizon it is indistinguishable from a wrong code.
        hopeless = self.verify([{"secret": SECRET, "code": code(at=self.NOW, offset=99)}])
        self.assertEqual(hopeless.items[0].reason, "wrong_code")

    def test_replay(self):
        store = MemoryNonceStore()
        entry = {"secret": SECRET, "code": code(at=self.NOW), "user_id": "u1"}
        first = self.verify([entry], nonce_store=store)
        self.assertEqual(first.items[0].reason, "ok")
        self.assertEqual(store.keys, {("u1", pyotp.TOTP(SECRET).timecode(self.NOW))})

        second = self.verify([entry], nonce_store=store)
        self.assertEqual(second.items[0].reason, "replay")
        self.assertFalse(second.items[0].ok)
        # The replay still reports which step it collided on.
        self.assertEqual(second.items[0].offset, 0)
        self.assertEqual(second.stats["ok"], 0)

    def test_replay_is_scoped_by_user_and_step(self):
        store = MemoryNonceStore()
        entry = {"secret": SECRET, "code": code(at=self.NOW), "user_id": "u1"}
        self.assertTrue(self.verify([entry], nonce_store=store).items[0].ok)
        other_user = dict(entry, user_id="u2")
        self.assertTrue(self.verify([other_user], nonce_store=store).items[0].ok)
        # Next time step is a new nonce for the same user.
        next_step = {"secret": SECRET, "code": code(at=self.NOW, offset=1), "user_id": "u1"}
        self.assertTrue(self.verify([next_step], nonce_store=store).items[0].ok)

    def test_replay_key_falls_back_to_secret(self):
        store = MemoryNonceStore()
        entry = {"secret": SECRET, "code": code(at=self.NOW)}
        self.assertTrue(self.verify([entry], nonce_store=store).items[0].ok)
        self.assertEqual(store.keys, {(SECRET, pyotp.TOTP(SECRET).timecode(self.NOW))})
        self.assertEqual(self.verify([entry], nonce_store=store).items[0].reason, "replay")

    def test_duplicate_entries_within_one_batch(self):
        store = MemoryNonceStore()
        entry = {"secret": SECRET, "code": code(at=self.NOW), "user_id": "u1"}
        out = self.verify([entry, entry], nonce_store=store)
        self.assertEqual([item.reason for item in out.items], ["ok", "replay"])

    def test_failed_entries_are_not_marked(self):
        store = MemoryNonceStore()
        self.verify([{"secret": SECRET, "code": "000000", "user_id": "u1"}], nonce_store=store)
        self.verify([{"secret": "BAD", "code": "123456", "user_id": "u2"}], nonce_store=store)
        self.assertEqual(store.keys, set())

    def test_code_normalization(self):
        raw = code(at=self.NOW)
        spaced = f"{raw[:3]} {raw[3:]}"
        hyphened = f"{raw[:3]}-{raw[3:]}"
        for candidate in (raw, spaced, hyphened, f" {raw} ", raw.zfill(8)):
            with self.subTest(candidate=candidate):
                out = self.verify([{"secret": SECRET, "code": candidate}])
                self.assertTrue(out.items[0].ok, out.items[0])

    def test_fullwidth_digits_fold_to_ascii(self):
        wide = str.maketrans("0123456789", "０１２３４５６７８９")
        out = self.verify([{"secret": SECRET, "code": code(at=self.NOW).translate(wide)}])
        self.assertTrue(out.items[0].ok, out.items[0])

    def test_eight_digit_otp(self):
        eight = code(at=self.NOW, digits=8)
        out = self.verify([{"secret": SECRET, "code": eight}])
        self.assertTrue(out.items[0].ok, out.items[0])
        self.assertEqual(out.items[0].offset, 0)

    def test_malformed_codes(self):
        for candidate in ("abcdef", "12345", "1234567", "123 456 7", "12345O", "", None, 123456):
            with self.subTest(candidate=candidate):
                out = self.verify([{"secret": SECRET, "code": candidate}])
                self.assertEqual(out.items[0].reason, "malformed")
                self.assertFalse(out.items[0].ok)
                self.assertIsNone(out.items[0].offset)

    def test_bad_secret_does_not_abort_batch(self):
        entries = [
            {"secret": "NOT-BASE32-@@", "code": "123456"},
            {"secret": "BAD", "code": "123456"},
            {"secret": None, "code": "123456"},
            {"secret": SECRET, "code": code(at=self.NOW)},
        ]
        out = self.verify(entries)
        self.assertEqual(
            [item.reason for item in out.items], ["bad_secret", "bad_secret", "bad_secret", "ok"]
        )
        self.assertEqual([item.index for item in out.items], [0, 1, 2, 3])

    def test_stats(self):
        entries = [
            {"secret": SECRET, "code": code(at=self.NOW)},
            {"secret": SECRET, "code": code(OTHER_SECRET, self.NOW)},
            {"secret": "BAD", "code": "123456"},
        ]
        stats = self.verify(entries).stats
        self.assertEqual(stats["ok"], 1)
        self.assertEqual(stats["bad"], 2)
        self.assertEqual(stats["by_reason"], {"ok": 1, "wrong_code": 1, "bad_secret": 1})
        self.assertEqual(stats["by_offset"], {0: 1})

    def test_stats_count_offsets(self):
        entries = [
            {"secret": SECRET, "code": code(at=self.NOW)},
            {"secret": SECRET, "code": code(at=self.NOW, offset=-1), "user_id": "a"},
            {"secret": SECRET, "code": code(at=self.NOW, offset=1), "user_id": "b"},
        ]
        stats = self.verify(entries).stats
        self.assertEqual(stats["by_offset"], {0: 1, -1: 1, 1: 1})

    def test_empty_input(self):
        out = self.verify([])
        self.assertEqual(out.items, [])
        self.assertEqual(out.stats["ok"], 0)
        self.assertEqual(out.stats["bad"], 0)
        self.assertEqual(out.stats["by_reason"], {})
        self.assertEqual(out.stats["by_offset"], {})

    def test_at_defaults_to_now(self):
        out = audit.verify_batch([{"secret": SECRET, "code": pyotp.TOTP(SECRET).now()}])
        self.assertTrue(out.items[0].ok, out.items[0])

    def test_at_accepts_datetime(self):
        import datetime

        at = datetime.datetime.fromtimestamp(self.NOW, datetime.timezone.utc)
        out = audit.verify_batch([{"secret": SECRET, "code": code(at=self.NOW)}], at=at)
        self.assertTrue(out.items[0].ok, out.items[0])

    def test_non_mapping_entry_is_malformed(self):
        out = self.verify([None, "nope"])  # type: ignore[list-item]
        self.assertEqual([item.reason for item in out.items], ["malformed", "malformed"])

    def test_large_batch_is_linear_enough(self):
        entries = [{"secret": SECRET, "code": code(at=self.NOW), "user_id": f"u{i}"} for i in range(10_000)]
        started = time.perf_counter()
        out = self.verify(entries)
        elapsed = time.perf_counter() - started
        self.assertEqual(out.stats["ok"], 10_000)
        self.assertLess(elapsed, 2.0)


class EstimateDriftTest(unittest.TestCase):
    NOW = 1_700_000_000

    def test_finds_offset(self):
        for offset in (-5, -2, -1, 0, 1, 2, 5):
            with self.subTest(offset=offset):
                drift_code = code(at=self.NOW, offset=offset)
                self.assertEqual(audit.estimate_drift(SECRET, drift_code, at=self.NOW, window=5), offset)

    def test_outside_window_returns_none(self):
        self.assertIsNone(audit.estimate_drift(SECRET, code(at=self.NOW, offset=2), at=self.NOW, window=1))

    def test_no_match_returns_none(self):
        self.assertIsNone(audit.estimate_drift(SECRET, code(OTHER_SECRET, self.NOW), at=self.NOW))
        self.assertIsNone(audit.estimate_drift(SECRET, "000000", at=self.NOW))

    def test_invalid_inputs_return_none(self):
        self.assertIsNone(audit.estimate_drift("BAD", code(at=self.NOW), at=self.NOW))
        self.assertIsNone(audit.estimate_drift(SECRET, "not-a-code", at=self.NOW))

    def test_default_window_is_five(self):
        self.assertEqual(audit.estimate_drift(SECRET, code(at=self.NOW, offset=-5), at=self.NOW), -5)
        self.assertIsNone(audit.estimate_drift(SECRET, code(at=self.NOW, offset=6), at=self.NOW))

    def test_accepts_normalized_code(self):
        raw = code(at=self.NOW, offset=2)
        self.assertEqual(audit.estimate_drift(SECRET, f"{raw[:3]} {raw[3:]}", at=self.NOW), 2)


class NoRegressionTest(unittest.TestCase):
    NOW = 1_700_000_000

    def test_existing_api_unchanged(self):
        totp = pyotp.TOTP(SECRET)
        at_code = totp.at(self.NOW)
        self.assertEqual(at_code, code(at=self.NOW))
        self.assertTrue(totp.verify(at_code, for_time=self.NOW))
        self.assertTrue(totp.verify(at_code, for_time=self.NOW, valid_window=1))
        hotp = pyotp.HOTP(SECRET)
        self.assertTrue(hotp.verify(hotp.at(0), 0))
        self.assertFalse(hotp.verify("000000", 0))

    def test_audit_does_not_touch_repo_state(self):
        raw = code(at=self.NOW)
        self.verify_store = MemoryNonceStore()
        audit.verify_batch([{"secret": SECRET, "code": raw}], at=self.NOW, nonce_store=self.verify_store)
        # Replay state lives only in the caller-provided store.
        self.assertTrue(pyotp.TOTP(SECRET).verify(raw, for_time=self.NOW))

    def test_secret_policy_is_preserved(self):
        short = base64.b32encode(bytes(range(10))).decode("ascii")
        with self.assertRaisesRegex(ValueError, "at least 112 bits after decoding"):
            pyotp.TOTP(short)
        out = audit.verify_batch([{"secret": short, "code": code(at=self.NOW)}], at=self.NOW)
        self.assertEqual(out.items[0].reason, "bad_secret")

    def test_invalid_at_raises(self):
        with self.assertRaises(ValueError):
            audit.verify_batch([{"secret": SECRET, "code": code(at=self.NOW)}], at=-1)


if __name__ == "__main__":
    unittest.main()
