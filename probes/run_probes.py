#!/usr/bin/env python3
"""验收探针：批量二次验证与防重放（10 条契约）。

在未实现 `pyotp.audit` 的基线上，10 条全部 FAIL。
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def audit():
    import pyotp.audit as m  # noqa: F401

    return m


SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SECRET2 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def code(secret=SECRET, at=None, offset=0):
    import pyotp

    t = pyotp.TOTP(secret)
    return t.at(at, counter_offset=offset)


@probe("P01 批量入口与成功项结构")
def p01():
    m = audit()
    now = int(time.time())
    entries = [{"secret": SECRET, "code": code(SECRET, now), "user_id": f"u{i}"} for i in range(3)]
    out = m.verify_batch(entries, at=now)
    for key in ("items", "stats"):
        assert hasattr(out, key), f"返回缺 {key}"
    assert len(out.items) == 3, f"应返回 3 条，实际 {len(out.items)}"
    for key in ("index", "ok", "reason", "offset"):
        assert key in out.items[0], f"item 缺字段 {key}"
    assert all(i.ok for i in out.items), "三条正确码应全部通过"
    assert all(i.offset == 0 for i in out.items), f"offset 应为 0，实际 {[i.offset for i in out.items]}"


@probe("P02 时间窗 ±1 与偏移量")
def p02():
    m = audit()
    now = int(time.time())
    prev_code = code(SECRET, now, offset=-1)
    next_code = code(SECRET, now, offset=1)
    out = m.verify_batch([{"secret": SECRET, "code": prev_code}], at=now, window=1)
    assert out.items[0].ok and out.items[0].offset == -1, f"上一步码应 ok 且 offset=-1，实际 {out.items[0]}"
    out2 = m.verify_batch([{"secret": SECRET, "code": next_code}], at=now, window=1)
    assert out2.items[0].ok and out2.items[0].offset == 1, f"下一步码应 ok 且 offset=1，实际 {out2.items[0]}"
    out3 = m.verify_batch([{"secret": SECRET, "code": next_code}], at=now, window=0)
    assert not out3.items[0].ok, "window=0 时下一步码不该通过"


@probe("P03 错误码与窗口外分类")
def p03():
    m = audit()
    now = int(time.time())
    wrong = code(SECRET2, now)
    out = m.verify_batch([{"secret": SECRET, "code": wrong}], at=now, window=1)
    assert out.items[0].reason == "wrong_code", f"应为 wrong_code，实际 {out.items[0].reason}"
    far = code(SECRET, now, offset=6)
    out2 = m.verify_batch([{"secret": SECRET, "code": far}], at=now, window=1)
    assert not out2.items[0].ok, "超出窗口的码不该通过"


@probe("P04 同码同时间步重放")
def p04():
    class Store:
        def __init__(self):
            self.s = set()

        def seen(self, key):
            return key in self.s

        def mark(self, key):
            self.s.add(key)

    m = audit()
    now = int(time.time())
    store = Store()
    entry = {"secret": SECRET, "code": code(SECRET, now), "user_id": "u1"}
    first = m.verify_batch([entry], at=now, nonce_store=store)
    assert first.items[0].reason == "ok", f"首次应为 ok，实际 {first.items[0].reason}"
    second = m.verify_batch([entry], at=now, nonce_store=store)
    assert second.items[0].reason == "replay", f"二次应为 replay，实际 {second.items[0].reason}"
    assert not second.items[0].ok, "重放不得算 ok"


@probe("P05 码格式归一与前导零")
def p05():
    m = audit()
    now = int(time.time())
    raw = code(SECRET, now)
    spaced = f"{raw[:3]} {raw[3:]}"
    out = m.verify_batch([{"secret": SECRET, "code": spaced}], at=now)
    assert out.items[0].ok, f"含空格应被归一后通过，实际 {out.items[0].reason}"
    import pyotp

    eight = pyotp.TOTP(SECRET, digits=8).at(now)
    out2 = m.verify_batch([{"secret": SECRET, "code": eight}], at=now)
    assert out2.items[0].ok, f"8 位前导零应被接受，实际 {out2.items[0].reason}"
    out3 = m.verify_batch([{"secret": SECRET, "code": "abcdef"}], at=now)
    assert out3.items[0].reason == "malformed", f"非数字应为 malformed，实际 {out3.items[0].reason}"


@probe("P06 坏密钥分类且不中断")
def p06():
    m = audit()
    now = int(time.time())
    entries = [
        {"secret": "NOT-BASE32-@@", "code": "123456"},
        {"secret": SECRET, "code": code(SECRET, now)},
    ]
    out = m.verify_batch(entries, at=now)
    assert out.items[0].reason == "bad_secret", f"坏密钥应为 bad_secret，实际 {out.items[0].reason}"
    assert out.items[1].ok, "坏密钥之后的合法条目应继续通过"


@probe("P07 漂移估计")
def p07():
    m = audit()
    now = int(time.time())
    drift_code = code(SECRET, now, offset=2)
    assert m.estimate_drift(SECRET, drift_code, at=now, window=5) == 2, "应识别出 +2 步漂移"
    assert m.estimate_drift(SECRET, "000000", at=now, window=5) is None, "无命中应返回 None"


@probe("P08 统计口径与空输入")
def p08():
    m = audit()
    now = int(time.time())
    entries = [
        {"secret": SECRET, "code": code(SECRET, now)},
        {"secret": SECRET, "code": code(SECRET2, now)},
        {"secret": "BAD", "code": "123456"},
    ]
    out = m.verify_batch(entries, at=now)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 计数不对：{st}"
    assert st["by_reason"].get("wrong_code") == 1, f"by_reason 不对：{st['by_reason']}"
    assert st["by_offset"].get(0) == 1, f"by_offset 不对：{st['by_offset']}"
    empty = m.verify_batch([], at=now)
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"


@probe("P09 window 非法与 at 缺省")
def p09():
    m = audit()
    try:
        m.verify_batch([], window=-1)
    except ValueError:
        pass
    else:
        raise AssertionError("window=-1 应抛 ValueError")
    now = int(time.time())
    out = m.verify_batch([{"secret": SECRET, "code": code(SECRET, now)}])
    assert out.items[0].ok, f"at 缺省时应按当前时间校验，实际 {out.items[0].reason}"


@probe("P10 万级性能与既有 API 不回归")
def p10():
    import pyotp

    m = audit()
    now = int(time.time())
    entries = [{"secret": SECRET, "code": code(SECRET, now), "user_id": f"u{i}"} for i in range(10000)]
    t0 = time.perf_counter()
    out = m.verify_batch(entries, at=now)
    cost = time.perf_counter() - t0
    assert out.stats["ok"] == 10000, f"万条应全部通过，实际 {out.stats['ok']}"
    assert cost < 2.0, f"万条校验耗时 {cost:.2f}s 超过 2s"
    t = pyotp.TOTP(SECRET)
    assert t.verify(t.at(now), for_time=now), "既有 TOTP.verify 被破坏"


def main():
    print("=" * 60)
    print("验收探针：批量二次验证与防重放（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
