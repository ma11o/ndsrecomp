#!/usr/bin/env python3
"""analysis_index_test — pins tools/analysis_index.py's cross-bank
resolution rules against small synthetic fixtures (no dependency on
`generated/` or the recompiler binary, so it can run standalone in CI
before any BIOS/firmware image is available).

Each check builds the minimal bank JSON needed to exercise one rule from
docs/analysis-metadata.md's "Cross-bank index" section, runs the tool as a
subprocess (the same way real callers invoke it), and asserts on stdout /
the written index file.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

TOOL = pathlib.Path(__file__).resolve().parents[1] / "analysis_index.py"

failures = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(name + (": " + detail if detail else ""))


def run(*args, expect_ok=True):
    proc = subprocess.run([sys.executable, str(TOOL), *args],
                           capture_output=True, text=True)
    if expect_ok and proc.returncode != 0:
        raise AssertionError("command failed: %r\nstdout=%s\nstderr=%s" %
                              (args, proc.stdout, proc.stderr))
    return proc


# ── fixture builders ────────────────────────────────────────────────────

def fn(id_, addr, end, name, calls=None, tail_calls=None, indirect=None,
       falls_through_to=None, literals=None, reads=None, writes=None,
       mode="arm"):
    bank = id_.split(":")[0]
    return {
        "id": id_, "addr": addr, "end": end, "mode": mode, "name": name,
        "symbol": bank + "_" + name,
        "reachable_insns": 1, "returns": 1, "undefined_insns": 0,
        "falls_through_to": falls_through_to,
        "calls": calls or [], "tail_calls": tail_calls or [],
        "indirect": indirect or [], "swis": [],
        "reads": reads or [], "writes": writes or [],
        "literals": literals or [], "blocks": [],
        "callers": [],
    }


def call(site, target, target_id=None, mode="arm"):
    return {"site": site, "target": target, "target_mode": mode,
            "target_id": target_id}


def bank(name, cpu, functions, program_id="p", load_address=None, image_size=4096):
    return {
        "schema": "ndsrecomp.analysis/1", "bank": name, "cpu": cpu,
        "program_id": program_id, "program_name": name,
        "image_sha1": "0" * 40,
        "load_address": load_address if load_address is not None else (
            functions[0]["addr"] if functions else "0x00000000"),
        "image_size": image_size, "function_count": len(functions),
        "functions": functions,
    }


def write(dirpath, name, obj):
    p = dirpath / name
    p.write_text(json.dumps(obj))
    return p


# ── the actual checks ───────────────────────────────────────────────────

def test_cross_bank_and_interior_and_same_bank_wins(tmp):
    # bank_a: a function whose call target (0x1000) lives only in bank_b.
    a = bank("bank_a", "arm9", [
        fn("bank_a:0x2000", "0x2000", "0x2008", "caller",
           calls=[call("0x2000", "0x1000")]),
    ])
    b = bank("bank_b", "arm9", [
        fn("bank_b:0x1000", "0x1000", "0x1010", "callee",
           # a call inside callee to an address 4 bytes past callee's own
           # start: exercises the interior-address path, not a function start.
           calls=[call("0x1004", "0x1006")]),
    ])
    pa, pb = write(tmp, "a.json", a), write(tmp, "b.json", b)
    out = tmp / "index.json"
    run("build", str(pa), str(pb), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}

    cross = by_id["bank_a:0x2000"]["calls"][0]
    check("cross-bank resolution", cross.get("target_candidates") ==
          ["bank_b:0x1000"], repr(cross))
    check("cross-bank feeds callers_all", by_id["bank_b:0x1000"]["callers_all"] ==
          ["bank_a:0x2000"])

    interior = by_id["bank_b:0x1000"]["calls"][0]
    check("interior address reported", interior.get("target_interior") ==
          [{"id": "bank_b:0x1000", "offset": 6}], repr(interior))
    check("interior address has no candidates", "target_candidates" not in interior)


def test_same_bank_target_id_wins_over_other_banks(tmp):
    # Two banks both have a function starting at 0x3000 (same cpu): a
    # same-bank call to 0x3000 inside bank_x must resolve to ONLY bank_x's
    # function, never bank_y's, even though bank_y also starts there.
    x = bank("bank_x", "arm9", [
        fn("bank_x:0x3000", "0x3000", "0x3008", "f"),
        fn("bank_x:0x3100", "0x3100", "0x3108", "g",
           calls=[call("0x3100", "0x3000", target_id="bank_x:0x3000")]),
    ])
    y = bank("bank_y", "arm9", [
        fn("bank_y:0x3000", "0x3000", "0x3008", "f"),
    ])
    px, py = write(tmp, "x.json", x), write(tmp, "y.json", y)
    out = tmp / "index.json"
    run("build", str(px), str(py), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["bank_x:0x3100"]["calls"][0]
    check("same-bank target_id wins", c["target_candidates"] == ["bank_x:0x3000"],
          repr(c))
    check("other bank not marked as caller",
          by_id["bank_y:0x3000"]["callers_all"] == [])


def test_arm9_arm7_isolation(tmp):
    # Same numeric address in both CPUs' banks must never cross-resolve.
    a9 = bank("game_arm9", "arm9", [
        fn("game_arm9:0x9000", "0x9000", "0x9008", "caller",
           calls=[call("0x9000", "0x9100")]),
    ])
    a7 = bank("game_arm7", "arm7", [
        fn("game_arm7:0x9100", "0x9100", "0x9108", "decoy"),
    ])
    p9, p7 = write(tmp, "a9.json", a9), write(tmp, "a7.json", a7)
    out = tmp / "index.json"
    run("build", str(p9), str(p7), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["game_arm9:0x9000"]["calls"][0]
    check("no cross-CPU resolution", "target_candidates" not in c, repr(c))
    check("no cross-CPU interior either", "target_interior" not in c, repr(c))


def test_overlay_ambiguity(tmp):
    # Two overlay banks resident at the same address at different times: a
    # third bank's call to that address must list BOTH as candidates and
    # land in callers_ambiguous on both, never callers_all.
    ov1 = bank("overlay1", "arm9", [
        fn("overlay1:0x4000", "0x4000", "0x4008", "init"),
    ])
    ov2 = bank("overlay2", "arm9", [
        fn("overlay2:0x4000", "0x4000", "0x4008", "init"),
    ])
    main = bank("main", "arm9", [
        fn("main:0x5000", "0x5000", "0x5008", "loader",
           calls=[call("0x5000", "0x4000")]),
    ])
    p1, p2, pm = (write(tmp, "ov1.json", ov1), write(tmp, "ov2.json", ov2),
                  write(tmp, "main.json", main))
    out = tmp / "index.json"
    run("build", str(p1), str(p2), str(pm), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["main:0x5000"]["calls"][0]
    check("two overlay candidates", c.get("target_candidates") ==
          ["overlay1:0x4000", "overlay2:0x4000"], repr(c))
    check("ov1 caller is ambiguous, not certain",
          by_id["overlay1:0x4000"]["callers_ambiguous"] == ["main:0x5000"] and
          by_id["overlay1:0x4000"]["callers_all"] == [])
    check("ov2 caller is ambiguous, not certain",
          by_id["overlay2:0x4000"]["callers_ambiguous"] == ["main:0x5000"] and
          by_id["overlay2:0x4000"]["callers_all"] == [])


def test_coresident_exclusion_to_zero(tmp):
    # ovA and ovB occupy the identical image range: they can never both be
    # resident, so ovA can never actually reach into ovB. ovB is the only
    # bank defining the target address, so the candidate list must end up
    # empty rather than reporting an impossible call.
    ova = bank("ovA", "arm9", [
        fn("ovA:0x4100", "0x4100", "0x4108", "caller",
           calls=[call("0x4100", "0x4200")]),
    ], load_address="0x4000", image_size=0x1000)
    ovb = bank("ovB", "arm9", [
        fn("ovB:0x4200", "0x4200", "0x4208", "callee"),
    ], load_address="0x4000", image_size=0x1000)
    pa, pb = write(tmp, "ovA.json", ova), write(tmp, "ovB.json", ovb)
    out = tmp / "index.json"
    run("build", str(pa), str(pb), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["ovA:0x4100"]["calls"][0]
    check("no candidates after full exclusion", "target_candidates" not in c,
          repr(c))
    check("excluded_not_coresident names the dropped bank's function",
          c.get("excluded_not_coresident") == ["ovB:0x4200"], repr(c))
    check("excluded candidate is not a certain caller",
          by_id["ovB:0x4200"]["callers_all"] == [])
    check("excluded candidate is not even an ambiguous caller",
          by_id["ovB:0x4200"]["callers_ambiguous"] == [])


def test_coresident_no_exclusion_for_non_overlapping_source(tmp):
    # Same shape as the overlay-ambiguity check, but with explicit
    # non-overlapping ranges: main doesn't overlap either overlay, so both
    # stay candidates (ambiguous) and nothing is excluded.
    ov1 = bank("cov1", "arm9", [
        fn("cov1:0x4000", "0x4000", "0x4008", "init"),
    ], load_address="0x4000", image_size=0x1000)
    ov2 = bank("cov2", "arm9", [
        fn("cov2:0x4000", "0x4000", "0x4008", "init"),
    ], load_address="0x4000", image_size=0x1000)
    main = bank("cmain", "arm9", [
        fn("cmain:0x9000", "0x9000", "0x9008", "loader",
           calls=[call("0x9000", "0x4000")]),
    ], load_address="0x9000", image_size=0x1000)
    p1, p2, pm = (write(tmp, "cov1.json", ov1), write(tmp, "cov2.json", ov2),
                  write(tmp, "cmain.json", main))
    out = tmp / "index.json"
    run("build", str(p1), str(p2), str(pm), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["cmain:0x9000"]["calls"][0]
    check("both overlay candidates kept when source overlaps neither",
          c.get("target_candidates") == ["cov1:0x4000", "cov2:0x4000"], repr(c))
    check("nothing excluded", "excluded_not_coresident" not in c, repr(c))


def test_coresident_mixed_overlap_and_nonoverlap(tmp):
    # ovA's call target is defined both by ovB (overlaps ovA — impossible)
    # and by bankC (does not overlap ovA — the real target). Exactly one
    # candidate must remain, and it must be the certain caller.
    ova = bank("ovAm", "arm9", [
        fn("ovAm:0x4100", "0x4100", "0x4108", "caller",
           calls=[call("0x4100", "0x4300")]),
    ], load_address="0x4000", image_size=0x1000)
    ovb = bank("ovBm", "arm9", [
        fn("ovBm:0x4300", "0x4300", "0x4308", "decoy"),
    ], load_address="0x4000", image_size=0x1000)  # overlaps ovAm
    bankc = bank("bankC", "arm9", [
        fn("bankC:0x4300", "0x4300", "0x4308", "real"),
    ], load_address="0x9000", image_size=0x1000)  # does not overlap ovAm
    pa, pb, pc = (write(tmp, "ovAm.json", ova), write(tmp, "ovBm.json", ovb),
                  write(tmp, "bankC.json", bankc))
    out = tmp / "index.json"
    run("build", str(pa), str(pb), str(pc), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["ovAm:0x4100"]["calls"][0]
    check("only the non-overlapping bank remains a candidate",
          c.get("target_candidates") == ["bankC:0x4300"], repr(c))
    check("overlapping bank listed as excluded",
          c.get("excluded_not_coresident") == ["ovBm:0x4300"], repr(c))
    check("non-overlapping bank is a certain caller",
          by_id["bankC:0x4300"]["callers_all"] == ["ovAm:0x4100"])
    check("overlapping bank is not any kind of caller",
          by_id["ovBm:0x4300"]["callers_all"] == [] and
          by_id["ovBm:0x4300"]["callers_ambiguous"] == [])

    # Co-residency filtering must stay order-independent like everything else.
    out2 = tmp / "index_swapped.json"
    run("build", str(pc), str(pa), str(pb), "--out", str(out2))
    check("co-residency filtering is order-independent",
          out.read_bytes() == out2.read_bytes())


def test_coresident_touching_ranges_not_excluded(tmp):
    # Half-open ranges that touch (one's end equals the other's start) are
    # adjacent, not overlapping — e.g. two images placed back to back can
    # both be resident, so nothing here should be filtered.
    left = bank("left_bank", "arm9", [
        fn("left_bank:0x100", "0x100", "0x108", "caller",
           calls=[call("0x100", "0x1000")]),
    ], load_address="0x000", image_size=0x1000)  # [0x000, 0x1000)
    right = bank("right_bank", "arm9", [
        fn("right_bank:0x1000", "0x1000", "0x1008", "callee"),
    ], load_address="0x1000", image_size=0x1000)  # [0x1000, 0x2000)
    pl, pr = write(tmp, "left.json", left), write(tmp, "right.json", right)
    out = tmp / "index.json"
    run("build", str(pl), str(pr), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["left_bank:0x100"]["calls"][0]
    check("touching ranges are not treated as overlapping",
          c.get("target_candidates") == ["right_bank:0x1000"], repr(c))
    check("nothing excluded for touching ranges",
          "excluded_not_coresident" not in c, repr(c))


def test_coresident_interior_filtered(tmp):
    # An interior hit (not at a function's start) inside an overlapping
    # bank's body must be dropped the same way an exact hit is; a surviving
    # interior hit in a non-overlapping bank stays and reports its offset.
    ova = bank("ovAi", "arm9", [
        fn("ovAi:0x4100", "0x4100", "0x4108", "caller",
           calls=[call("0x4100", "0x4306")]),  # +6 into the bodies below
    ], load_address="0x4000", image_size=0x1000)
    ovb = bank("ovBi", "arm9", [
        fn("ovBi:0x4300", "0x4300", "0x4310", "decoy_body"),
    ], load_address="0x4000", image_size=0x1000)  # overlaps ovAi
    bankc = bank("bankCi", "arm9", [
        fn("bankCi:0x4300", "0x4300", "0x4310", "real_body"),
    ], load_address="0x9000", image_size=0x1000)  # does not overlap ovAi
    pa, pb, pc = (write(tmp, "ovAi.json", ova), write(tmp, "ovBi.json", ovb),
                  write(tmp, "bankCi.json", bankc))
    out = tmp / "index.json"
    run("build", str(pa), str(pb), str(pc), "--out", str(out))
    idx = json.loads(out.read_text())
    by_id = {f["id"]: f for f in idx["functions"]}
    c = by_id["ovAi:0x4100"]["calls"][0]
    check("interior hit in the non-overlapping bank survives",
          c.get("target_interior") == [{"id": "bankCi:0x4300", "offset": 6}],
          repr(c))
    check("interior hit in the overlapping bank is excluded",
          c.get("excluded_not_coresident") == ["ovBi:0x4300"], repr(c))


def test_deterministic_output_independent_of_argv_order(tmp):
    a = bank("bank_a", "arm9", [fn("bank_a:0x100", "0x100", "0x108", "f")])
    b = bank("bank_b", "arm9", [fn("bank_b:0x200", "0x200", "0x208", "g")])
    pa, pb = write(tmp, "det_a.json", a), write(tmp, "det_b.json", b)
    out1, out2 = tmp / "idx1.json", tmp / "idx2.json"
    run("build", str(pa), str(pb), "--out", str(out1))
    run("build", str(pb), str(pa), "--out", str(out2))
    check("byte-identical regardless of argv order",
          out1.read_bytes() == out2.read_bytes())


def test_duplicate_bank_rejected(tmp):
    a1 = bank("dup", "arm9", [fn("dup:0x100", "0x100", "0x108", "f")])
    a2 = bank("dup", "arm9", [fn("dup:0x200", "0x200", "0x208", "g")])
    p1, p2 = write(tmp, "dup1.json", a1), write(tmp, "dup2.json", a2)
    out = tmp / "index.json"
    proc = run("build", str(p1), str(p2), "--out", str(out), expect_ok=False)
    check("duplicate bank name rejected", proc.returncode != 0)
    check("stderr names the problem", "dup" in proc.stderr)


def test_unknown_schema_rejected(tmp):
    bad = {"schema": "something.else/1", "bank": "x", "cpu": "arm9",
           "functions": []}
    p = write(tmp, "bad.json", bad)
    out = tmp / "index.json"
    proc = run("build", str(p), "--out", str(out), expect_ok=False)
    check("unknown schema rejected", proc.returncode != 0)


def test_addr_query_width_matching(tmp):
    # A 4-byte write at 0x04000130: querying the address in the *middle* of
    # that access (not its start) must still find it — this is DS MMIO
    # register width, e.g. querying byte 2 of a 4-byte KEYINPUT-sized write.
    a = bank("bank_a", "arm9", [
        fn("bank_a:0x100", "0x100", "0x110", "writer",
           writes=[{"addr": "0x04000130", "width": 4, "region": "io",
                    "sites": ["0x100"]}]),
    ])
    p = write(tmp, "addr.json", a)
    out = tmp / "index.json"
    run("build", str(p), "--out", str(out))
    proc = run("addr", str(out), "0x04000132")
    result = json.loads(proc.stdout)
    check("width-matched write found",
          any(w["id"] == "bank_a:0x100" for w in result["writes"]),
          proc.stdout)
    proc2 = run("addr", str(out), "0x04000140")  # just past the access
    result2 = json.loads(proc2.stdout)
    check("address outside the access range is not matched",
          result2["writes"] == [], proc2.stdout)


def test_cycle_safe_depth_walk(tmp):
    # a -> b -> a: a cyclic call graph. --depth 5 must terminate and must
    # not repeat a node it already reported.
    a = bank("cyc", "arm9", [
        fn("cyc:0x100", "0x100", "0x108", "a",
           calls=[call("0x100", "0x200", target_id="cyc:0x200")]),
        fn("cyc:0x200", "0x200", "0x208", "b",
           calls=[call("0x200", "0x100", target_id="cyc:0x100")]),
    ])
    p = write(tmp, "cyc.json", a)
    out = tmp / "index.json"
    run("build", str(p), "--out", str(out))
    proc = run("callees", str(out), "cyc:0x100", "--depth", "5")
    result = json.loads(proc.stdout)
    ids = [r["id"] for r in result]
    check("cycle walk terminates and visits each id once",
          sorted(ids) == ["cyc:0x200"], repr(ids))


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
        for t in tests:
            sub = tmp / t.__name__
            sub.mkdir()
            t(sub)

    for f in failures:
        print("FAIL:", f)
    if not failures:
        print("OK: %d checks" % len(tests))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
