#!/usr/bin/env python3
"""
analysis_index.py — merge several --analysis-json bank sidecars into one
cross-bank index, and answer queries against it.

Why this exists: analysis_metadata.cpp resolves `target_id` only within the
producing bank (see docs/analysis-metadata.md "Function identity") because a
single-bank tool has no way to know what else will be loaded at the same
guest address. Overlays and RAM banks legitimately reuse addresses — that's
the whole point of overlays — so a cross-bank target can name more than one
real function. This tool is the place that DOES have all the banks at once,
so it does the resolution, but it must not silently collapse an ambiguous
answer into a single guess: a DS ROM's overlay table decides which physical
bank is actually resident at a given moment, and this tool has no visibility
into that (it only sees static per-bank facts, per
docs/analysis-metadata.md "Limits"). So every cross-bank resolution is a
*list* of candidates, and callers/callees built from an ambiguous resolution
are kept out of the "certain" `callers_all` set — an LLM or script walking
the call graph should be able to trust `callers_all` without re-deriving the
ambiguity rule itself.

One thing this tool DOES know without the overlay table, though: two banks
whose image ranges overlap can never both be resident at once, so a bank
can never call into another bank it overlaps. That's used to prune obviously
wrong candidates before anything is reported as a candidate — see
GlobalMaps.resolve below.

Single file, standard library only.
"""
import argparse
import bisect
import json
import sys
from collections import defaultdict

SCHEMA_IN = "ndsrecomp.analysis/1"
SCHEMA_OUT = "ndsrecomp.analysis-index/1"


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def parse_hex(s):
    return int(s, 16)


def hexaddr(n):
    return "0x%08X" % (n & 0xFFFFFFFF)


# ── loading ──────────────────────────────────────────────────────────────

def load_bank(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        die("cannot read %s: %s" % (path, e))
    if data.get("schema") != SCHEMA_IN:
        die("%s: unknown schema %r (expected %r)" %
            (path, data.get("schema"), SCHEMA_IN))
    return data


# ── global address maps (built once, over every loaded bank) ───────────────

def bank_of(function_id):
    return function_id.split(":", 1)[0]


class GlobalMaps:
    """Per-CPU lookup structures used to resolve a raw guest address to the
    function(s) that could own it. Kept separate from per-bank data because
    resolution is explicitly cross-bank (but never cross-CPU: arm9 and arm7
    are different address spaces sharing numeric ranges by coincidence)."""

    def __init__(self, functions, banks):
        # (cpu, addr) -> sorted list of function ids starting exactly there.
        self.starts = defaultdict(set)
        # cpu -> sorted [(start, end, id), ...], plus parallel starts list
        # and the longest function span, for a bounded interior lookup.
        self.intervals = defaultdict(list)
        for fn in functions:
            cpu = fn["cpu"]
            addr = parse_hex(fn["addr"])
            end = parse_hex(fn["end"])
            self.starts[(cpu, addr)].add(fn["id"])
            self.intervals[cpu].append((addr, end, fn["id"]))
        self._starts_arr = {}
        self._maxlen = {}
        for cpu, ivs in self.intervals.items():
            ivs.sort(key=lambda t: (t[0], t[2]))
            self._starts_arr[cpu] = [s for s, _, _ in ivs]
            self._maxlen[cpu] = max((e - s for s, e, _ in ivs), default=0)

        # bank name -> half-open image range, for the co-residency filter.
        # A zero-size image (start == end) is stored as-is and never
        # overlaps anything, including itself.
        self.bank_ranges = {}
        for name, b in banks.items():
            start = parse_hex(b["load_address"])
            self.bank_ranges[name] = (start, start + b["image_size"])

    def exact(self, cpu, addr):
        return sorted(self.starts.get((cpu, addr), ()))

    def interior(self, cpu, addr):
        ivs = self.intervals.get(cpu)
        starts = self._starts_arr.get(cpu)
        if not ivs:
            return []
        maxlen = self._maxlen[cpu]
        lo = bisect.bisect_left(starts, addr - maxlen)
        hi = bisect.bisect_right(starts, addr)
        out = []
        for i in range(lo, hi):
            s, e, fid = ivs[i]
            if s <= addr < e:
                out.append({"id": fid, "offset": addr - s})
        out.sort(key=lambda r: r["id"])
        return out

    def _overlaps(self, bank_a, bank_b):
        ra, rb = self.bank_ranges.get(bank_a), self.bank_ranges.get(bank_b)
        if ra is None or rb is None:
            return False
        a_start, a_end = ra
        b_start, b_end = rb
        if a_start == a_end or b_start == b_end:
            return False  # empty image: overlaps nothing
        # Half-open ranges; touching (a_end == b_start or vice versa) is
        # not an overlap — the two images can be adjacent in the same bank.
        return a_start < b_end and b_start < a_end

    def _coresident(self, source_bank, candidate_ids):
        """Two banks that can never be memory-resident at the same time
        (their image ranges overlap) cannot call into each other: while one
        is loaded the other, by definition, isn't there. Splits
        candidate_ids into (kept, excluded), excluded sorted. A candidate in
        source_bank itself is always kept without consulting image ranges —
        this only happens via the interior fallback (an in-bank computed
        target that lands inside one of the bank's own functions but not at
        its head), and a bank is trivially resident with itself."""
        kept, excluded = [], []
        for cid in candidate_ids:
            cand_bank = bank_of(cid)
            if cand_bank != source_bank and self._overlaps(source_bank, cand_bank):
                excluded.append(cid)
            else:
                kept.append(cid)
        return kept, sorted(excluded)

    def resolve(self, cpu, addr, same_bank_target_id, source_bank):
        """Returns (target_candidates_or_None, target_interior_or_None,
        excluded_ids). Same-bank resolution always wins outright: a bank is
        one image, so a direct transfer to an address it defines lands in
        that image (and trivially can't be excluded — it can't fail to be
        co-resident with itself). Otherwise every candidate that can never
        be resident alongside `source_bank` is dropped before anything is
        reported as a candidate; if that empties the list, nothing is
        reported at all rather than falling back to a weaker match — a
        dropped candidate was still the address's only exact/interior
        owner, and guessing a different kind of match for it would invent
        a fact the sidecar doesn't have."""
        if same_bank_target_id is not None:
            return [same_bank_target_id], None, []
        cands = self.exact(cpu, addr)
        if cands:
            kept, excluded = self._coresident(source_bank, cands)
            return (kept or None), None, excluded
        interior = self.interior(cpu, addr)
        if interior:
            kept_ids, excluded = self._coresident(
                source_bank, [i["id"] for i in interior])
            kept = [i for i in interior if i["id"] in kept_ids] or None
            return None, kept, excluded
        return None, None, []


# ── augmenting one function record with cross-bank facts ───────────────────

def _apply_resolution(e, cands, interior, excluded):
    if cands:
        e["target_candidates"] = cands
    elif interior:
        e["target_interior"] = interior
    if excluded:
        e["excluded_not_coresident"] = excluded


def augment_transfer_list(entries, cpu, maps, edges_out, source_id, source_bank):
    """calls / tail_calls: each entry has target + target_id (same-bank or
    null). Mutates entries in place, and records caller edges."""
    for e in entries:
        addr = parse_hex(e["target"])
        cands, interior, excluded = maps.resolve(
            cpu, addr, e.get("target_id"), source_bank)
        _apply_resolution(e, cands, interior, excluded)
        record_edge(edges_out, source_id, cands)


def augment_indirect_list(entries, cpu, maps, edges_out, source_id, source_bank):
    for e in entries:
        if "target" not in e:
            continue  # unresolved indirect site: nothing to link
        addr = parse_hex(e["target"])
        cands, interior, excluded = maps.resolve(
            cpu, addr, e.get("target_id"), source_bank)
        _apply_resolution(e, cands, interior, excluded)
        record_edge(edges_out, source_id, cands)


def augment_falls_through(entry, cpu, maps, edges_out, source_id, source_bank):
    if entry is None:
        return
    addr = parse_hex(entry["target"])
    cands, interior, excluded = maps.resolve(
        cpu, addr, entry.get("target_id"), source_bank)
    _apply_resolution(entry, cands, interior, excluded)
    record_edge(edges_out, source_id, cands)


def augment_literals(entries, cpu, maps, source_bank):
    """Literals are NOT call edges (a constant in a literal pool is not a
    control-flow transfer), so they never feed callers_all/callers_ambiguous
    — only calls/tail_calls/resolved-indirect/falls_through_to do. They
    still get target_candidates/target_interior, because a
    literal that turns out to be a code address (region == a code region) is
    exactly the kind of fact an RE tool wants resolved across banks too."""
    for e in entries:
        addr = parse_hex(e["value"]) & ~1  # producer masks the same way
        cands, interior, excluded = maps.resolve(
            cpu, addr, e.get("target_id"), source_bank)
        _apply_resolution(e, cands, interior, excluded)


def record_edge(edges_out, source_id, cands):
    if not cands:
        return
    if len(cands) == 1:
        edges_out["all"][cands[0]].add(source_id)
    else:
        for c in cands:
            edges_out["ambiguous"][c].add(source_id)


# ── build ────────────────────────────────────────────────────────────────

def cmd_build(args):
    if len(set(args.inputs)) != len(args.inputs):
        die("duplicate input path on the command line")

    banks = {}       # bank name -> bank JSON dict
    all_funcs = []    # flat list, each function dict gets a "cpu"/"bank" tag
    for path in sorted(args.inputs):  # sort first: output must not depend on argv order
        data = load_bank(path)
        bank = data["bank"]
        if bank in banks:
            die("duplicate bank name %r (from %s and an earlier input)" %
                (bank, path))
        banks[bank] = data
        for fn in data["functions"]:
            fn = dict(fn)
            fn["cpu"] = data["cpu"]
            fn["bank"] = bank
            all_funcs.append(fn)

    if not banks:
        die("no inputs")

    maps = GlobalMaps(all_funcs, banks)
    edges = {"all": defaultdict(set), "ambiguous": defaultdict(set)}

    for fn in all_funcs:
        cpu, source_bank = fn["cpu"], fn["bank"]
        augment_transfer_list(fn["calls"], cpu, maps, edges, fn["id"], source_bank)
        augment_transfer_list(fn["tail_calls"], cpu, maps, edges, fn["id"], source_bank)
        augment_indirect_list(fn["indirect"], cpu, maps, edges, fn["id"], source_bank)
        augment_falls_through(fn.get("falls_through_to"), cpu, maps, edges,
                               fn["id"], source_bank)
        augment_literals(fn["literals"], cpu, maps, source_bank)

    for fn in all_funcs:
        fid = fn["id"]
        # Reorder keys: bank first (new), then the original producer fields,
        # then the two rebuilt global caller sets appended at the end so a
        # diff against the source bank file stays easy to read.
        ordered = {"bank": fn["bank"]}
        ordered.update({k: v for k, v in fn.items()
                         if k not in ("bank", "cpu")})
        ordered["cpu"] = fn["cpu"]
        ordered["callers_all"] = sorted(edges["all"].get(fid, ()))
        ordered["callers_ambiguous"] = sorted(edges["ambiguous"].get(fid, ()))
        fn.clear()
        fn.update(ordered)

    all_funcs.sort(key=lambda f: (f["cpu"], f["bank"], parse_hex(f["addr"])))

    bank_list = []
    for name in sorted(banks):
        b = banks[name]
        bank_list.append({
            "bank": b["bank"],
            "cpu": b["cpu"],
            "image_sha1": b["image_sha1"],
            "program_id": b["program_id"],
            "load_address": b["load_address"],
            "image_size": b["image_size"],
            "function_count": b["function_count"],
        })

    index = {
        "schema": SCHEMA_OUT,
        "banks": bank_list,
        "functions": all_funcs,
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(index, f, indent=2, sort_keys=False)
        f.write("\n")


# ── loading the built index for queries ─────────────────────────────────

def load_index(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        die("cannot read %s: %s" % (path, e))
    if data.get("schema") != SCHEMA_OUT:
        die("%s: not an analysis-index file (schema %r)" %
            (path, data.get("schema")))
    return data


def index_by_id(index):
    return {f["id"]: f for f in index["functions"]}


def emit(obj):
    print(json.dumps(obj, indent=2, sort_keys=False))


# ── query: func ──────────────────────────────────────────────────────────

def cmd_func(args):
    index = load_index(args.index)
    by_id = index_by_id(index)
    key = args.query
    if key in by_id:
        emit(by_id[key])
        return
    by_symbol = [f for f in index["functions"] if f["symbol"] == key]
    if by_symbol:
        emit(by_symbol if len(by_symbol) > 1 else by_symbol[0])
        return
    by_name = [f for f in index["functions"] if f["name"] == key]
    if by_name:
        emit(by_name if len(by_name) > 1 else by_name[0])
        return
    die("no function matches id/symbol/name %r" % key)


# ── query: callers / callees ────────────────────────────────────────────

def callees_of(fn):
    """Union of certain + ambiguous candidates named by every outgoing
    control-flow edge (calls, tail_calls, resolved indirect,
    falls_through_to). Literals are excluded — they are not control flow."""
    out = set()
    for group in (fn["calls"], fn["tail_calls"], fn["indirect"]):
        for e in group:
            out.update(e.get("target_candidates", ()))
    ft = fn.get("falls_through_to")
    if ft:
        out.update(ft.get("target_candidates", ()))
    return out


def callers_of(fn):
    """Union of callers_all and callers_ambiguous: for a reverse walk we
    want everyone who *might* reach this function; the certain/ambiguous
    split stays visible on the raw record for callers who need to be
    strict."""
    return set(fn["callers_all"]) | set(fn["callers_ambiguous"])


def walk(index, start_id, depth, neighbors_fn):
    by_id = index_by_id(index)
    if start_id not in by_id:
        die("no function with id %r" % start_id)
    seen = {start_id}
    out = []
    frontier = [start_id]
    for d in range(1, depth + 1):
        next_frontier = []
        for fid in frontier:
            fn = by_id.get(fid)
            if fn is None:
                continue  # a candidate id that doesn't exist would be a bug upstream; skip defensively
            for nid in sorted(neighbors_fn(fn)):
                if nid in seen:
                    continue
                seen.add(nid)
                nfn = by_id.get(nid)
                out.append({"id": nid,
                             "name": nfn["name"] if nfn else None,
                             "depth": d})
                next_frontier.append(nid)
        frontier = next_frontier
        if not frontier:
            break
    return out


def cmd_callers(args):
    index = load_index(args.index)
    emit(walk(index, args.id, args.depth, callers_of))


def cmd_callees(args):
    index = load_index(args.index)
    emit(walk(index, args.id, args.depth, callees_of))


# ── query: addr ──────────────────────────────────────────────────────────

def cmd_addr(args):
    index = load_index(args.index)
    addr = parse_hex(args.addr)
    reads, writes, literals, code = [], [], [], []
    for fn in index["functions"]:
        if args.cpu and fn["cpu"] != args.cpu:
            continue
        for acc, bucket in ((fn["reads"], reads), (fn["writes"], writes)):
            for a in acc:
                base = parse_hex(a["addr"])
                if base <= addr < base + a["width"]:
                    bucket.append({"id": fn["id"], "access_addr": a["addr"],
                                    "width": a["width"]})
        for lit in fn["literals"]:
            if parse_hex(lit["value"]) == addr:
                literals.append({"id": fn["id"], "value": lit["value"]})
        fn_addr, fn_end = parse_hex(fn["addr"]), parse_hex(fn["end"])
        if fn_addr <= addr < fn_end:
            code.append({"id": fn["id"], "offset": addr - fn_addr})
    emit({"addr": hexaddr(addr), "reads": reads, "writes": writes,
          "literals": literals, "code": code})


# ── query: region ────────────────────────────────────────────────────────

def cmd_region(args):
    index = load_index(args.index)
    out = []
    for fn in index["functions"]:
        if args.cpu and fn["cpu"] != args.cpu:
            continue
        reads = sorted({a["addr"] for a in fn["reads"] if a["region"] == args.region})
        writes = sorted({a["addr"] for a in fn["writes"] if a["region"] == args.region})
        if reads or writes:
            out.append({"id": fn["id"], "reads": reads, "writes": writes})
    emit(out)


# ── query: summary ──────────────────────────────────────────────────────

def cmd_summary(args):
    index = load_index(args.index)
    by_bank = defaultdict(lambda: {
        "functions": 0, "calls": 0, "tail_calls": 0,
        "cross_bank_edges_resolved": 0,
        "unresolved_direct_targets": defaultdict(int),
        "indirect_total": 0, "indirect_resolved": 0,
        "candidates_excluded_not_coresident": 0,
    })
    for fn in index["functions"]:
        s = by_bank[fn["bank"]]
        s["functions"] += 1
        for key, count_key in (("calls", "calls"), ("tail_calls", "tail_calls")):
            for e in fn[key]:
                s[count_key] += 1
                s["candidates_excluded_not_coresident"] += \
                    len(e.get("excluded_not_coresident", ()))
                cands = e.get("target_candidates")
                if cands:
                    if e.get("target_id") is None:
                        s["cross_bank_edges_resolved"] += 1
                elif "target_interior" not in e:
                    # No candidates and no interior hit survived: either
                    # nothing ever matched, or every match was excluded as
                    # not co-resident with this bank — both are "we don't
                    # know what this calls" from a caller's point of view.
                    s["unresolved_direct_targets"][e["target"]] += 1
        ft = fn.get("falls_through_to")
        if ft:
            s["candidates_excluded_not_coresident"] += \
                len(ft.get("excluded_not_coresident", ()))
            cands = ft.get("target_candidates")
            if cands and ft.get("target_id") is None:
                s["cross_bank_edges_resolved"] += 1
        for e in fn["indirect"]:
            s["indirect_total"] += 1
            if "target" in e:
                s["indirect_resolved"] += 1
                s["candidates_excluded_not_coresident"] += \
                    len(e.get("excluded_not_coresident", ()))
                if e.get("target_candidates") and e.get("target_id") is None:
                    s["cross_bank_edges_resolved"] += 1
        for e in fn["literals"]:
            s["candidates_excluded_not_coresident"] += \
                len(e.get("excluded_not_coresident", ()))

    out = {}
    for bank, s in sorted(by_bank.items()):
        top20 = sorted(s["unresolved_direct_targets"].items(),
                        key=lambda kv: (-kv[1], kv[0]))[:20]
        out[bank] = {
            "functions": s["functions"],
            "calls": s["calls"],
            "tail_calls": s["tail_calls"],
            "cross_bank_edges_resolved": s["cross_bank_edges_resolved"],
            "candidates_excluded_not_coresident":
                s["candidates_excluded_not_coresident"],
            "unresolved_direct_targets_top20": [
                {"target": t, "refs": n} for t, n in top20],
            "indirect_total": s["indirect_total"],
            "indirect_resolved": s["indirect_resolved"],
        }
    emit(out)


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build", help="merge bank analysis files into an index")
    p.add_argument("inputs", nargs="+")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("func", help="look up function record(s)")
    p.add_argument("index")
    p.add_argument("query")
    p.set_defaults(func=cmd_func)

    p = sub.add_parser("callers", help="transitive callers of a function")
    p.add_argument("index")
    p.add_argument("id")
    p.add_argument("--depth", type=int, default=1)
    p.set_defaults(func=cmd_callers)

    p = sub.add_parser("callees", help="transitive callees of a function")
    p.add_argument("index")
    p.add_argument("id")
    p.add_argument("--depth", type=int, default=1)
    p.set_defaults(func=cmd_callees)

    p = sub.add_parser("addr", help="who statically touches an absolute address")
    p.add_argument("index")
    p.add_argument("addr")
    p.add_argument("--cpu", choices=("arm9", "arm7"))
    p.set_defaults(func=cmd_addr)

    p = sub.add_parser("region", help="functions touching a memory region")
    p.add_argument("index")
    p.add_argument("region")
    p.add_argument("--cpu", choices=("arm9", "arm7"))
    p.set_defaults(func=cmd_region)

    p = sub.add_parser("summary", help="per-bank counts")
    p.add_argument("index")
    p.set_defaults(func=cmd_summary)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
