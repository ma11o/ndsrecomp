# Analysis metadata sidecar (`--analysis-json`)

`nds_recompile ... --out <dir> --bank <bank> --analysis-json` writes
`<dir>/<bank>_analysis.json` beside the generated bank. It is a
machine-readable description of every emitted function, meant for tooling
that has to navigate the low-level generated C: scripts, debuggers, and
LLM-assisted reverse engineering.

It is **observational only**. Codegen, dispatch, and the runtime never read
it, and the flag changes no generated C byte
(`recompiler/tests/analysis_metadata_test.py` pins both properties). Like
everything under `generated/`, the file is derived from a user-provided
image and is not checked in.

## Function identity

A function is identified by `"<bank>:0xADDR"` (`id`), never by bare PC —
the same rule the dispatch tables and `HLE_ARCHITECTURE.md` use, because
overlays and RAM banks reuse guest addresses. `symbol` is the exact C symbol
declared in `<bank>.h`.

`target_id` on a call, literal, or fall-through is the id of the function in
**this bank** that starts exactly at that address, or `null` (another bank,
an interior address, or data). The raw `target` is always present, so a
consumer holding several banks can resolve cross-bank edges itself.

## Per-function fields

| field | meaning |
|---|---|
| `addr`, `end`, `mode`, `name`, `symbol` | identity and extent (`end` exclusive) |
| `source_addr` | present when the body is decoded from a relocated copy |
| `reachable_insns` | instructions reached from the entry; literal pools are not decoded |
| `calls` | direct `BL` / `BLX` (Thumb BL pairs are combined) |
| `tail_calls` | direct `B` leaving `[addr, end)` |
| `indirect` | computed `call` / `jump` sites; `target` when constant propagation resolved it |
| `returns` | count of return-shaped transfers |
| `falls_through_to` | the finder split this body; control continues into the next function |
| `swis` | BIOS call sites and numbers |
| `reads`, `writes` | statically known absolute addresses, with access `width`, DS memory `region`, and `sites` |
| `literals` | distinct literal-pool constants with `region` — where globals and I/O bases enter |
| `blocks` | basic blocks with intra-function successors |
| `callers` | ids in this bank that call, tail-call, or resolvably jump here |

## Cross-bank index (`tools/analysis_index.py`)

A single bank's sidecar only resolves `target_id` within itself (see
"Function identity" above) — it has no way to know what else will be loaded
alongside it. `tools/analysis_index.py` merges several `*_analysis.json`
files and does that resolution across banks:

```
python3 tools/analysis_index.py build a_analysis.json b_analysis.json ... --out index.json
python3 tools/analysis_index.py func    index.json <bank:0xADDR | symbol | name>
python3 tools/analysis_index.py callers index.json <id> [--depth N]
python3 tools/analysis_index.py callees index.json <id> [--depth N]
python3 tools/analysis_index.py addr    index.json 0xADDR [--cpu arm9|arm7]
python3 tools/analysis_index.py region  index.json <region-name> [--cpu ...]
python3 tools/analysis_index.py summary index.json
```

Resolution never crosses CPUs (arm9 and arm7 are different address spaces
that happen to share numeric ranges). Within one CPU, resolution can be
ambiguous on purpose: DS overlays and RAM banks legitimately place different
functions at the same guest address at different times, and a static sidecar
has no visibility into which one is actually resident when a given call
runs. So a cross-bank target resolves to `target_candidates: [ids...]` — a
list, not a single guess — and, when the address falls inside a function's
body rather than at its start, to `target_interior: [{"id", "offset"}]`
instead. A same-bank `target_id` is never overridden by another bank, even
one that happens to define a function at the identical address.

Because of that, the merged index rebuilds `callers` as two sets instead of
one: `callers_all` (every call/tail-call/resolved-indirect/fall-through edge
that resolved to exactly one candidate) and `callers_ambiguous` (edges that
named this function only as one of several candidates). Treating an
ambiguous edge as a certain one would let a script or an LLM silently assume
a specific overlay is resident when it isn't — the split keeps that
assumption visible instead of hiding it in a merged list.

There is one case where candidates *can* be pruned outright, though: two
banks whose image ranges (`load_address` .. `load_address + image_size`)
overlap can never both be resident at the same time, so a function in one of
them can never actually call into the other — the call has to be reaching
some other code, not that bank's copy. `analysis_index.py` drops any
candidate (exact or interior) whose bank overlaps the calling function's own
bank before it is ever reported, and records what it dropped in
`excluded_not_coresident: [ids...]` on the same entry, so a dropped
candidate that turns out to matter for some other reason is still visible
instead of silently vanishing. This can turn an ambiguous resolution into a
certain one (goes from `callers_ambiguous` to `callers_all`), or empty a
resolution out entirely (no `target_candidates`/`target_interior`, only
`excluded_not_coresident`) when the address's only owner turns out to be
impossible. Ranges that merely touch (one's end equals the other's start)
are adjacent, not overlapping, and are never pruned this way — e.g. two
images placed back to back, both legitimately resident together.

## Limits

Memory and indirect-target facts come from a forward constant propagation
over the function's own CFG. It assumes AAPCS call clobbers (r0-r3, r12,
lr) and knows nothing about values that arrive in registers or memory, so
`base + field` accesses through a pointer argument are invisible. Treat the
sidecar as static evidence to combine with the runtime's ring buffers and
coverage captures, not as a complete access map.
