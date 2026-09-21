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

## Limits

Memory and indirect-target facts come from a forward constant propagation
over the function's own CFG. It assumes AAPCS call clobbers (r0-r3, r12,
lr) and knows nothing about values that arrive in registers or memory, so
`base + field` accesses through a pointer argument are invisible. Treat the
sidecar as static evidence to combine with the runtime's ring buffers and
coverage captures, not as a complete access map.
