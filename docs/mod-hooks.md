# Mod hooks: replacing and observing guest functions without editing generated C

Status: design. Nothing here is implemented yet.

## Goal

Let code that lives outside `generated/` intercept a recompiled guest
function, identified by `<bank>:0xADDR` (the identity `--analysis-json` and
the dispatch tables already use):

- **enter** — run host code when the function is entered; it may inspect and
  change registers and memory, then either let the original body run or
  complete the call itself (a full replacement);
- **leave** — run host code when that particular invocation returns to its
  caller, with the return value visible in `r0`.

"Before", "Replace" and "After" are all expressible with these two. Generated
C stays machine output: regenerating a bank never loses a mod, and a mod never
patches a bank.

This is a separate seam from performance HLE (`HLE_ARCHITECTURE.md`). HLE
replacements must be byte-identical to the LLE floor and are promoted by
measurement. Mod hooks exist to *change* behavior, are off unless a mod
registers one, and make no parity claim while active.

## What the generated code allows (constraints found by reading it)

1. **A generated C function is not a guest call frame.** Every instruction
   starts with `if (runtime_should_yield()) return;`, and the scheduler
   re-enters the same C function later at an interior PC through the resume
   `switch (g_cpu.R[15])`. A C `return` therefore means "yield, IRQ, unwind,
   or guest return" — host code placed after the call to the body would run
   at arbitrary points. **Leave hooks cannot be "code after the call".**
2. **Static banks call each other directly** (`BL` lowers to a C call of the
   callee's public symbol; literal branches cache a function pointer in an
   `NdsLinkSlot`). A hook that lives only in `runtime_dispatch` misses those
   calls — the same observation `HLE_ARCHITECTURE.md` makes. The seam has to
   be the callee's public symbol.
3. **The call-return stack (`g_crs`) is a host-side fast path, not a guest
   call stack.** Entries are cancelled on unwind, dropped in bulk on
   overflow, and a return that misses it is simply dispatched. It cannot be
   trusted to pair a return with its call.
4. **Every computed PC write in generated code funnels through two runtime
   functions**, with `g_cpu` fully updated (SP already written back) before
   the call: `runtime_call_should_return(target)` for return-shaped transfers
   (`bx lr`, `mov pc, lr`, `pop {…, pc}`), and `runtime_dispatch*()` →
   `runtime_dispatch_impl()` for everything else and for should-return
   misses. The Tier-3 interpreter reaches native code again only through its
   per-transfer `nds_has_bank()` probe in `tier3_run()`.
5. **Entry can be observed twice.** If the very first instruction yields, the
   function is re-entered with `R15 == start` again. `g_insn_count[cpu]` is
   incremented only after the yield check, so "no instruction retired since
   the enter hook ran" identifies the duplicate.
6. **Leaf inlining and fall-through coalescing bypass the public symbol.**
   The HLE profile path already excludes its candidates from both
   (`build_inline_leaves`, `build_superblocks`); hookable functions need the
   same exclusion.

## Design

### Seam: a wrapper on the public symbol

For each hookable function the recompiler emits the body under a private name
and a public wrapper, the shape `HLE_ARCHITECTURE.md` already uses:

```c
static void mkds_arm9_func_02012340__lle(void) { /* unchanged body */ }

void mkds_arm9_func_02012340(void) {
    if (g_hook_mkds_arm9_02012340.armed &&
        g_cpu.R[15] == 0x02012340u &&
        runtime_hook_enter(&g_hook_mkds_arm9_02012340))
        return;                       /* the mod completed the call */
    mkds_arm9_func_02012340__lle();
}
```

Direct calls, link slots and dispatch rows all target the wrapper; interior-PC
resumes fail the `R15 == start` test and fall straight into the body. An
unarmed slot costs one load and a predictable branch per guest call, next to
the per-instruction yield check the body already pays.

Each bank gets `<bank>_hooks.c`: the slot definitions plus a sorted
`{addr, thumb, &slot}` table, so a mod can arm a slot by `(bank, addr)` at
startup without the generated header.

**Which functions get a seam** is a recompiler flag, default off so existing
output (and `codegen_golden`) is untouched:

- `--hook-seams manifest --hook-manifest <toml>` — only listed functions.
  Adding a target means regenerating and recompiling one shard.
- `--hook-seams all` — every function in the bank. Any function becomes
  hookable by relinking a mod; no regeneration per experiment. Disables leaf
  inlining for the bank.

### Enter

`runtime_hook_enter(slot)`:

1. If the top hook frame for this CPU is this slot with the same entry SP and
   `g_insn_count` has not advanced, this is the duplicate entry from
   constraint 5 — return 0 without calling the mod again.
2. Call the mod's enter handler with a context (register file, CPSR, CPU,
   function id, entry LR/SP).
3. `NDS_HOOK_CONTINUE` → if the slot has a leave handler, push a return watch
   (below); return 0 so the original body runs — with whatever register or
   memory changes the handler made.
4. `NDS_HOOK_HANDLED` → the handler has produced the result. The runtime
   performs the guest return on its behalf (`R15 = entry LR`, CPSR.T from
   bit 0 on ARMv5 / unchanged rules as for `bx lr`), runs the leave handler
   immediately if one is armed, and returns 1. The wrapper returns to its C
   caller, whose existing `R15 != return_pc` check handles the rest; when
   entered from dispatch, the scheduler continues at the new PC.

A handler must not call back into guest code synchronously: the callee may
yield, and there is no host frame to resume into. "Call the original, then
post-process" is written as *enter → CONTINUE* plus a *leave* handler.
Synchronous guest calls from mods need a nested run loop with its own
scheduling rules and are out of scope here.

### Leave: a return watch, not a trampoline

Rewriting LR to point at a trampoline would be guest-visible (functions that
store, compare or tail-call through LR) and needs an executable address to
exist. Instead the runtime keeps, per CPU, a small stack of **return watches**
`{slot, return_pc (with mode bit), entry_sp}` pushed at enter.

A watch fires when the CPU transfers to `return_pc` **with `SP == entry_sp`**:
under AAPCS the callee restores SP before returning, recursion leaves deeper
frames with a lower SP, IRQ handlers run on the IRQ-mode SP, and another OS
thread runs on another stack — so SP disambiguates all of them without
inspecting LR. The check sits at the three choke points from constraint 4
(`runtime_call_should_return`, `runtime_dispatch_impl`, the Tier-3 transfer
probe), guarded by a per-CPU "any watch armed" flag so the unhooked path costs
one load.

On a match the watch is popped and the leave handler runs with the post-return
register state; it may rewrite `r0`/`r1` or memory. Tail calls need nothing
special: a function entered by `b` is watched with the LR its caller left,
which is exactly where it will return.

Watches whose function never returns (thread killed, `longjmp`-style unwinds)
would leak; the stack is bounded, evicts oldest-first, and counts evictions in
the diagnostics so a mod author can see it.

### Mod ABI (host side)

```c
typedef enum { NDS_HOOK_CONTINUE = 0, NDS_HOOK_HANDLED = 1 } NdsHookResult;

typedef struct NdsHookCtx {
    uint32_t*   r;          /* R0..R15 of the active CPU */
    uint32_t*   cpsr;
    int         cpu;        /* NDS_ARM9 / NDS_ARM7 */
    const char* bank;
    uint32_t    addr;
    uint32_t    entry_lr, entry_sp;
} NdsHookCtx;

int nds_hook_enter(const char* bank, uint32_t addr,
                   NdsHookResult (*fn)(NdsHookCtx*));
int nds_hook_leave(const char* bank, uint32_t addr, void (*fn)(NdsHookCtx*));

uint32_t nds_mod_read32(NdsHookCtx*, uint32_t addr);   /* + 8/16, write*  */
```

Memory access goes through the active CPU's bus so TCM, mirrors and I/O behave
as the guest sees them. Registration returns non-zero when `(bank, addr)` has
no seam, so a mod built against a stale analysis index fails loudly at startup
instead of silently never firing.

Mods are compiled into the runner from a directory given at configure time
(`-DNDS_MOD_DIR=…`), each exposing `void nds_mod_init(void)`. Loading shared
libraries at runtime can come later; static linking keeps the first version
free of platform loader differences.

### Timing and determinism

Hook handlers consume no guest cycles. With no hook armed the machine must be
bit-identical to a build without seams; that is the acceptance gate below.
With a hook armed, parity with the oracle is intentionally given up. Return
watches are not part of savestates in the first version: loading a state
clears them, and the diagnostics say so.

## Limits of the first version

- Only functions in **static banks** have seams. Code that runs on Tier 3 (on
  macOS that includes every overlay, since the live shard compiler is not
  available there) cannot be hooked until it is covered by a bank.
- Content-validated banks (several generations at one address) need the slot
  to be per generation; the design allows it — slots are per bank — but the
  first version only targets immutable title banks.
- No synchronous guest calls from a handler; no mid-function (address-level)
  hooks. Both are natural follow-ups: the second is an enter seam on a
  basic-block leader.

## Acceptance

1. `codegen_golden` unchanged with the flag off; a new golden case pins the
   wrapper shape with it on.
2. Runtime unit test on a synthetic bank: enter/CONTINUE, enter/HANDLED,
   leave with modified `r0`, recursion (two watches, correct order), a yield
   on the first instruction (enter fires once), a return reached through
   `runtime_dispatch` rather than the fast path, and watch eviction.
3. A/B on a real title built with `--hook-seams all` and no mod registered:
   identical framebuffer/RAM digests at a fixed VBlank versus a build without
   seams, and frame time within noise.
4. End to end: pick a function from the analysis index, register an enter
   hook that counts calls and a leave hook that changes its result, and show
   both take effect in the running game.
