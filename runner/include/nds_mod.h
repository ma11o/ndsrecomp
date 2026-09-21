// nds_mod.h — public ABI for code built into the runner from NDS_MOD_DIR.
//
// This is the only header a mod includes. It never pulls in generated-bank
// or runner-internal types: a mod's job is to arm hooks by (bank, addr) and
// read/observe the active CPU's registers and memory through this surface,
// exactly as docs/mod-hooks.md "Mod ABI" describes. Implemented by
// runner/src/mod_hooks.cpp.
//
// Every registered `.c`/`.cpp` file under NDS_MOD_DIR must define
// `void nds_mod_init_<stem>(void)` (stem = its filename without extension,
// sanitized to a C identifier); the generated registry calls it once at
// startup, before the machine runs. That is the right (and only) place to
// call nds_hook_enter / nds_hook_leave: registration happens once, on the
// emulation thread, before any guest code executes.

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum NdsHookResult {
    NDS_HOOK_CONTINUE = 0,  // let the original (or already-mutated) body run
    NDS_HOOK_HANDLED  = 1   // the handler produced the result; return now
} NdsHookResult;

// The active CPU's visible state at the moment a hook fires. `r` and `cpsr`
// point directly at the live register file (R0..R15, then CPSR) -- reading
// or writing through them takes effect immediately, the same as the guest
// instruction that would otherwise have run. `entry_lr`/`entry_sp` are a
// snapshot of R14/R13 taken at ENTER and handed unchanged to the matching
// LEAVE call, since by the time leave fires r[13]/r[14] already hold the
// post-return values.
typedef struct NdsHookCtx {
    uint32_t*   r;      // R0..R15 of the active CPU (16 entries)
    uint32_t*   cpsr;
    int         cpu;    // NDS_ARM9 (0) / NDS_ARM7 (1)
    const char* bank;
    uint32_t    addr;
    uint32_t    entry_lr;
    uint32_t    entry_sp;
} NdsHookCtx;

// Register an enter/leave handler for the function at (bank, addr). `addr`
// may carry the BX-style mode bit (bit 0 set = thumb) to disambiguate a bank
// that has both an ARM and a Thumb function at the same address; when only
// one function exists there, the bit is not required and either value is
// accepted. When both exist, bit 0 picks which one -- pass it deliberately,
// the same as you would to BX. Returns 0 on success. A nonzero return means
// (bank, addr) is not a seamed function in this build at all (1) -- a stale
// or misspelled selector fails loudly at startup rather than silently never
// firing.
int nds_hook_enter(const char* bank, uint32_t addr,
                   NdsHookResult (*fn)(NdsHookCtx*));
int nds_hook_leave(const char* bank, uint32_t addr,
                   void (*fn)(NdsHookCtx*));

// Memory access through the active CPU's bus (TCM, mirrors, and I/O behave
// exactly as the guest sees them). `ctx` is accepted for symmetry with the
// register accessors above and for future per-CPU addressing; the current
// implementation always targets whichever CPU is active when called, which
// during a hook callback is always ctx->cpu.
uint32_t nds_mod_read32(NdsHookCtx* ctx, uint32_t addr);
uint16_t nds_mod_read16(NdsHookCtx* ctx, uint32_t addr);
uint8_t  nds_mod_read8 (NdsHookCtx* ctx, uint32_t addr);
void nds_mod_write32(NdsHookCtx* ctx, uint32_t addr, uint32_t value);
void nds_mod_write16(NdsHookCtx* ctx, uint32_t addr, uint16_t value);
void nds_mod_write8 (NdsHookCtx* ctx, uint32_t addr, uint8_t value);

#ifdef __cplusplus
}  // extern "C"
#endif
