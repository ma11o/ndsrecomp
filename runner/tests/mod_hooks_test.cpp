// mod_hooks_test.cpp — docs/mod-hooks.md "Acceptance 2".
//
// Links the real runner/src/mod_hooks.cpp against the real
// runtime_call_should_return / runtime_dispatch / runtime_call_push_return
// (runner/src/runtime_arm.cpp), the same recipe code_cycles_fold_test.cpp
// uses to pin runtime behavior rather than a model of it. Rather than build
// a synthetic recompiled bank and its wrapper (the recompiler side already
// has its own codegen-shape test, hook_seams_codegen_test), this drives
// runtime_hook_enter() and the choke points directly with a fake CPU state
// -- runtime_hook_enter has exactly the signature the generated wrapper
// calls, so calling it directly IS calling the real seam, just without
// paying for a whole generated bank to reach it.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "runtime_arm.h"
#include "state.h"
#include "mod_hooks.h"

extern "C" int runtime_hook_enter(NdsHookSlot* slot);

namespace {

int g_failures = 0;
void fail(const char* what) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
}
void expect(bool cond, const char* what) {
    if (!cond) fail(what);
}

// ── Enter/leave call recorders ──────────────────────────────────────────
int g_enter_calls = 0;
NdsHookResult g_enter_result = NDS_HOOK_CONTINUE;
NdsHookCtx g_last_enter_ctx{};
int g_leave_calls = 0;
NdsHookCtx g_last_leave_ctx{};
uint32_t g_leave_sets_r0 = 0;
bool g_leave_writes_r0 = false;

NdsHookResult recording_enter(NdsHookCtx* ctx) {
    ++g_enter_calls;
    g_last_enter_ctx = *ctx;
    return g_enter_result;
}
void recording_leave(NdsHookCtx* ctx) {
    ++g_leave_calls;
    g_last_leave_ctx = *ctx;
    if (g_leave_writes_r0) ctx->r[0] = g_leave_sets_r0;
}

void reset_recorders() {
    g_enter_calls = 0;
    g_enter_result = NDS_HOOK_CONTINUE;
    g_last_enter_ctx = NdsHookCtx{};
    g_leave_calls = 0;
    g_last_leave_ctx = NdsHookCtx{};
    g_leave_writes_r0 = false;
}

// A fresh, unarmed slot. `nds_mod_hooks_test_reset()` clears the registry
// and watch state between scenarios; slots themselves are test-owned so
// tests can hold several at once (recursion, eviction).
NdsHookSlot make_slot(const char* bank, uint32_t addr, uint8_t thumb) {
    NdsHookSlot slot{};
    slot.armed = 1u;
    slot.bank = bank;
    slot.addr = addr;
    slot.thumb = thumb;
    slot.enter_fn = reinterpret_cast<void*>(&recording_enter);
    slot.leave_fn = nullptr;
    slot.user_data = nullptr;
    return slot;
}

void reset_cpu() {
    std::memset(&g_cpu, 0, sizeof(g_cpu));
    g_nds_active = NDS_ARM9;
    g_insn_count[0] = 0;
    g_insn_count[1] = 0;
    nds_mod_hooks_test_reset();
    reset_recorders();
}

// A no-op dispatch target so runtime_dispatch(pc) resolves instead of
// halting fatally (dispatch_lookup.h: a row with no NdsStaticValidation is
// unconditionally live, so nothing else needs to be set up for it to win).
extern "C" void dummy_dispatch_target(void) {}
NdsDispatchEntry g_dummy_row{0x02100000u, 0u, &dummy_dispatch_target,
                            nullptr};
bool g_dispatch_registered = false;
void ensure_dummy_dispatch_registered() {
    if (g_dispatch_registered) return;
    nds_register_dispatch(NDS_ARM9, &g_dummy_row, 1u, 0xFFFF0000u);
    g_dispatch_registered = true;
}

}  // namespace

int main() {
    // ── enter/CONTINUE: the body runs, no leave armed -> no watch pushed.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        g_enter_result = NDS_HOOK_CONTINUE;
        g_cpu.R[13] = 0x1000u;   // entry SP
        g_cpu.R[14] = 0x1004u;   // entry LR (ARM caller, no tag bit)
        g_cpu.R[15] = 0x1000u;
        const int r = runtime_hook_enter(&slot);
        expect(r == 0, "enter/CONTINUE must return 0 (let the body run)");
        expect(g_enter_calls == 1, "enter/CONTINUE must call the handler once");
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 0u,
              "enter/CONTINUE with no leave armed must not push a watch");
        expect(g_last_enter_ctx.entry_lr == 0x1004u, "ctx.entry_lr");
        expect(g_last_enter_ctx.entry_sp == 0x1000u, "ctx.entry_sp");
        expect(g_last_enter_ctx.bank && std::strcmp(g_last_enter_ctx.bank, "b") == 0,
              "ctx.bank");
        expect(g_last_enter_ctx.addr == 0x1000u, "ctx.addr");
    }

    // ── enter/HANDLED, ARM caller: R15 = entry_lr, CPSR.T cleared, leave
    //    (if armed) fires immediately, and the caller's own CRS entry (the
    //    one a direct-call BL site would have pushed) is popped -- keeping
    //    the wrapper's forced return consistent with `if (g_cpu.R[15] !=
    //    return_pc) { cancel; return; }` at that call site.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_enter_result = NDS_HOOK_HANDLED;
        g_cpu.R[13] = 0x2000u;
        g_cpu.R[14] = 0x1234u;  // ARM return address, bit0 clear
        g_cpu.R[15] = 0x1000u;
        // The CRS key mixes in the CURRENT cpsr.T at push time -- which in
        // real generated code is always the caller's own mode, the same
        // mode entry_lr's own tag bit already encodes (both come from the
        // same BL). Push with cpsr.T matching entry_lr's tag (clear, here)
        // so the later pop's key -- computed from R15 (=entry_lr) and
        // whatever HANDLED sets cpsr.T to -- lines up, exactly as a real
        // `bx lr` completing this call would.
        runtime_call_push_return(0x1234u);
        expect(runtime_call_stack_depth() == 1u, "CRS push landed");
        const int r = runtime_hook_enter(&slot);
        expect(r == 1, "enter/HANDLED must return 1");
        expect(g_cpu.R[15] == 0x1234u, "HANDLED: R15 = entry LR");
        expect((g_cpu.cpsr & CPSR_T_BIT) == 0u,
              "HANDLED (ARM return): CPSR.T must clear");
        expect(g_leave_calls == 1, "HANDLED with leave armed must fire it");
        expect(runtime_call_stack_depth() == 0u,
              "HANDLED must pop the CRS entry its own call pushed");
    }

    // ── enter/HANDLED, Thumb caller: LR bit 0 set -> CPSR.T set, PC masked
    //    to a halfword boundary (docs/mod-hooks.md: "CPSR.T from bit 0 on
    //    ARMv5 / unchanged rules as for bx lr").
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        g_enter_result = NDS_HOOK_HANDLED;
        g_cpu.R[13] = 0x2000u;
        g_cpu.R[14] = 0x1235u;  // Thumb return address, bit0 set
        g_cpu.R[15] = 0x1000u;
        const int r = runtime_hook_enter(&slot);
        expect(r == 1, "enter/HANDLED (thumb) must return 1");
        expect(g_cpu.R[15] == 0x1234u, "HANDLED (thumb): PC masked to ~1");
        expect((g_cpu.cpsr & CPSR_T_BIT) != 0u,
              "HANDLED (thumb return): CPSR.T must set");
    }

    // ── leave sees and can modify r0.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_leave_writes_r0 = true;
        g_leave_sets_r0 = 0x77u;
        g_cpu.R[0] = 0x11u;
        g_cpu.R[13] = 0x2000u;
        g_cpu.R[14] = 0x1234u;
        g_cpu.R[15] = 0x1000u;
        g_enter_result = NDS_HOOK_HANDLED;
        runtime_hook_enter(&slot);
        expect(g_last_leave_ctx.r != nullptr, "leave ctx.r must be valid");
        expect(g_cpu.R[0] == 0x77u, "leave handler's r0 write took effect");
    }

    // ── yield on the first instruction: the wrapper is entered a second
    //    time with R15 still == the function's own start (constraint 5).
    //    The duplicate must not re-invoke the enter handler.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        g_enter_result = NDS_HOOK_CONTINUE;
        g_cpu.R[13] = 0x3000u;
        g_cpu.R[14] = 0x1234u;
        g_cpu.R[15] = 0x1000u;
        const int r1 = runtime_hook_enter(&slot);
        expect(r1 == 0, "first entry (about to yield) returns 0");
        expect(g_enter_calls == 1, "first entry calls the handler once");
        // g_insn_count unchanged -- nothing retired before the yield, so
        // this is the SAME observation, not a second call.
        const int r2 = runtime_hook_enter(&slot);
        expect(r2 == 0, "duplicate re-entry also returns 0 (let body run)");
        expect(g_enter_calls == 1,
              "duplicate re-entry after a first-instruction yield must not "
              "call the handler again");
        // Once an instruction actually retires, a genuine re-entry (e.g. a
        // fresh call from the same call site) DOES call the handler again.
        ++g_insn_count[NDS_ARM9];
        const int r3 = runtime_hook_enter(&slot);
        expect(r3 == 0, "post-retirement entry returns 0");
        expect(g_enter_calls == 2,
              "an entry after insn_count advanced is a real call, not a "
              "duplicate");
    }

    // ── recursion: two watches on the same function fire innermost-first.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_enter_result = NDS_HOOK_CONTINUE;
        // Outer call: entry_sp=0x2000, returns to 0x1234.
        g_cpu.R[13] = 0x2000u; g_cpu.R[14] = 0x1234u; g_cpu.R[15] = 0x1000u;
        runtime_hook_enter(&slot);
        // Inner (recursive) call: entry_sp=0x1F00 (deeper), also returns to
        // 0x1234 (same call site calling itself).
        g_cpu.R[13] = 0x1F00u; g_cpu.R[14] = 0x1234u; g_cpu.R[15] = 0x1000u;
        runtime_hook_enter(&slot);
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 2u,
              "two recursive CONTINUE+leave calls push two watches");
        // Inner returns first: SP back at 0x1F00, target 0x1234, ARM mode.
        g_cpu.R[13] = 0x1F00u;
        nds_mod_hooks_check_return(0x1234u);
        expect(g_leave_calls == 1, "inner return must fire exactly one leave");
        expect(g_last_leave_ctx.entry_sp == 0x1F00u,
              "innermost (deepest entry_sp) watch must fire first");
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 1u,
              "firing the inner watch leaves the outer one armed");
        // Outer returns: SP back at 0x2000.
        g_cpu.R[13] = 0x2000u;
        nds_mod_hooks_check_return(0x1234u);
        expect(g_leave_calls == 2, "outer return must fire the remaining leave");
        expect(g_last_leave_ctx.entry_sp == 0x2000u, "outer watch's own entry_sp");
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 0u,
              "both watches consumed");
    }

    // ── a non-matching SP at the matching PC must not fire (IRQ-style: an
    //    interrupt returns through the same PC on a different stack).
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_enter_result = NDS_HOOK_CONTINUE;
        g_cpu.R[13] = 0x2000u; g_cpu.R[14] = 0x1234u; g_cpu.R[15] = 0x1000u;
        runtime_hook_enter(&slot);
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 1u, "watch pushed");
        g_cpu.R[13] = 0x0100u;  // IRQ-mode SP, not the watched entry_sp
        nds_mod_hooks_check_return(0x1234u);
        expect(g_leave_calls == 0,
              "matching PC on the wrong SP must not fire the watch");
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 1u,
              "the watch must remain armed for its real return");
        g_cpu.R[13] = 0x2000u;  // now the real return
        nds_mod_hooks_check_return(0x1234u);
        expect(g_leave_calls == 1, "the real return still fires it");
    }

    // ── return observed via the DISPATCH choke point rather than the
    //    should-return fast path (e.g. the CRS entry was never paired, or
    //    this transfer was reached through a resume/dispatch rather than a
    //    `bx lr` in the same C call chain).
    {
        reset_cpu();
        ensure_dummy_dispatch_registered();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_enter_result = NDS_HOOK_CONTINUE;
        g_cpu.R[13] = 0x2000u;
        g_cpu.R[14] = 0x02100000u;  // return target the dummy row covers
        g_cpu.R[15] = 0x1000u;
        runtime_hook_enter(&slot);
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 1u, "watch pushed");
        // Reached via runtime_dispatch(), NOT runtime_call_should_return():
        // the CRS was never told about this return at all.
        g_cpu.R[13] = 0x2000u;
        runtime_dispatch(0x02100000u);
        expect(g_leave_calls == 1,
              "a return reached through runtime_dispatch (not should_return) "
              "must still fire the watch");
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 0u, "watch consumed");
    }

    // ── watch eviction: bounded stack, oldest-first.
    {
        reset_cpu();
        NdsHookSlot slot = make_slot("b", 0x1000u, 0u);
        slot.leave_fn = reinterpret_cast<void*>(&recording_leave);
        g_enter_result = NDS_HOOK_CONTINUE;
        // mod_hooks.cpp's kWatchCapacity is 256; push past it with distinct
        // (entry_sp, entry_lr) pairs so none of these collide with the
        // duplicate-entry suppression (which keys on slot+sp+insn_count,
        // not on the watch stack at all -- each of these IS a fresh call).
        const unsigned kPushes = 300u;
        for (unsigned i = 0; i < kPushes; ++i) {
            g_cpu.R[13] = 0x10000u - i;      // strictly decreasing SP
            g_cpu.R[14] = 0x8000u + i * 4u;  // distinct return address
            g_cpu.R[15] = 0x1000u;
            runtime_hook_enter(&slot);
            ++g_insn_count[NDS_ARM9];  // each push is a genuinely new call
        }
        expect(nds_mod_hooks_test_watch_depth(NDS_ARM9) == 256u,
              "the watch stack must saturate at its bounded capacity, not "
              "grow unbounded");
        // The oldest watch (the very first push, entry_sp=0x10000) must have
        // been evicted -- it can no longer fire.
        g_cpu.R[13] = 0x10000u;
        nds_mod_hooks_check_return(0x8000u);
        expect(g_leave_calls == 0,
              "the oldest (evicted) watch must not fire");
        // The most recent watch (last push) must still be live.
        g_cpu.R[13] = 0x10000u - (kPushes - 1u);
        nds_mod_hooks_check_return(0x8000u + (kPushes - 1u) * 4u);
        expect(g_leave_calls == 1,
              "the newest watch must have survived the eviction");
    }

    // ── unknown (bank, addr) registration fails loudly.
    {
        reset_cpu();
        NdsHookTableEntry row{0x4000u, 0u, nullptr};
        NdsHookSlot slot = make_slot("known", 0x4000u, 0u);
        row.slot = &slot;
        nds_mod_hooks_register_table("known", &row, 1u);
        expect(nds_hook_enter("known", 0x4000u, &recording_enter) == 0,
              "a registered (bank, addr) must succeed");
        expect(nds_hook_enter("known", 0x5000u, &recording_enter) != 0,
              "an unregistered address in a known bank must fail");
        expect(nds_hook_enter("unknown_bank", 0x4000u, &recording_enter) != 0,
              "an unregistered bank must fail");
        expect(nds_hook_leave("unknown_bank", 0x4000u, &recording_leave) != 0,
              "nds_hook_leave must fail the same way");
    }

    if (g_failures != 0) {
        std::fprintf(stderr, "FAIL: %d check(s) failed\n", g_failures);
        return 1;
    }
    std::puts("PASS: mod hooks (docs/mod-hooks.md acceptance 2)");
    return 0;
}
