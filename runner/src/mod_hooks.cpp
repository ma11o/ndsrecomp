// mod_hooks.cpp — see mod_hooks.h and docs/mod-hooks.md.
//
// Three things live here:
//   1. The bank-table registry a mod's (bank, addr) lookup searches.
//   2. runtime_hook_enter(), the ABI runtime_arm.h declares and the
//      generated wrapper calls once `armed` and the entry-PC check both
//      pass (see recompiler/src/main.cpp write_bank_body's "hookable"
//      branch).
//   3. The per-CPU return-watch stack and its choke-point search, reached
//      through the nds_mod_hooks_check_return() inline in mod_hooks.h.
//
// Registration (nds_hook_enter / nds_hook_leave / the table registry) runs
// once at startup, before the machine runs, on the emulation thread -- the
// same convention nds_register_dispatch documents in runtime_arm.cpp. None
// of it is thread-safe against concurrent guest execution, and none needs
// to be.

#include "mod_hooks.h"

#include <cstring>
#include <vector>

namespace {

struct BankTable {
    const char* bank;
    const NdsHookTableEntry* table;
    unsigned len;
};
std::vector<BankTable> g_tables;

// The most recent slot runtime_hook_enter actually invoked a mod handler
// for, per CPU -- constraint 5 (docs/mod-hooks.md): a function whose first
// instruction yields is re-entered with R15 == its own start address, so the
// wrapper calls runtime_hook_enter again with the SAME slot. This is a
// duplicate of the observation already made, not a second call, distinguished
// from a genuine (rare) same-slot re-entry -- direct recursion through the
// exact same instruction before it retires is not representable -- by
// g_insn_count: nothing can have retired between the two calls if it is the
// same yield-before-progress case.
struct LastEnter {
    NdsHookSlot* slot = nullptr;
    uint32_t entry_sp = 0;
    uint64_t insn_count = 0;
    bool valid = false;
};
LastEnter g_last_enter[2];

// A pending leave: pushed at CONTINUE when the slot has a leave handler,
// popped/fired when the matching return is observed at one of the three
// choke points. `return_key` is the raw entry LR: generated code already
// tags bit 0 with the interworking mode for a BL from Thumb state (verified
// against generated/arm9_bios.c's `T bl` sites), and masked_addr | mode is
// exactly the key runtime_call_should_return's own CRS lookup computes --
// so storing entry LR verbatim lets every choke point compare against it
// with the identical formula it already uses for its own purpose.
struct Watch {
    NdsHookSlot* slot;
    uint32_t return_key;   // entry LR, bit 0 = thumb (BX/interworking tag)
    uint32_t entry_sp;
};
constexpr unsigned kWatchCapacity = 256u;
struct WatchStack {
    Watch items[kWatchCapacity];
    unsigned depth = 0;
};
WatchStack g_watch[2];

struct Diagnostics {
    unsigned long long enter_calls = 0;
    unsigned long long handled = 0;
    unsigned long long leave_fired = 0;
    unsigned long long dup_suppressed = 0;
    unsigned long long watch_pushed = 0;
    unsigned long long watch_evicted = 0;
    unsigned long long registrations_failed = 0;
};
Diagnostics g_diag;

uint32_t observed_key(uint32_t pc) {
    return (pc & ~1u) | ((g_cpu.cpsr & CPSR_T_BIT) ? 1u : 0u);
}

void fire_leave(const Watch& w) {
    if (!w.slot->leave_fn) return;
    auto fn = reinterpret_cast<void (*)(NdsHookCtx*)>(w.slot->leave_fn);
    NdsHookCtx ctx{g_cpu.R, &g_cpu.cpsr, static_cast<int>(g_nds_active),
                  w.slot->bank, w.slot->addr, w.return_key & ~1u, w.entry_sp};
    // entry_lr in the ctx handed to a mod is the plain return address --
    // AAPCS-visible, no interworking tag -- matching what a mod would read
    // out of a `bl` disassembly. The tag bit only matters internally, to
    // pick ARM vs Thumb when performing the return.
    fn(&ctx);
    ++g_diag.leave_fired;
}

void push_watch(int cpu, NdsHookSlot* slot, uint32_t entry_lr,
               uint32_t entry_sp) {
    WatchStack& st = g_watch[cpu];
    if (st.depth == kWatchCapacity) {
        // Oldest-first eviction: a watch whose function never returns
        // (killed thread, longjmp-style unwind) would otherwise pin this
        // slot forever. Shifting the array down is O(capacity) but this
        // only runs once every kWatchCapacity pushes past saturation.
        for (unsigned i = 1; i < kWatchCapacity; ++i) st.items[i - 1] = st.items[i];
        --st.depth;
        ++g_diag.watch_evicted;
    }
    st.items[st.depth++] = Watch{slot, entry_lr, entry_sp};
    ++g_diag.watch_pushed;
    g_nds_mod_watch_armed[cpu] = true;
}

}  // namespace

bool g_nds_mod_watch_armed[2] = {false, false};

void nds_mod_hooks_register_table(const char* bank,
                                  const NdsHookTableEntry* table,
                                  unsigned len) {
    g_tables.push_back(BankTable{bank, table, len});
}

namespace {

// (bank, addr) -> slot, per the lookup rule in docs/mod-hooks.md "Mod ABI":
// bit 0 of `addr` disambiguates a bank that has both an ARM and a Thumb
// function at the same address; when only one function exists there, the
// bit is not required. Returns null and sets *error to 1 (no seam at all)
// on failure -- there is no separate "ambiguous" outcome, since bit 0 always
// picks an answer when both rows exist; a caller that does not pass it
// deliberately gets whichever row bit 0 happens to select, exactly as a real
// BX would.
NdsHookSlot* find_slot(const char* bank, uint32_t addr, int* error) {
    const uint32_t masked = addr & ~1u;
    NdsHookSlot* arm_row = nullptr;
    NdsHookSlot* thumb_row = nullptr;
    for (const BankTable& bt : g_tables) {
        if (std::strcmp(bt.bank, bank) != 0) continue;
        for (unsigned i = 0; i < bt.len; ++i) {
            const NdsHookTableEntry& e = bt.table[i];
            if (e.addr != masked) continue;
            if (e.thumb) thumb_row = e.slot; else arm_row = e.slot;
        }
    }
    if (!arm_row && !thumb_row) { *error = 1; return nullptr; }
    if (arm_row && thumb_row) {
        // Both modes exist at this address (not observed in practice -- one
        // address is one instruction stream): bit 0 picks the row, as a BX
        // to that value would.
        return (addr & 1u) ? thumb_row : arm_row;
    }
    // Exactly one function at this address: tolerate either value of bit 0.
    return thumb_row ? thumb_row : arm_row;
}

}  // namespace

int nds_hook_enter(const char* bank, uint32_t addr,
                   NdsHookResult (*fn)(NdsHookCtx*)) {
    int error = 0;
    NdsHookSlot* slot = find_slot(bank, addr, &error);
    if (!slot) { ++g_diag.registrations_failed; return error; }
    slot->enter_fn = reinterpret_cast<void*>(fn);
    slot->armed = 1u;
    return 0;
}

int nds_hook_leave(const char* bank, uint32_t addr,
                   void (*fn)(NdsHookCtx*)) {
    int error = 0;
    NdsHookSlot* slot = find_slot(bank, addr, &error);
    if (!slot) { ++g_diag.registrations_failed; return error; }
    slot->leave_fn = reinterpret_cast<void*>(fn);
    slot->armed = 1u;
    return 0;
}

uint32_t nds_mod_read32(NdsHookCtx*, uint32_t addr) { return bus_read_u32(addr); }
uint16_t nds_mod_read16(NdsHookCtx*, uint32_t addr) { return bus_read_u16(addr); }
uint8_t  nds_mod_read8 (NdsHookCtx*, uint32_t addr) { return bus_read_u8(addr); }
void nds_mod_write32(NdsHookCtx*, uint32_t addr, uint32_t value) {
    bus_write_u32(addr, value);
}
void nds_mod_write16(NdsHookCtx*, uint32_t addr, uint16_t value) {
    bus_write_u16(addr, value);
}
void nds_mod_write8(NdsHookCtx*, uint32_t addr, uint8_t value) {
    bus_write_u8(addr, value);
}

extern "C" int runtime_hook_enter(NdsHookSlot* slot) {
    const int cpu = static_cast<int>(g_nds_active);
    const uint32_t entry_sp = g_cpu.R[13];
    const uint32_t entry_lr = g_cpu.R[14];

    LastEnter& last = g_last_enter[cpu];
    if (last.valid && last.slot == slot && last.entry_sp == entry_sp &&
        last.insn_count == g_insn_count[cpu]) {
        ++g_diag.dup_suppressed;
        return 0;  // the yield-before-progress re-entry; let the body run
    }
    last.slot = slot;
    last.entry_sp = entry_sp;
    last.insn_count = g_insn_count[cpu];
    last.valid = true;
    ++g_diag.enter_calls;

    NdsHookCtx ctx{g_cpu.R, &g_cpu.cpsr, cpu, slot->bank, slot->addr,
                   entry_lr, entry_sp};
    auto enter_fn = reinterpret_cast<NdsHookResult (*)(NdsHookCtx*)>(
        slot->enter_fn);
    const NdsHookResult result = enter_fn ? enter_fn(&ctx) : NDS_HOOK_CONTINUE;

    if (result == NDS_HOOK_HANDLED) {
        ++g_diag.handled;
        // Perform the guest return exactly as `bx lr` would: CPSR.T from
        // bit 0 (both ARM9/v5 and ARM7/v4T interwork identically on BX),
        // PC masked accordingly. entry_lr already carries the tag (see the
        // Watch comment above).
        const bool thumb = (entry_lr & 1u) != 0u;
        g_cpu.R[15] = entry_lr & (thumb ? ~1u : ~3u);
        if (thumb) g_cpu.cpsr |= CPSR_T_BIT; else g_cpu.cpsr &= ~CPSR_T_BIT;
        // Pop the call-return-stack entry this call's own push left behind,
        // exactly as the generated `bx lr` this replaces would have done
        // (runtime_call_should_return is idempotent-safe to call even when
        // nothing matches -- constraint 3, the CRS is an advisory fast path,
        // not an authoritative pairing). This keeps the direct-call caller's
        // own `if (g_cpu.R[15] != return_pc)` check consistent: entry_lr IS
        // that literal return_pc, so the check passes and the caller simply
        // continues, never seeing that the body never ran.
        //
        // This invocation's own leave runs first: runtime_call_should_return
        // is a return choke point, so it may fire the watch of an enclosing
        // hooked function that tail-called into this one, and that outer
        // leave must observe the state this one leaves behind.
        Watch synthetic{slot, entry_lr, entry_sp};
        fire_leave(synthetic);
        runtime_call_should_return(g_cpu.R[15]);
        return 1;
    }

    // CONTINUE: the original body is about to run (with whatever the
    // handler changed already in place). Only watch for the return if
    // something wants to observe it.
    if (slot->leave_fn) push_watch(cpu, slot, entry_lr, entry_sp);
    return 0;
}

void nds_mod_hooks_check_return_slow(uint32_t pc) {
    const int cpu = static_cast<int>(g_nds_active);
    const uint32_t key = observed_key(pc);
    const uint32_t sp = g_cpu.R[13];
    WatchStack& st = g_watch[cpu];
    // Innermost-first: search from the top (most recently pushed) down, so
    // two watches on the same function (recursion) fire in the order their
    // calls actually return, not registration order.
    for (unsigned i = st.depth; i-- > 0; ) {
        const Watch w = st.items[i];
        if (w.return_key != key || w.entry_sp != sp) continue;
        // Match: remove exactly this watch and keep every other one, in
        // order. Watches above it are NOT evidence of abandoned frames: the
        // guest OS switches threads, so a later-pushed watch can belong to a
        // different thread that is merely blocked inside its hooked function,
        // on a stack that may sit at a lower address than this one. Dropping
        // by SP comparison would silently lose that thread's leave. A watch
        // whose call really was abandoned (longjmp-style unwind, killed
        // thread) simply ages out through the bounded stack's eviction.
        for (unsigned j = i + 1; j < st.depth; ++j) st.items[j - 1] = st.items[j];
        --st.depth;
        g_nds_mod_watch_armed[cpu] = st.depth != 0;
        fire_leave(w);
        return;
    }
}

void nds_mod_hooks_report(std::FILE* out) {
    if (g_tables.empty() && g_diag.registrations_failed == 0) return;
    std::fprintf(out,
        "\n== mod hooks (%zu bank table%s registered) ==\n"
        "  enter calls=%llu handled=%llu leave fired=%llu\n"
        "  duplicate-entry suppressed=%llu\n"
        "  watches pushed=%llu evicted=%llu\n"
        "  registrations failed=%llu\n",
        g_tables.size(), g_tables.size() == 1u ? "" : "s",
        g_diag.enter_calls, g_diag.handled, g_diag.leave_fired,
        g_diag.dup_suppressed, g_diag.watch_pushed, g_diag.watch_evicted,
        g_diag.registrations_failed);
}

unsigned nds_mod_hooks_test_watch_depth(int cpu) {
    return g_watch[cpu].depth;
}

void nds_mod_hooks_test_reset() {
    g_tables.clear();
    g_last_enter[0] = LastEnter{};
    g_last_enter[1] = LastEnter{};
    g_watch[0] = WatchStack{};
    g_watch[1] = WatchStack{};
    g_nds_mod_watch_armed[0] = false;
    g_nds_mod_watch_armed[1] = false;
    g_diag = Diagnostics{};
}
