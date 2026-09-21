// analysis_metadata.cpp — see analysis_metadata.h.
//
// Per function: walk the reachable instructions from the entry (so literal
// pools inside [addr, end) are never decoded as code), run a forward
// constant propagation to a fixpoint over that CFG, then report what the
// instructions do with the constants that reached them.

#include "analysis_metadata.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <deque>
#include <map>
#include <set>
#include <unordered_map>

#include "arm_decode.h"
#include "arm_ir.h"
#include "thumb_decode.h"

namespace ndsrecomp {

namespace {

using armv4t::Cond;
using armv4t::Instr;
using armv4t::IrOp;

// Constant-propagation lattice over r0-r14. R15 is never stored: its value
// is a function of the instruction address and is synthesized on read.
struct RegState {
    bool     reached = false;
    uint16_t known = 0;
    std::array<uint32_t, 16> v{};

    bool get(uint8_t r, uint32_t* out) const {
        if (r >= 15 || !(known & (1u << r))) return false;
        *out = v[r];
        return true;
    }
    void set(uint8_t r, uint32_t value) {
        if (r >= 15) return;
        known |= static_cast<uint16_t>(1u << r);
        v[r] = value;
    }
    void kill(uint8_t r) {
        if (r < 16) known &= static_cast<uint16_t>(~(1u << r));
    }
    void kill_mask(uint32_t mask) {
        known &= static_cast<uint16_t>(~mask);
    }
    // Meet `other` into this; returns true when this changed.
    bool meet(const RegState& other) {
        if (!reached) { *this = other; reached = true; return true; }
        uint16_t keep = known & other.known;
        for (uint8_t r = 0; r < 15; r++)
            if ((keep & (1u << r)) && v[r] != other.v[r])
                keep &= static_cast<uint16_t>(~(1u << r));
        if (keep == known) return false;
        known = keep;
        return true;
    }
};

constexpr uint32_t kCallClobber = 0x500Fu;  // r0-r3, r12, lr (AAPCS)
constexpr uint32_t kSwiClobber  = 0x000Fu;  // BIOS SWIs return in r0/r1/r3

struct Access   { uint32_t site, addr; uint8_t width; bool write; };
struct Literal  { uint32_t site, addr, value; };
struct Transfer { uint32_t site, target; bool thumb; };
struct Indirect { uint32_t site; const char* kind; bool resolved; uint32_t target; };
struct Swi      { uint32_t site, number; };

struct FunctionFacts {
    std::map<uint32_t, Instr> insns;                    // reachable, by pc
    std::map<uint32_t, std::vector<uint32_t>> succ;     // intra-function edges
    std::set<uint32_t> leaders;
    std::vector<Transfer> calls, tail_calls;
    std::vector<Indirect> indirect;
    std::vector<Swi> swis;
    std::vector<Access> accesses;
    std::vector<Literal> literals;
    unsigned returns = 0;
    unsigned undefined = 0;
    bool falls_through = false;
};

bool is_load(IrOp op) {
    switch (op) {
        case IrOp::LDR: case IrOp::LDRB: case IrOp::LDRH:
        case IrOp::LDRSB: case IrOp::LDRSH: case IrOp::LDRD:
            return true;
        default: return false;
    }
}

bool is_store(IrOp op) {
    switch (op) {
        case IrOp::STR: case IrOp::STRB: case IrOp::STRH: case IrOp::STRD:
            return true;
        default: return false;
    }
}

uint8_t access_width(IrOp op) {
    switch (op) {
        case IrOp::LDRB: case IrOp::STRB: case IrOp::LDRSB: return 1;
        case IrOp::LDRH: case IrOp::STRH: case IrOp::LDRSH: return 2;
        case IrOp::LDRD: case IrOp::STRD: return 8;
        default: return 4;
    }
}

bool is_dp_with_result(IrOp op) {
    switch (op) {
        case IrOp::AND: case IrOp::EOR: case IrOp::SUB: case IrOp::RSB:
        case IrOp::ADD: case IrOp::ADC: case IrOp::SBC: case IrOp::RSC:
        case IrOp::ORR: case IrOp::MOV: case IrOp::BIC: case IrOp::MVN:
            return true;
        default: return false;
    }
}

// Whether `ins` can redirect control. Derived from the operation itself: the
// decoders' is_pc_writing hint is not set on every Thumb branch form.
bool transfers_control(const Instr& ins) {
    if (ins.is_pc_writing || ins.is_branch || ins.is_return) return true;
    switch (ins.op) {
        case IrOp::B: case IrOp::BL: case IrOp::BX: case IrOp::BLX_reg:
        case IrOp::BLX_imm: case IrOp::BL_suffix:
            return true;
        case IrOp::LDM:
            return ins.block.load && (ins.block.reg_list & 0x8000u);
        default:
            break;
    }
    if (is_dp_with_result(ins.op) || is_load(ins.op)) return ins.rd == 15;
    return false;
}

const char* region_name(uint32_t a, bool arm9) {
    if (a >= 0xFFFF0000u) return "bios";
    switch (a >> 24) {
        case 0x00: case 0x01: return arm9 ? "itcm" : "bios";
        case 0x02: return "main_ram";
        case 0x03: return arm9 ? "shared_wram" : "wram";
        case 0x04: return "io";
        case 0x05: return "palette";
        case 0x06: return "vram";
        case 0x07: return "oam";
        case 0x08: case 0x09: case 0x0A: return "gba_slot";
        default: return "other";
    }
}

class FunctionAnalyzer {
public:
    FunctionAnalyzer(const Function& fn, const uint8_t* rom,
                     std::size_t rom_size, uint32_t rom_base)
        : fn_(fn), rom_(rom), rom_size_(rom_size), rom_base_(rom_base),
          thumb_(fn.mode == CpuMode::Thumb), step_(thumb_ ? 2u : 4u),
          source_(fn.source_addr ? fn.source_addr : fn.addr) {}

    FunctionFacts run() {
        discover();
        propagate();
        collect();
        return std::move(facts_);
    }

private:
    const Function& fn_;
    const uint8_t*  rom_;
    std::size_t     rom_size_;
    uint32_t        rom_base_;
    bool            thumb_;
    uint32_t        step_;
    uint32_t        source_;
    FunctionFacts   facts_;
    std::unordered_map<uint32_t, RegState> in_;

    bool inside(uint32_t pc) const {
        return pc >= fn_.addr && pc < fn_.end_addr;
    }

    // Guest address -> image offset, honoring a relocated body the same way
    // emit_function_body does (guest delta applied to the source address).
    bool offset_for(uint32_t guest, uint32_t len, std::size_t* out) const {
        int64_t src = static_cast<int64_t>(source_) +
            (static_cast<int64_t>(guest) - static_cast<int64_t>(fn_.addr));
        if (src < static_cast<int64_t>(rom_base_)) return false;
        uint64_t off = static_cast<uint64_t>(src - rom_base_);
        if (off + len > rom_size_) return false;
        *out = static_cast<std::size_t>(off);
        return true;
    }

    bool read_u16(uint32_t guest, uint16_t* out) const {
        std::size_t o = 0;
        if (!offset_for(guest, 2, &o)) return false;
        *out = static_cast<uint16_t>(rom_[o] | (rom_[o + 1] << 8));
        return true;
    }

    bool read_u32(uint32_t guest, uint32_t* out) const {
        std::size_t o = 0;
        if (!offset_for(guest, 4, &o)) return false;
        *out = static_cast<uint32_t>(rom_[o]) |
               (static_cast<uint32_t>(rom_[o + 1]) << 8) |
               (static_cast<uint32_t>(rom_[o + 2]) << 16) |
               (static_cast<uint32_t>(rom_[o + 3]) << 24);
        return true;
    }

    bool decode(uint32_t pc, Instr* out) const {
        if (thumb_) {
            uint16_t hw = 0;
            if (!read_u16(pc, &hw)) return false;
            *out = armv4t::ThumbDecoder::decode(hw, pc);
        } else {
            uint32_t w = 0;
            if (!read_u32(pc, &w)) return false;
            *out = armv4t::ArmDecoder::decode(w, pc);
        }
        return true;
    }

    // Thumb BL/BLX pair starting at `pc`: full target and callee mode.
    bool thumb_bl_pair(const Instr& prefix, uint32_t* target,
                       bool* target_thumb) const {
        if (!thumb_ || prefix.op != IrOp::BL_prefix) return false;
        Instr lower;
        if (!decode(prefix.pc + 2u, &lower) || lower.op != IrOp::BL_suffix)
            return false;
        const bool blx = lower.branch_exchange;
        uint32_t full = prefix.branch_target + lower.swi_imm;
        full &= blx ? ~uint32_t{3} : ~uint32_t{1};
        *target = full;
        *target_thumb = !blx;
        return true;
    }

    // Value of R15 as an operand at `pc`. Thumb PC-relative addressing
    // word-aligns it; ARM's pc+8 is already aligned.
    uint32_t pc_operand(uint32_t pc) const {
        return thumb_ ? ((pc + 4u) & ~uint32_t{3}) : pc + 8u;
    }

    bool reg_value(const RegState& s, uint8_t r, uint32_t pc,
                   uint32_t* out) const {
        if (r == 15) { *out = pc_operand(pc); return true; }
        return s.get(r, out);
    }

    bool shifted_value(const RegState& s, const armv4t::ShiftedRegister& sh,
                       uint32_t pc, uint32_t* out) const {
        uint32_t rm = 0;
        if (sh.by_register || !reg_value(s, sh.rm, pc, &rm)) return false;
        const uint32_t n = sh.imm_or_rs;
        switch (sh.type) {
            case armv4t::ShiftType::LSL:
                *out = n >= 32u ? 0u : rm << n; return true;
            case armv4t::ShiftType::LSR:
                if (n == 0u) return false;      // encodes LSR #32
                *out = rm >> n; return true;
            case armv4t::ShiftType::ASR:
                if (n == 0u) return false;      // encodes ASR #32
                *out = static_cast<uint32_t>(static_cast<int32_t>(rm) >> n);
                return true;
            default: return false;              // ROR/RRX need carry
        }
    }

    bool op2_value(const RegState& s, const Instr& ins, uint32_t* out) const {
        if (ins.op2.kind == armv4t::Op2::Kind::Imm) {
            *out = ins.op2.imm_value;
            return true;
        }
        return shifted_value(s, ins.op2.shifted, ins.pc, out);
    }

    // Effective address of a single load/store, when statically known.
    bool mem_address(const RegState& s, const Instr& ins, uint32_t* ea,
                     uint32_t* updated_base) const {
        uint32_t base = 0, offset = 0;
        if (!reg_value(s, ins.mem.rn, ins.pc, &base)) return false;
        if (ins.mem.by_register) {
            if (!shifted_value(s, ins.mem.reg_offset, ins.pc, &offset))
                return false;
        } else {
            offset = ins.mem.imm_offset;
        }
        const uint32_t indexed = ins.mem.add ? base + offset : base - offset;
        *ea = ins.mem.pre_indexed ? indexed : base;
        *updated_base = indexed;
        return true;
    }

    // ── pass 1: reachable instructions + intra-function edges ───────────
    void discover() {
        std::deque<uint32_t> work{fn_.addr};
        facts_.leaders.insert(fn_.addr);
        auto edge = [&](uint32_t from, uint32_t to, bool leader) {
            if (!inside(to)) { facts_.falls_through = true; return; }
            facts_.succ[from].push_back(to);
            if (leader) facts_.leaders.insert(to);
            if (!facts_.insns.count(to)) work.push_back(to);
        };
        while (!work.empty()) {
            const uint32_t pc = work.front();
            work.pop_front();
            if (facts_.insns.count(pc)) continue;
            Instr ins;
            if (!decode(pc, &ins)) continue;
            facts_.insns.emplace(pc, ins);
            facts_.succ[pc];
            if (ins.is_undefined) { ++facts_.undefined; continue; }

            const bool conditional = ins.cond != Cond::AL;
            uint32_t next = pc + step_;
            uint32_t target = 0;
            bool target_thumb = thumb_;

            if (thumb_bl_pair(ins, &target, &target_thumb)) {
                facts_.calls.push_back({pc, target, target_thumb});
                edge(pc, pc + 4u, false);
                continue;
            }
            switch (ins.op) {
                case IrOp::B:
                    if (inside(ins.branch_target))
                        edge(pc, ins.branch_target, true);
                    else
                        facts_.tail_calls.push_back(
                            {pc, ins.branch_target, thumb_});
                    if (conditional) edge(pc, next, true);
                    continue;
                case IrOp::BL:
                    facts_.calls.push_back({pc, ins.branch_target, thumb_});
                    edge(pc, next, false);
                    continue;
                case IrOp::BLX_imm:
                    facts_.calls.push_back({pc, ins.branch_target, !thumb_});
                    edge(pc, next, false);
                    continue;
                case IrOp::SWI:                 // returns to the next insn
                    edge(pc, next, false);
                    continue;
                default:
                    break;
            }
            // Register/computed transfers are classified in collect(), where
            // the propagated constants are available. Here only the shape of
            // the CFG matters: calls and conditionals continue, the rest end.
            const bool computed_call =
                ins.op == IrOp::BLX_reg || ins.op == IrOp::BL_suffix;
            if (transfers_control(ins) && !computed_call) {
                if (conditional) edge(pc, next, true);
                continue;
            }
            edge(pc, next, false);
        }
    }

    // ── pass 2: constant propagation to a fixpoint ──────────────────────
    void transfer(const Instr& ins, RegState& s) const {
        if (ins.is_undefined) return;
        const bool conditional = ins.cond != Cond::AL;
        // A conditionally executed write leaves the register holding either
        // value, so it can only ever lose knowledge.
        auto define = [&](uint8_t rd, bool have, uint32_t value) {
            if (have && !conditional) s.set(rd, value); else s.kill(rd);
        };

        if (is_dp_with_result(ins.op)) {
            uint32_t a = 0, b = 0, r = 0;
            const bool hb = op2_value(s, ins, &b);
            const bool ha = reg_value(s, ins.rn, ins.pc, &a);
            bool ok = false;
            switch (ins.op) {
                case IrOp::MOV: ok = hb; r = b; break;
                case IrOp::MVN: ok = hb; r = ~b; break;
                case IrOp::ADD: ok = ha && hb; r = a + b; break;
                case IrOp::SUB: ok = ha && hb; r = a - b; break;
                case IrOp::RSB: ok = ha && hb; r = b - a; break;
                case IrOp::AND: ok = ha && hb; r = a & b; break;
                case IrOp::ORR: ok = ha && hb; r = a | b; break;
                case IrOp::EOR: ok = ha && hb; r = a ^ b; break;
                case IrOp::BIC: ok = ha && hb; r = a & ~b; break;
                default: break;                 // ADC/SBC/RSC need carry
            }
            define(ins.rd, ok, r);
            return;
        }
        if (is_load(ins.op) || is_store(ins.op)) {
            uint32_t ea = 0, new_base = 0;
            const bool known = mem_address(s, ins, &ea, &new_base);
            const bool wb = ins.mem.writeback || !ins.mem.pre_indexed;
            if (wb) define(ins.mem.rn, known, new_base);
            if (is_load(ins.op)) {
                uint32_t value = 0;
                const bool literal = known && ins.op == IrOp::LDR &&
                    ins.mem.rn == 15 && read_u32(ea, &value);
                define(ins.rd, literal, value);
                if (ins.op == IrOp::LDRD)
                    s.kill(static_cast<uint8_t>(ins.rd + 1u));
            }
            return;
        }
        switch (ins.op) {
            case IrOp::LDM: case IrOp::STM:
                if (ins.block.load) s.kill_mask(ins.block.reg_list);
                if (ins.block.writeback) s.kill(ins.block.rn);
                return;
            case IrOp::UMULL: case IrOp::UMLAL: case IrOp::SMULL:
            case IrOp::SMLAL: case IrOp::SMLALxy:
                s.kill(ins.rd); s.kill(ins.rn);   // RdHi / RdLo
                return;
            case IrOp::BL: case IrOp::BLX_imm: case IrOp::BLX_reg:
            case IrOp::BL_prefix: case IrOp::BL_suffix:
                s.kill_mask(kCallClobber);
                return;
            case IrOp::SWI:
                s.kill_mask(kSwiClobber);
                return;
            case IrOp::TST: case IrOp::TEQ: case IrOp::CMP: case IrOp::CMN:
            case IrOp::B: case IrOp::BX: case IrOp::MSR: case IrOp::MCR:
            case IrOp::CDP: case IrOp::PLD:
                return;
            default:
                s.kill(ins.rd);                   // MUL/CLZ/Q*/SM*/MRS/MRC/SWP
                return;
        }
    }

    void propagate() {
        RegState entry;
        entry.reached = true;
        in_[fn_.addr] = entry;
        std::deque<uint32_t> work{fn_.addr};
        while (!work.empty()) {
            const uint32_t pc = work.front();
            work.pop_front();
            auto found = facts_.insns.find(pc);
            if (found == facts_.insns.end()) continue;   // undecodable edge
            RegState out = in_[pc];
            transfer(found->second, out);
            for (uint32_t to : facts_.succ[pc])
                if (in_[to].meet(out)) work.push_back(to);
        }
    }

    // ── pass 3: report ──────────────────────────────────────────────────
    void collect() {
        for (const auto& [pc, ins] : facts_.insns) {
            if (ins.is_undefined) continue;
            const RegState& s = in_[pc];
            if (ins.op == IrOp::SWI) {
                facts_.swis.push_back({pc, ins.swi_imm});
                continue;
            }
            if (is_load(ins.op) || is_store(ins.op)) {
                uint32_t ea = 0, unused = 0;
                if (mem_address(s, ins, &ea, &unused)) {
                    uint32_t value = 0;
                    if (ins.mem.rn == 15 && is_load(ins.op)) {
                        if (ins.op == IrOp::LDR && read_u32(ea, &value))
                            facts_.literals.push_back({pc, ea, value});
                    } else {
                        facts_.accesses.push_back(
                            {pc, ea, access_width(ins.op), is_store(ins.op)});
                    }
                }
            }
            const bool pair_prefix = ins.op == IrOp::BL_prefix;
            if (!transfers_control(ins) || pair_prefix) continue;
            if (ins.op == IrOp::B || ins.op == IrOp::BL ||
                ins.op == IrOp::BLX_imm) continue;
            if (ins.op == IrOp::BL_suffix) {
                // Only reached standalone when the prefix half is not the
                // preceding reachable instruction (a split BL pair).
                auto prev = facts_.insns.find(pc - 2u);
                if (prev != facts_.insns.end() &&
                    prev->second.op == IrOp::BL_prefix) continue;
            }
            if (ins.is_return) { ++facts_.returns; continue; }
            uint32_t target = 0;
            bool resolved = false;
            if (ins.op == IrOp::BX || ins.op == IrOp::BLX_reg)
                resolved = s.get(ins.rm, &target);
            else if (ins.op == IrOp::MOV)
                resolved = op2_value(s, ins, &target);
            const bool call =
                ins.op == IrOp::BLX_reg || ins.op == IrOp::BL_suffix;
            facts_.indirect.push_back(
                {pc, call ? "call" : "jump", resolved, target});
        }
    }
};

// ── JSON emission ───────────────────────────────────────────────────────

std::string json_escape(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        } else out += static_cast<char>(c);
    }
    return out;
}

std::string hex(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", v);
    return buf;
}

struct BankIndex {
    const AnalysisBankInfo& info;
    std::map<uint32_t, const Function*> by_addr;

    std::string id(uint32_t addr) const { return info.bank + ":" + hex(addr); }

    // FunctionId of the function that starts exactly at `addr`, as a JSON
    // value. A target owned by another bank (or an interior address) is
    // null here; the raw address is always emitted alongside.
    std::string target_id_json(uint32_t addr) const {
        return by_addr.count(addr) ? "\"" + id(addr) + "\"" : "null";
    }
};

void emit_transfers(std::FILE* f, const char* key,
                    const std::vector<Transfer>& list, const BankIndex& idx) {
    std::fprintf(f, "      \"%s\": [", key);
    for (std::size_t i = 0; i < list.size(); i++) {
        const Transfer& t = list[i];
        std::fprintf(f,
            "%s\n        {\"site\": \"%s\", \"target\": \"%s\", "
            "\"target_mode\": \"%s\", \"target_id\": %s}",
            i ? "," : "", hex(t.site).c_str(), hex(t.target).c_str(),
            t.thumb ? "thumb" : "arm", idx.target_id_json(t.target).c_str());
    }
    std::fprintf(f, "%s],\n", list.empty() ? "" : "\n      ");
}

void emit_accesses(std::FILE* f, const char* key, bool write,
                   const std::vector<Access>& all, bool arm9) {
    // One row per distinct (address, width); sites are aggregated.
    std::map<std::pair<uint32_t, uint8_t>, std::vector<uint32_t>> rows;
    for (const Access& a : all)
        if (a.write == write) rows[{a.addr, a.width}].push_back(a.site);
    std::fprintf(f, "      \"%s\": [", key);
    bool first = true;
    for (const auto& [k, sites] : rows) {
        std::fprintf(f,
            "%s\n        {\"addr\": \"%s\", \"width\": %u, "
            "\"region\": \"%s\", \"sites\": [",
            first ? "" : ",", hex(k.first).c_str(), k.second,
            region_name(k.first, arm9));
        for (std::size_t i = 0; i < sites.size(); i++)
            std::fprintf(f, "%s\"%s\"", i ? ", " : "", hex(sites[i]).c_str());
        std::fprintf(f, "]}");
        first = false;
    }
    std::fprintf(f, "%s],\n", rows.empty() ? "" : "\n      ");
}

}  // namespace

bool write_bank_analysis(const std::string& dir,
                         const AnalysisBankInfo& info,
                         const std::vector<Function>& funcs,
                         const uint8_t* rom, std::size_t rom_size,
                         uint32_t rom_base) {
    const std::string path = dir + "/" + info.bank + "_analysis.json";
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        std::fprintf(stderr, "cannot write %s\n", path.c_str());
        return false;
    }
    // Bank names carry the owning core by project convention (the runner
    // classifies dispatch tables the same way).
    const bool arm7 = info.bank.find("arm7") != std::string::npos;
    const bool arm9 = !arm7;

    BankIndex idx{info, {}};
    for (const Function& fn : funcs) idx.by_addr.emplace(fn.addr, &fn);

    std::vector<FunctionFacts> facts;
    facts.reserve(funcs.size());
    std::map<uint32_t, std::set<uint32_t>> callers;   // callee -> caller addrs
    for (const Function& fn : funcs) {
        facts.push_back(FunctionAnalyzer(fn, rom, rom_size, rom_base).run());
        const FunctionFacts& ff = facts.back();
        auto note = [&](uint32_t target) {
            if (idx.by_addr.count(target)) callers[target].insert(fn.addr);
        };
        for (const Transfer& t : ff.calls) note(t.target);
        for (const Transfer& t : ff.tail_calls) note(t.target);
        for (const Indirect& i : ff.indirect) if (i.resolved) note(i.target & ~1u);
    }

    std::fprintf(f,
        "{\n"
        "  \"schema\": \"ndsrecomp.analysis/1\",\n"
        "  \"bank\": \"%s\",\n"
        "  \"cpu\": \"%s\",\n"
        "  \"program_id\": \"%s\",\n"
        "  \"program_name\": \"%s\",\n"
        "  \"image_sha1\": \"%s\",\n"
        "  \"load_address\": \"%s\",\n"
        "  \"image_size\": %u,\n"
        "  \"function_count\": %zu,\n"
        "  \"functions\": [",
        json_escape(info.bank).c_str(), arm7 ? "arm7" : "arm9",
        json_escape(info.program_id).c_str(),
        json_escape(info.program_name).c_str(),
        json_escape(info.image_sha1).c_str(),
        hex(info.load_address).c_str(), info.image_size, funcs.size());

    for (std::size_t n = 0; n < funcs.size(); n++) {
        const Function& fn = funcs[n];
        const FunctionFacts& ff = facts[n];
        std::fprintf(f,
            "%s\n    {\n"
            "      \"id\": \"%s\",\n"
            "      \"addr\": \"%s\",\n"
            "      \"end\": \"%s\",\n"
            "      \"mode\": \"%s\",\n"
            "      \"name\": \"%s\",\n"
            "      \"symbol\": \"%s\",\n",
            n ? "," : "", idx.id(fn.addr).c_str(), hex(fn.addr).c_str(),
            hex(fn.end_addr).c_str(),
            fn.mode == CpuMode::Thumb ? "thumb" : "arm",
            json_escape(fn.name).c_str(),
            json_escape(info.fn_prefix + fn.name).c_str());
        if (fn.source_addr && fn.source_addr != fn.addr)
            std::fprintf(f, "      \"source_addr\": \"%s\",\n",
                         hex(fn.source_addr).c_str());
        std::fprintf(f,
            "      \"reachable_insns\": %zu,\n"
            "      \"returns\": %u,\n"
            "      \"undefined_insns\": %u,\n"
            "      \"falls_through_to\": %s,\n",
            ff.insns.size(), ff.returns, ff.undefined,
            ff.falls_through
                ? ("{\"target\": \"" + hex(fn.end_addr) + "\", \"target_id\": " +
                   idx.target_id_json(fn.end_addr) + "}").c_str()
                : "null");

        emit_transfers(f, "calls", ff.calls, idx);
        emit_transfers(f, "tail_calls", ff.tail_calls, idx);

        std::fprintf(f, "      \"indirect\": [");
        for (std::size_t i = 0; i < ff.indirect.size(); i++) {
            const Indirect& in = ff.indirect[i];
            std::fprintf(f, "%s\n        {\"site\": \"%s\", \"kind\": \"%s\"",
                         i ? "," : "", hex(in.site).c_str(), in.kind);
            if (in.resolved)
                std::fprintf(f,
                    ", \"target\": \"%s\", \"target_mode\": \"%s\", "
                    "\"target_id\": %s",
                    hex(in.target & ~1u).c_str(),
                    (in.target & 1u) ? "thumb" : "arm",
                    idx.target_id_json(in.target & ~1u).c_str());
            std::fprintf(f, "}");
        }
        std::fprintf(f, "%s],\n", ff.indirect.empty() ? "" : "\n      ");

        std::fprintf(f, "      \"swis\": [");
        for (std::size_t i = 0; i < ff.swis.size(); i++)
            std::fprintf(f, "%s{\"site\": \"%s\", \"number\": %u}",
                         i ? ", " : "", hex(ff.swis[i].site).c_str(),
                         ff.swis[i].number);
        std::fprintf(f, "],\n");

        emit_accesses(f, "reads", false, ff.accesses, arm9);
        emit_accesses(f, "writes", true, ff.accesses, arm9);

        // Literal-pool constants, deduplicated by value. These are where
        // global pointers and hardware register bases enter a function.
        std::map<uint32_t, std::vector<uint32_t>> lits;
        for (const Literal& l : ff.literals) lits[l.value].push_back(l.site);
        std::fprintf(f, "      \"literals\": [");
        bool first = true;
        for (const auto& [value, sites] : lits) {
            std::fprintf(f,
                "%s\n        {\"value\": \"%s\", \"region\": \"%s\", "
                "\"target_id\": %s, \"sites\": [",
                first ? "" : ",", hex(value).c_str(),
                region_name(value, arm9),
                idx.target_id_json(value & ~1u).c_str());
            for (std::size_t i = 0; i < sites.size(); i++)
                std::fprintf(f, "%s\"%s\"", i ? ", " : "",
                             hex(sites[i]).c_str());
            std::fprintf(f, "]}");
            first = false;
        }
        std::fprintf(f, "%s],\n", lits.empty() ? "" : "\n      ");

        // Basic blocks: a leader starts one; it runs until the next leader,
        // a gap (literal pool / unreachable bytes), or a multi-way edge.
        std::fprintf(f, "      \"blocks\": [");
        first = true;
        for (auto it = ff.insns.begin(); it != ff.insns.end();) {
            const uint32_t start = it->first;
            uint32_t last = start;
            auto cur = it;
            for (;;) {
                last = cur->first;
                auto next = std::next(cur);
                const auto& out = ff.succ.at(last);
                const bool linear = next != ff.insns.end() &&
                    out.size() == 1u && out[0] == next->first &&
                    !ff.leaders.count(next->first);
                cur = next;
                if (!linear) break;
            }
            const uint32_t width =
                (ff.insns.at(last).op == IrOp::BL_prefix) ? 4u
                : (fn.mode == CpuMode::Thumb ? 2u : 4u);
            std::fprintf(f, "%s\n        {\"start\": \"%s\", \"end\": \"%s\", "
                            "\"succ\": [",
                         first ? "" : ",", hex(start).c_str(),
                         hex(last + width).c_str());
            const auto& out = ff.succ.at(last);
            for (std::size_t i = 0; i < out.size(); i++)
                std::fprintf(f, "%s\"%s\"", i ? ", " : "", hex(out[i]).c_str());
            std::fprintf(f, "]}");
            first = false;
            it = cur;
        }
        std::fprintf(f, "%s],\n", ff.insns.empty() ? "" : "\n      ");

        std::fprintf(f, "      \"callers\": [");
        auto found = callers.find(fn.addr);
        if (found != callers.end()) {
            std::size_t i = 0;
            for (uint32_t caller : found->second)
                std::fprintf(f, "%s\"%s\"", i++ ? ", " : "",
                             idx.id(caller).c_str());
        }
        std::fprintf(f, "]\n    }");
    }
    std::fprintf(f, "%s]\n}\n", funcs.empty() ? "" : "\n  ");
    std::fclose(f);
    std::printf("[analysis] %zu functions -> %s\n", funcs.size(), path.c_str());
    return true;
}

}  // namespace ndsrecomp
