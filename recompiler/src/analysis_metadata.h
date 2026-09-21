// analysis_metadata.h — machine-readable per-function analysis sidecar.
//
// `nds_recompile --analysis-json` writes <out>/<bank>_analysis.json next to
// the generated bank. It describes each emitted function the way a reader
// (human, script, or LLM) needs in order to navigate low-level generated C:
// identity, CFG, direct/indirect control transfers, SWIs, and the memory
// addresses the function statically reads and writes.
//
// The sidecar is OBSERVATIONAL ONLY. Nothing in codegen, dispatch, or the
// runtime consumes it, and enabling it changes no generated C byte. Its
// memory/indirect facts come from a best-effort constant propagation that
// assumes AAPCS call clobbers (r0-r3, r12, lr); treat them as evidence to
// combine with runtime traces, never as proof.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "function_finder.h"

namespace ndsrecomp {

struct AnalysisBankInfo {
    std::string bank;          // stable bank identity (FunctionId module part)
    std::string fn_prefix;     // C symbol prefix used by the bank header
    std::string program_id;
    std::string program_name;
    std::string image_sha1;
    uint32_t    load_address = 0;
    uint32_t    image_size = 0;
};

// Returns false (after printing to stderr) if the file cannot be written.
bool write_bank_analysis(const std::string& dir,
                         const AnalysisBankInfo& info,
                         const std::vector<Function>& funcs,
                         const uint8_t* rom, std::size_t rom_size,
                         uint32_t rom_base);

}  // namespace ndsrecomp
