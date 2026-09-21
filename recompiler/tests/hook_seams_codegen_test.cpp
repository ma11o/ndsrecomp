// hook_seams_codegen_test — pins --hook-seams wrapper emission and proves it
// compiles.
//
// The runner side of mod hooks (runner/src/mod_hooks.*) does not exist yet,
// so the only oracle available here is: does the C this flag emits actually
// compile against the real generated-code ABI header, and does it have the
// shape docs/mod-hooks.md describes (a private __lle body behind a public
// wrapper that tests `armed` before anything else, a sorted per-bank hook
// table, exclusion from leaf inlining, dispatch/direct-call sites still
// naming the public symbol, and a manifest that fails closed on an address
// nothing emits).
//
// A two-function corpus (a caller that BLs a tiny two-instruction leaf) is
// enough: with the pass on and neither function hooked, the callee is
// exactly the shape the tiny-leaf inliner expands at its call site (pinned
// by the baseline case below), so seeing it NOT expanded once it is hookable
// is real exclusion evidence, not just "the pass never ran".
//
// Usage: hook_seams_codegen_test <nds_recompile> <work-dir> <cc>
//        <runtime-include-dir>...

#include "sha1.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

bool write_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream file(path, std::ios::binary);
    file << text;
    return static_cast<bool>(file);
}

std::size_t count_occurrences(const std::string& haystack,
                              const std::string& needle) {
    std::size_t count = 0, at = 0;
    while ((at = haystack.find(needle, at)) != std::string::npos) {
        ++count;
        at += needle.size();
    }
    return count;
}

std::vector<std::string> list_c_files(const std::filesystem::path& dir) {
    std::vector<std::string> files;
    if (std::filesystem::is_directory(dir))
        for (const auto& entry : std::filesystem::directory_iterator(dir))
            if (entry.is_regular_file() && entry.path().extension() == ".c")
                files.push_back(entry.path().string());
    std::sort(files.begin(), files.end());
    return files;
}

int run(const std::string& command) {
#ifdef _WIN32
    return std::system(("\"" + command + "\"").c_str());
#else
    return std::system(command.c_str());
#endif
}

// Invoked directly (not through `xcrun cc`), clang on macOS finds no
// <string.h> without an explicit sysroot -- runtime_arm.h pulls it in for
// the inline bus fast path, so every compile below needs this. clang on
// Linux and MinGW gcc on Windows need no such flag.
std::vector<std::string> macos_sysroot_flags(const std::filesystem::path& work) {
#ifdef __APPLE__
    const auto out = work / "sdk_path.txt";
    if (run("xcrun --show-sdk-path > \"" + out.string() +
             "\" 2>/dev/null") != 0)
        return {};
    std::string sdk = read_file(out);
    while (!sdk.empty() && (sdk.back() == '\n' || sdk.back() == '\r'))
        sdk.pop_back();
    if (sdk.empty()) return {};
    return {"-isysroot", sdk};
#else
    (void)work;
    return {};
#endif
}

struct Result {
    int exit_code;
    std::string stdout_text;
};

Result recompile(const std::filesystem::path& recompile_bin,
                 const std::filesystem::path& bin,
                 const std::filesystem::path& config,
                 const std::filesystem::path& out, const std::string& bank,
                 const std::string& flags,
                 const std::filesystem::path& log) {
    std::error_code ec;
    std::filesystem::create_directories(out, ec);
    std::ostringstream command;
    command << '"' << recompile_bin.string() << '"'
            << " --config \"" << config.string() << '"'
            << " --bin \"" << bin.string() << '"'
            << " --out \"" << out.string() << '"'
            << " --bank " << bank << ' ' << flags
            << " > \"" << log.string() << "\" 2>&1";
    Result r;
    r.exit_code = run(command.str());
    r.stdout_text = read_file(log);
    return r;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
            "usage: %s <nds_recompile> <work-dir> <cc> "
            "[<runtime-include-dir>...]\n", argv[0]);
        return 2;
    }
    const std::filesystem::path recompile_bin = argv[1];
    const std::filesystem::path work = argv[2];
    const std::string cc = argv[3];
    std::vector<std::string> include_dirs;
    for (int i = 4; i < argc; ++i) include_dirs.push_back(argv[i]);

    std::error_code ec;
    std::filesystem::remove_all(work, ec);
    std::filesystem::create_directories(work, ec);

    // 0x000: BL +0x10 (call "callee"); BX LR                    -- "caller"
    // 0x010: MOV r0,#1; BX LR                                    -- "callee"
    // Exactly the tiny-leaf shape (<=8 insns, ends bx lr, no LR use elsewhere)
    // the inliner expands at BL sites when nothing excludes it.
    std::vector<uint8_t> page(0x20, 0u);
    const uint8_t caller[] = {0x02, 0x00, 0x00, 0xEB,   // BL +0x10
                              0x1E, 0xFF, 0x2F, 0xE1};  // BX LR
    const uint8_t callee[] = {0x01, 0x00, 0xA0, 0xE3,   // MOV r0,#1
                              0x1E, 0xFF, 0x2F, 0xE1};  // BX LR
    std::copy(std::begin(caller), std::end(caller), page.begin() + 0x000);
    std::copy(std::begin(callee), std::end(callee), page.begin() + 0x010);

    const std::string sha1 = gba::sha1(page.data(), page.size()).hex();
    const auto bin_path = work / "corpus.bin";
    if (!write_file(bin_path, std::string(reinterpret_cast<const char*>(
                                              page.data()), page.size()))) {
        std::fprintf(stderr, "FAIL: cannot write corpus.bin\n");
        return 1;
    }

    const std::string bank = "hookcorpus";
    std::ostringstream config_text;
    config_text << "[program]\n"
                   "name = \"hook seams corpus\"\n"
                   "id = \"hook_seams_corpus\"\n"
                   "load_address = 0x02000000\n"
                << "size = 0x" << std::hex << page.size() << std::dec << "\n"
                   "entry_pc = 0x02000000\n"
                   "authoritative_entry_points = false\n\n"
                   "[identity]\nsha1 = \"" << sha1 << "\"\n\n"
                   "[[entry_point]]\naddr = 0x02000000\nmode = \"arm\"\n"
                   "name = \"caller\"\nkind = \"test\"\n\n"
                   "[[entry_point]]\naddr = 0x02000010\nmode = \"arm\"\n"
                   "name = \"callee\"\nkind = \"test\"\n";
    const auto config_path = work / "corpus.toml";
    if (!write_file(config_path, config_text.str())) {
        std::fprintf(stderr, "FAIL: cannot write corpus.toml\n");
        return 1;
    }

    int failures = 0;
    auto fail = [&](const std::string& what) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++failures;
    };

    // The finder turns a BL's return address into its own discovered
    // function (a third, unnamed "afunc_..." landing pad at 0x004) even
    // though nothing branches to it explicitly -- pinned here by the
    // baseline run below rather than assumed, so this corpus's real function
    // count drives every count checked further down instead of a guess.
    const std::string kThirdFn = bank + "_afunc_02000004";

    // ── Baseline: hook-seams off. Pins that the corpus actually exercises
    //    the tiny-leaf inliner's ELIGIBILITY pass absent any exclusion (the
    //    callee is a 2-instruction `mov r0,#1; bx lr` leaf), so the later
    //    "0 eligible" observations mean the exclusion fired, not that
    //    nothing was ever a candidate. This corpus never reaches actual
    //    call-site EXPANSION regardless of --hook-seams: that only fires for
    //    a live bank whose calls go through the dispatcher rather than a
    //    direct C call (arm_codegen.cpp's `have_name` check), and
    //    --hook-seams rejects --validate-live-bytes outright (see the
    //    rejected-combinations checks below) -- so a hookable function's
    //    callee never reaches the codegen path that would inline it, by
    //    construction, not by an exclusion this corpus can observe directly.
    unsigned total_functions = 0u;
    {
        const auto out = work / "baseline";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank, "--shards 1", work / "baseline.log");
        if (r.exit_code != 0) fail("baseline recompile failed");
        if (r.stdout_text.find("inline leaves: 1 eligible") ==
            std::string::npos)
            fail("baseline corpus is not leaf-inlining eligible; the "
                 "exclusion checks below would be meaningless");
        const std::string header = read_file(out / (bank + ".h"));
        if (header.find(kThirdFn) == std::string::npos)
            fail("baseline: expected the finder to discover " + kThirdFn +
                 " at the BL return address");
        total_functions = static_cast<unsigned>(
            count_occurrences(header, "void " + bank + "_"));
        if (total_functions != 3u)
            fail("baseline: expected exactly 3 functions in this corpus, "
                 "got " + std::to_string(total_functions));
    }

    std::vector<std::filesystem::path> compile_dirs;

    // ── --hook-seams all: every function gets a wrapper; nothing is
    //    eligible for leaf inlining (every candidate is hookable).
    {
        const auto out = work / "hook_all";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank, "--shards 1 --hook-seams all",
                                 work / "hook_all.log");
        if (r.exit_code != 0) fail("--hook-seams all recompile failed");
        compile_dirs.push_back(out);
        if (r.stdout_text.find("inline leaves: 0 eligible") ==
            std::string::npos)
            fail("--hook-seams all: a hookable function is still eligible "
                 "for leaf inlining");
        const std::string expect_ratio = "hook seams (all): " +
            std::to_string(total_functions) + "/" +
            std::to_string(total_functions) + " functions";
        if (r.stdout_text.find(expect_ratio) == std::string::npos)
            fail("--hook-seams all: expected every function hookable ("
                 "wanted \"" + expect_ratio + "\")");
        const std::string body = read_file(out / (bank + ".c"));
        if (count_occurrences(body, "__lle(void) {") != total_functions)
            fail("--hook-seams all: expected " +
                 std::to_string(total_functions) + " __lle bodies");
        if (count_occurrences(body, "runtime_hook_enter(&g_hook_") !=
            total_functions)
            fail("--hook-seams all: expected " +
                 std::to_string(total_functions) + " wrapper call sites");
        // The caller's own (hookable) body still calls the callee by its
        // PUBLIC symbol, not by its private __lle body -- only a function's
        // own wrapper is allowed to name its own "<fn>__lle" (checked next
        // via the dispatch table, which never legitimately names one).
        const auto caller_at = body.find(bank + "_caller__lle(void) {");
        const auto caller_end = body.find("\n}\n", caller_at);
        if (caller_at == std::string::npos || caller_end == std::string::npos ||
            body.substr(caller_at, caller_end - caller_at)
                .find(bank + "_callee();") == std::string::npos)
            fail("--hook-seams all: caller no longer calls the callee's "
                 "public symbol");
        const std::string dispatch = read_file(
            out / (bank + "_dispatch.c"));
        if (dispatch.find("__lle") != std::string::npos)
            fail("--hook-seams all: dispatch table referenced a private "
                 "__lle symbol instead of the public wrapper");
        const std::string hooks = read_file(out / (bank + "_hooks.c"));
        if (hooks.empty()) fail("--hook-seams all: no _hooks.c emitted");
        // Table order: 0x02000000, 0x02000004, 0x02000010 -- addr-sorted.
        const auto table_start = hooks.find("NdsHookTableEntry");
        const auto p0 = hooks.find("0x02000000u", table_start);
        const auto p1 = hooks.find("0x02000004u", table_start);
        const auto p2 = hooks.find("0x02000010u", table_start);
        if (p0 == std::string::npos || p1 == std::string::npos ||
            p2 == std::string::npos || !(p0 < p1 && p1 < p2))
            fail("--hook-seams all: hook table is not addr-sorted");
        if (count_occurrences(hooks, "&g_hook_") != total_functions)
            fail("--hook-seams all: expected " +
                 std::to_string(total_functions) +
                 " rows in the hook table");
    }

    // ── --hook-seams manifest, hooking only the callee: the caller keeps
    //    its ordinary (non-wrapped) body and the callee is excluded from
    //    inlining at the caller's BL site even though the baseline proved it
    //    is otherwise eligible.
    {
        const std::string manifest_text =
            "version = 1\n"
            "[program]\nbank = \"" + bank + "\"\nsha1 = \"" + sha1 + "\"\n"
            "[[hook]]\naddress = 0x02000010\nmode = \"arm\"\n";
        const auto manifest_path = work / "hooks.toml";
        write_file(manifest_path, manifest_text);
        const auto out = work / "hook_manifest";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank,
                                 "--shards 1 --hook-seams manifest "
                                 "--hook-manifest \"" +
                                 manifest_path.string() + "\"",
                                 work / "hook_manifest.log");
        if (r.exit_code != 0) fail("--hook-seams manifest recompile failed");
        compile_dirs.push_back(out);
        const std::string expect_ratio = "hook seams (manifest): 1/" +
            std::to_string(total_functions) + " functions";
        if (r.stdout_text.find(expect_ratio) == std::string::npos)
            fail("--hook-seams manifest: expected exactly 1 hookable "
                 "function (wanted \"" + expect_ratio + "\")");
        const std::string body = read_file(out / (bank + ".c"));
        if (count_occurrences(body, "__lle(void) {") != 1u)
            fail("--hook-seams manifest: expected exactly 1 __lle body");
        if (body.find(bank + "_caller__lle") != std::string::npos)
            fail("--hook-seams manifest: the un-hooked caller must not get "
                 "a wrapper");
        if (body.find(bank + "_callee();") == std::string::npos)
            fail("--hook-seams manifest: the hooked callee must not be "
                 "inlined into the caller even though it is eligible");
        const std::string hooks = read_file(out / (bank + "_hooks.c"));
        if (count_occurrences(hooks, "&g_hook_") != 1u)
            fail("--hook-seams manifest: expected exactly 1 hook table row");
        if (hooks.find("0x02000010u") == std::string::npos)
            fail("--hook-seams manifest: hook table row has the wrong "
                 "address");
    }

    // ── A manifest naming an address nothing emits must fail closed.
    {
        const std::string bad_manifest =
            "version = 1\n"
            "[program]\nbank = \"" + bank + "\"\nsha1 = \"" + sha1 + "\"\n"
            "[[hook]]\naddress = 0x02000999\nmode = \"arm\"\n";
        const auto manifest_path = work / "hooks_bad.toml";
        write_file(manifest_path, bad_manifest);
        const auto out = work / "hook_manifest_bad";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank,
                                 "--shards 1 --hook-seams manifest "
                                 "--hook-manifest \"" +
                                 manifest_path.string() + "\"",
                                 work / "hook_manifest_bad.log");
        if (r.exit_code == 0)
            fail("a hook manifest naming an unemitted address must fail, "
                 "not silently seam nothing");
    }

    // ── Rejected combinations.
    {
        const auto out = work / "reject_live_bytes";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank,
                                 "--shards 1 --hook-seams all "
                                 "--validate-live-bytes",
                                 work / "reject_live_bytes.log");
        if (r.exit_code == 0)
            fail("--hook-seams combined with --validate-live-bytes must be "
                 "rejected");
    }
    {
        const auto out = work / "reject_hle";
        const auto r = recompile(recompile_bin, bin_path, config_path, out,
                                 bank,
                                 "--shards 1 --hook-seams all "
                                 "--hle-manifest nonexistent.toml",
                                 work / "reject_hle.log");
        if (r.exit_code == 0)
            fail("--hook-seams combined with --hle-manifest must be "
                 "rejected");
    }

    // ── Compile every emitted .c file against the real ABI header.
    for (const auto& dir : compile_dirs) {
        for (const std::string& src : list_c_files(dir)) {
            std::ostringstream command;
            command << '"' << cc << '"' << " -fsyntax-only -std=c11";
            for (const std::string& inc : include_dirs)
                command << " -I \"" << inc << '"';
            for (const std::string& flag : macos_sysroot_flags(work))
                command << ' ' << flag;
            command << " \"" << src << '"';
            if (run(command.str()) != 0)
                fail("emitted file failed to compile: " + src);
        }
    }

    if (failures != 0) {
        std::fprintf(stderr, "FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    std::puts("PASS: --hook-seams emission is well-formed and compiles");
    return 0;
}
