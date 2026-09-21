#include "config.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

bool write_text(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary);
    stream << text;
    return stream.good();
}

bool parses(const std::filesystem::path& path, const std::string& text) {
    if (!write_text(path, text)) return false;
    ndsrecomp::HookManifest manifest;
    return ndsrecomp::load_hook_manifest(path.string(), manifest);
}

}  // namespace

int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      "ndsrecomp_hook_manifest_test.toml";
    const std::string valid =
        "version = 1\n"
        "[program]\n"
        "bank = \"sm64ds_arm9\"\n"
        "sha1 = \"16e6c9168e34f267cb427bacb388e4783dadc584\"\n"
        "[[hook]]\n"
        "address = 0x02052858\n"
        "mode = \"arm\"\n";

    int failures = 0;
    if (!parses(path, valid)) {
        std::fprintf(stderr, "valid manifest was rejected\n");
        ++failures;
    }
    std::string unsafe_bank = valid;
    unsafe_bank.replace(unsafe_bank.find("sm64ds_arm9"), 11u,
                        "sm64ds-arm9");
    if (parses(path, unsafe_bank)) {
        std::fprintf(stderr, "non-C-identifier bank was accepted\n");
        ++failures;
    }
    if (parses(path, valid + "unknown = 1\n")) {
        std::fprintf(stderr, "unknown top-level key was accepted\n");
        ++failures;
    }
    std::string extra_hook_key = valid;
    extra_hook_key.replace(extra_hook_key.find("mode = \"arm\"\n"), 0u,
                           "id = \"extra\"\n");
    if (parses(path, extra_hook_key)) {
        std::fprintf(stderr, "extra [[hook]] key was accepted\n");
        ++failures;
    }
    if (parses(path, valid + "[[hook]]\naddress = 0x02052858\nmode = \"arm\"\n")) {
        std::fprintf(stderr, "duplicate hook selector was accepted\n");
        ++failures;
    }
    // Same address, different mode is a distinct selector and must parse.
    if (!parses(path, valid + "[[hook]]\naddress = 0x02052858\nmode = \"thumb\"\n")) {
        std::fprintf(stderr,
            "same address with a different mode was wrongly rejected\n");
        ++failures;
    }
    std::string bad_sha = valid;
    bad_sha.replace(bad_sha.find("16e6c9"), 6u, "nothex");
    if (parses(path, bad_sha)) {
        std::fprintf(stderr, "malformed program SHA-1 was accepted\n");
        ++failures;
    }
    std::string misaligned = valid;
    misaligned.replace(misaligned.find("0x02052858"), 10u, "0x02052859");
    if (parses(path, misaligned)) {
        std::fprintf(stderr, "misaligned ARM hook address was accepted\n");
        ++failures;
    }
    std::string no_hooks =
        "version = 1\n"
        "[program]\n"
        "bank = \"sm64ds_arm9\"\n"
        "sha1 = \"16e6c9168e34f267cb427bacb388e4783dadc584\"\n"
        "hook = []\n";
    if (parses(path, no_hooks)) {
        std::fprintf(stderr, "empty [[hook]] list was accepted\n");
        ++failures;
    }
    std::string bad_version = valid;
    bad_version.replace(bad_version.find("version = 1"), 11u, "version = 2");
    if (parses(path, bad_version)) {
        std::fprintf(stderr, "unsupported manifest version was accepted\n");
        ++failures;
    }

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return failures == 0 ? 0 : 1;
}
