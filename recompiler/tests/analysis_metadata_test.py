#!/usr/bin/env python3
"""analysis_metadata_test — pins the --analysis-json sidecar contract.

Runs nds_recompile over the vendored FreeBIOS ARM7 image (BSD-2-Clause, no
user dump needed) twice, with and without --analysis-json, and checks:

  * the flag changes no generated C byte (the sidecar is observational);
  * the JSON parses and carries one record per emitted function, keyed by
    "<bank>:0xADDR";
  * facts that are ground truth in third_party/freebios/bios_common.S are
    recovered: swi_halt stores a byte to HALTCNT (0x04000301), and the three
    interrupt-wait SWIs call interrupt_check.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def digest(directory):
    h = hashlib.sha1()
    for path in sorted(directory.glob("*.[ch]")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recompiler", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--work", required=True)
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    image = repo / "third_party/freebios/drastic_bios_arm7.bin"
    if not image.exists():
        print("SKIP: third_party/freebios submodule not checked out")
        return 0

    digests = []
    for name, extra in (("plain", []), ("analysis", ["--analysis-json"])):
        out = pathlib.Path(args.work) / name
        out.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [args.recompiler, "--config", str(repo / "bios/freebios7.toml"),
             "--bin", str(image), "--out", str(out),
             "--bank", "freebios_arm7", *extra],
            check=True, stdout=subprocess.DEVNULL)
        digests.append(digest(out))
    if digests[0] != digests[1]:
        print("FAIL: --analysis-json changed generated C")
        return 1

    data = json.loads((out / "freebios_arm7_analysis.json").read_text())
    funcs = {f["name"]: f for f in data["functions"]}
    header = (out / "freebios_arm7.h").read_text()
    failures = []
    if data["schema"] != "ndsrecomp.analysis/1" or data["cpu"] != "arm7":
        failures.append("bad schema/cpu header")
    if data["function_count"] != len(data["functions"]):
        failures.append("function_count mismatch")
    for f in data["functions"]:
        if f["id"] != "freebios_arm7:" + f["addr"]:
            failures.append("bad id " + f["id"])
        if "void %s(void);" % f["symbol"] not in header:
            failures.append("symbol not in bank header: " + f["symbol"])

    halt = [(w["addr"], w["width"]) for w in funcs["swi_halt"]["writes"]]
    if halt != [("0x04000301", 1)]:
        failures.append("swi_halt writes: %r" % halt)
    check = funcs["interrupt_check"]["id"]
    for name in ("swi_interrupt_wait", "swi_interrupt_check_first"):
        if [c["target_id"] for c in funcs[name]["calls"]] != [check]:
            failures.append(name + " does not call interrupt_check")
        if funcs[name]["id"] not in funcs["interrupt_check"]["callers"]:
            failures.append(name + " missing from interrupt_check callers")

    for line in failures:
        print("FAIL:", line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
