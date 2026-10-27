#!/usr/bin/env python3
"""Read-only prerequisite inventory. No TPM commands, provisioning, sudo or FIDO state reads."""
from __future__ import annotations
import glob
import json
import os
import pathlib
import platform
import shutil
import struct
import subprocess


def read_text(path: str) -> str | None:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")[:256].strip("\x00\r\n ")
    except OSError:
        return None


def elf_info(path: str) -> dict:
    try:
        with open(path, "rb") as stream:
            header = stream.read(64)
        if len(header) < 40 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
            return {"elf": False}
        byteorder = "little" if header[5] == 1 else "big"
        return {"elf": True, "bits": {1: 32, 2: 64}.get(header[4]),
                "machine": int.from_bytes(header[18:20], byteorder),
                "note": "ELF machine alone does not prove ARMv6 instruction compatibility"}
    except OSError:
        return {"readable": False}


def collect() -> dict:
    java = shutil.which("java")
    java_info: dict = {"present": java is not None, "cryptoki_module": None}
    if java:
        try:
            result = subprocess.run([java, "--list-modules"], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=45, check=False)
            java_info["query_exit"] = result.returncode
            java_info["cryptoki_module"] = any(
                line.startswith("jdk.crypto.cryptoki@") for line in result.stdout.splitlines()) if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            java_info["query_failed"] = True
    libraries: dict[str, dict] = {}
    for pattern in ("/usr/lib/*/libtpm2_pkcs11.so*", "/usr/lib/*/pkcs11/libtpm2_pkcs11.so*",
                    "/usr/lib/pkcs11/libtpm2_pkcs11.so*", "/usr/local/lib/libtpm2_pkcs11.so*"):
        for path in glob.glob(pattern):
            real = os.path.realpath(path)
            libraries[real] = elf_info(real)
    tpm_paths = [p for p in ("/dev/tpm0", "/dev/tpmrm0") if os.path.exists(p)]
    blockers = []
    if platform.system() != "Linux": blockers.append("linux_required_for_chosen_SPI_path")
    if not java: blockers.append("java_missing")
    elif java_info["cryptoki_module"] is not True: blockers.append("jdk_crypto_cryptoki_unconfirmed")
    if not libraries: blockers.append("tpm2_pkcs11_native_library_not_found")
    if not tpm_paths: blockers.append("TPM_device_not_present")
    return {
        "schema": "pikeyua-hardware-readiness/v1", "read_only": True,
        "model": read_text("/proc/device-tree/model"), "machine": platform.machine(),
        "userspace_bits": struct.calcsize("P") * 8, "kernel": platform.release(),
        "java": java_info, "native_libraries": libraries,
        "tpm_device_nodes": tpm_paths,
        "tpm_version": read_text("/sys/class/tpm/tpm0/tpm_version_major"),
        "slb9670_overlay_file": any(pathlib.Path(p).is_file() for p in (
            "/boot/firmware/overlays/tpm-slb9670.dtbo", "/boot/overlays/tpm-slb9670.dtbo")),
        "tools": {name: shutil.which(name) is not None for name in (
            "pkcs11-tool", "tpm2_getcap", "tpm2_ptool")},
        "blockers": blockers,
        "qualification": "NOT_TESTED_PHYSICAL_TPM_OR_ARMV6_SIGNING",
        "notes": ["No packages installed; no config changed; no device node opened.",
                  "No credentials, PINs, FIDO state, network settings or serial numbers read.",
                  "Missing prerequisites are information, not a reason to modify the running key."]
    }


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2, sort_keys=True))
