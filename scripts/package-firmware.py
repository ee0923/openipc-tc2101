#!/usr/bin/env python3
"""Audit the bootable payloads and write a fixed-slot NOR update archive."""
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = Path("lib/modules/4.9.84")


def verify_kernel(path, soc):
    kernel = path.read_bytes()
    if not 64 < len(kernel) <= 0x200000:
        raise SystemExit(f"Kernel size {len(kernel)} bytes is outside the 2 MiB slot limit")
    magic, checksum, _, length, _, _, data_crc, os_id, arch, image_type, _, name = struct.unpack(
        ">7I4B32s", kernel[:64]
    )
    header = kernel[:4] + bytes(4) + kernel[8:64]
    if (magic, os_id, arch, image_type) != (0x27051956, 5, 2, 2):
        raise SystemExit("Expected a legacy ARM Linux kernel uImage")
    if name.rstrip(b"\0") != f"Linux-4.9.84-{soc}".encode():
        raise SystemExit("Kernel header does not match the selected SoC")
    if length != len(kernel) - 64 or zlib.crc32(header) != checksum or zlib.crc32(kernel[64:]) != data_crc:
        raise SystemExit("uImage length or CRC mismatch")


def verify_rootfs(path, soc, lock):
    size = path.stat().st_size
    if size > 0x500000:
        raise SystemExit(f"SquashFS size {size} bytes exceeds the 5 MiB slot limit")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        # The runner cannot create the device nodes stored under /dev.
        # Extract only the trees used by the checks, keeping extraction errors fatal.
        subprocess.run(["unsquashfs", "-no-progress", "-no-xattrs", "-d", str(root),
                        str(path), "etc", "lib", "tmp", "usr", "var"], check=True)
        for name in ("usr/bin/majestic", "usr/sbin/iptables-restore", "usr/sbin/wpa_supplicant",
                     "usr/bin/yaml-cli", "etc/init.d/rcS", "etc/init.d/S95majestic",
                     "var/www/setup.html", "etc/sensors/jxq03.bin", "usr/bin/tc2101-ptz",
                     MODULE_DIR / "sigmastar/mi_ai.ko", MODULE_DIR / "sigmastar/mi_ao.ko"):
            if not (root / name).is_file():
                raise SystemExit(f"Missing firmware file: {name}")
        driver = root / MODULE_DIR / "sigmastar/sensor_jxq03_mipi.ko"
        # Buildroot strips the included module, so validate the packaged ABI
        # and driver identity here. customize.py checks its unstripped SHA256.
        vendor_module = driver.read_bytes()
        wifi_modules = list((root / MODULE_DIR).rglob("8188fu.ko"))
        if len(wifi_modules) != 1:
            raise SystemExit("Expected exactly one RTL8188FU kernel module")
        wifi_module = wifi_modules[0].read_bytes()
        vermagic = b"vermagic=4.9.84 preempt mod_unload ARMv7 thumb2 p2v8 "
        for blob in (vendor_module, wifi_module):
            if not blob.startswith(b"\x7fELF") or vermagic not in blob:
                raise SystemExit("Unexpected kernel module ABI")
        if b"drv_ms_cus_Q03_MIPI" not in vendor_module or b"usb:v0BDApF179" not in wifi_module:
            raise SystemExit("Wrong sensor or Wi-Fi device ID in kernel modules")
        text = (root / "etc/majestic.tc2101.yaml").read_text()
        policy = (root / "etc/tc2101-egress.v4").read_text()
        startup = (root / "etc/init.d/rcS").read_text()
        supervisor = (root / "etc/init.d/S95majestic").read_text()
        if any(key not in text for key in ("telemetry: false", 'iceServers: ""', "speakerPin: 15",
                                            "outputEnabled: true", "codec: h264", "size: 1920x1080")):
            raise SystemExit("Missing audio/video or privacy defaults")
        if ":OUTPUT DROP " not in policy or startup.index("iptables-restore") > startup.index("for i in /etc/init.d/"):
            raise SystemExit("Public egress defaults must apply before service startup")
        if (root / "etc/init.d/S35iptables").exists():
            raise SystemExit("Generic firewall init could override the TC2101 egress policy")
        if ".system.telemetry false" not in supervisor:
            raise SystemExit("Retained configuration is not covered by the telemetry patch")
        if ('/usr/bin/tc2101-ptz' not in (root / 'var/www/cgi-bin/j/ptz.cgi').read_text()
                or not os.access(root / 'usr/bin/tc2101-ptz', os.X_OK)):
            raise SystemExit("TC2101 PTZ backend is not connected to the WebUI")
        release = (root / "usr/lib/os-release").read_text()
        if f"BUILD_PLATFORM={soc}_lite_h3c-tc2101" not in release.splitlines():
            raise SystemExit("Wrong SoC in generated rootfs metadata")
        if any((root / name).exists() for name in ("etc/tc2101-wpa.conf", "tmp/wpa_supplicant.conf")):
            raise SystemExit("Unexpected Wi-Fi credentials in image")
        if any((root / "etc/dropbear").glob("*_host_key")):
            raise SystemExit("Unexpected pre-generated SSH host key in image")
        majestic = subprocess.check_output(
            ["tar", "-xOf", str(Path(os.environ["BR2_DL_DIR"]) / lock["downloads"][0]["path"]),
             "majestic-infinity6b0/majestic"]
        )
        if (root / "usr/bin/majestic").read_bytes() != majestic:
            # Reproduce the pinned Buildroot's STRIPCMD before comparing.
            stripped = Path(tmp) / "majestic"
            stripped.write_bytes(majestic)
            binaries = list((path.parent.parent / "host/bin").glob("*-strip"))
            if not binaries:
                raise SystemExit("Cannot verify the packaged Majestic executable")
            subprocess.run([binaries[0], "--remove-section=.comment", "--remove-section=.note", str(stripped)],
                           check=True)
            if (root / "usr/bin/majestic").read_bytes() != stripped.read_bytes():
                raise SystemExit("Majestic differs from the locked release")


def main():
    soc = sys.argv[1]
    if soc not in ("ssc335", "ssc337"):
        raise SystemExit("Unsupported SoC")
    output, dest = map(Path, sys.argv[2:])
    lock = json.loads((ROOT / "sources.lock.json").read_text())
    config = (output / ".config").read_text().splitlines()
    for setting in (f'BR2_OPENIPC_SOC_MODEL="{soc}"', 'BR2_OPENIPC_FLASH_SIZE="16"',
                    "BR2_PACKAGE_IPTABLES=y", "BR2_PACKAGE_RTL8188FU_OPENIPC=y", "BR2_PACKAGE_MAJESTIC_WEBUI_PTZ=y"):
        if setting not in config:
            raise SystemExit(f"Missing build setting: {setting}")
    kernel_config = next((output / "build").glob("linux-*/.config")).read_text().splitlines()
    for setting in ("CONFIG_IP_NF_IPTABLES=y", "CONFIG_IP_NF_FILTER=y", "# CONFIG_IPV6 is not set"):
        if setting not in kernel_config:
            raise SystemExit(f"Missing kernel security setting: {setting}")
    kernel = output / "images/uImage"
    rootfs = output / "images/rootfs.squashfs"
    verify_kernel(kernel, soc)
    verify_rootfs(rootfs, soc, lock)
    files = {f"uImage.{soc}": kernel, f"rootfs.squashfs.{soc}": rootfs}
    dest.mkdir()
    archive = dest / f"openipc-tc2101-{soc}-nor-lite.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, file in files.items():
            tar.add(file, arcname=name)
            data = f"{hashlib.md5(file.read_bytes()).hexdigest()}  {name}\n".encode()
            md5 = tarfile.TarInfo(f"{name}.md5sum")
            md5.size = len(data)
            tar.addfile(md5, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dest / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    manifest = {
        "soc": soc,
        "flash_bytes": 0x1000000,
        "build_revision": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "source_lock": lock,
        "partitions": {
            name: {"offset": offset, "capacity": capacity, "size": files[name].stat().st_size,
                   "sha256": hashlib.sha256(files[name].read_bytes()).hexdigest()}
            for name, offset, capacity in ((f"uImage.{soc}", 0x50000, 0x200000),
                                           (f"rootfs.squashfs.{soc}", 0x250000, 0x500000))
        },
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Verified {archive.name}: {digest}")


if __name__ == "__main__":
    main()
