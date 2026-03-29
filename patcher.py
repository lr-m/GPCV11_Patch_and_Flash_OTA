#!/usr/bin/env python3
"""
patcher.py - Patch and flash Generalplus GP11x firmware (AliGlasses).

Usage:
    python3 patcher.py                        # patch only → patched_flash.bin
    python3 patcher.py --flash                # patch + OTA flash to device
    python3 patcher.py --flash --dry-run      # patch + show flash plan, no send

To add a patch: append a function (bytearray) -> None to PATCHES or FLASH_PATCHES.
"""

import zlib
import struct
import sys
import os
import subprocess
import argparse

# ── ANSI colours — markers only ────────────────────────────────────────────────

G0  = '\033[38;5;220m'   # bright gold  (step numbers)
AMB = '\033[38;5;136m'   # amber        ([*] info)
GRN = '\033[38;5;34m'    # green        ([+] success)
RED = '\033[38;5;160m'   # red          ([-] error)
RST = '\033[0m'

# ── Banner ─────────────────────────────────────────────────────────────────────

BANNER = f"""
{G0}  ███████╗██╗      ██████╗ ████████╗███████╗{RST}
{G0}  ██╔════╝██║     ██╔═══██╗╚══██╔══╝██╔════╝{RST}
{G0}  ███████╗██║     ██║   ██║   ██║   ███████╗{RST}
{G0}  ╚════██║██║     ██║   ██║   ██║   ╚════██║{RST}
{G0}  ███████║███████╗╚██████╔╝   ██║   ███████║{RST}
{G0}  ╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚══════╝{RST}
"""

# ── Output helpers ─────────────────────────────────────────────────────────────

def _step(n, label):
    """Numbered step header."""
    print(f"\n{G0}[{n}]{RST} {label}")

def _ok(label, addr=None, note=None):
    """Success line with optional address and note."""
    parts = [f"  {GRN}[+]{RST}  {label}"]
    if addr is not None: parts.append(f"{addr:#010x}")
    if note is not None: parts.append(note)
    print("  ".join(parts))

def _kv(key, value):
    """Key/value info line."""
    print(f"  {AMB}[*]{RST}  {key}: {value}")

def _note(msg):
    """Plain indented note."""
    print(f"  {AMB}[*]{RST}  {msg}")

def _fail(msg):
    """Print error and exit."""
    print(f"\n  {RED}[-]{RST}  {msg}", file=sys.stderr)
    sys.exit(1)

def hexdump(data, indent="      ", bpl=16):
    """Hex + ASCII dump."""
    lines = []
    for i in range(0, len(data), bpl):
        chunk    = data[i:i+bpl]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(
            f"{indent}{i:08X}  {hex_part:<{bpl*3-1}}  {asc_part}"
        )
    return '\n'.join(lines)

# ── Config ─────────────────────────────────────────────────────────────────────

GOLDEN_FLASH    = "golden_read.BIN"
OUTPUT_FLASH    = "patched_flash.bin"
FLASH_SEND_SIZE = 0x1f0000

APP_BASE             = 0x10000
SECTOR_SIZE          = 0x200
HDR_START_SECTOR_OFF = 0x17
HDR_END_SECTOR_OFF   = 0x2E

# ── Patches ────────────────────────────────────────────────────────────────────

def patch_rtsp_banner(app: bytearray) -> None:
    target  = b"RTSP: remote IP %d.%d.%d.%d connected\r\n"
    replace = b"HIYA: remote IP %d.%d.%d.%d connected\r\n"
    off = app.index(target)
    app[off:off + len(target)] = replace
    _ok("patch_rtsp_banner", off)


def patch_version_string(app: bytearray) -> None:
    target  = b"AT-20250528"
    replace = b"TNRWASHERE!"
    off = app.index(target)
    app[off:off + len(target)] = replace
    _ok("patch_version_string", off)


def _cave_symbols(cave_elf: str) -> dict:
    """Return {name: offset} for defined text symbols via arm-none-eabi-nm."""
    out = subprocess.check_output(
        ["arm-none-eabi-nm", "--defined-only", cave_elf], text=True
    )
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            syms[parts[2]] = int(parts[0], 16)
    return syms


def patch_shellcode_caves(app: bytearray) -> None:
    """
    Append cave.bin and install trampoline + key-handler patches.

    1. Trampoline at print_version_on_screen (0x2b7b4) → version_cave
       PUSH {r0-r3,lr} / LDR r0,[pc,#4] / BLX r0 / POP {r0-r3,pc} / .word addr

    2. key_cave address resolved but pointer patch applied elsewhere.
    """
    shellcode_dir = os.path.join(os.path.dirname(__file__), "shellcode")
    cave_bin = os.path.join(shellcode_dir, "cave.bin")
    cave_elf = os.path.join(shellcode_dir, "cave.elf")

    cave = open(cave_bin, "rb").read()
    _kv("cave size", f"{len(cave):#x} bytes")

    pad = (-len(app)) & 3
    cave_base = len(app) + pad
    app.extend(b"\xff" * pad + cave)

    syms = _cave_symbols(cave_elf)
    version_cave_addr = cave_base + syms["version_cave"]
    key_cave_addr     = cave_base + syms["key_cave"]

    hook_off = 0x2b7b4
    trampoline = bytes([
        0x0F, 0x40, 0x2D, 0xE9,  # PUSH {r0-r3, lr}
        0x04, 0x00, 0x9F, 0xE5,  # LDR  r0, [pc, #4]
        0x30, 0xFF, 0x2F, 0xE1,  # BLX  r0
        0x0F, 0x80, 0xBD, 0xE8,  # POP  {r0-r3, pc}
    ]) + struct.pack("<I", version_cave_addr)
    app[hook_off : hook_off + len(trampoline)] = trampoline

    _ok("version_cave",  version_cave_addr, f"trampoline @ {hook_off:#010x}")
    _kv("key_cave", f"{key_cave_addr:#010x}  (inactive)")
    _note(f"trampoline bytes:\n{hexdump(trampoline)}")


PATCHES = [
    patch_rtsp_banner,
    patch_version_string,
    patch_shellcode_caves,
]

# ── Raw flash patches ──────────────────────────────────────────────────────────

def patch_flash_version_label(flash: bytearray) -> None:
    off     = 0x174496
    target  = b"Version\x00"
    replace = b"SLOTS\x00\x00\x00"
    if flash[off:off + len(target)] != target:
        _fail(f"Expected {target!r} at {off:#x}, got {flash[off:off+len(target)]!r}")
    flash[off:off + len(replace)] = replace
    old_str = target.rstrip(b'\x00').decode()
    new_str = replace.rstrip(b'\x00').decode()
    _ok("patch_flash_version_label", off, f'"{old_str}" → "{new_str}"')


FLASH_PATCHES = [
    patch_flash_version_label,
]

# ── GP flash internals ─────────────────────────────────────────────────────────

def extract_and_decompress(flash: bytes) -> tuple:
    if flash[APP_BASE:APP_BASE + 2] != b"GP":
        _fail("Missing GP magic at APP_BASE")
    if flash[APP_BASE + 4:APP_BASE + 13] != b"GPCODEROM":
        _fail("Missing GPCODEROM section header")

    start_sector = struct.unpack_from("<I", flash, APP_BASE + HDR_START_SECTOR_OFF)[0]
    end_sector   = struct.unpack_from("<I", flash, APP_BASE + HDR_END_SECTOR_OFF)[0]
    payload_off  = APP_BASE + start_sector * SECTOR_SIZE
    payload_size = (end_sector - start_sector) * SECTOR_SIZE

    if flash[payload_off:payload_off + 4] != b"GPZP":
        _fail(f"Missing GPZP magic at {payload_off:#x}")

    compressed = flash[payload_off + 4 : payload_off + payload_size]
    app = zlib.decompress(compressed, -15)
    return app, payload_off, start_sector, end_sector


def compress_app(data: bytes) -> bytes:
    cobj = zlib.compressobj(
        level    = 9,
        method   = zlib.DEFLATED,
        wbits    = -15,
        memLevel = 8,
        strategy = zlib.Z_FIXED,
    )
    return cobj.compress(data) + cobj.flush()


def repack_flash(flash: bytes, app: bytes, payload_off: int,
                 start_sector: int, old_end_sector: int) -> bytearray:
    compressed       = compress_app(app)
    blob             = b"GPZP" + compressed
    remainder        = len(blob) % SECTOR_SIZE
    if remainder:
        blob += b"\xff" * (SECTOR_SIZE - remainder)

    new_sector_count = len(blob) // SECTOR_SIZE
    new_end_sector   = start_sector + new_sector_count
    old_payload_size = (old_end_sector - start_sector) * SECTOR_SIZE

    out = bytearray(flash)
    out[payload_off : payload_off + old_payload_size] = b"\xff" * old_payload_size
    out[payload_off : payload_off + len(blob)] = blob
    struct.pack_into("<I", out, APP_BASE + HDR_END_SECTOR_OFF, new_end_sector)

    _kv("compressed", f"{len(compressed):#x} bytes")
    _kv("sectors",    f"{new_sector_count}  (end {new_end_sector}, was {old_end_sector})")
    return out

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    p = argparse.ArgumentParser(
        description="AliGlasses GP firmware patcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--flash",      action="store_true", help="OTA flash to device after patching")
    p.add_argument("--dry-run",    action="store_true", help="Show flash plan without sending")
    p.add_argument("--golden",     default=GOLDEN_FLASH,  help=f"Input golden image  (default: {GOLDEN_FLASH})")
    p.add_argument("--output",     default=OUTPUT_FLASH,  help=f"Output image         (default: {OUTPUT_FLASH})")
    p.add_argument("--host",       default="192.168.25.1")
    p.add_argument("--port",       type=int, default=8081)
    p.add_argument("--chunk-size", type=lambda x: int(x, 0), default=0x400)
    p.add_argument("--delay",      type=float, default=0.0)
    p.add_argument("--verbose",    action="store_true")
    args = p.parse_args()

    # ── 1. Load ────────────────────────────────────────────────────────────────
    _step(1, "Loading golden flash image")
    flash = open(args.golden, "rb").read()
    _kv("path", args.golden)
    _kv("size", f"{len(flash):#x} bytes")

    # ── 2. Extract ─────────────────────────────────────────────────────────────
    _step(2, "Extracting and decompressing GPCODEROM")
    app, payload_off, start_sector, end_sector = extract_and_decompress(flash)
    _kv("payload offset",  f"{payload_off:#010x}")
    _kv("sectors",         f"{start_sector} → {end_sector}  ({end_sector - start_sector} sectors)")
    _kv("decompressed",    f"{len(app):#x} bytes")

    # ── 3. Patch ───────────────────────────────────────────────────────────────
    _step(3, f"Applying {len(PATCHES)} app patch(es)")
    app = bytearray(app)
    for fn in PATCHES:
        fn(app)
    app = bytes(app)

    # ── 4. Repack ──────────────────────────────────────────────────────────────
    _step(4, "Recompressing and repacking")
    patched_flash = repack_flash(flash, app, payload_off, start_sector, end_sector)

    # ── 5. Sanity check ────────────────────────────────────────────────────────
    new_payload_off = APP_BASE + start_sector * SECTOR_SIZE
    new_end_sector  = struct.unpack_from("<I", patched_flash, APP_BASE + HDR_END_SECTOR_OFF)[0]
    payload_bytes   = (new_end_sector - start_sector) * SECTOR_SIZE - 4
    check = zlib.decompress(
        bytes(patched_flash[new_payload_off + 4 : new_payload_off + 4 + payload_bytes]), -15
    )
    if check != app:
        _fail("Sanity check FAILED: repacked payload does not decompress correctly")
    _ok("sanity check passed")

    # ── 5b. Flash patches ──────────────────────────────────────────────────────
    if FLASH_PATCHES:
        _step("5b", f"Applying {len(FLASH_PATCHES)} raw flash patch(es)")
        for fn in FLASH_PATCHES:
            fn(patched_flash)

    # ── 6. Write ───────────────────────────────────────────────────────────────
    _step(6, "Writing output")
    open(args.output, "wb").write(patched_flash)
    _ok("written", note=args.output)
    _kv("size", f"{len(patched_flash):#x} bytes")

    # ── 7. Flash ───────────────────────────────────────────────────────────────
    if args.flash:
        _step(7, "Flashing to device via GPSOCKET OTA")
        _kv("host", f"{args.host}:{args.port}")
        _kv("range", f"0x000000 → {FLASH_SEND_SIZE:#x}")
        from flash import send_firmware
        send_firmware(
            flash_path = args.output,
            host       = args.host,
            port       = args.port,
            offset     = 0,
            length     = FLASH_SEND_SIZE,
            chunk_size = args.chunk_size,
            delay      = args.delay,
            dry_run    = args.dry_run,
            verbose    = args.verbose,
        )


if __name__ == "__main__":
    main()
