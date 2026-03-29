#!/usr/bin/env python3
"""
flash.py - Write a patched flash image to the device via GPSOCKET OTA protocol.

Usage:
    python3 flash.py <flash_patched.bin> [--host 192.168.25.1] [--port 8081]
                                         [--offset 0x0] [--length 0x0]
                                         [--chunk-size 0x7F0] [--dry-run]

The device firmware update flow (from reverse engineering):
    0x0500  CMD_FW_INIT  — declare total_size + byte-sum checksum, device mallocs 0x200000
    0x0501  CMD_FW_CHUNK — send data in chunks (u16 LE size + data), chunk_size=0 = end
    0x0502  CMD_FW_APPLY — trigger checksum verify + flash write

Checksum is a simple 32-bit byte-sum (sum of all payload bytes & 0xFFFFFFFF).
"""

import sys
import struct
import argparse
import time
from gpsocket_client import GPSocketClient

# ── ANSI colours — markers only ────────────────────────────────────────────────
G0  = '\033[38;5;220m'
AMB = '\033[38;5;136m'
GRN = '\033[38;5;34m'
RED = '\033[38;5;160m'
RST = '\033[0m'

# App region boundaries in flash (from bootloader analysis)
APP_BASE         = 0x10000
SECTOR_SIZE      = 0x200
HDR_END_SECTOR   = 0x2E   # offset within GP header

MAX_CHUNK_DATA   = 0x7F2  # device recv buf is 0x800; header takes 0xe bytes


def bytesum32(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def app_region_end(flash: bytes) -> int:
    """Return the byte offset one past the end of the GPCODEROM payload."""
    import struct as _s
    end_sector = _s.unpack_from("<I", flash, APP_BASE + HDR_END_SECTOR)[0]
    start_sector = _s.unpack_from("<I", flash, APP_BASE + 0x17)[0]
    return APP_BASE + end_sector * SECTOR_SIZE


def send_firmware(flash_path: str, host: str, port: int,
                  offset: int, length: int, chunk_size: int, delay: float,
                  dry_run: bool, verbose: bool = False) -> bool:

    flash = open(flash_path, "rb").read()

    # Determine send range
    if length == 0:
        end = 0x1f0000
    else:
        end = offset + length

    payload = flash[offset:end]
    total   = len(payload)
    csum    = bytesum32(payload)

    print(f"  {AMB}[*]{RST}  flash file: {flash_path}")
    print(f"  {AMB}[*]{RST}  send range: {offset:#010x} – {end:#010x}  ({total:#x} bytes, {total:,})")
    print(f"  {AMB}[*]{RST}  checksum: {csum:#010x}")
    print(f"  {AMB}[*]{RST}  chunk size: {chunk_size:#x}")
    print(f"  {AMB}[*]{RST}  chunk delay: {delay*1000:.0f} ms")
    print(f"  {AMB}[*]{RST}  host: {host}:{port}")
    if dry_run:
        print(f"\n  {AMB}[*]{RST}  DRY RUN — not connecting to device")
        return True

    client = GPSocketClient(host=host, port=port, timeout=10, verbose=verbose)
    if not client.connect():
        return False

    try:
        # ── CMD_FW_INIT (0x0500) ──────────────────────────────────────────
        # recv_buffer[0xc:0x10] = total_size  (u32 LE)
        # recv_buffer[0x10:0x14] = checksum   (u32 LE)
        if verbose:
            print(f"\n  {AMB}[*]{RST}  CMD_FW_INIT — size={total:#x}, checksum={csum:#010x}")
        init_payload = struct.pack("<II", total, csum)
        resp = client.send_command(0x0500, init_payload)
        if resp is None:
            print(f"  {RED}[-]{RST}  No response to INIT")
            return False
        if len(resp) >= 9 and resp[8] != client.STATUS_SUCCESS:
            print(f"  {RED}[-]{RST}  INIT rejected (status={resp[8]:#04x})")
            return False

        # ── CMD_FW_CHUNK (0x0501) loop ────────────────────────────────────
        # recv_buffer[0xc:0xe] = chunk_size (u16 LE)
        # recv_buffer[0xe:]    = chunk data
        sent        = 0
        pkt_count   = 0
        bar_width   = 40
        t_start     = time.time()

        print(f"\n  {AMB}[*]{RST}  Flashing {total:#x} bytes...")

        while sent < total:
            this_size = min(chunk_size, total - sent)
            chunk     = payload[sent:sent + this_size]
            pkt       = struct.pack("<H", this_size) + chunk

            resp = client.send_command(0x0501, pkt)
            pkt_count += 1
            sent      += this_size

            if resp is None:
                print(f"\n  {RED}[-]{RST}  No response at offset {sent - this_size:#x} — device crashed?")
                return False
            if len(resp) >= 9 and resp[8] != client.STATUS_SUCCESS:
                print(f"\n  {RED}[-]{RST}  Chunk NAK at {sent - this_size:#x} (status={resp[8]:#04x})")
                return False

            if delay > 0:
                time.sleep(delay)

            # Progress bar
            pct   = sent / total
            filled = int(bar_width * pct)
            bar   = "=" * filled + "-" * (bar_width - filled)
            elapsed = time.time() - t_start
            rate  = sent / elapsed / 1024 if elapsed > 0 else 0
            print(f"\r    [{bar}] {pct:5.1%}  {sent:#010x}/{total:#x}  {rate:.1f} KB/s",
                  end="", flush=True)

        print()  # newline after progress bar

        # ── End-of-transfer: chunk_size == 0 ─────────────────────────────
        if verbose:
            print(f"  {AMB}[*]{RST}  Sending end-of-transfer marker...")
        resp = client.send_command(0x0501, struct.pack("<H", 0))
        if resp is None:
            print(f"  {RED}[-]{RST}  No response to end-of-transfer")
            return False

        status = resp[8] if len(resp) >= 9 else 0xFF
        if status != client.STATUS_SUCCESS:
            ecode = struct.unpack("<H", resp[12:14])[0] if len(resp) >= 14 else 0xFFFF
            print(f"  {RED}[-]{RST}  End-of-transfer rejected: status={status:#04x} ecode={ecode:#06x}")
            print(       "       (checksum mismatch or size mismatch — data not flashed)")
            return False
        print(f"  {GRN}[+]{RST}  Transfer complete, checksum verified")

        # ── CMD_FW_APPLY (0x0502) ─────────────────────────────────────────
        if verbose:
            print(f"  {AMB}[*]{RST}  CMD_FW_APPLY — triggering flash write...")
        client.send_command(0x0502, b"", fire_and_forget=True)
        print(f"  {GRN}[+]{RST}  APPLY sent — device is flashing and will reboot")
        return True

    finally:
        client.disconnect()


def main():
    p = argparse.ArgumentParser(description="Flash patched firmware via GPSOCKET OTA")
    p.add_argument("flash",                                   help="Patched flash image")
    p.add_argument("--host",       default="192.168.25.1",   help="Device IP (default: 192.168.25.1)")
    p.add_argument("--port",       type=int, default=8081,   help="Device port (default: 8081)")
    p.add_argument("--offset",     type=lambda x: int(x,0), default=0x0,
                   help="Start offset in flash file to send (default: 0x0)")
    p.add_argument("--length",     type=lambda x: int(x,0), default=0x0,
                   help="Bytes to send (default: auto = up to end of GPCODEROM payload)")
    p.add_argument("--chunk-size", type=lambda x: int(x,0), default=0x7F0,
                   help=f"Bytes per chunk packet (default: 0x7F0, max: {MAX_CHUNK_DATA:#x})")
    p.add_argument("--delay",      type=float, default=0.0,
                   help="Delay in seconds between chunks (default: 0)")
    p.add_argument("--dry-run",    action="store_true",
                   help="Parse and print plan without connecting")
    p.add_argument("--verbose",    action="store_true",
                   help="Print packet-level detail")
    args = p.parse_args()

    if args.chunk_size > MAX_CHUNK_DATA:
        print(f"[!] chunk-size capped at {MAX_CHUNK_DATA:#x} (device recv buffer limit)")
        args.chunk_size = MAX_CHUNK_DATA

    ok = send_firmware(
        flash_path = args.flash,
        host       = args.host,
        port       = args.port,
        offset     = args.offset,
        length     = args.length,
        chunk_size = args.chunk_size,
        delay      = args.delay,
        dry_run    = args.dry_run,
        verbose    = args.verbose,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
