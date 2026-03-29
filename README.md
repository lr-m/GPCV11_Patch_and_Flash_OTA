# GPCV1167B Firmware Patcher & Flasher

<p align="center">

  <img src="images/jackpot.gif" width="300">

</p>

Patch and OTA-flash Generalplus GPCV1167B firmware.

This work was done on 'smart glasses' from Aliexpress:

<p align="center">

  <img src="images/glasses.png" width="250">

</p>

- **Target:** Generalplus GPCV1167B · ARMv5TE · FreeRTOS + lwIP
- **Protocol:** GPSOCKET over TCP port 8081

---

## What's here

| File | Purpose |
|---|---|
| `patcher.py` | Decompress → patch → recompress the firmware image |
| `flash.py` | OTA-flash a patched image to the device via the GPSOCKET protocol |
| `gpsocket_client.py` | Low-level GPSOCKET client; also contains PoC methods for documented vulns |
| `shellcode/cave.c` | ARM shellcode injected by the patcher (version overlay, key hook) |
| `shellcode/Makefile` | Builds `cave.bin` with `arm-none-eabi-gcc` |
| `golden_read.BIN` | Unmodified reference flash dump (input to patcher) |

---

## Quick start

### Patch only

```bash
python3 patcher.py
# writes patched_flash.bin
```

### Patch + flash

Connect to the device Wi-Fi, then:

```bash
python3 patcher.py --flash
# default: 192.168.25.1:8081
```

### Patch + flash (custom host/options)

```bash
python3 patcher.py --flash --host 192.168.25.1 --port 8081 \
    --chunk-size 0x400 --delay 0.01 --verbose
```

### Dry run (shows flash plan, no transfer)

```bash
python3 patcher.py --flash --dry-run
```

### Flash a pre-built image directly

```bash
python3 flash.py patched_flash.bin --host 192.168.25.1
```

---

## Building the shellcode

Requires `arm-none-eabi-gcc`:

```bash
cd shellcode && make
```

This produces `cave.bin`, which `patcher.py` appends to the decompressed firmware
and installs a trampoline to at `0x2b7b4` (`print_version_on_screen`).

---

## Adding a patch

Append a function `(bytearray) -> None` to `PATCHES` in `patcher.py` for app-level
patches (applied before recompression), or to `FLASH_PATCHES` for raw flash patches
(applied after recompression).

```python
def my_patch(app: bytearray) -> None:
    off = app.index(b"some_target_string")
    app[off:off + 4] = b"\x00\x00\x00\x00"
    _ok("my_patch", off)

PATCHES = [
    ...
    my_patch,
]
```

---

## Flash image format

```
0x00000  Bootloader / low flash (not sent during OTA)
0x10000  GP header: "GP" magic + "GPCODEROM" section
           +0x17  start_sector (u32 LE)
           +0x2E  end_sector   (u32 LE)
0x???    GPZP block: b"GPZP" + raw deflate (wbits=-15, level=9, Z_FIXED)
```

The patcher decompresses at `start_sector`, patches, recompresses with identical
settings, and updates `end_sector` in the header.

---

## GPSOCKET protocol

```
[0:8]   Magic "GPSOCKET"
[8:10]  Direction: 0x0100 (request)
[10:12] Command ID (big-endian u16)
[12:]   Payload (command-specific)
```

Key commands used during OTA:

| Command | ID | Description |
|---|---|---|
| `CMD_FW_INIT`  | `0x0500` | Declare total size + byte-sum checksum; device mallocs 0x200000 |
| `CMD_FW_CHUNK` | `0x0501` | Send chunk: u16 LE size at payload[0:2], data at payload[2:] |
| `CMD_FW_APPLY` | `0x0502` | Trigger checksum verify + flash write |

Chunk size `0` in `CMD_FW_CHUNK` signals end-of-transfer and triggers the checksum check.

---

## Dependencies

- Python 3.8+, standard library only
- `arm-none-eabi-gcc` / `arm-none-eabi-nm` (shellcode build + symbol resolution)
