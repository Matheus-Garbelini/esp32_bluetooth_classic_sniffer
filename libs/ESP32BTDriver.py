import binascii
import os
import sys
import pty
import subprocess
import serial
import tty
import time
import ctypes
import serial.tools.list_ports
from threading import Thread
from binascii import hexlify, unhexlify
from colorama import Fore
from time import sleep
from firmware import reset_firmware


class ConnectionStatus(ctypes.LittleEndianStructure):
    _fields_ = [
        ("clock", ctypes.c_uint32, 8 * 4),
        ("channel", ctypes.c_uint8, 8),
        ("ptt", ctypes.c_uint8, 1),
        ("role", ctypes.c_uint8, 1),
        ("custom_lmp", ctypes.c_uint8, 1),
        ("retry_flag", ctypes.c_uint8, 1),
        ("intercept_req", ctypes.c_uint8, 1),
        ("tx_encrypted", ctypes.c_uint8, 1),
        ("rx_encrypted", ctypes.c_uint8, 1),
        ("is_eir", ctypes.c_uint8, 1),
    ]

    def getdict(self):
        return dict((f, getattr(self, f)) for f, _, _ in self._fields_)


# USB Serial commands
ESP32_CMD_DATA_RX = b'\xA7'
ESP32_CMD_DATA_TX = b'\xBB'
ESP32_CMD_CHECKSUM_ERROR = b'\xA8'
ESP32_CMD_CONFIG_AUTO_EMPTY_PDU = b'\xA9'
ESP32_CMD_CONFIG_ACK = b'\xAA'
ESP32_CMD_CONFIG_LOG_TX = b'\xCC'
ESP32_CMD_LOG = b'\x7F'
ESP32_CMD_RESET = b'\x86'
ESP32_CMD_VERSION = b'\xEE'
ESP32_CMD_ENABLE_LMP_SNIFFING = b'\x81'
ESP32_CMD_SET_BDADDR = b'\x87'
ESP32_CMD_DISABLE_POLL_NULL = b'\x89'

# HCI Codes to bridge
H4_NONE = b'\x00'
H4_CMD = b'\x01'
H4_ACL = b'\x02'
H4_SCO = b'\x03'
H4_EVT = b'\x04'
H4_EVT_HW_ERROR = b'\x10'


# Driver class
class ESP32BTDriver:

    event_counter = 0
    direction = None
    version = None
    status = None  # type: ConnectionStatus

    serial_bridge = None
    serial_bridge_name = None
    serial_hci_thread = None
    serial_baudrate = 921600
    serial_portname = None

    # Constructor ------------------------------------
    def __init__(self, port_name=None, baudrate=921600, reset_board=True,
                 debug=False):

        self.serial_portname = port_name
        self.serial_baudrate = baudrate

        if reset_board:
            # Reset ESP32 board to endure clean session
            self.reset_firmware()

        self.serial = serial.Serial(
            port_name, baudrate, rtscts=0, xonxoff=0, timeout=1)

        self.get_version()

        os.system("setserial %s low_latency >/dev/null" %
                  (self.serial_portname))

        master, slave = pty.openpty()
        self.serial_bridge_name = os.ttyname(slave)
        self.serial_bridge = master
        tty.setraw(master)
        tty.setraw(slave)
        print(Fore.GREEN + 'HCI Bridge started on ' + os.ttyname(slave))
        self.serial_hci_thread = Thread(target=self.hci_handler)
        self.serial_hci_thread.daemon = True
        self.serial_hci_thread.start()

    def close(self):
        print('ESP32 Driver closed')

    def reset_firmware(self, wait_reset=True, soft_reset=False):

        if soft_reset is False:
            try:
                import serial
            except:
                print("[ERROR] pyserial module not found, installing now via pip...")
                os.system(sys.executable +
                          ' -m pip install pyserial --upgrade')
                os.sync()

            # We should have pyserial installed here
            import serial

            ser = serial.Serial(self.serial_portname, self.serial_baudrate,
                                rtscts=False, dsrdtr=False)
            ser.rts = True
            ser.dtr = True
            ser.dtr = False
            ser.dtr = True
            ser.close()
            ser = None
            print('[!] Reset Done! EN pin toggled HIGH->LOW->HIGH')

        else:
            self.serial.write(ESP32_CMD_RESET + bytearray([0x86, 0xAA]))

        if wait_reset:
            print('[!] Waiting 0.8s...')
            sleep(0.8)

    # UART functions ---------------------------

    def get_version(self):
        self.serial.write(ESP32_CMD_VERSION)
        version_string = self.serial.readline()
        if version_string and len(version_string):
            self.version = version_string.decode('utf-8').split('\n')[0]
            print("[ESP32BT] Firmware version: " + self.version)
        else:
            raise Exception(
                "Version not received. Make sure to flash ESP32BT firmware")

    def enable_sniffing(self, val):
        self.serial.write(ESP32_CMD_ENABLE_LMP_SNIFFING + bytearray([val]))

    def disable_poll_null(self, val):
        self.serial.write(ESP32_CMD_DISABLE_POLL_NULL + bytearray([val]))
        self.serial.read(1)

    def set_bdaddr(self, value):
        addr = unhexlify(''.join(value.split(':')[::-1]))
        self.serial.write(ESP32_CMD_SET_BDADDR + addr)

    def hci_handler(self):
        while True:
            c = os.read(self.serial_bridge, 1)
            self.serial.write(c)

    def receive(self):
        cmd = self.serial.read(1)

        if cmd == H4_EVT:
            opcode = self.serial.read(1)
            length = self.serial.read(1)
            payload = self.serial.read(ord(length))
            os.write(self.serial_bridge, H4_EVT + opcode + length + payload)
        elif cmd == H4_ACL:
            opcode = self.serial.read(2)
            length = self.serial.read(2)
            payload = self.serial.read(length[0] | (length[1] << 8))
            os.write(self.serial_bridge, H4_ACL + opcode + length + payload)
        elif cmd == H4_CMD:  # Should not happen
            opcode = self.serial.read(2)
            length = self.serial.read(1)
            if len(length):
                payload = self.serial.read(ord(length))
                os.write(self.serial_bridge, H4_CMD +
                         opcode + length + payload)

        # Receive BT packets
        elif cmd == ESP32_CMD_DATA_RX or cmd == ESP32_CMD_DATA_TX:
            raw_sz = self.serial.read(2)
            sz = raw_sz[0] | (raw_sz[1] << 8)
            data = self.serial.read(sz)
            checksum = self.serial.read(1)
            # Check data checksum
            if (checksum and (sum(data) & 0xFF) == ord(checksum)):
                self.status = ConnectionStatus(*data[0:6])
                self.direction = (1 if cmd == ESP32_CMD_DATA_RX else 0)
                return data

        return None
