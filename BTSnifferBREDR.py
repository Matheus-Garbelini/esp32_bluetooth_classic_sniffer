#!/usr/bin/python3

import os
import sys
import _ctypes
import ctypes
import _thread
import colorama
import subprocess
import random
import signal
from threading import Thread
from time import sleep
from colorama import Fore, init

sys.path.insert(0, os.getcwd() + '/libs')

from scapy.layers.bluetooth import HCI_Hdr, BT_ACL_Hdr, HCI_PHDR_Hdr, BT_LMP, BT_Baseband
from scapy.utils import wrpcap, PcapWriter
from ESP32BTDriver import ESP32BTDriver


init(autoreset=True)


class SnifferBREDR:
    TAG = 'Sniffer'
    working_dir = None
    packets = []
    wireshark_process = None
    fifo_file = '/tmp/fifocap.fifo'
    pcap_filename = 'capture_bluetooth.pcap'
    save_pcap = False
    pcap_fifo_writer = None
    pcap_writer = None
    wireshark_started = False

    driver = None  # type: ESP32BTDriver
    run_driver = True
    serial_port = None
    serial_baud = None
    serial_thread = None
    bridge_hci = True
    bt_program = None
    bt_program_thread = None
    bt_program_run = True
    bt_program_process = None

    # BT Vars
    tx_packets = 0
    rx_packets = 0
    remote_address = b'a8:96:75:25:c2:ac'

    # Constructor
    def __init__(self,
                 serial_port=None,
                 serial_baud=4000000,
                 start_wireshark=False,
                 save_pcap=True,
                 pcap_filename=None,
                 bridge_hci=True,
                 bt_program=None):

        self.serial_port = serial_port
        self.serial_baud = serial_baud
        self.save_pcap = save_pcap
        self.bridge_hci = bridge_hci

        if pcap_filename:
            self.pcap_filename = pcap_filename

        if bt_program:
            self.bt_program = bt_program

        if start_wireshark:
            try:
                os.remove(self.fifo_file)
            except:
                pass
            os.mkfifo(self.fifo_file)
            try:
                self.l('[!] Starting Wireshark...')
                self.wireshark_process = subprocess.Popen(
                    ['wireshark', '-k', '-i', self.fifo_file])
                self.pcap_fifo_writer = PcapWriter(self.fifo_file, sync=True)
                self.wireshark_started = True
            except Exception as e:
                self.error('Wireshark could not start: ' + str(e))

        if save_pcap:
            self.pcap_writer = PcapWriter(self.pcap_filename, sync=True)
            if sys.platform == 'linux':
                os.system('chmod o+rw ' + self.pcap_filename)

    def signal_handler(self, signal, frame):
        self.error('You pressed Ctrl+C - or killed me with -2')
        exit(0)
        # sys.exit(0)

    # Logs

    def l(self, msg):
        print(Fore.YELLOW + '[' + self.TAG + '] ' + msg)

    def error(self, msg):
        print(Fore.RED + '[Error:' + self.TAG + '] ' + msg)

    # Main functions
    def start(self):

        if self.bridge_hci or self.bt_program is None:
            self.driver = ESP32BTDriver(self.serial_port, self.serial_baud)
            self.driver.enable_sniffing(1)
            self.driver.disable_poll_null(1)
            print(Fore.GREEN + 'ESP32BT driver started on ' +
                  self.serial_port + '@' + str(self.serial_baud))

            self.serial_thread = Thread(target=self.uart_rx_handler)
            self.serial_thread.daemon = True
            self.serial_thread.start()

        if self.bt_program is not None:
            self.bt_program_thread = Thread(target=self.bt_program_handler)
            self.bt_program_thread.daemon = True
            self.bt_program_thread.start()

    @staticmethod
    def skip_slashes(summary_text, idx):
        return '/'.join(summary_text.split('/')[idx:])

    def bt_program_handler(self):
        if self.bridge_hci:
            p_name = self.driver.serial_bridge_name
        else:
            p_name = self.serial_port

        print('Starting ' + self.bt_program + ' -u ' + p_name)
        process = subprocess.Popen([self.bt_program, '-u', p_name],
                                   #    stdin=subprocess.PIPE,
                                   #    stdout=subprocess.PIPE,
                                   #    stderr=subprocess.PIPE
                                   )
        self.bt_program_process = process

        while self.bt_program_run:
            sleep(1)

        rc = process.poll()
        return rc

    def uart_rx_handler(self):

        while self.run_driver:
            # Receive packet from the NRF52 Dongle
            data = self.driver.raw_receive()
            if data:
                # Decode Bluetooth Low Energy Data
                pkt = BT_Baseband(data)
                if pkt:
                    summary = pkt.summary()
                    direction = self.driver.direction
                    if direction == 1:
                        # print('R:' + summary)
                        self.log_rx(summary)
                        self.rx_packets += 1
                    elif direction == 0:

                        if BT_LMP in pkt:
                            # print('T:' + summary)
                            pkt = BT_ACL_Hdr(data)

                        self.log_tx(summary)
                        self.tx_packets += 1

                # self.update_summary(self.tx_packets, self.rx_packets)

                # Pipe/Save pcap
                hci_pkt = HCI_PHDR_Hdr(
                    direction=direction) / HCI_Hdr(type=8) / pkt
                if self.wireshark_started is True:
                    self.pcap_fifo_writer.write(hci_pkt)
                if self.save_pcap is True:
                    self.pcap_writer.write(hci_pkt)

    @staticmethod
    def decode_address(addr):
        return bytes.fromhex(''.join(addr.split(':')))

    def log_tx(self, log_message):
        print(Fore.CYAN + 'TX --> ' + log_message)

    def log_rx(self, log_message):
        print(Fore.GREEN + 'RX <-- ' + log_message)

    def update_summary(self, tx_pkts, rx_pkts):
        self.log_summary('TX packets: ' + str(tx_pkts))
        self.log_summary('RX Packets: ' + str(rx_pkts))
        self.log_summary('BT Clock: ' + str(self.driver.event_counter))


Sniffer = SnifferBREDR(serial_port='/dev/ttyUSB1',
                       serial_baud=4000000,
                       start_wireshark=False,
                       bt_program='./bin/spp_counter',
                       )
Sniffer.start()

try:
    while True:
        sleep(1)

except KeyboardInterrupt:
    if Sniffer.save_pcap:
        print(Fore.GREEN + 'Capture saved on capture_bluetooth.pcap')

    if Sniffer.bt_program_process is not None:
        Sniffer.bt_program_process.kill()
        print(Fore.YELLOW + 'BT Program finished')
