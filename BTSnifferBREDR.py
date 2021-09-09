#!./runtime/install/bin/python3

import os
import sys
import _ctypes
import ctypes
import _thread
import colorama
import subprocess
import random
import signal
import click
from threading import Thread
from time import sleep
from colorama import Fore, init
from scapy.layers.bluetooth import HCI_Hdr, HCI_PHDR_Hdr
from scapy.utils import wrpcap, PcapWriter
# Custom libs
from src.layers_bredr import ESP32_BREDR, BT_Baseband, BT_ACL_Hdr, BT_LMP
from src.ESP32BTDriver import ESP32BTDriver


class SnifferBREDR:
    TAG = 'Sniffer'
    working_dir = None
    wireshark_process = None
    pcap_fifo_filename = '/tmp/fifocap.fifo'
    pcap_filename = 'logs/capture_bluetooth.pcapng'
    save_pcap = False
    pcap_fifo_writer = None
    pcap_writer = None

    show_summary = True
    start_wireshark = False
    wireshark_started = False
    host_bdaddr = None

    driver = None  # type: ESP32BTDriver
    driver_run = False
    serial_port = None
    serial_baud = None
    serial_thread = None
    bridge_hci = True
    bt_program = None
    bt_program_thread = None
    bt_program_run = False
    bt_program_process = None
    # program parameters
    bt_bdaddr = None

    # BT Vars
    tx_packets = 0
    rx_packets = 0

    # Constructor
    def __init__(self,
                 serial_port=None,
                 serial_baud=921600,
                 show_summary=True,
                 start_wireshark=False,
                 save_pcap=True,
                 pcap_filename=None,
                 bridge_hci=True,
                 bt_program=None,
                 target_bdaddress=None,
                 host_bdaddr='E0:D4:E8:19:C7:68'):

        self.show_summary = show_summary
        self.start_wireshark = start_wireshark
        self.serial_port = serial_port
        self.serial_baud = serial_baud
        self.save_pcap = save_pcap
        self.bridge_hci = bridge_hci
        self.bt_bdaddr = target_bdaddress
        self.host_bdaddr = host_bdaddr

        if pcap_filename:
            self.pcap_filename = pcap_filename

        if bt_program:
            self.bt_program = bt_program

        if self.start_wireshark:
            try:
                os.remove(self.pcap_fifo_filename)
            except:
                pass
            os.mkfifo(self.pcap_fifo_filename)
            try:
                self.l('[!] Starting Wireshark...')
                self.wireshark_process = subprocess.Popen(
                    ['wireshark', '-k', '-i', self.pcap_fifo_filename])
                self.pcap_fifo_writer = PcapWriter(
                    self.pcap_fifo_filename, sync=True)
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
            self.driver.set_bdaddr(self.host_bdaddr)

            print(Fore.GREEN + 'ESP32BT driver started on ' +
                  self.serial_port + '@' + str(self.serial_baud))

            self.driver_run = True
            self.serial_thread = Thread(target=self.uart_rx_handler)
            self.serial_thread.daemon = True
            self.serial_thread.start()

        if self.bt_program is not None:
            self.bt_program_run = True
            self.bt_program_thread = Thread(target=self.bt_program_handler)
            self.bt_program_thread.daemon = True
            self.bt_program_thread.start()

    def bt_program_handler(self):
        if self.bridge_hci:
            p_name = self.driver.serial_bridge_name
        else:
            p_name = self.serial_port

        p_args = [self.bt_program, '-u', p_name, '-a', str(self.bt_bdaddr)]
        print('Starting ' + str(p_args))
        process = subprocess.Popen(p_args)
        self.bt_program_process = process

        while self.bt_program_run:
            sleep(1)

        rc = process.poll()
        return rc

    def uart_rx_handler(self):
        while self.driver_run:
            # Receive packet from the ESP32 Board
            data = self.driver.receive()
            if data is not None:
                # Decode Bluetooth Low Energy Data
                pkt = ESP32_BREDR(data)
                if pkt:
                    summary = pkt[BT_Baseband].summary()
                    direction = self.driver.direction
                    if direction == 1:
                        if self.show_summary:
                            self.log_rx(summary)
                        self.rx_packets += 1
                    elif direction == 0:
                        if self.show_summary:
                            self.log_tx(summary)
                        self.tx_packets += 1

                # Pipe / Save pcap
                hci_pkt = HCI_PHDR_Hdr(
                    direction=direction) / HCI_Hdr() / pkt
                if self.wireshark_started is True:
                    self.pcap_fifo_writer.write(hci_pkt)
                if self.save_pcap is True:
                    self.pcap_writer.write(hci_pkt)

    def log_tx(self, log_message):
        print(Fore.CYAN + 'TX --> ' + log_message)

    def log_rx(self, log_message):
        print(Fore.GREEN + 'RX <-- ' + log_message)


# Defaults
serial_port = '/dev/ttyUSB0'
serial_baud = 921600


@click.command()
@click.option('--port', default=serial_port,
              help='Serial port name (/dev/ttyUSBx for Linux)')
@click.option('--host', default='E0:D4:E8:19:C7:68', help='BDAddress of local host (default: E0:D4:E8:19:C7:68)')
@click.option('--target', help='BDAddress of remote target (ex: a8:96:75:25:c2:ac)')
@click.option('--live-wireshark', is_flag=True,
              help='Opens Wireshark live session')
@click.option('--live-terminal', is_flag=True,
              help='Show a summary of each packet on terminal')
@click.option('--bridge-only', is_flag=True,
              help='Starts the HCI bridge without connecting any BT Host stack')
def sniffer(port, host, target, live_wireshark, live_terminal, bridge_only):

    bt_program = None
    host_bdaddress = None
    target_bdaddress = None
    bd_role_master = False

    if target:
        # Check BDAddress format
        if ':' in target and (len(target.split(':')) == 6) and (len(target) == 17):
            target_bdaddress = target.lower()
        else:
            raise ValueError("Incorrect BDAddress format")

    if host:
        # Check BDAddress format
        if ':' in host and (len(host.split(':')) == 6) and (len(host) == 17):
            host_bdaddress = host.lower()
        else:
            raise ValueError("Incorrect BDAddress format")

    if (live_terminal or live_wireshark) and not bridge_only:
        bd_role_master = True if target else False
        bt_program = (
            './host_stack/sdp_rfcomm_query' if bd_role_master else './host_stack/spp_counter')
    else:
        print(Fore.YELLOW + '[!] Bridge will start without BT host stack')

    print('Using options:\n\
        Serial Port: %s\n\
        Serial Baud: %d\n\
        BT Host Program: %s\n\
        Host BDAddress: %s\n\
        Target BDAddress: %s' % (port, serial_baud, bt_program, host_bdaddress, target_bdaddress))

    Sniffer = SnifferBREDR(serial_port=port,
                           serial_baud=serial_baud,
                           show_summary=live_terminal,
                           start_wireshark=live_wireshark,
                           bt_program=bt_program,
                           target_bdaddress=target)
    Sniffer.start()

    try:
        while True:
            sleep(1)

    except KeyboardInterrupt:
        if Sniffer.save_pcap:
            print(Fore.GREEN + 'Capture saved on logs/capture_bluetooth.pcapng')

        if Sniffer.bt_program_process is not None:
            Sniffer.bt_program_process.kill()
            print(Fore.YELLOW + 'BT Program finished')


if __name__ == '__main__':
    init(autoreset=True)
    sniffer()
