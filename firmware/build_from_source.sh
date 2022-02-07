#!/usr/bin/env bash

git submodule init
git submodule update
cd esp32_firmware_patching_framework
./firmware.py build sniffer-serial
cp .pio/build/sniffer-serial/bootloader.bin ../
cp .pio/build/sniffer-serial/partitions.bin ../
cp .pio/build/sniffer-serial/firmware.bin ../ && echo 'Done. flash built firmware via ./firmware.py flash <serial port>'
