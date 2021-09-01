Bluetooth H4 Broadcom Wireshark plugin from the InternalBlue project
====================================================================

This dissector contains vendor specific additions to the serial protocol
H4, which is used by the operating system's driver to interact with
Bluetooth chips. Broadcom not only supports sending standard messages
such as HCI commands and events but also has an undocumented
diagnostic protocol using the H4 serial data type 0x07.

Subprotocols inside Broadcom's diagnostic protocol include the Link Management
Protocol (LMP) and Bluetooth Baseband (BB). The dissectors for LMP and BB were
updated to be compatible with Wireshark 3.0. Credit for most of the LMP and BB
dissector goes to the original authors of libbtbb.

About this repository
---------------------

This repository contains only the Wireshark dissector without the rest of
Internalblue. All credit goes to the original authors of InternalBlue. For
additional information see the original repository:

https://github.com/seemoo-lab/internalblue

Build and Install
-----------------

To build this on Debian/Ubuntu/BackTrack linux distributions:

    sudo apt-get install wireshark-dev wireshark cmake

    mkdir build
    cd build
    cmake ..
    make
    make install

This will install to the ~/.local/lib/wireshark/plugins/3.0/epan/ in your home
directory. To override this set the DESTDIR environment variable when running
cmake.

