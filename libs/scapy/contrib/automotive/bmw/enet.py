# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = ENET - BMW diagnostic protocol over Ethernet
# scapy.contrib.status = loads

import struct
import socket
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import IntField, ShortEnumField, XByteField
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.contrib.automotive.uds import UDS
from scapy.contrib.isotp import ISOTP
from scapy.error import Scapy_Exception
from scapy.data import MTU


"""
BMW specific diagnostic over IP protocol implementation ENET
"""

# #########################ENET###################################


class ENET(Packet):
    name = 'ENET'
    fields_desc = [
        IntField('length', None),
        ShortEnumField('type', 1, {0x01: "message",
                                   0x02: "echo"}),
        XByteField('src', 0),
        XByteField('dst', 0),
    ]

    def hashret(self):
        hdr_hash = struct.pack("B", self.src ^ self.dst)
        pay_hash = self.payload.hashret()
        return hdr_hash + pay_hash

    def answers(self, other):
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def extract_padding(self, s):
        return s[:self.length - 2], s[self.length - 2:]

    def post_build(self, pkt, pay):
        """
        This will set the LenField 'length' to the correct value.
        """
        if self.length is None:
            pkt = struct.pack("!I", len(pay) + 2) + pkt[4:]
        return pkt + pay


bind_bottom_up(TCP, ENET, sport=6801)
bind_bottom_up(TCP, ENET, dport=6801)
bind_layers(TCP, ENET, sport=6801, dport=6801)
bind_layers(ENET, UDS)


# ########################ENETSocket###################################


class ENETSocket(StreamSocket):
    def __init__(self, ip='127.0.0.1', port=6801):
        self.ip = ip
        self.port = port
        s = socket.socket()
        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s, ENET)


class ISOTP_ENETSocket(ENETSocket):
    def __init__(self, src, dst, ip='127.0.0.1', port=6801, basecls=ISOTP):
        super(ISOTP_ENETSocket, self).__init__(ip, port)
        self.src = src
        self.dst = dst
        self.basecls = ENET
        self.outputcls = basecls

    def send(self, x):
        if not isinstance(x, ISOTP):
            raise Scapy_Exception("Please provide a packet class based on "
                                  "ISOTP")
        super(ISOTP_ENETSocket, self).send(
            ENET(src=self.src, dst=self.dst) / x)

    def recv(self, x=MTU):
        pkt = super(ISOTP_ENETSocket, self).recv(x)
        return self.outputcls(bytes(pkt[1]))
