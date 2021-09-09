from scapy.packet import bind_layers, Packet
from scapy.fields import ByteEnumField, ByteField, Field, FieldLenField, \
    FieldListField, FlagsField, BitEnumField, XIntField, IntField, LEShortEnumField, LEShortField, \
    LenField, PacketListField, SignedByteField, StrField, StrFixedLenField, \
    StrLenField, XByteField, BitField, BitFieldLenField, XStrFixedLenField, LEIntField, XLELongField, PadField, \
    UUIDField, \
    XStrLenField, ConditionalField
from scapy.layers.bluetooth import HCI_PHDR_Hdr, HCI_Hdr, L2CAP_Hdr


_bluetooth_lmp_opcode = {
    0: "LMP_Broadcom_BPCS",
    1: "LMP_name_req",
    2: "LMP_name_res",
    3: "LMP_accepted",
    4: "LMP_not_accepted",
    5: "LMP_clkoffset_req",
    6: "LMP_clkoffset_res",
    7: "LMP_detach",
    8: "LMP_in_rand",
    9: "LMP_comb_key",
    10: "LMP_unit_key",
    11: "LMP_au_rand",
    12: "LMP_sres",
    13: "LMP_temp_rand",
    14: "LMP_temp_key",
    15: "LMP_encryption_mode_req",
    16: "LMP_encryption_key_size_req",
    17: "LMP_start_encryption_req",
    18: "LMP_stop_encryption_req",
    19: "LMP_switch_req",
    20: "LMP_hold",
    21: "LMP_hold_req",
    23: "LMP_sniff_req",
    24: "LMP_unsniff_req",
    25: "LMP_park_req",
    27: "LMP_set_broadcast_scan_window",
    28: "LMP_modify_beacon",
    29: "LMP_unpark_BD_ADDR_req",
    30: "LMP_unpark_PM_ADDR_req",
    31: "LMP_incr_power_req",
    32: "LMP_decr_power_req",
    33: "LMP_max_power",
    34: "LMP_min_power",
    35: "LMP_auto_rate",
    36: "LMP_preferred_rate",
    37: "LMP_version_req",
    38: "LMP_version_res",
    39: "LMP_features_req",
    40: "LMP_features_res",
    41: "LMP_quality_of_service",
    42: "LMP_quality_of_service_req",
    43: "LMP_SCO_link_req",
    44: "LMP_remove_SCO_link_req",
    45: "LMP_max_slot",
    46: "LMP_max_slot_req",
    47: "LMP_timing_accuracy_req",
    48: "LMP_timing_accuracy_res",
    49: "LMP_setup_complete",
    50: "LMP_use_semi_permanent_key",
    51: "LMP_host_connection_req",
    52: "LMP_slot_offset",
    53: "LMP_page_mode_req",
    54: "LMP_page_scan_mode_req",
    55: "LMP_supervision_timeout",
    56: "LMP_test_activate",
    57: "LMP_test_control",
    58: "LMP_encryption_key_size_mask_req",
    59: "LMP_encryption_key_size_mask_res",
    60: "LMP_set_AFH",
    61: "LMP_encapsulated_header",
    62: "LMP_encapsulated_payload",
    63: "LMP_Simple_Pairing_Confirm",
    64: "LMP_Simple_Pairing_Number",
    65: "LMP_DHkey_Check",
    124: "Escape 1",
    125: "Escape 2",
    126: "Escape 3",
    127: "Escape 4",
}

_bluetooth_lmp_ext_opcode = {
    1: "LMP_accepted_ext",
    2: "LMP_not_accepted_ext",
    3: "LMP_features_req_ext",
    4: "LMP_features_res_ext",
    11: "LMP_packet_type_table_req",
    12: "LMP_eSCO_link_req",
    13: "LMP_remove_eSCO_link_req",
    16: "LMP_channel_classification_req",
    17: "LMP_channel_classification",
    21: "LMP_sniff_subrating_req",
    22: "LMP_sniff_subrating_res",
    23: "LMP_pause_encryption_req",
    24: "LMP_resume_encryption_req",
    25: "LMP_IO_Capability_req",
    26: "LMP_IO_Capability_res",
    27: "LMP_numeric_comparison_failed",
    28: "LMP_passkey_failed",
    29: "LMP_oob_failed",
    30: "LMP_keypress_notification",
    31: "LMP_power_control_req",
    32: "LMP_power_control_res",
}

_bluetooth_lmp_error_code = {
    0: "Success",
    1: "Unknown HCI Command",
    2: "Unknown Connection Identifier",
    3: "Hardware Failure",
    4: "Page Timeout",
    5: "Authentication Failure",
    6: "PIN or Key Missing",
    7: "Memory Capacity Exceeded",
    8: "Connection Timeout",
    9: "Connection Limit Exceeded",
    10: "Synchronous Connection Limit To A Device Exceeded",
    11: "ACL Connection Already Exists",
    12: "Command Disallowed",
    13: "Connection Rejected due to Limited Resources",
    14: "Connection Rejected Due To Security Reasons",
    15: "Connection Rejected due to Unacceptable BD_ADDR",
    16: "Connection Accept Timeout Exceeded",
    17: "Unsupported Feature or Parameter Value",
    18: "Invalid HCI Command Parameters",
    19: "Remote User Terminated Connection",
    20: "Remote Device Terminated Connection due to Low Resources",
    21: "Remote Device Terminated Connection due to Power Off",
    22: "Connection Terminated By Local Host",
    23: "Repeated Attempts",
    24: "Pairing Not Allowed",
    25: "Unknown LMP PDU",
    26: "Unsupported Remote Feature / Unsupported LMP Feature",
    27: "SCO Offset Rejected",
    28: "SCO Interval Rejected",
    29: "SCO Air Mode Rejected",
    30: "Invalid LMP Parameters",
    31: "Unspecified Error",
    32: "Unsupported LMP Parameter Value",
    33: "Role Change Not Allowed",
    34: "LMP Response Timeout",
    35: "LMP Error Transaction Collision",
    36: "LMP PDU Not Allowed",
    37: "Encryption Mode Not Acceptable",
    38: "Link Key Can Not be Changed",
    39: "Requested QoS Not Supported",
    40: "Instant Passed",
    41: "Pairing With Unit Key Not Supported",
    42: "Different Transaction Collision",
    43: "Reserved",
    44: "QoS Unacceptable Parameter",
    45: "QoS Rejected",
    46: "Channel Classification Not Supported",
    47: "Insufficient Security",
    48: "Parameter Out Of Mandatory Range",
    49: "Reserved",
    50: "Role Switch Pending",
    51: "Reserved",
    52: "Reserved Slot Violation",
    53: "Role Switch Failed",
    54: "Extended Inquiry Response Too Large",
    55: "Secure Simple Pairing Not Supported By Host.",
    56: "Host Busy - Pairing",
    57: "Connection Rejected due to No Suitable Channel Found",
}

_bluetooth_lmp_versnr = {
    0: "1.0b",
    1: "1.1",
    2: "1.2",
    3: "2.0 + EDR",
    4: "2.1 + EDR",
    5: "3.0 + HS",
    6: "4.0",
    7: "4.1",
    8: "4.2",
    9: "5.0",
    10: "5.1",
    11: "5.2"
}

_bluetooth_lmp_features = [
    "lstimche", "inqtxpwr", "enhpwr", "res5", "res6", "res7", "res8", "extfeat",
    "extinqres", "simlebredr", "res3", "ssp", "enpdu", "edr", "nonflush", "res4",
    "5slotenh", "sniffsubr", "pauseenc", "afhcapma", "afhclama", "esco2", "esco3", "3slotenhesco",
    "ev4", "ev5", "res2", "afhcapsl", "afhclasl", "bredrnotsup", "lesup", "3slotenh",
    "res1", "acl2", "acl3", "eninq", "intinq", "intpag", "rssiinq", "ev3",
    "cvsd", "pagneg", "pwrctl", "transsync", "flowctl1", "flowctl2", "flowctl3", "bcenc",
    "res0", "pwrctlreq", "cqddr", "sco", "hv2", "hv3", "mulaw", "alaw",
    "3slot", "5slot", "enc", "slotoff", "timacc", "rolesw", "holdmo", "sniffmo",  # First octet
]

_bluetooth_lmp_ext_features_1 = [
    "un48", "un49", "un50", "un51", "un52", "un53", "un54", "un55",
    "un56", "un57", "un58", "un59", "un60", "un61", "un62", "un63",
    "un40", "un41", "un42", "un43", "un44", "un45", "un46", "un47",
    "un32", "un33", "un34", "un35", "un36", "un37", "un38", "un39",
    "un24", "un25", "un26", "un27", "un28", "un29", "un30", "un31",
    "un16", "un17", "un18", "un19", "un20", "un21", "un22", "un23",
    "un8", "un9", "un10", "un11", "un12", "un13", "un14", "un15",
    "ssp", "lesup", "lebredr", "sch", "un4", "un5", "un6", "un7",  # First octet
]

_bluetooth_lmp_ext_features_2 = [
    "un48", "un49", "un50", "un51", "un52", "un53", "un54", "un55",
    "un56", "un57", "un58", "un59", "un60", "un61", "un62", "un63",
    "un40", "un41", "un42", "un43", "un44", "un45", "un46", "un47",
    "un32", "un33", "un34", "un35", "un36", "un37", "un38", "un39",
    "un24", "un25", "un26", "un27", "un28", "un29", "un30", "un31",
    "un16", "un17", "un18", "un19", "un20", "un21", "un22", "un23",
    "scc", "ping", "res1", "trnud", "sam", "un13", "un14", "un15",
    "csbma", "csbsl", "syntr", "synsc", "inqresnote", "genintsc", "ccadj", "res0",  # First octet
]

_bluetooth_lmp_features_unused = [
    "un48", "un49", "un50", "un51", "un52", "un53", "un54", "un55",
    "un56", "un57", "un58", "un59", "un60", "un61", "un62", "un63",
    "un40", "un41", "un42", "un43", "un44", "un45", "un46", "un47",
    "un32", "un33", "un34", "un35", "un36", "un37", "un38", "un39",
    "un24", "un25", "un26", "un27", "un28", "un29", "un30", "un31",
    "un16", "un17", "un18", "un19", "un20", "un21", "un22", "un23",
    "un8", "un9", "un10", "un11", "un12", "un13", "un14", "un15",
    "un0", "un1", "un2", "un3", "un4", "un5", "un6", "un7",  # First octet
]

_bluetooth_lmp_power_adjustment_res = {
    0: "not supported",
    1: "changed one step (not min or max)",
    2: "max power",
    3: "min power"
}


class ESP32_BREDR(Packet):
    name = "ESP32_BREDR"
    fields_desc = [

        LEIntField("clk", 0),
        ByteField("channel", 0),

        BitField("is_eir", 0, 1),
        BitField("rx_enc", 0, 1),
        BitField("tx_enc", 0, 1),
        BitField("rfu", 0, 3),
        BitEnumField("role", 0, 1, {0x00: 'Master', 0x01: 'Slave'}),
        BitField("is_edr", 0, 1),
    ]


class BT_Baseband(Packet):
    name = "BT_Baseband"
    fields_desc = [

        BitField("flow", 0, 1),
        BitEnumField("type", 0, 4, {0x00: 'NULL', 0x01: 'POLL',
                     0x2: "FHS", 0x03: "DM1", 0x04: "DH1/2-DH1", 0x08: "DV/3-DH1"}),
        BitField("lt_addr", 0, 3),

        # BitField("lt_addr", 0, 3),
        # BitEnumField("type", 0, 4, {0x00: 'NULL', 0x01: 'POLL',
        #              0x2: "FHS", 0x03: "DM1", 0x04: "DH1/2-DH1", 0x08: "DV/3-DH1"}),
        # BitField("flow", 0, 1),

        BitField("arqn", 0, 1),
        BitField("seqn", 0, 1),
        BitField("hec", 0, 6),
    ]

    def guess_payload_class(self, payload):
        if self.type == 0x04 or self.type == 0x08:
            return BT_ACL_Hdr
        else:
            return Packet.guess_payload_class(self, payload)


class BT_ACL_Hdr(Packet):
    name = "BT ACL Header"
    fields_desc = [
        # BitField("rfu", 0, 3),
        BitFieldLenField("len", None, 5),
        BitEnumField("flow", 0, 1, {0: False, 1: True}),
        BitEnumField("llid", 0, 2, {0x00: 'undefined',
                                    0x01: 'Continuation fragment of an L2CAP message',
                                    0x02: 'Start of an L2CAP message or no fragmentation',
                                    0x03: 'LMP'}),
        ByteField('dummy', 0)
    ]


class BT_LMP(Packet):
    name = "Bluetooth Link Manager Protocol"
    fields_desc = [
        BitEnumField("opcode", 0, 7, _bluetooth_lmp_opcode),
        BitField("tid", None, 1),
        ConditionalField(ByteEnumField("ext_opcode", 3, _bluetooth_lmp_ext_opcode),
                         lambda pkt: pkt.opcode == 127),
    ]

    # Override default dissection function to include empty packet types
    def do_dissect_payload(self, s):
        cls = self.guess_payload_class(s)
        if s or not cls.fields_desc:
            p = cls(s, _internal=1, _underlayer=self)
            self.add_payload(p)


class LMP_features_req(Packet):
    name = "LMP_features_req"
    fields_desc = [FlagsField(
        "features", 0x8f7bffdbfecffebf, 64, _bluetooth_lmp_features)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_features_res(LMP_features_req):
    name = "LMP_features_res"


class LMP_version_req(Packet):
    name = "LMP_version_req"
    fields_desc = [
        # Version 4.2 by default
        ByteEnumField("version", 8, _bluetooth_lmp_versnr),
        LEShortField("company_id", 15),  # Broadcom
        LEShortField("subversion", 24841)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_version_res(LMP_version_req):
    name = "LMP_version_res"


class LMP_features_req_ext(Packet):
    name = "LMP_features_req_ext"
    fields_desc = [ByteEnumField("fpage", 1, {0: "standard features",
                                              1: "extended features 64-67",
                                              2: "extended features 128-140"}),
                   ByteField("max_page", 2),
                   ConditionalField(FlagsField("features0", 0, 64, _bluetooth_lmp_features),
                                    lambda pkt: pkt.fpage == 0),
                   ConditionalField(FlagsField("features1", 0, 64, _bluetooth_lmp_ext_features_1),
                                    lambda pkt: pkt.fpage == 1),
                   ConditionalField(FlagsField("features2", 0, 64, _bluetooth_lmp_ext_features_2),
                                    lambda pkt: pkt.fpage == 2),
                   ConditionalField(FlagsField("features", 0, 64, _bluetooth_lmp_ext_features_2),
                                    lambda pkt: pkt.fpage > 2),
                   ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_features_res_ext(LMP_features_req_ext):
    name = "LMP_features_res_ext"


class LMP_name_req(Packet):
    name = "LMP_name_req"
    fields_desc = [ByteField("name_offset", 0)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_name_res(Packet):
    name = "LMP_name_res"
    fields_desc = [
        ByteField("name_offset", 0),
        FieldLenField("name_len", None, length_of="name_frag", fmt="B"),
        StrLenField("name_frag", "", length_from=lambda pkt: pkt.name_len),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_detach(Packet):
    name = "LMP_detach"
    fields_desc = [ByteEnumField(
        "error_code", 0x13, _bluetooth_lmp_error_code)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_host_connection_req(Packet):
    name = "LMP_host_connection_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_accepted(Packet):
    name = "LMP_accepted"
    fields_desc = [
        BitField("unused", 0, 1),
        BitEnumField("code", 51, 7, _bluetooth_lmp_opcode),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_not_accepted(Packet):
    name = "LMP_not_accepted"
    fields_desc = [
        BitField("unused", 0, 1),
        BitEnumField("code", 51, 7, _bluetooth_lmp_opcode),
        ByteEnumField("error_code", 6, _bluetooth_lmp_error_code)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_au_rand(Packet):
    name = "LMP_au_rand"
    fields_desc = [
        StrFixedLenField("rand", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_encapsulated_header(Packet):
    name = "LMP_encapsulated_header"
    fields_desc = [
        ByteField("major_type", 1),
        ByteField("minor_type", 1),
        ByteField("enc_len", 48),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_encapsulated_payload(Packet):
    name = "LMP_encapsulated_payload"
    fields_desc = [
        StrFixedLenField("data", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_Simple_Pairing_Confirm(Packet):
    name = "LMP_Simple_Pairing_Confirm"
    fields_desc = [
        StrFixedLenField("commit", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_Simple_Pairing_Number(Packet):
    name = "LMP_Simple_Pairing_Number"
    fields_desc = [
        StrFixedLenField("nonce", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_DHkey_Check(Packet):
    name = "LMP_DHkey_Check"
    fields_desc = [
        StrFixedLenField("confirm", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_sres(Packet):
    name = "LMP_sres"
    fields_desc = [
        StrFixedLenField("authres", b"\x00" * 4, 4)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_encryption_mode_req(Packet):
    name = "LMP_encryption_mode_req"
    fields_desc = [
        ByteEnumField("mode", 1, {
            0: "no encryption",
            1: "encryption",
            2: "previously used",
        })
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_encryption_key_size_req(Packet):
    name = "LMP_encryption_key_size_req"
    fields_desc = [ByteField("keysize", 16)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_start_encryption_req(Packet):
    name = "LMP_start_encryption_req"
    fields_desc = [
        StrFixedLenField("rand", b"\x00" * 16, 16)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_stop_encryption_req(Packet):
    name = "LMP_stop_encryption_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_setup_complete(Packet):
    name = "LMP_setup_complete"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_packet_type_table_req(Packet):
    name = "LMP_packet_type_table_req"
    fields_desc = [ByteEnumField("pkt_type_table", 1, {
        0: "1 Mbps only",
        1: "2/3 Mbps",
    })]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_accepted_ext(Packet):
    name = "LMP_accepted_ext"
    fields_desc = [
        BitField("unused", 0, 1),
        BitEnumField("code1", 127, 7, _bluetooth_lmp_opcode),
        ByteEnumField("code2", 11, _bluetooth_lmp_ext_opcode)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_not_accepted_ext(Packet):
    name = "LMP_accepted_ext"
    fields_desc = [
        BitField("unused", 0, 1),
        BitEnumField("code1", 127, 7, _bluetooth_lmp_opcode),
        ByteEnumField("code2", 11, _bluetooth_lmp_ext_opcode),
        ByteEnumField("error_code", 6, _bluetooth_lmp_error_code),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_set_AFH(Packet):
    name = "LMP_set_AFH"
    fields_desc = [
        LEIntField("instant", 0x00011cee),
        ByteEnumField("mode", 1, {
            0: "disabled",
            1: "enabled"
        }),
        XStrFixedLenField(
            "chM", b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f', 10),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_channel_classification_req(Packet):
    name = "LMP_channel_classification_req"
    fields_desc = [
        ByteEnumField("mode", 1, {
            0: "AFH reporting disabled",
            1: "AFH reporting enabled"
        }),
        LEShortField("min_interval", 0x0640),
        LEShortField("max_interval", 0xbb80),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_channel_classification(Packet):
    name = "LMP_channel_classification"
    fields_desc = [XStrFixedLenField(
        "class", b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f', 10)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_max_slot_req(Packet):
    name = "LMP_max_slot_req"
    fields_desc = [ByteField("max_slots", 5)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_max_slot(LMP_max_slot_req):
    name = "LMP_max_slot"


class LMP_clkoffset_req(Packet):
    name = "LMP_clkoffset_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_clkoffset_res(Packet):
    name = "LMP_clkoffset_res"
    fields_desc = [LEShortField("offset", 9450)]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_sniff_req(Packet):
    name = "LMP_sniff_req"
    fields_desc = [
        FlagsField("timectr", 0x02, 8, [
                   "change", "init", "accwin", "un3", "un4", "un5", "un6", "un7"]),
        LEShortField("dsniff", 0),
        LEShortField("tsniff", 0x31e),
        LEShortField("sniff_attempt", 4),
        LEShortField("sniff_timeout", 1),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_unsniff_req(Packet):
    name = "LMP_unsniff_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_max_power(Packet):
    name = "LMP_max_power"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_min_power(Packet):
    name = "LMP_min_power"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_power_control_req(Packet):
    name = "LMP_power_control_req"
    fields_desc = [ByteEnumField("poweradj", 0, {
        0: "decrement power one step",
        1: "increment power one step",
        2: "increase to maximum power"
    })]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_power_control_res(Packet):
    name = "LMP_power_control_res"
    fields_desc = [
        BitField("unused", 0, 2),
        BitEnumField("p_8dpsk", 1, 2, _bluetooth_lmp_power_adjustment_res),
        BitEnumField("p_dqpsk", 1, 2, _bluetooth_lmp_power_adjustment_res),
        BitEnumField("p_gfsk", 1, 2, _bluetooth_lmp_power_adjustment_res),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_auto_rate(Packet):
    name = "LMP_auto_rate"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_preferred_rate(Packet):
    name = "LMP_preferred_rate"
    fields_desc = [
        BitField("rfu", 0, 1),
        BitEnumField("edrsize", 0, 2, {
            0: "not available",
            1: "1-slot packets",
            2: "3-slot packets",
            3: "5-slot packets",
        }),
        BitEnumField("type", 0, 2, {
            0: "DM1 packets",
            1: "2MBs packets",
            2: "3MBs packets",
            3: "rfu",
        }),
        BitEnumField("size", 0, 2, {
            0: "not available",
            1: "1-slot packets",
            2: "3-slot packets",
            3: "5-slot packets",
        }),
        BitEnumField("fec", 0, 1, {
            0: "use FEC",
            1: "do not use FEC"
        }),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_timing_accuracy_req(Packet):
    name = "LMP_timing_accuracy_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_timing_accuracy_res(Packet):
    name = "LMP_timing_accuracy_res"
    fields_desc = [
        ByteField("drift", 45),
        ByteField("jitter", 10)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_page_scan_mode_req(Packet):
    name = "LMP_page_scan_mode_req"
    fields_desc = [
        ByteEnumField("scheme", 45, {0: "mandatory"}),
        ByteEnumField("settings", 10, {
            0: "R0",
            1: "R1",
            2: "R2"
        })
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_page_mode_req(Packet):
    name = "LMP_page_mode_req"
    fields_desc = [
        ByteEnumField("scheme", 45, {0: "mandatory"}),
        ByteEnumField("settings", 10, {
            0: "R0",
            1: "R1",
            2: "R2"
        })
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_supervision_timeout(Packet):
    name = "LMP_supervision_timeout"
    fields_desc = [
        LEShortField("timeout", 8000)
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_sniff_subrating_req(Packet):
    name = "LMP_sniff_subrating_req"
    fields_desc = [
        ByteField("max_sniff_subrate", 1),
        LEShortField("min_sniff_timeout", 2),
        LEShortField("subrating_instant", 42432),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_sniff_subrating_res(LMP_sniff_subrating_req):
    name = "LMP_sniff_subrating_res"


class LMP_pause_encryption_req(Packet):
    name = "LMP_pause_encryption_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_resume_encryption_req(Packet):
    name = "LMP_resume_encryption_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_IO_Capability_req(Packet):
    name = "LMP_IO_Capability_req"
    fields_desc = [
        ByteEnumField("io_cap", 0x03, {
            0: "DisplayOnly",
            1: "DisplayYesNo",
            2: "KeyboardOnly",
            3: "NoInputNoOutput"
        }),
        ByteEnumField("oob", 0x00, {
            0: "not present",
            1: "P-192",
            2: "P-256",
            3: "P-192 and P-256"
        }),
        ByteEnumField("auth", 0x03, {
            0: "MITM Protection Not Required - No Bonding",
            1: "MITM Protection Required - No Bonding",
            2: "MITM Protection Not Required - Dedicated Bonding",
            3: "MITM Protection Required - Dedicated Bonding",
            4: "MITM Protection Not Required - General Bonding",
            5: "MITM Protection Required - General Bonding"
        }),
    ]

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_IO_Capability_res(LMP_IO_Capability_req):
    name = "LMP_IO_Capability_res"


class LMP_numeric_comparison_failed(Packet):
    name = "LMP_IO_Capability_res"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_passkey_failed(Packet):
    name = "LMP_passkey_failed"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_oob_failed(Packet):
    name = "LMP_oob_failed"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_ping_req(Packet):
    name = "LMP_ping_req"

    def post_dissect(self, s):
        # Truncate padding
        return ""


class LMP_ping_res(Packet):
    name = "LMP_ping_res"

    def post_dissect(self, s):
        # Truncate padding
        return ""


bind_layers(HCI_Hdr, ESP32_BREDR, type=9)

bind_layers(ESP32_BREDR, BT_Baseband)

bind_layers(BT_Baseband, BT_ACL_Hdr, type=0x08)
bind_layers(BT_Baseband, BT_ACL_Hdr, type=0x04)
bind_layers(BT_Baseband, BT_ACL_Hdr, type=0x03)

bind_layers(BT_ACL_Hdr, BT_LMP, llid=0x03)
bind_layers(BT_ACL_Hdr, L2CAP_Hdr, llid=0x02)

bind_layers(BT_LMP, LMP_name_req, opcode=1)
bind_layers(BT_LMP, LMP_name_res, opcode=2)
bind_layers(BT_LMP, LMP_accepted, opcode=3)
bind_layers(BT_LMP, LMP_not_accepted, opcode=4)
bind_layers(BT_LMP, LMP_clkoffset_req, opcode=5)
bind_layers(BT_LMP, LMP_clkoffset_res, opcode=6)
bind_layers(BT_LMP, LMP_detach, opcode=7)
bind_layers(BT_LMP, LMP_sniff_req, opcode=23)
bind_layers(BT_LMP, LMP_unsniff_req, opcode=24)
bind_layers(BT_LMP, LMP_max_power, opcode=33)
bind_layers(BT_LMP, LMP_min_power, opcode=34)
bind_layers(BT_LMP, LMP_auto_rate, opcode=35)
bind_layers(BT_LMP, LMP_preferred_rate, opcode=36)
bind_layers(BT_LMP, LMP_version_req, opcode=37)
bind_layers(BT_LMP, LMP_version_res, opcode=38)
bind_layers(BT_LMP, LMP_features_req, opcode=39)
bind_layers(BT_LMP, LMP_features_res, opcode=40)
bind_layers(BT_LMP, LMP_max_slot, opcode=45)
bind_layers(BT_LMP, LMP_max_slot_req, opcode=46)
bind_layers(BT_LMP, LMP_timing_accuracy_req, opcode=47)
bind_layers(BT_LMP, LMP_timing_accuracy_res, opcode=48)
bind_layers(BT_LMP, LMP_setup_complete, opcode=49)
bind_layers(BT_LMP, LMP_host_connection_req, opcode=51)
bind_layers(BT_LMP, LMP_page_mode_req, opcode=53)
bind_layers(BT_LMP, LMP_page_scan_mode_req, opcode=54)
bind_layers(BT_LMP, LMP_supervision_timeout, opcode=55)
bind_layers(BT_LMP, LMP_set_AFH, opcode=60)
bind_layers(BT_LMP, LMP_encapsulated_header, opcode=61)
bind_layers(BT_LMP, LMP_encapsulated_payload, opcode=62)
bind_layers(BT_LMP, LMP_Simple_Pairing_Confirm, opcode=63)
bind_layers(BT_LMP, LMP_Simple_Pairing_Number, opcode=64)
bind_layers(BT_LMP, LMP_DHkey_Check, opcode=65)
bind_layers(BT_LMP, LMP_au_rand, opcode=11)
bind_layers(BT_LMP, LMP_sres, opcode=12)
bind_layers(BT_LMP, LMP_encryption_mode_req, opcode=15)
bind_layers(BT_LMP, LMP_encryption_key_size_req, opcode=16)
bind_layers(BT_LMP, LMP_start_encryption_req, opcode=17)
bind_layers(BT_LMP, LMP_stop_encryption_req, opcode=18)
bind_layers(BT_LMP, LMP_accepted_ext, ext_opcode=1)
bind_layers(BT_LMP, LMP_not_accepted_ext, ext_opcode=2)
bind_layers(BT_LMP, LMP_features_req_ext, ext_opcode=3)
bind_layers(BT_LMP, LMP_features_res_ext, ext_opcode=4)
bind_layers(BT_LMP, LMP_packet_type_table_req, ext_opcode=11)
bind_layers(BT_LMP, LMP_channel_classification_req, ext_opcode=16)
bind_layers(BT_LMP, LMP_channel_classification, ext_opcode=17)
bind_layers(BT_LMP, LMP_sniff_subrating_req, ext_opcode=21)
bind_layers(BT_LMP, LMP_sniff_subrating_res, ext_opcode=22)
bind_layers(BT_LMP, LMP_pause_encryption_req, ext_opcode=23)
bind_layers(BT_LMP, LMP_resume_encryption_req, ext_opcode=24)
bind_layers(BT_LMP, LMP_IO_Capability_req, ext_opcode=25)
bind_layers(BT_LMP, LMP_IO_Capability_res, ext_opcode=26)
bind_layers(BT_LMP, LMP_numeric_comparison_failed, ext_opcode=27)
bind_layers(BT_LMP, LMP_passkey_failed, ext_opcode=28)
bind_layers(BT_LMP, LMP_oob_failed, ext_opcode=29)
bind_layers(BT_LMP, LMP_power_control_req, ext_opcode=31)
bind_layers(BT_LMP, LMP_power_control_res, ext_opcode=32)
bind_layers(BT_LMP, LMP_ping_req, ext_opcode=33)
bind_layers(BT_LMP, LMP_ping_res, ext_opcode=34)
