/* packet-btbrlmp.c
 * Routines for Bluetooth LMP dissection
 * Copyright 2009, Michael Ossmann <mike@ossmann.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

/* LMP opcodes */
#define LMP_VSC 0
#define LMP_NAME_REQ 1
#define LMP_NAME_RES 2
#define LMP_ACCEPTED 3
#define LMP_NOT_ACCEPTED 4
#define LMP_CLKOFFSET_REQ 5
#define LMP_CLKOFFSET_RES 6
#define LMP_DETACH 7
#define LMP_IN_RAND 8
#define LMP_COMB_KEY 9
#define LMP_UNIT_KEY 10
#define LMP_AU_RAND 11
#define LMP_SRES 12
#define LMP_TEMP_RAND 13
#define LMP_TEMP_KEY 14
#define LMP_ENCRYPTION_MODE_REQ 15
#define LMP_ENCRYPTION_KEY_SIZE_REQ 16
#define LMP_START_ENCRYPTION_REQ 17
#define LMP_STOP_ENCRYPTION_REQ 18
#define LMP_SWITCH_REQ 19
#define LMP_HOLD 20
#define LMP_HOLD_REQ 21
#define LMP_SNIFF_REQ 23
#define LMP_UNSNIFF_REQ 24
#define LMP_PARK_REQ 25
#define LMP_SET_BROADCAST_SCAN_WINDOW 27
#define LMP_MODIFY_BEACON 28
#define LMP_UNPARK_BD_ADDR_REQ 29
#define LMP_UNPARK_PM_ADDR_REQ 30
#define LMP_INCR_POWER_REQ 31
#define LMP_DECR_POWER_REQ 32
#define LMP_MAX_POWER 33
#define LMP_MIN_POWER 34
#define LMP_AUTO_RATE 35
#define LMP_PREFERRED_RATE 36
#define LMP_VERSION_REQ 37
#define LMP_VERSION_RES 38
#define LMP_FEATURES_REQ 39
#define LMP_FEATURES_RES 40
#define LMP_QUALITY_OF_SERVICE 41
#define LMP_QUALITY_OF_SERVICE_REQ 42
#define LMP_SCO_LINK_REQ 43
#define LMP_REMOVE_SCO_LINK_REQ 44
#define LMP_MAX_SLOT 45
#define LMP_MAX_SLOT_REQ 46
#define LMP_TIMING_ACCURACY_REQ 47
#define LMP_TIMING_ACCURACY_RES 48
#define LMP_SETUP_COMPLETE 49
#define LMP_USE_SEMI_PERMANENT_KEY 50
#define LMP_HOST_CONNECTION_REQ 51
#define LMP_SLOT_OFFSET 52
#define LMP_PAGE_MODE_REQ 53
#define LMP_PAGE_SCAN_MODE_REQ 54
#define LMP_SUPERVISION_TIMEOUT 55
#define LMP_TEST_ACTIVATE 56
#define LMP_TEST_CONTROL 57
#define LMP_ENCRYPTION_KEY_SIZE_MASK_REQ 58
#define LMP_ENCRYPTION_KEY_SIZE_MASK_RES 59
#define LMP_SET_AFH 60
#define LMP_ENCAPSULATED_HEADER 61
#define LMP_ENCAPSULATED_PAYLOAD 62
#define LMP_SIMPLE_PAIRING_CONFIRM 63
#define LMP_SIMPLE_PAIRING_NUMBER 64
#define LMP_DHKEY_CHECK 65
#define LMP_ESCAPE_1 124
#define LMP_ESCAPE_2 125
#define LMP_ESCAPE_3 126
#define LMP_ESCAPE_4 127

/* LMP extended opcodes */
#define LMP_ACCEPTED_EXT 1
#define LMP_NOT_ACCEPTED_EXT 2
#define LMP_FEATURES_REQ_EXT 3
#define LMP_FEATURES_RES_EXT 4
#define LMP_PACKET_TYPE_TABLE_REQ 11
#define LMP_ESCO_LINK_REQ 12
#define LMP_REMOVE_ESCO_LINK_REQ 13
#define LMP_CHANNEL_CLASSIFICATION_REQ 16
#define LMP_CHANNEL_CLASSIFICATION 17
#define LMP_SNIFF_SUBRATING_REQ 21
#define LMP_SNIFF_SUBRATING_RES 22
#define LMP_PAUSE_ENCRYPTION_REQ 23
#define LMP_RESUME_ENCRYPTION_REQ 24
#define LMP_IO_CAPABILITY_REQ 25
#define LMP_IO_CAPABILITY_RES 26
#define LMP_NUMERIC_COMPARISON_FAILED 27
#define LMP_PASSKEY_FAILED 28
#define LMP_OOB_FAILED 29
#define LMP_KEYPRESS_NOTIFICATION 30
#define LMP_POWER_CONTROL_REQ 31
#define LMP_POWER_CONTROL_RES 32
#define LMP_PING_REQ 33
#define LMP_PING_RES 34

/* initialize the protocol and registered fields */
static int proto_btbrlmp = -1;
static int hf_lmp_accscheme = -1;
static int hf_lmp_afhchmap = -1;
static int hf_lmp_afhclass = -1;
static int hf_lmp_afhinst = -1;
static int hf_lmp_afhmaxintvl = -1;
static int hf_lmp_afhminintvl = -1;
static int hf_lmp_afhmode = -1;
static int hf_lmp_afhrptmode = -1;
static int hf_lmp_airmode = -1;
static int hf_lmp_araddr = -1;
static int hf_lmp_authreqs = -1;
static int hf_lmp_authres = -1;
static int hf_lmp_bdaddr = -1;
static int hf_lmp_bdaddr1 = -1;
static int hf_lmp_bdaddr2 = -1;
static int hf_lmp_bsw = -1;
static int hf_lmp_clkoffset = -1;
static int hf_lmp_commit = -1;
static int hf_lmp_confirm = -1;
static int hf_lmp_compid = -1;
static int hf_lmp_cryptmode = -1;
static int hf_lmp_daccess = -1;
static int hf_lmp_db = -1;
static int hf_lmp_dbsleep = -1;
static int hf_lmp_deltab = -1;
static int hf_lmp_desco = -1;
static int hf_lmp_drift = -1;
static int hf_lmp_dsco = -1;
static int hf_lmp_dsniff = -1;
static int hf_lmp_encdata = -1;
static int hf_lmp_enclen = -1;
static int hf_lmp_encmaj = -1;
static int hf_lmp_encmin = -1;
static int hf_lmp_eop = -1;
static int hf_lmp_eopinre = -1;
static int hf_lmp_escolenms = -1;
static int hf_lmp_escolensm = -1;
static int hf_lmp_escotypems = -1;
static int hf_lmp_escotypesm = -1;
static int hf_lmp_err = -1;
static int hf_lmp_escohdl = -1;
static int hf_lmp_escoltaddr = -1;
static int hf_lmp_features = -1;
static int hf_lmp_feat_3slot = -1;
static int hf_lmp_feat_5slot = -1;
static int hf_lmp_feat_enc = -1;
static int hf_lmp_feat_slotoff = -1;
static int hf_lmp_feat_timacc = -1;
static int hf_lmp_feat_rolesw = -1;
static int hf_lmp_feat_holdmo = -1;
static int hf_lmp_feat_sniffmo = -1;
static int hf_lmp_feat_res0 = -1;
static int hf_lmp_feat_pwrctlreq = -1;
static int hf_lmp_feat_cqddr = -1;
static int hf_lmp_feat_sco = -1;
static int hf_lmp_feat_hv2 = -1;
static int hf_lmp_feat_hv3 = -1;
static int hf_lmp_feat_mulaw = -1;
static int hf_lmp_feat_alaw = -1;
static int hf_lmp_feat_cvsd = -1;
static int hf_lmp_feat_pagneg = -1;
static int hf_lmp_feat_pwrctl = -1;
static int hf_lmp_feat_transsync = -1;
static int hf_lmp_feat_flowctl1 = -1;
static int hf_lmp_feat_flowctl2 = -1;
static int hf_lmp_feat_flowctl3 = -1;
static int hf_lmp_feat_bcenc = -1;
static int hf_lmp_feat_res1 = -1;
static int hf_lmp_feat_acl2 = -1;
static int hf_lmp_feat_acl3 = -1;
static int hf_lmp_feat_eninq = -1;
static int hf_lmp_feat_intinq = -1;
static int hf_lmp_feat_intpag = -1;
static int hf_lmp_feat_rssiinq = -1;
static int hf_lmp_feat_ev3 = -1;
static int hf_lmp_feat_ev4 = -1;
static int hf_lmp_feat_ev5 = -1;
static int hf_lmp_feat_res2 = -1;
static int hf_lmp_feat_afhcapsl = -1;
static int hf_lmp_feat_afhclasl = -1;
static int hf_lmp_feat_bredrnotsup = -1;
static int hf_lmp_feat_lesup = -1;
static int hf_lmp_feat_3slotenh = -1;
static int hf_lmp_feat_5slotenh = -1;
static int hf_lmp_feat_sniffsubr = -1;
static int hf_lmp_feat_pauseenc = -1;
static int hf_lmp_feat_afhcapma = -1;
static int hf_lmp_feat_afhclama = -1;
static int hf_lmp_feat_esco2 = -1;
static int hf_lmp_feat_esco3 = -1;
static int hf_lmp_feat_3slotenhesco = -1;
static int hf_lmp_feat_extinqres = -1;
static int hf_lmp_feat_simlebredr = -1;
static int hf_lmp_feat_res3 = -1;
static int hf_lmp_feat_ssp = -1;
static int hf_lmp_feat_enpdu = -1;
static int hf_lmp_feat_edr = -1;
static int hf_lmp_feat_nonflush = -1;
static int hf_lmp_feat_res4 = -1;
static int hf_lmp_feat_lstimche = -1;
static int hf_lmp_feat_inqtxpwr = -1;
static int hf_lmp_feat_enhpwr = -1;
static int hf_lmp_feat_res5 = -1;
static int hf_lmp_feat_res6 = -1;
static int hf_lmp_feat_res7 = -1;
static int hf_lmp_feat_res8 = -1;
static int hf_lmp_feat_extfeat = -1;
static int hf_lmp_featuresext = -1;
static int hf_lmp_efeat_ssp = -1;
static int hf_lmp_efeat_lesup = -1;
static int hf_lmp_efeat_lebredr = -1;
static int hf_lmp_efeat_sch = -1;
static int hf_lmp_efeat_csbma = -1;
static int hf_lmp_efeat_csbsl = -1;
static int hf_lmp_efeat_syntr = -1;
static int hf_lmp_efeat_synsc = -1;
static int hf_lmp_efeat_inqresnote = -1;
static int hf_lmp_efeat_genintsc = -1;
static int hf_lmp_efeat_ccadj = -1;
static int hf_lmp_efeat_res0 = -1;
static int hf_lmp_efeat_scc = -1;
static int hf_lmp_efeat_ping = -1;
static int hf_lmp_efeat_res1 = -1;
static int hf_lmp_efeat_trnud = -1;
static int hf_lmp_efeat_sam = -1;
static int hf_lmp_fpage = -1;
static int hf_lmp_htime = -1;
static int hf_lmp_hinst = -1;
static int hf_lmp_hopmode = -1;
static int hf_lmp_iocaps = -1;
static int hf_lmp_jitter = -1;
static int hf_lmp_key = -1;
static int hf_lmp_keysz = -1;
static int hf_lmp_ksmask = -1;
static int hf_lmp_ltaddr1 = -1;
static int hf_lmp_ltaddr2 = -1;
static int hf_lmp_ltaddr3 = -1;
static int hf_lmp_ltaddr4 = -1;
static int hf_lmp_ltaddr5 = -1;
static int hf_lmp_ltaddr6 = -1;
static int hf_lmp_ltaddr7 = -1;
static int hf_lmp_maccess = -1;
static int hf_lmp_maxslots = -1;
static int hf_lmp_maxsp = -1;
static int hf_lmp_maxss = -1;
static int hf_lmp_minsmt = -1;
static int hf_lmp_naccslots = -1;
static int hf_lmp_namefrag = -1;
static int hf_lmp_namelen = -1;
static int hf_lmp_nameoffset = -1;
static int hf_lmp_nb = -1;
static int hf_lmp_nbc = -1;
static int hf_lmp_nbsleep = -1;
static int hf_lmp_negstate = -1;
static int hf_lmp_nonce = -1;
static int hf_lmp_nottype = -1;
static int hf_lmp_npoll = -1;
static int hf_lmp_oobauthdata = -1;
static int hf_lmp_op = -1;
static int hf_lmp_opinre = -1;
static int hf_lmp_pagesch = -1;
static int hf_lmp_pcmode = -1;
static int hf_lmp_pkttype = -1;
static int hf_lmp_pkttypetbl = -1;
static int hf_lmp_pmaddr = -1;
static int hf_lmp_pmaddr1 = -1;
static int hf_lmp_pmaddr2 = -1;
static int hf_lmp_pmaddr3 = -1;
static int hf_lmp_pmaddr4 = -1;
static int hf_lmp_pmaddr5 = -1;
static int hf_lmp_pmaddr6 = -1;
static int hf_lmp_pmaddr7 = -1;
static int hf_lmp_pollintvl = -1;
static int hf_lmp_pollper = -1;
static int hf_lmp_pssettings = -1;
static int hf_lmp_pwradjreq = -1;
static int hf_lmp_pwradjres = -1;
static int hf_lmp_pwradj_8dpsk = -1;
static int hf_lmp_pwradj_dqpsk = -1;
static int hf_lmp_pwradj_gfsk = -1;
static int hf_lmp_rand = -1;
static int hf_lmp_rate = -1;
static int hf_lmp_rate_fec = -1;
static int hf_lmp_rate_size = -1;
static int hf_lmp_rate_type = -1;
static int hf_lmp_rate_edrsize = -1;
static int hf_lmp_rxfreq = -1;
static int hf_lmp_scohdl = -1;
static int hf_lmp_scopkt = -1;
static int hf_lmp_slotoffset = -1;
static int hf_lmp_sniffatt = -1;
static int hf_lmp_sniffsi = -1;
static int hf_lmp_sniffto = -1;
static int hf_lmp_subversnr = -1;
static int hf_lmp_suptimeout = -1;
static int hf_lmp_swinst = -1;
static int hf_lmp_taccess = -1;
static int hf_lmp_tb = -1;
static int hf_lmp_tesco = -1;
static int hf_lmp_testlen = -1;
static int hf_lmp_testscen = -1;
static int hf_lmp_tid = -1;
static int hf_lmp_timectrl = -1;
static int hf_lmp_time_change = -1;
static int hf_lmp_time_init = -1;
static int hf_lmp_time_accwin = -1;
static int hf_lmp_tsco = -1;
static int hf_lmp_tsniff = -1;
static int hf_lmp_txfreq = -1;
static int hf_lmp_versnr = -1;
static int hf_lmp_wesco = -1;

/* supported features page 0 (standard p. 528) */
static const int *features_fields[] = {
	&hf_lmp_feat_3slot,
	&hf_lmp_feat_5slot,
	&hf_lmp_feat_enc,
	&hf_lmp_feat_slotoff,
	&hf_lmp_feat_timacc,
	&hf_lmp_feat_rolesw,
	&hf_lmp_feat_holdmo,
	&hf_lmp_feat_sniffmo,
	&hf_lmp_feat_res0,
	&hf_lmp_feat_pwrctlreq,
	&hf_lmp_feat_cqddr,
	&hf_lmp_feat_sco,
	&hf_lmp_feat_hv2,
	&hf_lmp_feat_hv3,
	&hf_lmp_feat_mulaw,
	&hf_lmp_feat_alaw,
	&hf_lmp_feat_cvsd,
	&hf_lmp_feat_pagneg,
	&hf_lmp_feat_pwrctl,
	&hf_lmp_feat_transsync,
	&hf_lmp_feat_flowctl1,
	&hf_lmp_feat_flowctl2,
	&hf_lmp_feat_flowctl3,
	&hf_lmp_feat_bcenc,
	&hf_lmp_feat_res1,
	&hf_lmp_feat_acl2,
	&hf_lmp_feat_acl3,
	&hf_lmp_feat_eninq,
	&hf_lmp_feat_intinq,
	&hf_lmp_feat_intpag,
	&hf_lmp_feat_rssiinq,
	&hf_lmp_feat_ev3,
	&hf_lmp_feat_ev4,
	&hf_lmp_feat_ev5,
	&hf_lmp_feat_res2,
	&hf_lmp_feat_afhcapsl,
	&hf_lmp_feat_afhclasl,
	&hf_lmp_feat_bredrnotsup,
	&hf_lmp_feat_lesup,
	&hf_lmp_feat_3slotenh,
	&hf_lmp_feat_5slotenh,
	&hf_lmp_feat_sniffsubr,
	&hf_lmp_feat_pauseenc,
	&hf_lmp_feat_afhcapma,
	&hf_lmp_feat_afhclama,
	&hf_lmp_feat_esco2,
	&hf_lmp_feat_esco3,
	&hf_lmp_feat_3slotenhesco,
	&hf_lmp_feat_extinqres,
	&hf_lmp_feat_simlebredr,
	&hf_lmp_feat_res3,
	&hf_lmp_feat_ssp,
	&hf_lmp_feat_enpdu,
	&hf_lmp_feat_edr,
	&hf_lmp_feat_nonflush,
	&hf_lmp_feat_res4,
	&hf_lmp_feat_lstimche,
	&hf_lmp_feat_inqtxpwr,
	&hf_lmp_feat_enhpwr,
	&hf_lmp_feat_res5,
	&hf_lmp_feat_res6,
	&hf_lmp_feat_res7,
	&hf_lmp_feat_res8,
	&hf_lmp_feat_extfeat,
	NULL};

/* supported features page 1+2 (standard p. 530) */
static const int *extfeatures1_fields[] = {

	&hf_lmp_efeat_ssp,
	&hf_lmp_efeat_lesup,
	&hf_lmp_efeat_lebredr,
	&hf_lmp_efeat_sch,
	NULL};

static const int *extfeatures2_fields[] = {
	&hf_lmp_efeat_csbma,
	&hf_lmp_efeat_csbsl,
	&hf_lmp_efeat_syntr,
	&hf_lmp_efeat_synsc,
	&hf_lmp_efeat_inqresnote,
	&hf_lmp_efeat_genintsc,
	&hf_lmp_efeat_ccadj,
	&hf_lmp_efeat_res0,
	&hf_lmp_efeat_scc,
	&hf_lmp_efeat_ping,
	&hf_lmp_efeat_res1,
	&hf_lmp_efeat_trnud,
	&hf_lmp_efeat_sam,
	NULL};

/* timing control flags */
static const int *timectrl_fields[] = {
	&hf_lmp_time_change,
	&hf_lmp_time_init,
	&hf_lmp_time_accwin,
	/* bits 3-7 reserved */
	NULL};

static const true_false_string time_change = {
	"timing change",
	"no timing change"};

static const true_false_string time_init = {
	"use initialization 2",
	"use initialization 1"};

static const true_false_string time_accwin = {
	"no access window",
	"access window"};

static const true_false_string fec = {
	"do not use FEC",
	"use FEC"};

static const true_false_string tid = {
	"transaction initiated by slave",
	"transaction initiated by master"};

/* short LMP opcodes */
static const value_string opcode[] = {
	{LMP_VSC, "LMP_Broadcom_BPCS"},
	{LMP_NAME_REQ, "LMP_name_req"},
	{LMP_NAME_RES, "LMP_name_res"},
	{LMP_ACCEPTED, "LMP_accepted"},
	{LMP_NOT_ACCEPTED, "LMP_not_accepted"},
	{LMP_CLKOFFSET_REQ, "LMP_clkoffset_req"},
	{LMP_CLKOFFSET_RES, "LMP_clkoffset_res"},
	{LMP_DETACH, "LMP_detach"},
	{LMP_IN_RAND, "LMP_in_rand"},
	{LMP_COMB_KEY, "LMP_comb_key"},
	{LMP_UNIT_KEY, "LMP_unit_key"},
	{LMP_AU_RAND, "LMP_au_rand"},
	{LMP_SRES, "LMP_sres"},
	{LMP_TEMP_RAND, "LMP_temp_rand"},
	{LMP_TEMP_KEY, "LMP_temp_key"},
	{LMP_ENCRYPTION_MODE_REQ, "LMP_encryption_mode_req"},
	{LMP_ENCRYPTION_KEY_SIZE_REQ, "LMP_encryption_key_size_req"},
	{LMP_START_ENCRYPTION_REQ, "LMP_start_encryption_req"},
	{LMP_STOP_ENCRYPTION_REQ, "LMP_stop_encryption_req"},
	{LMP_SWITCH_REQ, "LMP_switch_req"},
	{LMP_HOLD, "LMP_hold"},
	{LMP_HOLD_REQ, "LMP_hold_req"},
	{LMP_SNIFF_REQ, "LMP_sniff_req"},
	{LMP_UNSNIFF_REQ, "LMP_unsniff_req"},
	{LMP_PARK_REQ, "LMP_park_req"},
	{LMP_SET_BROADCAST_SCAN_WINDOW, "LMP_set_broadcast_scan_window"},
	{LMP_MODIFY_BEACON, "LMP_modify_beacon"},
	{LMP_UNPARK_BD_ADDR_REQ, "LMP_unpark_BD_ADDR_req"},
	{LMP_UNPARK_PM_ADDR_REQ, "LMP_unpark_PM_ADDR_req"},
	{LMP_INCR_POWER_REQ, "LMP_incr_power_req"},
	{LMP_DECR_POWER_REQ, "LMP_decr_power_req"},
	{LMP_MAX_POWER, "LMP_max_power"},
	{LMP_MIN_POWER, "LMP_min_power"},
	{LMP_AUTO_RATE, "LMP_auto_rate"},
	{LMP_PREFERRED_RATE, "LMP_preferred_rate"},
	{LMP_VERSION_REQ, "LMP_version_req"},
	{LMP_VERSION_RES, "LMP_version_res"},
	{LMP_FEATURES_REQ, "LMP_features_req"},
	{LMP_FEATURES_RES, "LMP_features_res"},
	{LMP_QUALITY_OF_SERVICE, "LMP_quality_of_service"},
	{LMP_QUALITY_OF_SERVICE_REQ, "LMP_quality_of_service_req"},
	{LMP_SCO_LINK_REQ, "LMP_SCO_link_req"},
	{LMP_REMOVE_SCO_LINK_REQ, "LMP_remove_SCO_link_req"},
	{LMP_MAX_SLOT, "LMP_max_slot"},
	{LMP_MAX_SLOT_REQ, "LMP_max_slot_req"},
	{LMP_TIMING_ACCURACY_REQ, "LMP_timing_accuracy_req"},
	{LMP_TIMING_ACCURACY_RES, "LMP_timing_accuracy_res"},
	{LMP_SETUP_COMPLETE, "LMP_setup_complete"},
	{LMP_USE_SEMI_PERMANENT_KEY, "LMP_use_semi_permanent_key"},
	{LMP_HOST_CONNECTION_REQ, "LMP_host_connection_req"},
	{LMP_SLOT_OFFSET, "LMP_slot_offset"},
	{LMP_PAGE_MODE_REQ, "LMP_page_mode_req"},
	{LMP_PAGE_SCAN_MODE_REQ, "LMP_page_scan_mode_req"},
	{LMP_SUPERVISION_TIMEOUT, "LMP_supervision_timeout"},
	{LMP_TEST_ACTIVATE, "LMP_test_activate"},
	{LMP_TEST_CONTROL, "LMP_test_control"},
	{LMP_ENCRYPTION_KEY_SIZE_MASK_REQ, "LMP_encryption_key_size_mask_req"},
	{LMP_ENCRYPTION_KEY_SIZE_MASK_RES, "LMP_encryption_key_size_mask_res"},
	{LMP_SET_AFH, "LMP_set_AFH"},
	{LMP_ENCAPSULATED_HEADER, "LMP_encapsulated_header"},
	{LMP_ENCAPSULATED_PAYLOAD, "LMP_encapsulated_payload"},
	{LMP_SIMPLE_PAIRING_CONFIRM, "LMP_Simple_Pairing_Confirm"},
	{LMP_SIMPLE_PAIRING_NUMBER, "LMP_Simple_Pairing_Number"},
	{LMP_DHKEY_CHECK, "LMP_DHkey_Check"},
	{LMP_ESCAPE_1, "Escape 1"},
	{LMP_ESCAPE_2, "Escape 2"},
	{LMP_ESCAPE_3, "Escape 3"},
	{LMP_ESCAPE_4, "Escape 4"},
	{0, NULL}};

/* extended LMP opcodes */
static const value_string ext_opcode[] = {
	{LMP_ACCEPTED_EXT, "LMP_accepted_ext"},
	{LMP_NOT_ACCEPTED_EXT, "LMP_not_accepted_ext"},
	{LMP_FEATURES_REQ_EXT, "LMP_features_req_ext"},
	{LMP_FEATURES_RES_EXT, "LMP_features_res_ext"},
	{LMP_PACKET_TYPE_TABLE_REQ, "LMP_packet_type_table_req"},
	{LMP_ESCO_LINK_REQ, "LMP_eSCO_link_req"},
	{LMP_REMOVE_ESCO_LINK_REQ, "LMP_remove_eSCO_link_req"},
	{LMP_CHANNEL_CLASSIFICATION_REQ, "LMP_channel_classification_req"},
	{LMP_CHANNEL_CLASSIFICATION, "LMP_channel_classification"},
	{LMP_SNIFF_SUBRATING_REQ, "LMP_sniff_subrating_req"},
	{LMP_SNIFF_SUBRATING_RES, "LMP_sniff_subrating_res"},
	{LMP_PAUSE_ENCRYPTION_REQ, "LMP_pause_encryption_req"},
	{LMP_RESUME_ENCRYPTION_REQ, "LMP_resume_encryption_req"},
	{LMP_IO_CAPABILITY_REQ, "LMP_IO_Capability_req"},
	{LMP_IO_CAPABILITY_RES, "LMP_IO_Capability_res"},
	{LMP_NUMERIC_COMPARISON_FAILED, "LMP_numeric_comparison_failed"},
	{LMP_PASSKEY_FAILED, "LMP_passkey_failed"},
	{LMP_OOB_FAILED, "LMP_oob_failed"},
	{LMP_KEYPRESS_NOTIFICATION, "LMP_keypress_notification"},
	{LMP_POWER_CONTROL_REQ, "LMP_power_control_req"},
	{LMP_POWER_CONTROL_RES, "LMP_power_control_res"},
	{LMP_PING_REQ, "LMP_ping_req"},
	{LMP_PING_RES, "LMP_ping_res"},
	{0, NULL}};

/* LMP error codes */
static const value_string error_code[] = {
	{0x00, "Success"},
	{0x01, "Unknown HCI Command"},
	{0x02, "Unknown Connection Identifier"},
	{0x03, "Hardware Failure"},
	{0x04, "Page Timeout"},
	{0x05, "Authentication Failure"},
	{0x06, "PIN or Key Missing"},
	{0x07, "Memory Capacity Exceeded"},
	{0x08, "Connection Timeout"},
	{0x09, "Connection Limit Exceeded"},
	{0x0A, "Synchronous Connection Limit To A Device Exceeded"},
	{0x0B, "ACL Connection Already Exists"},
	{0x0C, "Command Disallowed"},
	{0x0D, "Connection Rejected due to Limited Resources"},
	{0x0E, "Connection Rejected Due To Security Reasons"},
	{0x0F, "Connection Rejected due to Unacceptable BD_ADDR"},
	{0x10, "Connection Accept Timeout Exceeded"},
	{0x11, "Unsupported Feature or Parameter Value"},
	{0x12, "Invalid HCI Command Parameters"},
	{0x13, "Remote User Terminated Connection"},
	{0x14, "Remote Device Terminated Connection due to Low Resources"},
	{0x15, "Remote Device Terminated Connection due to Power Off"},
	{0x16, "Connection Terminated By Local Host"},
	{0x17, "Repeated Attempts"},
	{0x18, "Pairing Not Allowed"},
	{0x19, "Unknown LMP PDU"},
	{0x1A, "Unsupported Remote Feature / Unsupported LMP Feature"},
	{0x1B, "SCO Offset Rejected"},
	{0x1C, "SCO Interval Rejected"},
	{0x1D, "SCO Air Mode Rejected"},
	{0x1E, "Invalid LMP Parameters"},
	{0x1F, "Unspecified Error"},
	{0x20, "Unsupported LMP Parameter Value"},
	{0x21, "Role Change Not Allowed"},
	{0x22, "LMP Response Timeout"},
	{0x23, "LMP Error Transaction Collision"},
	{0x24, "LMP PDU Not Allowed"},
	{0x25, "Encryption Mode Not Acceptable"},
	{0x26, "Link Key Can Not be Changed"},
	{0x27, "Requested QoS Not Supported"},
	{0x28, "Instant Passed"},
	{0x29, "Pairing With Unit Key Not Supported"},
	{0x2A, "Different Transaction Collision"},
	{0x2B, "Reserved"},
	{0x2C, "QoS Unacceptable Parameter"},
	{0x2D, "QoS Rejected"},
	{0x2E, "Channel Classification Not Supported"},
	{0x2F, "Insufficient Security"},
	{0x30, "Parameter Out Of Mandatory Range"},
	{0x31, "Reserved"},
	{0x32, "Role Switch Pending"},
	{0x33, "Reserved"},
	{0x34, "Reserved Slot Violation"},
	{0x35, "Role Switch Failed"},
	{0x36, "Extended Inquiry Response Too Large"},
	{0x37, "Secure Simple Pairing Not Supported By Host."},
	{0x38, "Host Busy - Pairing"},
	{0x39, "Connection Rejected due to No Suitable Channel Found"},
	{0, NULL}};

static const value_string encryption_mode[] = {
	{0, "no encryption"},
	{1, "encryption"},
	{2, "encryption"},
	/* 3 - 255 reserved */
	{0, NULL}};

static const value_string access_scheme[] = {
	{0, "polling technique"},
	/* 1 - 15 reserved */
	{0, NULL}};

static const value_string packet_size[] = {
	{0, "no packet-size preference available"},
	{1, "use 1-slot packets"},
	{2, "use 3-slot packets"},
	{3, "use 5-slot packets"},
	{0, NULL}};

static const value_string edr_type[] = {
	{0, "use DM1 packets"},
	{1, "use 2 Mbps packets"},
	{2, "use 3 Mbps packets"},
	/* 3 reserved */
	{0, NULL}};

static const value_string versnr[] = {
	{0, "Bluetooth Core Specification 1.0b"},
	{1, "Bluetooth Core Specification 1.1"},
	{2, "Bluetooth Core Specification 1.2"},
	{3, "Bluetooth Core Specification 2.0 + EDR"},
	{4, "Bluetooth Core Specification 2.1 + EDR"},
	{5, "Bluetooth Core Specification 3.0 + HS"},
	{6, "Bluetooth Core Specification 4.0"},
	{7, "Bluetooth Core Specification 4.1"},
	{8, "Bluetooth Core Specification 4.2"},
	{9, "Bluetooth Core Specification 5.0"},
	{10, "Bluetooth Core Specification 5.1"},
	{11, "Bluetooth Core Specification 5.2"},
	/* 12 - 255 reserved */
	{0, NULL}};

static const value_string compid[] = {
	{0, "Ericsson Technology Licensing"},
	{1, "Nokia Mobile Phones"},
	{2, "Intel Corp."},
	{3, "IBM Corp."},
	{4, "Toshiba Corp."},
	{5, "3Com"},
	{6, "Microsoft"},
	{7, "Lucent"},
	{8, "Motorola"},
	{9, "Infineon Technologies AG"},
	{10, "Cambridge Silicon Radio"},
	{11, "Silicon Wave"},
	{12, "Digianswer A/S"},
	{13, "Texas Instruments Inc."},
	{14, "Parthus Technologies Inc."},
	{15, "Broadcom Corporation"},
	{16, "Mitel Semiconductor"},
	{17, "Widcomm, Inc."},
	{18, "Zeevo, Inc."},
	{19, "Atmel Corporation"},
	{20, "Mitsubishi Electric Corporation"},
	{21, "RTX Telecom A/S"},
	{22, "KC Technology Inc."},
	{23, "Newlogic"},
	{24, "Transilica, Inc."},
	{25, "Rohde & Schwarz GmbH & Co. KG"},
	{26, "TTPCom Limited"},
	{27, "Signia Technologies, Inc."},
	{28, "Conexant Systems Inc."},
	{29, "Qualcomm"},
	{30, "Inventel"},
	{31, "AVM Berlin"},
	{32, "BandSpeed, Inc."},
	{33, "Mansella Ltd"},
	{34, "NEC Corporation"},
	{35, "WavePlus Technology Co., Ltd."},
	{36, "Alcatel"},
	{37, "Philips Semiconductors"},
	{38, "C Technologies"},
	{39, "Open Interface"},
	{40, "R F Micro Devices"},
	{41, "Hitachi Ltd"},
	{42, "Symbol Technologies, Inc."},
	{43, "Tenovis"},
	{44, "Macronix International Co. Ltd."},
	{45, "GCT Semiconductor"},
	{46, "Norwood Systems"},
	{47, "MewTel Technology Inc."},
	{48, "ST Microelectronics"},
	{49, "Synopsys"},
	{50, "Red-M (Communications) Ltd"},
	{51, "Commil Ltd"},
	{52, "Computer Access Technology Corporation (CATC)"},
	{53, "Eclipse (HQ Espana) S.L."},
	{54, "Renesas Technology Corp."},
	{55, "Mobilian Corporation"},
	{56, "Terax"},
	{57, "Integrated System Solution Corp."},
	{58, "Matsushita Electric Industrial Co., Ltd."},
	{59, "Gennum Corporation"},
	{60, "Research In Motion"},
	{61, "IPextreme, Inc."},
	{62, "Systems and Chips, Inc"},
	{63, "Bluetooth SIG, Inc"},
	{64, "Seiko Epson Corporation"},
	{65, "Integrated Silicon Solution Taiwan, Inc."},
	{66, "CONWISE Technology Corporation Ltd"},
	{67, "PARROT SA"},
	{68, "Socket Mobile"},
	{69, "Atheros Communications, Inc."},
	{70, "MediaTek, Inc."},
	{71, "Bluegiga (tentative)"},
	{72, "Marvell Technology Group Ltd."},
	{73, "3DSP Corporation"},
	{74, "Accel Semiconductor Ltd."},
	{75, "Continental Automotive Systems"},
	{76, "Apple, Inc."},
	{77, "Staccato Communications, Inc."},
	{78, "Avago Technologies"},
	{79, "APT Ltd."},
	{80, "SiRF Technology, Inc."},
	{81, "Tzero Technologies, Inc."},
	{82, "J&M Corporation"},
	{83, "Free2move AB"},
	{84, "3DiJoyCorporation"},
	{85, "Plantronics,Inc."},
	{86, "SonyEricssonMobileCommunications"},
	{87, "HarmanInternationalIndustries,Inc."},
	{88, "Vizio,Inc."},
	{89, "NordicSemiconductorASA"},
	{90, "EMMicroelectronic-MarinSA"},
	{91, "RalinkTechnologyCorporation"},
	{92, "BelkinInternational,Inc."},
	{93, "RealtekSemiconductorCorporation"},
	{94, "StonestreetOne,LLC"},
	{95, "Wicentric,Inc."},
	{96, "RivieraWavesS.A.S"},
	{97, "RDAMicroelectronics"},
	{98, "GibsonGuitars"},
	{99, "MiCommandInc."},
	{100, "BandXIInternational,LLC"},
	{101, "Hewlett-PackardCompany"},
	{102, "9SolutionsOy"},
	{103, "GNNetcomA/S"},
	{104, "GeneralMotors"},
	{105, "A&DEngineering,Inc."},
	{106, "MindTreeLtd."},
	{107, "PolarElectroOY"},
	{108, "BeautifulEnterpriseCo.,Ltd."},
	{109, "BriarTek,Inc"},
	{110, "SummitDataCommunications,Inc."},
	{111, "SoundID"},
	{112, "Monster,LLC"},
	{113, "connectBlueAB"},
	{114, "ShangHaiSuperSmartElectronicsCo.Ltd."},
	{115, "GroupSenseLtd."},
	{116, "Zomm,LLC"},
	{117, "SamsungElectronicsCo.Ltd."},
	{118, "CreativeTechnologyLtd."},
	{119, "LairdTechnologies"},
	{120, "Nike,Inc."},
	{121, "lesswireAG"},
	{122, "MStarSemiconductor,Inc."},
	{123, "HanlynnTechnologies"},
	{124, "A&RCambridge"},
	{125, "SeersTechnologyCo.,Ltd."},
	{126, "SportsTrackingTechnologiesLtd."},
	{127, "AutonetMobile"},
	{128, "DeLormePublishingCompany,Inc."},
	{129, "WuXiVimicro"},
	{130, "SennheiserCommunicationsA/S"},
	{131, "TimeKeepingSystems,Inc."},
	{132, "LudusHelsinkiLtd."},
	{133, "BlueRadios,Inc."},
	{134, "EquinuxAG"},
	{135, "GarminInternational,Inc."},
	{136, "Ecotest"},
	{137, "GNReSoundA/S"},
	{138, "Jawbone"},
	{139, "TopconPositioningSystems,LLC"},
	{140, "GimbalInc.(formerlyQualcommLabs,Inc.andQualcommRetailSolutions,Inc.)"},
	{141, "ZscanSoftware"},
	{142, "QuinticCorp"},
	{143, "TelitWirelessSolutionsGmbH(formerlyStollmannE+VGmbH)"},
	{144, "FunaiElectricCo.,Ltd."},
	{145, "AdvancedPANMOBILsystemsGmbH&Co.KG"},
	{146, "ThinkOptics,Inc."},
	{147, "UniversalElectronics,Inc."},
	{148, "AirohaTechnologyCorp."},
	{149, "NECLighting,Ltd."},
	{150, "ODMTechnology,Inc."},
	{151, "ConnecteDeviceLtd."},
	{152, "zero1.tvGmbH"},
	{153, "i.TechDynamicGlobalDistributionLtd."},
	{154, "Alpwise"},
	{155, "JiangsuToppowerAutomotiveElectronicsCo.,Ltd."},
	{156, "Colorfy,Inc."},
	{157, "GeoforceInc."},
	{158, "BoseCorporation"},
	{159, "SuuntoOy"},
	{160, "KensingtonComputerProductsGroup"},
	{161, "SR-Medizinelektronik"},
	{162, "VertuCorporationLimited"},
	{163, "MetaWatchLtd."},
	{164, "LINAKA/S"},
	{165, "OTLDynamicsLLC"},
	{166, "PandaOceanInc."},
	{167, "VisteonCorporation"},
	{168, "ARPDevicesLimited"},
	{169, "MagnetiMarelliS.p.A"},
	{170, "CAENRFIDsrl"},
	{171, "Ingenieur-SystemgruppeZahnGmbH"},
	{172, "GreenThrottleGames"},
	{173, "PeterSystemtechnikGmbH"},
	{174, "OmegawaveOy"},
	{175, "Cinetix"},
	{176, "PassifSemiconductorCorp"},
	{177, "SarisCyclingGroup,Inc"},
	{178, "BekeyA/S"},
	{179, "ClarinoxTechnologiesPty.Ltd."},
	{180, "BDETechnologyCo.,Ltd."},
	{181, "SwirlNetworks"},
	{182, "Mesointernational"},
	{183, "TreLabLtd"},
	{184, "QualcommInnovationCenter,Inc.(QuIC)"},
	{185, "JohnsonControls,Inc."},
	{186, "StarkeyLaboratoriesInc."},
	{187, "S-PowerElectronicsLimited"},
	{188, "AceSensorInc"},
	{189, "AplixCorporation"},
	{190, "AAMPofAmerica"},
	{191, "StalmartTechnologyLimited"},
	{192, "AMICCOMElectronicsCorporation"},
	{193, "ShenzhenExcelsecuDataTechnologyCo.,Ltd"},
	{194, "GeneqInc."},
	{195, "adidasAG"},
	{196, "LGElectronics"},
	{197, "OnsetComputerCorporation"},
	{198, "SelflyBV"},
	{199, "QuuppaOy."},
	{200, "GeLoInc"},
	{201, "Evluma"},
	{202, "MC10"},
	{203, "BinauricSE"},
	{204, "BeatsElectronics"},
	{205, "MicrochipTechnologyInc."},
	{206, "ElgatoSystemsGmbH"},
	{207, "ARCHOSSA"},
	{208, "Dexcom,Inc."},
	{209, "PolarElectroEuropeB.V."},
	{210, "DialogSemiconductorB.V."},
	{211, "TaixingbangTechnology(HK)Co,.LTD."},
	{212, "Kawantech"},
	{213, "AustcoCommunicationSystems"},
	{214, "TimexGroupUSA,Inc."},
	{215, "QualcommTechnologies,Inc."},
	{216, "QualcommConnectedExperiences,Inc."},
	{217, "VoyetraTurtleBeach"},
	{218, "txtrGmbH"},
	{219, "Biosentronics"},
	{220, "Procter&Gamble"},
	{221, "HosidenCorporation"},
	{222, "MuzikLLC"},
	{223, "MisfitWearablesCorp"},
	{224, "Google"},
	{225, "DanlersLtd"},
	{226, "SemilinkInc"},
	{227, "inMusicBrands,Inc"},
	{228, "L.S.ResearchInc."},
	{229, "EdenSoftwareConsultantsLtd."},
	{230, "Freshtemp"},
	{231, "KSTechnologies"},
	{232, "ACTSTechnologies"},
	{233, "VtrackSystems"},
	{234, "Nielsen-KellermanCompany"},
	{235, "ServerTechnologyInc."},
	{236, "BioResearchAssociates"},
	{237, "JollyLogic,LLC"},
	{238, "AboveAverageOutcomes,Inc."},
	{239, "BitsplittersGmbH"},
	{240, "PayPal,Inc."},
	{241, "WitronTechnologyLimited"},
	{242, "MorseProjectInc."},
	{243, "KentDisplaysInc."},
	{244, "NautilusInc."},
	{245, "SmartifierOy"},
	{246, "ElcometerLimited"},
	{247, "VSNTechnologies,Inc."},
	{248, "AceUniCorp.,Ltd."},
	{249, "StickNFind"},
	{250, "CrystalCodeAB"},
	{251, "KOUKAAMa.s."},
	{252, "DelphiCorporation"},
	{253, "ValenceTechLimited"},
	{254, "StanleyBlackandDecker"},
	{255, "TypoProducts,LLC"},
	{256, "TomTomInternationalBV"},
	{257, "Fugoo,Inc."},
	{258, "KeiserCorporation"},
	{259, "Bang&OlufsenA/S"},
	{260, "PLUSLocationSystemsPtyLtd"},
	{261, "UbiquitousComputingTechnologyCorporation"},
	{262, "InnovativeYachtterSolutions"},
	{263, "WilliamDemantHoldingA/S"},
	{264, "ChiconyElectronicsCo.,Ltd."},
	{265, "AtusBV"},
	{266, "CodegateLtd"},
	{267, "ERi,Inc"},
	{268, "TransducersDirect,LLC"},
	{269, "FujitsuTenLImited"},
	{270, "AudiAG"},
	{271, "HiSiliconTechnologiesCol,Ltd."},
	{272, "NipponSeikiCo.,Ltd."},
	{273, "SteelseriesApS"},
	{274, "VisyblInc."},
	{275, "OpenbrainTechnologies,Co.,Ltd."},
	{276, "Xensr"},
	{277, "e.solutions"},
	{278, "10AKTechnologies"},
	{279, "WimotoTechnologiesInc"},
	{280, "RadiusNetworks,Inc."},
	{281, "WizeTechnologyCo.,Ltd."},
	{282, "QualcommLabs,Inc."},
	{283, "HewlettPackardEnterprise"},
	{284, "Baidu"},
	{285, "ArendiAG"},
	{286, "SkodaAutoa.s."},
	{287, "VolkswagenAG"},
	{288, "PorscheAG"},
	{289, "SinoWealthElectronicLtd."},
	{290, "AirTurn,Inc."},
	{291, "Kinsa,Inc"},
	{292, "HIDGlobal"},
	{293, "SEATes"},
	{294, "PrometheanLtd."},
	{295, "SaluticaAlliedSolutions"},
	{296, "GPSIGroupPtyLtd"},
	{297, "NimbleDevicesOy"},
	{298, "ChangzhouYongseInfotechCo.,Ltd."},
	{299, "SportIQ"},
	{300, "TEMECInstrumentsB.V."},
	{301, "SonyCorporation"},
	{302, "ASSAABLOY"},
	{303, "ClarionCo.Inc."},
	{304, "WarehouseInnovations"},
	{305, "CypressSemiconductor"},
	{306, "MADSInc"},
	{307, "BlueMaestroLimited"},
	{308, "ResolutionProducts,Ltd."},
	{309, "AirewareLLC"},
	{310, "Silvair,Inc."},
	{311, "PrestigioPlazaLtd."},
	{312, "NTEOInc."},
	{313, "FocusSystemsCorporation"},
	{314, "TencentHoldingsLtd."},
	{315, "Allegion"},
	{316, "MurataManufacturingCo.,Ltd."},
	{317, "WirelessWERX"},
	{318, "Nod,Inc."},
	{319, "B&BManufacturingCompany"},
	{320, "AlpineElectronics(China)Co.,Ltd"},
	{321, "FedExServices"},
	{322, "GrapeSystemsInc."},
	{323, "BkonConnect"},
	{324, "LintechGmbH"},
	{325, "NovatelWireless"},
	{326, "Ciright"},
	{327, "MightyCast,Inc."},
	{328, "AmbimatElectronics"},
	{329, "PerytonsLtd."},
	{330, "TivoliAudio,LLC"},
	{331, "MasterLock"},
	{332, "Mesh-NetLtd"},
	{333, "HUIZHOUDESAYSVAUTOMOTIVECO.,LTD."},
	{334, "Tangerine,Inc."},
	{335, "B&WGroupLtd."},
	{336, "PioneerCorporation"},
	{337, "OnBeep"},
	{338, "VernierSoftware&Technology"},
	{339, "ROLErgo"},
	{340, "PebbleTechnology"},
	{341, "NETATMO"},
	{342, "AccumulateAB"},
	{343, "AnhuiHuamiInformationTechnologyCo.,Ltd."},
	{344, "Inmites.r.o."},
	{345, "ChefSteps,Inc."},
	{346, "micasAG"},
	{347, "BiomedicalResearchLtd."},
	{348, "PitiusTecS.L."},
	{349, "Estimote,Inc."},
	{350, "UnikeyTechnologies,Inc."},
	{351, "TimerCapCo."},
	{352, "AwoX"},
	{353, "yikes"},
	{354, "MADSGlobalNZLtd."},
	{355, "PCHInternational"},
	{356, "QingdaoYeelinkInformationTechnologyCo.,Ltd."},
	{357, "MilwaukeeTool(FormallyMilwaukeeElectricTools)"},
	{358, "MISHIKPteLtd"},
	{359, "AscensiaDiabetesCareUSInc."},
	{360, "SpiceboxLLC"},
	{361, "emberlight"},
	{362, "Cooper-AtkinsCorporation"},
	{363, "Qblinks"},
	{364, "MYSPHERA"},
	{365, "LifeScanInc"},
	{366, "VolanticAB"},
	{367, "PodoLabs,Inc"},
	{368, "RocheDiabetesCareAG"},
	{369, "AmazonFulfillmentService"},
	{370, "ConnovateTechnologyPrivateLimited"},
	{371, "Kocomojo,LLC"},
	{372, "EverykeyInc."},
	{373, "DynamicControls"},
	{374, "SentriLock"},
	{375, "I-SYSTinc."},
	{376, "CASIOCOMPUTERCO.,LTD."},
	{377, "LAPISSemiconductorCo.,Ltd."},
	{378, "Telemonitor,Inc."},
	{379, "taskitGmbH"},
	{380, "DaimlerAG"},
	{381, "BatAndCat"},
	{382, "BluDotzLtd"},
	{383, "XTelWirelessApS"},
	{384, "GigasetCommunicationsGmbH"},
	{385, "GeckoHealthInnovations,Inc."},
	{386, "HOPUbiquitous"},
	{387, "WaltDisney"},
	{388, "Nectar"},
	{389, "bel'appsLLC"},
	{390, "CORELightingLtd"},
	{391, "SeraphimSenseLtd"},
	{392, "UnicoRBC"},
	{393, "PhysicalEnterprisesInc."},
	{394, "AbleTrendTechnologyLimited"},
	{395, "KonicaMinolta,Inc."},
	{396, "WiloSE"},
	{397, "ExtronDesignServices"},
	{398, "Fitbit,Inc."},
	{399, "FirefliesSystems"},
	{400, "IntellettoTechnologiesInc."},
	{401, "FDKCORPORATION"},
	{402, "Cloudleaf,Inc"},
	{403, "MavericAutomationLLC"},
	{404, "AcousticStreamCorporation"},
	{405, "Zuli"},
	{406, "PaxtonAccessLtd"},
	{407, "WiSilicaInc."},
	{408, "VENGITKorlatoltFelelosseguTarsasag"},
	{409, "SALTOSYSTEMSS.L."},
	{410, "TRONForum(formerlyT-EngineForum)"},
	{411, "CUBETECHs.r.o."},
	{412, "CokiyaIncorporated"},
	{413, "CVSHealth"},
	{414, "Ceruus"},
	{415, "StrainstallLtd"},
	{416, "ChannelEnterprises(HK)Ltd."},
	{417, "FIAMM"},
	{418, "GIGALANE.CO.,LTD"},
	{419, "EROAD"},
	{420, "MineSafetyAppliances"},
	{421, "IconHealthandFitness"},
	{422, "WilleEngineering(formelyasAsandooGmbH)"},
	{423, "ENERGOUSCORPORATION"},
	{424, "Taobao"},
	{425, "CanonInc."},
	{426, "GeophysicalTechnologyInc."},
	{427, "Facebook,Inc."},
	{428, "TrividiaHealth,Inc."},
	{429, "FlightSafetyInternational"},
	{430, "EarlensCorporation"},
	{431, "SunriseMicroDevices,Inc."},
	{432, "StarMicronicsCo.,Ltd."},
	{433, "NetizensSp.zo.o."},
	{434, "NymiInc."},
	{435, "Nytec,Inc."},
	{436, "TrineoSp.zo.o."},
	{437, "NestLabsInc."},
	{438, "LMTechnologiesLtd"},
	{439, "GeneralElectricCompany"},
	{440, "i+D3S.L."},
	{441, "HANAMicron"},
	{442, "StagesCyclingLLC"},
	{443, "CochlearBoneAnchoredSolutionsAB"},
	{444, "SenionLabAB"},
	{445, "SyszoneCo.,Ltd"},
	{446, "PulsateMobileLtd."},
	{447, "HongKongHunterSunElectronicLimited"},
	{448, "pironexGmbH"},
	{449, "BRADATECHCorp."},
	{450, "TransenergooilAG"},
	{451, "Bunch"},
	{452, "DMEMicroelectronics"},
	{453, "BitcrazeAB"},
	{454, "HASWAREInc."},
	{455, "AbiogenixInc."},
	{456, "Poly-ControlApS"},
	{457, "Avi-on"},
	{458, "LaerdalMedicalAS"},
	{459, "FetchMyPet"},
	{460, "SamLabsLtd."},
	{461, "ChengduSynwingTechnologyLtd"},
	{462, "HOUWASYSTEMDESIGN,k.k."},
	{463, "BSH"},
	{464, "PrimusInterParesLtd"},
	{465, "AugustHome,Inc"},
	{466, "GillElectronics"},
	{467, "SkyWaveDesign"},
	{468, "NewlabS.r.l."},
	{469, "ELADsrl"},
	{470, "G-wearablesinc."},
	{471, "SquadroneSystemsInc."},
	{472, "CodeCorporation"},
	{473, "SavantSystemsLLC"},
	{474, "LogitechInternationalSA"},
	{475, "InnblueConsulting"},
	{476, "iParkingLtd."},
	{477, "KoninklijkePhilipsElectronicsN.V."},
	{478, "MinelabElectronicsPtyLimited"},
	{479, "BisonGroupLtd."},
	{480, "WidexA/S"},
	{481, "JollaLtd"},
	{482, "Lectronix,Inc."},
	{483, "CaterpillarInc"},
	{484, "FreedomInnovations"},
	{485, "DynamicDevicesLtd"},
	{486, "TechnologySolutions(UK)Ltd"},
	{487, "IPSGroupInc."},
	{488, "STIR"},
	{489, "Sano,Inc."},
	{490, "AdvancedApplicationDesign,Inc."},
	{491, "AutoMapLLC"},
	{492, "SpreadtrumCommunicationsShanghaiLtd"},
	{493, "CuteCircuitLTD"},
	{494, "ValeoService"},
	{495, "FullpowerTechnologies,Inc."},
	{496, "KloudNation"},
	{497, "ZebraTechnologiesCorporation"},
	{498, "Itron,Inc."},
	{499, "TheUniversityofTokyo"},
	{500, "UTCFireandSecurity"},
	{501, "CoolWebthingsLimited"},
	{502, "DJOGlobal"},
	{503, "GellinerLimited"},
	{504, "Anyka(Guangzhou)MicroelectronicsTechnologyCo,LTD"},
	{505, "MedtronicInc."},
	{506, "GozioInc."},
	{507, "FormLifting,LLC"},
	{508, "WahooFitness,LLC"},
	{509, "KontaktMicro-LocationSp.zo.o."},
	{510, "RadioSystemsCorporation"},
	{511, "FreescaleSemiconductor,Inc."},
	{512, "VerifoneSystemsPteLtd.TaiwanBranch"},
	{513, "ARTiming"},
	{514, "RigadoLLC"},
	{515, "KemppiOy"},
	{516, "TapcentiveInc."},
	{517, "SmartboticsInc."},
	{518, "OtterProducts,LLC"},
	{519, "STEMPInc."},
	{520, "LumiGeekLLC"},
	{521, "InvisionHeartInc."},
	{522, "MacnicaInc."},
	{523, "JaguarLandRoverLimited"},
	{524, "CoroWareTechnologies,Inc"},
	{525, "SimploTechnologyCo.,LTD"},
	{526, "OmronHealthcareCo.,LTD"},
	{527, "ComoduleGMBH"},
	{528, "ikeGPS"},
	{529, "TelinkSemiconductorCo.Ltd"},
	{530, "InterplanCo.,Ltd"},
	{531, "WylerAG"},
	{532, "IKMultimediaProductionsrl"},
	{533, "LukotonExperienceOy"},
	{534, "MTILtd"},
	{535, "Tech4home,Lda"},
	{536, "HiotechAB"},
	{537, "DOTTLimited"},
	{538, "BlueSpeckLabs,LLC"},
	{539, "CiscoSystems,Inc"},
	{540, "MobicommInc"},
	{541, "Edamic"},
	{542, "Goodnet,Ltd"},
	{543, "LusterLeafProductsInc"},
	{544, "ManusMachinaBV"},
	{545, "MobiquityNetworksInc"},
	{546, "PraxisDynamics"},
	{547, "PhilipMorrisProductsS.A."},
	{548, "ComarchSA"},
	{549, "NestlNespressoS.A."},
	{550, "MerliniaA/S"},
	{551, "LifeBEAMTechnologies"},
	{552, "TwocanoesLabs,LLC"},
	{553, "MuovertiLimited"},
	{554, "StamerMusikanlagenGMBH"},
	{555, "TeslaMotors"},
	{556, "PharynksCorporation"},
	{557, "Lupine"},
	{558, "SiemensAG"},
	{559, "Huami(Shanghai)CultureCommunicationCO.,LTD"},
	{560, "FosterElectricCompany,Ltd"},
	{561, "ETASA"},
	{562, "x-SensoSolutionsKft"},
	{563, "ShenzhenSuLongCommunicationLtd"},
	{564, "FengFan(BeiJing)TechnologyCo,Ltd"},
	{565, "QrioInc"},
	{566, "PitpatpetLtd"},
	{567, "MSHelis.r.l."},
	{568, "Trakm8Ltd"},
	{569, "JINCO,Ltd"},
	{570, "AlatechTehnology"},
	{571, "BeijingCarePulseElectronicTechnologyCo,Ltd"},
	{572, "Awarepoint"},
	{573, "ViCentraB.V."},
	{574, "RavenIndustries"},
	{575, "WaveWareTechnologiesInc."},
	{576, "ArgenoxTechnologies"},
	{577, "BragiGmbH"},
	{578, "16LabInc"},
	{579, "MasimoCorp"},
	{580, "IoteraInc"},
	{581, "Endress+Hauser"},
	{582, "ACKmeNetworks,Inc."},
	{583, "FiftyThreeInc."},
	{584, "ParkerHannifinCorp"},
	{585, "TranscranialLtd"},
	{586, "UwatecAG"},
	{587, "OrlanLLC"},
	{588, "BlueCloverDevices"},
	{589, "M-WaySolutionsGmbH"},
	{590, "MicrotronicsEngineeringGmbH"},
	{591, "SchneiderSchreibgerteGmbH"},
	{592, "SapphireCircuitsLLC"},
	{593, "LumoBodytechInc."},
	{594, "UKCTechnosolution"},
	{595, "XicatoInc."},
	{596, "Playbrush"},
	{597, "DaiNipponPrintingCo.,Ltd."},
	{598, "G24PowerLimited"},
	{599, "AdBabbleLocalCommerceInc."},
	{600, "DevialetSA"},
	{601, "ALTYOR"},
	{602, "UniversityofAppliedSciencesValais/HauteEcoleValaisanne"},
	{603, "FiveInteractive,LLCdbaZendo"},
	{604, "NetEaseHangzhouNetworkco.Ltd."},
	{605, "LexmarkInternationalInc."},
	{606, "FlukeCorporation"},
	{607, "YardarmTechnologies"},
	{608, "SensaRx"},
	{609, "SECVREGmbH"},
	{610, "GlacialRidgeTechnologies"},
	{611, "Identiv,Inc."},
	{612, "DDS,Inc."},
	{613, "SMKCorporation"},
	{614, "SchawbelTechnologiesLLC"},
	{615, "XMISystemsSA"},
	{616, "Cerevo"},
	{617, "TorroxGmbH&CoKG"},
	{618, "Gemalto"},
	{619, "DEKAResearch&DevelopmentCorp."},
	{620, "DomsterTadeuszSzydlowski"},
	{621, "TechnogymSPA"},
	{622, "FLEURBAEYBVBA"},
	{623, "AptcodeSolutions"},
	{624, "LSIADLTechnology"},
	{625, "AnimasCorp"},
	{626, "AlpsElectricCo.,Ltd."},
	{627, "OCEASOFT"},
	{628, "MotsaiResearch"},
	{629, "Geotab"},
	{630, "E.G.O.Elektro-GertebauGmbH"},
	{631, "bewhereinc"},
	{632, "JohnsonOutdoorsInc"},
	{633, "steuteSchaltgerateGmbH&Co.KG"},
	{634, "Ekominiinc."},
	{635, "DEFAAS"},
	{636, "AseptikaLtd"},
	{637, "HUAWEITechnologiesCo.,Ltd.()"},
	{638, "HabitAware,LLC"},
	{639, "ruwidoaustriagmbh"},
	{640, "ITECcorporation"},
	{641, "StoneL"},
	{642, "SonovaAG"},
	{643, "MavenMachines,Inc."},
	{644, "SynapseElectronics"},
	{645, "StandardInnovationInc."},
	{646, "RFCode,Inc."},
	{647, "WallyVenturesS.L."},
	{648, "WillowbankElectronicsLtd"},
	{649, "SKTelecom"},
	{650, "JetroAS"},
	{651, "CodeGearsLTD"},
	{652, "NANOLINKAPS"},
	{653, "IF,LLC"},
	{654, "RFDigitalCorp"},
	{655, "Church&DwightCo.,Inc"},
	{656, "MultibitOy"},
	{657, "CliniCloudInc"},
	{658, "SwiftSensors"},
	{659, "BlueBite"},
	{660, "ELIASGmbH"},
	{661, "SivantosGmbH"},
	{662, "Petzl"},
	{663, "stormpowerltd"},
	{664, "EISSTLtd"},
	{665, "InexessTechnologySimmaKG"},
	{666, "Currant,Inc."},
	{667, "C2Development,Inc."},
	{668, "BlueSkyScientific,LLC"},
	{669, "ALOTTAZSLABS,LLC"},
	{670, "Kupsonspol.sr.o."},
	{671, "AreusEngineeringGmbH"},
	{672, "ImpossibleCameraGmbH"},
	{673, "InventureTrackSystems"},
	{674, "LockedUp"},
	{675, "Itude"},
	{676, "PacificLockCompany"},
	{677, "TendyronCorporation()"},
	{678, "RobertBoschGmbH"},
	{679, "IlluxtroninternationalB.V."},
	{680, "miSportLtd."},
	{681, "Chargelib"},
	{682, "DopplerLab"},
	{683, "BBPOSLimited"},
	{684, "RTBElektronikGmbH&Co.KG"},
	{685, "RxNetworks,Inc."},
	{686, "WeatherFlow,Inc."},
	{687, "TechnicolorUSAInc."},
	{688, "Bestechnic(Shanghai),Ltd"},
	{689, "RadenInc"},
	{690, "JouZenOy"},
	{691, "CLABERS.P.A."},
	{692, "Hyginex,Inc."},
	{693, "HANSHINELECTRICRAILWAYCO.,LTD."},
	{694, "SchneiderElectric"},
	{695, "OortTechnologiesLLC"},
	{696, "ChronoTherapeutics"},
	{697, "RinnaiCorporation"},
	{698, "SwissprimeTechnologiesAG"},
	{699, "Koha.,Co.Ltd"},
	{700, "GenevacLtd"},
	{701, "Chemtronics"},
	{702, "SeguroTechnologySp.zo.o."},
	{703, "RedbirdFlightSimulations"},
	{704, "DashRobotics"},
	{705, "LINECorporation"},
	{706, "GuillemotCorporation"},
	{707, "TechtronicPowerToolsTechnologyLimited"},
	{708, "WilsonSportingGoods"},
	{709, "Lenovo(Singapore)PteLtd.()"},
	{710, "AyatanSensors"},
	{711, "ElectronicsTomorrowLimited"},
	{712, "VASCODataSecurityInternational,Inc."},
	{713, "PayRangeInc."},
	{714, "ABOVSemiconductor"},
	{715, "AINA-WirelessInc."},
	{716, "EijkelkampSoil&Water"},
	{717, "BMAergonomicsb.v."},
	{718, "TevaBrandedPharmaceuticalProductsR&D,Inc."},
	{719, "Anima"},
	{720, "3M"},
	{721, "EmpaticaSrl"},
	{722, "Afero,Inc."},
	{723, "PowercastCorporation"},
	{724, "SecuyouApS"},
	{725, "OMRONCorporation"},
	{726, "SendSolutions"},
	{727, "NIPPONSYSTEMWARECO.,LTD."},
	{728, "Neosfar"},
	{729, "FlieglAgrartechnikGmbH"},
	{730, "Gilvader"},
	{731, "DigiInternationalInc(R)"},
	{732, "DeWalchTechnologies,Inc."},
	{733, "FlintRehabilitationDevices,LLC"},
	{734, "SamsungSDSCo.,Ltd."},
	{735, "BlurProductDevelopment"},
	{736, "UniversityofMichigan"},
	{737, "VictronEnergyBV"},
	{738, "NTTdocomo"},
	{739, "CarmanahTechnologiesCorp."},
	{740, "BytestormLtd."},
	{741, "EspressifIncorporated(())"},
	{742, "Unwire"},
	{743, "ConnectedYard,Inc."},
	{744, "AmericanMusicEnvironments"},
	{745, "SensogramTechnologies,Inc."},
	{746, "FujitsuLimited"},
	{747, "ArdicTechnology"},
	{748, "DeltaSystems,Inc"},
	{749, "HTCCorporation"},
	{750, "CitizenHoldingsCo.,Ltd."},
	{751, "SMART-INNOVATION.inc"},
	{752, "BlackratSoftware"},
	{753, "TheIdeaCave,LLC"},
	{754, "GoPro,Inc."},
	{755, "AuthAir,Inc"},
	{756, "Vensi,Inc."},
	{757, "IndagemTechLLC"},
	{758, "IntemoTechnologies"},
	{759, "DreamVisionsco.,Ltd."},
	{760, "RunteqOyLtd"},
	{761, "IMAGINATIONTECHNOLOGIESLTD"},
	{762, "CoSTARTEchnologies"},
	{763, "ClariusMobileHealthCorp."},
	{764, "ShanghaiFrequenMicroelectronicsCo.,Ltd."},
	{765, "Uwanna,Inc."},
	{766, "LierdaScience&TechnologyGroupCo.,Ltd."},
	{767, "SiliconLaboratories"},
	{768, "WorldMotoInc."},
	{769, "GiatecScientificInc."},
	{770, "LoopDevices,Inc"},
	{771, "IACAelectronique"},
	{772, "ProxyTechnologies,Inc."},
	{773, "SwippApS"},
	{774, "LifeLaboratoryInc."},
	{775, "FUJIINDUSTRIALCO.,LTD."},
	{776, "Surefire,LLC"},
	{777, "DolbyLabs"},
	{778, "Ellisys"},
	{779, "MagnitudeLightingConverters"},
	{780, "HiltiAG"},
	{781, "DevdataS.r.l."},
	{782, "Deviceworx"},
	{783, "ShortcutLabs"},
	{784, "SGLItaliaS.r.l."},
	{785, "PEEQDATA"},
	{786, "DucereTechnologiesPvtLtd"},
	{787, "DiveNav,Inc."},
	{788, "RIIGAISp.zo.o."},
	{789, "ThermoFisherScientific"},
	{790, "AGMeasurematicsPvt.Ltd."},
	{791, "CHUOElectronicsCO.,LTD."},
	{792, "AspentaInternational"},
	{793, "EugsterFrismagAG"},
	{794, "AmberwirelessGmbH"},
	{795, "HQInc"},
	{796, "LabSensorSolutions"},
	{797, "EnterlabApS"},
	{798, "Eyefi,Inc."},
	{799, "MetaSystemS.p.A."},
	{800, "SONOELECTRONICS.CO.,LTD"},
	{801, "Jewelbots"},
	{802, "CompumedicsLimited"},
	{803, "RotorBikeComponents"},
	{804, "Astro,Inc."},
	{805, "AmotusSolutions"},
	{806, "HealthwearTechnologies(Changzhou)Ltd"},
	{807, "EssexElectronics"},
	{808, "GrundfosA/S"},
	{809, "Eargo,Inc."},
	{810, "ElectronicDesignLab"},
	{811, "ESYLUX"},
	{812, "NIPPONSMT.CO.,Ltd"},
	{813, "BMinnovationsGmbH"},
	{814, "indoormap"},
	{815, "OttoQInc"},
	{816, "NorthPoleEngineering"},
	{817, "3flaresTechnologiesInc."},
	{818, "ElectrocompanietA.S."},
	{819, "Mul-T-Lock"},
	{820, "CorentiumAS"},
	{821, "EnlightedInc"},
	{822, "GISTIC"},
	{823, "AJP2Holdings,LLC"},
	{824, "COBIGmbH"},
	{825, "BlueSkyScientific,LLC"},
	{826, "Appception,Inc."},
	{827, "CourtneyThorneLimited"},
	{828, "Virtuosys"},
	{829, "TPVTechnologyLimited"},
	{830, "MonitraSA"},
	{831, "AutomationComponents,Inc."},
	{832, "Letsenses.r.l."},
	{833, "EtesianTechnologiesLLC"},
	{834, "GERTECBRASILLTDA."},
	{835, "DrekkerDevelopmentPty.Ltd."},
	{836, "WhirlInc"},
	{837, "LocusPositioning"},
	{838, "AcuityBrandsLighting,Inc"},
	{839, "PreventBiometrics"},
	{840, "Arioneo"},
	{841, "VersaMe"},
	{842, "Vaddio"},
	{843, "LibratoneA/S"},
	{844, "HMElectronics,Inc."},
	{845, "TASERInternational,Inc."},
	{846, "SafeTrustInc."},
	{847, "HeartlandPaymentSystems"},
	{848, "BitstrataSystemsInc."},
	{849, "PiepsGmbH"},
	{850, "iRiding(Xiamen)TechnologyCo.,Ltd."},
	{851, "AlphaAudiotronics,Inc."},
	{852, "TOPPANFORMSCO.,LTD."},
	{853, "SigmaDesigns,Inc."},
	{854, "SpectrumBrands,Inc."},
	{855, "PolymapWireless"},
	{856, "MagniWareLtd."},
	{857, "NovotecMedicalGmbH"},
	{858, "MedicomInnovationPartnera/s"},
	{859, "MatrixInc."},
	{860, "EatonCorporation"},
	{861, "KYS"},
	{862, "NayaHealth,Inc."},
	{863, "Acromag"},
	{864, "InsuletCorporation"},
	{865, "WellinksInc."},
	{866, "ONSemiconductor"},
	{867, "FREELAPSA"},
	{868, "FaveroElectronicsSrl"},
	{869, "BioMechSensorLLC"},
	{870, "BOLTTSportstechnologiesPrivatelimited"},
	{871, "SapheInternational"},
	{872, "MetormoteAB"},
	{873, "littleBits"},
	{874, "SetPointMedical"},
	{875, "BRControlsProductsBV"},
	{876, "Zipcar"},
	{877, "AirBoltPtyLtd"},
	{878, "KeepTruckinInc"},
	{879, "Motiv,Inc."},
	{880, "WazombiLabsO"},
	{881, "ORBCOMM"},
	{882, "NixieLabs,Inc."},
	{883, "AppNearMeLtd"},
	{884, "HolmanIndustries"},
	{885, "ExpainAS"},
	{886, "ElectronicTemperatureInstrumentsLtd"},
	{887, "PlejdAB"},
	{888, "PropellerHealth"},
	{889, "ShenzheniMCOElectronicTechnologyCo.,Ltd"},
	{890, "Algoria"},
	{891, "ApptionLabsInc."},
	{892, "CronologicsCorporation"},
	{893, "MICRODIALtd."},
	{894, "lulabytesS.L."},
	{895, "NestecS.A."},
	{896, "LLC\"MEGA-Fservice\""},
	{897, "SharpCorporation"},
	{898, "PrecisionOutcomesLtd"},
	{899, "KronosIncorporated"},
	{900, "OCOSMOSCo.,Ltd."},
	{901, "EmbeddedElectronicSolutionsLtd.dbae2Solutions"},
	{902, "AtericaInc."},
	{903, "BluStorPMC,Inc."},
	{904, "KapschTrafficComAB"},
	{905, "ActiveBluCorporation"},
	{906, "KohlerMiraLimited"},
	{907, "Noke"},
	{908, "AppionInc."},
	{909, "ResmedLtd"},
	{910, "CrownstoneB.V."},
	{911, "XiaomiInc."},
	{912, "INFOTECHs.r.o."},
	{913, "ThingsquareAB"},
	{914, "T&D"},
	{915, "LAVAZZAS.p.A."},
	{916, "NetclearanceSystems,Inc."},
	{917, "SDATAWAY"},
	{918, "BLOKSGmbH"},
	{919, "LEGOSystemA/S"},
	{920, "ThetatronicsLtd"},
	{921, "NikonCorporation"},
	{922, "NeST"},
	{923, "SouthSiliconValleyMicroelectronics"},
	{924, "ALEInternational"},
	{925, "CareViewCommunications,Inc."},
	{926, "SchoolBoardLimited"},
	{927, "MolexCorporation"},
	{928, "IVTWirelessLimited"},
	{929, "AlpineLabsLLC"},
	{930, "CanduraInstruments"},
	{931, "SmartMovtTechnologyCo.,Ltd"},
	{932, "TokenZeroLtd"},
	{933, "ACECADEnterpriseCo.,Ltd.(ACECAD)"},
	{934, "Medela,Inc"},
	{935, "AeroScout"},
	{936, "EsrilleInc."},
	{937, "THINKERLYSRL"},
	{938, "ExonSp.zo.o."},
	{939, "MeizuTechnologyCo.,Ltd."},
	{940, "SmabloLTD"},
	{941, "XiQ"},
	{942, "AllswellInc."},
	{943, "Comm-N-SenseCorpDBAVerigo"},
	{944, "VIBRADORMGmbH"},
	{945, "OtodataWirelessNetworkInc."},
	{946, "PropagationSystemsLimited"},
	{947, "MidwestInstruments&Controls"},
	{948, "AlphaNodus,inc."},
	{949, "petPOMM,Inc"},
	{950, "Mattel"},
	{951, "AirblyInc."},
	{952, "A-SafeLimited"},
	{953, "FREDERIQUECONSTANTSA"},
	{954, "MaxscendMicroelectronicsCompanyLimited"},
	{955, "AbbottDiabetesCare"},
	{956, "ASBBankLtd"},
	{957, "amadas"},
	{958, "AppliedScience,Inc."},
	{959, "iLumiSolutionsInc."},
	{960, "ArchSystemsInc."},
	{961, "EmberTechnologies,Inc."},
	{962, "SnapchatInc"},
	{963, "CasambiTechnologiesOy"},
	{964, "PicoTechnologyInc."},
	{965, "St.JudeMedical,Inc."},
	{966, "Intricon"},
	{967, "StructuralHealthSystems,Inc."},
	{968, "AvvelInternational"},
	{969, "GallagherGroup"},
	{970, "In2thingsAutomationPvt.Ltd."},
	{971, "SYSDEVSrl"},
	{972, "VonkilTechnologiesLtd"},
	{973, "WyndTechnologies,Inc."},
	{974, "CONTRINEXS.A."},
	{975, "MIRA,Inc."},
	{976, "WatteamLtd"},
	{977, "DensityInc."},
	{978, "IOTPotIndiaPrivateLimited"},
	{979, "SigmaConnectivityAB"},
	{980, "PEGPEREGOSPA"},
	{981, "WyzelinkSystemsInc."},
	{982, "YotaDevicesLTD"},
	{983, "FINSECUR"},
	{984, "Zen-MeLabsLtd"},
	{985, "3IWareCo.,Ltd."},
	{986, "EnOceanGmbH"},
	{987, "Instabeat,Inc"},
	{988, "NimaLabs"},
	{989, "AndreasStihlAG&Co.KG"},
	{990, "NathanRhoadesLLC"},
	{991, "GrobTechnologies,LLC"},
	{992, "Actions(Zhuhai)TechnologyCo.,Limited"},
	{993, "SPDDevelopmentCompanyLtd"},
	{994, "SensoanOy"},
	{995, "QualcommLifeInc"},
	{996, "Chip-ingAG"},
	{997, "ffly4u"},
	{998, "IoTInstrumentsOy"},
	{999, "TRUEFitnessTechnology"},
	{1000, "ReinerKartengeraeteGmbH&Co.KG."},
	{1001, "SHENZHENLEMONJOYTECHNOLOGYCO.,LTD."},
	{1002, "HelloInc."},
	{1003, "EvollveInc."},
	{1004, "JigowattsInc."},
	{1005, "BASICMICRO.COM,INC."},
	{1006, "CUBETECHNOLOGIES"},
	{1007, "foolographyGmbH"},
	{1008, "CLINK"},
	{1009, "HestanSmartCookingInc."},
	{1010, "WindowMasterA/S"},
	{1011, "FlowscapeAB"},
	{1012, "PALTechnologiesLtd"},
	{1013, "WHERE,Inc."},
	{1014, "ItonTechnologyCorp."},
	{1015, "OwlLabsInc."},
	{1016, "RockfordCorp."},
	{1017, "BeconTechnologiesCo.,Ltd."},
	{1018, "VyassoftTechnologiesInc"},
	{1019, "NoxMedical"},
	{1020, "Kimberly-Clark"},
	{1021, "TrimbleNavigationLtd."},
	{1022, "Littelfuse"},
	{1023, "Withings"},
	{1024, "i-developerITBeratungUG"},
	{1025, ""},
	{1026, "SearsHoldingsCorporation"},
	{1027, "GantnerElectronicGmbH"},
	{1028, "AuthomateInc"},
	{1029, "VertexInternational,Inc."},
	{1030, "Airtago"},
	{1031, "SwissAudioSA"},
	{1032, "ToGetHomeInc."},
	{1033, "AXIS"},
	{1034, "Openmatics"},
	{1035, "JanaCareInc."},
	{1036, "SenixCorporation"},
	{1037, "NorthStarBatteryCompany,LLC"},
	{1038, "SKF(U.K.)Limited"},
	{1039, "CO-AXTechnology,Inc."},
	{1040, "FenderMusicalInstruments"},
	{1041, "LuidiaInc"},
	{1042, "SEFAM"},
	{1043, "WirelessCablesInc"},
	{1044, "LightningProtectionInternationalPtyLtd"},
	{1045, "UberTechnologiesInc"},
	{1046, "SODAGmbH"},
	{1047, "FatigueScience"},
	{1048, "AlpineElectronicsInc."},
	{1049, "NovalogyLTD"},
	{1050, "FridayLabsLimited"},
	{1051, "OrthoAccelTechnologies"},
	{1052, "WaterGuru,Inc."},
	{1053, "BenningElektrotechnikundElektronikGmbH&Co.KG"},
	{1054, "DellComputerCorporation"},
	{1055, "KopinCorporation"},
	{1056, "TecBakeryGmbH"},
	{1057, "BackboneLabs,Inc."},
	{1058, "DELSEYSA"},
	{1059, "ChargifiLimited"},
	{1060, "TrainesenseLtd."},
	{1061, "UnifySoftwareandSolutionsGmbH&Co.KG"},
	{1062, "HusqvarnaAB"},
	{1063, "Focusfleetandfuelmanagementinc"},
	{1064, "SmallLoop,LLC"},
	{1065, "ProlonInc."},
	{1066, "BDMedical"},
	{1067, "iMicroMedIncorporated"},
	{1068, "TictoN.V."},
	{1069, "MeshtechAS"},
	{1070, "MemCachierInc."},
	{1071, "DanfossA/S"},
	{1072, "SnapStykInc."},
	{1073, "AmwayCorporation"},
	{1074, "SilkLabs,Inc."},
	{1075, "PillsyInc."},
	{1076, "HatchBaby,Inc."},
	{1077, "BlocksWearablesLtd."},
	{1078, "DraysonTechnologies(Europe)Limited"},
	{1079, "eBestIOTInc."},
	{1080, "HelvarLtd"},
	{1081, "RadianceTechnologies"},
	{1082, "NuhearaLimited"},
	{1083, "Appsideco.,ltd."},
	{1084, "DeLaval"},
	{1085, "CoilerCorporation"},
	{1086, "Thermomedics,Inc."},
	{1087, "TentacleSyncGmbH"},
	{1088, "Valencell,Inc."},
	{1089, "iProtoXiOy"},
	{1090, "SECOMCO.,LTD."},
	{1091, "TuckerInternationalLLC"},
	{1092, "MetanateLimited"},
	{1093, "KobianCanadaInc."},
	{1094, "NETGEAR,Inc."},
	{1095, "FabtronicsAustraliaPtyLtd"},
	{1096, "GrandCentrixGmbH"},
	{1097, "1UPUSA.comllc"},
	{1098, "SHIMANOINC."},
	{1099, "NainInc."},
	{1100, "LifeStyleLock,LLC"},
	{1101, "VEGAGrieshaberKG"},
	{1102, "XtravaInc."},
	{1103, "TTSTooltechnicSystemsAG&Co.KG"},
	{1104, "TeenageEngineeringAB"},
	{1105, "TunstallNordicAB"},
	{1106, "SvepDesignCenterAB"},
	{1107, "GreenPeakTechnologiesBV"},
	{1108, "SphinxElectronicsGmbH&CoKG"},
	{1109, "Atomation"},
	{1110, "NemikConsultingInc"},
	{1111, "RFINNOVATION"},
	{1112, "MiniSolutionCo.,Ltd."},
	{1113, "Lumenetix,Inc"},
	{1114, "2048450OntarioInc"},
	{1115, "SPACEEKLTD"},
	{1116, "DeltaTCorporation"},
	{1117, "BostonScientificCorporation"},
	{1118, "Nuviz,Inc."},
	{1119, "RealTimeAutomation,Inc."},
	{1120, "Kolibree"},
	{1121, "vhfelektronikGmbH"},
	{1122, "BonsaiSystemsGmbH"},
	{1123, "FathomSystemsInc."},
	{1124, "Bellman&Symfon"},
	{1125, "InternationalForteGroupLLC"},
	{1126, "CycleLabsSolutionsinc."},
	{1127, "CodenexOy"},
	{1128, "KynesimLtd"},
	{1129, "PalagoAB"},
	{1130, "INSIGMAINC."},
	{1131, "PMDSolutions"},
	{1132, "QingdaoRealtimeTechnologyCo.,Ltd."},
	{1133, "BEGAGantenbrink-LeuchtenKG"},
	{1134, "PamborLtd."},
	{1135, "DevelcoProductsA/S"},
	{1136, "iDesigns.r.l."},
	{1137, "TiVoCorp"},
	{1138, "Control-JPtyLtd"},
	{1139, "Steelcase,Inc."},
	{1140, "iApartmentco.,ltd."},
	{1141, "Icominc."},
	{1142, "OxstrenWearableTechnologiesPrivateLimited"},
	{1143, "BlueSparkTechnologies"},
	{1144, "FarSiteCommunicationsLimited"},
	{1145, "mywerksystemGmbH"},
	{1146, "SinosunTechnologyCo.,Ltd."},
	{1147, "MIYOSHIELECTRONICSCORPORATION"},
	{1148, "POWERMATLTD"},
	{1149, "OcclyLLC"},
	{1150, "OurHubDevIvS"},
	{1151, "Pro-Mark,Inc."},
	{1152, "DynometricsInc."},
	{1153, "QuintraxLimited"},
	{1154, "POSTuningUdoVosshenrichGmbH&Co.KG"},
	{1155, "MultiCareSystemsB.V."},
	{1156, "RevolTechnologiesInc"},
	{1157, "SKIDATAAG"},
	{1158, "DEVTECNOLOGIAINDUSTRIA,COMERCIOEMANUTENCAODEEQUIPAMENTOSLTDA.-ME"},
	{1159, "CentricaConnectedHome"},
	{1160, "AutomotiveDataSolutionsInc"},
	{1161, "IgarashiEngineering"},
	{1162, "TaelekOy"},
	{1163, "CPElectronicsLimited"},
	{1164, "VectronixAG"},
	{1165, "S-LabsSp.zo.o."},
	{1166, "CompanionMedical,Inc."},
	{1167, "BlueKitchenGmbH"},
	{1168, "MattingAB"},
	{1169, "SOREX-WirelessSolutionsGmbH"},
	{1170, "ADCTechnology,Inc."},
	{1171, "LynxemiPteLtd"},
	{1172, "SENNHEISERelectronicGmbH&Co.KG"},
	{1173, "LMTMercerGroup,Inc"},
	{1174, "PolymorphicLabsLLC"},
	{1175, "CochlearLimited"},
	{1176, "METERGroup,Inc.USA"},
	{1177, "RuuviInnovationsLtd."},
	{1178, "SituneAS"},
	{1179, "nVisti,LLC"},
	{1180, "DyOcean"},
	{1181, "Uhlmann&ZacherGmbH"},
	{1182, "AND!XORLLC"},
	{1183, "tictoteAB"},
	{1184, "Vypin,LLC"},
	{1185, "PNISensorCorporation"},
	{1186, "ovrEngineered,LLC"},
	{1187, "GT-tronicsHKLtd"},
	{1188, "HerbertWaldmannGmbH&Co.KG"},
	{1189, "GuangzhouFiiOElectronicsTechnologyCo.,Ltd"},
	{1190, "VinetechCo.,Ltd"},
	{1191, "DallasLogicCorporation"},
	{1192, "BioTex,Inc."},
	{1193, "DISCOVERYSOUNDTECHNOLOGY,LLC"},
	{1194, "LINKIOSAS"},
	{1195, "Harbortronics,Inc."},
	{1196, "UndagridB.V."},
	{1197, "ShureInc"},
	{1198, "ERMElectronicSystemsLTD"},
	{1199, "BIOROWERHandelsagenturGmbH"},
	{1200, "WebaSportundMed.ArtikelGmbH"},
	{1201, "KartographersTechnologiesPvt.Ltd."},
	{1202, "TheShadowontheMoon"},
	{1203, "mobike(HongKong)Limited"},
	{1204, "InuheatGroupAB"},
	{1205, "SwiftronixAB"},
	{1206, "DiagnopticsTechnologies"},
	{1207, "AnalogDevices,Inc."},
	{1208, "SoraaInc."},
	{1209, "CSRBuildingProductsLimited"},
	{1210, "CrestronElectronics,Inc."},
	{1211, "NeateboxLtd"},
	{1212, "DraegerwerkAG&Co.KGaA"},
	{1213, "AlbynMedical"},
	{1214, "AverosFZCO"},
	{1215, "VITInitiative,LLC"},
	{1216, "StatsportsInternational"},
	{1217, "Sospitas,s.r.o."},
	{1218, "DmetProductsCorp."},
	{1219, "MantracourtElectronicsLimited"},
	{1220, "TeAMHutchinsAB"},
	{1221, "SeibertWilliamsGlass,LLC"},
	{1222, "InstaGmbH"},
	{1223, "SvantekSp.zo.o."},
	{1224, "ShanghaiFlycoElectricalApplianceCo.,Ltd."},
	{1225, "ThornwaveLabsInc"},
	{1226, "Steiner-OptikGmbH"},
	{1227, "NovoNordiskA/S"},
	{1228, "EnfluxInc."},
	{1229, "SafetechProductsLLC"},
	{1230, "GOOOLEDS.R.L."},
	{1231, "DOMSicherheitstechnikGmbH&Co.KG"},
	{1232, "OlympusCorporation"},
	{1233, "KTSGmbH"},
	{1234, "AnloqTechnologiesInc."},
	{1235, "Queercon,Inc"},
	{1236, "5thElementLtd"},
	{1237, "GooeeLimited"},
	{1238, "LUGLOCLLC"},
	{1239, "Blincam,Inc."},
	{1240, "FUJIFILMCorporation"},
	{1241, "RandMcNally"},
	{1242, "FranceschiMarinasnc"},
	{1243, "EngineeredAudio,LLC."},
	{1244, "IOTTIVE(OPC)PRIVATELIMITED"},
	{1245, "4MODTechnology"},
	{1246, "LutronElectronicsCo.,Inc."},
	{1247, "Emerson"},
	{1248, "Guardtec,Inc."},
	{1249, "REACTECLIMITED"},
	{1250, "EllieGrid"},
	{1251, "UnderArmour"},
	{1252, "Woodenshark"},
	{1253, "AvackOy"},
	{1254, "SmartSolutionTechnology,Inc."},
	{1255, "REHABTRONICSINC."},
	{1256, "STABILOInternational"},
	{1257, "BuschJaegerElektroGmbH"},
	{1258, "PacificBioscienceLaboratories,Inc"},
	{1259, "BirdHomeAutomationGmbH"},
	{1260, "MotorolaSolutions"},
	{1261, "R9Technology,Inc."},
	{1262, "Auxivia"},
	{1263, "DaisyWorks,Inc"},
	{1264, "KosiLimited"},
	{1265, "ThebenAG"},
	{1266, "InDreamerTechsolPrivateLimited"},
	{1267, "CerevastMedical"},
	{1268, "ZanComputeInc."},
	{1269, "PirelliTyreS.P.A."},
	{1270, "McLearLimited"},
	{1271, "ShenzhenHuidingTechnologyCo.,Ltd."},
	{1272, "ConvergenceSystemsLimited"},
	{1273, "Interactio"},
	{1274, "AndrotecGmbH"},
	{1275, "BenchmarkDrivesGmbH&Co.KG"},
	{1276, "SwingLyncL.L.C."},
	{1277, "TapkeyGmbH"},
	{1278, "WoosimSystemsInc."},
	{1279, "MicrosemiCorporation"},
	{1280, "WiliotLTD."},
	{1281, "PolarisIND"},
	{1282, "Specifi-KaliLLC"},
	{1283, "Locoroll,Inc"},
	{1284, "PHYPLUSInc"},
	{1285, "InplayTechnologiesLLC"},
	{1286, "Hager"},
	{1287, "Yellowcog"},
	{1288, "AxesSystemsp.zo.o."},
	{1289, "myLIFTERInc."},
	{1290, "Shake-onB.V."},
	{1291, "VibrissaInc."},
	{1292, "OSRAMGmbH"},
	{1293, "TRSystemsGmbH"},
	{1294, "YichipMicroelectronics(Hangzhou)Co.,Ltd."},
	{1295, "FoundationEngineeringLLC"},
	{1296, "UNI-ELECTRONICS,INC."},
	{1297, "BrookfieldEquinoxLLC"},
	{1298, "SoprodSA"},
	{1299, "9974091CanadaInc."},
	{1300, "FIBROGmbH"},
	{1301, "RBControlsCo.,Ltd."},
	{1302, "Footmarks"},
	{1303, "AmtronicSverigeAB(formerlyAmcoreAB)"},
	{1304, "MAMORIO.inc"},
	{1305, "TytoLifeLLC"},
	{1306, "LeicaCameraAG"},
	{1307, "AngeeTechnologiesLtd."},
	{1308, "EDPS"},
	{1309, "OFFLineCo.,Ltd."},
	{1310, "DetectBlueLimited"},
	{1311, "SetecPtyLtd"},
	{1312, "TargetCorporation"},
	{1313, "IAICorporation"},
	{1314, "NSTech,Inc."},
	{1315, "MTGCo.,Ltd."},
	{1316, "HangzhouiMagicTechnologyCo.,Ltd"},
	{1317, "HONGKONGNANOICTECHNOLOGIESCO.,LIMITED"},
	{1318, "HoneywellInternationalInc."},
	{1319, "AlbrechtJUNG"},
	{1320, "LuneraLightingInc."},
	{1321, "LumenUAB"},
	{1322, "KeynesControlsLtd"},
	{1323, "NovartisAG"},
	{1324, "GeosatisSA"},
	{1325, "EXFO,Inc."},
	{1326, "LEDVANCEGmbH"},
	{1327, "CenterIDCorp."},
	{1328, "Adolene,Inc."},
	{1329, "D&MHoldingsInc."},
	{1330, "CRESCOWireless,Inc."},
	{1331, "NuraOperationsPtyLtd"},
	{1332, "Frontiergadget,Inc."},
	{1333, "SmartComponentTechnologiesLimited"},
	{1334, "ZTRControlSystemsLLC"},
	{1335, "MetaLogicsCorporation"},
	{1336, "MedelaAG"},
	{1337, "OPPLELightingCo.,Ltd"},
	{1338, "SavitechCorp.,"},
	{1339, "prodigy"},
	{1340, "ScreenovateTechnologiesLtd"},
	{1341, "TESASA"},
	{1342, "CLIM8LIMITED"},
	{1343, "SilergyCorp"},
	{1344, "SilverPlus,Inc"},
	{1345, "Sharknetsrl"},
	{1346, "MistSystems,Inc."},
	{1347, "MIWALOCKCO.,Ltd"},
	{1348, "OrthoSensor,Inc."},
	{1349, "CandyHooverGroups.r.l"},
	{1350, "ApexarTechnologiesS.A."},
	{1351, "LOGICDATAd.o.o."},
	{1352, "KnickElektronischeMessgeraeteGmbH&Co.KG"},
	{1353, "SmartTechnologiesandInvestmentLimited"},
	{1354, "LinoughInc."},
	{1355, "AdvancedElectronicDesigns,Inc."},
	{1356, "CarefreeScottFetzerCoInc"},
	{1357, "Sensome"},
	{1358, "FORTRONIKstoritved.o.o."},
	{1359, "Sinnoz"},
	{1360, "VersaNetworks,Inc."},
	{1361, "Sylero"},
	{1362, "AvempaceSARL"},
	{1363, "NintendoCo.,Ltd."},
	{1364, "NationalInstruments"},
	{1365, "KROHNEMesstechnikGmbH"},
	{1366, "OtodynamicsLtd"},
	{1367, "ArwinTechnologyLimited"},
	{1368, "benegear,inc."},
	{1369, "NewconOptik"},
	{1370, "CANDYHOUSE,Inc."},
	{1371, "FRANKLINTECHNOLOGYINC"},
	{1372, "Lely"},
	{1373, "ValveCorporation"},
	{1374, "HekatronVertriebsGmbH"},
	{1375, "PROTECHS.A.S.DIGIRARDIANDREA&C."},
	{1376, "SaritaCareTechAPS(formerlySaritaCareTechIVS)"},
	{1377, "FinderS.p.A."},
	{1378, "ThalmicLabsInc."},
	{1379, "SteinelVertriebGmbH"},
	{1380, "BeghelliSpa"},
	{1381, "BeijingSmartspaceTechnologiesInc."},
	{1382, "CORETRANSPORTTECHNOLOGIESNZLIMITED"},
	{1383, "XiamenEveresportsGoodsCo.,Ltd"},
	{1384, "BodyportInc."},
	{1385, "AudionicsSystem,INC."},
	{1386, "FlipnaviCo.,Ltd."},
	{1387, "RionCo.,Ltd."},
	{1388, "LongRangeSystems,LLC"},
	{1389, "RedmondIndustrialGroupLLC"},
	{1390, "VIZPININC."},
	{1391, "BikeFinderAS"},
	{1392, "ConsumerSleepSolutionsLLC"},
	{1393, "PSIKICK,INC."},
	{1394, "AntTail.com"},
	{1395, "LightingScienceGroupCorp."},
	{1396, "AFFORDABLEELECTRONICSINC"},
	{1397, "IntegralMemroyPlc"},
	{1398, "Globalstar,Inc."},
	{1399, "TrueWearables,Inc."},
	{1400, "WellingtonDriveTechnologiesLtd"},
	{1401, "EnsembleTechPrivateLimited"},
	{1402, "OMNIRemotes"},
	{1403, "DuracellU.S.OperationsInc."},
	{1404, "ToorTechnologiesLLC"},
	{1405, "InstinctPerformance"},
	{1406, "Beco,Inc"},
	{1407, "ScufGamingInternational,LLC"},
	{1408, "ARANZMedicalLimited"},
	{1409, "LYSTECHNOLOGIESLTD"},
	{1410, "BreakwallAnalytics,LLC"},
	{1411, "CodeBlueCommunications"},
	{1412, "GiraGiersiepenGmbH&Co.KG"},
	{1413, "HearingLabTechnology"},
	{1414, "LEGRAND"},
	{1415, "DerichsGmbH"},
	{1416, "ALT-TEKNIKLLC"},
	{1417, "StarTechnologies"},
	{1418, "STARTTODAYCO.,LTD."},
	{1419, "MaximIntegratedProducts"},
	{1420, "MERCKKommanditgesellschaftaufAktien"},
	{1421, "JungheinrichAktiengesellschaft"},
	{1422, "OculusVR,LLC"},
	{1423, "HENDONSEMICONDUCTORSPTYLTD"},
	{1424, "Pur3Ltd"},
	{1425, "ViasatGroupS.p.A."},
	{1426, "IZITHERM"},
	{1427, "SpauldingClinicalResearch"},
	{1428, "KohlerCompany"},
	{1429, "InorProcessAB"},
	{1430, "MySmartBlinds"},
	{1431, "RadioPulseInc"},
	{1432, "rapitagGmbH"},
	{1433, "Lazlo326,LLC."},
	{1434, "TeledyneLecroy,Inc."},
	{1435, "DataflowSystemsLimited"},
	{1436, "MacrogigaElectronics"},
	{1437, "TandemDiabetesCare"},
	{1438, "Polycom,Inc."},
	{1439, "Fisher&PaykelHealthcare"},
	{1440, "RCPSoftwareOy"},
	{1441, "ShanghaiXiaoyiTechnologyCo.,Ltd."},
	{1442, "ADHERIUM(NZ)LIMITED"},
	{1443, "AxiomwareSystemsIncorporated"},
	{1444, "O.E.M.Controls,Inc."},
	{1445, "KiirooBV"},
	{1446, "TeleconMobileLimited"},
	{1447, "SonosInc"},
	{1448, "TomAllebrandiConsulting"},
	{1449, "Monidor"},
	{1450, "TramexLimited"},
	{1451, "NofenceAS"},
	{1452, "GoerTekDynaudioCo.,Ltd."},
	{1453, "INIA"},
	{1454, "CARMATEMFG.CO.,LTD"},
	{1455, "ONvocal"},
	{1456, "NewTecGmbH"},
	{1457, "MedallionInstrumentationSystems"},
	{1458, "CARELINDUSTRIESS.P.A."},
	{1459, "ParabitSystems,Inc."},
	{1460, "WhiteHorseScientificltd"},
	{1461, "verisilicon"},
	{1462, "ElecsIndustryCo.,Ltd."},
	{1463, "BeijingPineconeElectronicsCo.,Ltd."},
	{1464, "AmbystomaLabsInc."},
	{1465, "SuzhouPairlinkNetworkTechnology"},
	{1466, "igloohome"},
	{1467, "OxfordMetricsplc"},
	{1468, "LevitonMfg.Co.,Inc."},
	{1469, "ULCRoboticsInc."},
	{1470, "RFIDGlobalbySoftworkSrL"},
	{1471, "Real-World-SystemsCorporation"},
	{1472, "NaluMedical,Inc."},
	{1473, "P.I.Engineering"},
	{1474, "GroteIndustries"},
	{1475, "Runtime,Inc."},
	{1476, "Codecoupsp.zo.o.sp.k."},
	{1477, "SELVEGmbH&Co.KG"},
	{1478, "SmartAnimalTrainingSystems,LLC"},
	{1479, "LippertComponents,INC"},
	{1480, "SOMFYSAS"},
	{1481, "TBSElectronicsB.V."},
	{1482, "MHLCustomInc"},
	{1483, "LucentWearLLC"},
	{1484, "WATTSELECTRONICS"},
	{1485, "RJBrandsLLC"},
	{1486, "V-ZUGLtd"},
	{1487, "BiowatchSA"},
	{1488, "AnovaAppliedElectronics"},
	{1489, "LindabAB"},
	{1490, "frogblueTECHNOLOGYGmbH"},
	{1491, "AcurableLimited"},
	{1492, "LAMPLIGHTCo.,Ltd."},
	{1493, "TEGAM,Inc."},
	{1494, "ZhuhaiJielitechnologyCo.,Ltd"},
	{1495, "modum.ioAG"},
	{1496, "FarmJennyLLC"},
	{1497, "ToyoElectronicsCorporation"},
	{1498, "AppliedNeuralResearchCorp"},
	{1499, "AvidIdentificationSystems,Inc."},
	{1500, "PetronicsInc."},
	{1501, "essentimGmbH"},
	{1502, "QTMedicalINC."},
	{1503, "VIRTUALCLINIC.DIRECTLIMITED"},
	{1504, "ViperDesignLLC"},
	{1505, "Human,Incorporated"},
	{1506, "stAPPtronicsGmbH"},
	{1507, "ElementalMachines,Inc."},
	{1508, "TaiyoYudenCo.,Ltd"},
	{1509, "INEOENERGY&SYSTEMS"},
	{1510, "MotionInstrumentsInc."},
	{1511, "PressurePro"},
	{1512, "COWBOY"},
	{1513, "iconmobileGmbH"},
	{1514, "ACS-Control-SystemGmbH"},
	{1515, "BayerischeMotorenWerkeAG"},
	{1516, "GycomSvenskaAB"},
	{1517, "FujiXeroxCo.,Ltd"},
	{1518, "GlideInc."},
	{1519, "SIKOMAS"},
	{1520, "beken"},
	{1521, "TheLinuxFoundation"},
	{1522, "TryandECO.,LTD."},
	{1523, "SeeScan"},
	{1524, "Clearity,LLC"},
	{1525, "GSTAG"},
	{1526, "DPTechnics"},
	{1527, "TRACMO,INC."},
	{1528, "AnkiInc."},
	{1529, "HagleitnerHygieneInternationalGmbH"},
	{1530, "KonamiSportsLifeCo.,Ltd."},
	{1531, "ArbletInc."},
	{1532, "MasbandoGmbH"},
	{1533, "Innoseis"},
	{1534, "Niko"},
	{1535, "WellnomicsLtd"},
	{1536, "iRobotCorporation"},
	{1537, "SchraderElectronics"},
	{1538, "GeberitInternationalAG"},
	{1539, "FourthEvolutionInc"},
	{1540, "Cell2JackLLC"},
	{1541, "FMWelectronicFuttereru.Maier-WolfOHG"},
	{1542, "JohnDeere"},
	{1543, "RookeryTechnologyLtd"},
	{1544, "KeySafe-Cloud"},
	{1545, "BUCHILabortechnikAG"},
	{1546, "IQAirAG"},
	{1547, "TriaxTechnologiesInc"},
	{1548, "VuzixCorporation"},
	{1549, "TDKCorporation"},
	{1550, "BlueairAB"},
	{1551, "SignifyNetherlands"},
	{1552, "ADHGUARDIANUSALLC"},
	{1553, "BeurerGmbH"},
	{1554, "PlayfinityAS"},
	{1555, "HansDinslageGmbH"},
	{1556, "OnAssetIntelligence,Inc."},
	{1557, "INTERACTIONCorporation"},
	{1558, "OS42UG(haftungsbeschraenkt)"},
	{1559, "WIZCONNECTEDCOMPANYLIMITED"},
	{1560, "Audio-TechnicaCorporation"},
	{1561, "SixGuysLabs,s.r.o."},
	{1562, "R.W.BeckettCorporation"},
	{1563, "silextechnology,inc."},
	{1564, "UnivationsLimited"},
	{1565, "SENSInnovationApS"},
	{1566, "DiamondKinetics,Inc."},
	{1567, "PhrameInc."},
	{1568, "ForciotOy"},
	{1569, "Noordungd.o.o."},
	{1570, "BeamLabs,LLC"},
	{1571, "PhiladelphiaScientific(U.K.)Limited"},
	{1572, "BiovotionAG"},
	{1573, "SquarePanda,Inc."},
	{1574, "Amplifico"},
	{1575, "WEGS.A."},
	{1576, "EnstoOy"},
	{1577, "PHONEPEPVTLTD"},
	{1578, "LunaticoAstronomiaSL"},
	{1579, "MinebeaMitsumiInc."},
	{1580, "ASPionGmbH"},
	{1581, "Vossloh-SchwabeDeutschlandGmbH"},
	{1582, "Procept"},
	{1583, "ONKYOCorporation"},
	{1584, "AsthreaD.O.O."},
	{1585, "FortioriDesignLLC"},
	{1586, "HugoMullerGmbH&CoKG"},
	{1587, "WangiLaiPLT"},
	{1588, "FanstelCorp"},
	{1589, "Crookwood"},
	{1590, "ELECTRONICAINTEGRALDESONIDOS.A."},
	{1591, "GiPInnovationToolsGmbH"},
	{1592, "LXSOLUTIONSPTYLIMITED"},
	{1593, "ShenzhenMinewTechnologiesCo.,Ltd."},
	{1594, "ProlojikLimited"},
	{1595, "KromekGroupPlc"},
	{1596, "ContecMedicalSystemsCo.,Ltd."},
	{1597, "XradioTechnologyCo.,Ltd."},
	{1598, "TheIndoorLab,LLC"},
	{1599, "LDLTECHNOLOGY"},
	{1600, "Parkifi"},
	{1601, "RevenueCollectionSystemsFRANCESAS"},
	{1602, "BluetrumTechnologyCo.,Ltd"},
	{1603, "makitacorporation"},
	{1604, "ApogeeInstruments"},
	{1605, "BM3"},
	{1606, "SGVGroupHoldingGmbH&Co.KG"},
	{1607, "MED-EL"},
	{1608, "UltuneTechnologies"},
	{1609, "RyeexTechnologyCo.,Ltd."},
	{1610, "OpenResearchInstitute,Inc."},
	{1611, "Scale-Tec,Ltd"},
	{1612, "ZumtobelGroupAG"},
	{1613, "iLOQOy"},
	{1614, "KRUXWorksTechnologiesPrivateLimited"},
	{1615, "DigitalMatterPtyLtd"},
	{1616, "Coravin,Inc."},
	{1617, "StasisLabs,Inc."},
	{1618, "ITZInnovations-undTechnologiezentrumGmbH"},
	{1619, "MeggittSA"},
	{1620, "LedlenserGmbH&Co.KG"},
	{1621, "RenishawPLC"},
	{1622, "ZhuHaiAdvanProTechnologyCompanyLimited"},
	{1623, "MeshtronixLimited"},
	{1624, "PayexNorgeAS"},
	{1625, "UnSeenTechnologiesOy"},
	{1626, "ZoundIndustriesInternationalAB"},
	{1627, "SesamSolutionsBV"},
	{1628, "PixArtImagingInc."},
	{1629, "PanduitCorp."},
	{1630, "AloAB"},
	{1631, "RicohCompanyLtd"},
	{1632, "RTCIndustries,Inc."},
	{1633, "ModeLightingLimited"},
	{1634, "ParticleIndustries,Inc."},
	{1635, "AdvancedTelemetrySystems,Inc."},
	{1636, "RHATECHNOLOGIESLTD"},
	{1637, "PureInternationalLimited"},
	{1638, "WTOWerkzeug-EinrichtungenGmbH"},
	{1639, "SparkTechnologyLabsInc."},
	{1640, "BlebTechnologysrl"},
	{1641, "LivanovaUSA,Inc."},
	{1642, "BradyWorldwideInc."},
	{1643, "DewertOkinGmbH"},
	{1644, "ZtoveApS"},
	{1645, "VensoEcoSolutionsAB"},
	{1646, "EurotronikKranjd.o.o."},
	{1647, "HugTechnologyLtd"},
	{1648, "GemaSwitzerlandGmbH"},
	{1649, "BuzzProductsLtd."},
	{1650, "Kopi"},
	{1651, "InnovaIdeasLimited"},
	{1652, "BeSpoon"},
	{1653, "DecoEnterprises,Inc."},
	{1654, "ExpaiSolutionsPrivateLimited"},
	{1655, "InnovationFirst,Inc."},
	{1656, "SABIKOffshoreGmbH"},
	{1657, "4iiiiInnovationsInc."},
	{1658, "TheEnergyConservatory,Inc."},
	{1659, "I.FARM,INC."},
	{1660, "Tile,Inc."},
	{1661, "FormAthleticaInc."},
	{1662, "MbientLabInc"},
	{1663, "NETGRIDS.N.C.DIBISSOLIMATTEO,CAMPOREALESIMONE,TOGNETTIFEDERICO"},
	{1664, "MannkindCorporation"},
	{1665, "TradeFIDESa.s."},
	{1666, "PhotronLimited"},
	{1667, "EltakoGmbH"},
	{1668, "Dermalapps,LLC"},
	{1669, "GreenwaldIndustries"},
	{1670, "inQsCo.,Ltd."},
	{1671, "CherryGmbH"},
	{1672, "AmstedDigitalSolutionsInc."},
	{1673, "Tacxb.v."},
	{1674, "RaytacCorporation"},
	{1675, "JiangsuTeranovoTechCo.,Ltd."},
	{1676, "ChangzhouSoundDragonElectronicsandAcousticsCo.,Ltd"},
	{1677, "JetBeepInc."},
	{1678, "RazerInc."},
	{1679, "JRMGroupLimited"},
	{1680, "EccrineSystems,Inc."},
	{1681, "CuriePointAB"},
	{1682, "GeorgFischerAG"},
	{1683, "Hach-Danaher"},
	{1684, "T&ALaboratoriesLLC"},
	{1685, "KokiHoldingsCo.,Ltd."},
	{1686, "GunakarPrivateLimited"},
	{1687, "StemcoProductsInc"},
	{1688, "WoodITSecurity,LLC"},
	{1689, "RandomLabSAS"},
	{1690, "Adero,Inc.(formerlyasTrackR,Inc.)"},
	{1691, "DragonchipLimited"},
	{1692, "NoomiAB"},
	{1693, "VakarosLLC"},
	{1694, "DeltaElectronics,Inc."},
	{1695, "FlowMotionTechnologiesAS"},
	{1696, "OBIQLocationTechnologyInc."},
	{1697, "CardoSystems,Ltd"},
	{1698, "GlobalworxGmbH"},
	{1699, "Nymbus,LLC"},
	{1700, "SanyoTechnoSolutionsTottoriCo.,Ltd."},
	{1701, "TEKZITELPTYLTD"},
	{1702, "RoambeeCorporation"},
	{1703, "ChipseaTechnologies(ShenZhen)Corp."},
	{1704, "GDMideaAir-ConditioningEquipmentCo.,Ltd."},
	{1705, "SoundmaxElectronicsLimited"},
	{1706, "ProdualOy"},
	{1707, "HMSIndustrialNetworksAB"},
	{1708, "IngchipsTechnologyCo.,Ltd."},
	{1709, "InnovaSeaSystemsInc."},
	{1710, "SenseQInc."},
	{1711, "ShoofTechnologies"},
	{1712, "BRKBrands,Inc."},
	{1713, "SimpliSafe,Inc."},
	{1714, "TussockInnovation2013Limited"},
	{1715, "TheHablabApS"},
	{1716, "SencilionOy"},
	{1717, "WabilogicLtd."},
	{1718, "SociometricSolutions,Inc."},
	{1719, "iCOGNIZEGmbH"},
	{1720, "ShadeCraft,Inc"},
	{1721, "BeflexInc."},
	{1722, "BeaconzoneLtd"},
	{1723, "LeaftronixAnalogicSolutionsPrivateLimited"},
	{1724, "TWSSrl"},
	{1725, "ABBOy"},
	{1726, "HitSeedOy"},
	{1727, "DelcomProductsInc."},
	{1728, "CAMES.p.A."},
	{1729, "Alarm.comHoldings,Inc"},
	{1730, "MeasurlogicInc."},
	{1731, "KingIElectronics.Co.,Ltd"},
	{1732, "DreamLabsGmbH"},
	{1733, "UrbanCompass,Inc"},
	{1734, "SimmTronicLimited"},
	{1735, "SomatixInc"},
	{1736, "Storz&BickelGmbH&Co.KG"},
	{1737, "MYLAPSB.V."},
	{1738, "ShenzhenZhongguangInfotechTechnologyDevelopmentCo.,Ltd"},
	{1739, "Dyeware,LLC"},
	{1740, "DongguanSmartActionTechnologyCo.,Ltd."},
	{1741, "DIGCorporation"},
	{1742, "FIOR&GENTZ"},
	{1743, "BelpartsN.V."},
	{1744, "EtekcityCorporation"},
	{1745, "MeyerSoundLaboratories,Incorporated"},
	{1746, "CeoTronicsAG"},
	{1747, "TriTeqLockandSecurity,LLC"},
	{1748, "DYNAKODETECHNOLOGYPRIVATELIMITED"},
	{1749, "SensirionAG"},
	{1750, "JCTHealthcarePtyLtd"},
	{1751, "FUBAAutomotiveElectronicsGmbH"},
	{1752, "AWCompany"},
	{1753, "ShanghaiMountainViewSiliconCo.,Ltd."},
	{1754, "ZliideTechnologiesApS"},
	{1755, "AutomaticLabs,Inc."},
	{1756, "IndustrialNetworkControls,LLC"},
	{1757, "IntellithingsLtd."},
	{1758, "Navcast,Inc."},
	{1759, "HubbellLighting,Inc."},
	{1760, "Avaya"},
	{1761, "MilestoneAVTechnologiesLLC"},
	{1762, "AlangoTechnologiesLtd"},
	{1763, "SpinlockLtd"},
	{1764, "Aluna"},
	{1765, "OPTEXCO.,LTD."},
	{1766, "NIHONDENGYOKOUSAKU"},
	{1767, "VELUXA/S"},
	{1768, "AlmendoTechnologiesGmbH"},
	{1769, "ZmartfunElectronics,Inc."},
	{1770, "SafeLineSwedenAB"},
	{1771, "HoustonRadarLLC"},
	{1772, "Sigur"},
	{1773, "JNeadesLtd"},
	{1774, "AvantisSystemsLimited"},
	{1775, "ALCARECo.,Ltd."},
	{1776, "ChargyTechnologies,SL"},
	{1777, "ShibutaniCo.,Ltd."},
	{1778, "TrapperDataAB"},
	{1779, "AlfredInternationalInc."},
	{1780, "NearFieldSolutionsLtd"},
	{1781, "VigilTechnologiesInc."},
	{1782, "VituloPlusBV"},
	{1783, "WILKASchliesstechnikGmbH"},
	{1784, "BodyPlusTechnologyCo.,Ltd"},
	{1785, "happybrushGmbH"},
	{1786, "EnequiAB"},
	{1787, "SartoriusAG"},
	{1788, "TomCommunicationIndustrialCo.,Ltd."},
	{1789, "ESSEmbeddedSystemSolutionsInc."},
	{1790, "MahrGmbH"},
	{1791, "RedpineSignalsInc"},
	{1792, "TraqFreqLLC"},
	{1793, "PAFERSTECH"},
	{1794, "Akcijusabiedriba\"SAFTEHNIKA\""},
	{1795, "BeijingJingdongCenturyTradingCo.,Ltd."},
	{1796, "JBXDesignsInc."},
	{1797, "ABElectrolux"},
	{1798, "WernhervonBraunCenterforASdvancedResearch"},
	{1799, "EssityHygieneandHealthAktiebolag"},
	{1800, "BeInteractiveCo.,Ltd"},
	{1801, "CarewearCorp."},
	{1802, "HufHlsbeck&FrstGmbH&Co.KG"},
	{1803, "ElementProducts,Inc."},
	{1804, "BeijingWinnerMicroelectronicsCo.,Ltd"},
	{1805, "SmartSnuggPtyLtd"},
	{1806, "FiveCoSarl"},
	{1807, "CaliforniaThingsInc."},
	{1808, "AudiodoAB"},
	{1809, "ABAXAS"},
	{1810, "BullGroupCompanyLimited"},
	{1811, "RespiriLimited"},
	{1812, "MindPeaceSafetyLLC"},
	{1813, "VgyanSolutions"},
	{1814, "Altonics"},
	{1815, "iQsquareBV"},
	{1816, "IDIBAIXenginneering"},
	{1817, "ECSG"},
	{1818, "REVSMARTWEARABLEHKCOLTD"},
	{1819, "Precor"},
	{1820, "F5Sports,Inc"},
	/* 1821 - 65534 reserved */
	{65535, "test"},
	{0, NULL}};

static const value_string sco_packet[] = {
	{0, "HV1"},
	{1, "HV2"},
	{2, "HV3"},
	/* 3 - 255 reserved */
	{0, NULL}};

static const value_string air_mode[] = {
	{0, "mu-law log"},
	{1, "A-law log"},
	{2, "CVSD"},
	{3, "transparent data"},
	/* 4 - 255 reserved */
	{0, NULL}};

static const value_string paging_scheme[] = {
	{0, "mandatory scheme"},
	/* 1 - 255 reserved */
	{0, NULL}};

static const value_string paging_scheme_settings[] = {
	/* for mandatory scheme: */
	{0, "R0"},
	{1, "R1"},
	{2, "R2"},
	/* 3 - 255 reserved */
	{0, NULL}};

static const value_string afh_mode[] = {
	{0, "AFH disabled"},
	{1, "AFH enabled"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string features_page[] = {
	{0, "standard features"},
	{1, "extended features 64-67"},
	{2, "extended features 128-140"},
	/* 3 - 255 other feature pages */
	{0, NULL}};

static const value_string packet_type_table[] = {
	{0, "1 Mbps only"},
	{1, "2/3 Mbps"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string negotiation_state[] = {
	{0, "Initiate negotiation"},
	{1, "The latest received set of negotiable parameters were possible but these parameters are preferred."},
	{2, "The latest received set of negotiable parameters would cause a reserved slot violation."},
	{3, "The latest received set of negotiable parameters would cause a latency violation."},
	{4, "The latest received set of negotiable parameters are not supported."},
	/* 5 - 255 reserved */
	{0, NULL}};

static const value_string afh_reporting_mode[] = {
	{0, "AFH reporting disabled"},
	{1, "AFH reporting enabled"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string io_capabilities[] = {
	{0, "Display Only"},
	{1, "Display Yes/No"},
	{2, "Keyboard Only"},
	{3, "No Input/No Output"},
	/* 4 - 255 reserved */
	{0, NULL}};

static const value_string oob_auth_data[] = {
	{0, "No OOB Authentication Data received"},
	{1, "OOB Authentication Data received"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string auth_requirements[] = {
	{0x00, "MITM Protection Not Required - No Bonding"},
	{0x01, "MITM Protection Required - No Bonding"},
	{0x02, "MITM Protection Not Required - Dedicated Bonding"},
	{0x03, "MITM Protection Required - Dedicated Bonding"},
	{0x04, "MITM Protection Not Required - General Bonding"},
	{0x05, "MITM Protection Required - General Bonding"},
	/* 0x06 - 0xff reserved */
	{0, NULL}};

static const value_string power_adjust_req[] = {
	{0, "decrement power one step"},
	{1, "increment power one step"},
	{2, "increase to maximum power"},
	/* 3 - 255 reserved */
	{0, NULL}};

static const value_string power_adjust_res[] = {
	{0, "not supported"},
	{1, "changed one step (not min or max)"},
	{2, "max power"},
	{3, "min power"},
	/* 4 - 255 reserved */
	{0, NULL}};

static const value_string test_scenario[] = {
	{0, "Pause Test Mode"},
	{1, "Transmitter test - 0 pattern"},
	{2, "Transmitter test - 1 pattern"},
	{3, "Transmitter test - 1010 pattern"},
	{4, "Pseudorandom bit sequence"},
	{5, "Closed Loop Back - ACL packets"},
	{6, "Closed Loop Back - Synchronous packets"},
	{7, "ACL Packets without whitening"},
	{8, "Synchronous Packets without whitening"},
	{9, "Transmitter test - 1111 0000 pattern"},
	/* 10 - 254 reserved */
	{255, "Exit Test Mode"},
	{0, NULL}};

static const value_string hopping_mode[] = {
	{0, "RX/TX on single frequency"},
	{1, "Normal hopping"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string power_control_mode[] = {
	{0, "fixed TX output power"},
	{1, "adaptive power control"},
	/* 2 - 255 reserved */
	{0, NULL}};

static const value_string esco_packet_type[] = {
	{0x00, "NULL/POLL"},
	{0x07, "EV3"},
	{0x0C, "EV4"},
	{0x0D, "EV5"},
	{0x26, "2-EV3"},
	{0x2C, "2-EV5"},
	{0x37, "3-EV3"},
	{0x3D, "3-EV5"},
	/* other values reserved */
	{0, NULL}};

static const value_string notification_value[] = {
	{0, "passkey entry started"},
	{1, "passkey digit entered"},
	{2, "passkey digit erased"},
	{3, "passkey cleared"},
	{4, "passkey entry completed"},
	/* 5 - 255 reserved */
	{0, NULL}};

/* initialize the subtree pointers */
static gint ett_lmp = -1;
static gint ett_lmp_pwradjres = -1;
static gint ett_lmp_rate = -1;
static gint ett_lmp_timectrl = -1;
static gint ett_lmp_features = -1;
static gint ett_lmp_featuresext = -1;

/* LMP PDUs with short opcodes */
void dissect_vsc(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	/* TODO implement Broadcom VSC opcodes here:
	 * 0: Features Request
	 * 1: Features Response
	 * 	0 and 1: Features: 0x%02X%02X%02X%02X
	 * 2: Not Accept
	 * 	Rejection BPCS Opcode: 0x%02X
	 * 	Rejection Error Code: 0x%02X
	 * 3: BFC Suspend
	 * 4: BFC Resume Request
	 * 	if receive direction:
	 * 		BFC Resume Response (instead)
	 * 	BFC Link State: 0x%02X
	 * 	BFC Stack State: 0x%02X
	 * 	BFC Reserved: 0x%02X\
	 * 5: BFC Accept
	 * 	BPCS Accepted Opcode: 0x%02X
	 * 	
	 */
}

void dissect_name_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_nameoffset, tvb, offset, 1, ENC_NA);
}

void dissect_name_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);

	proto_tree_add_item(tree, hf_lmp_nameoffset, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_namelen, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_namefrag, tvb, offset, 14, ENC_ASCII | ENC_NA);
}

void dissect_accepted(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_NA);
}

void dissect_not_accepted(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void dissect_clkoffset_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_clkoffset_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_clkoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_detach(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void dissect_in_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void dissect_comb_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void dissect_unit_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_key, tvb, offset, 16, ENC_NA);
}

void dissect_au_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void dissect_sres(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 4);

	proto_tree_add_item(tree, hf_lmp_authres, tvb, offset, 4, ENC_NA);
}

void dissect_temp_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void dissect_temp_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_key, tvb, offset, 16, ENC_NA);
}

void dissect_encryption_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_cryptmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_encryption_key_size_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);
    proto_tree_add_item(tree, hf_lmp_keysz, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    int ret = tvb_get_guint8(tvb, offset);
    DISSECTOR_ASSERT(ret >= 7);
}

void dissect_start_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void dissect_stop_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_switch_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 4);

	proto_tree_add_item(tree, hf_lmp_swinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void dissect_hold(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_htime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_hinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void dissect_hold_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_htime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_hinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void dissect_sniff_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 10);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 9);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_tsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffatt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffto, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_unsniff_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_park_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_tb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_deltab, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_araddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_nbsleep, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dbsleep, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_daccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_taccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_naccslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_npoll, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_accscheme, tvb, offset, 1, ENC_NA);
}

void dissect_set_broadcast_scan_window(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present)
	{
		DISSECTOR_ASSERT(len == 6);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 4);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
	else
	{
		DISSECTOR_ASSERT(len == 4);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);
	}

	proto_tree_add_item(tree, hf_lmp_bsw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_modify_beacon(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present)
	{
		DISSECTOR_ASSERT(len == 13);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 11);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
	else
	{
		DISSECTOR_ASSERT(len == 11);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 9);
	}

	proto_tree_add_item(tree, hf_lmp_tb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_deltab, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_daccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_taccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_naccslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_npoll, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_accscheme, tvb, offset, 1, ENC_NA);
}

void dissect_unpark_bd_addr_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;
	proto_item;

	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present)
	{
		DISSECTOR_ASSERT(len == 17);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 15);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
	else
	{
		DISSECTOR_ASSERT(len == 15);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 13);
	}

	proto_tree_add_item(tree, hf_lmp_ltaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_bdaddr1, tvb, offset, 6, ENC_LITTLE_ENDIAN);
	offset += 6;

	proto_tree_add_item(tree, hf_lmp_bdaddr2, tvb, offset, 6, ENC_LITTLE_ENDIAN);
	offset += 6;
}

void dissect_unpark_pm_addr_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present)
	{
		DISSECTOR_ASSERT(len == 15);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 13);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
	else
	{
		DISSECTOR_ASSERT(len == 13);
		DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 11);
	}

	proto_tree_add_item(tree, hf_lmp_ltaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_incr_power_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);

	/* skipping one byte "for future use" */
}

void dissect_decr_power_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);

	/* skipping one byte "for future use" */
}

void dissect_max_power(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_min_power(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_auto_rate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_preferred_rate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	proto_item *rate_item;
	proto_tree *rate_tree;

	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	rate_item = proto_tree_add_item(tree, hf_lmp_rate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	rate_tree = proto_item_add_subtree(rate_item, ett_lmp_rate);

	proto_tree_add_item(rate_tree, hf_lmp_rate_fec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_edrsize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_version_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 6);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_version_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 6);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_features_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 8);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_features,
						   ett_lmp_features, features_fields, ENC_LITTLE_ENDIAN);
}

void dissect_features_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 8);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_features,
						   ett_lmp_features, features_fields, ENC_LITTLE_ENDIAN);
}

void dissect_quality_of_service(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_pollintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nbc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_quality_of_service_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_pollintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nbc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_sco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_scohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_tsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_scopkt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_remove_sco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_scohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void dissect_max_slot(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_maxslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_max_slot_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_maxslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_timing_accuracy_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_timing_accuracy_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_drift, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_jitter, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_setup_complete(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_use_semi_permanent_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_host_connection_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_slot_offset(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 8);

	proto_tree_add_item(tree, hf_lmp_slotoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_bdaddr, tvb, offset, 6, ENC_LITTLE_ENDIAN);
}

void dissect_page_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_pagesch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pssettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_page_scan_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_pagesch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pssettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_supervision_timeout(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_suptimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_test_activate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_test_control(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 10);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 9);

	proto_tree_add_uint(tree, hf_lmp_testscen, tvb, offset, 1, tvb_get_guint8(tvb, offset) ^ 0x55);
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_hopmode, tvb, offset, 1, tvb_get_guint8(tvb, offset) ^ 0x55);
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_txfreq, tvb, offset, 1, (tvb_get_guint8(tvb, offset) ^ 0x55) + 2402); //MHz
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_rxfreq, tvb, offset, 1, (tvb_get_guint8(tvb, offset) ^ 0x55) + 2402);
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_pcmode, tvb, offset, 1, tvb_get_guint8(tvb, offset) ^ 0x55);
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_pollper, tvb, offset, 1, (tvb_get_guint8(tvb, offset) ^ 0x55) * 1.25); //ms
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_pkttype, tvb, offset, 1, tvb_get_guint8(tvb, offset) ^ 0x55);
	offset += 1;

	proto_tree_add_uint(tree, hf_lmp_testlen, tvb, offset, 2, tvb_get_bits16(tvb, offset * 8, 16, ENC_LITTLE_ENDIAN) ^ 0x5555);
}

void dissect_encryption_key_size_mask_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void dissect_encryption_key_size_mask_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_ksmask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_set_afh(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 16);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 15);

	proto_tree_add_item(tree, hf_lmp_afhinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_lmp_afhmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_afhchmap, tvb, offset, 10, ENC_NA);
}

void dissect_encapsulated_header(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_encmaj, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_encmin, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_enclen, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_encapsulated_payload(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_encdata, tvb, offset, 16, ENC_NA);
}

void dissect_simple_pairing_confirm(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_commit, tvb, offset, 16, ENC_NA);
}

void dissect_simple_pairing_number(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_nonce, tvb, offset, 16, ENC_NA);
}

void dissect_dhkey_check(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_confirm, tvb, offset, 16, ENC_NA);
}

/* LMP PDUs with extended opcodes */

void dissect_accepted_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_eopinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_not_accepted_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_eopinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void dissect_features_req_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int feat_page = 0;

	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_fpage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	feat_page = tvb_get_guint8(tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maxsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (feat_page == 1)
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_featuresext,
							   ett_lmp_featuresext, extfeatures1_fields, ENC_LITTLE_ENDIAN);
	}
	else
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_featuresext,
							   ett_lmp_featuresext, extfeatures2_fields, ENC_LITTLE_ENDIAN);
	}
}

void dissect_features_res_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int feat_page = 0;
	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_fpage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	feat_page = tvb_get_guint8(tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maxsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (feat_page == 1)
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_featuresext,
							   ett_lmp_featuresext, extfeatures1_fields, ENC_LITTLE_ENDIAN);
	}
	else
	{
		proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_featuresext,
							   ett_lmp_featuresext, extfeatures2_fields, ENC_LITTLE_ENDIAN);
	}
}

void dissect_packet_type_table_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_pkttypetbl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_esco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 16);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 14);

	proto_tree_add_item(tree, hf_lmp_escohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escoltaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
						   ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_desco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_tesco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_wesco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escotypems, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escotypesm, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escolenms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_escolensm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_negstate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_remove_esco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_escohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void dissect_channel_classification_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_afhrptmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_afhminintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_afhmaxintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_channel_classification(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_afhclass, tvb, offset, 10, ENC_NA);
}

void dissect_sniff_subrating_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 7);

	proto_tree_add_item(tree, hf_lmp_maxss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_minsmt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffsi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_sniff_subrating_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 7);

	proto_tree_add_item(tree, hf_lmp_maxss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_minsmt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffsi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void dissect_pause_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_resume_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_io_capability_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_iocaps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_oobauthdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_authreqs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_io_capability_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_iocaps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_oobauthdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_authreqs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_numeric_comparison_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_passkey_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_oob_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_keypress_notification(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_nottype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_power_control_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_pwradjreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_power_control_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	proto_item *pa_item;
	proto_tree *pa_tree;

	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_reported_length_remaining(tvb, offset) >= 1);

	pa_item = proto_tree_add_item(tree, hf_lmp_pwradjres, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	pa_tree = proto_item_add_subtree(pa_item, ett_lmp_pwradjres);

	proto_tree_add_item(pa_tree, hf_lmp_pwradj_gfsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(pa_tree, hf_lmp_pwradj_dqpsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(pa_tree, hf_lmp_pwradj_8dpsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void dissect_ping_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void dissect_ping_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

/* Link Manager Protocol */
static int
dissect_btbrlmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *lmp_item;
	proto_tree *lmp_tree;
	int offset;
	int len;
	int op;	 /* opcode */
	int eop; /* extended opcode */

	// struct timespec start_time;
	// struct timespec end_time;
	// clock_gettime(CLOCK_MONOTONIC, &start_time);

	offset = 0;
	len = tvb_reported_length(tvb);

	DISSECTOR_ASSERT(len >= 1);

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LMP");

	/* clear the info column first just in case of type fetching failure. */
	col_clear(pinfo->cinfo, COL_INFO);
	// printf("pinfo->p2p_dir:%d\n",pinfo->p2p_dir);
	switch (pinfo->p2p_dir)
	{
	case P2P_DIR_SENT:
		col_set_str(pinfo->cinfo, COL_INFO, "TX --> ");
		break;
	case P2P_DIR_RECV:
		col_set_str(pinfo->cinfo, COL_INFO, "RX <-- ");
		break;
	default:
		break;
	}

	op = tvb_get_guint8(tvb, offset) >> 1;

	if (op == LMP_ESCAPE_4)
	{
		DISSECTOR_ASSERT(len >= 2);

		eop = tvb_get_guint8(tvb, offset + 1);

		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(eop, ext_opcode, "Unknown Extended Opcode (%d)"));
	}
	else
	{
		col_append_str(pinfo->cinfo, COL_INFO, val_to_str(op, opcode, "Unknown Opcode (%d)"));
	}

	/* see if we are being asked for details */
	if (!tree)
		return tvb_reported_length(tvb);

	lmp_item = proto_tree_add_item(tree, proto_btbrlmp, tvb, offset, -1, ENC_NA);
	lmp_tree = proto_item_add_subtree(lmp_item, ett_lmp);

	proto_tree_add_item(lmp_tree, hf_lmp_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(lmp_tree, hf_lmp_op, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	switch (op)
	{
	case LMP_NAME_REQ:
		dissect_name_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_NAME_RES:
		dissect_name_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_ACCEPTED:
		dissect_accepted(lmp_tree, tvb, offset, len);
		break;
	case LMP_NOT_ACCEPTED:
		dissect_not_accepted(lmp_tree, tvb, offset, len);
		break;
	case LMP_CLKOFFSET_REQ:
		dissect_clkoffset_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_CLKOFFSET_RES:
		dissect_clkoffset_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_DETACH:
		dissect_detach(lmp_tree, tvb, offset, len);
		break;
	case LMP_IN_RAND:
		dissect_in_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_COMB_KEY:
		dissect_comb_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNIT_KEY:
		dissect_unit_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_AU_RAND:
		dissect_au_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_SRES:
		dissect_sres(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEMP_RAND:
		dissect_temp_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEMP_KEY:
		dissect_temp_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_MODE_REQ:
		dissect_encryption_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_REQ:
		dissect_encryption_key_size_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_START_ENCRYPTION_REQ:
		dissect_start_encryption_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_STOP_ENCRYPTION_REQ:
		dissect_stop_encryption_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SWITCH_REQ:
		dissect_switch_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOLD:
		dissect_hold(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOLD_REQ:
		dissect_hold_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SNIFF_REQ:
		dissect_sniff_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNSNIFF_REQ:
		dissect_unsniff_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_PARK_REQ:
		dissect_park_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SET_BROADCAST_SCAN_WINDOW:
		dissect_set_broadcast_scan_window(lmp_tree, tvb, offset, len);
		break;
	case LMP_MODIFY_BEACON:
		dissect_modify_beacon(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNPARK_BD_ADDR_REQ:
		dissect_unpark_bd_addr_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNPARK_PM_ADDR_REQ:
		dissect_unpark_pm_addr_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_INCR_POWER_REQ:
		dissect_incr_power_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_DECR_POWER_REQ:
		dissect_decr_power_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_POWER:
		dissect_max_power(lmp_tree, tvb, offset, len);
		break;
	case LMP_MIN_POWER:
		dissect_min_power(lmp_tree, tvb, offset, len);
		break;
	case LMP_AUTO_RATE:
		dissect_auto_rate(lmp_tree, tvb, offset, len);
		break;
	case LMP_PREFERRED_RATE:
		dissect_preferred_rate(lmp_tree, tvb, offset, len);
		break;
	case LMP_VERSION_REQ:
		dissect_version_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_VERSION_RES:
		dissect_version_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_FEATURES_REQ:
		dissect_features_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_FEATURES_RES:
		dissect_features_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_QUALITY_OF_SERVICE:
		dissect_quality_of_service(lmp_tree, tvb, offset, len);
		break;
	case LMP_QUALITY_OF_SERVICE_REQ:
		dissect_quality_of_service_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SCO_LINK_REQ:
		dissect_sco_link_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_REMOVE_SCO_LINK_REQ:
		dissect_remove_sco_link_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_SLOT:
		dissect_max_slot(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_SLOT_REQ:
		dissect_max_slot_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_TIMING_ACCURACY_REQ:
		dissect_timing_accuracy_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_TIMING_ACCURACY_RES:
		dissect_timing_accuracy_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_SETUP_COMPLETE:
		dissect_setup_complete(lmp_tree, tvb, offset, len);
		break;
	case LMP_USE_SEMI_PERMANENT_KEY:
		dissect_use_semi_permanent_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOST_CONNECTION_REQ:
		dissect_host_connection_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SLOT_OFFSET:
		dissect_slot_offset(lmp_tree, tvb, offset, len);
		break;
	case LMP_PAGE_MODE_REQ:
		dissect_page_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_PAGE_SCAN_MODE_REQ:
		dissect_page_scan_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SUPERVISION_TIMEOUT:
		dissect_supervision_timeout(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEST_ACTIVATE:
		dissect_test_activate(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEST_CONTROL:
		dissect_test_control(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_MASK_REQ:
		dissect_encryption_key_size_mask_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_MASK_RES:
		dissect_encryption_key_size_mask_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_SET_AFH:
		dissect_set_afh(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCAPSULATED_HEADER:
		dissect_encapsulated_header(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCAPSULATED_PAYLOAD:
		dissect_encapsulated_payload(lmp_tree, tvb, offset, len);
		break;
	case LMP_SIMPLE_PAIRING_CONFIRM:
		dissect_simple_pairing_confirm(lmp_tree, tvb, offset, len);
		break;
	case LMP_SIMPLE_PAIRING_NUMBER:
		dissect_simple_pairing_number(lmp_tree, tvb, offset, len);
		break;
	case LMP_DHKEY_CHECK:
		dissect_dhkey_check(lmp_tree, tvb, offset, len);
		break;
	/* 
	   If the initial 7 bits 
	   of the opcode have one of the special escape values 124-127 then an 
	   additional byte of opcode is located in the second byte of the payload 
	*/
	case LMP_ESCAPE_1:
		break;
	case LMP_ESCAPE_2:
		break;
	case LMP_ESCAPE_3:
		break;
	case LMP_ESCAPE_4:
		/* extended opcode */
		DISSECTOR_ASSERT(len >= 2);
		proto_tree_add_item(lmp_tree, hf_lmp_eop, tvb, offset, 1, ENC_NA);
		offset += 1;

		switch (eop)
		{
		case LMP_ACCEPTED_EXT:
			dissect_accepted_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_NOT_ACCEPTED_EXT:
			dissect_not_accepted_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_FEATURES_REQ_EXT:
			dissect_features_req_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_FEATURES_RES_EXT:
			dissect_features_res_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_PACKET_TYPE_TABLE_REQ:
			dissect_packet_type_table_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_ESCO_LINK_REQ:
			dissect_esco_link_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_REMOVE_ESCO_LINK_REQ:
			dissect_remove_esco_link_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_CHANNEL_CLASSIFICATION_REQ:
			dissect_channel_classification_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_CHANNEL_CLASSIFICATION:
			dissect_channel_classification(lmp_tree, tvb, offset, len);
			break;
		case LMP_SNIFF_SUBRATING_REQ:
			dissect_sniff_subrating_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_SNIFF_SUBRATING_RES:
			dissect_sniff_subrating_res(lmp_tree, tvb, offset, len);
			break;
		case LMP_PAUSE_ENCRYPTION_REQ:
			dissect_pause_encryption_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_RESUME_ENCRYPTION_REQ:
			dissect_resume_encryption_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_IO_CAPABILITY_REQ:
			dissect_io_capability_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_IO_CAPABILITY_RES:
			dissect_io_capability_res(lmp_tree, tvb, offset, len);
			break;
		case LMP_NUMERIC_COMPARISON_FAILED:
			dissect_numeric_comparison_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_PASSKEY_FAILED:
			dissect_passkey_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_OOB_FAILED:
			dissect_oob_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_KEYPRESS_NOTIFICATION:
			dissect_keypress_notification(lmp_tree, tvb, offset, len);
			break;
		case LMP_POWER_CONTROL_REQ:
			dissect_power_control_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_POWER_CONTROL_RES:
			dissect_power_control_res(lmp_tree, tvb, offset, len);
			break;
		case LMP_PING_REQ:
			dissect_ping_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_PING_RES:
			dissect_ping_res(lmp_tree, tvb, offset, len);
			break;
		default:
			break;
		}
	default:
		break;
	}

	// clock_gettime(CLOCK_MONOTONIC, &end_time);
	// long measured_latency_ns = ((end_time.tv_sec - start_time.tv_sec) * 1000000000UL) + (end_time.tv_nsec - start_time.tv_nsec) / 1000;
	// printf("lmp=%ld\n", measured_latency_ns);

	/* Return the amount of data this dissector was able to dissect */
	return tvb_reported_length(tvb);
};

/* register the protocol with Wireshark */
void proto_register_btbrlmp(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{&hf_lmp_accscheme,
		 {"Access Scheme", "btbrlmp.accscheme",
		  FT_UINT8, BASE_DEC, VALS(access_scheme), 0xf0,
		  NULL, HFILL}},
		{&hf_lmp_afhchmap,
		 {"AFH Channel Map", "btbrlmp.afhchmap",
		  /* could break out individual channels but long */
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Adaptive Frequency Hopping Channel Map", HFILL}},
		{&hf_lmp_afhclass,
		 {"AFH Channel Classification", "btbrlmp.afhclass",
		  /* could break out individual channels but long */
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Adaptive Frequency Hopping Channel Classification", HFILL}},
		{&hf_lmp_afhinst,
		 {"AFH Instant", "btbrlmp.afhinst",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Adaptive Frequency Hopping Instant (slot)", HFILL}},
		{&hf_lmp_afhmaxintvl,
		 {"AFH Max Interval", "btbrlmp.maxintvl",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Adaptive Maximum Interval in slots", HFILL}},
		{&hf_lmp_afhminintvl,
		 {"AFH Min Interval", "btbrlmp.minintvl",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Adaptive Minimum Interval in slots", HFILL}},
		{&hf_lmp_afhmode,
		 {"AFH Mode", "btbrlmp.afhmode",
		  FT_UINT8, BASE_DEC, VALS(afh_mode), 0x0,
		  "Adaptive Frequency Hopping Mode", HFILL}},
		{&hf_lmp_afhrptmode,
		 {"AFH Reporting Mode", "btbrlmp.afhrptmode",
		  FT_UINT8, BASE_DEC, VALS(afh_reporting_mode), 0x0,
		  "Adaptive Frequency Hopping Reporting Mode", HFILL}},
		{&hf_lmp_airmode,
		 {"Air Mode", "btbrlmp.airmode",
		  FT_UINT8, BASE_HEX, VALS(air_mode), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_araddr,
		 {"AR_ADDR", "btbrlmp.araddr",
		  FT_UINT8, BASE_HEX, NULL, 0xfe,
		  NULL, HFILL}},
		{&hf_lmp_authreqs,
		 {"Authentication Requirements", "btbrlmp.authreqs",
		  FT_UINT8, BASE_HEX, VALS(auth_requirements), 0x00,
		  NULL, HFILL}},
		{&hf_lmp_authres,
		 {"Authentication Response", "btbrlmp.authres",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_bdaddr,
		 {"BD_ADDR", "btbrlmp.bdaddr",
		  FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
		  NULL, HFILL}},
		{&hf_lmp_bdaddr1,
		 {"BD_ADDR 1", "btbrlmp.bdaddr",
		  FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
		  NULL, HFILL}},
		{&hf_lmp_bdaddr2,
		 {"BD_ADDR2", "btbrlmp.bdaddr",
		  FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
		  "BD_ADDR 2", HFILL}},
		{&hf_lmp_bsw,
		 {"Broadcast Scan Window", "btbrlmp.bsw",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Broadcast Scan Window in slots", HFILL}},
		{&hf_lmp_clkoffset,
		 {"Clock Offset", "btbrlmp.clkoffset",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Clock Offset in units of 1.25 ms", HFILL}},
		{&hf_lmp_commit,
		 {"Commitment Value", "btbrlmp.commit",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_confirm,
		 {"Confirmation Value", "btbrlmp.confirm",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_compid,
		 {"Company ID", "btbrlmp.compid",
		  FT_UINT16, BASE_DEC, VALS(compid), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_cryptmode,
		 {"Encryption Mode", "btbrlmp.cryptmode",
		  FT_UINT8, BASE_DEC, VALS(encryption_mode), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_daccess,
		 {"Daccess", "btbrlmp.daccess",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Daccess in slots", HFILL}},
		{&hf_lmp_db,
		 {"Db", "btbrlmp.db",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Db in slots", HFILL}},
		{&hf_lmp_dbsleep,
		 {"Dbsleep", "btbrlmp.dbsleep",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_deltab,
		 {"Deltab", "btbrlmp.deltab",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Deltab in slots", HFILL}},
		{&hf_lmp_desco,
		 {"Desco", "btbrlmp.desco",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Desco in slots", HFILL}},
		{&hf_lmp_drift,
		 {"Drift", "btbrlmp.drift",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Drift in ppm", HFILL}},
		{&hf_lmp_dsco,
		 {"Dsco", "btbrlmp.dsco",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Dsco in slots", HFILL}},
		{&hf_lmp_dsniff,
		 {"Dsniff", "btbrlmp.dsniff",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Dsniff in slots", HFILL}},
		{&hf_lmp_encdata,
		 {"Encapsulated Data", "btbrlmp.encdata",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_enclen,
		 {"Encapsulated Length", "btbrlmp.enclen",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_encmaj,
		 {"Encapsulated Major Type", "btbrlmp.encmaj",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_encmin,
		 {"Encapsulated Minor Type", "btbrlmp.encmin",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_eop,
		 {"Extended Opcode", "btbrlmp.eop",
		  FT_UINT8, BASE_DEC, VALS(ext_opcode), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_eopinre,
		 {"In Response To", "btbrlmp.eopinre",
		  FT_UINT8, BASE_DEC, VALS(ext_opcode), 0x0,
		  "Extended Opcode this is in response to", HFILL}},
		{&hf_lmp_escolenms,
		 {"Packet Length M -> S", "btbrlmp.escolenms",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Packet Length in bytes Master to Slave", HFILL}},
		{&hf_lmp_escolensm,
		 {"Packet Length S -> M", "btbrlmp.escolensm",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Packet Length in bytes Slave to Master", HFILL}},
		{&hf_lmp_escotypems,
		 {"eSCO Packet Type M -> S", "btbrlmp.escotypems",
		  FT_UINT8, BASE_HEX, VALS(esco_packet_type), 0x0,
		  "eSCO Packet Type Master to Slave", HFILL}},
		{&hf_lmp_escotypesm,
		 {"eSCO Packet Type S -> M", "btbrlmp.escotypesm",
		  FT_UINT8, BASE_HEX, VALS(esco_packet_type), 0x0,
		  "eSCO Packet Type Slave to Master", HFILL}},
		{&hf_lmp_err,
		 {"Error Code", "btbrlmp.err",
		  FT_UINT8, BASE_HEX, VALS(error_code), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_escohdl,
		 {"eSCO Handle", "btbrlmp.escohdl",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_escoltaddr,
		 {"eSCO LT_ADDR", "btbrlmp.escoltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "eSCO Logical Transport Address", HFILL}},
		{&hf_lmp_features,
		 {"Features", "btbrlmp.features",
		  FT_UINT64, BASE_HEX, NULL, 0x0,
		  "Feature Mask", HFILL}},
		{&hf_lmp_feat_3slot,
		 {"3 slot packets", "btbrlmp.feat.3slot",
		  FT_BOOLEAN, 64, NULL, 0x1,
		  NULL, HFILL}},
		{&hf_lmp_feat_5slot,
		 {"5 slot packets", "btbrlmp.feat.5slot",
		  FT_BOOLEAN, 64, NULL, 0x1 << 1,
		  NULL, HFILL}},
		{&hf_lmp_feat_enc,
		 {"Encryption", "btbrlmp.feat.enc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 2,
		  NULL, HFILL}},
		{&hf_lmp_feat_slotoff,
		 {"Slot offset", "btbrlmp.feat.slotoff",
		  FT_BOOLEAN, 64, NULL, 0x1 << 3,
		  NULL, HFILL}},
		{&hf_lmp_feat_timacc,
		 {"Timing accuracy", "btbrlmp.feat.timacc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 4,
		  NULL, HFILL}},
		{&hf_lmp_feat_rolesw,
		 {"Role switch", "btbrlmp.feat.rolesw",
		  FT_BOOLEAN, 64, NULL, 0x1 << 5,
		  NULL, HFILL}},
		{&hf_lmp_feat_holdmo,
		 {"Hold mode", "btbrlmp.feat.holdmo",
		  FT_BOOLEAN, 64, NULL, 0x1 << 6,
		  NULL, HFILL}},
		{&hf_lmp_feat_sniffmo,
		 {"Sniff mode", "btbrlmp.feat.sniffmo",
		  FT_BOOLEAN, 64, NULL, 0x1 << 7,
		  NULL, HFILL}},
		{&hf_lmp_feat_res0,
		 {"Reserved", "btbrlmp.feat.res0",
		  FT_BOOLEAN, 64, NULL, 0x1 << 8,
		  NULL, HFILL}},
		{&hf_lmp_feat_pwrctlreq,
		 {"Power control requests", "btbrlmp.feat.pwrctlreq",
		  FT_BOOLEAN, 64, NULL, 0x1 << 9,
		  NULL, HFILL}},
		{&hf_lmp_feat_cqddr,
		 {"Channel quality driven data rate (CQDDR)", "btbrlmp.feat.cqddr",
		  FT_BOOLEAN, 64, NULL, 0x1 << 10,
		  NULL, HFILL}},
		{&hf_lmp_feat_sco,
		 {"SCO link", "btbrlmp.feat.sco",
		  FT_BOOLEAN, 64, NULL, 0x1 << 11,
		  NULL, HFILL}},
		{&hf_lmp_feat_hv2,
		 {"HV2 packets", "btbrlmp.feat.hv2",
		  FT_BOOLEAN, 64, NULL, 0x1 << 12,
		  NULL, HFILL}},
		{&hf_lmp_feat_hv3,
		 {"HV3 packets", "btbrlmp.feat.hv3",
		  FT_BOOLEAN, 64, NULL, 0x1 << 13,
		  NULL, HFILL}},
		{&hf_lmp_feat_mulaw,
		 {"u-law log synchronous data", "btbrlmp.feat.mulaw",
		  FT_BOOLEAN, 64, NULL, 0x1 << 14,
		  NULL, HFILL}},
		{&hf_lmp_feat_alaw,
		 {"A-law log synchronous data", "btbrlmp.feat.alaw",
		  FT_BOOLEAN, 64, NULL, 0x1 << 15,
		  NULL, HFILL}},
		{&hf_lmp_feat_cvsd,
		 {"CVSD synchronous data", "btbrlmp.feat.cvsd",
		  FT_BOOLEAN, 64, NULL, 0x1 << 16,
		  NULL, HFILL}},
		{&hf_lmp_feat_pagneg,
		 {"Paging parameter negotiation", "btbrlmp.feat.pagneg",
		  FT_BOOLEAN, 64, NULL, 0x1 << 17,
		  NULL, HFILL}},
		{&hf_lmp_feat_pwrctl,
		 {"Power control", "btbrlmp.feat.pwrctl",
		  FT_BOOLEAN, 64, NULL, 0x1 << 18,
		  NULL, HFILL}},
		{&hf_lmp_feat_transsync,
		 {"Transparent synchronous data", "btbrlmp.feat.transsync",
		  FT_BOOLEAN, 64, NULL, 0x1 << 19,
		  NULL, HFILL}},
		{&hf_lmp_feat_flowctl1,
		 {"Flow control lag (least significant bit)", "btbrlmp.feat.flowctl1",
		  FT_BOOLEAN, 64, NULL, 0x1 << 20,
		  NULL, HFILL}},
		{&hf_lmp_feat_flowctl2,
		 {"Flow control lag (middle bit)", "btbrlmp.feat.flowctl2",
		  FT_BOOLEAN, 64, NULL, 0x1 << 21,
		  NULL, HFILL}},
		{&hf_lmp_feat_flowctl3,
		 {"Flow control lag (most significant bit)", "btbrlmp.feat.flowctl3",
		  FT_BOOLEAN, 64, NULL, 0x1 << 22,
		  NULL, HFILL}},
		{&hf_lmp_feat_bcenc,
		 {"Broadcast Encryption", "btbrlmp.feat.bcenc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 23,
		  NULL, HFILL}},
		{&hf_lmp_feat_res1,
		 {"Reserved for future use", "btbrlmp.feat.res1",
		  FT_BOOLEAN, 64, NULL, 0x1 << 24,
		  NULL, HFILL}},
		{&hf_lmp_feat_acl2,
		 {"Enhanced Data Rate ACL 2 Mb/s mode", "btbrlmp.feat.acl2",
		  FT_BOOLEAN, 64, NULL, 0x1 << 25,
		  NULL, HFILL}},
		{&hf_lmp_feat_acl3,
		 {"Enhanced Data Rate ACL 3 Mb/s mode", "btbrlmp.feat.acl3",
		  FT_BOOLEAN, 64, NULL, 0x1 << 26,
		  NULL, HFILL}},
		{&hf_lmp_feat_eninq,
		 {"Enhanced inquiry scan", "btbrlmp.feat.eninq",
		  FT_BOOLEAN, 64, NULL, 0x1 << 27,
		  NULL, HFILL}},
		{&hf_lmp_feat_intinq,
		 {"Interlaced inquiry scan", "btbrlmp.feat.intinq",
		  FT_BOOLEAN, 64, NULL, 0x1 << 28,
		  NULL, HFILL}},
		{&hf_lmp_feat_intpag,
		 {"Interlaced page scan", "btbrlmp.feat.intpag",
		  FT_BOOLEAN, 64, NULL, 0x1 << 29,
		  NULL, HFILL}},
		{&hf_lmp_feat_rssiinq,
		 {"RSSI with inquiry results", "btbrlmp.feat.rssiinq",
		  FT_BOOLEAN, 64, NULL, 0x1 << 30,
		  NULL, HFILL}},
		{&hf_lmp_feat_ev3,
		 {"Extended SCO link (EV3 packets)", "btbrlmp.feat.ev3",
		  FT_BOOLEAN, 64, NULL, 0x80000000,
		  NULL, HFILL}},
		{&hf_lmp_feat_ev4,
		 {"EV4 packets", "btbrlmp.feat.ev4",
		  FT_BOOLEAN, 64, NULL, 0x100000000,
		  NULL, HFILL}},
		{&hf_lmp_feat_ev5,
		 {"EV5 packets", "btbrlmp.feat.ev5",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 1,
		  NULL, HFILL}},
		{&hf_lmp_feat_res2,
		 {"Reserved", "btbrlmp.feat.res2",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 2,
		  NULL, HFILL}},
		{&hf_lmp_feat_afhcapsl,
		 {"AFH capable slave", "btbrlmp.feat.afhcapsl",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 3,
		  NULL, HFILL}},
		{&hf_lmp_feat_afhclasl,
		 {"AFH classification slave", "btbrlmp.feat.afhclasl",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 4,
		  NULL, HFILL}},
		{&hf_lmp_feat_bredrnotsup,
		 {"BR/EDR Not Supported", "btbrlmp.feat.bredrnotsup",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 5,
		  NULL, HFILL}},
		{&hf_lmp_feat_lesup,
		 {"LE Supported (Controller)", "btbrlmp.feat.lesup",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 6,
		  NULL, HFILL}},
		{&hf_lmp_feat_3slotenh,
		 {"3-slot Enhanced Data Rate ACL packets", "btbrlmp.feat.3slotenh",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 7,
		  NULL, HFILL}},
		{&hf_lmp_feat_5slotenh,
		 {"5-slot Enhanced Data Rate ACL packets", "btbrlmp.feat.5slotenh",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 8,
		  NULL, HFILL}},
		{&hf_lmp_feat_sniffsubr,
		 {"Sniff subrating", "btbrlmp.feat.sniffsubr",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 9,
		  NULL, HFILL}},
		{&hf_lmp_feat_pauseenc,
		 {"Pause encryption", "btbrlmp.feat.pauseenc",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 10,
		  NULL, HFILL}},
		{&hf_lmp_feat_afhcapma,
		 {"AFH capable master", "btbrlmp.feat.afhcapma",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 11,
		  NULL, HFILL}},
		{&hf_lmp_feat_afhclama,
		 {"AFH classification master", "btbrlmp.feat.afhclama",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 12,
		  NULL, HFILL}},
		{&hf_lmp_feat_esco2,
		 {"Enhanced Data Rate eSCO 2 Mb/s mode", "btbrlmp.feat.esco2",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 13,
		  NULL, HFILL}},
		{&hf_lmp_feat_esco3,
		 {"Enhanced Data Rate eSCO 3 Mb/s mode", "btbrlmp.feat.esco3",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 14,
		  NULL, HFILL}},
		{&hf_lmp_feat_3slotenhesco,
		 {"3-slot Enhanced Data Rate eSCO packets", "btbrlmp.feat.3slotenhesco",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 15,
		  NULL, HFILL}},
		{&hf_lmp_feat_extinqres,
		 {"Extended Inquiry Response", "btbrlmp.feat.extinqres",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 16,
		  NULL, HFILL}},
		{&hf_lmp_feat_simlebredr,
		 {"Simultaneous LE and BR/EDR to Same Device Capable (Controller)", "btbrlmp.feat.simlebredr",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 17,
		  NULL, HFILL}},
		{&hf_lmp_feat_res3,
		 {"Reserved", "btbrlmp.feat.res3",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 18,
		  NULL, HFILL}},
		{&hf_lmp_feat_ssp,
		 {"Secure Simple Pairing", "btbrlmp.feat.ssp",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 19,
		  NULL, HFILL}},
		{&hf_lmp_feat_enpdu,
		 {"Encapsulated PDU", "btbrlmp.feat.enpdu",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 20,
		  NULL, HFILL}},
		{&hf_lmp_feat_edr,
		 {"Erroneous Data Reporting", "btbrlmp.feat.edr",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 21,
		  NULL, HFILL}},
		{&hf_lmp_feat_nonflush,
		 {"Non-flushable Packet Boundary Flag", "btbrlmp.feat.nonflush",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 22,
		  NULL, HFILL}},
		{&hf_lmp_feat_res4,
		 {"Reserved", "btbrlmp.feat.res4",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 23,
		  NULL, HFILL}},
		{&hf_lmp_feat_lstimche,
		 {"Link Supervision Timeout Changed Event", "btbrlmp.feat.lstimche",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 24,
		  NULL, HFILL}},
		{&hf_lmp_feat_inqtxpwr,
		 {"Inquiry TX Power Level", "btbrlmp.feat.inqtxpwr",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 25,
		  NULL, HFILL}},
		{&hf_lmp_feat_enhpwr,
		 {"Enhanced Power Control", "btbrlmp.feat.enhpwr",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 26,
		  NULL, HFILL}},
		{&hf_lmp_feat_res5,
		 {"Reserved", "btbrlmp.feat.res5",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 27,
		  NULL, HFILL}},
		{&hf_lmp_feat_res6,
		 {"Reserved", "btbrlmp.feat.res6",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 28,
		  NULL, HFILL}},
		{&hf_lmp_feat_res7,
		 {"Reserved", "btbrlmp.feat.res7",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 29,
		  NULL, HFILL}},
		{&hf_lmp_feat_res8,
		 {"Reserved", "btbrlmp.feat.res8",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 30,
		  NULL, HFILL}},
		{&hf_lmp_feat_extfeat,
		 {"Extended features", "btbrlmp.feat.extfeat",
		  FT_BOOLEAN, 64, NULL, 0x100000000 << 31,
		  NULL, HFILL}},
		{&hf_lmp_featuresext,
		 {"Extended Features", "btbrlmp.featuresext",
		  FT_UINT64, BASE_HEX, NULL, 0x0,
		  "Extended Feature Mask", HFILL}},
		/* extended features page 1 */
		{&hf_lmp_efeat_ssp,
		 {"Secure Simple Pairing (Host Support)", "btbrlmp.efeat.ssp",
		  FT_BOOLEAN, 64, NULL, 0x1 << 0,
		  NULL, HFILL}},
		{&hf_lmp_efeat_lesup,
		 {"LE Supported (Host)", "btbrlmp.efeat.lesup",
		  FT_BOOLEAN, 64, NULL, 0x1 << 1,
		  NULL, HFILL}},
		{&hf_lmp_efeat_lebredr,
		 {"Simultaneous LE and BR/EDR to Same Device Capable (Host)", "btbrlmp.efeat.lebredr",
		  FT_BOOLEAN, 64, NULL, 0x1 << 2,
		  NULL, HFILL}},
		{&hf_lmp_efeat_sch,
		 {"Secure Connections (Host Support)", "btbrlmp.efeat.sch",
		  FT_BOOLEAN, 64, NULL, 0x1 << 3,
		  NULL, HFILL}},
		/* extended features page 2 */
		{&hf_lmp_efeat_csbma,
		 {"Connectionless Slave Broadcast - Master Operation", "btbrlmp.efeat.csbma",
		  FT_BOOLEAN, 64, NULL, 0x1 << 0,
		  NULL, HFILL}},
		{&hf_lmp_efeat_csbsl,
		 {"Connectionless Slave Broadcast - Slave Operation", "btbrlmp.efeat.csbsl",
		  FT_BOOLEAN, 64, NULL, 0x1 << 1,
		  NULL, HFILL}},
		{&hf_lmp_efeat_syntr,
		 {"Synchronization Train", "btbrlmp.efeat.syntr",
		  FT_BOOLEAN, 64, NULL, 0x1 << 2,
		  NULL, HFILL}},
		{&hf_lmp_efeat_synsc,
		 {"Synchronization Scan", "btbrlmp.efeat.synsc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 3,
		  NULL, HFILL}},
		{&hf_lmp_efeat_inqresnote,
		 {"Inquiry Response Notification Event", "btbrlmp.efeat.inqresnote",
		  FT_BOOLEAN, 64, NULL, 0x1 << 4,
		  NULL, HFILL}},
		{&hf_lmp_efeat_genintsc,
		 {"Generalized interlaced scan", "btbrlmp.efeat.genintsc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 5,
		  NULL, HFILL}},
		{&hf_lmp_efeat_ccadj,
		 {"Coarse Clock Adjustment", "btbrlmp.efeat.ccadj",
		  FT_BOOLEAN, 64, NULL, 0x1 << 6,
		  NULL, HFILL}},
		{&hf_lmp_efeat_res0,
		 {"Reserved for future use", "btbrlmp.efeat.res0",
		  FT_BOOLEAN, 64, NULL, 0x1 << 7,
		  NULL, HFILL}},
		{&hf_lmp_efeat_scc,
		 {"Secure Connections (Controller Support)", "btbrlmp.efeat.scc",
		  FT_BOOLEAN, 64, NULL, 0x1 << 8,
		  NULL, HFILL}},
		{&hf_lmp_efeat_ping,
		 {"Ping", "btbrlmp.efeat.ping",
		  FT_BOOLEAN, 64, NULL, 0x1 << 9,
		  NULL, HFILL}},
		{&hf_lmp_efeat_res1,
		 {"Reserved for future use", "btbrlmp.efeat.res1",
		  FT_BOOLEAN, 64, NULL, 0x1 << 10,
		  NULL, HFILL}},
		{&hf_lmp_efeat_trnud,
		 {"Train nudging", "btbrlmp.efeat.trnud",
		  FT_BOOLEAN, 64, NULL, 0x1 << 11,
		  NULL, HFILL}},
		{&hf_lmp_efeat_sam,
		 {"Slot Availability Mask", "btbrlmp.efeat.sam",
		  FT_BOOLEAN, 64, NULL, 0x1 << 12, //typo in the BT standard defines this as >>10 ...
		  NULL, HFILL}},
		{&hf_lmp_fpage,
		 {"Features Page", "btbrlmp.fpage",
		  FT_UINT8, BASE_DEC, VALS(features_page), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_htime,
		 {"Hold Time", "btbrlmp.htime",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Hold Time in slots", HFILL}},
		{&hf_lmp_hinst,
		 {"Hold Instant", "btbrlmp.hinst",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Hold Instant (slot)", HFILL}},
		{&hf_lmp_hopmode,
		 {"Hopping Mode", "btbrlmp.hopmode",
		  FT_UINT8, BASE_DEC, VALS(hopping_mode), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_iocaps,
		 {"IO Capabilities", "btbrlmp.iocaps",
		  FT_UINT8, BASE_DEC, VALS(io_capabilities), 0x0,
		  "Input/Output Capabilities", HFILL}},
		{&hf_lmp_jitter,
		 {"Jitter", "btbrlmp.jitter",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Jitter in microseconds", HFILL}},
		{&hf_lmp_key,
		 {"Key", "btbrlmp.key",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_keysz,
		 {"Key Size", "btbrlmp.keysz",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Key Size in bytes", HFILL}},
		{&hf_lmp_ksmask,
		 {"Key Size Mask", "btbrlmp.ksmask",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_ltaddr1,
		 {"LT_ADDR 1", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0f,
		  "Logical Transport Address 1", HFILL}},
		{&hf_lmp_ltaddr2,
		 {"LT_ADDR 2", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0xf0,
		  "Logical Transport Address 2", HFILL}},
		{&hf_lmp_ltaddr3,
		 {"LT_ADDR 3", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0f,
		  "Logical Transport Address 3", HFILL}},
		{&hf_lmp_ltaddr4,
		 {"LT_ADDR 4", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0xf0,
		  "Logical Transport Address 4", HFILL}},
		{&hf_lmp_ltaddr5,
		 {"LT_ADDR 5", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0f,
		  "Logical Transport Address 5", HFILL}},
		{&hf_lmp_ltaddr6,
		 {"LT_ADDR 6", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0xf0,
		  "Logical Transport Address 6", HFILL}},
		{&hf_lmp_ltaddr7,
		 {"LT_ADDR 7", "btbrlmp.ltaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0f,
		  "Logical Transport Address 7", HFILL}},
		{&hf_lmp_maccess,
		 {"Maccess", "btbrlmp.maccess",
		  FT_UINT8, BASE_HEX, NULL, 0x0f,
		  "Number of access windows", HFILL}},
		{&hf_lmp_maxslots,
		 {"Max Slots", "btbrlmp.maxslots",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_maxsp,
		 {"Max Supported Page", "btbrlmp.maxsp",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Highest extended features page with non-zero bit", HFILL}},
		{&hf_lmp_maxss,
		 {"Max Sniff Subrate", "btbrlmp.maxss",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_minsmt,
		 {"Min Sniff Mode Timeout", "btbrlmp.minsmt",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Min Sniff Mode Timeout in slots", HFILL}},
		{&hf_lmp_naccslots,
		 {"Nacc-slots", "btbrlmp.naccslots",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_namefrag,
		 {"Name Fragment", "btbrlmp.namefrag",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_namelen,
		 {"Name Length", "btbrlmp.namelen",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Name Length in bytes", HFILL}},
		{&hf_lmp_nameoffset,
		 {"Name Offset", "btbrlmp.nameoffset",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Name Offset in bytes", HFILL}},
		{&hf_lmp_nb,
		 {"Nb", "btbrlmp.nb",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_nbc,
		 {"Nbc", "btbrlmp.nbc",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_nbsleep,
		 {"Nbsleep", "btbrlmp.nbsleep",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_negstate,
		 {"Negotiation State", "btbrlmp.negstate",
		  FT_UINT8, BASE_DEC, VALS(negotiation_state), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_nonce,
		 {"Nonce Value", "btbrlmp.nonce",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_nottype,
		 {"Notification Type", "btbrlmp.nottype",
		  FT_UINT8, BASE_DEC, VALS(notification_value), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_npoll,
		 {"Npoll", "btbrlmp.npoll",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_oobauthdata,
		 {"OOB Authentication Data", "btbrlmp.oobauthdata",
		  FT_UINT8, BASE_DEC, VALS(oob_auth_data), 0x00,
		  NULL, HFILL}},
		{&hf_lmp_op,
		 {"Opcode", "btbrlmp.op",
		  FT_UINT8, BASE_DEC, VALS(opcode), 0xfe,
		  NULL, HFILL}},
		{&hf_lmp_opinre,
		 {"In Response To", "btbrlmp.opinre",
		  FT_UINT8, BASE_DEC, VALS(opcode), 0x7f,
		  "Opcode this is in response to", HFILL}},
		{&hf_lmp_pagesch,
		 {"Paging Scheme", "btbrlmp.pagesch",
		  FT_UINT8, BASE_DEC, VALS(paging_scheme), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pcmode,
		 {"Power Control Mode", "btbrlmp.pcmode",
		  FT_UINT8, BASE_DEC, VALS(power_control_mode), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pkttype,
		 {"Packet Type", "btbrlmp.pkttype",
		  /* FIXME break out further */
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Packet Type", HFILL}},
		{&hf_lmp_pkttypetbl,
		 {"Packet Type Table", "btbrlmp.pkttypetbl",
		  FT_UINT8, BASE_DEC, VALS(packet_type_table), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr,
		 {"PM_ADDR", "btbrlmp.pmaddr",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr1,
		 {"PM_ADDR 1", "btbrlmp.pmaddr1",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr2,
		 {"PM_ADDR 2", "btbrlmp.pmaddr2",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr3,
		 {"PM_ADDR 3", "btbrlmp.pmaddr3",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr4,
		 {"PM_ADDR 4", "btbrlmp.pmaddr4",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr5,
		 {"PM_ADDR 5", "btbrlmp.pmaddr5",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr6,
		 {"PM_ADDR 6", "btbrlmp.pmaddr6",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pmaddr7,
		 {"PM_ADDR 7", "btbrlmp.pmaddr7",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pollintvl,
		 {"Poll Interval", "btbrlmp.pollintvl",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Poll Interval in slots", HFILL}},
		{&hf_lmp_pollper,
		 {"Poll Period (ms)", "btbrlmp.pollper",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Poll Period in units of 1.25 ms", HFILL}},
		{&hf_lmp_pssettings,
		 {"Paging Scheme Settings", "btbrlmp.pssettings",
		  FT_UINT8, BASE_DEC, VALS(paging_scheme_settings), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pwradjreq,
		 {"Power Adjustment Request", "btbrlmp.pwradjreq",
		  FT_UINT8, BASE_DEC, VALS(power_adjust_req), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pwradjres,
		 {"Power Adjustment Response", "btbrlmp.pwradjres",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_pwradj_8dpsk,
		 {"8DPSK", "btbrlmp.pwradj_8dpsk",
		  FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x30,
		  "8DPSK Power Adjustment Response", HFILL}},
		{&hf_lmp_pwradj_dqpsk,
		 {"DQPSK", "btbrlmp.pwradj_dqpsk",
		  FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x0C,
		  "DQPSK Power Adjustment Response", HFILL}},
		{&hf_lmp_pwradj_gfsk,
		 {"GFSK", "btbrlmp.pwradj_gfsk",
		  FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x03,
		  "GFSK Power Adjustment Response", HFILL}},
		{&hf_lmp_rand,
		 {"Random Number", "btbrlmp.rand",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_rate,
		 {"Data Rate", "btbrlmp.rate",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_rate_fec,
		 {"FEC", "btbrlmp.rate.fec",
		  FT_BOOLEAN, BASE_DEC, TFS(&fec), 0x01,
		  "Forward Error Correction", HFILL}},
		{&hf_lmp_rate_size,
		 {"Packet Size", "btbrlmp.rate.size",
		  FT_UINT8, BASE_HEX, VALS(packet_size), 0x06,
		  "Basic Rate Packet Size", HFILL}},
		{&hf_lmp_rate_type,
		 {"EDR Type", "btbrlmp.rate.type",
		  FT_UINT8, BASE_HEX, VALS(edr_type), 0x18,
		  "Enhanced Data Rate type", HFILL}},
		{&hf_lmp_rate_edrsize,
		 {"EDR Size", "btbrlmp.rate.edrsize",
		  FT_UINT8, BASE_HEX, VALS(packet_size), 0x60,
		  "Enhanced Data Rate packet size", HFILL}},
		{&hf_lmp_rxfreq,
		 {"RX Frequency (MHz)", "btbrlmp.rxfreq",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Receive Frequency in MHz above 2402", HFILL}},
		{&hf_lmp_scohdl,
		 {"SCO Handle", "btbrlmp.scohdl",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_scopkt,
		 {"SCO Packet", "btbrlmp.scopkt",
		  FT_UINT8, BASE_DEC, VALS(sco_packet), 0x0,
		  NULL, HFILL}},
		{&hf_lmp_slotoffset,
		 {"Slot Offset", "btbrlmp.slotoffset",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Slot Offset in microseconds", HFILL}},
		{&hf_lmp_sniffatt,
		 {"Sniff Attempt", "btbrlmp.sniffatt",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Number of receive slots", HFILL}},
		{&hf_lmp_sniffsi,
		 {"Sniff Subrating Instant", "btbrlmp.sniffsi",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Sniff Subrating Instant (slot)", HFILL}},
		{&hf_lmp_sniffto,
		 {"Sniff Timeout", "btbrlmp.sniffto",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Number of receive slots", HFILL}},
		{&hf_lmp_subversnr,
		 {"SubVersNr", "btbrlmp.subversnr",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "SubVersion", HFILL}},
		{&hf_lmp_suptimeout,
		 {"Supervision Timeout", "btbrlmp.suptimeout",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Supervision Timeout in slots", HFILL}},
		{&hf_lmp_swinst,
		 {"Switch Instant", "btbrlmp.swinst",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Switch Instant (slot)", HFILL}},
		{&hf_lmp_taccess,
		 {"Taccess", "btbrlmp.taccess",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Taccess in slots", HFILL}},
		{&hf_lmp_tb,
		 {"Tb", "btbrlmp.tb",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Tb in slots", HFILL}},
		{&hf_lmp_tesco,
		 {"Tesco", "btbrlmp.tesco",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Tesco in slots", HFILL}},
		{&hf_lmp_testlen,
		 {"Test Length", "btbrlmp.testlen",
		  FT_UINT16, BASE_DEC, NULL, 0x00,
		  "Length of test sequence in bytes", HFILL}},
		{&hf_lmp_testscen,
		 {"Test Scenario", "btbrlmp.testscen",
		  FT_UINT8, BASE_DEC, VALS(test_scenario), 0x00,
		  NULL, HFILL}},
		{&hf_lmp_tid,
		 {"TID", "btbrlmp.tid",
		  FT_BOOLEAN, BASE_DEC, TFS(&tid), 0x01,
		  "Transaction ID", HFILL}},
		{&hf_lmp_timectrl,
		 {"Timing Control Flags", "btbrlmp.timectrl",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_lmp_time_change,
		 {"Timing Change", "btbrlmp.time.change",
		  FT_BOOLEAN, 8, TFS(&time_change), 0x01,
		  NULL, HFILL}},
		{&hf_lmp_time_init,
		 {"Initialization", "btbrlmp.time.init",
		  FT_BOOLEAN, 8, TFS(&time_init), 0x02,
		  NULL, HFILL}},
		{&hf_lmp_time_accwin,
		 {"Access Window", "btbrlmp.time.accwin",
		  FT_BOOLEAN, 8, TFS(&time_accwin), 0x04,
		  NULL, HFILL}},
		{&hf_lmp_tsco,
		 {"Tsco", "btbrlmp.tsco",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Tsco in slots", HFILL}},
		{&hf_lmp_tsniff,
		 {"Tsniff", "btbrlmp.tsniff",
		  FT_UINT16, BASE_HEX, NULL, 0x0,
		  "Tsniff in slots", HFILL}},
		{&hf_lmp_txfreq,
		 {"TX Frequency (MHz)", "btbrlmp.txfreq",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Transmit Frequency in MHz above 2402", HFILL}},
		{&hf_lmp_versnr,
		 {"VersNr", "btbrlmp.versnr",
		  FT_UINT8, BASE_DEC, VALS(versnr), 0x0,
		  "Version", HFILL}},
		{&hf_lmp_wesco,
		 {"Wesco", "btbrlmp.wesco",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Number of slots in retransmission window", HFILL}},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_lmp,
		&ett_lmp_pwradjres,
		&ett_lmp_rate,
		&ett_lmp_timectrl,
		&ett_lmp_features,
		&ett_lmp_featuresext,
	};

	/* register the protocol name and description */
	proto_btbrlmp = proto_register_protocol(
		"Bluetooth Link Manager Protocol", /* full name */
		"btlmp",						   /* short name */
		"btlmp"							   /* abbreviation (e.g. for filters) */
	);

	register_dissector("btlmp", dissect_btbrlmp, proto_btbrlmp);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btbrlmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_btbrlmp(void)
{
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
