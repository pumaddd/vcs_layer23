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
/* Parse json */
#include <jansson.h>

enum dch_state_t {
	DCH_SDCCH,
	DCH_WAIT_KC,
	DCH_TCH,
};

static struct {
	int ccch_mode;
	int has_si1;
	int has_si3;
	int has_si5;
	int has_si6;
	int has_si5ter;
	int has_kc;

	int has_CMrequest_pagingrespone;
	int has_jump_channel;

	uint8_t Call_Flow;
	int neci;
	uint16_t cell_id;
	uint16_t lac_id;
	uint8_t dch_nr;
	uint8_t dch_ciph;

	int dch_badcnt;

	enum dch_state_t dch_state;

	struct gsm_sysinfo_freq cell_arfcns[1024];
	sbit_t bursts_dl[116 * 4];
	sbit_t bursts_ul[116 * 4];

	char phonenumber[MAX_PHONE_NUMBER_LEN];

	uint8_t kc[8];
	char kc_str[GSM_KC_LEN * 10];
	/* Cipher data */
	uint32_t cipher_index;
	struct l1ctl_burst_ind cipher_buffer[1000];
	sbit_t bursts_dl_cipherbuffer[116 * 4];
	sbit_t bursts_ul_cipherbuffer[116 * 4];

	/* Send request to server */
	EV_HTTP_DATA http_data;

	/* Target tmsi */
	IMSI_TMSI local_addr;
	uint8_t local_addr_str[MAX_IMSI_TMSI_LEN * 2 + 1];
	uint8_t match_imsi_tmsi;
	uint8_t is_tmsi_in_blacklist;

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

	uint8_t count_badpack_in_cph;
} app_state;


uint32_t d_arfcn;
uint32_t d_chan_nr;
uint32_t d_frame_nr;
uint32_t d_tseq;
uint32_t d_hsn;
uint32_t d_maio;
uint16_t d_ma_list[64];
uint32_t d_ma_len;
uint32_t d_h;
uint32_t d_cell_id;
uint32_t d_lac_id;
uint8_t d_target = 0;
uint8_t d_target_list[41][9];
uint8_t d_blacklist_len;
uint8_t d_blacklist[41][9];
uint8_t d_tmsi_finder_flag;
uint8_t d_is_catch_voice;
uint8_t d_is_catch_sms;
uint32_t d_father_pid;
uint32_t watch_dog;
uint32_t d_index_round;
/* Vars for extern */
char *b64_sdcch_buff = NULL;
extern int ccch_quit;

extern struct gsmtap_inst *gsmtap_inst;
extern int quit;

extern int is_send_request;

/* Global vars */

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

static void handle_si3(struct osmocom_ms *ms, struct gsm48_system_information_type_3 *si) {
	if (app_state.ccch_mode != CCCH_MODE_NONE)
		return;

	if (si->control_channel_desc.ccch_conf == RSL_BCCH_CCCH_CONF_1_C)
		app_state.ccch_mode = CCCH_MODE_COMBINED;
	else
		app_state.ccch_mode = CCCH_MODE_NON_COMBINED;

	// No need change ccch_mode
	// l1ctl_tx_ccch_mode_req(ms, app_state.ccch_mode);

	app_state.neci = si->cell_sel_par.neci;
	app_state.has_si3 = 1;
	app_state.cell_id = ntohs(si->cell_identity);
	app_state.lac_id = ntohs(si->lai.lac);
}

static void dump_bcch(struct osmocom_ms *ms, uint8_t tc, const uint8_t *data) {
	struct gsm48_system_information_type_header *si_hdr;
	si_hdr = (struct gsm48_system_information_type_header *) data;
	uint8_t si_type = si_hdr->system_information;

	// LOGP(DRR, LOGL_INFO, "BCCH message (type=0x%02x): %s\n",
	// 	si_type, gsm48_rr_msg_name(si_type));

	if (bcch_check_tc(si_type, tc) == -EINVAL)
		LOGP(DRR, LOGL_INFO, "SI on wrong tc=%u\n", tc);

	/* GSM 05.02 §6.3.1.3 Mapping of BCCH data */
	switch (si_type) {
	case GSM48_MT_RR_SYSINFO_1:
		/* No need handle */
		// if (!app_state.has_si1){
		// 	struct gsm48_system_information_type_1 *si1 = (struct gsm48_system_information_type_1 *) data;
		// 	gsm48_decode_freq_list(app_state.cell_arfcns, si1->cell_channel_description, sizeof(si1->cell_channel_description), 0xff, 0x01);
		// 	app_state.has_si1 = 1;
		// 	LOGP(DRR, LOGL_INFO, "BCCH message (type=0x%02x): %s\n", si_type, gsm48_rr_msg_name(si_type));
		// }
		break;
	case GSM48_MT_RR_SYSINFO_3:
		/* No need handle */
		// handle_si3(ms,
		// 	(struct gsm48_system_information_type_3 *) data);
		break;

	default:
		/* We don't care about other types of SI */
		break; /* thus there is nothing to do */
	};
}

static int insert_request_kc_table(){
	MYSQL *con = mysql_init(NULL);
	char *sql_cmd = (char*) malloc(strlen(b64_sdcch_buff) * sizeof(char) + 5000);
	memset(sql_cmd, 0, strlen(b64_sdcch_buff) * sizeof(char) + 5000);

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	if (app_state.dch_ciph == 1)
		sprintf(sql_cmd, "INSERT INTO `request_kc`(`Id_http`, `Sdcch_buff`, `Cell_id`, `Lac_id`, `Bcch_arfcn`, `Local_addr`, `Dch_ciph`, `State_process`, `Is_catch_voice`, `Is_catch_sms`, `Index_round`) VALUES (\"%s\", \"%s\", %u, %u, %u, \"%s\", %u, %u, %u, %u, %u)",
			app_state.http_data.id, b64_sdcch_buff, d_cell_id, d_lac_id, d_arfcn, app_state.local_addr_str, app_state.dch_ciph, 0, app_state.is_catch_voice, app_state.is_catch_sms, d_index_round);
	else 
		sprintf(sql_cmd, "INSERT INTO `request_kc`(`Id_http`, `Sdcch_buff`, `Cell_id`, `Lac_id`, `Bcch_arfcn`, `Local_addr`, `Dch_ciph`, `State_process`, `Is_catch_voice`, `Is_catch_sms`, `Index_round`) VALUES (\"%s\", \"%s\", %u, %u, %u, \"%s\", %u, %u, %u, %u, %u)",
			app_state.http_data.id, b64_sdcch_buff, d_cell_id, d_lac_id, d_arfcn, app_state.local_addr_str, app_state.dch_ciph, 2, app_state.is_catch_voice, app_state.is_catch_sms, d_index_round);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
	}
	mysql_close(con);
	return 1;
}

void finish_with_error(MYSQL *con)
{
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);        
}

char *read_string_from_file_config(FILE *file, char const *desired_name) { 
    char name[128];
    char val[128];

    while (fscanf(file, "%127[^=]=%127[^\n]%*c", name, val) == 2) {
        if (strcmp(name, desired_name) == 0) {
            return strdup(val);
        }
    }
    return NULL;
}

static time_t get_start_time_capture() {
	FILE *fp;
	uint64_t time = 0;
	time_t ret;
	fp = fopen("/etc/data/grd_config", "r");

	char* table_name = read_string_from_file_config(fp, "TABLENAME");
	LOGP(DRR, LOGL_INFO, "Table name: %s\n", table_name);

	MYSQL *con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		exit(1);
	}  

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "file.db", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	char* sql_cmd = (char*) malloc(1000 * sizeof(char));
	sprintf(sql_cmd, "SELECT `date` FROM `%s` WHERE ID = 1 ", table_name);

	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
	}

	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) {
		finish_with_error(con);
	}
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) { 
		time = atoll(row[0]);
	}
	free(sql_cmd);
	fclose(fp);

	ret = (time_t) time;
	LOGP(DRR, LOGL_INFO, "Start capture time: %llu\n", ret);
	return ret;
}

static float get_sample_rate(char* key) {
	FILE *fp;
	float ret;

	fp = fopen("/etc/data/grd_config", "r");
	char* sample_rate_str = read_string_from_file_config(fp, key);
	ret = atof(sample_rate_str);
	fclose(fp);
	if (sample_rate_str)
		free(sample_rate_str);
	return ret;
}

static int get_params_from_mysql_server(uint32_t id) {
	MYSQL *con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		exit(1);
	}  

	if (mysql_real_connect(con, DATABASE_HOSTNAME, "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	char sql_cmd[1000] = {0};
	sprintf(sql_cmd , "SELECT * FROM `imm_ass` WHERE Id = %u", id);
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

		d_arfcn = atoi(row[1]);
		d_index_round = atoi(row[2]);
		d_maio = atoi(row[3]);
		d_hsn = atoi(row[4]);
		d_chan_nr = atoi(row[5]);
		d_tseq = atoi(row[6]);
		d_frame_nr = atoi(row[7]);
		d_cell_id = atoi(row[9]);
		d_lac_id = atoi(row[10]);

		d_ma_len = 0;
		token = strtok(row[8], " ");
		while (token != NULL) {
			d_ma_list[d_ma_len++] = atoi(token);
			token = strtok(NULL, " ");
		}
		return 0;
	}
	mysql_close(con);
	return 1;
}

/**
 * This method used to send a l1ctl_tx_dm_est_req_h0 or
 * a l1ctl_tx_dm_est_req_h1 to the layer1 to follow this
 * assignment. The code has been removed.
 */
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
					ch_subch, ia->chan_desc.h0.tsc, fn, d_arfcn,
					app_state.cell_id, app_state.lac_id);

			// insertDB(db, 0, 0, ia->chan_desc.chan_nr, ia->chan_desc.h0.tsc, fn, ma, 1);

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
					ch_subch, ia->chan_desc.h1.tsc, fn, d_arfcn,
					app_state.cell_id, app_state.lac_id);

			// insertDB(db, maio, hsn, ia->chan_desc.chan_nr, ia->chan_desc.h1.tsc, fn, ma, ma_len);
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

/* TODO: share / generalize this code */
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

static void create_id(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	time_t d;
	struct tm *lt;

	time(&d);
	lt = gmtime(&d);

	snprintf(app_state.http_data.id, 150,
			"%04d%02d%02d_%02d%02d%02d_%d_%d_%02x_%02x", lt->tm_year + 1900,
			lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec,
			d_arfcn, ntohl(bi->frame_nr), bi->chan_nr, sys.id);
	LOGP(DCC, LOGL_NOTICE, "Session id: %s\n", app_state.http_data.id);
}

static uint64_t convert_fn_offset(int16_t arfcn, uint16_t cell_id, uint16_t lac_id, uint32_t fn, uint32_t index_round){
	MYSQL *con = mysql_init(NULL);
	char *sql_cmd = (char*) malloc(sizeof(char) * 1000);
	memset(sql_cmd, 0, sizeof(char) * 1000);
	uint64_t sample_offset = 0; 
	uint32_t frame_number = 0;

	if (mysql_real_connect(con, "127.0.0.1", "netsharing", "12345678", "test.db", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}
	char _format[] = "SELECT ID, SampleOffset, ((51 * 26 * T1) + (51 * (((T3 + 26) - T2) \x25 26)) + T3) AS frame_number FROM `%u` where NameEvent = 2 AND Cell_Id = %u AND Lac_ID = %u AND Index_round = %u ORDER BY ABS(frame_number - %llu) LIMIT 1" ;
	char table_name[1000];
	sprintf(sql_cmd, _format , arfcn, cell_id, lac_id, index_round ,fn);
	LOGP(DL1C, LOGL_DEBUG,"SQL query %s\n", sql_cmd);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
		return sample_offset;
	}

	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) {
		finish_with_error(con);
	}
	mysql_close(con);
	uint64_t best_frame = -1;
	int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) { 
		sample_offset = atoll(row[1]);
		frame_number = atoi(row[2]);
	}
	LOGP(DL1C, LOGL_DEBUG,"Query get sample offset %llu from frame number %lu\n", sample_offset, frame_number);
	return sample_offset;

}

static void create_offline_id(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi) {
	/* Get time start capture */
	struct tm *lt;
	time_t start_capture_time;
	time_t start_event_time;
	uint64_t sample_offset;
	uint32_t elapsed_time;
	float sample_rate;
	start_capture_time = get_start_time_capture();

	/* Convert frame number immediate assignment to sample offset */
	sample_offset = convert_fn_offset(d_arfcn, app_state.cell_id, app_state.lac_id, d_frame_nr, d_index_round);
	/* Compute time receive immediate assignment  */
	if (d_arfcn < 512) {
		/* GSM 900 */
		sample_rate = get_sample_rate("SAMPRATEOUTGSM900");
		elapsed_time = sample_offset / sample_rate;
	} else {
		/* DCS 1800 */
		sample_rate = get_sample_rate("SAMPRATEOUTDCS1800");
		elapsed_time = sample_offset / sample_rate;
	}
	/* Create id */
	start_event_time = start_capture_time + elapsed_time;

	lt = gmtime(&start_event_time);
	snprintf(app_state.http_data.id, 150,
			"%04d%02d%02d_%02d%02d%02d_%d_%d_%02x_%02x", lt->tm_year + 1900,
			lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec,
			d_arfcn, ntohl(bi->frame_nr), bi->chan_nr, sys.id);
	LOGP(DCC, LOGL_NOTICE, "Session id: %s\n", app_state.http_data.id);
}

static struct osmo_timer_list updconfig_timer;
static void start_updconfig_timer(int sec, int micro);
static void timeout_updconfig_cb(void *arg);
static void stop_updconfig_timer(void);


static void timeout_updconfig_cb(void *arg) {
	watch_dog += 1;
	LOGP(DSUM, LOGL_NOTICE, "Timeout_updconfig_cb -- ccch_quit: %d, watchdog counter: %d\n", ccch_quit, watch_dog);
	if (watch_dog >= 25) {
		LOGP(DSUM, LOGL_NOTICE, "Quit SDCCH by watchdog \n");
		ccch_quit = 2;
	}
	if (ccch_quit == 2){
		stop_updconfig_timer();
		quit = 1;
		return;
		// kill(getpid(),SIGINT);
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

static void local_burst_decode(struct osmocom_ms *ms, struct l1ctl_burst_ind *bi)
{
	int16_t rx_dbm;
	uint16_t arfcn;
	uint8_t cbits, tn, lch_idx, mIdx;
	uint32_t fn;
	int ul, bid, i;
	sbit_t *bursts;
	ubit_t bt[116];
	int v;
	int pi = 0;

	char tempbuf[200] = "";
	char filebuf[2000] = "";
	uint8_t RRlayer2[23];
	uint8_t NR = 0;

	arfcn = ntohs(bi->band_arfcn);
	rx_dbm = rxlev2dbm(bi->rx_level);
	fn = ntohl(bi->frame_nr);
	ul = !!(arfcn & ARFCN_UPLINK);
	bursts = ul ? app_state.bursts_ul : app_state.bursts_dl;
	cbits = bi->chan_nr >> 3;
	tn = bi->chan_nr & 7;
	bid = -1;

	/* Is gen http_data.id ? */
	if (strlen(app_state.http_data.id) == 0) {
		create_offline_id(ms, bi);
		// create_id(ms, bi);
	}

	if (cbits == 0x01) { /* TCH/F */
		lch_idx = 0;
		if (bi->flags & BI_FLG_SACCH) {
			uint32_t fn_report;
			fn_report = (fn - (tn * 13) + 104) % 104;
			bid = (fn_report - 12) / 26;
			if (bid > 3)
				bid = -1;
			if (bid == 3)
				LOGP(DCC, LOGL_NOTICE, "-- SACCH arfcn = %d, fn = %d fn_report = %d, bid = %d , bi->snr =  %x \n", d_arfcn, fn, fn_report, bid, bi->snr);
		}
	} else if ((cbits & 0x1e) == 0x02) { /* TCH/H */
		lch_idx = cbits & 1;
		if (bi->flags & BI_FLG_SACCH) {
			uint32_t fn_report;
			uint8_t tn_report = (tn & ~1) | lch_idx;
			fn_report = (fn - (tn_report * 13) + 104) % 104;
			bid = (fn_report - 12) / 26;
			if (bid == 3)
				LOGP(DCC, LOGL_NOTICE, "TCH/H ---- SACCH arfcn = %d, fn = %d fn_report = %d, bid = %d , bi->snr =  %x \n", d_arfcn, fn, fn_report, bid, bi->snr);
		}

	} else if ((cbits & 0x1c) == 0x04) { /* SDCCH/4 */
		lch_idx = cbits & 3;
		bid = bi->flags & 3;
	} else if ((cbits & 0x18) == 0x08) { /* SDCCH/8 */
		lch_idx = cbits & 7;
		bid = bi->flags & 3;
	}

	if (bid == -1)
		return;

	if (bid < 0 || bid > 3)
		return;

	/* Clear if new set */
	if (bid == 0)
		memset(bursts, 0x00, 116 * 4);

	/* Unpack (ignore hu/hl) */
	osmo_pbit2ubit_ext(bt, 0, bi->bits, 0, 57, 0);
	osmo_pbit2ubit_ext(bt, 59, bi->bits, 57, 57, 0);
	bt[57] = bt[58] = 1;

	/* Fill app_state.http_data.ciphertext */
	if ((app_state.dch_ciph) && (ul == 0)) {
		memset(filebuf, 0, sizeof(filebuf));
		memset(tempbuf, 0, sizeof(tempbuf));

		snprintf(tempbuf, 200, "fn=%d,bid=%d, 114bit=", fn, bid);
		strcat(filebuf, tempbuf);
		for (pi = 0; pi < 57; pi++) {
			snprintf(tempbuf, 200, "%d", bt[pi]);
			strcat(filebuf, tempbuf);
		}

		for (pi = 59; pi < 116; pi++) {
			snprintf(tempbuf, 200, "%d", bt[pi]);
			strcat(filebuf, tempbuf);
		}
		strcat(filebuf, "\n");
		evbuffer_add_printf(app_state.http_data.ciphertext, "%s", filebuf);
	}

	/* Convert to softbits */
	for (i = 0; i < 116; i++)
		bursts[(116 * bid) + i] = bt[i] ? -(bi->snr >> 1) : (bi->snr >> 1);
	
	/* If last, decode */
	if (bid == 3) {
		uint8_t l2[23];
		int rv;
		uint8_t chan_type, chan_ts, chan_ss;
		uint8_t gsmtap_chan_type;

		rv = xcch_decode(l2, bursts);

		if (rv == 0) {
			/* Send to gsmtap */
			rsl_dec_chan_nr(bi->chan_nr, &chan_type, &chan_ss, &chan_ts);
			gsmtap_chan_type = chantype_rsl2gsmtap(chan_type,
					bi->flags & BI_FLG_SACCH ? 0x40 : 0x00);
			gsmtap_send(gsmtap_inst, arfcn, chan_ts, gsmtap_chan_type, chan_ss,
					ntohl(bi->frame_nr), bi->rx_level - 110, bi->snr, l2,
					sizeof(l2));

			/* Handle CMservice request */
			if (((l2[3] & 0x0F) == 0x05) && (l2[4] == 0x24)) {

				/* Check CMservice request type */
				switch (l2[5] & 0x0F)
				{
				case 0x01:
					LOGP(DRR, LOGL_NOTICE, "CMservice request type voice\n");
					break;
				case 0x04:
					LOGP(DRR, LOGL_NOTICE, "CMservice request type SMS\n");
					app_state.http_data.type = GSM_TYPE_SMS;
					break;	
				default:
					LOGP(DRR, LOGL_NOTICE, "Not handle CMservice request type: %x, realease\n", l2[5] & 0x0F);
					ccch_quit = 2;
					break;
				}

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

				/* Check TMSI in blacklist*/
				for (mIdx = 0; mIdx < d_blacklist_len; mIdx++) {
					char* pos = d_blacklist[mIdx];
					for (int count = 0; count < 4; count++) {
						char buf[10];
						sprintf(buf, "0x%c%c", pos[0], pos[1]);
						val[count] = strtol(buf, NULL, 0);
						pos += 2 * sizeof(char);
					}
					if (memcmp(app_state.local_addr.data, val, 4 * sizeof(char)) == 0) {
						app_state.is_tmsi_in_blacklist = 1;
						break;
					}
				}

				if (app_state.is_tmsi_in_blacklist) {
					/* Not follow target in blacklist */
					ccch_quit = 2;
				}

				/* Check TMSI in target list (whitelist) */
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

				if (d_tmsi_finder_flag == 1) {
					/* With mode find tmsi, accept all paging respone, enable catch sms */
					app_state.is_catch_sms = 1;

					if (app_state.match_imsi_tmsi == 0) {
						/* Not target, no need catch voice */
						app_state.is_catch_voice == 0;
					} else {
						app_state.is_catch_voice = d_is_catch_voice;
					}
					app_state.match_imsi_tmsi = 1;
				} else {
					/* Forward is_catch_voice, is_catch_sms flag */
					app_state.is_catch_voice = d_is_catch_voice;
					app_state.is_catch_sms = d_is_catch_sms;
				}
				LOGP(DRR, LOGL_NOTICE, "CMrequest catch_voice flag: %d, catch_sms flag: %d\n", app_state.is_catch_voice, app_state.is_catch_sms);


				if (app_state.match_imsi_tmsi == 1) {
					LOGP(DRR, LOGL_NOTICE, "Match tmsi, continue following\n");
				}
				else{
					LOGP(DRR, LOGL_NOTICE, "Not match tmsi, stop following\n");
					ccch_quit = 2;
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

				/* Check TMSI in blacklist*/
				for (mIdx = 0; mIdx < d_blacklist_len; mIdx++) {
					char* pos = d_blacklist[mIdx];
					for (int count = 0; count < 4; count++) {
						char buf[10];
						sprintf(buf, "0x%c%c", pos[0], pos[1]);
						val[count] = strtol(buf, NULL, 0);
						pos += 2 * sizeof(char);
					}
					if (memcmp(app_state.local_addr.data, val, 4 * sizeof(char)) == 0) {
						app_state.is_tmsi_in_blacklist = 1;
						break;
					}
				}

				if (app_state.is_tmsi_in_blacklist) {
					/* Not follow target in blacklist */
					ccch_quit = 2;
				}

				/* Check TMSI in target list (whitelist) */
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
					/* len(target_list) == 0 => Capture all */
					app_state.match_imsi_tmsi = 1;
				}

				if (d_tmsi_finder_flag == 1) {
					/* With mode find tmsi, accept all paging respone, enable catch sms */
					app_state.is_catch_sms = 1;

					if (app_state.match_imsi_tmsi == 0) {
						/* Not target, no need catch voice */
						app_state.is_catch_voice == 0;
					} else {
						app_state.is_catch_voice = d_is_catch_voice;
					}
					app_state.match_imsi_tmsi = 1;
				} else {
					/* Forward is_catch_voice, is_catch_sms flag */
					app_state.is_catch_voice = d_is_catch_voice;
					app_state.is_catch_sms = d_is_catch_sms;
				}
				LOGP(DRR, LOGL_NOTICE, "Paging respone catch_voice flag: %d, catch_sms flag: %d\n", app_state.is_catch_voice, app_state.is_catch_sms);

				if (app_state.match_imsi_tmsi == 1) {
					LOGP(DRR, LOGL_NOTICE, "Match tmsi, continue following\n");
				}
				else{
					LOGP(DRR, LOGL_NOTICE, "Not match tmsi, stop following\n");
					ccch_quit = 2;
				}
			}

			if ((ul == 0) && (app_state.count_badpack_in_cph <= 3)){ 
				/* Handle Si6 */
				if ((ul == 0) && (l2[2] == 0x03) && (l2[3] == 0x03) && (l2[5] == 0x06) && (l2[6] == 0x1e)) {
					memcpy(app_state.SI6, l2, 23);
					memset(tempbuf, 0, sizeof(tempbuf));
					memset(filebuf, 0, sizeof(filebuf));

					snprintf(tempbuf, 200, "SI6power0, fn(bid3)= %d, data=", fn);
					strcat(filebuf, tempbuf);
					for (v = 0; v < 23; v++) {
						snprintf(tempbuf, 200, "%02x", app_state.SI6[v]);
						strcat(filebuf, tempbuf);
					}
					strcat(filebuf, "\n");

					os_http_clear_buffer(app_state.http_data.si6);
					evbuffer_add_printf(app_state.http_data.plaintext, "%s", filebuf);
					evbuffer_add_printf(app_state.http_data.si6, "%s", filebuf);
					app_state.has_si6 = 1;
				}

				/* Handle Si5ter */
				if ((ul == 0) && (l2[2] == 0x03) && (l2[3] == 0x03) && (l2[5] == 0x06) && ((l2[6] == 0x06) || (l2[6] == 0x05))) {
					memcpy(app_state.SI5ter, l2, 23);
					memset(tempbuf, 0, sizeof(tempbuf));
					memset(filebuf, 0, sizeof(filebuf));

					snprintf(tempbuf, 200, "SI5terpower0, fn(bid3)= %d, data=", fn);
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
			
		}
	}
}

static void layer3_rx_burst(struct osmocom_ms *ms, struct msgb *msg) 
{
	int ul;
	uint16_t arfcn;
    struct l1ctl_burst_ind *bi;
	int rx_dbm;

	if (app_state.dch_state == DCH_WAIT_KC)
		return;

	/* Receive burst, reset watchdog */
	watch_dog = 0;

	bi = (struct l1ctl_burst_ind *) msg->l1h;
	arfcn = ntohs(bi->band_arfcn);
	ul = !!(arfcn & ARFCN_UPLINK);
	rx_dbm = rxlev2dbm(bi->rx_level);

	if (app_state.dch_state == DCH_SDCCH && app_state.dch_nr == bi->chan_nr){
		local_burst_decode(ms, bi);

		evbuffer_add(app_state.http_data.sdcch, bi, sizeof(*bi));

		/* Cache cipher data decode later */
		if (app_state.dch_ciph == 1 && app_state.cipher_index < 800){
			memcpy(&(app_state.cipher_buffer[app_state.cipher_index]), bi, sizeof(*bi));
			app_state.cipher_index++;
		}

		/* Count bad burst */
		if (!ul && (bi->flags & BI_FLG_SACCH)){
			if (app_state.dch_ciph && app_state.count_badpack_in_cph <= 10) 
					app_state.count_badpack_in_cph++;
		}

		if (!ul) {
			if (bi->snr < 64) {
				app_state.dch_badcnt++;	
				LOGP(DRR, LOGL_NOTICE, "app_state.dch_badcnt++ %d \n", app_state.dch_badcnt);
			} else if (app_state.dch_badcnt >= 2)
				app_state.dch_badcnt -= 2;
			else
				app_state.dch_badcnt = 0;
		}
		
		/* Check for channel end */
		if (app_state.dch_badcnt >= 10){
			/* Send wait kc */
			l1ctl_tx_wait_kc_state(ms);
			/* Check then send to server */
			LOGP(DRR, LOGL_NOTICE, "app_state.cipher_index: %u\n", app_state.cipher_index);
			LOGP(DRR, LOGL_NOTICE, "Channel SDCCH end\n");
			/* Fill app_state_http_data */
			app_state.http_data.arfcn = d_arfcn;
			app_state.http_data.speech.dch_ciph = app_state.dch_ciph;
			evbuffer_add_printf(app_state.http_data.speech.local_addr, "%s", app_state.local_addr_str);

			if (app_state.match_imsi_tmsi == 0){
				if (app_state.has_CMrequest_pagingrespone == 0)
					LOGP(DRR, LOGL_NOTICE, "Not have CM request or Paging respone, may be Location Update ???\n");
				else
					LOGP(DRR, LOGL_NOTICE, "Not match TMSI, dont send data to server\n");
				ccch_quit = 2;
			} else {
				/* Send request kc */
				uint8_t idx;
				for (idx = 0; idx < sys.workers[sys.id].http_retries; idx++) {
					if (os_http_client_sendreq(&app_state.http_data) == 0) {
						ccch_quit = 1;
						LOGP(DRR, LOGL_NOTICE, "os_http_client_sendreq\n");
						app_state.dch_state = DCH_WAIT_KC;
						os_http_clear_buffer(app_state.http_data.plaintext);
						os_http_clear_buffer(app_state.http_data.ciphertext);
						os_http_clear_buffer(app_state.http_data.sdcch);
						break;
					}
				}

				if (app_state.http_data.type != GSM_TYPE_SMS){
					/* Push context to database */
					LOGP(DRR, LOGL_NOTICE, "Push context to request kc\n");
					insert_request_kc_table();
				} else 
					LOGP(DRR, LOGL_NOTICE, "Type SMS uplink, no need push context to database\n");
			}
		}
	}
}

static int process_received_imm_ass(struct osmocom_ms *ms)
{
	uint8_t ch_type, ch_subch, ch_ts;

	/* Get params from imm_ass.db */
	get_params_from_mysql_server(d_h);
	rsl_dec_chan_nr(d_chan_nr, &ch_type, &ch_subch, &ch_ts);
	LOGP(DRR, LOGL_NOTICE, "Check param --- bcch_arfcn: %u, maio: %u, hsn: %u, ma_len: %u\n", d_arfcn, d_maio, d_hsn, d_ma_len);
	app_state.cell_id = d_cell_id;
	app_state.lac_id = d_lac_id;
	app_state.http_data.cell_id = d_cell_id;
	app_state.http_data.lac = d_lac_id;
	l1ctl_tx_hopping_args(ms, d_arfcn, 0, d_maio, d_hsn, d_tseq, d_chan_nr,
			d_frame_nr, ch_ts, d_ma_len, d_ma_list, d_cell_id, d_lac_id, d_index_round);
	l1ctl_tx_dm_est_req_h1(ms, d_maio, d_hsn, d_ma_list, d_ma_len,
			d_chan_nr, ch_ts, GSM48_CMODE_SIGN, 0);
	app_state.dch_state = DCH_SDCCH;
	app_state.dch_nr = d_chan_nr;
}

void layer3_app_reset(void)
{
	/* Reset state */
	app_state.ccch_mode = CCCH_MODE_NONE;
	app_state.has_si1 = 0;
	app_state.has_si3 = 0;
	app_state.cell_id = 0;
	app_state.lac_id = 0;
	app_state.neci = 0;
	app_state.dch_badcnt = 0;
	app_state.dch_state = DCH_SDCCH;
	memset(&app_state.cell_arfcns, 0x00, sizeof(app_state.cell_arfcns));

	/* Reset app_state.http_data */
	os_http_clear_buffer(app_state.http_data.plaintext);
	os_http_clear_buffer(app_state.http_data.ciphertext);
	os_http_clear_buffer(app_state.http_data.sdcch);
	os_http_clear_speech_data(&app_state.http_data.speech);
	os_http_clear_http_data(&app_state.http_data);
}

static int signal_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
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
	osmo_signal_register_handler(SS_L1CTL, &signal_cb, NULL);
	layer3_init(ms);

	os_http_init_data(&app_state.http_data, &sys);

	/* Init default value for app_state */
	app_state.http_data.type = GSM_TYPE_VOICE;
	app_state.ms = ms;

	start_updconfig_timer(1,0);
	process_received_imm_ass(ms);
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

