//
// Created by dainv5 on 2/6/18.
//

#ifndef YAMLLOADER_CONF_H
#define YAMLLOADER_CONF_H

#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <signal.h>

//#define SPEECH_DECODE
#define UNUSED_BLOCK
#define TCH_HOPPING

//#define PHANTAI
#define FREESTATE 0
#define BUSYSTATE 2
#define PROCESS_IMMASS 1


#define MAX_MASTER_SUPPORT 		8
#define MAX_WORKER_SUPPORT 		64
#define MAX_DEVICE_ID_LEN		64
#define MAX_TTY_PATH_LEN        64
#define MAX_SOCKET_PATH_LEN     64
#define MAX_REQ_ID_LEN			256
#define MAX_CRT_PATH_LEN     	256
#define MAX_PEM_PATH_LEN     	256
#define MAX_URL_LEN     		256
#define GSM_KC_LEN				8
#define MAX_PHONE_NUMBER_LEN	33

#define MAX_TIME_RINGING		55  // 45 seconds							
#define MAX_TIME_WAIT_KC		35	// 35 seconds
#define MAX_SPEECH_BLOCK		20	// 20 seconds
#define MAX_NUM_CELL_INFO		128
#define MAX_SEND_CELLINFO_BLOCK	300	// 300 seconds = 5minutes
#define MAX_SEND_UPDATE_SETTING	5	// 15 seconds
#define MAX_RXLEV_THRESHOLD		-95	// -95 dbm
#define MAX_NUM_SPEECH_RATE		128

#define MAX_TARGET_IMSI_TMSI 	32
#define MAX_IMSI_TMSI_LEN 		20

#define HANDOVER_RESYNC_MAX		11
#define TCH_MAX_TIME_RESYNC		5
#define TCH_MAX_BADCNT_RELEASE		50
#define TCH_MAX_BADCNT_TRIGGER_CLONE 20

#define TRIGGER_SIGNAL_NUM		(SIGRTMIN+5)
#define TRIGGER_RESET_SIGNAL	(SIGRTMIN+6)
#define TRIGGER_CLONE_SIGNAL	(SIGRTMIN+7)
#define DCH_WAIT_MAX			4
#define MAX_NEIGHBOUR_LIST		20
#define NEIGHBOUR_SNR_THRESHOLD		5
#define CLOG_LOGGER			0	
#define CLOG_HOSTNAME		"192.168.48.130"
#define CLOG_PORT			8099
#define APP_NAME			"grd_ccch"

#define DATABASE_HOSTNAME		"172.17.0.1"

typedef enum {
	NODE_TYPE_WORKER = 0,
	NODE_TYPE_MASTER,
	NODE_TYPE_CELL_LOG,
} NODE_TYPE;

typedef enum
{
	SIG_FORK = 0,
	SIG_DEATH,
	SIG_HO_FORK,
	SIG_HO_DEATH,
} E_SIG_CLONE;

struct gsm48_imm_ass_shm {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t page_mode;
	struct gsm48_chan_desc chan_desc;
	struct gsm48_req_ref req_ref;
	uint8_t timing_advance;
	uint8_t mob_alloc_len;
	uint8_t mob_alloc[256];
} __attribute__((packed));

typedef struct _workerconf {
	uint8_t id;
	uint16_t arfcn;
	uint16_t sem_key;
	char tty_path[MAX_TTY_PATH_LEN];
	char socket_path[MAX_SOCKET_PATH_LEN];
	NODE_TYPE node_type;
	//http config
	int http_ignore_cert;
	int http_retries;
	int http_timeout;
	char http_crt_path[MAX_CRT_PATH_LEN];
	char http_pem_path[MAX_CRT_PATH_LEN];
	char http_url[MAX_URL_LEN];
} T_WORKERCONF;

typedef struct {
	uint8_t	 length;
	uint16_t arfcn[MAX_MASTER_SUPPORT];
} ARFCNs;

typedef struct {
	uint8_t length;
	uint8_t data[MAX_IMSI_TMSI_LEN];
} IMSI_TMSI;

typedef struct {
	uint8_t	 length;
	IMSI_TMSI tmsi_imsi[MAX_TARGET_IMSI_TMSI];
} IMSI_TMSIs;

typedef struct _multirate_conf {
	uint8_t length;
	uint8_t data[MAX_NUM_SPEECH_RATE];
} T_MULTIRATE_CONFIG;


typedef struct {
	uint16_t arfcn;
	uint16_t cell_id;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	int8_t rxlev;
	int8_t snr;
} T_NEIGHBOOUR_INFO;

typedef struct {
	E_SIG_CLONE sig;
	uint8_t iamroot;
	__pid_t parent;
	__pid_t child;
	uint16_t arfcn;
	uint16_t ma[64];
	uint8_t  ma_len;
	uint8_t chan_mod;
	struct gsm48_chan_desc ch_desc;
	uint8_t kc[8];
	char id[MAX_REQ_ID_LEN];
	char phonenumber[MAX_PHONE_NUMBER_LEN];
	uint8_t local_addr_str[MAX_IMSI_TMSI_LEN * 2 + 1];
	uint8_t	dch_ciph;
	uint8_t current_part;
	uint8_t req_ref;
	T_MULTIRATE_CONFIG multi_rate;
} T_SIGCLONE_CTX;

typedef struct _sharemem {
	__pid_t pid;
	uint8_t state;
	uint32_t semid;
	uint16_t arfcn;
	// uint8_t is_hopping_en;
	uint16_t session_id;
	struct gsm48_imm_ass_shm ia;
	T_SIGCLONE_CTX clone_ctx;
	uint16_t guard[10];
} T_SHAREMEM;

typedef struct _global_sharemem {
	ARFCNs arfcs_list;
	uint8_t reboot_mobile_flag;
	IMSI_TMSIs tmsi_list;
	uint8_t targeted_by_tmsi_imsi;
	uint8_t is_catch_voice;
	uint8_t is_catch_sms;
	uint8_t is_scan_tmsi_enable;
	T_NEIGHBOOUR_INFO neigh_bour_list[MAX_NEIGHBOUR_LIST];
	uint8_t neigbour_busy_flag;
	uint16_t mnc;
	uint16_t mcc;
	uint16_t guard[10];
} T_GLOBAL_SHAREMEM;

typedef struct _sysconf {
	uint8_t id;
	uint16_t shm_key;
	T_SHAREMEM * workers_addr;

	uint8_t has_celllog;
	uint8_t num_master;
	uint8_t total_worker;
	T_WORKERCONF workers[MAX_WORKER_SUPPORT];

	uint8_t max_worker_at_time;
	uint8_t min_worker_at_time;

	char device_id[MAX_DEVICE_ID_LEN];
	char settings_url[MAX_URL_LEN];
	uint16_t mcc;
	uint16_t mnc;
} T_SYSCONF;

extern T_SYSCONF sys;

bool LoadConfig(T_SYSCONF *sysconf, const char* filepath);

#endif //YAMLLOADER_CONF_H
