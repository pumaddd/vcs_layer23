#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>

#include "scheduler.h"
#include "sched_trx.h"

/* Forward declaration to avoid mutual include */
struct l1ctl_link;

enum trx_fsm_states {
	TRX_STATE_OFFLINE = 0,
	TRX_STATE_IDLE,
	TRX_STATE_ACTIVE,
	TRX_STATE_RSP_WAIT,
};

struct trx_instance {
	struct osmo_fd trx_ofd_ctrl;
	struct osmo_fd trx_ofd_data;

	struct osmo_timer_list trx_ctrl_timer;
	struct llist_head trx_ctrl_list;
	struct osmo_fsm_inst *fsm;

	/* HACK: we need proper state machines */
	uint32_t prev_state;
	bool powered_up;

	/* GSM L1 specific */
	uint16_t pm_band_arfcn_start;
	uint16_t pm_band_arfcn_stop;
	uint16_t band_arfcn;
	uint8_t tx_power;
	uint8_t bsic;
	uint8_t tsc;
	int8_t ta;

	/* Scheduler stuff */
	struct trx_sched sched;
	struct trx_ts *ts_list[TRX_TS_COUNT];

	/* Bind L1CTL link */
	struct l1ctl_link *l1l;
};

struct trx_ctrl_msg {
	struct llist_head list;
	char cmd[128];
	int retry_cnt;
	int critical;
	int cmd_len;
};

struct trx_instance *trx_if_open(void *tall_ctx,
	const char *local_host, const char *remote_host, uint16_t port);
void trx_if_flush_ctrl(struct trx_instance *trx);
void trx_if_close(struct trx_instance *trx);

int trx_if_cmd_poweron(struct trx_instance *trx);
int trx_if_cmd_poweroff(struct trx_instance *trx);
int trx_if_cmd_echo(struct trx_instance *trx);

int trx_if_cmd_setta(struct trx_instance *trx, int8_t ta);

int trx_if_cmd_rxtune(struct trx_instance *trx, uint16_t band_arfcn);
int trx_if_cmd_txtune(struct trx_instance *trx, uint16_t band_arfcn);

int trx_if_cmd_setslot(struct trx_instance *trx, uint8_t tn, uint8_t type);
int trx_if_cmd_setfh(struct trx_instance *trx, uint8_t hsn,
	uint8_t maio, uint16_t *ma, size_t ma_len);

int trx_if_cmd_measure(struct trx_instance *trx,
	uint16_t band_arfcn_start, uint16_t band_arfcn_stop);

int trx_if_tx_burst(struct trx_instance *trx, uint8_t tn, uint32_t fn,
	uint8_t pwr, const ubit_t *bits);

int trx_if_cmd_set_arfcn(struct trx_instance *trx, uint16_t arfcn, uint64_t sample_start, uint16_t cell_id, uint16_t lac_id, uint32_t index_round);

int trx_if_cmd_set_hopping_args(struct trx_instance *trx, uint16_t arfcn, uint16_t old_bcch_arfcn,
								uint8_t maio, uint8_t hsn, uint8_t tseq, uint32_t frame_nr, uint8_t ma_len,
								uint16_t* ma, uint16_t cell_id, uint16_t lac_id, uint8_t time_slot, uint32_t index_round);

int trx_if_send_wait_kc(struct trx_instance *trx, uint8_t state);
int trx_if_send_cell_lac(struct trx_instance *trx, uint16_t cell_id, uint16_t lac_id);
