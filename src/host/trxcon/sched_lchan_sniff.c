#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/bits.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/coding/gsm0503_coding.h>

#include "l1ctl_proto.h"
#include "scheduler.h"
#include "sched_trx.h"
#include "logging.h"
#include "trx_if.h"
#include "l1ctl.h"

int rx_burst_fn(struct trx_instance *trx, struct trx_ts *ts,
	struct trx_lchan_state *lchan, uint32_t fn, uint8_t bid,
	sbit_t *bits, int8_t rssi, int16_t toa256, uint8_t snr)
{
	const struct trx_lchan_desc *lchan_desc;
    struct l1ctl_burst_ind bi_hdr;
	sbit_t *buffer;
	ubit_t ubits[148];
        
    lchan_desc = &trx_lchan_desc[lchan->type];
    bi_hdr.frame_nr = htonl(fn);
    bi_hdr.band_arfcn = htons(trx->band_arfcn);
    bi_hdr.chan_nr = lchan_desc->chan_nr | ts->index;
    bi_hdr.snr = snr;
    bi_hdr.flags = (bid & 0x03) | (lchan_desc->link_id == TRX_CH_LID_SACCH ? BI_FLG_SACCH : 0);
	bi_hdr.rx_level = dbm2rxlev(rssi);
    // LOGP(DSCHD, LOGL_ERROR, "rx_burst_fn: %d -- %s -- arfcn: %d -- snr: %x\n", fn,  !!(trx->band_arfcn & 0x4000)?"uplink": "\tdownlink",trx->band_arfcn ,snr);
	
	/* TODO Can loi giai thich */
    // if (bid) {
	// 	/* RX level: 0 .. 63 in typical GSM notation (dBm + 110) */
	// 	bi_hdr.rx_level = dbm2rxlev(rssi);
	// } else {
	// 	/* No measurements, assuming the worst */
	// 	bi_hdr.rx_level = dbm2rxlev(rssi);
	// }
  
    osmo_sbit2ubit((ubit_t*)ubits, (sbit_t *)(bits + 3), 57);
	osmo_sbit2ubit((ubit_t*)(ubits + 57), (sbit_t *)(bits + 88), 57);
	osmo_ubit2pbit_ext(bi_hdr.bits, 0, ubits, 0, 116, 0);
	return l1ctl_tx_burst_ind(trx->l1l, &bi_hdr);
}
