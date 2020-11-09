#ifndef	_HTTP_CLIENT_H_
#define	_HTTP_CLIENT_H_

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <pthread.h>

#include <osmocom/bb/common/conf.h>

typedef enum { HTTP, HTTPS } HTTP_TYPE;

typedef struct _ev_http_client {
	int connected;
	//
	char* http_url;
	char* settings_url;
    HTTP_TYPE type;
    char host[MAX_URL_LEN];
    int port;
    int retries;
    int timeout;

    //
    struct event_base *base;
    //
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    char *crt;
    char *pem;
    //
    char *device_id;
    //
    struct bufferevent *bev;
    struct evhttp_connection *evcon;
    struct evhttp_request *req;
    // threading
    pthread_t thread;
} EV_HTTP_CLIENT;

typedef struct _ev_cell_data {
	uint16_t arfcn;
	uint16_t cell_id;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	int8_t rxlev;
	uint8_t snr;
} EV_CELL_DATA;

typedef struct _ev_cell_info {
	EV_CELL_DATA data[MAX_NUM_CELL_INFO];
	uint16_t cell_info_idx;
} EV_CELL_INFO;


#define HTTP_JSON_TEMPLATE			"{\"id\":\"%*s\",\"si5\":\"%*s\",\"si6\":\"%*s\",\"si5ter\":\"%*s\",\"plaintext\":\"%*s\",\"ciphertext\":\"%*s\",\"sdcch\":\"%*s\",\"type\":\"%*s\",\"arfcn\":\"%d\",\"speech\":{\"speed_mode\":\"%d\",\"is_end_part\":\"%d\",\"dch_ciph\":\"%d\",\"remote_addr\":\"%*s\",\"local_addr\":\"%*s\",\"mulrate_conf\":\"%*s\",\"cell_id\":\"%d\",\"lac\":\"%d\"}}"
#define HTTP_JSON_VOICE_TEMPLATE	"{\"id\":\"%*s\",\"type\":\"%*s\",\"arfcn\":\"%d\",\"speech\":{\"data%d\":{\"voice\":\"%*s\",\"mode\":\"%d\"},\"speed_mode\":\"%d\",\"is_end_part\":\"%d\",\"dch_ciph\":\"%d\",\"remote_addr\":\"%*s\",\"local_addr\":\"%*s\",\"mulrate_conf\":\"%*s\",\"need_find_speed\":\"%u\"}}"
#define HTTP_JSON_TYPEUDP_TEMPLATE	"{\"id\":\"%*s\",\"type\":\"%*s\"}"
#define MAX_SEND_BUF_SIZE 		10*1024*1024	// 10MB
#define MAX_STATUS_BUF_SIZE 	1024
#define MAX_RECEIVE_BUF_SIZE 	1*1024*1024	// 1MB
#define MAX_URL_LEN 			1024

typedef enum { GSM_TYPE_SMS = 0, GSM_TYPE_VOICE, GSM_TYPE_SPEECH } GSM_TYPE;
extern const char *gsm_type_map[];

typedef struct _ev_speech_data {
	struct evbuffer *speech_data;
	int speed_mode;
	uint8_t current_part;
	time_t last_send_time;
	uint8_t is_end_part;
	uint8_t dch_ciph;
	struct evbuffer *remote_addr;
	struct evbuffer *local_addr;

	T_MULTIRATE_CONFIG mulrate_conf;
} EV_SPEECH_DATA;


typedef struct _ev_http_data {
	char id[MAX_REQ_ID_LEN];
	struct evbuffer *si5;
	struct evbuffer *si6;
	struct evbuffer *si5ter;
	struct evbuffer *plaintext;
	struct evbuffer *ciphertext;
	struct evbuffer *sdcch;
	int type;
	int arfcn;
	EV_SPEECH_DATA speech;
	uint16_t cell_id;
	uint16_t lac;
	uint8_t need_find_speed;
} EV_HTTP_DATA;

int HexToBin (const char* s, unsigned char * buff, int length);
void BinToHex (const unsigned char * buff, int length, char * output, int outLength);

int http_client_reconnect(EV_HTTP_CLIENT *pHttpClient, const char *url);

int http_client_init(const char* hosturl, EV_HTTP_CLIENT *pHttpClient);
int http_client_cleanup(EV_HTTP_CLIENT *pHttpClient);
int http_client_req(EV_HTTP_CLIENT *pHttpClient, const char *url, const char *data, const uint64_t data_len);

void os_http_init_data(EV_HTTP_DATA *data, const T_SYSCONF *conf);
void os_http_clear_buffer(struct evbuffer *buf);
void os_http_clear_http_data(EV_HTTP_DATA *data);
void os_http_free_http_data(EV_HTTP_DATA *data);

void os_http_init_speech_data(EV_SPEECH_DATA *data);
void os_http_clear_speech_data(EV_SPEECH_DATA *data);
void os_http_free_speech_data(EV_SPEECH_DATA *data);

int os_http_client_reconnect();
int os_http_client_init(const T_SYSCONF *conf);
void os_http_client_cleanup();
int os_http_client_sendreq(EV_HTTP_DATA *data);
int os_http_client_update_type(char *reqId, GSM_TYPE type);
int os_http_client_cancelreq(char *reqId);
int os_http_client_statusreq(char *reqId);
int os_http_client_send_cellinfo(EV_CELL_INFO *cellinfo);
int os_http_client_update_settings();

#endif	/* !_HTTP_CLIENT_H_ */
