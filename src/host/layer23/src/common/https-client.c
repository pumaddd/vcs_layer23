#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <osmocom/bb/common/https-client.h>
#include <osmocom/bb/common/openssl_hostname_validation.h>
#include <osmocom/bb/common/queue.h>
#include <osmocom/bb/common/base64.h>
#include <osmocom/bb/common/networks.h>
#include <osmocom/bb/common/logging.h>

const char *gsm_type_map[] = { "sms", "voice", "speech" };

static int ignore_cert = 0;
static EV_HTTP_CLIENT *httpclient = NULL;

// utility function for data convert
unsigned char HexChar(char c) {
	if ('0' <= c && c <= '9')
		return (unsigned char) (c - '0');
	if ('A' <= c && c <= 'F')
		return (unsigned char) (c - 'A' + 10);
	if ('a' <= c && c <= 'f')
		return (unsigned char) (c - 'a' + 10);
	return 0xFF;
}

int HexToBin(const char* s, unsigned char * buff, int length) {
	int result;
	if (!s || !buff || length <= 0)
		return -1;

	for (result = 0; *s; ++result) {
		unsigned char msn = HexChar(*s++);
		if (msn == 0xFF)
			return -1;
		unsigned char lsn = HexChar(*s++);
		if (lsn == 0xFF)
			return -1;
		unsigned char bin = (msn << 4) + lsn;

		if (length-- <= 0)
			return -1;
		*buff++ = bin;
	}
	return result;
}

void BinToHex(const unsigned char * buff, int length, char * output,
		int outLength) {
	char binHex[] = "0123456789ABCDEF";

	if (!output || outLength < 4)
		return;
	*output = '\0';

	if (!buff || length <= 0 || outLength <= 2 * length) {
		*output = '\0';
		return;
	}

	for (; length > 0; --length, outLength -= 2) {
		unsigned char byte = *buff++;

		*output++ = binHex[(byte >> 4) & 0x0F];
		*output++ = binHex[byte & 0x0F];
	}
	if (outLength-- <= 0)
		return;
	*output++ = '\0';
}

// ssl util
static pthread_mutex_t *lockarray;

static void lock_callback(int mode, int type, char *file, int line) {
	(void) file;
	(void) line;
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lockarray[type]));
	} else {
		pthread_mutex_unlock(&(lockarray[type]));
	}
}

static unsigned long thread_id(void) {
	unsigned long ret;

	ret = (unsigned long) pthread_self();
	return (ret);
}

void os_ssl_init_locks(void) {
	int i;

	lockarray = (pthread_mutex_t *) OPENSSL_malloc(
			CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(lockarray[i]), NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)()) thread_id);
	CRYPTO_set_locking_callback(
			(void (*)(int, int, const char*, int)) lock_callback);
}

void os_ssl_kill_locks(void) {
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lockarray[i]));

	OPENSSL_free(lockarray);
}

// http client function
int ccch_quit;
int is_send_request;
static void http_connection_closed(struct evhttp_connection *conn, void *arg) {
	LOGP(DMEAS, LOGL_NOTICE, "Connection is being cleaned up\n");
	if (arg != NULL) {
		EV_HTTP_CLIENT *pHttpClient = (EV_HTTP_CLIENT *) arg;
		pHttpClient->connected = 0;
	}
}

static void http_request_done(struct evhttp_request *req, void *ctx) {
	char buffer[MAX_RECEIVE_BUF_SIZE];
	int nread;
	int count = 0;

	if (req == NULL) {
		/* If req is NULL, it means an error occurred, but
		 * sadly we are mostly left guessing what the error
		 * might have been.  We'll do our best... */
		struct bufferevent *bev = (struct bufferevent *) ctx;
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();
		LOGP(DMEAS, LOGL_NOTICE,
				"some request failed - no idea which one though!\n");
		/* Print out the OpenSSL error queue that libevent
		 * squirreled away for us, if any. */
		while ((oslerr = bufferevent_get_openssl_error(bev))) {
			ERR_error_string_n(oslerr, buffer, sizeof(buffer));
			LOGP(DMEAS, LOGL_NOTICE, "%s\n", buffer);
			printed_err = 1;
		}
		/* If the OpenSSL error queue was empty, maybe it was a
		 * socket error; let's try printing that. */
		if (!printed_err)
			LOGP(DMEAS, LOGL_NOTICE, "socket error = %s (%d)\n",
					evutil_socket_error_to_string(errcode), errcode);
		ccch_quit = 2;
		return;
	}

	LOGP(DMEAS, LOGL_NOTICE, "Response line: %d %s\n",
			evhttp_request_get_response_code(req),
			evhttp_request_get_response_code_line(req));

	if (evhttp_request_get_response_code(req) != 200) {
//#ifndef UNUSED_BLOCK
		while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
				buffer, sizeof(buffer))) > 0) {
			buffer[nread] = '\0';
			//l23_update_kc(buffer);
			LOGP(DMEAS, LOGL_NOTICE, "%s\n", buffer);
		}
//#endif
//		ccch_quit = 2;
		if (ccch_quit == 1){
			ccch_quit = 2;
		}
		if (is_send_request == 1){
//			LOGP(DMEAS, LOGL_NOTICE, "---------------------------- quit here: \n");
			ccch_quit = 2;
		}
		return;
	}
	if (is_send_request == 1) {
		is_send_request = 0;
		ccch_quit = 0;
		LOGP(DMEAS, LOGL_NOTICE, "Reset is_send_request and ccch_quit\n");
	}
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
			buffer, sizeof(buffer))) > 0) {
		buffer[nread] = '\0';
		/* Not update kc via layer23 */
		// l23_update_kc(buffer);
	}
	if (ccch_quit == 1) {
		ccch_quit = 2;
	}
}

static void err_openssl(const char *func) {
	LOGP(DMEAS, LOGL_NOTICE, "%s failed:\n", func);
}

#ifndef _WIN32
/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg) {
	char cert_str[256];
	const char *host = (const char *) arg;
	const char *res_str = "X509_verify_cert failed";
	HostnameValidationResult res = Error;

	/* This is the function that OpenSSL would call if we hadn't called
	 * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
	 * the default functionality, rather than replacing it. */
	int ok_so_far = 0;

	X509 *server_cert = NULL;

	if (ignore_cert) {
		return 1;
	}

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (ok_so_far) {
		res = validate_hostname(host, server_cert);

		switch (res) {
		case MatchFound:
			res_str = "MatchFound";
			break;
		case MatchNotFound:
			res_str = "MatchNotFound";
			break;
		case NoSANPresent:
			res_str = "NoSANPresent";
			break;
		case MalformedCertificate:
			res_str = "MalformedCertificate";
			break;
		case Error:
			res_str = "Error";
			break;
		default:
			res_str = "WTF!";
			break;
		}
	}

	X509_NAME_oneline(X509_get_subject_name(server_cert), cert_str,
			sizeof(cert_str));

	if (res == MatchFound) {
		LOGP(DMEAS, LOGL_NOTICE, "https server '%s' has this certificate, "
				"which looks good to me:\n%s\n", host, cert_str);
		return 1;
	} else {
		LOGP(DMEAS, LOGL_NOTICE,
				"Got '%s' for hostname '%s' and certificate:\n%s\n", res_str,
				host, cert_str);
		return 0;
	}
}
#endif

int http_client_reconnect(EV_HTTP_CLIENT *pHttpClient, const char *url) {
	http_client_cleanup(pHttpClient);

	if (http_client_init(url, httpclient) == 0) {
		httpclient->connected = 1;
	} else {
		httpclient->connected = 0;
	}
	return httpclient->connected;
}

int http_client_init(const char* hosturl, EV_HTTP_CLIENT *pHttpClient) {
	int result = 0;
	struct evhttp_uri *http_uri;
	char *scheme;
	char *host;
	int r;
	enum bufferevent_options bevopts = 0;

#ifdef _WIN32
    {
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;

		wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0) {
			LOGP(DMEAS, LOGL_NOTICE, "WSAStartup failed with error: %d\n", err);
			goto error;
		}
	}
#endif // _WIN32

	LOGP(DMEAS, LOGL_NOTICE, "http_client_init => hosturl = %s\n", hosturl);
	http_uri = evhttp_uri_parse(hosturl);
	if (http_uri == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "malformed url\n");
		goto error;
	}

	scheme = evhttp_uri_get_scheme(http_uri);
	if (scheme == NULL
			|| (strcasecmp(scheme, "https") != 0
					&& strcasecmp(scheme, "http") != 0)) {
		LOGP(DMEAS, LOGL_NOTICE, "url must be http or https\n");
		goto error;
	}

	host = evhttp_uri_get_host(http_uri);
	if (pHttpClient->host == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "url must have a host\n");
		goto error;
	}
	snprintf(pHttpClient->host, sizeof(pHttpClient->host), "%s", host);

	pHttpClient->port = evhttp_uri_get_port(http_uri);
	if (pHttpClient->port == -1) {
		pHttpClient->port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
	}

	/* This isn't strictly necessary... OpenSSL performs RAND_poll
	 * automatically on first use of random number generator. */
	r = RAND_poll();
	if (r == 0) {
		err_openssl("RAND_poll");
		goto error;
	}

	/* Create a new OpenSSL context */
	pHttpClient->ssl_ctx = SSL_CTX_new(TLSv1_2_method());
	if (!pHttpClient->ssl_ctx) {
		err_openssl("SSL_CTX_new");
		goto error;
	}

	SSL_CTX_set_options(pHttpClient->ssl_ctx,
			SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

#ifndef _WIN32
	/* TODO: Add certificate loading on Windows as well */

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	if (1
			!= SSL_CTX_load_verify_locations(pHttpClient->ssl_ctx,
					pHttpClient->crt, NULL)) {
		err_openssl("SSL_CTX_load_verify_locations");
		goto error;
	}
	/* Ask OpenSSL to verify the server certificate.  Note that this
	 * does NOT include verifying that the hostname is correct.
	 * So, by itself, this means anyone with any legitimate
	 * CA-issued certificate for any website, can impersonate any
	 * other website in the world.  This is not good.  See "The
	 * Most Dangerous Code in the World" article at
	 * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
	 */
	SSL_CTX_set_verify(pHttpClient->ssl_ctx, SSL_VERIFY_NONE, NULL);
//    SSL_CTX_set_verify(pHttpClient->ssl_ctx, SSL_VERIFY_PEER, NULL);
	/* This is how we solve the problem mentioned in the previous
	 * comment.  We "wrap" OpenSSL's validation routine in our
	 * own routine, which also validates the hostname by calling
	 * the code provided by iSECPartners.  Note that even though
	 * the "Everything You've Always Wanted to Know About
	 * Certificate Validation With OpenSSL (But Were Afraid to
	 * Ask)" paper from iSECPartners says very explicitly not to
	 * call SSL_CTX_set_cert_verify_callback (at the bottom of
	 * page 2), what we're doing here is safe because our
	 * cert_verify_callback() calls X509_verify_cert(), which is
	 * OpenSSL's built-in routine which would have been called if
	 * we hadn't set the callback.  Therefore, we're just
	 * "wrapping" OpenSSL's routine, not replacing it. */
	SSL_CTX_set_cert_verify_callback(pHttpClient->ssl_ctx, cert_verify_callback,
			(void *) pHttpClient->host);

	//
	r = SSL_CTX_use_certificate_file(pHttpClient->ssl_ctx, pHttpClient->crt,
	SSL_FILETYPE_PEM);
	if (r != 1) {
		LOGP(DMEAS, LOGL_NOTICE, "Error: cannot load certificate file.\n");
		goto error;
	}

	/* load private key */
	r = SSL_CTX_use_PrivateKey_file(pHttpClient->ssl_ctx, pHttpClient->pem,
	SSL_FILETYPE_PEM);
	if (r != 1) {
		LOGP(DMEAS, LOGL_NOTICE, "Error: cannot load private key file.\n");
		goto error;
	}

	/* check if the private key is valid */
	r = SSL_CTX_check_private_key(pHttpClient->ssl_ctx);
	if (r != 1) {
		LOGP(DMEAS, LOGL_NOTICE, "Error: checking the private key failed. \n");
		goto error;
	}
#else // _WIN32
    (void)crt;
#endif // _WIN32

	// Create OpenSSL bufferevent and stack evhttp on top of it
	pHttpClient->ssl = SSL_new(pHttpClient->ssl_ctx);
	if (pHttpClient->ssl == NULL) {
		err_openssl("SSL_new()");
		goto error;
	}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(pHttpClient->ssl, pHttpClient->host);
#endif

	bevopts = (BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE
			| BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_DEFER_CALLBACKS);
	if (strcasecmp(scheme, "http") == 0) {
		pHttpClient->type = HTTP;
		pHttpClient->bev = bufferevent_socket_new(pHttpClient->base, -1,
				bevopts);
	} else {
		pHttpClient->type = HTTPS;
		pHttpClient->bev = bufferevent_openssl_socket_new(pHttpClient->base, -1,
				pHttpClient->ssl, BUFFEREVENT_SSL_CONNECTING, bevopts);
	}

	if (pHttpClient->bev == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "bufferevent_openssl_socket_new() failed\n");
		goto error;
	}

	bufferevent_openssl_set_allow_dirty_shutdown(pHttpClient->bev, 1);

	// For simplicity, we let DNS resolution block. Everything else should be
	// asynchronous though.
	pHttpClient->evcon = evhttp_connection_base_bufferevent_new(
			pHttpClient->base, NULL, pHttpClient->bev, pHttpClient->host,
			pHttpClient->port);
	if (pHttpClient->evcon == NULL) {
		LOGP(DMEAS, LOGL_NOTICE,
				"evhttp_connection_base_bufferevent_new() failed\n");
		goto error;
	}

	evhttp_connection_set_closecb(pHttpClient->evcon, http_connection_closed,
			pHttpClient);

	if (pHttpClient->retries > 0) {
		evhttp_connection_set_retries(pHttpClient->evcon, pHttpClient->retries);
	}
	if (pHttpClient->timeout >= 0) {
		evhttp_connection_set_timeout(pHttpClient->evcon, pHttpClient->timeout);
	}

	result = 0;
	goto cleanup;
	error: result = 1;
	if (pHttpClient->ssl_ctx) {
		SSL_CTX_free(pHttpClient->ssl_ctx);
		pHttpClient->ssl_ctx = NULL;
	}
	cleanup: if (http_uri)
		evhttp_uri_free(http_uri);

	return result;
}

int http_client_cleanup(EV_HTTP_CLIENT *pHttpClient) {
#ifndef UNUSED_BLOCK
	if (pHttpClient->evcon) {
		evhttp_connection_free(pHttpClient->evcon);
    }
#endif
	if (pHttpClient->ssl_ctx) {
		SSL_CTX_free(pHttpClient->ssl_ctx);
	}

	return 0;
}

int http_client_req(EV_HTTP_CLIENT *pHttpClient, const char *url,
		const char *data, const uint64_t data_len) {
	int r;
	int result = 0;
	struct evhttp_uri *http_uri;
	char uri[512];
	char *path;
	char *query;

	struct evkeyvalq *output_headers;
	struct evbuffer *output_buffer;

	// check connection
	if (pHttpClient == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "http_client_req => pHttpClient == NULL\n");
		goto error;
	}

	if (pHttpClient->connected == 0) {
		if (http_client_reconnect(pHttpClient, url) == 0) {
			LOGP(DMEAS, LOGL_NOTICE, "http_client_reconnect is failed\n");
			goto error;
		}
	}

	http_uri = evhttp_uri_parse(url);
	if (http_uri == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "malformed url\n");
		goto error;
	}

	path = evhttp_uri_get_path(http_uri);
	if (strlen(path) == 0) {
		path = "/";
	}

	query = evhttp_uri_get_query(http_uri);
	if (query == NULL) {
		snprintf(uri, sizeof(uri) - 1, "%s", path);
	} else {
		snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
	}
	uri[sizeof(uri) - 1] = '\0';

	// Fire off the request
	if (pHttpClient->bev == NULL || pHttpClient->evcon == NULL) {
		pHttpClient->connected = 0;
		LOGP(DMEAS, LOGL_NOTICE, "connection is closed\n");
		goto error;
	}

	pHttpClient->req = evhttp_request_new(http_request_done, pHttpClient->bev);
	if (pHttpClient->req == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "evhttp_request_new() failed\n");
		goto error;
	}

	output_headers = evhttp_request_get_output_headers(pHttpClient->req);
	evhttp_add_header(output_headers, "Host", pHttpClient->host);
	evhttp_add_header(output_headers, "Content-Type", "application/json");
	evhttp_add_header(output_headers, "Connection", "keep-alive");
//    evhttp_add_header(output_headers, "Connection", "close");

	if (data != NULL && data_len != 0) {
		char buf[24];
		output_buffer = evhttp_request_get_output_buffer(pHttpClient->req);
		evbuffer_add(output_buffer, data, data_len);
		evutil_snprintf(buf, sizeof(buf) - 1, "%lu", data_len);
		evhttp_add_header(output_headers, "Content-Length", buf);
		r = evhttp_make_request(pHttpClient->evcon, pHttpClient->req,
				EVHTTP_REQ_POST, uri);
	} else {
		r = evhttp_make_request(pHttpClient->evcon, pHttpClient->req,
				EVHTTP_REQ_GET, uri);
	}

	if (r != 0) {
		LOGP(DMEAS, LOGL_NOTICE, "evhttp_make_request() failed\n");
		goto error;
	}

	result = 0;
	goto cleanup;
	error: result = 1;
	cleanup: if (http_uri)
		evhttp_uri_free(http_uri);

	return result;
}

void event_base_monitoring(void *param) {
	EV_HTTP_CLIENT *pHttpClient = (EV_HTTP_CLIENT *) param;

	while (1) {
		event_base_loop(pHttpClient->base, EVLOOP_NO_EXIT_ON_EMPTY);
		usleep(100);
	}
}

void os_http_init_data(EV_HTTP_DATA *data, const T_SYSCONF *conf) {
	if (data != NULL) {
		memset(data, 0, sizeof(EV_HTTP_DATA));
		data->si5 = evbuffer_new();
		data->si6 = evbuffer_new();
		data->si5ter = evbuffer_new();
		data->plaintext = evbuffer_new();
		data->ciphertext = evbuffer_new();
		data->sdcch = evbuffer_new();
		data->arfcn = conf->workers[conf->id].arfcn;

		os_http_init_speech_data(&data->speech);
	}
}

void os_http_clear_buffer(struct evbuffer *buf) {
	if (buf != NULL) {
		evbuffer_drain(buf, (int) evbuffer_get_length(buf));
	}
}

void os_http_clear_http_data(EV_HTTP_DATA *data) {
	if (data != NULL) {
		os_http_clear_buffer(data->si5);
		os_http_clear_buffer(data->si6);
		os_http_clear_buffer(data->si5ter);
		os_http_clear_buffer(data->plaintext);
		os_http_clear_buffer(data->ciphertext);
		os_http_clear_buffer(data->sdcch);
	}
}

void os_http_free_http_data(EV_HTTP_DATA *data) {
	if (data != NULL) {
		evbuffer_free(data->si5);
		evbuffer_free(data->si6);
		evbuffer_free(data->si5ter);
		evbuffer_free(data->plaintext);
		evbuffer_free(data->ciphertext);
		evbuffer_free(data->sdcch);

		os_http_free_speech_data(&data->speech);
	}
}

void os_http_init_speech_data(EV_SPEECH_DATA *data) {
	if (data != NULL) {
		memset(data, 0, sizeof(EV_SPEECH_DATA));
		data->speech_data = evbuffer_new();

		data->remote_addr = evbuffer_new();
		data->local_addr = evbuffer_new();
	}
}
void os_http_clear_speech_data(EV_SPEECH_DATA *data) {
	if (data != NULL) {
		os_http_clear_buffer(data->speech_data);
	}
}
void os_http_free_speech_data(EV_SPEECH_DATA *data) {
	if (data != NULL) {
		evbuffer_free(data->speech_data);
	}
}

int os_http_client_reconnect() {
	if (httpclient != NULL)
		return http_client_reconnect(httpclient, httpclient->http_url);
	return -1;
}

int os_http_client_init(const T_SYSCONF *conf) {
	struct event_config *cfg;
	evthread_use_pthreads();
	event_init();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif

	os_ssl_init_locks();

	httpclient = (EV_HTTP_CLIENT*) malloc(sizeof(EV_HTTP_CLIENT));
	if (httpclient == NULL) {
		LOGP(DMEAS, LOGL_NOTICE,
				"os_http_client_init init httpclient failed\n");
		return -1;
	}

	memset(httpclient, 0, sizeof(EV_HTTP_CLIENT));

	httpclient->device_id = conf->device_id;
	// Create event base
	if (!httpclient->base) {
		cfg = event_config_new();
		if (!cfg)
			return (-1);

		httpclient->base = event_base_new_with_config(cfg);
		event_config_free(cfg);
	}

	// init http client
	ignore_cert = conf->workers[conf->id].http_ignore_cert;
	httpclient->crt = conf->workers[conf->id].http_crt_path;
	httpclient->pem = conf->workers[conf->id].http_pem_path;
	httpclient->retries = conf->workers[conf->id].http_retries;
	httpclient->timeout = conf->workers[conf->id].http_timeout;
	httpclient->http_url = conf->workers[conf->id].http_url;
	httpclient->settings_url = conf->settings_url;

	if (http_client_init(httpclient->http_url, httpclient) == 0) {
		httpclient->connected = 1;
	} else {
		httpclient->connected = 0;
	}

	// create new thread for http_event
	pthread_create(&httpclient->thread, NULL, event_base_monitoring,
			httpclient);
//	pthread_detach(&httpclient->thread);

	// Send test request
//	http_client_req(httpclient, url, data_file);

	return 0;
}

void os_http_client_cleanup() {
	if (httpclient->base)
		event_base_free(httpclient->base);
	http_client_cleanup(httpclient);
	pthread_join(&httpclient->thread, NULL);

	if (httpclient)
		free(httpclient);

	os_ssl_kill_locks();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_cleanup();
	ERR_free_strings();

#ifdef EVENT__HAVE_ERR_REMOVE_THREAD_STATE
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif
	CRYPTO_cleanup_all_ex_data();

	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif /*OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef _WIN32
	WSACleanup();
#endif
}

extern char *b64_sdcch_buff;

int os_http_client_sendreq(EV_HTTP_DATA *data) {
	int result = -1;
	char url[MAX_URL_LEN] = { 0 };
	char mulrate_conf[MAX_NUM_SPEECH_RATE * 2 + 1] = { 0 };

	char *si5 = "";
	char *b64_si5 = NULL;
	char *si6 = "";
	char *b64_si6 = NULL;
	char *si5ter = "";
	char *b64_si5ter = NULL;
	char *plaintext = "";
	char *b64_plaintext = NULL;
	char *ciphertext = "";
	char *b64_ciphertext = NULL;
	char *sdcch = "";
	char *b64_sdcch = NULL;

	char *speech_data = "";
	char *b64_speech_data = NULL;
	int speed_mode = 0;
	char *remote_addr = "";
	char *local_addr = "";

	char *mBuff = NULL;
	mBuff = (char *) malloc(MAX_SEND_BUF_SIZE);
	if (mBuff == NULL) {
		LOGP(DMEAS, LOGL_NOTICE, "os_http_client_sendreq init mBuff failed\n");
		return -1;
	}
	memset(mBuff, 0, MAX_SEND_BUF_SIZE);
	snprintf(url, sizeof(url), "%s?device_id=%s", httpclient->http_url,
			httpclient->device_id);

	if ((int) evbuffer_get_length(data->speech.local_addr) != 0) {
		local_addr = evbuffer_pullup(data->speech.local_addr, -1);
	}
	if ((int) evbuffer_get_length(data->speech.remote_addr) != 0) {
		remote_addr = evbuffer_pullup(data->speech.remote_addr, -1);
	}

	speed_mode = data->speech.speed_mode;
	BinToHex(data->speech.mulrate_conf.data, data->speech.mulrate_conf.length,
			mulrate_conf, sizeof(mulrate_conf));

	if (data->type == GSM_TYPE_SPEECH) {
		b64_speech_data = b64_encode(
				evbuffer_pullup(data->speech.speech_data, -1),
				(int) evbuffer_get_length(data->speech.speech_data));
		if (b64_speech_data != NULL)
			speech_data = b64_speech_data;
	} else {
		b64_si5 = b64_encode(evbuffer_pullup(data->si5, -1),
				(int) evbuffer_get_length(data->si5));
		if (b64_si5 != NULL)
			si5 = b64_si5;
		b64_si6 = b64_encode(evbuffer_pullup(data->si6, -1),
				(int) evbuffer_get_length(data->si6));
		if (b64_si6 != NULL)
			si6 = b64_si6;
		b64_si5ter = b64_encode(evbuffer_pullup(data->si5ter, -1),
				(int) evbuffer_get_length(data->si5ter));
		if (b64_si5ter != NULL)
			si5ter = b64_si5ter;
		b64_plaintext = b64_encode(evbuffer_pullup(data->plaintext, -1),
				(int) evbuffer_get_length(data->plaintext));
		if (b64_plaintext != NULL)
			plaintext = b64_plaintext;
		b64_ciphertext = b64_encode(evbuffer_pullup(data->ciphertext, -1),
				(int) evbuffer_get_length(data->ciphertext));
		if (b64_ciphertext != NULL)
			ciphertext = b64_ciphertext;
		LOGP(DMEAS, LOGL_NOTICE, "Sdcch text len: %d\n", (int) evbuffer_get_length(data->sdcch));
		b64_sdcch = b64_encode(evbuffer_pullup(data->sdcch, -1),
				(int) evbuffer_get_length(data->sdcch));
		if (b64_sdcch != NULL)
			sdcch = b64_sdcch;
		LOGP(DMEAS, LOGL_NOTICE, "B64 Sdcch text len: %d\n", strlen(b64_sdcch));
		b64_sdcch_buff = (char*) malloc(strlen(b64_sdcch) * sizeof(char) + 1);
		if (b64_sdcch_buff == NULL)
		{
			LOGP(DMEAS, LOGL_NOTICE, "Malloc b64_ciphertext_sdcch false\n");
		}
		memset(b64_sdcch_buff, 0, strlen(b64_sdcch) * sizeof(char) + 1);
		strncpy(b64_sdcch_buff, b64_sdcch, strlen(b64_sdcch) * sizeof(char));
	}
#ifndef UNUSED_BLOCK
	LOGP(DMEAS, LOGL_NOTICE, "plaintext = %d, ciphertext = %d, si5 = %d, si6 = %d, si5ter = %d, type = %d (%s), id = %d\n",
			 (int)evbuffer_get_length(data->plaintext),  (int)evbuffer_get_length(data->ciphertext),  (int)evbuffer_get_length(data->si5),
			 (int)evbuffer_get_length(data->si6),  (int)evbuffer_get_length(data->si5ter), data->type, gsm_type_map[data->type], strlen(data->id));

#endif

	if (strlen(speech_data) != 0 || strlen(sdcch) != 0
			|| ((strlen(ciphertext) != 0
					&& (strlen(plaintext) != 0 || strlen(si5) != 0
							|| strlen(si6) != 0 || strlen(si5ter) != 0)))) {
		LOGP(DMEAS, LOGL_NOTICE, "send data with type %s to server\n",
				gsm_type_map[data->type]);

		if (data->type == GSM_TYPE_SPEECH) {
			snprintf(mBuff, MAX_SEND_BUF_SIZE, HTTP_JSON_VOICE_TEMPLATE,
			/* id*/(int) strlen(data->id), data->id,
			/* type*/(int) strlen(gsm_type_map[data->type]),
					gsm_type_map[data->type],
					/* arfcn*/data->arfcn,
					/* speech_data*/data->speech.current_part,
					(int) strlen(speech_data), speech_data, speed_mode,
					/* speed_mode*/speed_mode,
					/* is_end_part*/data->speech.is_end_part,
					/* dch_ciph*/data->speech.dch_ciph,
					/* remote_addr*/(int) strlen(remote_addr), remote_addr,
					/* local_addr*/(int) strlen(local_addr), local_addr,
					/* mulrate_conf*/(int) strlen(mulrate_conf), mulrate_conf,
					/* need_find_speed */ data->need_find_speed);
		} else {
			snprintf(mBuff, MAX_SEND_BUF_SIZE, HTTP_JSON_TEMPLATE,
			/* id*/(int) strlen(data->id), data->id,
			/* si5*/(int) strlen(si5), si5,
			/* si6*/(int) strlen(si6), si6,
			/* si5ter*/(int) strlen(si5ter), si5ter,
			/* plaintext*/(int) strlen(plaintext), plaintext,
			/* ciphertext*/(int) strlen(ciphertext), ciphertext,
			/* sdcch*/(int) strlen(sdcch), sdcch,
			/* type*/(int) strlen(gsm_type_map[data->type]),
					gsm_type_map[data->type],
					/* arfcn*/data->arfcn,
					/* speed_mode*/speed_mode,
					/* is_end_part*/data->speech.is_end_part,
					/* dch_ciph*/data->speech.dch_ciph,
					/* remote_addr*/(int) strlen(remote_addr), remote_addr,
					/* local_addr*/(int) strlen(local_addr), local_addr,
					/* mulrate_conf*/(int) strlen(mulrate_conf), mulrate_conf,
					/* cell_id */(uint16_t) data->cell_id,
					/* lac */(uint16_t) data->lac);
		}

//#ifndef UNUSED_BLOCK
		// LOGP(DMEAS, LOGL_NOTICE, "URL:%s\n", url);
		// LOGP(DMEAS, LOGL_NOTICE, "%s\n", mBuff);
		printf("URL:%s\n", url);
		printf("%s \n", mBuff);
//#endif
		result = http_client_req(httpclient, url, mBuff, strlen(mBuff));
	}

	if (b64_si5)
		free(b64_si5);
	if (b64_si6)
		free(b64_si6);
	if (b64_si5ter)
		free(b64_si5ter);
	if (b64_plaintext)
		free(b64_plaintext);
	if (b64_ciphertext)
		free(b64_ciphertext);
	if (b64_sdcch)
		free(b64_sdcch);

	if (b64_speech_data)
		free(b64_speech_data);

	if (mBuff)
		free(mBuff);
	return result;
}

int os_http_client_update_type(char *reqId, GSM_TYPE type) {
	int result = -1;
	char url[MAX_URL_LEN] = { 0 };

	char *mBuff = NULL;
	mBuff = (char *) malloc(MAX_STATUS_BUF_SIZE);
	if (mBuff == NULL) {
		LOGP(DMEAS, LOGL_NOTICE,
				"os_http_client_update_type init mBuff failed\n");
		return -1;
	}

	if (reqId != NULL) {
		snprintf(url, sizeof(url), "%s?device_id=%s", httpclient->http_url,
				httpclient->device_id);
		LOGP(DMEAS, LOGL_NOTICE, "send update type msg to server %s\n",
				gsm_type_map[type]);

		snprintf(mBuff, MAX_STATUS_BUF_SIZE, HTTP_JSON_TYPEUDP_TEMPLATE,
		/* id*/(int) strlen(reqId), reqId,
		/* type*/(int) strlen(gsm_type_map[type]), gsm_type_map[type]);
		result = http_client_req(httpclient, url, mBuff, strlen(mBuff));
	}

	if (mBuff)
		free(mBuff);
	return result;
}

int os_http_client_cancelreq(char *reqId) {
	char url[MAX_URL_LEN] = { 0 };
	const char *keyword = "cancel";

	LOGP(DMEAS, LOGL_NOTICE, "send cancel request to server\n");
	snprintf(url, sizeof(url), "%s?device_id=%s&id=%s", httpclient->http_url,
			httpclient->device_id, reqId);

	return http_client_req(httpclient, url, NULL, 0);
}

int os_http_client_statusreq(char *reqId) {
	char url[MAX_URL_LEN] = { 0 };
	const char *keyword = "status";

	LOGP(DMEAS, LOGL_NOTICE, "send statusreq to server\n");
	snprintf(url, sizeof(url), "%s?device_id=%s&id=%s", httpclient->http_url,
			httpclient->device_id, reqId);
	LOGP(DMEAS, LOGL_NOTICE, "url: %s\n", url);
	return http_client_req(httpclient, url, NULL, 0);
}

int os_http_client_send_cellinfo(EV_CELL_INFO *cellinfo) {
	int result = -1;
	uint16_t idx;
	char url[MAX_URL_LEN] = { 0 };
	struct evbuffer *cell_list = evbuffer_new();

	char *mBuff = NULL;
	mBuff = (char *) malloc(MAX_SEND_BUF_SIZE);
	memset(mBuff, 0, MAX_SEND_BUF_SIZE);
	if (cellinfo != NULL && cell_list != NULL && mBuff != NULL) {
		if (cellinfo->cell_info_idx
				> 0&& cellinfo->cell_info_idx < MAX_NUM_CELL_INFO) {
			LOGP(DMEAS, LOGL_NOTICE, "send cellinfo to server\n");
			for (idx = 0; idx < cellinfo->cell_info_idx; idx++) {
				EV_CELL_DATA *data = &cellinfo->data[idx];
				if (idx != 0) {
					evbuffer_add_printf(cell_list, ",");
				}
				evbuffer_add_printf(cell_list,
						"{\"arfcn\":\"%d\",\"mcc\":\"%s\",\"mnc\":\"%s\",\"cell\":\"%d\",\"lac\":\"%d\",\"rxlev\":\"%d\"}",
						data->arfcn, gsm_print_mcc(data->mcc),
						gsm_print_mnc(data->mnc), data->cell_id, data->lac,
						data->rxlev);
			}

			snprintf(url, sizeof(url), "%s?device_id=%s", httpclient->http_url,
					httpclient->device_id);

			snprintf(mBuff, MAX_SEND_BUF_SIZE,
					"{\"type\":\"arfcn\",\"device_id\":\"%s\",\"arfcn_list\":[%*s]}",
					httpclient->device_id, (int) evbuffer_get_length(cell_list),
					evbuffer_pullup(cell_list, -1));
//#ifndef UNUSED_BLOCK
			LOGP(DMEAS, LOGL_NOTICE, "url \n%s\n", url);
			LOGP(DMEAS, LOGL_NOTICE, "\n%s\n", mBuff);
//#endif
			result = http_client_req(httpclient, url, mBuff, strlen(mBuff));
		}

	}

	if (mBuff)
		free(mBuff);
	if (cell_list)
		evbuffer_free(cell_list);
	return 0;
}

int os_http_client_update_settings() {
	char url[MAX_URL_LEN] = { 0 };
	const char *keyword = "settings";

	LOGP(DMEAS, LOGL_NOTICE, "send update_settings request to server\n");
	snprintf(url, sizeof(url), "%s?device_id=%s", httpclient->settings_url,
			httpclient->device_id);

	return http_client_req(httpclient, url, NULL, 0);
}
