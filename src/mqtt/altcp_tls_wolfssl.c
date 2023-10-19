#define PLATFORM_BEKEN 1
#define ENABLE_MQTT_TLS 1

#include "obk_config.h"

#if PLATFORM_BEKEN && ENABLE_MQTT_TLS
#include "lwip/opt.h"
#include "altcp_tls_wolfssl.h"
#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/debug.h"

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/priv/altcp_priv.h"

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "../logging/logging.h"
#include "wolfssl/wolfcrypt/logging.h"

#include <string.h>

static char* err_msg;
char* toHex(char* s, int len);
char* toHex(char* s, int len)
{
	int i = 0;
	if (!err_msg) {
		err_msg = mem_calloc(100, sizeof(char));
	}
	memset(err_msg, 0, 100);
	if (s && len > 0) {
		if (len > 30) {
			len = 30;
		}
		for (i = 0; i < len; ++i)
		{
			sprintf(&err_msg[i * 3], " %02X", s[i]);
		}
	}
	return err_msg;
}
/*
*/

#ifdef DEBUG_WOLFSSL
void ObkLoggingCallback(const int logLevel, const char* const logMessage);
void ObkLoggingCallback(const int logLevel, const char* const logMessage)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, logMessage);
}
#endif //DEBUG_WOLFSSL

#ifdef CUSTOM_RAND_GENERATE_BLOCK
#include "fake_clock_pub.h"
int wolfssl_custom_random(unsigned char* buf, unsigned int len)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->wolfssl_custom_random len(%u)", len);
	srand(fclk_get_second());
	while (len--) {
		*buf++ = rand() % 255;
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-wolfssl_custom_random ret(%u)", 0);
	return 0;
}
#endif //CUSTOM_RAND_GENERATE_BLOCK

struct altcp_tls_config*
	altcp_tls_create_config_client(const u8_t* ca, size_t ca_len)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_tls_create_config_client ca_len(%d)", (int)ca_len);
	int ret;

#ifdef DEBUG_WOLFSSL
	wolfSSL_SetLoggingCb(ObkLoggingCallback);
	wolfSSL_Debugging_ON();
#endif

	struct altcp_tls_config* conf;
	WOLFSSL_METHOD* method;

	conf = mem_calloc(1, sizeof(struct altcp_tls_config));
	if (!conf)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client (!conf)");
		return NULL;
	}

	/* initialize wolfssl library: */
	if (wolfSSL_Init() != WOLFSSL_SUCCESS)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client (wolfSSL_Init() != WOLFSSL_SUCCESS)");
		altcp_wolfssl_free(conf, NULL);
		return NULL;
	}
	method = wolfTLSv1_2_client_method();

	/* make ssl context */
	if ((conf->ctx = wolfSSL_CTX_new(method)) == NULL)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client ((conf->ctx = wolfSSL_CTX_new(method)) == NULL)");
		altcp_wolfssl_free(conf, NULL);
		return NULL;
	}

	/* Add cert to ctx FOR TEST  */
	// ca = test_cert;
	// ca_len = sizeof(test_cert);

	if (ca != NULL && ca_len > 0)
	{
		ret = wolfSSL_CTX_load_verify_buffer(conf->ctx, ca, ca_len, SSL_FILETYPE_PEM);
		if (ret != WOLFSSL_SUCCESS)
		{
#ifdef NO_ERROR_STRINGS
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client fail init certs ret(%d)");
#else
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client fail init certs ret(%d) %s",
				ret, wolfSSL_ERR_reason_error_string(ret));
#endif
			altcp_wolfssl_free(conf, NULL);
			return NULL;
		}
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->altcp_tls_create_config_client Cert load successful");
	}
	else {
		/* Disable peer certificate validation for testing */
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->altcp_tls_create_config_client Invalid cert. Disable cert validation");
		wolfSSL_CTX_set_verify(conf->ctx, WOLFSSL_VERIFY_NONE, NULL);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client");
	return conf;
}

struct altcp_pcb*
	altcp_tls_wrap(struct altcp_tls_config* config, struct altcp_pcb* inner_pcb)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_tls_wrap");
	struct altcp_pcb* out_pcb;
	altcp_wolfssl_state* state;
	WOLFSSL* ssl;

	if (!inner_pcb || !config)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_wrap argument error");
		return NULL;
	}

	/* allocate return pcb */
	out_pcb = altcp_alloc();
	if (!out_pcb)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_wrap altcp_alloc");
		return NULL;
	}

	state = mem_calloc(1, sizeof(altcp_wolfssl_state));
	if (!state)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " < -altcp_tls_wrap alooc altcp_wolfssl_state");
		altcp_free(out_pcb);
		return NULL;
	}

	/* make new wolfSSL struct */
	ssl = wolfSSL_new(config->ctx);
	if (!ssl)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_wrap wolfSSL_new (!ssl)");
		altcp_wolfssl_free(NULL, out_pcb);
		altcp_free(out_pcb);
		return NULL;
	}

	out_pcb->state = state;
	out_pcb->inner_conn = inner_pcb;
	out_pcb->fns = &altcp_wolfssl_functions;

	/* tell wolfssl about our I/O functions*/
	wolfSSL_SSLSetIOSend(ssl, altcp_wolfssl_bio_send);
	wolfSSL_SSLSetIORecv(ssl, altcp_wolfssl_bio_recv);
	wolfSSL_SetIOReadCtx(ssl, out_pcb);
	wolfSSL_SetIOWriteCtx(ssl, out_pcb);

	state->ssl = ssl;
	state->connected = 0;
	state->pbuf_offset = 0;

	/* set callback functions */
	altcp_recv(inner_pcb, altcp_wolfssl_lower_recv);
	altcp_sent(inner_pcb, altcp_wolfssl_lower_sent);
	altcp_err(inner_pcb, altcp_wolfssl_lower_err);
	altcp_arg(inner_pcb, out_pcb);

	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_tls_wrap");
	return out_pcb;
}

static err_t
altcp_wolfssl_connect(struct altcp_pcb* conn, const ip_addr_t* ipaddr, u16_t port, altcp_connected_fn connected)
{
	err_t ret;
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_connect");
	if (conn == NULL)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect erro (conn == NULL)");
		return ERR_ARG;
	}
	conn->connected = connected;
	ret = altcp_connect(conn->inner_conn, ipaddr, port, altcp_wolfssl_connected);
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect (%d)", ret);
	return ret;
}

/** Connected callback from lower connection (i.e. TCP).
 */
static err_t
altcp_wolfssl_connected(void* arg, struct altcp_pcb* inner_conn, err_t err)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_connected (%d)", err);

	int ret;
	struct altcp_pcb* conn = (struct altcp_pcb*)arg;
	LWIP_UNUSED_ARG(inner_conn);

	if (!conn || !conn->state)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected error (!conn || !conn->state)");
		return ERR_ARG;
	}
	altcp_wolfssl_state* state = (altcp_wolfssl_state*)conn->state;
	if (!state->ssl)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected error (!state->ssl)");
		altcp_abort(conn);
		return ERR_ARG;
	}

	/* upper connected is called when if error base connect */
	if (err != ERR_OK && conn->connected)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect erro (conn == NULL)");
		return conn->connected(conn->arg, conn, err);
	}

	/* start ssl handshake */
	ret = connect_wolfssl_context(state);
	/* Abort on error*/
	if (ret != ERR_OK) {
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv abort connect_wolfssl_context (%d)", ret);
		altcp_abort(conn);
		return ret;
	}
	/* upper connected is called when handshake is done*/
	if (conn->connected && ret == ERR_OK && state->connected)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <->altcp_wolfssl_lower_recv handshke doen return upper conneted");
		ret = conn->connected(conn->arg, conn, ret);
	}

	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected ret(%d)", ret);
	return ret;
}

static err_t connect_wolfssl_context(altcp_wolfssl_state* state)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->connect_wolfssl_context");
	int ret, err_ssl;
	
	LWIP_ASSERT_CORE_LOCKED();
	ret = wolfSSL_connect(state->ssl);
	if (ret == WOLFSSL_SUCCESS)
	{
		state->connected = 1;
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->Secure connection done!");
		/* TODO adicionar debug com detalhes nivle de certificado */
		//wolfSSL_FreeHandshakeResources(state->ssl);
		return ERR_OK;
	}
	err_ssl = wolfSSL_get_error(state->ssl, 0);
	if (err_ssl == WOLFSSL_ERROR_WANT_READ)
	{
		/* handshake non-blocking socket wants data to be read */
		addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-connect_wolfssl_context ret(%d) WOLFSSL_ERROR_WANT_READ", ERR_OK);
		return ERR_OK;
	}
#ifdef NO_ERROR_STRINGS
	addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-connect_wolfssl_context error ret(%d) err_ssl(%d)", ret, err_ssl);
#else
	addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-connect_wolfssl_context error ret(%d) err_ssl(%d) %s", ret, err_ssl,
		wolfSSL_ERR_error_string(err_ssl, NULL));
#endif

	/* List available cipher suites and curves */
	char ciphers[1024];
	memset(ciphers, 0, 1024);
	int ret_cipher = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));
	if (ret_cipher != WOLFSSL_SUCCESS)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, "Error load enabled ciphes ret(%d)", ret);
	}
	else {
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, "CIPHERS: %s", ciphers);
	}
	addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, "CURVE: %s", wolfSSL_get_curve_name(state->ssl));
	return ERR_ABRT;
}

int altcp_wolfssl_bio_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_bio_send V1022 sz(%d) %s", sz, toHex(buf, sz));
	//addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_bio_send sz(%d)", sz);
	err_t err;
	int ret = 0;
	struct altcp_pcb* out_pcb;
	LWIP_UNUSED_ARG(ssl);

	if (!ctx || !buf || sz < 1)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_send error (!ctx || !buf || sz < 1)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	out_pcb = (struct altcp_pcb*)ctx;
	if (!out_pcb->inner_conn) {
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_send error (!out_pcb->out_pcb->inner_conn)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	LWIP_ASSERT_CORE_LOCKED();
	err = altcp_write(out_pcb->inner_conn, buf, sz, TCP_WRITE_FLAG_MORE);
	if (err == ERR_OK)
	{
		ret = sz;
	}
	else
	{
		ret = WOLFSSL_CBIO_ERR_GENERAL;
	}

	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_send ret(%d) sz(%d)", ret, sz);
	return ret;
}

int altcp_wolfssl_bio_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_bio_recv len(%d)", sz);

	u16_t ret;
	struct altcp_pcb* out_pcb;
	altcp_wolfssl_state* state;
	LWIP_UNUSED_ARG(ssl);
	if (!ctx || sz < 1)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv error (!ctx || sz < 1)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	out_pcb = (struct altcp_pcb*)ctx;
	if (!out_pcb->state)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv error (!out_pcb->state)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	state = (altcp_wolfssl_state*)out_pcb->state;

	if (!state->buf || (state->buf->tot_len - state->pbuf_offset) < sz)
	{
		addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv WOLFSSL_CBIO_ERR_WANT_READ");
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}
	else
	{
		ret = pbuf_copy_partial(state->buf, buf, sz, state->pbuf_offset);
		if (ret > 0)
		{
			//struct pbuf* head = state->buf;
			state->buf = pbuf_skip(state->buf, (ret + state->pbuf_offset), &state->pbuf_offset);
			/*
			if (head != state->buf){
				addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv buf read (%d)", ret);
				pbuf_free(head);
				addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv buf free (%d)", head->len);
				head = NULL;
			}
			*/
		}
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv (%d)/(%d)", ret, sz);
	return ret;
}

/** Receive callback function called from tcp lower
 * This function mainly chain received pbuf inta a actual.
 * If SSL handshake not done, just chain the received pbuf
 * If SSL handshake done, decrypt the payload into a new pbuf and chain
 */
static err_t altcp_wolfssl_lower_recv(void* cb, struct altcp_pcb* pcb, struct pbuf* p, err_t err)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_recv (%d) %s", (p ? p->tot_len : 0), toHex(p->payload, p->len));
	//addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_recv (%d)", (p ? p->tot_len : 0));
	altcp_wolfssl_state* state;
	struct altcp_pcb* out_pcb;
	int sz, err_ssl;
	err_t ret = ERR_OK;

	if (!pcb || !p || !cb)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv error (!pcb || !p || !cb)");
		return ERR_ARG;
	}
	out_pcb = (struct altcp_pcb*)cb;
	if (!out_pcb->state)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv error (!out_pcb->state)");
		altcp_abort(out_pcb);
		return ERR_ARG;
	}
	state = (altcp_wolfssl_state*)out_pcb->state;

	/* Add received packge to chain */
	if (state->buf == NULL)
	{
		state->buf = p;
		sz = p->tot_len;
	}
	else
	{
		pbuf_chain(state->buf, p);
		sz = p->tot_len;
	}
	if (!state->connected)
	{
		/* Call again connected to complete handshake */
		ret = connect_wolfssl_context(state);
		altcp_recved(pcb, p->tot_len);
		/* Abort on error*/
		if (ret != ERR_OK) {
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv abort connect_wolfssl_context (%d)", ret);
			altcp_abort(pcb);
			return ret;
		}
		/* upper connected is called when handshake is done*/
		if (out_pcb->connected && ret == ERR_OK && state->connected)
		{
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <->altcp_wolfssl_lower_recv handshke doen return upper conneted");
			ret = out_pcb->connected(out_pcb->arg, out_pcb, ret);
		}
	}
	else
	{
		/* decrypt and return to app */
		if (out_pcb->recv)
		{
			char reply[state->buf->tot_len];
			memset(reply, 0, sizeof(reply));
			sz = wolfSSL_read(state->ssl, reply, sizeof(reply));
			if (sz <= 0)
			{
				err_ssl = wolfSSL_get_error(state->ssl, 0);
				if (err_ssl == SSL_ERROR_WANT_READ) {
					addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <->COMO TRATAR AQUI sz(%d) recv(%d)", sz, p->tot_len);
				}
				else
				{
#ifdef NO_ERROR_STRINGS
					addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT,
						" <-altcp_wolfssl_lower_recv wolfSSL_read error ret(%d) ssl_err(%d)");
#else
					addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT,
						" <-altcp_wolfssl_lower_recv wolfSSL_read error ret(%d) ssl_err(%d) %s",
						sz, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL));
#endif
					return ERR_ABRT;
				}
			}
			struct pbuf* pbuf = pbuf_alloc(PBUF_RAW, sz, PBUF_POOL);
			pbuf_take(pbuf, reply, sz);
			ret = out_pcb->recv(out_pcb->arg, out_pcb, pbuf, err);
		}
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv ret(%d) recv(%d)", ret, sz);
	return ret;
}

/** Sent callback from lower connection (i.e. TCP)
 * This only informs the upper layer the number of ACKed bytes.
 * This now take care of TLS added bytes so application receive
 * correct ACKed bytes.
 */
inline static err_t altcp_wolfssl_lower_sent(void* cb, struct altcp_pcb* pcb, u16_t len)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_sent (%d)", len);
	err_t err = ERR_OK;
	if (!cb || !pcb)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent error (!cb|| !pcb)");
		return ERR_ARG;
	}
	struct altcp_pcb* out_pcb = cb;
	if (out_pcb->state == NULL)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent error (out_pcb->state == NULL)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	if (out_pcb->sent)
	{
		err = out_pcb->sent(out_pcb->arg, pcb, len);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent len(%d)", len);
	return err;
}

static void altcp_wolfssl_lower_err(void* arg, err_t err)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_err err(%d)", err);
	struct altcp_pcb* conn = (struct altcp_pcb*)arg;
	if (conn)
	{
		conn->inner_conn = NULL; /* already freed */
		if (conn->err)
		{
			conn->err(conn->arg, err);
		}
		altcp_free(conn);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_err err(%d)", err);
}

/** Write data to a TLS connection. Calls into wolfssl, which in turn calls into
 * lower write to send the encrypted data */
static err_t
altcp_wolfssl_write(struct altcp_pcb* conn, const void* dataptr, u16_t len, u8_t apiflags)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_write len(%d)", len);
	int ret, err_ssl;
	err_t err = ERR_OK;

	altcp_wolfssl_state* state;

	if (!conn || !dataptr || len < 1)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!conn || !dataptr || len < 1)");
		return ERR_ARG;
	}
	state = (altcp_wolfssl_state*)conn->state;
	if (!state || !state->ssl)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!state || !state->ssl)");
		return ERR_ARG;
	}

	LWIP_UNUSED_ARG(apiflags);

	if (!state->connected)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!state->connected)");
		return ERR_ABRT;
	}

	ret = wolfSSL_write(state->ssl, dataptr, len);
	err_ssl = wolfSSL_get_error(state->ssl, 0);
	if (ret <= 0)
	{
#ifdef NO_ERROR_STRINGS
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write wolfSSL_write error ret(%d) err_ssl(%d)");
#else
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write wolfSSL_write error ret(%d) err_ssl(%d) %s",
			ret, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL));
#endif
		return ERR_ABRT;
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write (%d)/(%d)", ret, len);
	return err;
}

static void
altcp_wolfssl_set_poll(struct altcp_pcb* conn, u8_t interval)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_set_poll interval(%d)", interval);

	if (conn != NULL) {
		altcp_poll(conn->inner_conn, altcp_wolfssl_lower_poll, interval);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_set_poll interval(%d)", interval);
}

/** Poll callback from lower connection (i.e. TCP)
 * Just pass this on to the application.
 */
static err_t
altcp_wolfssl_lower_poll(void* arg, struct altcp_pcb* inner_conn)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_poll");
	err_t err = ERR_OK;

	struct altcp_pcb* conn = (struct altcp_pcb*)arg;
	LWIP_UNUSED_ARG(inner_conn);
	if (conn) {
		LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
		if (conn->poll) {
			err = conn->poll(conn->arg, conn);
			if (err) {
				addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_poll (%d))", err);
				return err;
			}
		}
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_poll");
	return err;
}

static void
altcp_wolfssl_abort(struct altcp_pcb* conn)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_abort");

	if (conn != NULL)
	{
		altcp_abort(conn->inner_conn);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_abort");
}

static err_t
altcp_wolfssl_close(struct altcp_pcb* conn)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_close");

	struct altcp_pcb* inner_conn;
	if (!conn || !conn->inner_conn)
	{
		return ERR_VAL;
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_close (!conn || !conn->inner_conn)");
	}
	inner_conn = conn->inner_conn;
	if (inner_conn)
	{
		err_t err;
		altcp_arg(inner_conn, NULL);
		altcp_recv(inner_conn, NULL);
		altcp_sent(inner_conn, NULL);
		altcp_err(inner_conn, NULL);
		err = altcp_close(conn->inner_conn);
		if (err != ERR_OK)
		{
			/* not closed, set up all callbacks again */
			altcp_recv(inner_conn, altcp_wolfssl_lower_recv);
			altcp_sent(inner_conn, altcp_wolfssl_lower_sent);
			altcp_err(inner_conn, altcp_wolfssl_lower_err);
			altcp_arg(inner_conn, conn);
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_close erro (%d)", err);
			return err;
		}
		conn->inner_conn = NULL;
	}
	altcp_free(conn);
	return ERR_OK;
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_close");
}

static void
altcp_wolfssl_dealloc(struct altcp_pcb* conn)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_dealloc");
	/* clean up and free tls state */
	if (conn)
	{
		altcp_wolfssl_state* state = (altcp_wolfssl_state*)conn->state;
		if (state)
		{
			altcp_wolfssl_free(NULL, conn);
			conn->state = NULL;
		}
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_dealloc");
}

void altcp_wolfssl_free(struct altcp_tls_config* conf, struct altcp_pcb* conn)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_free conf(%d) conn(%d)", conf, conn);

	if (conn) {
		if (conn->state) {
			altcp_wolfssl_state* state = conn->state;
			if (state->buf) {
				pbuf_free(state->buf);
				state->buf = NULL;
			}
			if (state->ssl) {
				wolfSSL_shutdown(state->ssl);
				wolfSSL_free(state->ssl);
				state->ssl = NULL;
			}
			mem_free(state);
		}
	}

	if (conf) {
		if (conf->ctx) {
			wolfSSL_CTX_free(conf->ctx);
			conf->ctx = NULL;
		}
		wolfSSL_Cleanup();
		mem_free(conf);
	}

	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_free");
}

#endif /* LWIP_ALTCP LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL*/
#endif /* PLATFORM_BEKEN && ENABLE_MQTT_TLS*/