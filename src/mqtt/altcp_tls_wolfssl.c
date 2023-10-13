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

/*
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->wc_GenerateSeed");
	word32 i;
	for (i = 0; i < sz; i++)
		output[i] = i;

	(void)os;

	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-wc_GenerateSeed");
	return 0;
}
*/
void MyLoggingCallback(const int logLevel, const char* const logMessage);
void MyLoggingCallback(const int logLevel, const char* const logMessage)
{
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, logMessage);
}

struct altcp_tls_config*
	altcp_tls_create_config_client(const u8_t* ca, size_t ca_len)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_tls_create_config_client ca_len(%d)\n", (int)ca_len));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_tls_create_config_client ca_len(%d)", (int)ca_len);

	wolfSSL_SetLoggingCb(MyLoggingCallback);
	wolfSSL_Debugging_ON();

	struct altcp_tls_config* conf;
	WOLFSSL_METHOD* method;

	conf = mem_calloc(1, sizeof(struct altcp_tls_config));
	if (!conf)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client ERR_MEM\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client (!conf)");
		return NULL;
	}

	/* initialize wolfssl library: */
	if (wolfSSL_Init() != WOLFSSL_SUCCESS)
	{
		altcp_wolfssl_free(conf, NULL);
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client (wolfSSL_Init() != WOLFSSL_SUCCESS)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client (wolfSSL_Init() != WOLFSSL_SUCCESS)");
		return NULL;
	}
	method = wolfTLSv1_2_client_method();

	/* make ssl context */
	if ((conf->ctx = wolfSSL_CTX_new(method)) == NULL)
	{
		altcp_wolfssl_free(conf, NULL);
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client fail wolfSSL_CTX_new\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client ((conf->ctx = wolfSSL_CTX_new(method)) == NULL)");
		return NULL;
	}

	/* Add cert to ctx FOR TEST  */
	// ca = test_cert;
	// ca_len = sizeof(test_cert);

	if (ca != NULL && ca_len > 0)
	{
		int ret = wolfSSL_CTX_load_verify_buffer(conf->ctx, ca, ca_len, SSL_FILETYPE_PEM);
		if (ret != WOLFSSL_SUCCESS)
		{
			altcp_wolfssl_free(conf, NULL);
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client fail init certs ret(%d) %s\n",
			//	ret, wolfSSL_ERR_reason_error_string(ret)));
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client fail init certs ret(%d) %s\n",
				ret, wolfSSL_ERR_reason_error_string(ret));
			return NULL;
		}
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, (" <->altcp_tls_create_config_client Cert load successful\n"));
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->altcp_tls_create_config_client Cert load successful\n");
#ifdef ALTCP_WOLFSSL_DBG_INFO
		byte cert_der_buf[ca_len];
		int ret_decode, cert_der_len = ca_len;
		DecodedCert decodedCert;

		ret_decode = wolfSSL_CertPemToDer(ca, ca_len, cert_der_buf, cert_der_len, CERT_TYPE);
		if (ret_decode <= 0)
		{
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client wolfSSL_CertPemToDer ret(%d)\n", ret_decode));
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client wolfSSL_CertPemToDer ret(%d)", ret_decode);
			goto exit_cert_decode;
		}
		cert_der_len = ret_decode;

		InitDecodedCert(&decodedCert, cert_der_buf, cert_der_len, 0);

		ret_decode = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
		if (ret_decode)
		{
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_create_config_client ParseCerts ret(%d)\n", ret_decode));
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client ParseCerts ret(%d)", ret_decode);
			goto exit_cert_decode;
		}

		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, ("      Issuer: %s\n", decodedCert.issuer));
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, "      Issuer: %s", decodedCert.issuer);
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, ("      Subject: %s\n", decodedCert.subject));
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, "      Subject: %s", decodedCert.subject);
		DNS_entry * altName = decodedCert.altNames;
		while (altName) {
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, ("      Alt Name: %s\n", altName->name));
			addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, "      Alt Name: %s", altName->name);
			altName = altName->next;
		}
		if (decodedCert.afterDateLen) {
			char after_date[decodedCert.afterDateLen - 2];
			memcpy(after_date, decodedCert.afterDate + 2, decodedCert.afterDateLen - 2);
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, ("      After Date: %s\n", after_date));
			addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, "      After Date: %s", after_date);
		}
	exit_cert_decode:
		FreeDecodedCert(&decodedCert);
#endif
	}
	else {
		/* Disable peer certificate validation for testing  */
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, (" <->altcp_tls_create_config_client Invalid cert. Disable cert validation\n"));
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->altcp_tls_create_config_client Invalid cert. Disable cert validation");
		wolfSSL_CTX_set_verify(conf->ctx, WOLFSSL_VERIFY_NONE, NULL);
	}
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_tls_create_config_client");
	return conf;
}

struct altcp_pcb*
	altcp_tls_wrap(struct altcp_tls_config* config, struct altcp_pcb* inner_pcb)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_tls_wrap\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_tls_wrap");
	struct altcp_pcb* out_pcb;
	altcp_wolfssl_state* state;
	WOLFSSL* ssl;

	if (!inner_pcb || !config)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_wrap argument error\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_wrap argument error");
		return NULL;
	}

	/* allocate return pcb */
	out_pcb = altcp_alloc();
	if (!out_pcb)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_wrap altcp_alloc\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_tls_wrap altcp_alloc");
		return NULL;
	}

	state = mem_calloc(1, sizeof(altcp_wolfssl_state));
	if (!state)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_tls_wrap alooc altcp_wolfssl_state\n"));
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

	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_tls_wrap\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_tls_wrap");
	return out_pcb;
}

static err_t
altcp_wolfssl_connect(struct altcp_pcb* conn, const ip_addr_t* ipaddr, u16_t port, altcp_connected_fn connected)
{
	err_t ret;
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_connect\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_connect");
	if (conn == NULL)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_connect erro (conn == NULL)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect erro (conn == NULL)");
		return ERR_ARG;
	}
	conn->connected = connected;
	ret = altcp_connect(conn->inner_conn, ipaddr, port, altcp_wolfssl_connected);
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_connect\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect (%d)", ret);
	return ret;
}

/** Connected callback from lower connection (i.e. TCP).
 */
static err_t
altcp_wolfssl_connected(void* arg, struct altcp_pcb* inner_conn, err_t err)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_connected\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_connected (%d)", err);
	
	int ret;
	struct altcp_pcb* conn = (struct altcp_pcb*)arg;
	LWIP_UNUSED_ARG(inner_conn);

	if (!conn || !conn->state)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_connected error (!conn || !conn->state)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected error (!conn || !conn->state)");
		return ERR_ARG;
	}
	altcp_wolfssl_state* nlwip = (altcp_wolfssl_state*)conn->state;
	if (!nlwip->ssl)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_connected error (!nlwip->ssl)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected error (!nlwip->ssl)");
		return ERR_ARG;
	}

	/* upper connected is called when if error base connect */
	if (err != ERR_OK && conn->connected)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_connected lower error(%d)\n", err));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connect erro (conn == NULL)");
		return conn->connected(conn->arg, conn, err);
	}

	/* start ssl handshake */
	ret = connect_wolfssl_context(nlwip);
	/* Abort on error*/
	if (ret != ERR_OK) {
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv abort connect_wolfssl_context (%d)", ret);
		altcp_abort(conn);
		return ret;
	}
	/* upper connected is called when handshake is done*/
	if (conn->connected && ret == ERR_OK && nlwip->connected)
	{
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <->altcp_wolfssl_lower_recv handshke doen return upper conneted");
		ret = conn->connected(conn->arg, conn, ret);
	}

//	LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_connected ret(%d)\n", ret));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_connected ret(%d)", ret);
	return ret;
}

static err_t connect_wolfssl_context(altcp_wolfssl_state* nlwip)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->connect_wolfssl_context\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->connect_wolfssl_context");
	int ret, err_ssl;

	ret = wolfSSL_connect(nlwip->ssl);
	if (ret == WOLFSSL_SUCCESS)
	{
		nlwip->connected = 1;
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_INFO, (" <->Secure connection done!\n"));
		addLogAdv(LOG_INFO, LOG_FEATURE_MQTT, " <->Secure connection done!");
		/* TODO adicionar debug com detalhes nivle de certificado */
		wolfSSL_FreeHandshakeResources(nlwip->ssl);
		return ERR_OK;
	}
	err_ssl = wolfSSL_get_error(nlwip->ssl, 0);
	if (err_ssl == WOLFSSL_ERROR_WANT_READ || err_ssl == WOLFSSL_ERROR_WANT_WRITE)
	{
		/* handshake non-blocking socket wants data to be read */
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-connect_wolfssl_context WOLFSSL_ERROR_WANT_READ\n"));
		addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-connect_wolfssl_context ret(%d) WOLFSSL_ERROR_WANT_READ", ERR_OK);
		return ERR_OK;
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-connect_wolfssl_context error ret(%d) err_ssl(%d) %s\n", ret, err_ssl,
	//	wolfSSL_ERR_error_string(err_ssl, NULL)));		
	addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-connect_wolfssl_context error ret(%d) err_ssl(%d) %s", ret, err_ssl,
		wolfSSL_ERR_error_string(err_ssl, NULL));
	return ERR_ABRT;
}

int altcp_wolfssl_bio_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_bio_send sz(%d)\n", sz));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_bio_send sz(%d)", sz);
	err_t err;
	int ret = 0;
	struct altcp_pcb* out_pcb = (struct altcp_pcb*)ctx;
	LWIP_UNUSED_ARG(ssl);

	if (!out_pcb || !buf || sz < 1)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_bio_send error (!out_pcb || !buf || sz < 1)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_send error (!out_pcb || !buf || sz < 1)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	err = altcp_write(out_pcb->inner_conn, buf, sz, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK)
	{
		ret = sz;
	} else 
	{
	 ret = WOLFSSL_CBIO_ERR_WANT_WRITE;
	}

	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_bio_send ret(%d) sz(%d)\n", ret, sz));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_send ret(%d) sz(%d)", ret, sz);
	return ret;
}

int altcp_wolfssl_bio_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_bio_recv len(%d)\n", sz));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_bio_recv len(%d)", sz);

	u16_t ret;
	struct altcp_pcb* out_pcb;
	altcp_wolfssl_state* nlwip;
	LWIP_UNUSED_ARG(ssl);
	if (!ctx || sz < 1)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_bio_recv error (!ctx || sz < 1)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv error (!ctx || sz < 1)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	out_pcb = (struct altcp_pcb*)ctx;
	if (!out_pcb->state)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_bio_recv error (!out_pcb->state)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv error (!out_pcb->state)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	nlwip = (altcp_wolfssl_state*)out_pcb->state;

	if (!nlwip->buf || (nlwip->buf->tot_len - nlwip->pbuf_offset) < sz)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_bio_recv WOLFSSL_CBIO_ERR_WANT_READ\n"));
		addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_bio_recv WOLFSSL_CBIO_ERR_WANT_READ");
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}
	else
	{
		ret = pbuf_copy_partial(nlwip->buf, buf, sz, nlwip->pbuf_offset);
		if (ret > 0)
		{
			nlwip->buf = pbuf_skip(nlwip->buf, (ret + nlwip->pbuf_offset), &nlwip->pbuf_offset);
		}
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_bio_recv (%d)/(%d)\n", ret, sz));
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
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_lower_recv (%d)\n", (p ? p->tot_len : 0)));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_recv (%d)", (p ? p->tot_len : 0));
	altcp_wolfssl_state* nlwip;
	struct altcp_pcb* out_pcb;
	int sz, err_ssl;
	err_t ret = ERR_OK;

	if (!pcb || !p || !cb)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_lower_recv error (!pcb || !p || !cb)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv error (!pcb || !p || !cb)");
		return ERR_ARG;
	}
	out_pcb = (struct altcp_pcb*)cb;
	if (!out_pcb->state)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_lower_recv error (!out_pcb->state)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv error (!out_pcb->state)");
		return ERR_ARG;
	}
	nlwip = (altcp_wolfssl_state*)out_pcb->state;

	/* Add received packge to chain */
	if (nlwip->buf == NULL)
	{
		nlwip->buf = p;
		sz = p->tot_len;
	}
	else
	{
		pbuf_chain(nlwip->buf, p);
		sz = p->tot_len;
	}
	if (!nlwip->connected)
	{
		/* Call again connected to complete handshake */
		ret = connect_wolfssl_context(nlwip);
		altcp_recved(pcb, p->tot_len);
		/* Abort on error*/
		if (ret != ERR_OK){
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_recv abort connect_wolfssl_context (%d)", ret);
			altcp_abort(pcb);
			return ret;			
		}
		/* upper connected is called when handshake is done*/
		if (out_pcb->connected && ret == ERR_OK && nlwip->connected)
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
			char reply[nlwip->buf->tot_len];
			memset(reply, 0, sizeof(reply));
			sz = wolfSSL_read(nlwip->ssl, reply, sizeof(reply));
			if (sz <= 0)
			{
				err_ssl = wolfSSL_get_error(nlwip->ssl, 0);
				if (err_ssl == SSL_ERROR_WANT_READ) {
					//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <->COMO TRATAR AQUI sz(%d) recv(%d)\n", sz, p->tot_len));
					addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <->COMO TRATAR AQUI sz(%d) recv(%d)", sz, p->tot_len);
				}
				else
				{
					//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO,
					//	(" <-altcp_wolfssl_lower_recv wolfSSL_read error ret(%d) ssl_err(%d) %s\n",
					//		sz, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL)));
					addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, 
						" <-altcp_wolfssl_lower_recv wolfSSL_read error ret(%d) ssl_err(%d) %s",
						sz, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL));
					return ERR_ABRT;
				}
			}
			struct pbuf* pbuf = pbuf_alloc(PBUF_RAW, sz, PBUF_POOL);
			pbuf_take(pbuf, reply, sz);
			ret = out_pcb->recv(out_pcb->arg, out_pcb, pbuf, err);
		}
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_lower_recv ret(%d) recv(%d)\n", ret, sz));
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
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_lower_sent (%d)\n", len));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_sent (%d)", len);
	err_t err = ERR_OK;
	if (!cb || !pcb)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_lower_sent error (!cb|| !pcb)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent error (!cb|| !pcb)");
		return ERR_ARG;
	}
	struct altcp_pcb* out_pcb = cb;
	if (out_pcb->state == NULL)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_lower_sent error (out_pcb->state == NULL)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent error (out_pcb->state == NULL)");
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	if (out_pcb->sent)
	{
		err = out_pcb->sent(out_pcb->arg, pcb, len);
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_lower_sent len(%d)\n", len));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_sent len(%d)", len);
	return err;
}

static void altcp_wolfssl_lower_err(void* arg, err_t err)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, ("->altcp_wolfssl_lower_err err(%d)\n", err));
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
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_lower_err err(%d)\n", err));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_err err(%d)", err);
}

/** Write data to a TLS connection. Calls into wolfssl, which in turn calls into
 * lower write to send the encrypted data */
static err_t
altcp_wolfssl_write(struct altcp_pcb* conn, const void* dataptr, u16_t len, u8_t apiflags)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_write len(%d)\n", len));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_write len(%d)", len);
	int ret, err_ssl;
	err_t err = ERR_OK;

	altcp_wolfssl_state* nlwip;

	if (!conn || !dataptr || len < 1)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_write error (!conn || !dataptr || len < 1)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!conn || !dataptr || len < 1)");
		return ERR_ARG;
	}
	nlwip = (altcp_wolfssl_state*)conn->state;
	if (!nlwip || !nlwip->ssl)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_write error (!nlwip || !nlwip->ssl)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!nlwip || !nlwip->ssl)");
		return ERR_ARG;
	}

	LWIP_UNUSED_ARG(apiflags);

	if (!nlwip->connected)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_write error (!nlwip->connected)\n"));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write error (!nlwip->connected)");
		return ERR_ABRT;
	}

	ret = wolfSSL_write(nlwip->ssl, dataptr, len);
	err_ssl = wolfSSL_get_error(nlwip->ssl, 0);
	if (ret <= 0)
	{
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_write wolfSSL_write error ret(%d) err_ssl(%d) %s\n",
		//	ret, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL)));
		addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write wolfSSL_write error ret(%d) err_ssl(%d) %s",
			ret, err_ssl, wolfSSL_ERR_error_string(err_ssl, NULL));
		return ERR_ABRT;
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_write (%d)/(%d)\n", ret, len));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_write (%d)/(%d)", ret, len);
	return err;
}

static void
altcp_wolfssl_set_poll(struct altcp_pcb* conn, u8_t interval)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_set_poll interval(%d)\n", interval));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_set_poll interval(%d)", interval);

	if (conn != NULL) {
		altcp_poll(conn->inner_conn, altcp_wolfssl_lower_poll, interval);
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_set_poll interval(%d)\n", interval));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_set_poll interval(%d)", interval);
}

/** Poll callback from lower connection (i.e. TCP)
 * Just pass this on to the application.
 */
static err_t
altcp_wolfssl_lower_poll(void* arg, struct altcp_pcb* inner_conn)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_lower_poll\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_lower_poll");
	err_t err = ERR_OK;

	struct altcp_pcb* conn = (struct altcp_pcb*)arg;
	LWIP_UNUSED_ARG(inner_conn);
	if (conn) {
		LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
		if (conn->poll) {
			err = conn->poll(conn->arg, conn);
			if (err) {
				///LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_lower_poll (%d))\n", err));
				addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_poll (%d))", err);
				return err;
			}
		}
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_lower_poll\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_lower_poll");
	return err;
}

static void
altcp_wolfssl_abort(struct altcp_pcb* conn)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_abort\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_abort");

	if (conn != NULL)
	{
		altcp_abort(conn->inner_conn);
	}
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_abort\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_abort");
}

static err_t
altcp_wolfssl_close(struct altcp_pcb* conn)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_close\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_close");

	struct altcp_pcb* inner_conn;
	if (!conn || !conn->inner_conn)
	{
		return ERR_VAL;
		//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_close (!conn || !conn->inner_conn)\n"));
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
			//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_ERRO, (" <-altcp_wolfssl_close erro (%d)\n", err));
			addLogAdv(LOG_ERROR, LOG_FEATURE_MQTT, " <-altcp_wolfssl_close erro (%d)", err);
			return err;
		}
		conn->inner_conn = NULL;
	}
	altcp_free(conn);
	return ERR_OK;
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_close\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_close");
}

static void
altcp_wolfssl_dealloc(struct altcp_pcb* conn)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_dealloc\n"));
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
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_dealloc\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_dealloc");
}

void altcp_wolfssl_free(struct altcp_tls_config* conf, struct altcp_pcb* conn)
{
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, ("->altcp_wolfssl_free\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, "->altcp_wolfssl_free conf(%d) state(%d)", conf, conn);

	if (conn) {
		if (conn->state){
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
	//LWIP_DEBUGF(ALTCP_WOLFSSL_DBG_TRACE, (" <-altcp_wolfssl_free\n"));
	addLogAdv(LOG_WARN, LOG_FEATURE_MQTT, " <-altcp_wolfssl_free");
}

#endif /* LWIP_ALTCP LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL*/
#endif /* PLATFORM_BEKEN && ENABLE_MQTT_TLS*/