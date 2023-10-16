#ifndef ALTCP_TLS_WOLFSSL_H
#define ALTCP_TLS_WOLFSSL_H

#include "obk_config.h"
#if PLATFORM_BEKEN && ENABLE_MQTT_TLS
#include "lwip/opt.h"
#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/altcp.h"
#include "lwip/debug.h"
#include "lwip/priv/altcp_priv.h"

#include "wolfssl/ssl.h"

/** Configure debug level of this file */
#ifndef ALTCP_WOLFSSL_DBG_TRACE
#define ALTCP_WOLFSSL_DBG_TRACE     LWIP_DBG_OFF
#endif
#ifndef ALTCP_WOLFSSL_DBG_INFO
#define ALTCP_WOLFSSL_DBG_INFO      LWIP_DBG_OFF
#endif
#ifndef ALTCP_WOLFSSL_DBG_ERRO
#define ALTCP_WOLFSSL_DBG_ERRO      LWIP_DBG_OFF
#endif

	typedef struct altcp_wolfssl_state
	{
		WOLFSSL* ssl;
		u16_t pbuf_offset;
		struct pbuf* buf;
		byte connected;
	} altcp_wolfssl_state;

	struct altcp_tls_config
	{
		WOLFSSL_CTX* ctx;
	};


	int altcp_wolfssl_bio_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
	int altcp_wolfssl_bio_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
	static err_t altcp_wolfssl_lower_recv(void* cb, struct altcp_pcb* pcb, struct pbuf* pbuf, err_t err);
	static err_t altcp_wolfssl_lower_sent(void* cb, struct altcp_pcb* pcb, u16_t len);
	static void altcp_wolfssl_lower_err(void* arg, err_t err);
	static err_t altcp_wolfssl_connect(struct altcp_pcb* conn, const ip_addr_t* ipaddr, u16_t port, altcp_connected_fn connected);
	static err_t altcp_wolfssl_connected(void* arg, struct altcp_pcb* inner_conn, err_t err);
	static err_t altcp_wolfssl_write(struct altcp_pcb* conn, const void* dataptr, u16_t len, u8_t apiflags);
	static void altcp_wolfssl_set_poll(struct altcp_pcb* conn, u8_t interval);
	static err_t altcp_wolfssl_lower_poll(void* arg, struct altcp_pcb* inner_conn);
	static err_t connect_wolfssl_context(altcp_wolfssl_state* nlwip);
	static err_t altcp_wolfssl_close(struct altcp_pcb* conn);
	static void altcp_wolfssl_abort(struct altcp_pcb* conn);
	static void altcp_wolfssl_dealloc(struct altcp_pcb* conn);
	void altcp_wolfssl_free(struct altcp_tls_config* conf, struct altcp_pcb* conn);
	int wolfssl_custom_random(unsigned char* output, unsigned int);

	const struct altcp_functions altcp_wolfssl_functions = {
		altcp_wolfssl_set_poll,
		altcp_default_recved,
		altcp_default_bind,
		altcp_wolfssl_connect,
		NULL, // altcp_listen,
		altcp_wolfssl_abort,
		altcp_wolfssl_close,
		altcp_default_shutdown,
		altcp_wolfssl_write,
		altcp_default_output,
		altcp_default_mss,
		altcp_default_sndbuf,
		altcp_default_sndqueuelen,
		altcp_default_nagle_disable,
		altcp_default_nagle_enable,
		altcp_default_nagle_disabled,
		altcp_default_setprio,
		altcp_wolfssl_dealloc,
		altcp_default_get_tcp_addrinfo,
		altcp_default_get_ip,
		altcp_default_get_port
	#if LWIP_TCP_KEEPALIVE
		,
		altcp_default_keepalive_disable, altcp_default_keepalive_enable
	#endif
	#ifdef LWIP_DEBUG
		,
		altcp_default_dbg_get_tcp_state
	#endif
	};

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL*/
#endif /* PLATFORM_BEKEN && ENABLE_MQTT_TLS*/
#endif /* ALTCP_TLS_WOLFSSL_H */
