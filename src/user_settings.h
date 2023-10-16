/* --------------------------------------------------------------------------- 
 * Application specific settings for wolfssl BK7231
 * ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------- */
/* Port - Platform */
/* ------------------------------------------------------------------------- */
#define FREERTOS
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX

/* disable directory support */
#undef  NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR

/* disable writev */
#undef  NO_WRITEV
#define NO_WRITEV

/* we provide main entry point */
#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

/* if using in single threaded mode */
#undef  SINGLE_THREADED
//#define SINGLE_THREADED

/* reduces stack usage, by using malloc/free for stack variables over 100 bytes */
#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK

#undef WOLFSSL_NO_SOCK
#define WOLFSSL_NO_SOCK

#undef WOLFSSL_USER_IO
#define WOLFSSL_USER_IO

#undef HAVE_STRINGS_H
#define HAVE_STRINGS_H

#undef WOLF_C99
#define WOLF_C99

/* ------------------------------------------------------------------------- */
/* Random Number Generator */
/* ------------------------------------------------------------------------- */
#undef CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK    wolfssl_custom_random
#ifdef CUSTOM_RAND_GENERATE_BLOCK
extern int wolfssl_custom_random(unsigned char* output, unsigned int);
#endif
/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
/* fast math uses stack and inline assembly to speed up math */
#undef  USE_FAST_MATH
#define USE_FAST_MATH

#ifdef USE_FAST_MATH
	/* timing resistance for side-channel attack protection */
#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#else
#define WOLFSSL_SP_MATH_SMAL
#endif

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* TLS13 */
#undef WOLFSSL_DTLS13
//#define WOLFSSL_DTLS13
#undef WOLFSSL_DTLS13
//#define WOLFSSL_DTLS13

/* ECC */
#if 1
#undef  HAVE_ECC
#define HAVE_ECC

/* Support for custom curves */
#undef WOLFSSL_CUSTOM_CURVES
//#define WOLFSSL_CUSTOM_CURVES

/* Curve types */
#define NO_ECC_SECP
//#define HAVE_ECC_SECPR2
#define HAVE_ECC_SECPR3
//#define HAVE_ECC_BRAINPOOL
///#define HAVE_ECC_KOBLITZ

/* Curve sizes */
#undef  HAVE_ALL_CURVES
//#define HAVE_ALL_CURVES
#ifndef HAVE_ALL_CURVES
	/* allows enabling custom curve sizes */
#undef  ECC_USER_CURVES
//#define ECC_USER_CURVES

//#define HAVE_ECC112
//#define HAVE_ECC128
//#define HAVE_ECC160
//#define HAVE_ECC192
//#define HAVE_ECC224
#define NO_ECC256
//#define HAVE_ECC384
//#define HAVE_ECC521
#endif

/* Fixed point cache (speeds repeated operations against same private key) */
#undef  FP_ECC
#define FP_ECC
#ifdef FP_ECC
	/* Bits / Entries */
#undef  FP_ENTRIES
#define FP_ENTRIES  2
#undef  FP_LUT
#define FP_LUT      4
#endif

/* Optional ECC calculation method */
/* Note: doubles heap usage, but slightly faster */
#undef  ECC_SHAMIR
//#define ECC_SHAMIR

/* Reduces heap usage, but slower */
/* timing resistance for side-channel attack protection */
#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#ifdef USE_FAST_MATH
	/* use reduced size math buffers for ecc points */
#undef  ALT_ECC_SIZE
#define ALT_ECC_SIZE

/* Enable TFM optimizations for ECC */
#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
#define TFM_ECC192
#endif
#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
#define TFM_ECC224
#endif
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
#undef TFM_ECC256
#define TFM_ECC256
#endif
#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
#define TFM_ECC384
#endif
#if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
#define TFM_ECC521
#endif
#endif
#endif

/* RSA */
#undef NO_RSA
#if 1
#ifdef USE_FAST_MATH
	/* Maximum math bits (Max RSA key bits * 2) */
#undef  FP_MAX_BITS
#define FP_MAX_BITS     4096
#endif

/* half as much memory but twice as slow */
#undef  RSA_LOW_MEM
#define RSA_LOW_MEM

/* RSA blinding countermeasures */
#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

/* Will be deprecated */
#undef WOLFSSL_STATIC_RSA
#define WOLFSSL_STATIC_RSA

#else
#define NO_RSA
#endif

/* AES */
#undef NO_AES
#if 0
#undef  HAVE_AESGCM
#define HAVE_AESGCM

#ifdef HAVE_AESGCM
/* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
//#define GCM_SMALL
#define GCM_TABLE
#endif

#undef  WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_COUNTER

#undef  HAVE_AESCCM
#define HAVE_AESCCM

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  HAVE_AES_KEYWRAP
#define HAVE_AES_KEYWRAP
#else
#define NO_AES
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 1
#define HAVE_CHACHA
#define HAVE_POLY1305

/* Needed for Poly1305 */
#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 -> Needed for SHA512*/
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if 1
#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_ED25519_KEY_IMPORT
/* Optionally use small math (less flash usage, but much slower) */
#if 1
#define CURVED25519_SMALL
#endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 0
	/* 1k smaller, but 25% slower */
	//#define USE_SLOW_SHA
#else
#define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
#else
#define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 1
#define WOLFSSL_SHA512

/* Sha384 */
#undef  WOLFSSL_SHA384
#if 0
#define WOLFSSL_SHA384
#endif

/* over twice as small, but 50% slower */
#define USE_SLOW_SHA2
#else
#define NO_SHA512
#endif

/* MD5 */
#undef  NO_MD5
//#define NO_MD5


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef  WC_RSA_PSS
#define WC_RSA_PSS

#undef  KEEP_PEER_CERT
//#define KEEP_PEER_CERT

#undef  HAVE_COMP_KEY
//#define HAVE_COMP_KEY

#undef  HAVE_ECC_ENCRYPT
//#define HAVE_ECC_ENCRYPT

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  WOLFSSL_DTLS
//#define WOLFSSL_DTLS

#undef  OPENSSL_EXTRA
//#define OPENSSL_EXTRA

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

/* HKDF is a simple key derivation function(KDF) based on the HMAC message authentication code. */
#undef  HAVE_HKDF
#define HAVE_HKDF

/* Cipher-based message authentication codes (or CMACs) are a tool for calculating message authentication
codes using a block cipher coupled with a secret key. You can use an CMAC to verify both the integrity
and authenticity of a message. A subset of CMAC with the AES-128 algorithm is described in RFC 4493. */
#undef  WOLFSSL_CMAC
#define WOLFSSL_CMAC

#undef  WOLFSSL_KEY_GEN
//#define WOLFSSL_KEY_GEN

#undef  WOLFSSL_CERT_GEN
//#define WOLFSSL_CERT_GEN

#undef  WOLFSSL_CERT_REQ
//#define WOLFSSL_CERT_REQ

#undef  WOLFSSL_CERT_EXT
//#define WOLFSSL_CERT_EXT

#undef  HAVE_PK_CALLBACKS
//#define HAVE_PK_CALLBACKS

/* Application-Layer Protocol Negotiation (ALPN) is a Transport Layer Security (TLS)
extension that allows the application layer to negotiate which protocol should be
performed over a secure connection in a manner that avoids additional round trips
and which is independent of the application-layer protocols */
#undef  HAVE_ALPN
//#define HAVE_ALPN

/* Server Name Indication is an extension to the Transport Layer Security computer
networking protocol by which a client indicates which hostname it is attempting
to connect to at the start of the handshaking process. */
#undef  HAVE_SNI
//#define HAVE_SNI

#undef  HAVE_MAX_FRAGMENT
#define HAVE_MAX_FRAGMENT

/* HMAC (hash-based message authentication code)
Overall HMAC can be used with a range of different hashing methods,
such as MD5, SHA-1, SHA-256 (SHA-2) and SHA-3 */
#undef  HAVE_TRUNCATED_HMAC
#define HAVE_TRUNCATED_HMAC

#undef  SESSION_CERTS
#define SESSION_CERTS

#undef  HAVE_SESSION_TICKET
//#define HAVE_SESSION_TICKET

/* SRP password - authenticated key exchange */
#undef  WOLFCRYPT_HAVE_SRP
#define WOLFCRYPT_HAVE_SRP

#undef  WOLFSSL_HAVE_CERT_SERVICE
//#define WOLFSSL_HAVE_CERT_SERVICE

/* Standard syntax for storing signed and/or encrypted data. Like PEM */
#undef  HAVE_PKCS7
//#define HAVE_PKCS7

#undef  HAVE_X963_KDF
#define HAVE_X963_KDF

/* Simple Certificate Enrollment Protocol, or SCEP,
is a protocol that allows devices to easily enroll for a certificate by using a URL a
nd a shared secret to communicate with a PKI */
#undef  WOLFSSL_HAVE_WOLFSCEP
#define WOLFSSL_HAVE_WOLFSCEP

#undef  WOLFSSL_ALWAYS_KEEP_SNI
//#define WOLFSSL_ALWAYS_KEEP_SNI

#undef  WOLFSSL_ALWAYS_VERIFY_CB
//#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  WOLFSSL_SEP
#define WOLFSSL_SEP

#undef  ATOMIC_USER
#define ATOMIC_USER

#undef  HAVE_OCSP
#define HAVE_OCSP

#undef  HAVE_CERTIFICATE_STATUS_REQUEST
//#define HAVE_CERTIFICATE_STATUS_REQUEST

#undef  HAVE_CERTIFICATE_STATUS_REQUEST_V2
//#define HAVE_CERTIFICATE_STATUS_REQUEST_V2

/*certificate revocation list. list of digital certificates that have been revoked
  by the issuing certificate authority(CA) before their actual or assigned expiration date*/
#undef  HAVE_CRL
//#define HAVE_CRL

#undef  PERSIST_CERT_CACHE
//#define PERSIST_CERT_CACHE

#undef  PERSIST_SESSION_CACHE
//#define PERSIST_SESSION_CACHE

#undef  WOLFSSL_DER_LOAD
//#define WOLFSSL_DER_LOAD

#undef  WOLFSSL_DES_ECB
//#define WOLFSSL_DES_ECB

#undef  HAVE_CAMELLIA
//#define HAVE_CAMELLIA

#undef  HAVE_NULL_CIPHER
//#define HAVE_NULL_CIPHER

#undef  WOLFSSL_RIPEMD
//#define WOLFSSL_RIPEMD


/* TLS Session Cache */
#if 0
#define SMALL_SESSION_CACHE
//#define MEDIUM_SESSION_CACHE
//#define BIG_SESSION_CACHE
//#define HUGE_SESSION_CACHE
#else
#define NO_SESSION_CACHE
#endif


/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_WOLFSSL_SERVER
#define NO_WOLFSSL_SERVER

#undef  NO_WOLFSSL_CLIENT
//#define NO_WOLFSSL_CLIENT

/* disables TLS 1.0/1.1 support */
#undef  NO_OLD_TLS
#define NO_OLD_TLS

/* disable access to filesystem */
#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_RC4
#define NO_RC4

#undef  NO_MD4
#define NO_MD4

/* Pre-shared keys */
#undef  NO_PSK
//#define NO_PSK

#ifndef NO_PSK
/* Will be deprecated */
#undef WOLFSSL_STATIC_PSK
#define WOLFSSL_STATIC_PSK
#endif

#undef  NO_DSA
//#define NO_DSA

#undef  NO_DH
//#define NO_DH
#ifndef NO_DH
/* Will be deprecated */
#undef WOLFSSL_STATIC_DH
#define WOLFSSL_STATIC_DH
#endif

/* Null Authentication/Encryption 3DES */
#undef  NO_DES3
//#define NO_DES3

#undef  NO_PWDBASED
//#define NO_PWDBASED

/* encoding/decoding support */
#undef  NO_CODING
//#define NO_CODING

/* memory wrappers and memory callbacks */
#undef  NO_WOLFSSL_MEMORY
//#define NO_WOLFSSL_MEMORY

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef  DEBUG_WOLFSSL
//#define DEBUG_WOLFSSL
#ifdef DEBUG_WOLFSSL
	/* Use this to measure / print heap usage */
#if 0
#undef  USE_WOLFSSL_MEMORY
#define USE_WOLFSSL_MEMORY

#undef  WOLFSSL_TRACK_MEMORY
#define WOLFSSL_TRACK_MEMORY
#endif

#undef  WOLFSSL_DEBUG_MATH
//#define WOLFSSL_DEBUG_MATH
#endif

#undef  NO_ERROR_STRINGS
//#define NO_ERROR_STRINGS
