/* --------------------------------------------------------------------------- 
 * Application specific settings for wolfssl BK7231
 * ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------- */
/* Port - Platform */
/* ------------------------------------------------------------------------- */
#define FREERTOS
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX
//#define XREALLOC(p, n, h, t) pvPortRealloc((p), (n))

#undef  WOLFSSL_GENERAL_ALIGNMENT
#define WOLFSSL_GENERAL_ALIGNMENT   4

#undef  WOLFSSL_USE_ALIGN
#define WOLFSSL_USE_ALIGN

/* disable directory support */
#undef  NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR

/* disable access to filesystem */
#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

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
#if 0
#define USE_FAST_MATH
// timing resistance for side-channel attack protection */
#undef  TFM_TIMING_RESISTANT
#if 1
#define TFM_TIMING_RESISTANT
#endif

#else //USE_FAST_MATH
//#define WOLFSSL_SP_MATH_SMAL
#define WOLFSSL_SP_MATH_ALL
#endif 


/* ------------------------------------------------------------------------- */
/* Curves */
/* ------------------------------------------------------------------------- */

/*-------------------------------------ECC ----------------------------------*/
#if 0
#define HAVE_ECC

/* Support for custom curves */
#if 0
#define WOLFSSL_CUSTOM_CURVES
#define HAVE_ECC_BRAINPOOL
#define HAVE_ECC_KOBLITZ
#else
#undef WOLFSSL_CUSTOM_CURVES
#endif

/* Curve types */
#if 1
#undef NO_ECC_SECP
//#define HAVE_ECC_SECPR2
//#define HAVE_ECC_SECPR3
#else
#define NO_ECC_SECP
#endif

/* Curve sizes */
#if 1
#define HAVE_ALL_CURVES 		// Enable all key sizes(on unless ECC_USER_CURVES is defined) 
#undef ECC_USER_CURVES
#else
#undef HAVE_ALL_CURVES
#define ECC_USER_CURVES
//#define ECC_MIN_KEY_SZ  384   // Minimum supported ECC key size
//#define HAVE_ECC112        
//#define HAVE_ECC128 		
//#define HAVE_ECC160 		
//#define HAVE_ECC192 		
//#define HAVE_ECC224 
//#define HAVE_ECC239 
#define NO_ECC256          		// Disables 256 bit key(on by default)
//#define HAVE_ECC320 
#define HAVE_ECC384 
//#define HAVE_ECC512 
//#define HAVE_ECC521 
#endif

/* Optional ECC calculation method */
/* Note: doubles heap usage, but slightly faster */
#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  HAVE_ECC_ENCRYPT
//#define HAVE_ECC_ENCRYPT

#undef  HAVE_COMP_KEY
//#define HAVE_COMP_KEY

#undef  HAVE_ECC_CDH
//#define HAVE_ECC_CDH

#undef WOLFSSL_ECC_CURVE_STATIC
//#define WOLFSSL_ECC_CURVE_STATIC

/* timing resistance for side-channel attack protection */
#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#else
#undef  HAVE_ECC
#define NO_ECC_SECP
#undef  HAVE_ALL_CURVES
#undef  ECC_USER_CURVES
#undef  WOLFSSL_CUSTOM_CURVES
#endif //HAVE_ECC

/*----------------------------------Curve25519--------------------------------*/
#if 1
#define HAVE_CURVE25519
//#define HAVE_ED25519 // Needed for SHA512*
#if 1
#define CURVED25519_SMALL // Optionally use small math (less flash usage, but much slower)
#endif
#else
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#endif

/*-----------------------------------Curve448---------------------------------*/
#if 0
#define HAVE_CURVE448
//#define HAVE_ED448
#if 0
#define CURVED448_SMALL
#endif
#else
#undef HAVE_CURVE448
#undef HAVE_ED448
#endif

/*--------------------------------------DH-----------------------------------*/
#if 0
#undef  NO_DH
#if 0
#define HAVE_FFDHE
#else
#undef HAVE_FFDHE
#endif //HAVE_FFDHE

#if 0
#define WOLFSSL_STATIC_DH
#else
#undef WOLFSSL_STATIC_DH
#endif //WOLFSSL_STATIC_DH

#else
#define NO_DH
#undef HAVE_FFDHE
#endif //DH

/*--------------------------------------PSK-----------------------------------*/
#if 0
#undef  NO_PSK
#if 0
#define WOLFSSL_STATIC_PSK
#else
#undef WOLFSSL_STATIC_PSK
#endif
#else
#define NO_PSK
#endif


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */

/* ------------------------------------RSA---------------------------------- */
#if 1
#undef NO_RSA

/* half as much memory but twice as slow */
#undef  RSA_LOW_MEM
#define RSA_LOW_MEM

/* RSA blinding countermeasures */
#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

/* Disables RSA OAEP padding default: on) */
#undef  WC_NO_RSA_OAEP
//#define WC_NO_RSA_OAEP

#undef WOLFSSL_STATIC_RSA
//#define WOLFSSL_STATIC_RSA

#undef  WC_RSA_PSS
#define WC_RSA_PSS

#else // RSA
#define NO_RSA
#endif

/* ------------------------------------AES---------------------------------- */
#if 0
#undef NO_AES

// GCM
#if 0
#define HAVE_AESGCM
//#define GCM_WORD32 
//#define GCM_SMALL 
//#define GCM_TABLE 
//#define GCM_TABLE_4BIT
#else
#undef  HAVE_AESGCM
#endif //GCM

#undef  WOLFSSL_AES_COUNTER
//#define WOLFSSL_AES_COUNTER

#undef  HAVE_AESCCM
//#define HAVE_AESCCM

#undef  WOLFSSL_AES_DIRECT
//#define WOLFSSL_AES_DIRECT

#undef  HAVE_AES_KEYWRAP
//#define HAVE_AES_KEYWRAP

#else 
#define NO_AES
#undef  HAVE_AESGCM
#endif //AES

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */

/* ----------------------------ChaCha20 / Poly1305-------------------------- */
#if 1
#define HAVE_CHACHA
#define HAVE_POLY1305
#else
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#endif

//Required for Poly1305
#ifdef HAVE_POLY1305
#undef HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH
#endif

/* ------------------------------------SHA---------------------------------- */
#if 0
#undef NO_SHA
#define USE_SLOW_SHA // 1k smaller, but 25% slower 
#else
#define NO_SHA
#endif

/* ----------------------------------SHA256--------------------------------- */
#if 1
#undef NO_SHA256
#else
#define NO_SHA256
#endif

/* ----------------------------------SHA512--------------------------------- */
#if 0
#define WOLFSSL_SHA512
//#define USE_SLOW_SHA2   // over twice as small, but 50% slower 
#if 0
#define WOLFSSL_SHA384
#else
#undef  WOLFSSL_SHA384
#endif
#else
#define NO_SHA512
#endif


/* ----------------------------------OTHERS-------------------------------- */
#undef  NO_RC4
#define NO_RC4

#undef  NO_MD4
#define NO_MD4

#undef  NO_MD5
#define NO_MD5

#undef  NO_DSA
#define NO_DSA

/* disables TLS 1.0/1.1 support */
#undef  NO_OLD_TLS
#define NO_OLD_TLS

/* Null Authentication/Encryption 3DES */
#undef  NO_DES3
#define NO_DES3

#undef  WOLFSSL_DES_ECB
//#define WOLFSSL_DES_ECB

#undef  HAVE_CAMELLIA
//#define HAVE_CAMELLIA

#undef  HAVE_NULL_CIPHER
//#define HAVE_NULL_CIPHER

#undef  WOLFSSL_RIPEMD
//#define WOLFSSL_RIPEMD


/* ------------------------------------------------------------------------- */
/* Features                                                                  */
/* ------------------------------------------------------------------------- */

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

/*
// HKDF is a simple key derivation function(KDF) based on the HMAC message authentication code.
#undef  HAVE_HKDF
#define HAVE_HKDF

#undef  WOLFSSL_LEAN_PSK
#define WOLFSSL_LEAN_PSK

#undef  WOLFSSL_LEAN_TLS
#define WOLFSSL_LEAN_TLS

#undef WOLFSSL_TLS13
//#define WOLFSSL_TLS13

#undef WOLFSSL_DTLS13
//#define WOLFSSL_DTLS13

#undef WOLFSSL_PEM_TO_DER
//#define WOLFSSL_PEM_TO_DER

#undef  WOLFSSL_BASE64_ENCODE
//#define WOLFSSL_BASE64_ENCODE

// encoding/decoding support 
#undef  NO_CODING
//#define NO_CODING

#undef  KEEP_PEER_CERT
//#define KEEP_PEER_CERT

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef HAVE_ENCRYPT_THEN_MAC
#define HAVE_ENCRYPT_THEN_MAC

#undef  WOLFSSL_DTLS
//#define WOLFSSL_DTLS

#undef  OPENSSL_EXTRA
//#define OPENSSL_EXTRA

// Cipher-based message authentication codes (or CMACs) are a tool for calculating message authentication
// codes using a block cipher coupled with a secret key. You can use an CMAC to verify both the integrity
// and authenticity of a message. A subset of CMAC with the AES-128 algorithm is described in RFC 4493. 
#undef  WOLFSSL_CMAC
#define WOLFSSL_CMAC

// Allows Private Key Generation with ECC 
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

// Application-Layer Protocol Negotiation (ALPN) is a Transport Layer Security (TLS)
// extension that allows the application layer to negotiate which protocol should be
// performed over a secure connection in a manner that avoids additional round trips
// and which is independent of the application-layer protocols 
#undef  HAVE_ALPN
#define HAVE_ALPN

// Server Name Indication is an extension to the Transport Layer Security computer
// networking protocol by which a client indicates which hostname it is attempting
// to connect to at the start of the handshaking process.
#undef  HAVE_SNI
//#define HAVE_SNI

#undef  HAVE_MAX_FRAGMENT
//#define HAVE_MAX_FRAGMENT

// HMAC (hash-based message authentication code)
// Overall HMAC can be used with a range of different hashing methods,
// such as MD5, SHA-1, SHA-256 (SHA-2) and SHA-3 
#undef  HAVE_TRUNCATED_HMAC
//#define HAVE_TRUNCATED_HMAC

#undef  SESSION_CERTS
//#define SESSION_CERTS

#undef  HAVE_SESSION_TICKET
//#define HAVE_SESSION_TICKET

// SRP password - authenticated key exchange 
#undef  WOLFCRYPT_HAVE_SRP
//#define WOLFCRYPT_HAVE_SRP

#undef  WOLFSSL_HAVE_CERT_SERVICE
//#define WOLFSSL_HAVE_CERT_SERVICE

// Standard syntax for storing signed and/or encrypted data. Like PEM 
#undef  HAVE_PKCS7
//#define HAVE_PKCS7

#undef  HAVE_X963_KDF
//#define HAVE_X963_KDF

// Simple Certificate Enrollment Protocol, or SCEP,
// is a protocol that allows devices to easily enroll for a certificate by using a URL 
// and a shared secret to communicate with a PKI
#undef  WOLFSSL_HAVE_WOLFSCEP
//#define WOLFSSL_HAVE_WOLFSCEP

#undef  WOLFSSL_SEP
//#define WOLFSSL_SEP

#undef  WOLFSSL_ALWAYS_KEEP_SNI
//#define WOLFSSL_ALWAYS_KEEP_SNI

#undef  WOLFSSL_ALWAYS_VERIFY_CB
//#define WOLFSSL_ALWAYS_VERIFY_CB

#undef  ATOMIC_USER
//#define ATOMIC_USER

#undef  HAVE_OCSP
//#define HAVE_OCSP

#undef  HAVE_CERTIFICATE_STATUS_REQUEST
//#define HAVE_CERTIFICATE_STATUS_REQUEST

#undef  HAVE_CERTIFICATE_STATUS_REQUEST_V2
//#define HAVE_CERTIFICATE_STATUS_REQUEST_V2

//certificate revocation list. list of digital certificates that have been revoked
//by the issuing certificate authority(CA) before their actual or assigned expiration date
#undef  HAVE_CRL
//#define HAVE_CRL

#undef  PERSIST_CERT_CACHE
//#define PERSIST_CERT_CACHE

#undef  PERSIST_SESSION_CACHE
//#define PERSIST_SESSION_CACHE

#undef  WOLFSSL_DER_LOAD
//#define WOLFSSL_DER_LOAD

// TLS Session Cache
#if 0
#define SMALL_SESSION_CACHE
//#define MEDIUM_SESSION_CACHE
//#define BIG_SESSION_CACHE
//#define HUGE_SESSION_CACHE
#else
#define NO_SESSION_CACHE
#endif

#undef  NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_SERVER

#undef  NO_WOLFSSL_CLIENT
//#define NO_WOLFSSL_CLIENT

#undef  NO_PWDBASED
//#define NO_PWDBASED

// memory wrappers and memory callbacks
#undef  NO_WOLFSSL_MEMORY
//#define NO_WOLFSSL_MEMORY

// In-lining of misc.c functions 
// If defined, must include wolfcrypt/src/misc.c in build 
// Slower, but about 1k smaller 
#undef  NO_INLINE
//#define NO_INLINE
*/

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef  DEBUG_WOLFSSL
#define DEBUG_WOLFSSL
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


/* ------------------------------------------------------------------------- */
/* Post optizations */
/* ------------------------------------------------------------------------- */
#ifdef USE_FAST_MATH
#ifdef HAVE_ECC

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
#endif //HAVE_ECC

#ifndef NO_RSA
#undef  FP_MAX_BITS
#define FP_MAX_BITS     4096  //Maximum math bits (Max RSA key bits * 2) 
#endif // RSA

#endif //USE_FAST_MATH