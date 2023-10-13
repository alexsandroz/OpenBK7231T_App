/*
 * Application specific settings for wolfssl RTOS
*/

/* Uncomment next line if using FreeRTOS+ TCP */
#define SINGLE_THREADED
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
//#define NO_DEV_RANDOM
#define NO_DEV_URANDOM
#define WOLFSSL_USER_IO
#define NO_WOLFSSL_SERVER
#define NO_SESSION_CACHE

/* Math */
#define WOLFSSL_SP_SMALL

/* Crypto */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
//#define WC_RSA_BLINDING
#define RSA_LOW_MEM
#define NO_OLD_TLS
//#define NO_DES3
#define NO_DH
#define NO_AES
#define NO_DSA
#define NO_SHA512
//#define NO_MD4
#define NO_MD5
#define NO_SHA
//#define HAVE_AESGCM
//#define HAVE_HKDF
//#define WOLFSSL_TLS13

/* RNG */
#define WOLFSSL_GENSEED_FORTEST

/* Development */
#define NO_ERROR_STRINGS
//#define HAVE_TLS_EXTENSIONS
//#define HAVE_SUPPORTED_CURVES
//#define HAVE_ENCRYPT_THEN_MAC
//#define HAVE_EXTENDED_MASTER
//#define WC_RSA_PSS
#define DEBUG_WOLFSSL
