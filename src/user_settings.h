/*
 * Application specific settings for wolfssl RTOS
*/

/* Library */
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK

/* Environment */
#define WOLFSSL_NO_SOCK
#define NO_WRITEV 
#define NO_FILESYSTEM
#define NO_WOLFSSL_SERVER
#define NO_SESSION_CACHE
#define WOLFSSL_USER_IO
#define HAVE_STRINGS_H
#define WOLF_C99
//#define WOLFSSL_LW_MEMORY
//#define USE_CERT_BUFFERS_2048

/* Math */
//#define WOLFSSL_SP_MATH_ALL
//#define WOLFSSL_SP_SMALL
//#define WOLFSSL_HAVE_SP_RSA
//#define WOLFSSL_HAVE_SP_ECC
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT

/* Crypto */
#define HAVE_RSA
#define WC_RSA_BLINDING
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define HAVE_POLY1305
#define HAVE_CHACHA
//#define HAVE_AESGCM
//#define HAVE_HKDF
//#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define NO_SHA512
//#define NO_SHA
#define NO_DES3
#define NO_DH
//#define NO_AES
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_PSK
#define NO_PWDBASED

/* RNG */
#define CUSTOM_RAND_GENERATE_BLOCK    os_get_random 

/* Development */
#define DEBUG_WOLFSSL
#define NO_ERROR_STRINGS
//#define HAVE_TLS_EXTENSIONS
//#define HAVE_SUPPORTED_CURVES
//#define HAVE_ENCRYPT_THEN_MAC
//#define HAVE_EXTENDED_MASTER
//#define WC_RSA_PSS