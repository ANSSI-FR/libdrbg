/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author: Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __HASH_H__
#define __HASH_H__

/* The configuration file */
#include "libhash_config.h"

#include "utils.h"
#define MAX_DIGEST_SIZE 0
#define MAX_BLOCK_SIZE  0

/* Hash algorithms */
#ifdef WITH_HASH_SHA224
#include "sha224.h"
#endif
#ifdef WITH_HASH_SHA256
#include "sha256.h"
#endif
#ifdef WITH_HASH_SHA384
#include "sha384.h"
#endif
#ifdef WITH_HASH_SHA512
#include "sha512.h"
#endif
#ifdef WITH_HASH_SHA512_224
#include "sha512-224.h"
#endif
#ifdef WITH_HASH_SHA512_256
#include "sha512-256.h"
#endif
#ifdef WITH_HASH_SHA3_224
#include "sha3-224.h"
#endif
#ifdef WITH_HASH_SHA3_256
#include "sha3-256.h"
#endif
#ifdef WITH_HASH_SHA3_384
#include "sha3-384.h"
#endif
#ifdef WITH_HASH_SHA3_512
#include "sha3-512.h"
#endif
#ifdef WITH_HASH_SM3
#include "sm3.h"
#endif
#ifdef WITH_HASH_SHAKE256
#include "shake256.h"
#endif
#ifdef WITH_HASH_STREEBOG256
#include "streebog256.h"
#endif
#ifdef WITH_HASH_STREEBOG512
#include "streebog512.h"
#endif
#ifdef WITH_HASH_RIPEMD160
#include "ripemd160.h"
#endif
#ifdef WITH_HASH_BELT_HASH
#include "belt-hash.h"
#endif
#ifdef WITH_HASH_BASH224
#include "bash224.h"
#endif
#ifdef WITH_HASH_BASH256
#include "bash256.h"
#endif
#ifdef WITH_HASH_BASH384
#include "bash384.h"
#endif
#ifdef WITH_HASH_BASH512
#include "bash512.h"
#endif
/* Deprecated hash algorithms */
#ifdef WITH_HASH_MD2
/* MD-2 */
#include "md2.h"
#endif
#ifdef WITH_HASH_MD4
/* MD-4 */
#include "md4.h"
#endif
#ifdef WITH_HASH_MD5
/* MD-5 */
#include "md5.h"
#endif
#ifdef WITH_HASH_SHA0
/* SHA-0 */
#include "sha0.h"
#endif
#ifdef WITH_HASH_SHA1
/* SHA-1 */
#include "sha1.h"
#endif
#ifdef WITH_HASH_MDC2
/* MDC-2 */
#include "mdc2.h"
#endif
#ifdef WITH_HASH_GOSTR34_11_94
/* GOSTR34-11-94 source code */
#include "gostr34_11_94.h"
#endif

#if (MAX_BLOCK_SIZE == 0) || (MAX_DIGEST_SIZE == 0)
#error "No hash function is defined!!! Please define at least one ..."
#endif

/****************************************************/
/****************************************************/
/****************************************************/
typedef enum {
	HASH_UNKNOWN_HASH_ALG     = 0,
#ifdef WITH_HASH_SHA224
	HASH_SHA224               = 1,
#endif
#ifdef WITH_HASH_SHA256
	HASH_SHA256               = 2,
#endif
#ifdef WITH_HASH_SHA384
	HASH_SHA384               = 3,
#endif
#ifdef WITH_HASH_SHA512
	HASH_SHA512               = 4,
#endif
#ifdef WITH_HASH_SHA512_224
	HASH_SHA512_224           = 5,
#endif
#ifdef WITH_HASH_SHA512_256
	HASH_SHA512_256           = 6,
#endif
#ifdef WITH_HASH_SHA3_224
	HASH_SHA3_224             = 7,
#endif
#ifdef WITH_HASH_SHA3_256
	HASH_SHA3_256             = 8,
#endif
#ifdef WITH_HASH_SHA3_384
	HASH_SHA3_384             = 9,
#endif
#ifdef WITH_HASH_SHA3_512
	HASH_SHA3_512             = 10,
#endif
#ifdef WITH_HASH_SM3
	HASH_SM3                  = 11,
#endif
#ifdef WITH_HASH_STREEBOG256
	HASH_STREEBOG256          = 12,
#endif
#ifdef WITH_HASH_STREEBOG512
	HASH_STREEBOG512          = 13,
#endif
#ifdef WITH_HASH_SHAKE256
	HASH_SHAKE256             = 14,
#endif
#ifdef WITH_HASH_RIPEMD160
	HASH_RIPEMD160            = 15,
#endif
#ifdef WITH_HASH_BELT_HASH
	HASH_BELT_HASH            = 16,
#endif
#ifdef WITH_HASH_BASH224
	HASH_BASH224              = 17,
#endif
#ifdef WITH_HASH_BASH256
	HASH_BASH256              = 18,
#endif
#ifdef WITH_HASH_BASH384
	HASH_BASH384              = 19,
#endif
#ifdef WITH_HASH_BASH512
	HASH_BASH512              = 20,
#endif
	/* Deprecated hash algorithms (for security reasons).
	 * XXX: NOTE: These algorithms are here as a playground e.g.
	 * to test some backward compatibility of cryptographic cipher suites,
	 * please DO NOT use them in production code!
	 */
#ifdef WITH_HASH_MD2
	HASH_MD2                  = 21,
#endif
#ifdef WITH_HASH_MD4
	HASH_MD4                  = 22,
#endif
#ifdef WITH_HASH_MD5
	HASH_MD5                  = 23,
#endif
#ifdef WITH_HASH_SHA0
	HASH_SHA0                 = 24,
#endif
#ifdef WITH_HASH_SHA1
	HASH_SHA1                 = 25,
#endif
#ifdef WITH_HASH_MDC2
	HASH_MDC2_PADDING1        = 26,
	HASH_MDC2_PADDING2        = 27,
#endif
#ifdef WITH_HASH_GOSTR34_11_94
	HASH_GOST34_11_94_NORM    = 28,
	HASH_GOST34_11_94_RFC4357 = 29,
#endif
} hash_alg_type;

/* Our generic hash context */
typedef union {
#ifdef WITH_HASH_SHA224
	sha224_context sha224ctx;
#endif
#ifdef WITH_HASH_SHA256
	sha256_context sha256ctx;
#endif
#ifdef WITH_HASH_SHA384
	sha384_context sha384ctx;
#endif
#ifdef WITH_HASH_SHA512
	sha512_context sha512ctx;
#endif
#ifdef WITH_HASH_SHA512_224
	sha512_224_context sha512_224ctx;
#endif
#ifdef WITH_HASH_SHA512_256
	sha512_256_context sha512_256ctx;
#endif
#ifdef WITH_HASH_SHA3_224
	sha3_224_context sha3_224ctx;
#endif
#ifdef WITH_HASH_SHA3_256
	sha3_256_context sha3_256ctx;
#endif
#ifdef WITH_HASH_SHA3_384
	sha3_384_context sha3_384ctx;
#endif
#ifdef WITH_HASH_SHA3_512
	sha3_512_context sha3_512ctx;
#endif
#ifdef WITH_HASH_SM3
	sm3_context sm3ctx;
#endif
#ifdef WITH_HASH_STREEBOG256
	streebog256_context streebog256ctx;
#endif
#ifdef WITH_HASH_STREEBOG512
	streebog512_context streebog512ctx;
#endif
#ifdef WITH_HASH_SHAKE256
	shake256_context shake256ctx;
#endif
#ifdef WITH_HASH_RIPEMD160
	ripemd160_context ripemd160ctx;
#endif
#ifdef WITH_HASH_BELT_HASH
	belt_hash_context belt_hashctx;
#endif
#ifdef WITH_HASH_BASH224
	bash224_context bash224ctx;
#endif
#ifdef WITH_HASH_BASH256
	bash256_context bash256ctx;
#endif
#ifdef WITH_HASH_BASH384
	bash384_context bash384ctx;
#endif
#ifdef WITH_HASH_BASH512
	bash512_context bash512ctx;
#endif
	/*** Deprecated hash functions ***/
#ifdef WITH_HASH_MD2
	/* MD2 */
	md2_context md2ctx;
#endif
#ifdef WITH_HASH_MD4
	/* MD4 */
	md4_context md4ctx;
#endif
#ifdef WITH_HASH_MD5
	/* MD5 */
	md5_context md5ctx;
#endif
#ifdef WITH_HASH_SHA0
	/* SHA-0 */
	sha0_context sha0ctx;
#endif
#ifdef WITH_HASH_SHA1
	/* SHA-1 */
	sha1_context sha1ctx;
#endif
#ifdef WITH_HASH_MDC2
	/* MDC2 */
	mdc2_context mdc2ctx;
#endif
#ifdef WITH_HASH_GOSTR34_11_94
	/* GOSTR34-11-94 */
	gostr34_11_94_context gostr34_11_94ctx;
#endif
} hash_context;

int hash_get_hash_sizes(hash_alg_type hash_type, uint8_t *hlen, uint8_t *block_size);
int hash_init(hash_context *ctx, hash_alg_type hash_type);
int hash_update(hash_context *ctx, const uint8_t *chunk, uint32_t chunklen, hash_alg_type hash_type);
int hash_final(hash_context *ctx, uint8_t *output, hash_alg_type hash_type);
int hash_hfunc(const uint8_t *input, uint32_t ilen, uint8_t *digest, hash_alg_type hash_type);
int hash_hfunc_scattered(const uint8_t **input, const uint32_t *ilen, uint8_t *digest, hash_alg_type hash_type);

/* Safeguard to handle MAX_DIGEST_SIZE consistency */
#ifdef __GNUC__
/* gcc and clang */
#define ATTRIBUTE_USED __attribute__((used))
#else
#define ATTRIBUTE_USED
#endif

#define _LIBHASH_CONCATENATE(a, b) a##_##b
#define LIBHASH_CONCATENATE(a, b) _LIBHASH_CONCATENATE(a, b)
void LIBHASH_CONCATENATE(libhash_consistency_check, MAX_DIGEST_SIZE) (void);
#ifdef LIBHASH_CONSISTENCY_CHECK
ATTRIBUTE_USED void LIBHASH_CONCATENATE(libhash_consistency_check,
                                        MAX_DIGEST_SIZE) (void) {
        return;
}
#else
ATTRIBUTE_USED static inline void libhash_check_libconsistency(void)
{
        LIBHASH_CONCATENATE(libhash_consistency_check,
                            MAX_DIGEST_SIZE) ();
        return;
}
#endif

#endif /* __HASH_H__ */
