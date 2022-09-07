/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA512_256_H__
#define __SHA512_256_H__

#include "utils.h"
#include "sha2.h"
#include "sha512_core.h"

#define SHA512_256_STATE_SIZE   SHA512_CORE_STATE_SIZE
#define SHA512_256_BLOCK_SIZE   SHA512_CORE_BLOCK_SIZE
#define SHA512_256_DIGEST_SIZE  32
#define SHA512_256_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA512_256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA512_256_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA512_256_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA512_256_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE	0
#endif
#if (MAX_BLOCK_SIZE < SHA512_256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA512_256_BLOCK_SIZE
#endif

#define SHA512_256_HASH_MAGIC ((uint64_t)(0x1239567373987616ULL))
#define SHA512_256_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA512_256_HASH_MAGIC), ret, err)

typedef sha512_core_context sha512_256_context;

int sha512_256_init(sha512_256_context *ctx);
int sha512_256_update(sha512_256_context *ctx, const uint8_t *input, uint32_t ilen);
int sha512_256_final(sha512_256_context *ctx, uint8_t output[SHA512_256_DIGEST_SIZE]);
int sha512_256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			 uint8_t output[SHA512_256_DIGEST_SIZE]);
int sha512_256(const uint8_t *input, uint32_t ilen, uint8_t output[SHA512_256_DIGEST_SIZE]);

#endif /* __SHA512_256_H__ */
