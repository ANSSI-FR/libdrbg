/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA3_384_H__
#define __SHA3_384_H__

#include "utils.h"
#include "sha3.h"

#define SHA3_384_BLOCK_SIZE   104
#define SHA3_384_DIGEST_SIZE  48
#define SHA3_384_DIGEST_SIZE_BITS  384

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SHA3_384_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA3_384_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA3_384_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA3_384_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA3_384_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA3_384_BLOCK_SIZE
#endif

#define SHA3_384_HASH_MAGIC ((uint64_t)(0x2233223273935643ULL))
#define SHA3_384_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA3_384_HASH_MAGIC), ret, err)

typedef sha3_context sha3_384_context;

int sha3_384_init(sha3_384_context *ctx);
int sha3_384_update(sha3_384_context *ctx, const uint8_t *input, uint32_t ilen);
int sha3_384_final(sha3_384_context *ctx, uint8_t output[SHA3_384_DIGEST_SIZE]);
int sha3_384_scattered(const uint8_t **inputs, const uint32_t *ilens,
		       uint8_t output[SHA3_384_DIGEST_SIZE]);
int sha3_384(const uint8_t *input, uint32_t ilen, uint8_t output[SHA3_384_DIGEST_SIZE]);

#endif /* __SHA3_384_H__ */
