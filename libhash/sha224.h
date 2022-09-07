/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA224_H__
#define __SHA224_H__

#include "utils.h"
#include "sha2.h"

#define SHA224_STATE_SIZE   8
#define SHA224_BLOCK_SIZE   64
#define SHA224_DIGEST_SIZE  28
#define SHA224_DIGEST_SIZE_BITS  224

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA224_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA224_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA224_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA224_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA224_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA224_BLOCK_SIZE
#endif

#define SHA224_HASH_MAGIC ((uint64_t)(0x1120323b32342910ULL))
#define SHA224_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA224_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t sha224_total;
	/* Internal state */
	uint32_t sha224_state[SHA224_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sha224_buffer[SHA224_BLOCK_SIZE];
        /* Initialization magic value */
        uint64_t magic;
} sha224_context;

int sha224_init(sha224_context *ctx);
int sha224_update(sha224_context *ctx, const uint8_t *input, uint32_t ilen);
int sha224_final(sha224_context *ctx, uint8_t output[SHA224_DIGEST_SIZE]);
int sha224_scattered(const uint8_t **inputs, const uint32_t *ilens,
		     uint8_t output[SHA224_DIGEST_SIZE]);
int sha224(const uint8_t *input, uint32_t ilen, uint8_t output[SHA224_DIGEST_SIZE]);

#endif /* __SHA224_H__ */
