/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA256_H__
#define __SHA256_H__

#include "utils.h"
#include "sha2.h"

#define SHA256_STATE_SIZE   8
#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SHA256_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SHA256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA256_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS	0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA256_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA256_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA256_BLOCK_SIZE
#endif

#define SHA256_HASH_MAGIC ((uint64_t)(0x11299a2b32098412ULL))
#define SHA256_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA256_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t sha256_total;
	/* Internal state */
	uint32_t sha256_state[SHA256_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sha256_buffer[SHA256_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} sha256_context;

int sha256_init(sha256_context *ctx);
int sha256_update(sha256_context *ctx, const uint8_t *input, uint32_t ilen);
int sha256_final(sha256_context *ctx, uint8_t output[SHA256_DIGEST_SIZE]);
int sha256_scattered(const uint8_t **inputs, const uint32_t *ilens,
		     uint8_t output[SHA256_DIGEST_SIZE]);
int sha256(const uint8_t *input, uint32_t ilen, uint8_t output[SHA256_DIGEST_SIZE]);

#endif /* __SHA256_H__ */
