/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HASH_BASH256

#ifndef __BASH256_H__
#define __BASH256_H__

#include "utils.h"
#include "bash.h"

#define BASH256_BLOCK_SIZE   128
#define BASH256_DIGEST_SIZE  32
#define BASH256_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < BASH256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE BASH256_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < BASH256_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS BASH256_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < BASH256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE BASH256_BLOCK_SIZE
#endif

#define BASH256_HASH_MAGIC ((uint64_t)(0x72839273873434aaULL))
#define BASH256_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == BASH256_HASH_MAGIC), ret, err)

typedef bash_context bash256_context;

int bash256_init(bash256_context *ctx);
int bash256_update(bash256_context *ctx, const uint8_t *input, uint32_t ilen);
int bash256_final(bash256_context *ctx, uint8_t output[BASH256_DIGEST_SIZE]);
int bash256_scattered(const uint8_t **inputs, const uint32_t *ilens,
		       uint8_t output[BASH256_DIGEST_SIZE]);
int bash256(const uint8_t *input, uint32_t ilen, uint8_t output[BASH256_DIGEST_SIZE]);

#endif /* __BASH256_H__ */
#endif /* WITH_HASH_BASH256 */
