/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHAKE256_H__
#define __SHAKE256_H__

#include "utils.h"
#include "shake.h"

/* NOTE: this is an instantiation of SHAKE256 with
 * maximum size of 114 bytes, specifically suited for EdDSA Ed448
 * signature scheme.
 */
#define SHAKE256_BLOCK_SIZE   136
#define SHAKE256_DIGEST_SIZE  114
#define SHAKE256_DIGEST_SIZE_BITS  912

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SHAKE256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHAKE256_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHAKE256_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHAKE256_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHAKE256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHAKE256_BLOCK_SIZE
#endif

#define SHAKE256_HASH_MAGIC ((uint64_t)(0x4326763238134567ULL))
#define SHAKE256_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHAKE256_HASH_MAGIC), ret, err)

typedef shake_context shake256_context;

int shake256_init(shake256_context *ctx);
int shake256_update(shake256_context *ctx, const uint8_t *input, uint32_t ilen);
int shake256_final(shake256_context *ctx, uint8_t output[SHAKE256_DIGEST_SIZE]);
int shake256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			uint8_t output[SHAKE256_DIGEST_SIZE]);
int shake256(const uint8_t *input, uint32_t ilen, uint8_t output[SHAKE256_DIGEST_SIZE]);

#endif /* __SHAKE256_H__ */
