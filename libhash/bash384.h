/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HASH_BASH384

#ifndef __BASH384_H__
#define __BASH384_H__

#include "utils.h"
#include "bash.h"

#define BASH384_BLOCK_SIZE   96
#define BASH384_DIGEST_SIZE  48
#define BASH384_DIGEST_SIZE_BITS  384

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < BASH384_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE BASH384_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < BASH384_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS BASH384_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < BASH384_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE BASH384_BLOCK_SIZE
#endif

#define BASH384_HASH_MAGIC ((uint64_t)(0x391af28773938752ULL))
#define BASH384_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == BASH384_HASH_MAGIC), ret, err)

typedef bash_context bash384_context;

int bash384_init(bash384_context *ctx);
int bash384_update(bash384_context *ctx, const uint8_t *input, uint32_t ilen);
int bash384_final(bash384_context *ctx, uint8_t output[BASH384_DIGEST_SIZE]);
int bash384_scattered(const uint8_t **inputs, const uint32_t *ilens,
		       uint8_t output[BASH384_DIGEST_SIZE]);
int bash384(const uint8_t *input, uint32_t ilen, uint8_t output[BASH384_DIGEST_SIZE]);

#endif /* __BASH384_H__ */
#endif /* WITH_HASH_BASH384 */
