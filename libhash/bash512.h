/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HASH_BASH512

#ifndef __BASH512_H__
#define __BASH512_H__

#include "utils.h"
#include "bash.h"

#define BASH512_BLOCK_SIZE   64
#define BASH512_DIGEST_SIZE  64
#define BASH512_DIGEST_SIZE_BITS  512

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < BASH512_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE BASH512_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < BASH512_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS BASH512_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < BASH512_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE BASH512_BLOCK_SIZE
#endif

#define BASH512_HASH_MAGIC ((uint64_t)(0xcd12faec63111283ULL))
#define BASH512_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == BASH512_HASH_MAGIC), ret, err)

typedef bash_context bash512_context;

int bash512_init(bash512_context *ctx);
int bash512_update(bash512_context *ctx, const uint8_t *input, uint32_t ilen);
int bash512_final(bash512_context *ctx, uint8_t output[BASH512_DIGEST_SIZE]);
int bash512_scattered(const uint8_t **inputs, const uint32_t *ilens,
		       uint8_t output[BASH512_DIGEST_SIZE]);
int bash512(const uint8_t *input, uint32_t ilen, uint8_t output[BASH512_DIGEST_SIZE]);

#endif /* __BASH512_H__ */
#endif /* WITH_HASH_BASH512 */
