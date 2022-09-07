/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __HMAC_H__
#define __HMAC_H__

#include "hash.h"

#define HMAC_MAGIC ((uint64_t)(0x9849020187612083ULL))
#define HMAC_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == HMAC_MAGIC) && ((A)->hash_type != HASH_UNKNOWN_HASH_ALG), ret, err)

/* The HMAC structure is made of two hash contexts */
typedef struct {
	/* The hash associated with the hmac */
	hash_alg_type hash_type;
	/* The two hash contexts (inner and outer) */
	hash_context in_ctx;
	hash_context out_ctx;
	uint8_t digest_size;
	uint8_t block_size;
	/* Initialization magic value */
	uint64_t magic;
} hmac_context;

int hmac_init(hmac_context *ctx, const uint8_t *hmackey, uint32_t hmackey_len,
              hash_alg_type hash_type);
int hmac_update(hmac_context *ctx, const uint8_t *input, uint32_t ilen);
int hmac_finalize(hmac_context *ctx, uint8_t *output, uint8_t *outlen);

#endif /* __HMAC_H__ */
