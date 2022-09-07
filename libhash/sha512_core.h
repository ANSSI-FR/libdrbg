/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA512_CORE_H__
#define __SHA512_CORE_H__

#include "utils.h"
#include "sha2.h"

#define SHA512_CORE_STATE_SIZE   8
#define SHA512_CORE_BLOCK_SIZE   128
#define SHA512_CORE_DIGEST_SIZE  64

typedef struct {
	/* Number of bytes processed on 128 bits */
	uint64_t sha512_total[2];
	/* Internal state */
	uint64_t sha512_state[SHA512_CORE_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sha512_buffer[SHA512_CORE_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} sha512_core_context;


int sha512_core_update(sha512_core_context *ctx, const uint8_t *input, uint32_t ilen);
int sha512_core_final(sha512_core_context *ctx, uint8_t *output, uint32_t output_size);

#endif /* __SHA512_CORE_H__ */
