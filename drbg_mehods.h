/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __DRBG_METHODS_H__
#define __DRBG_METHODS_H__

#include "helpers.h"

typedef struct {
	drbg_error (*generate)(drbg_ctx *ctx,
			       const unsigned char *addin, uint32_t addin_len,
			       unsigned char *out, uint32_t out_len);
	drbg_error (*reseed)(drbg_ctx *ctx,
			     const unsigned char *entropy_input, uint32_t entropy_input_len,
			     const unsigned char *addin, uint32_t addin_len);
	drbg_error (*uninstantiate)(drbg_ctx *ctx);

	uint32_t (*get_min_entropy_input_length)(drbg_ctx *ctx);
	uint32_t (*get_max_entropy_input_length)(drbg_ctx *ctx);
	uint32_t (*get_drbg_strength)(drbg_ctx *ctx);
	bool (*get_prediction_resistance)(drbg_ctx *ctx);
	bool (*get_need_reseed)(drbg_ctx *ctx);
	uint64_t (*get_reseed_counter)(drbg_ctx *ctx);
	uint64_t (*get_reseed_interval)(drbg_ctx *ctx);
	uint32_t (*get_max_asked_length)(drbg_ctx *ctx);
} drbg_methods;

#endif /* __DRBG_METHODS_H__ */
