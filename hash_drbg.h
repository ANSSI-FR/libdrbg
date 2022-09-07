/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __HASH_DRBG_H__
#define __HASH_DRBG_H__

#include "drbg_common.h"


drbg_error hash_drbg_get_lengths(drbg_options *options,
				 uint32_t *drbg_strength,
				 uint32_t *min_entropy_input_length,
				 uint32_t *max_entropy_input_length,
				 uint32_t *max_pers_string_length,
				 uint32_t *max_addin_length,
				 uint32_t *max_asked_length);

drbg_error hash_drbg_instantiate(drbg_ctx *ctx,
				 const unsigned char *entropy_input, uint32_t entropy_input_len,
				 const unsigned char *nonce, uint32_t nonce_len,
				 const unsigned char *personalization_string, uint32_t personalization_string_len,
				 uint32_t *asked_strength,
				 drbg_options *opt);

drbg_error hash_drbg_reseed(drbg_ctx *ctx,
			    const unsigned char *entropy_input, uint32_t entropy_input_len,
			    const unsigned char *addin, uint32_t addin_len);

drbg_error hash_drbg_generate(drbg_ctx *ctx,
			      const unsigned char *addin, uint32_t addin_len,
			      unsigned char *out, uint32_t out_len);

drbg_error hash_drbg_uninstantiate(drbg_ctx *ctx);

#endif /* __HASH_DRBG_H__ */
