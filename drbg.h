/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:	  Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __DRBG_H__
#define __DRBG_H__

#include "drbg_common.h"
#include "hmac_drbg.h"
#include "hash_drbg.h"
#include "ctr_drbg.h"

drbg_error drbg_get_lengths(drbg_options *options,
			    uint32_t *drbg_strength,
			    uint32_t *min_entropy_input_length,
			    uint32_t *max_entropy_input_length,
			    uint32_t *max_pers_string_length,
			    uint32_t *max_addin_length,
			    uint32_t *max_asked_length,
			    drbg_type type);

/* The 4 main functions for DRBG (instantiate, reseed, generate and
 * uninstantiate)
 */
drbg_error drbg_instantiate(drbg_ctx *ctx,
			    const uint8_t *pers_string, uint32_t pers_string_len,
			    uint32_t *req_inst_sec_strength,
			    bool prediction_resistance,
			    drbg_type type,
			    drbg_options *opt);

drbg_error drbg_reseed(drbg_ctx *ctx,
		       const uint8_t *addin, uint32_t addin_len,
		       bool prediction_resistance_req);

drbg_error drbg_generate(drbg_ctx *ctx,
			 const uint8_t *addin, uint32_t addin_len,
			 uint8_t *out, uint32_t out_len,
			 bool prediction_resistance_req);

/*** Advanced APIs with external entropy provided by the user ***/
drbg_error drbg_instantiate_user_entropy(drbg_ctx *ctx,
					 const uint8_t *pers_string, uint32_t pers_string_len,
					 const uint8_t *entropy_input, uint32_t entropy_input_len,
					 const uint8_t *nonce, uint32_t nonce_len,
					 uint32_t *req_inst_sec_strength,
					 bool prediction_resistance,
					 drbg_type type,
					 drbg_options *opt);

drbg_error drbg_reseed_user_entropy(drbg_ctx *ctx,
				    const uint8_t *entropy_input, uint32_t entropy_input_len,
				    const uint8_t *addin, uint32_t addin_len,
				    bool prediction_resistance_req);

drbg_error drbg_generate_with_user_entropy(drbg_ctx *ctx,
				      const uint8_t *addin, uint32_t addin_len,
				      const uint8_t *reseed_entropy, uint32_t reseed_entropy_len,
				      uint8_t *out, uint32_t out_len,
				      bool prediction_resistance_req);


drbg_error drbg_uninstantiate(drbg_ctx *ctx);


/* DRBG administrative information getters */
drbg_error drbg_get_min_entropy_input_length(drbg_ctx *ctx,
					     uint32_t *min_entropy_input_length);
drbg_error drbg_get_max_entropy_input_length(drbg_ctx *ctx,
					     uint32_t *max_entropy_input_length);
drbg_error drbg_get_max_pers_string_length(drbg_ctx *ctx,
					   uint32_t *max_pers_string_length);

drbg_error drbg_get_max_addin_length(drbg_ctx *ctx,
				     uint32_t *max_addin_length);
drbg_error drbg_get_drbg_strength(drbg_ctx *ctx,
				  uint32_t *drbg_strength);
drbg_error drbg_get_prediction_resistance(drbg_ctx *ctx,
					  bool *prediction_resistance);
drbg_error drbg_get_reseed_required_flag(drbg_ctx *ctx,
					 bool *reseed_required_flag);
drbg_error drbg_get_reseed_counter(drbg_ctx *ctx,
				   uint64_t *reseed_counter);
drbg_error drbg_get_reseed_interval(drbg_ctx *ctx,
				    uint64_t *reseed_interval);
drbg_error drbg_get_max_asked_length(drbg_ctx *ctx,
				     uint32_t *max_asked_length);
drbg_error drbg_check_instantiated(drbg_ctx *ctx);

#endif /* __DRBG_H__ */
