/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "drbg.h"

/* Entropy gathering function
 * NOTE: XXX: to be implemented by the user!
 */
#include "entropy.h"

#define DRBG_INIT_MAGIC    0x1963422244881273

/* The backends callback methods */
#ifdef WITH_HASH_DRBG
static drbg_methods hash_drbg_methods = {
	.instantiate = hash_drbg_instantiate,
	.generate = hash_drbg_generate,
	.reseed = hash_drbg_reseed,
	.uninstantiate = hash_drbg_uninstantiate,
	.get_lengths = hash_drbg_get_lengths,
};
#endif
#ifdef WITH_HMAC_DRBG
static drbg_methods hmac_drbg_methods = {
	.instantiate = hmac_drbg_instantiate,
	.generate = hmac_drbg_generate,
	.reseed = hmac_drbg_reseed,
	.uninstantiate = hmac_drbg_uninstantiate,
	.get_lengths = hmac_drbg_get_lengths,
};
#endif
#ifdef WITH_CTR_DRBG
static drbg_methods ctr_drbg_methods = {
	.instantiate = ctr_drbg_instantiate,
	.generate = ctr_drbg_generate,
	.reseed = ctr_drbg_reseed,
	.uninstantiate = ctr_drbg_uninstantiate,
	.get_lengths = ctr_drbg_get_lengths,
};
#endif

/* DRBG for PRNG.
 * Standardized by NIST SP 800-90A.
 * We support HMAC-DRBG, HASH-DRBG and CTR-DRBG
 * as possible backends.
 */
static drbg_error drbg_check_initialized(drbg_ctx *ctx)
{
	drbg_error ret = DRBG_ERROR;

	if(ctx == NULL){
		ret = DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(ctx->magic != DRBG_INIT_MAGIC){
		ret = DRBG_NON_INIT;
		goto err;
	}

	ret = DRBG_OK;

err:
	return ret;
}

/**************************************/
/* DRBG properties getters */

drbg_error drbg_check_instantiated(drbg_ctx *ctx)
{
	drbg_error ret = DRBG_NON_INIT;

	if(drbg_check_initialized(ctx) != DRBG_OK){
		ret = DRBG_NON_INIT;
		goto err;
	}
	if((ctx->is_instantiated == false) ||
	   (ctx->engine_is_instantiated == false)){
		ret = DRBG_NON_INIT;
		goto err;
	}
	/* Sanity check on internal stuff */
	switch(ctx->type){
#ifdef WITH_HASH_DRBG
		case DRBG_HASH:{
			if((ctx->methods != (&hash_drbg_methods)) ||
			   (ctx->engine_magic != HASH_DRBG_INIT_MAGIC)){
				ret = DRBG_NON_INIT;
				goto err;
			}
			break;
		}
#endif
#ifdef WITH_HMAC_DRBG
		case DRBG_HMAC:{
			if((ctx->methods != (&hmac_drbg_methods)) ||
			   (ctx->engine_magic != HMAC_DRBG_INIT_MAGIC)){
				ret = DRBG_NON_INIT;
				goto err;
			}
			break;
		}
#endif
#ifdef WITH_CTR_DRBG
		case DRBG_CTR:{
			if((ctx->methods != (&ctr_drbg_methods)) ||
			   (ctx->engine_magic != CTR_DRBG_INIT_MAGIC)){
				ret = DRBG_NON_INIT;
				goto err;
			}
			break;
		}
#endif
		default:{
			ret = DRBG_ERROR;
			goto err;
		}
	}


	ret = DRBG_OK;

err:
	return ret;
}

/*
 * Use with caution: this macro returns and requires that
 * field in context matches function parameter name. On the
 * good side, it avoids a lot of code duplication for getters
 * defined below.
 */
#define GET_FROM_CTX_FIELD_OR_ERR(ctx, name)                 \
do {							     \
	if ((drbg_check_instantiated(ctx) != DRBG_OK) ||     \
	    (name == NULL)) {				     \
		return DRBG_ILLEGAL_INPUT;		     \
	}						     \
							     \
	(*(name)) = ctx->name;				     \
							     \
	return DRBG_OK;					     \
} while (0)

drbg_error drbg_get_min_entropy_input_length(drbg_ctx *ctx,
					     uint32_t *min_entropy_input_length)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, min_entropy_input_length);
}

drbg_error drbg_get_max_entropy_input_length(drbg_ctx *ctx,
					     uint32_t *max_entropy_input_length)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, max_entropy_input_length);
}

drbg_error drbg_get_max_pers_string_length(drbg_ctx *ctx,
					   uint32_t *max_pers_string_length)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, max_pers_string_length);
}

drbg_error drbg_get_max_addin_length(drbg_ctx *ctx,
				     uint32_t *max_addin_length)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, max_addin_length);
}

drbg_error drbg_get_drbg_strength(drbg_ctx *ctx,
				  uint32_t *drbg_strength)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, drbg_strength);
}

drbg_error drbg_get_prediction_resistance(drbg_ctx *ctx,
					  bool *prediction_resistance)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, prediction_resistance);
}

drbg_error drbg_get_reseed_required_flag(drbg_ctx *ctx,
				bool *reseed_required_flag)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, reseed_required_flag);
}

drbg_error drbg_get_reseed_counter(drbg_ctx *ctx,
				   uint64_t *reseed_counter)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, reseed_counter);
}

drbg_error drbg_get_reseed_interval(drbg_ctx *ctx,
				    uint64_t *reseed_interval)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, reseed_interval);
}

drbg_error drbg_get_max_asked_length(drbg_ctx *ctx,
				     uint32_t *max_asked_length)
{
	GET_FROM_CTX_FIELD_OR_ERR(ctx, max_asked_length);
}

/**************************************/

/* DRBG instantiate internal.
 */
static drbg_error _drbg_instantiate(drbg_ctx *ctx,
				    const uint8_t *pers_string, uint32_t pers_string_len,
				    const uint8_t *entropy_input, uint32_t entropy_input_len,
				    const uint8_t *nonce, uint32_t nonce_len,
				    uint32_t *req_inst_sec_strength,
				    bool prediction_resistance,
				    drbg_type type,
				    drbg_options *opt)
{
	drbg_error ret = DRBG_ERROR;
	const uint8_t *final_entropy_input;
	uint32_t final_entropy_input_len;
	const uint8_t *final_nonce;
	uint32_t final_nonce_len;
	uint32_t min_entropy_input_length;
	uint8_t *entropy_pool1 = NULL;
	uint8_t *entropy_pool2 = NULL;

	if(ctx == NULL){
		ret = DRBG_ILLEGAL_INPUT;
		goto err;
	}
	/* Depending on the chosen backend and the requested security strength,
	 * set the callbacks
	 */
	switch(type){
#ifdef WITH_HASH_DRBG
		case DRBG_HASH:{
			ctx->methods = (&hash_drbg_methods);
			break;
		}
#endif
#ifdef WITH_HMAC_DRBG
		case DRBG_HMAC:{
			ctx->methods = (&hmac_drbg_methods);
			break;
		}
#endif
#ifdef WITH_CTR_DRBG
		case DRBG_CTR:{
			ctx->methods = (&ctr_drbg_methods);
			break;
		}
#endif
		default:{
			ret = DRBG_ILLEGAL_INPUT;
			goto err;
		}
	}

	/* Get the min_entropy_input_length */
	if((ret = ctx->methods->get_lengths(opt,
					    req_inst_sec_strength,
					    &min_entropy_input_length, NULL, NULL,
					    NULL, NULL)) != DRBG_OK){
		goto err;
	}

	/* Now that we have our minimum entropy length, go and get some */
	if(min_entropy_input_length > (0xffffffff >> 1)){
		ret = DRBG_ENTROPY_ERROR;
		goto err;
	}
	/* If we are provided an entropy input, use it! */
	if(entropy_input != NULL){
		if(entropy_input_len < min_entropy_input_length){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		final_entropy_input = entropy_input;
		final_entropy_input_len = entropy_input_len;
	}
	else{
		if(get_entropy_input(&entropy_pool1, min_entropy_input_length,
				     prediction_resistance)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		final_entropy_input = (const uint8_t*)entropy_pool1;
		final_entropy_input_len = min_entropy_input_length;
	}
	/* If we are provided a nonce, use it! */
	if(nonce != NULL){
		final_nonce = nonce;
		final_nonce_len = nonce_len;
	}
	else{
		if(get_entropy_input(&entropy_pool2, min_entropy_input_length,
				     prediction_resistance)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		final_nonce = (const uint8_t*)entropy_pool2;
		final_nonce_len = min_entropy_input_length;
	}
	/* Now instantiate the drbg */
	if((ret = ctx->methods->instantiate(ctx, final_entropy_input, final_entropy_input_len,
					    final_nonce, final_nonce_len,
					    pers_string, pers_string_len,
					    req_inst_sec_strength,
					    opt)) != DRBG_OK){
		goto err;
	}

	/* Handle the prediciton resistance and the need reseed flags */
	ctx->prediction_resistance = prediction_resistance;
	ctx->reseed_required_flag = false;

	/* Now we are instantiated */
	ctx->is_instantiated = true;
	/* Set the init magic */
	ctx->magic = DRBG_INIT_MAGIC;

	ret = DRBG_OK;

err:
	if(entropy_pool1 != NULL){
		if(clear_entropy_input(entropy_pool1)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
	}
	if(entropy_pool2 != NULL){
		if(clear_entropy_input(entropy_pool2)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
	}

	return ret;
}

/* DRBG reseed internal.
 */
static drbg_error _drbg_reseed(drbg_ctx *ctx,
			       const uint8_t *entropy_input, uint32_t entropy_input_len,
			       const uint8_t *addin, uint32_t addin_len,
			       bool prediction_resistance_req)
{
	drbg_error ret = DRBG_ERROR;
	const uint8_t *final_entropy_input;
	uint32_t final_entropy_input_len;
	uint32_t min_entropy_input_length;
	bool prediction_resistance_flag;
	uint8_t *entropy_pool = NULL;

	if(drbg_check_instantiated(ctx)){
		ret = DRBG_NON_INIT;
		goto err;
	}
	/* Get parameters */
	min_entropy_input_length = ctx->min_entropy_input_length;
	prediction_resistance_flag = ctx->prediction_resistance;

	if((prediction_resistance_req == true) && (prediction_resistance_flag == false)){
		ret = DRBG_ILLEGAL_INPUT;
		goto err;
	}
	if(entropy_input != NULL){
		if(entropy_input_len < min_entropy_input_length){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		final_entropy_input = entropy_input;
		final_entropy_input_len = entropy_input_len;
	}
	else{
		/* Get entropy */
		if(get_entropy_input(&entropy_pool, min_entropy_input_length,
				     prediction_resistance_req)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		final_entropy_input = (const uint8_t*)entropy_pool;
		final_entropy_input_len = min_entropy_input_length;
	}
	/* Call the underlying backend reseed function */
	/* NOTE: size of additional input is cheched by the backend */
	if((ret = ctx->methods->reseed(ctx, final_entropy_input, final_entropy_input_len,
					addin, addin_len)) != DRBG_OK){
		goto err;
	}

	ret = DRBG_OK;

err:
	if(entropy_pool != NULL){
		if(clear_entropy_input(entropy_pool)){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
	}

	return ret;
}

/* DRBG generate internal.
 */
static drbg_error _drbg_generate(drbg_ctx *ctx,
				 const uint8_t *addin, uint32_t addin_len,
				 const uint8_t *reseed_entropy, uint32_t reseed_entropy_len,
				 uint8_t *out, uint32_t out_len,
				 bool prediction_resistance_req)
{
	drbg_error ret = DRBG_ERROR;
	bool prediction_resistance_flag;
	bool local_prediction_resistance_req = prediction_resistance_req;
	const uint8_t *local_addin = addin;
	uint32_t local_addin_len = addin_len;
	bool used_reseed_entropy = false;

	if(drbg_check_instantiated(ctx)){
		ret = DRBG_NON_INIT;
		goto err;
	}
	/* NOTE: the state automaton below is the one depicted in NIST SP 800-90A
	 * "Generate Process:".
	 */

	prediction_resistance_flag = ctx->prediction_resistance;

	/* 5. If prediction_resistance_req is set, and prediction_resistance_flag is not set, then
		return (ERROR_FLAG, Null)*/
	if((local_prediction_resistance_req == true) &&
	   (prediction_resistance_flag == false)){
		ret = DRBG_ILLEGAL_INPUT;
		goto err;
	}
	/* 6. Clear the reseed_required_flag */
	ctx->reseed_required_flag = false;

step7:
	/* 7.  If reseed_required_flag is set, or if prediction_resistance_request is set, then */
	if((ctx->reseed_required_flag == true) || (local_prediction_resistance_req == true)){
		/* If the user provided entropy and we exhausted it, trigger an error ... */
		if(used_reseed_entropy == true){
			ret = DRBG_ENTROPY_ERROR;
			goto err;
		}
		/* 7.1 Call reseed */
		if((ret = _drbg_reseed(ctx,
				       reseed_entropy, reseed_entropy_len,
				       local_addin, local_addin_len,
				       local_prediction_resistance_req)) != DRBG_OK){
			goto err;
		}
		if(reseed_entropy != NULL){
			/* Tell that we have used the user provided entropy */
			used_reseed_entropy = true;
		}
		/* 7.4  additional_input = the Null string */
		local_addin = NULL;
		local_addin_len = 0;
		/* 7.5  Clear the reseed_required_flag */
		ctx->reseed_required_flag = false;
	}
	/* 8. Call generate */
	if((ret = ctx->methods->generate(ctx, local_addin, local_addin_len, out, out_len)) != DRBG_OK){
		/*  If status indicates that a reseed is required before the requested bits can be generated,
		 * then:
		 */
		if(ret == DRBG_NEED_RESEED){
			/* 9.1	 Set the reseed_required_flag */
			ctx->reseed_required_flag = true;
			/* 9.2	 If the prediction_resistance_flag is set,
			 * then set the prediction_resistance request indication
			 */
			if(prediction_resistance_flag == true){
				local_prediction_resistance_req = true;
			}
			goto step7;
		}
		else{
			goto err;
		}
	}

	ret = DRBG_OK;
err:
	return ret;
}

/**************************************/
/* DRBG get lengths */
drbg_error drbg_get_lengths(drbg_options *options,
			    uint32_t *drbg_strength,
			    uint32_t *min_entropy_input_length,
			    uint32_t *max_entropy_input_length,
			    uint32_t *max_pers_string_length,
			    uint32_t *max_addin_length,
			    uint32_t *max_asked_length,
			    drbg_type type)
{
	drbg_error ret = DRBG_ERROR;

	switch(type){
#ifdef WITH_HASH_DRBG
		case DRBG_HASH:{
			ret = hash_drbg_methods.get_lengths(options, drbg_strength,
							    min_entropy_input_length,
							    max_entropy_input_length,
							    max_pers_string_length,
							    max_addin_length,
							    max_asked_length);
			break;
		}
#endif
#ifdef WITH_HMAC_DRBG
		case DRBG_HMAC:{
			ret = hmac_drbg_methods.get_lengths(options, drbg_strength,
							    min_entropy_input_length,
							    max_entropy_input_length,
							    max_pers_string_length,
							    max_addin_length,
							    max_asked_length);
			break;
		}
#endif
#ifdef WITH_CTR_DRBG
		case DRBG_CTR:{
			ret = ctr_drbg_methods.get_lengths(options, drbg_strength,
							   min_entropy_input_length,
							   max_entropy_input_length,
							   max_pers_string_length,
							   max_addin_length,
							   max_asked_length);
			break;
		}
#endif
		default:{
			ret = DRBG_ILLEGAL_INPUT;
			goto err;
		}
	}

err:
	return ret;
}

/* DRBG instantiate:
 * As described in NIST SP 800-90A in section 9.1, entropy_input and nonce are
 * not provided by the consuming application, but instead extracted inside the
 * drbg_instantiate function by a call to get_entropy_input.
 */
drbg_error drbg_instantiate(drbg_ctx *ctx,
			    const uint8_t *pers_string, uint32_t pers_string_len,
			    uint32_t *req_inst_sec_strength,
			    bool prediction_resistance,
			    drbg_type type,
			    drbg_options *opt)
{

	return _drbg_instantiate(ctx,
				 pers_string, pers_string_len,
				 NULL, 0,
				 NULL, 0,
				 req_inst_sec_strength, prediction_resistance,
				 type, opt);
}

drbg_error drbg_instantiate_with_user_entropy(drbg_ctx *ctx,
					 const uint8_t *pers_string, uint32_t pers_string_len,
					 const uint8_t *entropy_input, uint32_t entropy_input_len,
					 const uint8_t *nonce, uint32_t nonce_len,
					 uint32_t *req_inst_sec_strength,
					 bool prediction_resistance,
					 drbg_type type,
					 drbg_options *opt)
{
	return _drbg_instantiate(ctx,
				 pers_string, pers_string_len,
				 entropy_input, entropy_input_len,
				 nonce, nonce_len,
				 req_inst_sec_strength, prediction_resistance,
				 type, opt);
}

/* DRBG reseed.
 */
drbg_error drbg_reseed(drbg_ctx *ctx,
		       const uint8_t *addin, uint32_t addin_len,
		       bool prediction_resistance_req)
{
	return _drbg_reseed(ctx,
			    NULL, 0,
			    addin, addin_len,
			    prediction_resistance_req);
}

drbg_error drbg_reseed_with_user_entropy(drbg_ctx *ctx,
				    const uint8_t *entropy_input, uint32_t entropy_input_len,
				    const uint8_t *addin, uint32_t addin_len,
				    bool prediction_resistance_req)
{
	return _drbg_reseed(ctx,
			    entropy_input, entropy_input_len,
			    addin, addin_len,
			    prediction_resistance_req);
}


/* DRBG generate.
 */
drbg_error drbg_generate(drbg_ctx *ctx,
			 const uint8_t *addin, uint32_t addin_len,
			 uint8_t *out, uint32_t out_len,
			 bool prediction_resistance_req)
{
	return _drbg_generate(ctx,
			      addin, addin_len,
			      NULL, 0,
			      out, out_len,
			      prediction_resistance_req);
}

drbg_error drbg_generate_with_user_entropy(drbg_ctx *ctx,
					   const uint8_t *addin, uint32_t addin_len,
					   const uint8_t *reseed_entropy, uint32_t reseed_entropy_len,
					   uint8_t *out, uint32_t out_len,
					   bool prediction_resistance_req)
{
	return _drbg_generate(ctx,
			      addin, addin_len,
			      reseed_entropy, reseed_entropy_len,
			      out, out_len,
			      prediction_resistance_req);
}


/* DRBG uninstantiate */
drbg_error drbg_uninstantiate(drbg_ctx *ctx)
{
	if(drbg_check_instantiated(ctx)){
		/* NOTE: we ignore the return value on purpose to clean up
		 * the other fields in any case
		 */
		ctx->methods->uninstantiate(ctx);
	}

	ctx->prediction_resistance = false;
	ctx->reseed_required_flag = false;

	ctx->is_instantiated = false;

	ctx->magic = 0;

	return DRBG_OK;
}
