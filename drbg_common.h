/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __DRBG_COMMON_H__
#define __DRBG_COMMON_H__

#include "helpers.h"

/*** Sanity check ***/
#if !defined(WITH_HASH_DRBG) && !defined(WITH_HMAC_DRBG) && !defined(WITH_CTR_DRBG)
#error "No DRBG backend compiled! Please activate at least one!"
#endif

/* NOTE: the following helpers and macros are here to abstract
 * our DRBG type (HMAC, Hash or CTR).
 */

/* DRBG types */
typedef enum {
        DRBG_UNKNOWN = 0,
#ifdef WITH_HASH_DRBG
        DRBG_HASH    = 1,
#endif
#ifdef WITH_HMAC_DRBG
        DRBG_HMAC    = 2,
#endif
#ifdef WITH_CTR_DRBG
        DRBG_CTR     = 3,
#endif
} drbg_type;

/* DRBG errors, mapped to internal DRBG values.
 */
typedef enum {
        DRBG_OK             = 0,
        DRBG_NON_INIT       = 1,
        DRBG_ILLEGAL_INPUT  = 2,
        DRBG_BACKEND_ERROR  = 3,
        DRBG_ENTROPY_ERROR  = 4,
        DRBG_ERROR          = 5,
        DRBG_NEED_RESEED    = 6, /* used internally */
} drbg_error;

#ifdef WITH_HASH_DRBG
/*********************************************/
/********** Hash-DRBG specific data ***********/
/*********************************************/
#include "hash.h"
/* Hash-DRBG errors */
#define HASH_DRBG_OK		DRBG_OK
#define HASH_DRBG_NON_INIT	DRBG_NON_INIT
#define HASH_DRBG_ILLEGAL_INPUT	DRBG_ILLEGAL_INPUT
#define HASH_DRBG_HASH_ERROR	DRBG_BACKEND_ERROR
#define HASH_DRBG_NEED_RESEED	DRBG_NEED_RESEED
#define HASH_DRBG_ERROR		DRBG_ERROR

#define HASH_DRBG_SEED_LEN_LOW  440
#define HASH_DRBG_SEED_LEN_HIGH 888
/* Maximum seedlen */
#define HASH_DRBG_MAX_SEED_LEN    (LOCAL_MAX(HASH_DRBG_SEED_LEN_LOW, HASH_DRBG_SEED_LEN_HIGH) / 8)
/* Useful for our local buffers sizes */
#define HASH_DRBG_MAX_DIGEST_OR_SEED_SIZE (LOCAL_MAX(MAX_DIGEST_SIZE, HASH_DRBG_MAX_SEED_LEN))

/* Maximum sizes in bytes, see NIST SP800-90A Table 2 */
#define HASH_DRBG_MAX_ENTROPY_SIZE              ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HASH_DRBG_MAX_ADDIN_SIZE                ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HASH_DRBG_MAX_PERS_STRING_SIZE          ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HASH_DRBG_MAX_ADDIN_SIZE		((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */

#define HASH_DRBG_MAX_ASKED_LENGTH		(0x1 << 16) /* 2**16 bytes */
#define HASH_DRBG_MAX_RESEED_INTERVAL		((uint64_t)0x1 << 48) /* 2**48 max reseed interval */

#define HASH_DRBG_INIT_MAGIC    0x3457546717839201

typedef struct {
	hash_alg_type hash_type;
	unsigned char V[HASH_DRBG_MAX_SEED_LEN];
	unsigned char C[HASH_DRBG_MAX_SEED_LEN];
	uint32_t digest_size;
	uint32_t seed_len;
} hash_drbg_engine_data;
#define DRBG_HASH_V_SIZE HASH_DRBG_MAX_SEED_LEN
#define DRBG_HASH_C_SIZE HASH_DRBG_MAX_SEED_LEN

typedef struct {
	hash_alg_type hash_type;
} drbg_hash_options;
#define DRBG_HASH_OPTIONS_MAGIC 0x8383910264abffee
#define DRBG_HASH_OPTIONS_INIT(o, a) do {		\
	(o).type = DRBG_HASH;				\
	(o).magic = DRBG_HASH_OPTIONS_MAGIC;		\
	(o).opt.hash_options.hash_type = (a);		\
} while(0)
#endif /* WITH_HASH_DRBG */

#ifdef WITH_HMAC_DRBG
/*********************************************/
/********** HMAC-DRBG specific data ***********/
/*********************************************/
#include "hmac.h"
/* HMAC-DRBG errors */
#define HMAC_DRBG_OK		DRBG_OK
#define HMAC_DRBG_NON_INIT	DRBG_NON_INIT
#define HMAC_DRBG_ILLEGAL_INPUT	DRBG_ILLEGAL_INPUT
#define HMAC_DRBG_HMAC_ERROR	DRBG_BACKEND_ERROR
#define HMAC_DRBG_NEED_RESEED	DRBG_NEED_RESEED
#define HMAC_DRBG_ERROR		DRBG_ERROR

/* Maximum sizes in bytes, see NIST SP800-90A Table 2 */
#define HMAC_DRBG_MAX_ENTROPY_SIZE              ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HMAC_DRBG_MAX_ADDIN_SIZE                ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HMAC_DRBG_MAX_PERS_STRING_SIZE          ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define HMAC_DRBG_MAX_ADDIN_SIZE		((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */

#define HMAC_DRBG_MAX_ASKED_LENGTH		(0x1 << 16) /* 2**16 bytes */
#define HMAC_DRBG_MAX_RESEED_INTERVAL		((uint64_t)0x1 << 48) /* 2**48 max reseed interval */

#define HMAC_DRBG_INIT_MAGIC    0x1248203963918324

typedef struct {
	hash_alg_type hash_type;
	unsigned char K[MAX_DIGEST_SIZE];
	unsigned char V[MAX_DIGEST_SIZE];
	uint32_t digest_size;
} hmac_drbg_engine_data;
#define DRBG_HMAC_K_SIZE MAX_DIGEST_SIZE
#define DRBG_HMAC_V_SIZE MAX_DIGEST_SIZE

typedef struct {
	hash_alg_type hash_type;
} drbg_hmac_options;
#define DRBG_HMAC_OPTIONS_MAGIC 0x8736152903456781
#define DRBG_HMAC_OPTIONS_INIT(o, a) do {		\
	(o).type = DRBG_HMAC;				\
	(o).magic = DRBG_HMAC_OPTIONS_MAGIC;		\
	(o).opt.hmac_options.hash_type = (a);		\
} while(0)
#endif /* WITH_HMAC_DRBG */

#ifdef WITH_CTR_DRBG
/*********************************************/
/********** CTR-DRBG specific data ***********/
/*********************************************/
/* TDEA algorithm */
#include "tdes.h"
/* AES algorithm */
#include "aes.h"

/* CTR-DRBG errors */
#define CTR_DRBG_OK		DRBG_OK
#define CTR_DRBG_NON_INIT	DRBG_NON_INIT
#define CTR_DRBG_ILLEGAL_INPUT	DRBG_ILLEGAL_INPUT
#define CTR_DRBG_CTR_ERROR	DRBG_BACKEND_ERROR
#define CTR_DRBG_NEED_RESEED	DRBG_NEED_RESEED
#define CTR_DRBG_ERROR		DRBG_ERROR

/* The CTR-DRBG supported block cipher.
 * For now, we only support the approved block ciphers
 * of Table 3 in NIST SP800-90A, namely 3 Key TDEA,
 * AES-128, AES-192 and AES-256.
 */
typedef enum {
	CTR_DRBG_BC_NONE    = 0,
#ifdef WITH_BC_TDEA
	CTR_DRBG_BC_TDEA    = 1,
#endif
#ifdef WITH_BC_AES
	CTR_DRBG_BC_AES128  = 2,
	CTR_DRBG_BC_AES192  = 3,
	CTR_DRBG_BC_AES256  = 4,
#endif
} block_cipher_type;

/* CTR-DRBG DF derivation functions */
typedef enum {
	CTR_DRBG_DF_NONE = 0,
	CTR_DRBG_DF_BC	 = 1,
} df_alg;

/* Maximum key length is for AES-256 */
#define CTR_DRBG_MAX_KEY_LEN    32
/* Maximum block length is for AES */
#define CTR_DRBG_MAX_BLOCK_LEN   16
/* Maximum seedlen is CTR_DRBG_MAX_KEY_LEN + CTR_DRBG_MAX_BLOCK_LEN */
#define CTR_DRBG_MAX_SEED_LEN  (CTR_DRBG_MAX_KEY_LEN + CTR_DRBG_MAX_BLOCK_LEN)

/* Maximum sizes in bytes, see NIST SP800-90A Table 3 */
#define CTR_DRBG_MAX_ENTROPY_SIZE                               ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define CTR_DRBG_MAX_ADDIN_SIZE                                 ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define CTR_DRBG_MAX_PERS_STRING_SIZE                           ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */
#define CTR_DRBG_MAX_ADDIN_SIZE                                 ((uint64_t)0x1 << 32)  /* 2**35 bits max, 2**32 bytes max */

#define CTR_DRBG_MAX_ASKED_LENGTH_TDEA(ctr_len)			((uint32_t)(LOCAL_MIN(((0x1 << (ctr_len)) - 4) * 64, (0x1 << 13))) / 8)
#define CTR_DRBG_MAX_ASKED_LENGTH_AES(ctr_len)			((uint32_t)(LOCAL_MIN(((0x1 << (ctr_len)) - 4) * 128, (0x1 << 19))) / 8)

#define CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_TDEA              ((uint64_t)0x1 << 32) /* 2**32 max reseed interval */
#define CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_AES               ((uint64_t)0x1 << 48) /* 2**48 max reseed interval */
#define CTR_DRBG_MAX_RESEED_INTERVAL(bc_type)                   (((bc_type) == CTR_DRBG_BC_TDEA) ? CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_TDEA : CTR_DRBG_CTR_DRBG_MAX_RESEED_INTERVAL_AES)

#define CTR_DRBG_INIT_MAGIC     0x9834651251389320

typedef struct {
	block_cipher_type bc_type;
	bool use_df;
	unsigned char Key[CTR_DRBG_MAX_KEY_LEN];
	unsigned char V[CTR_DRBG_MAX_BLOCK_LEN];
	uint32_t key_len;
	uint32_t block_len;
	uint32_t ctr_len;
	uint32_t seed_len;
} ctr_drbg_engine_data;
#define DRBG_CTR_KEY_SIZE CTR_DRBG_MAX_KEY_LEN
#define DRBG_CTR_V_SIZE CTR_DRBG_MAX_BLOCK_LEN

typedef struct {
	block_cipher_type bc_type;
	bool use_df;
	uint32_t ctr_len;
} drbg_ctr_options;
#define DRBG_CTR_OPTIONS_MAGIC 0xefbf12450184b456
#define DRBG_CTR_OPTIONS_INIT(o, a, b, c) do {		\
	(o).type = DRBG_CTR;                            \
	(o).magic = DRBG_CTR_OPTIONS_MAGIC;		\
	(o).opt.ctr_options.bc_type = (a);		\
	(o).opt.ctr_options.use_df  = (b);		\
	(o).opt.ctr_options.ctr_len = (c);		\
} while(0)
#endif /* WITH_CTR_DRBG */

/***********************************************************************/
/***********************************************************************/
/***********************************************************************/


/*
 * Some helpers for power user which need to tweak specific aspects of
 * underlying DRBG engine during instantiate. Read the document and
 * use with caution.
 */
typedef struct {
	uint64_t magic;
	drbg_type type;
	union {
#ifdef WITH_HASH_DRBG
		drbg_hash_options hash_options;
#endif
#ifdef WITH_HMAC_DRBG
		drbg_hmac_options hmac_options;
#endif
#ifdef WITH_CTR_DRBG
		drbg_ctr_options ctr_options;
#endif
	} opt;
} drbg_options;

typedef union {
#ifdef WITH_HASH_DRBG
	hash_drbg_engine_data hash_data;
#endif
#ifdef WITH_HMAC_DRBG
	hmac_drbg_engine_data hmac_data;
#endif
#ifdef WITH_CTR_DRBG
	ctr_drbg_engine_data  ctr_data;
#endif
} engine_data;

/*
 * DRBG context, common to engines (CTR, HMAC, HASH) and global
 * drbg high level interface.
 */
typedef struct drbg_ctx drbg_ctx;

/* Abstract methods */
typedef struct {
	/* Main methods */
	drbg_error (*instantiate)(drbg_ctx *ctx,
				  const unsigned char *entropy_input, uint32_t entropy_input_len,
				  const unsigned char *nonce, uint32_t nonce_len,
				  const unsigned char *pers_string, uint32_t pers_string_len,
				  uint32_t *asked_strength,
				  drbg_options *opt);

	drbg_error (*generate)(drbg_ctx *ctx,
			       const unsigned char *addin, uint32_t addin_len,
			       unsigned char *out, uint32_t out_len);

	drbg_error (*reseed)(drbg_ctx *ctx,
			     const unsigned char *entropy_input, uint32_t entropy_input_len,
			     const unsigned char *addin, uint32_t addin_len);

	drbg_error (*uninstantiate)(drbg_ctx *ctx);

	drbg_error (*get_lengths)(drbg_options *options,
				  uint32_t *drb_strength,
				  uint32_t *min_entropy_input_length,
				  uint32_t *max_entropy_input_length,
				  uint32_t *max_pers_string_length,
				  uint32_t *max_addin_length,
				  uint32_t *max_asked_length);
} drbg_methods;

struct drbg_ctx {
	/* Elements specific to high level interface */
	uint64_t magic;
	bool is_instantiated;
	drbg_type type;

	/* Elements common to all engines */
	uint64_t engine_magic;
	uint32_t drbg_strength; /* in bits */
	uint32_t min_entropy_input_length;
	uint32_t max_entropy_input_length;
	uint32_t max_pers_string_length;
	uint32_t max_addin_length;
	uint32_t max_asked_length;
	uint64_t reseed_counter;
	uint64_t reseed_interval;
	bool engine_is_instantiated;
	bool prediction_resistance;
	bool reseed_required_flag;

	/* Methods for the current engine */
	drbg_methods *methods;

	/* Data/state specific to current engine */
	engine_data data;
};

static inline void common_drbg_ctx_uninit(drbg_ctx *ctx){
	if(ctx != NULL){
		ctx->drbg_strength = 0;
		ctx->min_entropy_input_length = ctx->max_entropy_input_length = 0;
		ctx->max_pers_string_length = ctx->max_addin_length = 0;
		ctx->max_asked_length = 0;
		ctx->reseed_counter = ctx->reseed_interval = 0;
		ctx->engine_is_instantiated = false;
		ctx->type = DRBG_UNKNOWN;
	}

	return;
}

static inline int common_drbg_lengths_check(drbg_ctx *ctx, const uint32_t *entropy_input_len,
					    const uint32_t *nonce_len, const uint32_t *personalization_string_len,
					    const uint32_t *addin_len, const uint32_t *asked_len){
	int ret = -1;

	(void)nonce_len;

	/*
	 * We are ensured that the context is (at least partly)
	 * instantiated when calling this function.
	 */
	if(entropy_input_len != NULL){
		if(((*entropy_input_len) < ctx->min_entropy_input_length) ||
		   ((*entropy_input_len) > ctx->max_entropy_input_length)){
			goto err;
		}
	}
	if(personalization_string_len != NULL){
		if((*personalization_string_len) > ctx->max_pers_string_length){
			goto err;
		}
	}
	if(addin_len != NULL){
		if((*addin_len) > ctx->max_addin_length){
			goto err;
		}
	}
	if(asked_len != NULL){
		if((*asked_len) > ctx->max_asked_length){
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

#if defined(WITH_HASH_DRBG) || defined(WITH_HMAC_DRBG)
static const hash_alg_type nist_supported_hashes[] = {
#ifdef WITH_HASH_SHA1
		HASH_SHA1,
#endif
#ifdef WITH_HASH_SHA224
		HASH_SHA224,
#endif
#ifdef WITH_HASH_SHA256
		HASH_SHA256,
#endif
#ifdef WITH_HASH_SHA384
		HASH_SHA384,
#endif
#ifdef WITH_HASH_SHA512
		HASH_SHA512,
#endif
#ifdef WITH_HASH_SHA512_224
		HASH_SHA512_224,
#endif
#ifdef WITH_HASH_SHA512_256
		HASH_SHA512_256,
#endif
		HASH_UNKNOWN_HASH_ALG,
};

/*
 * Provide minimum available hash function for given strength in bit.
 * hash parameter is only meaningfull if return valule is 0.
 */
ATTRIBUTE_UNUSED static int get_hash_from_strength(uint32_t drbg_strength,
						   hash_alg_type *hash)
{
	int ret = -1;

	/* Avoid unused parameters */
	(void)drbg_strength;
	(void)hash;

	if(hash == NULL) {
		goto err;
	}

#ifdef WITH_HASH_SHA1
	if(drbg_strength <= 128) {
		(*hash) = HASH_SHA1;
		ret = 0;
	}
	else
#endif
#if defined(WITH_HASH_SHA224)
	if(drbg_strength <= 192) {
		(*hash) = HASH_SHA224;
		ret = 0;
	}
	else
#elif defined(WITH_HASH_SHA512_224)
	if(drbg_strength <= 192){
		(*hash) = HASH_SHA512_224;
		ret = 0;
	}
	else
#endif
	{
#if defined(WITH_HASH_SHA256)
		(*hash) = HASH_SHA256;
		ret = 0;
#elif defined(WITH_HASH_SHA512_256)
		(*hash) = HASH_SHA512_256;
		ret = 0;
#elif defined(WITH_HASH_SHA384)
		(*hash) = HASH_SHA384;
		ret = 0;
#elif defined(WITH_HASH_SHA512)
		(*hash) = HASH_SHA512;
		ret = 0;
#endif
	}

err:
	return ret;
}
#endif

#endif /* __DRBG_COMMON_H__ */
