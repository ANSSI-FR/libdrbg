/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "hmac.h"

int hmac_init(hmac_context *ctx, const uint8_t *hmackey, uint32_t hmackey_len,
              hash_alg_type hash_type)
{
        uint8_t ipad[MAX_BLOCK_SIZE] = { 0 };
        uint8_t opad[MAX_BLOCK_SIZE] = { 0 };
        uint8_t local_hmac_key[MAX_BLOCK_SIZE] = { 0 };
        unsigned int i, local_hmac_key_len;
        int ret = -1;
	uint8_t digest_size, block_size;

	if((ctx == NULL) || (hmackey == NULL)){
		goto err;
	}

        /* Set ipad and opad to appropriate values */
        memset(ipad, 0x36, sizeof(ipad));
        memset(opad, 0x5c, sizeof(opad));

	if((ret = hash_get_hash_sizes(hash_type, &digest_size, &block_size))){
		goto err;
	}
	ctx->hash_type = hash_type;
	ctx->block_size = block_size;
	ctx->digest_size = digest_size;

        if(hmackey_len <= block_size){
                /* The key size is less than the hash function block size */
                memcpy(local_hmac_key, hmackey, hmackey_len);
                local_hmac_key_len = hmackey_len;
        }
        else{
                /* The key size is greater than the hash function block size.
                 * We hash it to shorten it.
                 */
                hash_context tmp_ctx;
                if((ret = hash_init(&tmp_ctx, hash_type))){
			goto err;
		}
                if((ret = hash_update(&tmp_ctx, hmackey, hmackey_len, hash_type))){
			goto err;
		}
                if((ret = hash_final(&tmp_ctx, local_hmac_key, hash_type))){
			goto err;
		}
                local_hmac_key_len = digest_size;
        }

        /* Initialize our input and output hash contexts */
        if((ret = hash_init(&(ctx->in_ctx), hash_type))){
		goto err;
	}
        if((ret = hash_init(&(ctx->out_ctx), hash_type))){
		goto err;
	}

        /* Update our input context with K^ipad */
        for(i = 0; i < local_hmac_key_len; i++){
                ipad[i] ^= local_hmac_key[i];
        }
        if((ret = hash_update(&(ctx->in_ctx), ipad, block_size, hash_type))){
		goto err;
	}
        /* Update our output context with K^opad */
        for(i = 0; i < local_hmac_key_len; i++){
                opad[i] ^= local_hmac_key[i];
        }
        if((ret = hash_update(&(ctx->out_ctx), opad, block_size, hash_type))){
		goto err;
	}

        /* Initialize our magic */
	ret = 0;
        ctx->magic = HMAC_MAGIC;

err:
        return ret;
}

int hmac_update(hmac_context *ctx, const uint8_t *input, uint32_t ilen)
{
        int ret = -1;

        HMAC_CHECK_INITIALIZED(ctx, ret, err);
	if(!((input != NULL) || (ilen == 0))){
		goto err;
	}
        if((ret = hash_update(&(ctx->in_ctx), input, ilen, ctx->hash_type))){
		goto err;
	}

err:
        return ret;
}

int hmac_finalize(hmac_context *ctx, uint8_t *output, uint8_t *outlen)
{
        int ret = -1;
        uint8_t in_hash[MAX_DIGEST_SIZE] = { 0 };

        HMAC_CHECK_INITIALIZED(ctx, ret, err);

        if((output == NULL) || (outlen == NULL)){
		goto err;
	}
        if((*outlen) < ctx->digest_size){
		goto err;
	}

        if((ret = hash_final(&(ctx->in_ctx), in_hash, ctx->hash_type))){
		goto err;
	}
        if((ret = hash_update(&(ctx->out_ctx), in_hash, ctx->digest_size, ctx->hash_type))){
		goto err;
	}
        if((ret = hash_final(&(ctx->out_ctx), output, ctx->hash_type))){
		goto err;
	}
        (*outlen) = ctx->digest_size;

err:
        if(ctx != NULL){
                /* Clear the hash contexts that could contain sensitive data */
                memset(ctx, 0, sizeof(hmac_context));
                /* Uninitialize the context  */
                ctx->magic = (uint64_t)0;
        }
        if(ret && (outlen != NULL)){
                (*outlen) = 0;
        }
        return ret;
}
