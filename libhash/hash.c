/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author: Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

/* NOTE: this is here for compilation time consistency check */
#define LIBHASH_CONSISTENCY_CHECK

#include "hash.h"

int hash_get_hash_sizes(hash_alg_type hash_type, uint8_t *hlen, uint8_t *block_size)
{
	int ret;

	MUST_HAVE((hlen != NULL) && (block_size != NULL), ret, err);

	switch(hash_type){
#ifdef WITH_HASH_SHA224
		case HASH_SHA224:{
			(*hlen) = SHA224_DIGEST_SIZE;
			(*block_size) = SHA224_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA256
		case HASH_SHA256:{
			(*hlen) = SHA256_DIGEST_SIZE;
			(*block_size) = SHA256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA384
		case HASH_SHA384:{
			(*hlen) = SHA384_DIGEST_SIZE;
			(*block_size) = SHA384_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA512
		case HASH_SHA512:{
			(*hlen) = SHA512_DIGEST_SIZE;
			(*block_size) = SHA512_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_224
		case HASH_SHA512_224:{
			(*hlen) = SHA512_224_DIGEST_SIZE;
			(*block_size) = SHA512_224_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_256
		case HASH_SHA512_256:{
			(*hlen) = SHA512_256_DIGEST_SIZE;
			(*block_size) = SHA512_256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_224
		case HASH_SHA3_224:{
			(*hlen) = SHA3_224_DIGEST_SIZE;
			(*block_size) = SHA3_224_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_256
		case HASH_SHA3_256:{
			(*hlen) = SHA3_256_DIGEST_SIZE;
			(*block_size) = SHA3_256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_384
		case HASH_SHA3_384:{
			(*hlen) = SHA3_384_DIGEST_SIZE;
			(*block_size) = SHA3_384_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_512
		case HASH_SHA3_512:{
			(*hlen) = SHA3_512_DIGEST_SIZE;
			(*block_size) = SHA3_512_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SM3
		case HASH_SM3:{
			(*hlen) = SM3_DIGEST_SIZE;
			(*block_size) = SM3_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG256
		case HASH_STREEBOG256:{
			(*hlen) = STREEBOG256_DIGEST_SIZE;
			(*block_size) = STREEBOG256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG512
		case HASH_STREEBOG512:{
			(*hlen) = STREEBOG512_DIGEST_SIZE;
			(*block_size) = STREEBOG512_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHAKE256
		case HASH_SHAKE256:{
			(*hlen) = SHAKE256_DIGEST_SIZE;
			(*block_size) = SHAKE256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_RIPEMD160
		case HASH_RIPEMD160:{
			(*hlen) = RIPEMD160_DIGEST_SIZE;
			(*block_size) = RIPEMD160_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_BELT_HASH
		case HASH_BELT_HASH:{
			(*hlen) = BELT_HASH_DIGEST_SIZE;
			(*block_size) = BELT_HASH_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_BASH224
		case HASH_BASH224:{
			(*hlen) = BASH224_DIGEST_SIZE;
			(*block_size) = BASH224_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_BASH256
		case HASH_BASH256:{
			(*hlen) = BASH256_DIGEST_SIZE;
			(*block_size) = BASH256_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_BASH384
		case HASH_BASH384:{
			(*hlen) = BASH384_DIGEST_SIZE;
			(*block_size) = BASH384_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_BASH512
		case HASH_BASH512:{
			(*hlen) = BASH512_DIGEST_SIZE;
			(*block_size) = BASH512_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
		/** Deprecated hash functions **/
#ifdef WITH_HASH_MD2
		case HASH_MD2:{
			(*hlen) = MD2_DIGEST_SIZE;
			(*block_size) = MD2_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_MD4
		case HASH_MD4:{
			(*hlen) = MD4_DIGEST_SIZE;
			(*block_size) = MD4_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_MD5
		case HASH_MD5:{
			(*hlen) = MD5_DIGEST_SIZE;
			(*block_size) = MD5_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA0
		case HASH_SHA0:{
			(*hlen) = SHA0_DIGEST_SIZE;
			(*block_size) = SHA0_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_SHA1
		case HASH_SHA1:{
			(*hlen) = SHA1_DIGEST_SIZE;
			(*block_size) = SHA1_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_MDC2
		case HASH_MDC2_PADDING1:
		case HASH_MDC2_PADDING2:{
			(*hlen) = MDC2_DIGEST_SIZE;
			(*block_size) = MDC2_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
#ifdef WITH_HASH_GOSTR34_11_94
		case HASH_GOST34_11_94_NORM:
		case HASH_GOST34_11_94_RFC4357:{
			(*hlen) = GOSTR34_11_94_DIGEST_SIZE;
			(*block_size) = GOSTR34_11_94_BLOCK_SIZE;
			ret = 0;
			break;
		}
#endif
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}

int hash_hfunc_scattered(const uint8_t **input, const uint32_t *ilen, uint8_t *digest, hash_alg_type hash_type)
{
	int ret;

	switch(hash_type){
#ifdef WITH_HASH_SHA224
		case HASH_SHA224:{
			ret = sha224_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA256
		case HASH_SHA256:{
			ret = sha256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA384
		case HASH_SHA384:{
			ret = sha384_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512
		case HASH_SHA512:{
			ret = sha512_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_224
		case HASH_SHA512_224:{
			ret = sha512_224_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_256
		case HASH_SHA512_256:{
			ret = sha512_256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_224
		case HASH_SHA3_224:{
			ret = sha3_224_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_256
		case HASH_SHA3_256:{
			ret = sha3_256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_384
		case HASH_SHA3_384:{
			ret = sha3_384_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_512
		case HASH_SHA3_512:{
			ret = sha3_512_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SM3
		case HASH_SM3:{
			ret = sm3_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG256
		case HASH_STREEBOG256:{
			ret = streebog256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG512
		case HASH_STREEBOG512:{
			ret = streebog512_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHAKE256
		case HASH_SHAKE256:{
			ret = shake256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_RIPEMD160
		case HASH_RIPEMD160:{
			ret = ripemd160_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BELT_HASH
		case HASH_BELT_HASH:{
			ret = belt_hash_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH224
		case HASH_BASH224:{
			ret = bash224_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH256
		case HASH_BASH256:{
			ret = bash256_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH384
		case HASH_BASH384:{
			ret = bash384_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH512
		case HASH_BASH512:{
			ret = bash384_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
		/** Deprecated hash functions **/
#ifdef WITH_HASH_MD2
		case HASH_MD2:{
			ret = md2_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD4
		case HASH_MD4:{
			ret = md4_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD5
		case HASH_MD5:{
			ret = md5_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA0
		case HASH_SHA0:{
			ret = sha0_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA1
		case HASH_SHA1:{
			ret = sha1_scattered(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MDC2
		case HASH_MDC2_PADDING1:{
			ret = mdc2_scattered_padding1(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_MDC2_PADDING2:{
			ret = mdc2_scattered_padding2(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_GOSTR34_11_94
		case HASH_GOST34_11_94_NORM:{
			ret = gostr34_11_94_scattered_norm(input, ilen, digest); EG(ret, err);
			break;
		}
		case HASH_GOST34_11_94_RFC4357:{
			ret = gostr34_11_94_scattered_rfc4357(input, ilen, digest); EG(ret, err);
			break;
		}
#endif
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}

int hash_hfunc(const uint8_t *input, uint32_t ilen, uint8_t *digest, hash_alg_type hash_type)
{
	const uint8_t *inputs[2] = { input, NULL };
	uint32_t ilens[2] = { ilen, 0 };

	return hash_hfunc_scattered(inputs, ilens, digest, hash_type);
}

int hash_init(hash_context *ctx, hash_alg_type hash_type)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	switch(hash_type){
#ifdef WITH_HASH_SHA224
		case HASH_SHA224:{
			ret = sha224_init(&(ctx->sha224ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA256
		case HASH_SHA256:{
			ret = sha256_init(&(ctx->sha256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA384
		case HASH_SHA384:{
			ret = sha384_init(&(ctx->sha384ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512
		case HASH_SHA512:{
			ret = sha512_init(&(ctx->sha512ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_224
		case HASH_SHA512_224:{
			ret = sha512_224_init(&(ctx->sha512_224ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_256
		case HASH_SHA512_256:{
			ret = sha512_256_init(&(ctx->sha512_256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_224
		case HASH_SHA3_224:{
			ret = sha3_224_init(&(ctx->sha3_224ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_256
		case HASH_SHA3_256:{
			ret = sha3_256_init(&(ctx->sha3_256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_384
		case HASH_SHA3_384:{
			ret = sha3_384_init(&(ctx->sha3_384ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_512
		case HASH_SHA3_512:{
			ret = sha3_512_init(&(ctx->sha3_512ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SM3
		case HASH_SM3:{
			ret = sm3_init(&(ctx->sm3ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG256
		case HASH_STREEBOG256:{
			ret = streebog256_init(&(ctx->streebog256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG512
		case HASH_STREEBOG512:{
			ret = streebog512_init(&(ctx->streebog512ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHAKE256
		case HASH_SHAKE256:{
			ret = shake256_init(&(ctx->shake256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_RIPEMD160
		case HASH_RIPEMD160:{
			ret = ripemd160_init(&(ctx->ripemd160ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BELT_HASH
		case HASH_BELT_HASH:{
			ret = belt_hash_init(&(ctx->belt_hashctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH224
		case HASH_BASH224:{
			ret = bash224_init(&(ctx->bash224ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH256
		case HASH_BASH256:{
			ret = bash256_init(&(ctx->bash256ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH384
		case HASH_BASH384:{
			ret = bash384_init(&(ctx->bash384ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH512
		case HASH_BASH512:{
			ret = bash512_init(&(ctx->bash512ctx)); EG(ret, err);
			break;
		}
#endif
		/** Deprecated hash functions **/
#ifdef WITH_HASH_MD2
		case HASH_MD2:{
			ret = md2_init(&(ctx->md2ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD4
		case HASH_MD4:{
			ret = md4_init(&(ctx->md4ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD5
		case HASH_MD5:{
			ret = md5_init(&(ctx->md5ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA0
		case HASH_SHA0:{
			ret = sha0_init(&(ctx->sha0ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA1
		case HASH_SHA1:{
			ret = sha1_init(&(ctx->sha1ctx)); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MDC2
		case HASH_MDC2_PADDING1:{
			ret = mdc2_init(&(ctx->mdc2ctx)); EG(ret, err);
			ret = mdc2_set_padding_type(&(ctx->mdc2ctx), ISOIEC10118_TYPE1); EG(ret, err);
			break;
		}
		case HASH_MDC2_PADDING2:{
			ret = mdc2_init(&(ctx->mdc2ctx)); EG(ret, err);
			ret = mdc2_set_padding_type(&(ctx->mdc2ctx), ISOIEC10118_TYPE2); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_GOSTR34_11_94
		case HASH_GOST34_11_94_NORM:{
			ret = gostr34_11_94_init(&(ctx->gostr34_11_94ctx)); EG(ret, err);
			ret = gostr34_11_94_set_type(&(ctx->gostr34_11_94ctx), GOST34_11_94_NORM); EG(ret, err);
			break;
		}
		case HASH_GOST34_11_94_RFC4357:{
			ret = gostr34_11_94_init(&(ctx->gostr34_11_94ctx)); EG(ret, err);
			ret = gostr34_11_94_set_type(&(ctx->gostr34_11_94ctx), GOST34_11_94_RFC4357); EG(ret, err);
			break;
		}
#endif
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}

int hash_update(hash_context *ctx, const uint8_t *chunk, uint32_t chunklen, hash_alg_type hash_type)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	switch(hash_type){
#ifdef WITH_HASH_SHA224
		case HASH_SHA224:{
			ret = sha224_update(&(ctx->sha224ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA256
		case HASH_SHA256:{
			ret = sha256_update(&(ctx->sha256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA384
		case HASH_SHA384:{
			ret = sha384_update(&(ctx->sha384ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512
		case HASH_SHA512:{
			ret = sha512_update(&(ctx->sha512ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_224
		case HASH_SHA512_224:{
			ret = sha512_224_update(&(ctx->sha512_224ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_256
		case HASH_SHA512_256:{
			ret = sha512_256_update(&(ctx->sha512_256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_224
		case HASH_SHA3_224:{
			ret = sha3_224_update(&(ctx->sha3_224ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_256
		case HASH_SHA3_256:{
			ret = sha3_256_update(&(ctx->sha3_256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_384
		case HASH_SHA3_384:{
			ret = sha3_384_update(&(ctx->sha3_384ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_512
		case HASH_SHA3_512:{
			ret = sha3_512_update(&(ctx->sha3_512ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SM3
		case HASH_SM3:{
			ret = sm3_update(&(ctx->sm3ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG256
		case HASH_STREEBOG256:{
			ret = streebog256_update(&(ctx->streebog256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG512
		case HASH_STREEBOG512:{
			ret = streebog512_update(&(ctx->streebog512ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHAKE256
		case HASH_SHAKE256:{
			ret = shake256_update(&(ctx->shake256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_RIPEMD160
		case HASH_RIPEMD160:{
			ret = ripemd160_update(&(ctx->ripemd160ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BELT_HASH
		case HASH_BELT_HASH:{
			ret = belt_hash_update(&(ctx->belt_hashctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH224
		case HASH_BASH224:{
			ret = bash224_update(&(ctx->bash224ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH256
		case HASH_BASH256:{
			ret = bash256_update(&(ctx->bash256ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH384
		case HASH_BASH384:{
			ret = bash384_update(&(ctx->bash384ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH512
		case HASH_BASH512:{
			ret = bash512_update(&(ctx->bash512ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
		/** Deprecated hash functions **/
#ifdef WITH_HASH_MD2
		case HASH_MD2:{
			ret = md2_update(&(ctx->md2ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD4
		case HASH_MD4:{
			ret = md4_update(&(ctx->md4ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD5
		case HASH_MD5:{
			ret = md5_update(&(ctx->md5ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA0
		case HASH_SHA0:{
			ret = sha0_update(&(ctx->sha0ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA1
		case HASH_SHA1:{
			ret = sha1_update(&(ctx->sha1ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MDC2
		case HASH_MDC2_PADDING1:
		case HASH_MDC2_PADDING2:{
			ret = mdc2_update(&(ctx->mdc2ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_GOSTR34_11_94
		case HASH_GOST34_11_94_NORM:
		case HASH_GOST34_11_94_RFC4357:{
			ret = gostr34_11_94_update(&(ctx->gostr34_11_94ctx), chunk, chunklen); EG(ret, err);
			break;
		}
#endif
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}

int hash_final(hash_context *ctx, uint8_t *output, hash_alg_type hash_type)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	switch(hash_type){
#ifdef WITH_HASH_SHA224
		case HASH_SHA224:{
			ret = sha224_final(&(ctx->sha224ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA256
		case HASH_SHA256:{
			ret = sha256_final(&(ctx->sha256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA384
		case HASH_SHA384:{
			ret = sha384_final(&(ctx->sha384ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512
		case HASH_SHA512:{
			ret = sha512_final(&(ctx->sha512ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_224
		case HASH_SHA512_224:{
			ret = sha512_224_final(&(ctx->sha512_224ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA512_256
		case HASH_SHA512_256:{
			ret = sha512_256_final(&(ctx->sha512_256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_224
		case HASH_SHA3_224:{
			ret = sha3_224_final(&(ctx->sha3_224ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_256
		case HASH_SHA3_256:{
			ret = sha3_256_final(&(ctx->sha3_256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_384
		case HASH_SHA3_384:{
			ret = sha3_384_final(&(ctx->sha3_384ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA3_512
		case HASH_SHA3_512:{
			ret = sha3_512_final(&(ctx->sha3_512ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SM3
		case HASH_SM3:{
			ret = sm3_final(&(ctx->sm3ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG256
		case HASH_STREEBOG256:{
			ret = streebog256_final(&(ctx->streebog256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_STREEBOG512
		case HASH_STREEBOG512:{
			ret = streebog512_final(&(ctx->streebog512ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHAKE256
		case HASH_SHAKE256:{
			ret = shake256_final(&(ctx->shake256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_RIPEMD160
		case HASH_RIPEMD160:{
			ret = ripemd160_final(&(ctx->ripemd160ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BELT_HASH
		case HASH_BELT_HASH:{
			ret = belt_hash_final(&(ctx->belt_hashctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH224
		case HASH_BASH224:{
			ret = bash224_final(&(ctx->bash224ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH256
		case HASH_BASH256:{
			ret = bash256_final(&(ctx->bash256ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH384
		case HASH_BASH384:{
			ret = bash384_final(&(ctx->bash384ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_BASH512
		case HASH_BASH512:{
			ret = bash512_final(&(ctx->bash512ctx), output); EG(ret, err);
			break;
		}
#endif
		/** Deprecated hash functions **/
#ifdef WITH_HASH_MD2
		case HASH_MD2:{
			ret = md2_final(&(ctx->md2ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD4
		case HASH_MD4:{
			ret = md4_final(&(ctx->md4ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MD5
		case HASH_MD5:{
			ret = md5_final(&(ctx->md5ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA0
		case HASH_SHA0:{
			ret = sha0_final(&(ctx->sha0ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_SHA1
		case HASH_SHA1:{
			ret = sha1_final(&(ctx->sha1ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_MDC2
		case HASH_MDC2_PADDING1:
		case HASH_MDC2_PADDING2:{
			ret = mdc2_final(&(ctx->mdc2ctx), output); EG(ret, err);
			break;
		}
#endif
#ifdef WITH_HASH_GOSTR34_11_94
		case HASH_GOST34_11_94_NORM:
		case HASH_GOST34_11_94_RFC4357:{
			ret = gostr34_11_94_final(&(ctx->gostr34_11_94ctx), output); EG(ret, err);
			break;
		}
#endif
		default:{
			ret = -1;
			goto err;
		}
	}

err:
	return ret;
}
