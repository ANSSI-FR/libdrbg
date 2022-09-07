/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __LIBHASH_CONFIG_H__
#define __LIBHASH_CONFIG_H__

#ifndef WITH_HASH_CONF_OVERRIDE

#define WITH_HASH_SHA224
#define WITH_HASH_SHA256
#define WITH_HASH_SHA384
#define WITH_HASH_SHA512
#define WITH_HASH_SHA512_224
#define WITH_HASH_SHA512_256
#define WITH_HASH_SHA3_224
#define WITH_HASH_SHA3_256
#define WITH_HASH_SHA3_384
#define WITH_HASH_SHA3_512
#define WITH_HASH_SM3
#define WITH_HASH_STREEBOG256
#define WITH_HASH_STREEBOG512
#define WITH_HASH_SHAKE256
#define WITH_HASH_RIPEMD160
#define WITH_HASH_BELT_HASH
#define WITH_HASH_BASH224
#define WITH_HASH_BASH256
#define WITH_HASH_BASH384
#define WITH_HASH_BASH512
/* Deprecated hash functions */
#define WITH_HASH_MD2
#define WITH_HASH_MD4
#define WITH_HASH_MD5
#define WITH_HASH_SHA0
#define WITH_HASH_SHA1
#define WITH_HASH_MDC2
#define WITH_HASH_GOSTR34_11_94

#endif /* WITH_HASH_CONF_OVERRIDE */


#endif /* __LIBHASH_CONFIG_H__ */
