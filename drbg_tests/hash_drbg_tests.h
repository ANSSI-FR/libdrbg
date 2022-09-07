/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __HASH_DRBG_TESTS_H__
#define __HASH_DRBG_TESTS_H__

#ifdef WITH_HASH_DRBG

#include "hash_drbg.h"

typedef enum {
        HASH_INSTANTIATE     = 0,
        HASH_RESEED_EXPLICIT = 1,
        HASH_RESEED_PR       = 2,
        HASH_GENERATE        = 3
} hash_dbrg_self_test_op;
typedef struct {
        hash_dbrg_self_test_op op;
        const char *EntropyInput;
	uint32_t EntropyInputLen;
        const char *Nonce;
	uint32_t NonceLen;
        const char *PersonalizationString;
	uint32_t PersonalizationStringLen;
        const char *AdditionalInput;
	uint32_t AdditionalInputLen;
        const char *EntropyInputPR;
	uint32_t EntropyInputPRLen;
        const char *EntropyInputReseed;
	uint32_t EntropyInputReseedLen;
        const char *AdditionalInputReseed;
	uint32_t AdditionalInputReseedLen;
        /* Expected out */
        const char *V;
        const char *C;
	uint64_t reseed_counter;
        uint32_t outlen;
        const char *out;
} hash_dbrg_self_test_expected;
typedef struct {
        const char *name;
        hash_alg_type hash;
        bool prediction_resistance;
        unsigned int num_gen;
        const hash_dbrg_self_test_expected *Expected;
} hash_dbrg_self_test;

#include <stdio.h>
int do_hash_dbrg_self_tests(const hash_dbrg_self_test *all_tests[], unsigned int num_tests);

#endif

#endif /* __HASH_DRBG_TESTS_H__ */
