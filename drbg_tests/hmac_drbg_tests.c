/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifdef WITH_HMAC_DRBG

#include "hmac_drbg_tests.h"

static const char *get_op_name(hmac_dbrg_self_test_op op){
	switch(op){
		case HMAC_GENERATE:
			return "HMAC_GENERATE";
		case HMAC_INSTANTIATE:
			return "HMAC_INSTANTIATE";
		case HMAC_RESEED_EXPLICIT:
			return "HMAC_RESEED_EXPLICIT";
		case HMAC_RESEED_PR:
			return "HMAC_RESEED_PR";
		default:
			return "UNKNOWN_OP";
	}
}

#define MAX_OUT_SIZE 2048

int do_hmac_dbrg_self_tests(const hmac_dbrg_self_test *all_tests[], unsigned int num_tests){
	unsigned int i, j;
	drbg_ctx ctx_;
	drbg_ctx *ctx = &ctx_;
	drbg_options options;
	unsigned int num_tests_checked = 0;

	for(i = 0; i < num_tests; i++){
                hash_alg_type hash_type;
		const char *name;

	        /* Skip dummy tests */
                if(all_tests[i] == NULL){
                        continue;
                }

                hash_type = all_tests[i]->hash;
		name = all_tests[i]->name;

                DRBG_HMAC_OPTIONS_INIT(options, hash_type);

		printf("\n\t=========== Testing %s\n", name);
		num_tests_checked++;
		/* Parse all our tests */
		for(j = 0; j < all_tests[i]->num_gen; j++){
		        hmac_dbrg_self_test_op op = all_tests[i]->Expected[j].op;
			const unsigned char *EntropyInput = (const unsigned char*)all_tests[i]->Expected[j].EntropyInput;
			uint32_t EntropyInputLen = all_tests[i]->Expected[j].EntropyInputLen;
			const unsigned char *Nonce = (const unsigned char*)all_tests[i]->Expected[j].Nonce;
			uint32_t NonceLen = all_tests[i]->Expected[j].NonceLen;
			const unsigned char *PersonalizationString = (const unsigned char*)all_tests[i]->Expected[j].PersonalizationString;
			uint32_t PersonalizationStringLen = all_tests[i]->Expected[j].PersonalizationStringLen;
			const unsigned char *AdditionalInput = (const unsigned char*)all_tests[i]->Expected[j].AdditionalInput;
			uint32_t AdditionalInputLen = all_tests[i]->Expected[j].AdditionalInputLen;
			const unsigned char *AdditionalInputReseed = (const unsigned char*)all_tests[i]->Expected[j].AdditionalInputReseed;
			uint32_t AdditionalInputReseedLen = all_tests[i]->Expected[j].AdditionalInputReseedLen;
			const unsigned char *EntropyInputPR = (const unsigned char*)all_tests[i]->Expected[j].EntropyInputPR;
			uint32_t EntropyInputPRLen = all_tests[i]->Expected[j].EntropyInputPRLen;
			const unsigned char *EntropyInputReseed = (const unsigned char*)all_tests[i]->Expected[j].EntropyInputReseed;
			uint32_t EntropyInputReseedLen = all_tests[i]->Expected[j].EntropyInputReseedLen;
			const unsigned char *V = (const unsigned char*)all_tests[i]->Expected[j].V;
			const unsigned char *K = (const unsigned char*)all_tests[i]->Expected[j].K;
			const unsigned char *expected_out = (const unsigned char*)all_tests[i]->Expected[j].out;
			unsigned char output[MAX_OUT_SIZE];
			uint32_t outlen = all_tests[i]->Expected[j].outlen;

			if(MAX_OUT_SIZE < outlen){
				/* Size overflow ... */
				printf("Output size overflow ...\n");
				goto err;
			}

			if(op == HMAC_INSTANTIATE){
				/* Instantiate */
				printf("[HMAC_INSTANTIATE]\n");
				if(hmac_drbg_instantiate(ctx, EntropyInput, EntropyInputLen, Nonce, NonceLen, PersonalizationString, PersonalizationStringLen, NULL, &options) != HMAC_DRBG_OK){
					printf("Error in HMAC_INSTANTIATE\n");
					goto err;
				}
			}
			else if(op == HMAC_RESEED_EXPLICIT){
				printf("[RESEED (explicit)]\n");
				/* Explicitly call reseed */
				if(hmac_drbg_reseed(ctx, EntropyInputReseed, EntropyInputReseedLen, AdditionalInputReseed, AdditionalInputReseedLen) != HMAC_DRBG_OK){
					printf("Error in HMAC_RESEED_EXPLICIT\n");
					goto err;
				}
			}
			else if(op == HMAC_RESEED_PR){
				printf("[RESEED (PR)]\n");
				/* Explicitly call reseed */
				if(hmac_drbg_reseed(ctx, EntropyInputPR, EntropyInputPRLen, AdditionalInput, AdditionalInputLen) != HMAC_DRBG_OK){
					printf("Error in HMAC_RESEED_PR\n");
					goto err;
				}
			}
			else if(op == HMAC_GENERATE){
				printf("[HMAC_GENERATE %u bytes]\n", outlen);
				if(hmac_drbg_generate(ctx, AdditionalInput, AdditionalInputLen, output, outlen) != HMAC_DRBG_OK){
					printf("Error in HMAC_GENERATE\n");
					goto err;
				}
			}
			else{
				/* Unknown operation */
				goto err;
			}

			/* Check internal state and output if necessary */
#ifdef HMAC_DRBG_SELF_TESTS_VERBOSE
			hexdump("\tV  = ", (const char*)ctx->data.hmac_data.V, ctx->data.hmac_data.digest_size);
			hexdump("\tK  = ", (const char*)ctx->data.hmac_data.K, ctx->data.hmac_data.digest_size);
#endif
			if((strlen((const char*)V) != 0) && (strlen((const char*)K) != 0)){
				if((memcmp(ctx->data.hmac_data.V, V, ctx->data.hmac_data.digest_size)) || (memcmp(ctx->data.hmac_data.K, K, ctx->data.hmac_data.digest_size))){
					printf("Error for K or V after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef HMAC_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) V  = ", (const char*)V, ctx->data.hmac_data.digest_size);
					hexdump("\t(expected) K  = ", (const char*)K, ctx->data.hmac_data.digest_size);
#endif
					goto err;
				}
			}
			if(strlen(((const char*)expected_out)) > 0){
#ifdef HMAC_DRBG_SELF_TESTS_VERBOSE
				hexdump("\tout= ", (const char*)output, outlen);
#endif

				if(memcmp(output, expected_out, outlen)){
					printf("Error for output after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef HMAC_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) out  = ", (const char*)expected_out, outlen);
#endif
					goto err;
				}
			}
		}
		/* Uninstantiate */
		hmac_drbg_uninstantiate(ctx);
	}
	printf("\n-----------------------------\n");
	printf("[+] All tests for HMAC-DRBG are OK! :-)\n");
	printf("    (%u tests performed)\n", num_tests_checked);

	return 0;
err:
	return -1;
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
