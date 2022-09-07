#ifdef WITH_HASH_DRBG

#include "hash_drbg_tests.h"

static const char *get_op_name(hash_dbrg_self_test_op op){
	switch(op){
		case HASH_GENERATE:
			return "HASH_GENERATE";
		case HASH_INSTANTIATE:
			return "HASH_INSTANTIATE";
		case HASH_RESEED_EXPLICIT:
			return "HASH_RESEED_EXPLICIT";
		case HASH_RESEED_PR:
			return "HASH_RESEED_PR";
		default:
			return "UNKNOWN_OP";
	}
}

#define MAX_OUT_SIZE 2048

int do_hash_dbrg_self_tests(const hash_dbrg_self_test *all_tests[], unsigned int num_tests){
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

                DRBG_HASH_OPTIONS_INIT(options, hash_type);

		printf("\n\t=========== Testing %s\n", name);
		num_tests_checked++;
		/* Parse all our tests */
		for(j = 0; j < all_tests[i]->num_gen; j++){
		        hash_dbrg_self_test_op op = all_tests[i]->Expected[j].op;
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
			const unsigned char *C = (const unsigned char*)all_tests[i]->Expected[j].C;
			const unsigned char *V = (const unsigned char*)all_tests[i]->Expected[j].V;
			uint64_t reseed_counter = all_tests[i]->Expected[j].reseed_counter;
			const unsigned char *expected_out = (const unsigned char*)all_tests[i]->Expected[j].out;
			unsigned char output[MAX_OUT_SIZE];
			uint32_t outlen = all_tests[i]->Expected[j].outlen;

			if(MAX_OUT_SIZE < outlen){
				/* Size overflow ... */
				printf("Output size overflow ...\n");
				goto err;
			}

			if(op == HASH_INSTANTIATE){
				/* Instantiate */
				printf("[HASH_INSTANTIATE]\n");
				if(hash_drbg_instantiate(ctx, EntropyInput, EntropyInputLen, Nonce, NonceLen, PersonalizationString, PersonalizationStringLen, NULL, &options) != HASH_DRBG_OK){
					printf("Error in HASH_INSTANTIATE\n");
					goto err;
				}
			}
			else if(op == HASH_RESEED_EXPLICIT){
				printf("[RESEED (explicit)]\n");
				/* Explicitly call reseed */
				if(hash_drbg_reseed(ctx, EntropyInputReseed, EntropyInputReseedLen, AdditionalInputReseed, AdditionalInputReseedLen) != HASH_DRBG_OK){
					printf("Error in HASH_RESEED_EXPLICIT\n");
					goto err;
				}
			}
			else if(op == HASH_RESEED_PR){
				printf("[RESEED (PR)]\n");
				/* Explicitly call reseed */
				if(hash_drbg_reseed(ctx, EntropyInputPR, EntropyInputPRLen, AdditionalInput, AdditionalInputLen) != HASH_DRBG_OK){
					printf("Error in HASH_RESEED_PR\n");
					goto err;
				}
			}
			else if(op == HASH_GENERATE){
				printf("[HASH_GENERATE %u bytes]\n", outlen);
				if(hash_drbg_generate(ctx, AdditionalInput, AdditionalInputLen, output, outlen) != HASH_DRBG_OK){
					printf("Error in HASH_GENERATE\n");
					goto err;
				}
			}
			else{
				/* Unknown operation */
				goto err;
			}

			/* Check internal state and output if necessary */
#ifdef HASH_DRBG_SELF_TESTS_VERBOSE
			hexdump("\tC  = ", (const char*)ctx->data.hash_data.C, ctx->data.hash_data.seed_len);
			hexdump("\tV  = ", (const char*)ctx->data.hash_data.V, ctx->data.hash_data.seed_len);
			printf("\treseed_counter = %lu\n", ctx->reseed_counter);
#endif
			if((strlen((const char*)C) != 0) && (strlen((const char*)V) != 0)){
				if((memcmp(ctx->data.hash_data.C, C, ctx->data.hash_data.seed_len)) || (memcmp(ctx->data.hash_data.V, V, ctx->data.hash_data.seed_len)) || (ctx->reseed_counter != reseed_counter)){
					printf("Error for C, V or reseed_counter after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef HASH_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) C  = ", (const char*)C, ctx->data.hash_data.seed_len);
					hexdump("\t(expected) V  = ", (const char*)V, ctx->data.hash_data.seed_len);
					printf("\t(expected) reseed_counter  = %lu\n", reseed_counter);
#endif
					goto err;
				}
			}
			if(strlen(((const char*)expected_out)) > 0){
#ifdef HASH_DRBG_SELF_TESTS_VERBOSE
				hexdump("\tout= ", (const char*)output, outlen);
#endif

				if(memcmp(output, expected_out, outlen)){
					printf("Error for output after operations #%u  (type %s) for %s\n", j, get_op_name(op), name);
#ifdef HASH_DRBG_SELF_TESTS_VERBOSE
					hexdump("\t(expected) out  = ", (const char*)expected_out, outlen);
#endif
					goto err;
				}
			}
		}
		/* Uninstantiate */
		hash_drbg_uninstantiate(ctx);
	}
	printf("\n-----------------------------\n");
	printf("[+] All tests for HASH-DRBG are OK! :-)\n");
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
