/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#include "libhash_config.h"

#ifdef WITH_HASH_GOSTR34_11_94

#include "gostr34_11_94.h"

/* The 8 4-bit GOST block cipher encryption SBOX */
static const uint8_t gostr34_11_94_sbox_norm[8][16] =
{
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};

static const uint8_t gostr34_11_94_sbox_rfc4357[8][16] =
{
	{ 10,  4,  5,  6,  8,  1,  3,  7, 13, 12, 14,  0,  9,  2, 11, 15},
	{  5, 15,  4,  0,  2, 13, 11,  9,  1,  7,  6,  3, 12, 14, 10,  8},
	{  7, 15, 12, 14,  9,  4,  1,  0,  3, 11,  5,  2,  6, 10,  8, 13},
	{  4, 10,  7, 12,  0, 15,  2,  8, 14,  1,  6,  5, 13, 11,  9,  3},
	{  7,  6,  4, 11,  9, 12,  2, 10,  1,  8,  0, 14, 15, 13,  3,  5},
	{  7,  6,  2,  4, 13,  9, 15,  0, 10,  1,  5, 11,  8, 14, 12,  3},
	{ 13, 14,  4,  1,  7,  0,  5, 10,  3, 12,  8, 15,  6,  2,  9, 11},
	{  1,  3, 10,  9,  5, 11,  4, 15,  8,  6,  7, 14, 13,  0,  2, 12}
};


/* Endianness handling */
static inline int gostr34_11_94_arch_is_big_endian(void)
{
	const uint16_t val = 0x0102;
	const uint8_t *buf = (const uint8_t *)(&val);

	return (buf[0] == 0x01);
}

/* A and P linear transformations */
static inline void gostr34_11_94_A(const uint64_t Y[GOSTR34_11_94_STATE_SIZE], uint64_t Y_[GOSTR34_11_94_STATE_SIZE])
{
	uint64_t y1, y2, y3, y4;

	y1 = Y[3];
	y2 = Y[2];
	y3 = Y[1];
	y4 = Y[0];

	Y_[0] = (y1 ^ y2);
	Y_[1] = y4;
	Y_[2] = y3;
	Y_[3] = y2;

	return;
}

static inline void gostr34_11_94_P(const uint64_t Y[GOSTR34_11_94_STATE_SIZE], uint64_t Y_[GOSTR34_11_94_STATE_SIZE])
{
	unsigned int i, k;

	const uint8_t *y = (const uint8_t*)Y;
	uint8_t *y_      = (uint8_t*)Y_;

	for(i = 0; i < 4; i++){
		for(k = 1; k < 9; k++){
			unsigned int phi_idx = (8 * GOSTR34_11_94_STATE_SIZE) - (i + (4 * (k - 1)));
			unsigned int phi = ((8 * i) + k);
			y_[phi_idx - 1] = y[phi - 1];
		}
	}
	return;
}

/* GOSTR34_11_94 key generation constants */
static const uint64_t gostr34_11_94_C[3][GOSTR34_11_94_STATE_SIZE] = {
	{ 0, 0, 0, 0 },
	{ 0xff000000ffff00ffULL, 0x00ffff00ff0000ffULL, 0xff00ff00ff00ff00ULL, 0x00ff00ff00ff00ffULL },
	{ 0, 0, 0, 0 },
};

/* GOSTR34_11_94 key generation */
static inline int gostr34_11_94_key_generation(const uint64_t H[GOSTR34_11_94_STATE_SIZE], const uint64_t M[GOSTR34_11_94_STATE_SIZE], uint64_t K[4][GOSTR34_11_94_STATE_SIZE])
{
	/* U, V, W */
	uint64_t U[GOSTR34_11_94_STATE_SIZE], V[GOSTR34_11_94_STATE_SIZE], W[GOSTR34_11_94_STATE_SIZE];
	unsigned int i, j;
	int ret;

	/* U = H */
	memcpy(U, H, sizeof(U));
	/* V = M */
	memcpy(V, M, sizeof(V));
	/* W = U ^ V */
	for(j = 0; j < GOSTR34_11_94_STATE_SIZE; j++){
		W[j] = (U[j] ^ V[j]);
	}
	/* K1 = P(W) */
	gostr34_11_94_P(W, K[0]);

	for(i = 1; i < 4; i++){
		/* U = A(U) ^ C */
		gostr34_11_94_A(U, U);
		for(j = 0; j < GOSTR34_11_94_STATE_SIZE; j++){
			uint64_t C;
			GET_UINT64_LE(C, (const uint8_t*)&gostr34_11_94_C[i - 1][j], 0);
			U[j] = (uint64_t)(U[j] ^ C);
		}
		/* V = A(A(V)) */
		gostr34_11_94_A(V, V);
		gostr34_11_94_A(V, V);
		/* W = U ^ V */
		for(j = 0; j < GOSTR34_11_94_STATE_SIZE; j++){
			W[j] = (uint64_t)(U[j] ^ V[j]);
		}
		/* Ki = P(W) */
		gostr34_11_94_P(W, K[i]);
	}

	ret = 0;

	return ret;
}

/* GOSTR34_11_94 state encryption */
static inline int gostr34_11_94_block_encryption(const uint64_t K[GOSTR34_11_94_STATE_SIZE], const uint64_t P, uint64_t *E, const uint8_t sbox[8][16])
{
	int ret;
	unsigned int round, i;
	uint32_t R_i, L_i, R_i1 = 0, L_i1 = 0;
	const uint8_t *p = (const uint8_t*)&P;
	uint8_t *e = (uint8_t*)E;

	MUST_HAVE((K != NULL) && (sbox != NULL) && (E != NULL), ret, err);

	/* The encryption is a Feistel network */
	GET_UINT32_BE(L_i, p, 0);
	GET_UINT32_BE(R_i, p, 4);
	for(round = 0; round < 32; round++){
		uint32_t sk;
		const uint8_t *k = (const uint8_t*)K;
		uint8_t *r_i1 = (uint8_t *)&R_i1;

		/* Key schedule */
		if(round < 24){
			GET_UINT32_LE(sk, k, (4 * (round % 8)));
		}
		else{
			GET_UINT32_LE(sk, k, (4 * (7 - (round % 8))));
		}
		/*** Feistel round ***/
		R_i1 = (uint32_t)(R_i + sk); /* add round key */
		/* SBox layer */
		for(i = 0; i < 4; i++){
			unsigned int sb_idx;
			if(gostr34_11_94_arch_is_big_endian()){
				sb_idx = (2 * (3 - i));
			}
			else{
				sb_idx = (2 * i);
			}
			r_i1[i] = (uint8_t)((sbox[sb_idx + 1][(r_i1[i] & 0xf0) >> 4] << 4) | (sbox[sb_idx][(r_i1[i] & 0x0f)]));
		}
		/* Rotation by 11 and XOR with L */
		R_i1 = (uint32_t)(ROTL_GOSTR34_11_94(R_i1, 11) ^ L_i);
		/* Feistel */
		L_i1 = R_i;
		/* Next round */
		R_i = R_i1;
		L_i = L_i1;
	}
	/* Output */
	PUT_UINT32_LE(L_i1, e, 0);
	PUT_UINT32_LE(R_i1, e, 4);

	ret = 0;

err:
	return ret;
}

static inline int gostr34_11_94_state_encryption(const uint64_t K[4][GOSTR34_11_94_STATE_SIZE], const uint64_t H[GOSTR34_11_94_STATE_SIZE], uint64_t S[GOSTR34_11_94_STATE_SIZE], const uint8_t sbox[8][16])
{
	int ret;


	MUST_HAVE((GOSTR34_11_94_STATE_SIZE == 4), ret, err);
	/* Return S = s4 s3 s2 s1 */
	/* s1 = E(h1, K1) */
	ret = gostr34_11_94_block_encryption(K[0], H[3], &S[0], sbox); EG(ret, err);
	/* s2 = E(h2, K2) */
	ret = gostr34_11_94_block_encryption(K[1], H[2], &S[1], sbox); EG(ret, err);
	/* s3 = E(h3, K3) */
	ret = gostr34_11_94_block_encryption(K[2], H[1], &S[2], sbox); EG(ret, err);
	/* s4 = E(h4, K4) */
	ret = gostr34_11_94_block_encryption(K[3], H[0], &S[3], sbox); EG(ret, err);

	ret = 0;

err:
	return ret;
}

/*
 * NOTE: we use a somehow "artificial" union here in order to deal with
 * possible alignment issues in the gostr34_11_94_state_psi function
 * (as we have to interpret an array of 4 uint64_t into an array of 16 uint16_t
 *  in order to apply our Psi function).
 */
typedef union {
	uint64_t A[GOSTR34_11_94_STATE_SIZE];
	uint16_t B[16];
} gostr34_11_94_union;

/* GOSTR34_11_94 output transformation */
static inline int gostr34_11_94_state_psi(const uint64_t G[GOSTR34_11_94_STATE_SIZE], uint64_t G_[GOSTR34_11_94_STATE_SIZE])
{
	int ret;
	unsigned int i;
	/* Use our unions in order to deal with alignment issues
	 * (see the rationale above).
	 */
	gostr34_11_94_union G_copy;
	gostr34_11_94_union *g  = &G_copy;
	gostr34_11_94_union *g_ = (gostr34_11_94_union*)G_;

	/* Better safe than sorry ... */
	MUST_HAVE((sizeof(gostr34_11_94_union) == (sizeof(uint64_t) * GOSTR34_11_94_STATE_SIZE)), ret, err);

	/* Copy input */
	memcpy(g, G, sizeof(gostr34_11_94_union));

	/* ψ(Γ) = (γ0 ⊕ γ1 ⊕ γ2 ⊕ γ3 ⊕ γ12 ⊕ γ15) γ15 γ14 · · · γ1
	 * where Γ is split into sixteen 16-bit words, i.e. Γ = γ15 γ14 · · · γ0.
	 */
	for(i = 0; i < 15; i++){
		g_->B[i] = g->B[i + 1];
	}
	g_->B[15] = (uint16_t)((g->B[0]) ^ (g->B[1]) ^ (g->B[2]) ^ (g->B[3]) ^ (g->B[12]) ^ (g->B[15]));

	ret = 0;

err:
	return ret;
}

static inline int gostr34_11_94_state_output_transform(const uint64_t H[GOSTR34_11_94_STATE_SIZE], const uint64_t S[GOSTR34_11_94_STATE_SIZE], const uint64_t M[GOSTR34_11_94_STATE_SIZE], uint64_t H_[GOSTR34_11_94_STATE_SIZE])
{
	unsigned int i;
	int ret;

	/* Compute psi^12 of S */
	memcpy(H_, S, GOSTR34_11_94_STATE_SIZE * sizeof(uint64_t));
	for(i = 0; i < 12; i++){
		ret = gostr34_11_94_state_psi(H_, H_); EG(ret, err);
	}
	/* Compute M xor psi^12  */
	for(i = 0; i < GOSTR34_11_94_STATE_SIZE; i++){
		uint64_t m;
		if(gostr34_11_94_arch_is_big_endian()){
			GET_UINT64_LE(m, (const uint8_t*)&M[GOSTR34_11_94_STATE_SIZE - i - 1], 0);
		}
		else{
			GET_UINT64_BE(m, (const uint8_t*)&M[GOSTR34_11_94_STATE_SIZE - i - 1], 0);
		}
		H_[i] = (uint64_t)(H_[i] ^ m);
	}
	ret = gostr34_11_94_state_psi(H_, H_); EG(ret, err);
	/* Xor it with H */
	for(i = 0; i < GOSTR34_11_94_STATE_SIZE; i++){
		uint64_t h;
		if(gostr34_11_94_arch_is_big_endian()){
			GET_UINT64_LE(h, (const uint8_t*)&H[GOSTR34_11_94_STATE_SIZE - i - 1], 0);
		}
		else{
			GET_UINT64_BE(h, (const uint8_t*)&H[GOSTR34_11_94_STATE_SIZE - i - 1], 0);
		}
		H_[i] = (uint64_t)(H_[i] ^ h);
	}
	/* Now compute psi^61 */
	for(i = 0; i < 61; i++){
		ret = gostr34_11_94_state_psi(H_, H_); EG(ret, err);
	}

	ret = 0;

err:
	return ret;
}

/* GOSTR34_11_94 256-bit words summing (a simple adder with carry in constant time) */
static inline void gostr34_11_94_256bit_sum(const uint64_t A[GOSTR34_11_94_STATE_SIZE], const uint64_t B[GOSTR34_11_94_STATE_SIZE], uint64_t C[GOSTR34_11_94_STATE_SIZE])
{
	unsigned int i;
	uint64_t tmp, carry1, carry2, _carry;

	_carry = 0;
	for(i = 0; i < GOSTR34_11_94_STATE_SIZE; i++){
		uint64_t a, b, c;
		unsigned int idx = (GOSTR34_11_94_STATE_SIZE - i - 1);
		GET_UINT64_BE(a, (const uint8_t*)(&A[idx]), 0);
		GET_UINT64_BE(b, (const uint8_t*)(&B[idx]), 0);
		tmp = (uint64_t)(a + b);
		carry1 = (uint64_t)(tmp < a);
		c = (uint64_t)(tmp + _carry);
		carry2 = (uint64_t)(c < tmp);
		_carry = (uint64_t)(carry1 | carry2);
		PUT_UINT64_BE(c, (uint8_t*)(&C[idx]), 0);
	}

	return;
}

/* GOSTR34_11_94 core processing. Returns 0 on success, -1 on error. */
static inline int gostr34_11_94_process(gostr34_11_94_context *ctx,
			   const uint8_t data[GOSTR34_11_94_BLOCK_SIZE])
{
	int ret;
	unsigned int i;
	uint64_t K[4][GOSTR34_11_94_STATE_SIZE];
	uint64_t H[GOSTR34_11_94_STATE_SIZE], S[GOSTR34_11_94_STATE_SIZE], M[GOSTR34_11_94_STATE_SIZE];

	MUST_HAVE((data != NULL), ret, err);
	GOSTR34_11_94_HASH_CHECK_INITIALIZED(ctx, ret, err);
	/* Get our local data in little endian format */
	for(i = 0; i < GOSTR34_11_94_BLOCK_SIZE; i++){
		((uint8_t*)M)[i] = data[GOSTR34_11_94_BLOCK_SIZE - i - 1];
	}
	/* Get the saved state */
	for(i = 0; i < GOSTR34_11_94_BLOCK_SIZE; i++){
		((uint8_t*)H)[i] = ((uint8_t*)ctx->gostr34_11_94_state)[GOSTR34_11_94_BLOCK_SIZE - i - 1];
	}

	/* Key generation */
	ret = gostr34_11_94_key_generation(H, M, K); EG(ret, err);
	/* State encryption */
	switch(ctx->gostr34_11_94_t){
		case GOST34_11_94_NORM:{
			ret = gostr34_11_94_state_encryption((const uint64_t (*)[4])K, H, S, gostr34_11_94_sbox_norm); EG(ret, err);
			break;
		}
		case GOST34_11_94_RFC4357:{
			ret = gostr34_11_94_state_encryption((const uint64_t (*)[4])K, H, S, gostr34_11_94_sbox_rfc4357); EG(ret, err);
			break;
		}
		default:{
			ret = -1;
			goto err;
		}
	}
	/* Output transformation */
	ret = gostr34_11_94_state_output_transform(H, S, M, ctx->gostr34_11_94_state); EG(ret, err);
	/* Update the internal sum */
	gostr34_11_94_256bit_sum(ctx->gostr34_11_94_sum, M, ctx->gostr34_11_94_sum);

	ret = 0;

err:
	return ret;
}

/* Init hash function. Returns 0 on success, -1 on error. */
int gostr34_11_94_init(gostr34_11_94_context *ctx)
{
	int ret;

	MUST_HAVE((ctx != NULL), ret, err);

	ctx->gostr34_11_94_total = 0;
	ctx->gostr34_11_94_state[0] = 0;
	ctx->gostr34_11_94_state[1] = 0;
	ctx->gostr34_11_94_state[2] = 0;
	ctx->gostr34_11_94_state[3] = 0;

	memset(ctx->gostr34_11_94_sum, 0, sizeof(ctx->gostr34_11_94_sum));

	/* Our default GOST34_11_94 type is GOST34_11_94_NORM */
	ctx->gostr34_11_94_t = GOST34_11_94_NORM;

	/* Tell that we are initialized */
	ctx->magic = GOSTR34_11_94_HASH_MAGIC;

	ret = 0;

err:
	return ret;
}

/* Function to modify the initial IV as it is not imposed by the RFCs */
int gostr34_11_94_set_iv(gostr34_11_94_context *ctx, const uint64_t iv[GOSTR34_11_94_STATE_SIZE])
{
	int ret;

	MUST_HAVE((iv != NULL), ret, err);
	GOSTR34_11_94_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* We cannot change the IV after the first update */
	MUST_HAVE((ctx->gostr34_11_94_total == 0), ret, err);

	ctx->gostr34_11_94_state[0] = iv[0];
	ctx->gostr34_11_94_state[1] = iv[1];
	ctx->gostr34_11_94_state[2] = iv[2];
	ctx->gostr34_11_94_state[3] = iv[3];

	ret = 0;

err:
	return ret;
}

/* Function to modify the GOST type (that will dictate the underlying SBOX to use for block encryption) */
int gostr34_11_94_set_type(gostr34_11_94_context *ctx, gostr34_11_94_type type)
{
	int ret;

	GOSTR34_11_94_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* We cannot change the algorithm type after the first update */
	MUST_HAVE((ctx->gostr34_11_94_total == 0), ret, err);

	if((type != GOST34_11_94_NORM) && (type != GOST34_11_94_RFC4357)){
		ret = -1;
		goto err;
	}

	ctx->gostr34_11_94_t = type;

	ret = 0;

err:
	return ret;
}


int gostr34_11_94_update(gostr34_11_94_context *ctx, const uint8_t *input, uint32_t ilen)
{
	const uint8_t *data_ptr = input;
	uint32_t remain_ilen = ilen;
	uint16_t fill;
	uint8_t left;
	int ret;

	MUST_HAVE((input != NULL) || (ilen == 0), ret, err);
	GOSTR34_11_94_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* Nothing to process, return */
	if (ilen == 0) {
		ret = 0;
		goto err;
	}

	/* Get what's left in our local buffer */
	left = (ctx->gostr34_11_94_total & 0x3F);
	fill = (uint16_t)(GOSTR34_11_94_BLOCK_SIZE - left);

	ctx->gostr34_11_94_total += ilen;

	if ((left > 0) && (remain_ilen >= fill)) {
		/* Copy data at the end of the buffer */
		memcpy(ctx->gostr34_11_94_buffer + left, data_ptr, fill);
		ret = gostr34_11_94_process(ctx, ctx->gostr34_11_94_buffer); EG(ret, err);
		data_ptr += fill;
		remain_ilen -= fill;
		left = 0;
	}

	while (remain_ilen >= GOSTR34_11_94_BLOCK_SIZE) {
		ret = gostr34_11_94_process(ctx, data_ptr); EG(ret, err);
		data_ptr += GOSTR34_11_94_BLOCK_SIZE;
		remain_ilen -= GOSTR34_11_94_BLOCK_SIZE;
	}

	if (remain_ilen > 0) {
		memcpy(ctx->gostr34_11_94_buffer + left, data_ptr, remain_ilen);
	}

	ret = 0;

err:
	return ret;
}

/* Finalize. Returns 0 on success, -1 on error.*/
int gostr34_11_94_final(gostr34_11_94_context *ctx, uint8_t output[GOSTR34_11_94_DIGEST_SIZE])
{
	unsigned int block_present = 0;
	uint8_t last_padded_block[2 * GOSTR34_11_94_BLOCK_SIZE];
	int ret;

	MUST_HAVE((output != NULL), ret, err);
	GOSTR34_11_94_HASH_CHECK_INITIALIZED(ctx, ret, err);

	/* This is our final step, so we proceed with the padding if necessary */
	/* Fill in our last block with zeroes */
	memset(last_padded_block, 0, sizeof(last_padded_block));

	block_present = ctx->gostr34_11_94_total % GOSTR34_11_94_BLOCK_SIZE;
	/* Copy what's left in our temporary context buffer */
	memcpy(last_padded_block, ctx->gostr34_11_94_buffer,
			     block_present);

	/* Put in the second block the size in bits of the message in bits in little endian */
	PUT_UINT64_LE(8 * ctx->gostr34_11_94_total, last_padded_block, GOSTR34_11_94_BLOCK_SIZE);

	if(block_present != 0){
		/* Process padding block if necessary */
		ret = gostr34_11_94_process(ctx, last_padded_block); EG(ret, err);
	}
	/* Copy our sum in the beginning of the block */
	if(gostr34_11_94_arch_is_big_endian()){
		PUT_UINT64_LE(ctx->gostr34_11_94_sum[3], last_padded_block, 0);
		PUT_UINT64_LE(ctx->gostr34_11_94_sum[2], last_padded_block, 8);
		PUT_UINT64_LE(ctx->gostr34_11_94_sum[1], last_padded_block, 16);
		PUT_UINT64_LE(ctx->gostr34_11_94_sum[0], last_padded_block, 24);
	}
	else{
		PUT_UINT64_BE(ctx->gostr34_11_94_sum[3], last_padded_block, 0);
		PUT_UINT64_BE(ctx->gostr34_11_94_sum[2], last_padded_block, 8);
		PUT_UINT64_BE(ctx->gostr34_11_94_sum[1], last_padded_block, 16);
		PUT_UINT64_BE(ctx->gostr34_11_94_sum[0], last_padded_block, 24);
	}

	/* Process the "size" in bits block */
	ret = gostr34_11_94_process(ctx, last_padded_block + GOSTR34_11_94_BLOCK_SIZE); EG(ret, err);
	/* Process the message blocks sum */
	ret = gostr34_11_94_process(ctx, last_padded_block); EG(ret, err);

	/* Output the hash result */
	if(gostr34_11_94_arch_is_big_endian()){
		PUT_UINT64_BE(ctx->gostr34_11_94_state[0], output, 0);
		PUT_UINT64_BE(ctx->gostr34_11_94_state[1], output, 8);
		PUT_UINT64_BE(ctx->gostr34_11_94_state[2], output, 16);
		PUT_UINT64_BE(ctx->gostr34_11_94_state[3], output, 24);
	}
	else{
		PUT_UINT64_LE(ctx->gostr34_11_94_state[0], output, 0);
		PUT_UINT64_LE(ctx->gostr34_11_94_state[1], output, 8);
		PUT_UINT64_LE(ctx->gostr34_11_94_state[2], output, 16);
		PUT_UINT64_LE(ctx->gostr34_11_94_state[3], output, 24);
	}

	/* Tell that we are uninitialized */
	ctx->magic = (uint64_t)0;

	ret = 0;

err:
	return ret;
}


/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int gostr34_11_94_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE], gostr34_11_94_type type)
{
	gostr34_11_94_context ctx;
	int ret, pos = 0;

	MUST_HAVE((inputs != NULL) && (ilens != NULL) && (output != NULL), ret, err);

	ret = gostr34_11_94_init(&ctx); EG(ret, err);
	ret = gostr34_11_94_set_type(&ctx, type); EG(ret, err);

	while (inputs[pos] != NULL) {
		ret = gostr34_11_94_update(&ctx, inputs[pos], ilens[pos]); EG(ret, err);
		pos += 1;
	}

	ret = gostr34_11_94_final(&ctx, output);

err:
	return ret;
}

int gostr34_11_94_scattered_norm(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE])
{
	return gostr34_11_94_scattered(inputs, ilens, output, GOST34_11_94_NORM);
}

int gostr34_11_94_scattered_rfc4357(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE])
{
	return gostr34_11_94_scattered(inputs, ilens, output, GOST34_11_94_RFC4357);
}


/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int gostr34_11_94(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE], gostr34_11_94_type type)
{
	gostr34_11_94_context ctx;
	int ret;

	ret = gostr34_11_94_init(&ctx); EG(ret, err);
	ret = gostr34_11_94_set_type(&ctx, type); EG(ret, err);
	ret = gostr34_11_94_update(&ctx, input, ilen); EG(ret, err);
	ret = gostr34_11_94_final(&ctx, output);

err:
	return ret;
}

int gostr34_11_94_norm(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE])
{
	return gostr34_11_94(input, ilen, output, GOST34_11_94_NORM);
}

int gostr34_11_94_rfc4357(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE])
{
	return gostr34_11_94(input, ilen, output, GOST34_11_94_RFC4357);
}

#else
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
