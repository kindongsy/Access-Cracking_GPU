#include "sha512.cuh"
#define FIX_PTLEN	8
#define FIX_SALTLEN	4
#define FIX_DKLEN	64
#define FIX_DKOUT	(FIX_DKLEN >> 3)
#define US_PAD_PT_SIZE	7 * 4

__constant__ uint8_t constant_salt[4] = { 0, };

__device__ void _SHA512_init(SHA512_INFO* info) {
	for (int i = 0; i < SHA512_BLOCK; i++)
		info->BUF[i] = 0;
	info->lastLen = 0, info->ptLen = 0;
	info->digest[0] = 0x6a09e667f3bcc908;
	info->digest[1] = 0xbb67ae8584caa73b;
	info->digest[2] = 0x3c6ef372fe94f82b;
	info->digest[3] = 0xa54ff53a5f1d36f1;
	info->digest[4] = 0x510e527fade682d1;
	info->digest[5] = 0x9b05688c2b3e6c1f;
	info->digest[6] = 0x1f83d9abfb41bd6b;
	info->digest[7] = 0x5be0cd19137e2179;
}

static void state_transform(uint8_t* state, uint64_t block_size, uint64_t thread_size) {
	uint8_t* buffer = (uint8_t*)malloc(block_size * thread_size * sizeof(uint8_t) * FIX_PTLEN);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint8_t) * FIX_PTLEN);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[i] = buffer[FIX_PTLEN * i];
		state[(1 * block_size * thread_size) + i] = buffer[FIX_PTLEN * i + 1];
		state[(2 * block_size * thread_size) + i] = buffer[FIX_PTLEN * i + 2];
		state[(3 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 3];
		state[(4 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 4];
		state[(5 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 5];
		state[(6 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 6];
		state[(7 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 7];
	}
	free(buffer);
}
static void salt_transform(uint8_t* state, uint64_t block_size, uint64_t thread_size) {
	uint8_t* buffer = (uint8_t*)malloc(block_size * thread_size * sizeof(uint8_t) * FIX_SALTLEN);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint8_t) * FIX_SALTLEN);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[i] = buffer[FIX_SALTLEN * i];
		state[(1 * block_size * thread_size) + i] = buffer[FIX_SALTLEN * i + 1];
		state[(2 * block_size * thread_size) + i] = buffer[FIX_SALTLEN * i + 2];
		state[(3 * block_size * thread_size + i)] = buffer[FIX_SALTLEN * i + 3];
	}
	free(buffer);
}
static void dk_transform(uint64_t* state, uint64_t block_size, uint64_t thread_size) {
	uint64_t* buffer = (uint64_t*)malloc(block_size * thread_size * sizeof(uint64_t) * 8);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint64_t) * 8);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[FIX_PTLEN * i] = buffer[i];
		state[FIX_PTLEN * i + 1] = buffer[(1 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 2] = buffer[(2 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 3] = buffer[(3 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 4] = buffer[(4 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 5] = buffer[(5 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 6] = buffer[(6 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 7] = buffer[(7 * block_size * thread_size) + i];
	}
	free(buffer);
}

static void dk_transform_2(uint64_t* state, uint64_t block_size, uint64_t thread_size) {
	uint64_t* buffer = (uint64_t*)malloc(block_size * thread_size * sizeof(uint64_t) * 8);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint64_t) * 8);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[FIX_PTLEN * i] = buffer[i];
		state[FIX_PTLEN * i + 1] = buffer[(1 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 2] = buffer[(2 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 3] = buffer[(3 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 4] = buffer[(4 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 5] = buffer[(5 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 6] = buffer[(6 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 7] = buffer[(7 * block_size * thread_size) + i];
	}
	free(buffer);
}

__device__ void _SHA512_preCompute_core(uint64_t* input, uint64_t* digest) {

	uint64_t w0_t = ENDIAN_CHANGE64(input[0]);
	uint64_t w1_t = ENDIAN_CHANGE64(input[1]);
	uint64_t w2_t = ENDIAN_CHANGE64(input[2]);
	uint64_t w3_t = ENDIAN_CHANGE64(input[3]);
	uint64_t w4_t = ENDIAN_CHANGE64(input[4]);
	uint64_t w5_t = ENDIAN_CHANGE64(input[5]);
	uint64_t w6_t = ENDIAN_CHANGE64(input[6]);
	uint64_t w7_t = ENDIAN_CHANGE64(input[7]);
	uint64_t w8_t = ENDIAN_CHANGE64(input[8]);
	uint64_t w9_t = ENDIAN_CHANGE64(input[9]);
	uint64_t wa_t = ENDIAN_CHANGE64(input[10]);
	uint64_t wb_t = ENDIAN_CHANGE64(input[11]);
	uint64_t wc_t = ENDIAN_CHANGE64(input[12]);
	uint64_t wd_t = ENDIAN_CHANGE64(input[13]);
	uint64_t we_t = ENDIAN_CHANGE64(input[14]);
	uint64_t wf_t = ENDIAN_CHANGE64(input[15]);
	uint64_t a, b, c, d, e, f, g, h = 0;

	a = 0x6a09e667f3bcc908;
	b = 0xbb67ae8584caa73b;
	c = 0x3c6ef372fe94f82b;
	d = 0xa54ff53a5f1d36f1;
	e = 0x510e527fade682d1;
	f = 0x9b05688c2b3e6c1f;
	g = 0x1f83d9abfb41bd6b;
	h = 0x5be0cd19137e2179;

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);


	digest[0] = a + 0x6a09e667f3bcc908;
	digest[1] = b + 0xbb67ae8584caa73b;
	digest[2] = c + 0x3c6ef372fe94f82b;
	digest[3] = d + 0xa54ff53a5f1d36f1;
	digest[4] = e + 0x510e527fade682d1;
	digest[5] = f + 0x9b05688c2b3e6c1f;
	digest[6] = g + 0x1f83d9abfb41bd6b;
	digest[7] = h + 0x5be0cd19137e2179;
}

__device__ void _PBKDF2_HMAC_SHA512_precompute(uint8_t* pt, uint64_t ptLen, PBKDF2_HMAC_SHA512_INFO* info) {
	uint8_t K1[SHA512_BLOCK];
	uint8_t K2[SHA512_BLOCK];

	for (int i = 0; i < ptLen; i++) {
		K1[i] = 0x36 ^ pt[i];
		K2[i] = 0x5c ^ pt[i];
	}
	for (int i = ptLen; i < SHA512_BLOCK; i++) {
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}
	_SHA512_preCompute_core((uint64_t*)K1, info->IPAD);
	_SHA512_preCompute_core((uint64_t*)K2, info->OPAD);
}

__device__ void _SHA512_core(const uint64_t* input, uint64_t* digest) {
	uint64_t w0_t = ENDIAN_CHANGE64(input[0]);
	uint64_t w1_t = ENDIAN_CHANGE64(input[1]);
	uint64_t w2_t = ENDIAN_CHANGE64(input[2]);
	uint64_t w3_t = ENDIAN_CHANGE64(input[3]);
	uint64_t w4_t = ENDIAN_CHANGE64(input[4]);
	uint64_t w5_t = ENDIAN_CHANGE64(input[5]);
	uint64_t w6_t = ENDIAN_CHANGE64(input[6]);
	uint64_t w7_t = ENDIAN_CHANGE64(input[7]);
	uint64_t w8_t = ENDIAN_CHANGE64(input[8]);
	uint64_t w9_t = ENDIAN_CHANGE64(input[9]);
	uint64_t wa_t = ENDIAN_CHANGE64(input[10]);
	uint64_t wb_t = ENDIAN_CHANGE64(input[11]);
	uint64_t wc_t = ENDIAN_CHANGE64(input[12]);
	uint64_t wd_t = ENDIAN_CHANGE64(input[13]);
	uint64_t we_t = ENDIAN_CHANGE64(input[14]);
	uint64_t wf_t = ENDIAN_CHANGE64(input[15]);
	uint64_t a, b, c, d, e, f, g, h = 0;

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

__device__ void _SHA512_process(uint8_t* pt, uint64_t ptLen, SHA512_INFO* info) {
	uint64_t pt_index = 0;
	while ((ptLen + info->lastLen) >= SHA512_BLOCK) {
		for (int i = info->lastLen; i < (SHA512_BLOCK - info->lastLen); i++) {
			info->BUF[i] = pt[i + pt_index];
		}
		_SHA512_core((uint64_t*)info->BUF, info->digest);
		ptLen -= (SHA512_BLOCK - info->lastLen);
		info->ptLen += (SHA512_BLOCK - info->lastLen);
		pt_index += (SHA512_BLOCK - info->lastLen);
		info->lastLen = 0;
	}
	for (int i = 0; i < ptLen; i++) {
		info->BUF[i + info->lastLen] = pt[i + pt_index];
	}
	info->lastLen += ptLen;
	pt_index = 0;
}

__device__ void _SHA512_salt_compute_final(SHA512_INFO* info, uint64_t* out) {
	uint64_t r = (info->lastLen) % SHA512_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA512_BLOCK - 16) {
		for (uint64_t i = r; i < SHA512_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA512_core((uint64_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 2] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) >> 61);
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 1] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) << 3) & 0xffffffffffffffff;
	_SHA512_core((uint64_t*)info->BUF, info->digest);
	out[0] = info->digest[0];
	out[1] = info->digest[1];
	out[2] = info->digest[2];
	out[3] = info->digest[3];
	out[4] = info->digest[4];
	out[5] = info->digest[5];
	out[6] = info->digest[6];
	out[7] = info->digest[7];
}

__device__ void _PBKDF2_HMAC_SHA512_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA512_INFO* INFO, uint64_t* out) {
	SHA512_INFO info;
	uint8_t temp[4] = { (integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, (integer & 0xff) };
	info.digest[0] = INFO->IPAD[0];
	info.digest[1] = INFO->IPAD[1];
	info.digest[2] = INFO->IPAD[2];
	info.digest[3] = INFO->IPAD[3];
	info.digest[4] = INFO->IPAD[4];
	info.digest[5] = INFO->IPAD[5];
	info.digest[6] = INFO->IPAD[6];
	info.digest[7] = INFO->IPAD[7];
	info.ptLen = SHA512_BLOCK;
	info.lastLen = 0;
	_SHA512_process(salt, saLen, &info);
	_SHA512_process(temp, 4, &info);
	_SHA512_salt_compute_final(&info, out);
}



__device__ void _PBKDF2_HMAC_SHA512_core(uint64_t* _prestate, uint64_t* digest, uint64_t* in) {
	uint64_t w0_t = in[0];
	uint64_t w1_t = in[1];
	uint64_t w2_t = in[2];
	uint64_t w3_t = in[3];
	uint64_t w4_t = in[4];
	uint64_t w5_t = in[5];
	uint64_t w6_t = in[6];
	uint64_t w7_t = in[7];
	uint64_t w8_t = 0x8000000000000000;
	uint64_t w9_t = 0;
	uint64_t wa_t = 0;
	uint64_t wb_t = 0;
	uint64_t wc_t = 0;
	uint64_t wd_t = 0;
	uint64_t we_t = 0;
	uint64_t wf_t = (128 + 64) << 3;

	uint64_t a = _prestate[0];
	uint64_t b = _prestate[1];
	uint64_t c = _prestate[2];
	uint64_t d = _prestate[3];
	uint64_t e = _prestate[4];
	uint64_t f = _prestate[5];
	uint64_t g = _prestate[6];
	uint64_t h = _prestate[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] = _prestate[0] + a;
	digest[1] = _prestate[1] + b;
	digest[2] = _prestate[2] + c;
	digest[3] = _prestate[3] + d;
	digest[4] = _prestate[4] + e;
	digest[5] = _prestate[5] + f;
	digest[6] = _prestate[6] + g;
	digest[7] = _prestate[7] + h;

}

__device__ void _PBKDF2_HMAC_SHA512_core_test(uint64_t* _prestate_1, uint64_t* _prestate_2, uint64_t* digest, uint32_t* in, uint32_t* _temp) {
	uint64_t w0_t = (uint64_t)in[0] << 32 | in[1];
	uint64_t w1_t = (uint64_t)in[2] << 32 | in[3];
	uint64_t w2_t = (uint64_t)in[4] << 32 | in[5];
	uint64_t w3_t = (uint64_t)in[6] << 32 | in[7];
	uint64_t w4_t = (uint64_t)in[8] << 32 | in[9];
	uint64_t w5_t = (uint64_t)in[10] << 32 | in[11];
	uint64_t w6_t = (uint64_t)in[12] << 32 | in[13];
	uint64_t w7_t = (uint64_t)in[14] << 32 | in[15];

	uint64_t w8_t = 0x8000000000000000;
	uint64_t w9_t = 0;
	uint64_t wa_t = 0;
	uint64_t wb_t = 0;
	uint64_t wc_t = 0;
	uint64_t wd_t = 0;
	uint64_t we_t = 0;
	uint64_t wf_t = (128 + 64) << 3;

	uint64_t a = _prestate_1[0];
	uint64_t b = _prestate_1[1];
	uint64_t c = _prestate_1[2];
	uint64_t d = _prestate_1[3];
	uint64_t e = _prestate_1[4];
	uint64_t f = _prestate_1[5];
	uint64_t g = _prestate_1[6];
	uint64_t h = _prestate_1[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);

	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);

	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	w0_t = _prestate_1[0] + a;
	w1_t = _prestate_1[1] + b;
	w2_t = _prestate_1[2] + c;
	w3_t = _prestate_1[3] + d;
	w4_t = _prestate_1[4] + e;
	w5_t = _prestate_1[5] + f;
	w6_t = _prestate_1[6] + g;
	w7_t = _prestate_1[7] + h;
	w8_t = 0x8000000000000000;
	w9_t = 0;
	wa_t = 0;
	wb_t = 0;
	wc_t = 0;
	wd_t = 0;
	we_t = 0;
	wf_t = (128 + 64) << 3;

	a = _prestate_2[0];
	b = _prestate_2[1];
	c = _prestate_2[2];
	d = _prestate_2[3];
	e = _prestate_2[4];
	f = _prestate_2[5];
	g = _prestate_2[6];
	h = _prestate_2[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] = _prestate_2[0] + a;
	digest[1] = _prestate_2[1] + b;
	digest[2] = _prestate_2[2] + c;
	digest[3] = _prestate_2[3] + d;
	digest[4] = _prestate_2[4] + e;
	digest[5] = _prestate_2[5] + f;
	digest[6] = _prestate_2[6] + g;
	digest[7] = _prestate_2[7] + h;

	_temp[0] = _temp[0] ^ (digest[0] >> 32);
	_temp[1] = _temp[1] ^ (digest[0] & 0xffffffff);
	_temp[2] = _temp[2] ^ (digest[1] >> 32);
	_temp[3] = _temp[3] ^ (digest[1] & 0xffffffff);
	_temp[4] = _temp[4] ^ (digest[2] >> 32);
	_temp[5] = _temp[5] ^ (digest[2] & 0xffffffff);
	_temp[6] = _temp[6] ^ (digest[3] >> 32);
	_temp[7] = _temp[7] ^ (digest[3] & 0xffffffff);
	_temp[8] = _temp[8] ^ (digest[4] >> 32);
	_temp[9] = _temp[9] ^(digest[4] & 0xffffffff);
	_temp[10] = _temp[10] ^ (digest[5] >> 32);
	_temp[11] = _temp[11] ^ (digest[5] & 0xffffffff);
	_temp[12] = _temp[12] ^ (digest[6] >> 32);
	_temp[13] = _temp[13] ^ (digest[6] & 0xffffffff);
	_temp[14] = _temp[14] ^ (digest[7] >> 32);
	_temp[15] = _temp[15] ^ (digest[7] & 0xffffffff);

	in[0] = digest[0] >> 32;
	in[1] = digest[0] & 0xffffffff;
	in[2] = digest[1] >> 32;
	in[3] = digest[1] & 0xffffffff;
	in[4] = digest[2] >> 32;
	in[5] = digest[2] & 0xffffffff;
	in[6] = digest[3] >> 32;
	in[7] = digest[3] & 0xffffffff;
	in[8] = digest[4] >> 32;
	in[9] = digest[4] & 0xffffffff;
	in[10] = digest[5] >> 32;
	in[11] = digest[5] & 0xffffffff;
	in[12] = digest[6] >> 32;
	in[13] = digest[6] & 0xffffffff;
	in[14] = digest[7] >> 32;
	in[15] = digest[7] & 0xffffffff;
}

//__shared__ uint64_t temp_test[8 * 128 + 63];		//for BC
//__shared__ uint64_t temp_test[8 * 128];		//원본
//__shared__ uint64_t _temp[8 * 128];

__device__ void PBKDF2_HMAC_SHA512(uint8_t* pt, uint64_t ptLen, uint8_t* salt, uint64_t saLen, uint64_t* dk, uint64_t dkLen, uint32_t iter, uint32_t* temp_test, uint32_t* _temp) {
	//uint8_t buf[SHA512_BLOCK];
	uint64_t _first[8];
	uint64_t _second[8];
	//uint64_t temp_test[8];
	//uint64_t _temp[8];
	PBKDF2_HMAC_SHA512_INFO info;
	uint64_t _tkLen = dkLen / SHA512_DIGEST;
	int k = 0;
	int i = 0;
	uint64_t test_arr[16];
	_PBKDF2_HMAC_SHA512_precompute(pt, ptLen, &info);
	_PBKDF2_HMAC_SHA512_salt_compute(salt, saLen, i + 1, &info, _first);
	_PBKDF2_HMAC_SHA512_core(info.OPAD, _second, _first);

	temp_test[0 + threadIdx.x * 17] = _second[0] >> 32;
	temp_test[1 + threadIdx.x * 17] = _second[0] & 0xffffffff;
	temp_test[2 + threadIdx.x * 17] = _second[1] >> 32;
	temp_test[3 + threadIdx.x * 17] = _second[1] & 0xffffffff;
	temp_test[4 + threadIdx.x * 17] = _second[2] >> 32;
	temp_test[5 + threadIdx.x * 17] = _second[2] & 0xffffffff;
	temp_test[6 + threadIdx.x * 17] = _second[3] >> 32;
	temp_test[7 + threadIdx.x * 17] = _second[3] & 0xffffffff;
	temp_test[8 + threadIdx.x * 17] = _second[4] >> 32;
	temp_test[9 + threadIdx.x * 17] = _second[4] & 0xffffffff;
	temp_test[10 + threadIdx.x * 17] = _second[5] >> 32;
	temp_test[11 + threadIdx.x * 17] = _second[5] & 0xffffffff;
	temp_test[12 + threadIdx.x * 17] = _second[6] >> 32;
	temp_test[13 + threadIdx.x * 17] = _second[6] & 0xffffffff;
	temp_test[14 + threadIdx.x * 17] = _second[7] >> 32;
	temp_test[15 + threadIdx.x * 17] = _second[7] & 0xffffffff;
	temp_test[16 + threadIdx.x * 17] = 0xffffffff;

	_temp[0 + threadIdx.x * 17] = temp_test[0 + threadIdx.x * 17]; 
	_temp[1 + threadIdx.x * 17] = temp_test[1 + threadIdx.x * 17]; 
	_temp[2 + threadIdx.x * 17] = temp_test[2 + threadIdx.x * 17]; 
	_temp[3 + threadIdx.x * 17] = temp_test[3 + threadIdx.x * 17]; 
	_temp[4 + threadIdx.x * 17] = temp_test[4 + threadIdx.x * 17]; 
	_temp[5 + threadIdx.x * 17] = temp_test[5 + threadIdx.x * 17]; 
	_temp[6 + threadIdx.x * 17] = temp_test[6 + threadIdx.x * 17]; 
	_temp[7 + threadIdx.x * 17] = temp_test[7 + threadIdx.x * 17]; 
	_temp[8 + threadIdx.x * 17] = temp_test[8 + threadIdx.x * 17]; 
	_temp[9 + threadIdx.x * 17] = temp_test[9 + threadIdx.x * 17]; 
	_temp[10 + threadIdx.x * 17] = temp_test[10 + threadIdx.x * 17];
	_temp[11 + threadIdx.x * 17] =temp_test[11 + threadIdx.x * 17];
	_temp[12 + threadIdx.x * 17] = temp_test[12 + threadIdx.x * 17];
	_temp[13 + threadIdx.x * 17] =temp_test[13 + threadIdx.x * 17];
	_temp[14 + threadIdx.x * 17] = temp_test[14 + threadIdx.x * 17];
	_temp[15 + threadIdx.x * 17] =temp_test[15 + threadIdx.x * 17];
	_temp[16 + threadIdx.x * 17] = temp_test[16 + threadIdx.x * 17];

	for (k = 1; k < iter; k++) {
		_PBKDF2_HMAC_SHA512_core_test(info.IPAD, info.OPAD, _first, (temp_test + threadIdx.x * 17), (_temp + threadIdx.x * 17));
#ifdef Inner_print
		for (int i = 0; i < 16; i++) {
			printf("%02x", _temp[i]);
		}
		printf("\n");
#endif // inner_print

	}

	dk[0] = ((uint64_t)_temp[0 + threadIdx.x * 17] << 32) | (_temp[1 + threadIdx.x * 17]);
	dk[1] = ((uint64_t)_temp[2 + threadIdx.x * 17] << 32) | (_temp[3 + threadIdx.x * 17]);
	dk[2] = ((uint64_t)_temp[4 + threadIdx.x * 17] << 32) | (_temp[5 + threadIdx.x * 17]);
	dk[3] = ((uint64_t)_temp[6 + threadIdx.x * 17] << 32) | (_temp[7 + threadIdx.x * 17]);
	dk[4] = ((uint64_t)_temp[8 + threadIdx.x * 17] << 32) | (_temp[9 + threadIdx.x * 17]);
	dk[5] = ((uint64_t)_temp[10 + threadIdx.x * 17] << 32) | (_temp[11 + threadIdx.x * 17]);
	dk[6] = ((uint64_t)_temp[12 + threadIdx.x * 17] << 32) | (_temp[13 + threadIdx.x * 17]);
	dk[7] = ((uint64_t)_temp[14 + threadIdx.x * 17] << 32) | (_temp[15 + threadIdx.x * 17]);

	//dk[0] = 0x1111111111111111;
	//dk[1] = 0x2222222222222222;
	//dk[2] = 0x3333333333333333;
	//dk[3] = 0x4444444444444444;
	//dk[4] = 0x5555555555555555;
	//dk[5] = 0x6666666666666666;
	//dk[6] = 0x7777777777777777;
	//dk[7] = 0x8888888888888888;
}

__global__ void PBKDF2_HMAC_SHA512_fixed_Coalseced_memory(uint8_t* pt, uint64_t* dk, uint32_t iteration_count) {

	uint64_t iternal_tid = (blockDim.x * blockIdx.x) + threadIdx.x;
	uint64_t iternal_index = (blockDim.x * gridDim.x);
	uint64_t iternal_dk[FIX_DKOUT];

	__shared__ uint8_t shared_pt[THREAD_SIZE * FIX_PTLEN + US_PAD_PT_SIZE];

	//pt Copy
	shared_pt[0 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[0 * iternal_index + iternal_tid];
	shared_pt[1 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[1 * iternal_index + iternal_tid];
	shared_pt[2 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[2 * iternal_index + iternal_tid];
	shared_pt[3 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[3 * iternal_index + iternal_tid];
	shared_pt[4 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[4 * iternal_index + iternal_tid];
	shared_pt[5 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[5 * iternal_index + iternal_tid];
	shared_pt[6 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[6 * iternal_index + iternal_tid];
	shared_pt[7 + FIX_PTLEN * threadIdx.x + 4*(threadIdx.x / 16)] = pt[7 * iternal_index + iternal_tid];

	__shared__ uint32_t temp_test[2 * 8 * THREAD_SIZE + THREAD_SIZE];		//for BC
	__shared__ uint32_t _temp[2 * 8 * THREAD_SIZE + THREAD_SIZE];		//for BC

	PBKDF2_HMAC_SHA512(shared_pt + (8 * threadIdx.x) + 4*(threadIdx.x / 16), FIX_PTLEN, constant_salt, FIX_SALTLEN, iternal_dk, FIX_DKLEN, iteration_count, temp_test, _temp);

	//dk copy
	dk[0 * iternal_index + iternal_tid] = iternal_dk[0];
	dk[1 * iternal_index + iternal_tid] = iternal_dk[1];
	dk[2 * iternal_index + iternal_tid] = iternal_dk[2];
	dk[3 * iternal_index + iternal_tid] = iternal_dk[3];
	dk[4 * iternal_index + iternal_tid] = iternal_dk[4];
	dk[5 * iternal_index + iternal_tid] = iternal_dk[5];
	dk[6 * iternal_index + iternal_tid] = iternal_dk[6];
	dk[7 * iternal_index + iternal_tid] = iternal_dk[7];
}

void PBKDF2_HMAC_SHA512_coalesed_test(uint64_t blocksize, uint64_t threadsize) {

	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint8_t test_pt[8] = { 0x67, 0x6f, 0x6f, 0x64, 0x74, 0x65, 0x73, 0x74 };		//676f6f6474657374
	uint8_t test_sa[4] = { 0x67, 0x6f, 0x6f, 0x64 };	//676f6f64
	int iteration_count = 129977;

	uint8_t* temp = (uint8_t*)malloc(blocksize * threadsize * 8);
	uint64_t* dk_temp = (uint64_t*)malloc(blocksize * threadsize * 8 * sizeof(uint64_t));
	for (int i = 0; i < blocksize * threadsize; i++) {
		memcpy(temp + 8 * i, test_pt, 8);
	}

	state_transform(temp, blocksize, threadsize);

	uint8_t* gpu_pt = NULL;
	uint64_t* gpu_dk = NULL;

	cudaMalloc((void**)&gpu_pt, blocksize * threadsize * 8);
	cudaMalloc((void**)&gpu_dk, blocksize * threadsize * sizeof(uint64_t) * 8);

	cudaMemcpy(gpu_pt, temp, blocksize * threadsize * 8, cudaMemcpyHostToDevice);
	cudaMemcpyToSymbol(constant_salt, test_sa, 4 * sizeof(uint8_t));

	printf("[Time stamp]");
	time_t timer = time(NULL);
	struct tm* t = localtime(&timer);
	printf("\n%04d.%02d.%02d, %02d:%02d:%02d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

	//
	printf("\n[GPU Specification]");
	cudaDeviceProp  prop;
	int count;
	cudaGetDeviceCount(&count);

	for (int i = 0; i < count; i++) {
		cudaGetDeviceProperties(&prop, i);
		//printf("\n--- General Information for device %d ---\n", i);
		printf("\nName:  %s\n", prop.name);
		printf("Compute capability:  %d.%d\n", prop.major, prop.minor);
		printf("Clock rate:  %d\n", prop.clockRate);
		//printf("Device copy overlap:  ");
		//if (prop.deviceOverlap)
		//	printf("Enabled\n");
		//else
		//	printf("Disabled\n");
		//printf("Kernel execution timeout :  ");
		//if (prop.kernelExecTimeoutEnabled)
		//	printf("Enabled\n");
		//else
		//	printf("Disabled\n");
		//printf("\n");

		//printf("   --- Memory Information for device %d ---\n", i);
		//printf("Total global mem:  %ld\n", prop.totalGlobalMem);
		//printf("Total constant Mem:  %ld\n", prop.totalConstMem);
		//printf("Max mem pitch:  %ld\n", prop.memPitch);
		//printf("Texture Alignment:  %ld\n", prop.textureAlignment);
		//printf("\n");

		//printf("   --- MP Information for device %d ---\n", i);
		//printf("Multiprocessor count:  %d\n", prop.multiProcessorCount);
		//printf("Shared mem per mp:  %ld\n", prop.sharedMemPerBlock);
		//printf("Registers per mp:  %d\n", prop.regsPerBlock);
		//printf("Threads in warp:  %d\n", prop.warpSize);
		//printf("Max threads per block:  %d\n", prop.maxThreadsPerBlock);
		//printf("Max thread dimensions:  (%d, %d, %d)\n", prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2]);
		//printf("Max grid dimensions:  (%d, %d, %d)\n", prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);
	}
	stopLoadingAnimation();
	//

#if Overclock==1	//3090 overclock
	printf("\n[Overclock Specification]");
	printf("\nOverclock Enabled : On");
	printf("\nCore Clock(+MHz) : 160\n");
#elif Overclock==2	//4090 overclock
	printf("\n[Overclock Specification]");
	printf("\nOverclock Enabled : On");
	printf("\nCore Clock(+MHz) : 260\n");
#else // no voverclock
	printf("\n[Overclock Specification]");
	printf("\nOverclock Enabled : Off\n");
#endif

	printf("\n============\n");

	//
	printf("\n[PBKDF2-HMAC-SHA512 Input]");
	printf("\nPassword : ");
	for (int i = 0; i < 8; i++) {
		printf("0x%02X ", test_pt[i]);
	}
	printf("(The ASCII hexadecimal representation of \"goodtest\")");
	printf("\nSalt : ");
	for (int i = 0; i < 4; i++) {
		printf("0x%02X ", test_sa[i]);
	}
	printf("(The ASCII hexadecimal representation of \"good\")");
	printf("\nIteration Count : %d\n\n", iteration_count);

	startLoadingAnimation();

	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);

	for (int i = 0; i < 5; i++) {
		PBKDF2_HMAC_SHA512_fixed_Coalseced_memory << <blocksize, threadsize >> > (gpu_pt, gpu_dk, iteration_count);
	}

	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;

	stopLoadingAnimation();

	printf("\n\n[PBKDF2-HMAC-SHA512 Performance]\n");
	printf("\nBlock_size = %d, Thread_size = %d\n", blocksize, threadsize);
	//printf("Compiler PTX repeat 1times\n");
	//printf("My PTX(Pipeline) repeat 4times\n");
	printf("Performance : %4.2f PBKDF2-HMAC-SHA512 times per second \n", blocksize * threadsize / ((elapsed_time_ms / 1000 /5)));
	//printf("Performance : %4.2f PBKDF2 time per second \n", 2* blocksize * threadsize / ((elapsed_time_ms / 1000)));
	//cudaMemcpy(dk_temp, gpu_dk, 2 * blocksize * threadsize * sizeof(uint64_t) * 8, cudaMemcpyDeviceToHost);
	cudaMemcpy(dk_temp, gpu_dk, blocksize * threadsize * sizeof(uint64_t) * 8, cudaMemcpyDeviceToHost);
	dk_transform(dk_temp, blocksize, threadsize);

	printf("\n\n[PBKDF2-HMAC-SHA512 Output]\n");
	printf("(Currently, all threads are programmed to compute the same output.)\n\n");

	printf("Output : ");
	for (int i = 0; i < 8; i++) {
		printf("%016llx ", dk_temp[i]);
	}
	printf("\n\n");

	//getchar();
	//printf("\n");
	//for (int i = 0; i < blocksize * threadsize * 8; i++) {
	//	printf("%016llx ", dk_temp[i]);
	//	if ((i + 1) % 8 == 0)
	//		printf("\n");
	//}
}
