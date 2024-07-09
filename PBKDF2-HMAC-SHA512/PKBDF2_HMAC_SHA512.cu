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


__device__ void _PBKDF2_HMAC_SHA512_core_test7(uint64_t* _prestate_1, uint64_t* _prestate_2, uint64_t* digest, uint64_t* in, uint64_t* _temp) {
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

	uint64_t a = _prestate_1[0];
	uint64_t b = _prestate_1[1];
	uint64_t c = _prestate_1[2];
	uint64_t d = _prestate_1[3];
	uint64_t e = _prestate_1[4];
	uint64_t f = _prestate_1[5];
	uint64_t g = _prestate_1[6];
	uint64_t h = _prestate_1[7];


#if 1
	asm("{\n\t"
		".reg.u64			w0_t;			\n\t"
		".reg.u64			w1_t;			\n\t"
		".reg.u64			w2_t;			\n\t"
		".reg.u64			w3_t;			\n\t"
		".reg.u64			w4_t;			\n\t"
		".reg.u64			w5_t;			\n\t"
		".reg.u64			w6_t;			\n\t"
		".reg.u64			w7_t;			\n\t"
		".reg.u64			w8_t;			\n\t"
		".reg.u64			w9_t;			\n\t"
		".reg.u64			wa_t;			\n\t"
		".reg.u64			wb_t;			\n\t"
		".reg.u64			wc_t;			\n\t"
		".reg.u64			wd_t;			\n\t"
		".reg.u64			we_t;			\n\t"
		".reg.u64			wf_t;			\n\t"

		".reg.u64			a;			\n\t"
		".reg.u64			b;			\n\t"
		".reg.u64			c;			\n\t"
		".reg.u64			d;			\n\t"
		".reg.u64			e;			\n\t"
		".reg.u64			f;			\n\t"
		".reg.u64			g;			\n\t"
		".reg.u64			h;			\n\t"

		"mov.u64			w0_t,	%8;				\n\t"
		"mov.u64			w1_t,	%9;				\n\t"
		"mov.u64			w2_t,	%10;			\n\t"
		"mov.u64			w3_t,	%11;			\n\t"
		"mov.u64			w4_t,	%12;			\n\t"
		"mov.u64			w5_t,	%13;			\n\t"
		"mov.u64			w6_t,	%14;			\n\t"
		"mov.u64			w7_t,	%15;			\n\t"

		"mov.u64			w8_t,	0x8000000000000000;			\n\t"
		"mov.u64			w9_t,	0;			\n\t"
		"mov.u64			wa_t,	0;			\n\t"
		"mov.u64			wb_t,	0;			\n\t"
		"mov.u64			wc_t,	0;			\n\t"
		"mov.u64			wd_t,	0;			\n\t"
		"mov.u64			we_t,	0;			\n\t"
		"mov.u64			wf_t,	1536;			\n\t"

		"mov.u64			a,	%0;			\n\t"
		"mov.u64			b,	%1;			\n\t"
		"mov.u64			c,	%2;			\n\t"
		"mov.u64			d,	%3;			\n\t"
		"mov.u64			e,	%4;			\n\t"
		"mov.u64			f,	%5;			\n\t"
		"mov.u64			g,	%6;			\n\t"
		"mov.u64			h,	%7;			\n\t"

		//SHA512_STEP
		".reg.u32			r1;			\n\t"
		".reg.u32			r2;			\n\t"
		".reg.u32			r3;			\n\t"
		".reg.u32			r4;			\n\t"
		".reg.u32			r5;			\n\t"
		".reg.u32			r6;			\n\t"
		".reg.u32			r7;			\n\t"
		".reg.u32			r8;			\n\t"
		".reg.u32			r9;			\n\t"
		".reg.u32			r10;			\n\t"


		".reg.u64			rd1;			\n\t"
		".reg.u64			rd2;			\n\t"
		".reg.u64			rd3;			\n\t"
		".reg.u64			rd4;			\n\t"
		".reg.u64			rd5;			\n\t"
		".reg.u64			rd6;			\n\t"
		".reg.u64			rd7;			\n\t"
		".reg.u64			rd8;			\n\t"
		".reg.u64			rd9;			\n\t"
		".reg.u64			rd10;			\n\t"
		".reg.u64			rd11;			\n\t"
		".reg.u64			rd12;			\n\t"
		".reg.u64			rd13;			\n\t"
		".reg.u64			rd14;			\n\t"
		".reg.u64			rd15;			\n\t"

		".reg.u64			temp1;			\n\t"
		".reg.u64			temp2;			\n\t"
		".reg.u64			temp3;			\n\t"
		".reg.u64			temp4;			\n\t"
		".reg.u64			temp5;			\n\t"
		".reg.u64			temp6;			\n\t"
		".reg.u64			temp7;			\n\t"
		".reg.u64			temp8;			\n\t"
		".reg.u64			temp9;			\n\t"
		".reg.u64			temp10;			\n\t"
		".reg.u64			temp11;			\n\t"
		".reg.u64			temp12;			\n\t"
		".reg.u64			temp13;			\n\t"
		".reg.u64			temp14;			\n\t"
		".reg.u64			temp15;			\n\t"
		".reg.u64			temp16;			\n\t"

		"mov.b64			temp1, 0x428a2f98d728ae22;			\n\t"
		"mov.b64			temp2,0x7137449123ef65cd;			\n\t"
		"mov.b64			temp3,0xb5c0fbcfec4d3b2f;			\n\t"
		"mov.b64			temp4,0xe9b5dba58189dbbc;			\n\t"
		"mov.b64			temp5,0x3956c25bf348b538;			\n\t"
		"mov.b64			temp6,0x59f111f1b605d019;			\n\t"
		"mov.b64			temp7,0x923f82a4af194f9b;			\n\t"
		"mov.b64			temp8,0xab1c5ed5da6d8118;			\n\t"
		"mov.b64			temp9,0xd807aa98a3030242;			\n\t"
		"mov.b64			temp10,0x12835b0145706fbe;			\n\t"
		"mov.b64			temp11,0x243185be4ee4b28c;			\n\t"
		"mov.b64			temp12,0x550c7dc3d5ffb4e2;			\n\t"
		"mov.b64			temp13,0x72be5d74f27b896f;			\n\t"
		"mov.b64			temp14,0x80deb1fe3b1696b1;			\n\t"
		"mov.b64			temp15,0x9bdc06a725c71235;			\n\t"
		"mov.b64			temp16,0xc19bf174cf692694;			\n\t"


		//! 1. SHA512_STEP(a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
		//d += h + 0x428a2f98d728ae22 + w0_t + (ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41)) + (g ^ (e & (f ^ g)));	
		".reg.b32	dummy;\n\t"
		"mov.b64		{ r1, dummy }, e; \n\t"
		"mov.b64		{ dummy, r2 }, e; \n\t"

		//변경 : 연산 후 메모리 접근
		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, f, g;\n\t"
		"and .b64			rd7, e, rd6;\n\t"
		"xor .b64			rd8, g, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, h, temp1;\n\t"
		"add.u64			rd11, rd10, w0_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			d, rd12, d;\n\t"

		".reg.u64			temp_d;\n\t"
		"mov.u64			temp_d, rd12;\n\t"


		//h = h + 0x428a2f98d728ae22 + w0_t + (ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41)) + (g ^ (e & (f ^ g))) + ((ROTR64(a, 28)) ^ ROTR64(a, 34) ^ ROTR64(a, 39)) + ((a & b) | (c & (a ^ b)));
		"mov.b64		{ r1, dummy }, a;\n\t"
		"mov.b64		{ dummy, r2 }, a;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, a, b;			\n\t"
		"and.b64			rd7, c, rd6;			\n\t"
		"and.b64			rd8, a, b;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			h, temp_d, rd10;\n\t"

		".reg.u64			temp_h;\n\t"
		//"mov.u64			temp_h, rd10;\n\t"

		//! 2. SHA512_STEP(h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
		//c += g + 0x7137449123ef65cd + w1_t + (((d >> 14) | (d << 50)) ^ ((d >> 18) | (d << 46)) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f)));
		"mov.b64		{ r1, dummy }, d; \n\t"
		"mov.b64		{ dummy, r2 }, d; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, e, f;\n\t"
		"and .b64			rd7, d, rd6;\n\t"
		"xor .b64			rd8, f, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, g, temp2;\n\t"
		"add.u64			rd11, rd10, w1_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			c, rd12, c;\n\t"

		".reg.u64			temp_c;\n\t"
		"mov.u64			temp_c, rd12;\n\t"


		//g = g + 0x7137449123ef65cd + w1_t + (((d >> 14) | (d << (50))) ^ ((d >> 18) | (d << (46))) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f))) + (((h >> 28) | (h << 36)) ^ ((h >> 34) | (h << 30)) ^ ((h >> 39) | (h << 25))) + ((h & a) | (b & (h ^ a)));
		"mov.b64		{ r1, dummy }, h;\n\t"
		"mov.b64		{ dummy, r2 }, h;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, h, a;			\n\t"
		"and.b64			rd7, b, rd6;			\n\t"
		"and.b64			rd8, h, a;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			g, temp_c, rd10;\n\t"

		".reg.u64			temp_g;\n\t"
		//"mov.u64			temp_g, rd10;\n\t"

		//! 3. SHA512_STEP(g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
		//b += f + 0xb5c0fbcfec4d3b2f + w2_t + (((c >> 14) | (c << 50)) ^ ((c >> 18) | (c << 46)) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e)));
		"mov.b64		{ r1, dummy }, c; \n\t"
		"mov.b64		{ dummy, r2 }, c; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, d, e;\n\t"
		"and .b64			rd7, c, rd6;\n\t"
		"xor .b64			rd8, e, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, f, temp3;\n\t"
		"add.u64			rd11, rd10, w2_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			b, rd12, b;\n\t"

		".reg.u64			temp_b;\n\t"
		"mov.u64			temp_b, rd12;\n\t"


		//f = f + 0xb5c0fbcfec4d3b2f + w2_t + (((c >> 14) | (c << (50))) ^ ((c >> 18) | (c << (46))) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e))) + (((g >> 28) | (g << 36)) ^ ((g >> 34) | (g << 30)) ^ ((g >> 39) | (g << 25))) + ((g & h) | (a & (g ^ h)));
		"mov.b64		{ r1, dummy }, g;\n\t"
		"mov.b64		{ dummy, r2 }, g;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, g, h;			\n\t"
		"and.b64			rd7, a, rd6;			\n\t"
		"and.b64			rd8, g, h;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			f, temp_b, rd10;\n\t"

		".reg.u64			temp_f;\n\t"
		//"mov.u64			temp_f, rd10;\n\t"


		//! 4. SHA512_STEP(f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
		//a += e + 0xe9b5dba58189dbbc + w3_t + (((b >> 14) | (b << 50)) ^ ((b >> 18) | (b << 46)) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d)));
		"mov.b64		{ r1, dummy }, b; \n\t"
		"mov.b64		{ dummy, r2 }, b; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, c, d;\n\t"
		"and .b64			rd7, b, rd6;\n\t"
		"xor .b64			rd8, d, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, e, temp4;\n\t"
		"add.u64			rd11, rd10, w3_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			a, rd12, a;\n\t"

		".reg.u64			temp_a;\n\t"
		"mov.u64			temp_a, rd12;\n\t"


		//e = e + 0xe9b5dba58189dbbc + w3_t + (((b >> 14) | (b << (50))) ^ ((b >> 18) | (b << (46))) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d))) + (((f >> 28) | (f << 36)) ^ ((f >> 34) | (f << 30)) ^ ((f >> 39) | (f << 25))) + ((f & g) | (h & (f ^ g)));
		"mov.b64		{ r1, dummy }, f;\n\t"
		"mov.b64		{ dummy, r2 }, f;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, f, g;			\n\t"
		"and.b64			rd7, h, rd6;			\n\t"
		"and.b64			rd8, f, g;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			e, temp_a, rd10;\n\t"

		".reg.u64			temp_e;\n\t"
		//"mov.u64			temp_e, rd10;\n\t"

		//! 5. SHA512_STEP(e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
		//h += d + 0x3956c25bf348b538 + w4_t + (((a >> 14) | (a << 50)) ^ ((a >> 18) | (a << 46)) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c)));
		"mov.b64		{ r1, dummy }, a; \n\t"
		"mov.b64		{ dummy, r2 }, a; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, b, c;\n\t"
		"and .b64			rd7, a, rd6;\n\t"
		"xor .b64			rd8, c, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, d, temp5;\n\t"
		"add.u64			rd11, rd10, w4_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			h, rd12, h;\n\t"

		"mov.u64			temp_h, rd12;\n\t"


		//d = d + 0x3956c25bf348b538 + w4_t + (((a >> 14) | (a << (50))) ^ ((a >> 18) | (a << (46))) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c))) + (((e >> 28) | (e << 36)) ^ ((e >> 34) | (e << 30)) ^ ((e >> 39) | (e << 25))) + ((e & f) | (g & (e ^ f)));
		"mov.b64		{ r1, dummy }, e;\n\t"
		"mov.b64		{ dummy, r2 }, e;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, e, f;			\n\t"
		"and.b64			rd7, g, rd6;			\n\t"
		"and.b64			rd8, e, f;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			d, temp_h, rd10;\n\t"

		//"mov.u64			temp_d, rd10;\n\t"

		//! 6. SHA512_STEP(d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
		//g += c + 0x59f111f1b605d019 + w5_t + (((h >> 14) | (h << 50)) ^ ((h >> 18) | (h << 46)) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b)));
		"mov.b64		{ r1, dummy }, h; \n\t"
		"mov.b64		{ dummy, r2 }, h; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, a, b;\n\t"
		"and .b64			rd7, h, rd6;\n\t"
		"xor .b64			rd8, b, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, c, temp6;\n\t"
		"add.u64			rd11, rd10, w5_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			g, rd12, g;\n\t"

		"mov.u64			temp_g, rd12;\n\t"


		//c = c + 0x59f111f1b605d019 + w5_t + (((h >> 14) | (h << (50))) ^ ((h >> 18) | (h << (46))) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b))) + (((d >> 28) | (d << 36)) ^ ((d >> 34) | (d << 30)) ^ ((d >> 39) | (d << 25))) + ((d & e) | (f & (d ^ e)));
		"mov.b64		{ r1, dummy }, d;\n\t"
		"mov.b64		{ dummy, r2 }, d;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, d, e;			\n\t"
		"and.b64			rd7, f, rd6;			\n\t"
		"and.b64			rd8, d, e;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			c, temp_g, rd10;\n\t"

		//"mov.u64			temp_c, rd10;\n\t"

		//! 7. SHA512_STEP(c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
		//f += b + 0x923f82a4af194f9b + w6_t + (((g >> 14) | (g << 50)) ^ ((g >> 18) | (g << 46)) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a)));
		"mov.b64		{ r1, dummy }, g; \n\t"
		"mov.b64		{ dummy, r2 }, g; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, h, a;\n\t"
		"and .b64			rd7, g, rd6;\n\t"
		"xor .b64			rd8, a, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, b, temp7;\n\t"
		"add.u64			rd11, rd10, w6_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			f, rd12, f;\n\t"

		"mov.u64			temp_f, rd12;\n\t"

		//b = b + 0x923f82a4af194f9b + w6_t + (((g >> 14) | (g << (50))) ^ ((g >> 18) | (g << (46))) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a))) + (((c >> 28) | (c << 36)) ^ ((c >> 34) | (c << 30)) ^ ((c >> 39) | (c << 25))) + ((c & d) | (e & (c ^ d)));
		"mov.b64		{ r1, dummy }, c;\n\t"
		"mov.b64		{ dummy, r2 }, c;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, c, d;			\n\t"
		"and.b64			rd7, e, rd6;			\n\t"
		"and.b64			rd8, c, d;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			b, temp_f, rd10;\n\t"

		//"mov.u64			temp_b, rd10;\n\t"

		//! 8. SHA512_STEP(b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
		//e += a + 0xab1c5ed5da6d8118 + w7_t + (((f >> 14) | (f << 50)) ^ ((f >> 18) | (f << 46)) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h)));
		"mov.b64		{ r1, dummy }, f; \n\t"
		"mov.b64		{ dummy, r2 }, f; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, g, h;\n\t"
		"and .b64			rd7, f, rd6;\n\t"
		"xor .b64			rd8, h, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, a, temp8;\n\t"
		"add.u64			rd11, rd10, w7_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			e, rd12, e;\n\t"

		"mov.u64			temp_e, rd12;\n\t"

		//a = a + 0xab1c5ed5da6d8118 + w7_t + (((f >> 14) | (f << (50))) ^ ((f >> 18) | (f << (46))) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h))) + (((b >> 28) | (b << 36)) ^ ((b >> 34) | (b << 30)) ^ ((b >> 39) | (b << 25))) + ((b & c) | (d & (b ^ c)));
		"mov.b64		{ r1, dummy }, b;\n\t"
		"mov.b64		{ dummy, r2 }, b;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, b, c;			\n\t"
		"and.b64			rd7, d, rd6;			\n\t"
		"and.b64			rd8, b, c;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			a, temp_e, rd10;\n\t"

		//"mov.u64			temp_a, rd10;\n\t"



		//SHA512_STEP(a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
		//SHA512_STEP(h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
		//SHA512_STEP(g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
		//SHA512_STEP(f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
		//SHA512_STEP(e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
		//SHA512_STEP(d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
		//SHA512_STEP(c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
		//SHA512_STEP(b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

		//SHA512_STEP(a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
		//d += h + 0xd807aa98a3030242 + w8_t + (((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23))) + (g ^ (e & (f ^ g)));
		//h = h + 0xd807aa98a3030242 + w8_t + (((e >> 14) | (e << (50))) ^ ((e >> 18) | (e << (46))) ^ ((e >> 41) | (e << 23))) + (g ^ (e & (f ^ g))) + (((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25))) + ((a & b) | (c & (a ^ b)));
		"mov.b64		{ r1, dummy }, e; \n\t"
		"mov.b64		{ dummy, r2 }, e; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, f, g;\n\t"
		"and .b64			rd7, e, rd6;\n\t"
		"xor .b64			rd8, g, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, h, temp9;\n\t"
		"add.u64			rd11, rd10, w8_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			d, rd12, d;\n\t"

		"mov.u64			temp_d, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, a;\n\t"
		"mov.b64		{ dummy, r2 }, a;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, a, b;			\n\t"
		"and.b64			rd7, c, rd6;			\n\t"
		"and.b64			rd8, a, b;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			h, temp_d, rd10;\n\t"

		//"mov.u64			temp_h, rd10;\n\t"

		//SHA512_STEP(h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
		//c += g + 0x12835b0145706fbe + w9_t + (((d >> 14) | (d << 50)) ^ ((d >> 18) | (d << 46)) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f)));
		//g = g + 0x12835b0145706fbe + w9_t + (((d >> 14) | (d << (50))) ^ ((d >> 18) | (d << (46))) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f))) + (((h >> 28) | (h << 36)) ^ ((h >> 34) | (h << 30)) ^ ((h >> 39) | (h << 25))) + ((h & a) | (b & (h ^ a)));
		"mov.b64		{ r1, dummy }, d; \n\t"
		"mov.b64		{ dummy, r2 }, d; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"


		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, e, f;\n\t"
		"and .b64			rd7, d, rd6;\n\t"
		"xor .b64			rd8, f, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, g, temp10;\n\t"
		"add.u64			rd11, rd10, w9_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			c, rd12, c;\n\t"

		"mov.u64			temp_c, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, h;\n\t"
		"mov.b64		{ dummy, r2 }, h;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, h, a;			\n\t"
		"and.b64			rd7, b, rd6;			\n\t"
		"and.b64			rd8, h, a;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			g, temp_c, rd10;\n\t"

		//"mov.u64			temp_g, rd10;\n\t"

		//SHA512_STEP(g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
		//b += f + 0x243185be4ee4b28c + wa_t + (((c >> 14) | (c << 50)) ^ ((c >> 18) | (c << 46)) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e)));
		//f = f + 0x243185be4ee4b28c + wa_t + (((c >> 14) | (c << (50))) ^ ((c >> 18) | (c << (46))) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e))) + (((g >> 28) | (g << 36)) ^ ((g >> 34) | (g << 30)) ^ ((g >> 39) | (g << 25))) + ((g & h) | (a & (g ^ h)));
		"mov.b64		{ r1, dummy }, c; \n\t"
		"mov.b64		{ dummy, r2 }, c; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, d, e;\n\t"
		"and .b64			rd7, c, rd6;\n\t"
		"xor .b64			rd8, e, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, f, temp11;\n\t"
		"add.u64			rd11, rd10, wa_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			b, rd12, b;\n\t"

		"mov.u64			temp_b, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, g;\n\t"
		"mov.b64		{ dummy, r2 }, g;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, g, h;			\n\t"
		"and.b64			rd7, a, rd6;			\n\t"
		"and.b64			rd8, g, h;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			f, temp_b, rd10;\n\t"

		//	"mov.u64			temp_f, rd10;\n\t"


			//SHA512_STEP(f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
			//a += e + 0x550c7dc3d5ffb4e2 + wb_t + (((b >> 14) | (b << 50)) ^ ((b >> 18) | (b << 46)) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d)));
			//e = e + 0x550c7dc3d5ffb4e2 + wb_t + (((b >> 14) | (b << (50))) ^ ((b >> 18) | (b << (46))) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d))) + (((f >> 28) | (f << 36)) ^ ((f >> 34) | (f << 30)) ^ ((f >> 39) | (f << 25))) + ((f & g) | (h & (f ^ g)));
		"mov.b64		{ r1, dummy }, b; \n\t"
		"mov.b64		{ dummy, r2 }, b; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, c, d;\n\t"
		"and .b64			rd7, b, rd6;\n\t"
		"xor .b64			rd8, d, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, e, temp12;\n\t"
		"add.u64			rd11, rd10, wb_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			a, rd12, a;\n\t"

		"mov.u64			temp_a, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, f;\n\t"
		"mov.b64		{ dummy, r2 }, f;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, f, g;			\n\t"
		"and.b64			rd7, h, rd6;			\n\t"
		"and.b64			rd8, f, g;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			e, temp_a, rd10;\n\t"

		//"mov.u64			temp_e, rd10;\n\t"

		//SHA512_STEP(e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
		//h += d + 0x72be5d74f27b896f + wc_t + (((a >> 14) | (a << 50)) ^ ((a >> 18) | (a << 46)) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c)));
		//d = d + 0x72be5d74f27b896f + wc_t + (((a >> 14) | (a << (50))) ^ ((a >> 18) | (a << (46))) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c))) + (((e >> 28) | (e << 36)) ^ ((e >> 34) | (e << 30)) ^ ((e >> 39) | (e << 25))) + ((e & f) | (g & (e ^ f)));
		"mov.b64		{ r1, dummy }, a; \n\t"
		"mov.b64		{ dummy, r2 }, a; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, b, c;\n\t"
		"and .b64			rd7, a, rd6;\n\t"
		"xor .b64			rd8, c, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, d, temp13;\n\t"
		"add.u64			rd11, rd10, wc_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			h, rd12, h;\n\t"

		"mov.u64			temp_h, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, e;\n\t"
		"mov.b64		{ dummy, r2 }, e;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, e, f;			\n\t"
		"and.b64			rd7, g, rd6;			\n\t"
		"and.b64			rd8, e, f;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			d, temp_h, rd10;\n\t"

		//"mov.u64			temp_d, rd10;\n\t"

		//SHA512_STEP(d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
		//g += c + 0x80deb1fe3b1696b1 + wd_t + (((h >> 14) | (h << 50)) ^ ((h >> 18) | (h << 46)) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b)));
		//c = c + 0x80deb1fe3b1696b1 + wd_t + (((h >> 14) | (h << (50))) ^ ((h >> 18) | (h << (46))) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b))) + (((d >> 28) | (d << 36)) ^ ((d >> 34) | (d << 30)) ^ ((d >> 39) | (d << 25))) + ((d & e) | (f & (d ^ e)));
		"mov.b64		{ r1, dummy }, h; \n\t"
		"mov.b64		{ dummy, r2 }, h; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, a, b;\n\t"
		"and .b64			rd7, h, rd6;\n\t"
		"xor .b64			rd8, b, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, c, temp14;\n\t"
		"add.u64			rd11, rd10, wd_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			g, rd12, g;\n\t"

		"mov.u64			temp_g, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, d;\n\t"
		"mov.b64		{ dummy, r2 }, d;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, d, e;			\n\t"
		"and.b64			rd7, f, rd6;			\n\t"
		"and.b64			rd8, d, e;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			c, temp_g, rd10;\n\t"

		//"mov.u64			temp_c, rd10;\n\t"

		//SHA512_STEP(c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
		//f += b + 0x9bdc06a725c71235 + we_t + (((g >> 14) | (g << 50)) ^ ((g >> 18) | (g << 46)) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a)));
		//b = b + 0x9bdc06a725c71235 + we_t + (((g >> 14) | (g << (50))) ^ ((g >> 18) | (g << (46))) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a))) + (((c >> 28) | (c << 36)) ^ ((c >> 34) | (c << 30)) ^ ((c >> 39) | (c << 25))) + ((c & d) | (e & (c ^ d)));
		"mov.b64		{ r1, dummy }, g; \n\t"
		"mov.b64		{ dummy, r2 }, g; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, h, a;\n\t"
		"and .b64			rd7, g, rd6;\n\t"
		"xor .b64			rd8, a, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, b, temp15;\n\t"
		"add.u64			rd11, rd10, we_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			f, rd12, f;\n\t"

		"mov.u64			temp_f, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, c;\n\t"
		"mov.b64		{ dummy, r2 }, c;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, c, d;			\n\t"
		"and.b64			rd7, e, rd6;			\n\t"
		"and.b64			rd8, c, d;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			b, temp_f, rd10;\n\t"

		//"mov.u64			temp_b, rd10;\n\t"

		//SHA512_STEP(b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);
		//e += a + 0xc19bf174cf692694 + wf_t + (((f >> 14) | (f << 50)) ^ ((f >> 18) | (f << 46)) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h)));
		//a = a + 0xc19bf174cf692694 + wf_t + (((f >> 14) | (f << (50))) ^ ((f >> 18) | (f << (46))) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h))) + (((b >> 28) | (b << 36)) ^ ((b >> 34) | (b << 30)) ^ ((b >> 39) | (b << 25))) + ((b & c) | (d & (b ^ c)));
		"mov.b64		{ r1, dummy }, f; \n\t"
		"mov.b64		{ dummy, r2 }, f; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"


		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"


		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, g, h;\n\t"
		"and .b64			rd7, f, rd6;\n\t"
		"xor .b64			rd8, h, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, a, temp16;\n\t"
		"add.u64			rd11, rd10, wf_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			e, rd12, e;\n\t"

		"mov.u64			temp_e, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, b;\n\t"
		"mov.b64		{ dummy, r2 }, b;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, b, c;			\n\t"
		"and.b64			rd7, d, rd6;			\n\t"
		"and.b64			rd8, b, c;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			a, temp_e, rd10;\n\t"

		//출력
		"mov.u64			%0, a;			\n\t"
		"mov.u64			%1, b;			\n\t"
		"mov.u64			%2, c;			\n\t"
		"mov.u64			%3, d;			\n\t"
		"mov.u64			%4, e;			\n\t"
		"mov.u64			%5, f;			\n\t"
		"mov.u64			%6, g;			\n\t"
		"mov.u64			%7, h;			\n\t"

		"mov.u64			%8, w0_t;			\n\t"
		"mov.u64			%9, w1_t;			\n\t"
		"mov.u64			%10, w2_t;			\n\t"
		"mov.u64			%11, w3_t;			\n\t"
		"mov.u64			%12, w4_t;			\n\t"
		"mov.u64			%13, w5_t;			\n\t"
		"mov.u64			%14, w6_t;			\n\t"
		"mov.u64			%15, w7_t;			\n\t"


		"}"
		//:"+l"(_prestate_1[0]), "+l"(_prestate_1[1]), "+l"(_prestate_1[2]), "+l"(_prestate_1[3]), "+l"(_prestate_1[4]), "+l"(_prestate_1[5]), "+l"(_prestate_1[6]), "+l"(_prestate_1[7]), "+l"(in[0]), "+l"(in[1]), "+l"(in[2]), "+l"(in[3]), "+l"(in[4]), "+l"(in[5]), "+l"(in[6]), "+l"(in[7])

		: "+l"(a), "+l"(b), "+l"(c), "+l"(d), "+l"(e), "+l"(f), "+l"(g), "+l"(h), "+l"(w0_t), "+l"(w1_t), "+l"(w2_t), "+l"(w3_t), "+l"(w4_t), "+l"(w5_t), "+l"(w6_t), "+l"(w7_t)
	);
#endif

#if 0
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
#endif

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	//성능 저하 발생 - temp 고정 값 사용 시 성능 저하 발견(해결)
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	//성능 저하 발생 - 
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

#if 1
	asm("{\n\t"
		".reg.u64			w0_t;			\n\t"
		".reg.u64			w1_t;			\n\t"
		".reg.u64			w2_t;			\n\t"
		".reg.u64			w3_t;			\n\t"
		".reg.u64			w4_t;			\n\t"
		".reg.u64			w5_t;			\n\t"
		".reg.u64			w6_t;			\n\t"
		".reg.u64			w7_t;			\n\t"
		".reg.u64			w8_t;			\n\t"
		".reg.u64			w9_t;			\n\t"
		".reg.u64			wa_t;			\n\t"
		".reg.u64			wb_t;			\n\t"
		".reg.u64			wc_t;			\n\t"
		".reg.u64			wd_t;			\n\t"
		".reg.u64			we_t;			\n\t"
		".reg.u64			wf_t;			\n\t"

		".reg.u64			a;			\n\t"
		".reg.u64			b;			\n\t"
		".reg.u64			c;			\n\t"
		".reg.u64			d;			\n\t"
		".reg.u64			e;			\n\t"
		".reg.u64			f;			\n\t"
		".reg.u64			g;			\n\t"
		".reg.u64			h;			\n\t"

		"mov.u64			w0_t,	%8;				\n\t"
		"mov.u64			w1_t,	%9;				\n\t"
		"mov.u64			w2_t,	%10;			\n\t"
		"mov.u64			w3_t,	%11;			\n\t"
		"mov.u64			w4_t,	%12;			\n\t"
		"mov.u64			w5_t,	%13;			\n\t"
		"mov.u64			w6_t,	%14;			\n\t"
		"mov.u64			w7_t,	%15;			\n\t"

		"mov.u64			w8_t,	0x8000000000000000;			\n\t"
		"mov.u64			w9_t,	0;			\n\t"
		"mov.u64			wa_t,	0;			\n\t"
		"mov.u64			wb_t,	0;			\n\t"
		"mov.u64			wc_t,	0;			\n\t"
		"mov.u64			wd_t,	0;			\n\t"
		"mov.u64			we_t,	0;			\n\t"
		"mov.u64			wf_t,	1536;			\n\t"

		"mov.u64			a,	%0;			\n\t"
		"mov.u64			b,	%1;			\n\t"
		"mov.u64			c,	%2;			\n\t"
		"mov.u64			d,	%3;			\n\t"
		"mov.u64			e,	%4;			\n\t"
		"mov.u64			f,	%5;			\n\t"
		"mov.u64			g,	%6;			\n\t"
		"mov.u64			h,	%7;			\n\t"

		//SHA512_STEP
		".reg.u32			r1;			\n\t"
		".reg.u32			r2;			\n\t"
		".reg.u32			r3;			\n\t"
		".reg.u32			r4;			\n\t"
		".reg.u32			r5;			\n\t"
		".reg.u32			r6;			\n\t"
		".reg.u32			r7;			\n\t"
		".reg.u32			r8;			\n\t"
		".reg.u32			r9;			\n\t"
		".reg.u32			r10;			\n\t"


		".reg.u64			rd1;			\n\t"
		".reg.u64			rd2;			\n\t"
		".reg.u64			rd3;			\n\t"
		".reg.u64			rd4;			\n\t"
		".reg.u64			rd5;			\n\t"
		".reg.u64			rd6;			\n\t"
		".reg.u64			rd7;			\n\t"
		".reg.u64			rd8;			\n\t"
		".reg.u64			rd9;			\n\t"
		".reg.u64			rd10;			\n\t"
		".reg.u64			rd11;			\n\t"
		".reg.u64			rd12;			\n\t"
		".reg.u64			rd13;			\n\t"
		".reg.u64			rd14;			\n\t"
		".reg.u64			rd15;			\n\t"

		".reg.u64			temp1;			\n\t"
		".reg.u64			temp2;			\n\t"
		".reg.u64			temp3;			\n\t"
		".reg.u64			temp4;			\n\t"
		".reg.u64			temp5;			\n\t"
		".reg.u64			temp6;			\n\t"
		".reg.u64			temp7;			\n\t"
		".reg.u64			temp8;			\n\t"
		".reg.u64			temp9;			\n\t"
		".reg.u64			temp10;			\n\t"
		".reg.u64			temp11;			\n\t"
		".reg.u64			temp12;			\n\t"
		".reg.u64			temp13;			\n\t"
		".reg.u64			temp14;			\n\t"
		".reg.u64			temp15;			\n\t"
		".reg.u64			temp16;			\n\t"

		"mov.b64			temp1, 0x428a2f98d728ae22;			\n\t"
		"mov.b64			temp2,0x7137449123ef65cd;			\n\t"
		"mov.b64			temp3,0xb5c0fbcfec4d3b2f;			\n\t"
		"mov.b64			temp4,0xe9b5dba58189dbbc;			\n\t"
		"mov.b64			temp5,0x3956c25bf348b538;			\n\t"
		"mov.b64			temp6,0x59f111f1b605d019;			\n\t"
		"mov.b64			temp7,0x923f82a4af194f9b;			\n\t"
		"mov.b64			temp8,0xab1c5ed5da6d8118;			\n\t"
		"mov.b64			temp9,0xd807aa98a3030242;			\n\t"
		"mov.b64			temp10,0x12835b0145706fbe;			\n\t"
		"mov.b64			temp11,0x243185be4ee4b28c;			\n\t"
		"mov.b64			temp12,0x550c7dc3d5ffb4e2;			\n\t"
		"mov.b64			temp13,0x72be5d74f27b896f;			\n\t"
		"mov.b64			temp14,0x80deb1fe3b1696b1;			\n\t"
		"mov.b64			temp15,0x9bdc06a725c71235;			\n\t"
		"mov.b64			temp16,0xc19bf174cf692694;			\n\t"


		//! 1. SHA512_STEP(a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
		//d += h + 0x428a2f98d728ae22 + w0_t + (ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41)) + (g ^ (e & (f ^ g)));	
		".reg.b32	dummy;\n\t"
		"mov.b64		{ r1, dummy }, e; \n\t"
		"mov.b64		{ dummy, r2 }, e; \n\t"

		//변경 : 연산 후 메모리 접근
		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, f, g;\n\t"
		"and .b64			rd7, e, rd6;\n\t"
		"xor .b64			rd8, g, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, h, temp1;\n\t"
		"add.u64			rd11, rd10, w0_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			d, rd12, d;\n\t"

		".reg.u64			temp_d;\n\t"
		"mov.u64			temp_d, rd12;\n\t"


		//h = h + 0x428a2f98d728ae22 + w0_t + (ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41)) + (g ^ (e & (f ^ g))) + ((ROTR64(a, 28)) ^ ROTR64(a, 34) ^ ROTR64(a, 39)) + ((a & b) | (c & (a ^ b)));
		"mov.b64		{ r1, dummy }, a;\n\t"
		"mov.b64		{ dummy, r2 }, a;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, a, b;			\n\t"
		"and.b64			rd7, c, rd6;			\n\t"
		"and.b64			rd8, a, b;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			h, temp_d, rd10;\n\t"

		".reg.u64			temp_h;\n\t"
		//"mov.u64			temp_h, rd10;\n\t"

		//! 2. SHA512_STEP(h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
		//c += g + 0x7137449123ef65cd + w1_t + (((d >> 14) | (d << 50)) ^ ((d >> 18) | (d << 46)) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f)));
		"mov.b64		{ r1, dummy }, d; \n\t"
		"mov.b64		{ dummy, r2 }, d; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, e, f;\n\t"
		"and .b64			rd7, d, rd6;\n\t"
		"xor .b64			rd8, f, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, g, temp2;\n\t"
		"add.u64			rd11, rd10, w1_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			c, rd12, c;\n\t"

		".reg.u64			temp_c;\n\t"
		"mov.u64			temp_c, rd12;\n\t"


		//g = g + 0x7137449123ef65cd + w1_t + (((d >> 14) | (d << (50))) ^ ((d >> 18) | (d << (46))) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f))) + (((h >> 28) | (h << 36)) ^ ((h >> 34) | (h << 30)) ^ ((h >> 39) | (h << 25))) + ((h & a) | (b & (h ^ a)));
		"mov.b64		{ r1, dummy }, h;\n\t"
		"mov.b64		{ dummy, r2 }, h;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, h, a;			\n\t"
		"and.b64			rd7, b, rd6;			\n\t"
		"and.b64			rd8, h, a;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			g, temp_c, rd10;\n\t"

		".reg.u64			temp_g;\n\t"
		//"mov.u64			temp_g, rd10;\n\t"

		//! 3. SHA512_STEP(g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
		//b += f + 0xb5c0fbcfec4d3b2f + w2_t + (((c >> 14) | (c << 50)) ^ ((c >> 18) | (c << 46)) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e)));
		"mov.b64		{ r1, dummy }, c; \n\t"
		"mov.b64		{ dummy, r2 }, c; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, d, e;\n\t"
		"and .b64			rd7, c, rd6;\n\t"
		"xor .b64			rd8, e, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, f, temp3;\n\t"
		"add.u64			rd11, rd10, w2_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			b, rd12, b;\n\t"

		".reg.u64			temp_b;\n\t"
		"mov.u64			temp_b, rd12;\n\t"


		//f = f + 0xb5c0fbcfec4d3b2f + w2_t + (((c >> 14) | (c << (50))) ^ ((c >> 18) | (c << (46))) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e))) + (((g >> 28) | (g << 36)) ^ ((g >> 34) | (g << 30)) ^ ((g >> 39) | (g << 25))) + ((g & h) | (a & (g ^ h)));
		"mov.b64		{ r1, dummy }, g;\n\t"
		"mov.b64		{ dummy, r2 }, g;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, g, h;			\n\t"
		"and.b64			rd7, a, rd6;			\n\t"
		"and.b64			rd8, g, h;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			f, temp_b, rd10;\n\t"

		".reg.u64			temp_f;\n\t"
		//"mov.u64			temp_f, rd10;\n\t"


		//! 4. SHA512_STEP(f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
		//a += e + 0xe9b5dba58189dbbc + w3_t + (((b >> 14) | (b << 50)) ^ ((b >> 18) | (b << 46)) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d)));
		"mov.b64		{ r1, dummy }, b; \n\t"
		"mov.b64		{ dummy, r2 }, b; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, c, d;\n\t"
		"and .b64			rd7, b, rd6;\n\t"
		"xor .b64			rd8, d, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, e, temp4;\n\t"
		"add.u64			rd11, rd10, w3_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			a, rd12, a;\n\t"

		".reg.u64			temp_a;\n\t"
		"mov.u64			temp_a, rd12;\n\t"


		//e = e + 0xe9b5dba58189dbbc + w3_t + (((b >> 14) | (b << (50))) ^ ((b >> 18) | (b << (46))) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d))) + (((f >> 28) | (f << 36)) ^ ((f >> 34) | (f << 30)) ^ ((f >> 39) | (f << 25))) + ((f & g) | (h & (f ^ g)));
		"mov.b64		{ r1, dummy }, f;\n\t"
		"mov.b64		{ dummy, r2 }, f;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, f, g;			\n\t"
		"and.b64			rd7, h, rd6;			\n\t"
		"and.b64			rd8, f, g;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			e, temp_a, rd10;\n\t"

		".reg.u64			temp_e;\n\t"
		//"mov.u64			temp_e, rd10;\n\t"

		//! 5. SHA512_STEP(e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
		//h += d + 0x3956c25bf348b538 + w4_t + (((a >> 14) | (a << 50)) ^ ((a >> 18) | (a << 46)) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c)));
		"mov.b64		{ r1, dummy }, a; \n\t"
		"mov.b64		{ dummy, r2 }, a; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, b, c;\n\t"
		"and .b64			rd7, a, rd6;\n\t"
		"xor .b64			rd8, c, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, d, temp5;\n\t"
		"add.u64			rd11, rd10, w4_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			h, rd12, h;\n\t"

		"mov.u64			temp_h, rd12;\n\t"


		//d = d + 0x3956c25bf348b538 + w4_t + (((a >> 14) | (a << (50))) ^ ((a >> 18) | (a << (46))) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c))) + (((e >> 28) | (e << 36)) ^ ((e >> 34) | (e << 30)) ^ ((e >> 39) | (e << 25))) + ((e & f) | (g & (e ^ f)));
		"mov.b64		{ r1, dummy }, e;\n\t"
		"mov.b64		{ dummy, r2 }, e;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, e, f;			\n\t"
		"and.b64			rd7, g, rd6;			\n\t"
		"and.b64			rd8, e, f;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			d, temp_h, rd10;\n\t"

		//"mov.u64			temp_d, rd10;\n\t"

		//! 6. SHA512_STEP(d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
		//g += c + 0x59f111f1b605d019 + w5_t + (((h >> 14) | (h << 50)) ^ ((h >> 18) | (h << 46)) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b)));
		"mov.b64		{ r1, dummy }, h; \n\t"
		"mov.b64		{ dummy, r2 }, h; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, a, b;\n\t"
		"and .b64			rd7, h, rd6;\n\t"
		"xor .b64			rd8, b, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, c, temp6;\n\t"
		"add.u64			rd11, rd10, w5_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			g, rd12, g;\n\t"

		"mov.u64			temp_g, rd12;\n\t"


		//c = c + 0x59f111f1b605d019 + w5_t + (((h >> 14) | (h << (50))) ^ ((h >> 18) | (h << (46))) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b))) + (((d >> 28) | (d << 36)) ^ ((d >> 34) | (d << 30)) ^ ((d >> 39) | (d << 25))) + ((d & e) | (f & (d ^ e)));
		"mov.b64		{ r1, dummy }, d;\n\t"
		"mov.b64		{ dummy, r2 }, d;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, d, e;			\n\t"
		"and.b64			rd7, f, rd6;			\n\t"
		"and.b64			rd8, d, e;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			c, temp_g, rd10;\n\t"

		//"mov.u64			temp_c, rd10;\n\t"

		//! 7. SHA512_STEP(c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
		//f += b + 0x923f82a4af194f9b + w6_t + (((g >> 14) | (g << 50)) ^ ((g >> 18) | (g << 46)) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a)));
		"mov.b64		{ r1, dummy }, g; \n\t"
		"mov.b64		{ dummy, r2 }, g; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, h, a;\n\t"
		"and .b64			rd7, g, rd6;\n\t"
		"xor .b64			rd8, a, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, b, temp7;\n\t"
		"add.u64			rd11, rd10, w6_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			f, rd12, f;\n\t"

		"mov.u64			temp_f, rd12;\n\t"

		//b = b + 0x923f82a4af194f9b + w6_t + (((g >> 14) | (g << (50))) ^ ((g >> 18) | (g << (46))) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a))) + (((c >> 28) | (c << 36)) ^ ((c >> 34) | (c << 30)) ^ ((c >> 39) | (c << 25))) + ((c & d) | (e & (c ^ d)));
		"mov.b64		{ r1, dummy }, c;\n\t"
		"mov.b64		{ dummy, r2 }, c;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, c, d;			\n\t"
		"and.b64			rd7, e, rd6;			\n\t"
		"and.b64			rd8, c, d;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			b, temp_f, rd10;\n\t"

		//"mov.u64			temp_b, rd10;\n\t"

		//! 8. SHA512_STEP(b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
		//e += a + 0xab1c5ed5da6d8118 + w7_t + (((f >> 14) | (f << 50)) ^ ((f >> 18) | (f << 46)) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h)));
		"mov.b64		{ r1, dummy }, f; \n\t"
		"mov.b64		{ dummy, r2 }, f; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, g, h;\n\t"
		"and .b64			rd7, f, rd6;\n\t"
		"xor .b64			rd8, h, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, a, temp8;\n\t"
		"add.u64			rd11, rd10, w7_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			e, rd12, e;\n\t"

		"mov.u64			temp_e, rd12;\n\t"

		//a = a + 0xab1c5ed5da6d8118 + w7_t + (((f >> 14) | (f << (50))) ^ ((f >> 18) | (f << (46))) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h))) + (((b >> 28) | (b << 36)) ^ ((b >> 34) | (b << 30)) ^ ((b >> 39) | (b << 25))) + ((b & c) | (d & (b ^ c)));
		"mov.b64		{ r1, dummy }, b;\n\t"
		"mov.b64		{ dummy, r2 }, b;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, b, c;			\n\t"
		"and.b64			rd7, d, rd6;			\n\t"
		"and.b64			rd8, b, c;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			a, temp_e, rd10;\n\t"

		//"mov.u64			temp_a, rd10;\n\t"



		//SHA512_STEP(a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
		//SHA512_STEP(h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
		//SHA512_STEP(g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
		//SHA512_STEP(f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
		//SHA512_STEP(e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
		//SHA512_STEP(d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
		//SHA512_STEP(c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
		//SHA512_STEP(b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

		//SHA512_STEP(a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
		//d += h + 0xd807aa98a3030242 + w8_t + (((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23))) + (g ^ (e & (f ^ g)));
		//h = h + 0xd807aa98a3030242 + w8_t + (((e >> 14) | (e << (50))) ^ ((e >> 18) | (e << (46))) ^ ((e >> 41) | (e << 23))) + (g ^ (e & (f ^ g))) + (((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25))) + ((a & b) | (c & (a ^ b)));
		"mov.b64		{ r1, dummy }, e; \n\t"
		"mov.b64		{ dummy, r2 }, e; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, f, g;\n\t"
		"and .b64			rd7, e, rd6;\n\t"
		"xor .b64			rd8, g, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, h, temp9;\n\t"
		"add.u64			rd11, rd10, w8_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			d, rd12, d;\n\t"

		"mov.u64			temp_d, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, a;\n\t"
		"mov.b64		{ dummy, r2 }, a;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, a, b;			\n\t"
		"and.b64			rd7, c, rd6;			\n\t"
		"and.b64			rd8, a, b;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			h, temp_d, rd10;\n\t"

		//"mov.u64			temp_h, rd10;\n\t"

		//SHA512_STEP(h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
		//c += g + 0x12835b0145706fbe + w9_t + (((d >> 14) | (d << 50)) ^ ((d >> 18) | (d << 46)) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f)));
		//g = g + 0x12835b0145706fbe + w9_t + (((d >> 14) | (d << (50))) ^ ((d >> 18) | (d << (46))) ^ ((d >> 41) | (d << 23))) + (f ^ (d & (e ^ f))) + (((h >> 28) | (h << 36)) ^ ((h >> 34) | (h << 30)) ^ ((h >> 39) | (h << 25))) + ((h & a) | (b & (h ^ a)));
		"mov.b64		{ r1, dummy }, d; \n\t"
		"mov.b64		{ dummy, r2 }, d; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"


		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, e, f;\n\t"
		"and .b64			rd7, d, rd6;\n\t"
		"xor .b64			rd8, f, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, g, temp10;\n\t"
		"add.u64			rd11, rd10, w9_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			c, rd12, c;\n\t"

		"mov.u64			temp_c, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, h;\n\t"
		"mov.b64		{ dummy, r2 }, h;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, h, a;			\n\t"
		"and.b64			rd7, b, rd6;			\n\t"
		"and.b64			rd8, h, a;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			g, temp_c, rd10;\n\t"

		//"mov.u64			temp_g, rd10;\n\t"

		//SHA512_STEP(g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
		//b += f + 0x243185be4ee4b28c + wa_t + (((c >> 14) | (c << 50)) ^ ((c >> 18) | (c << 46)) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e)));
		//f = f + 0x243185be4ee4b28c + wa_t + (((c >> 14) | (c << (50))) ^ ((c >> 18) | (c << (46))) ^ ((c >> 41) | (c << 23))) + (e ^ (c & (d ^ e))) + (((g >> 28) | (g << 36)) ^ ((g >> 34) | (g << 30)) ^ ((g >> 39) | (g << 25))) + ((g & h) | (a & (g ^ h)));
		"mov.b64		{ r1, dummy }, c; \n\t"
		"mov.b64		{ dummy, r2 }, c; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, d, e;\n\t"
		"and .b64			rd7, c, rd6;\n\t"
		"xor .b64			rd8, e, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, f, temp11;\n\t"
		"add.u64			rd11, rd10, wa_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			b, rd12, b;\n\t"

		"mov.u64			temp_b, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, g;\n\t"
		"mov.b64		{ dummy, r2 }, g;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, g, h;			\n\t"
		"and.b64			rd7, a, rd6;			\n\t"
		"and.b64			rd8, g, h;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			f, temp_b, rd10;\n\t"

		//	"mov.u64			temp_f, rd10;\n\t"


			//SHA512_STEP(f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
			//a += e + 0x550c7dc3d5ffb4e2 + wb_t + (((b >> 14) | (b << 50)) ^ ((b >> 18) | (b << 46)) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d)));
			//e = e + 0x550c7dc3d5ffb4e2 + wb_t + (((b >> 14) | (b << (50))) ^ ((b >> 18) | (b << (46))) ^ ((b >> 41) | (b << 23))) + (d ^ (b & (c ^ d))) + (((f >> 28) | (f << 36)) ^ ((f >> 34) | (f << 30)) ^ ((f >> 39) | (f << 25))) + ((f & g) | (h & (f ^ g)));
		"mov.b64		{ r1, dummy }, b; \n\t"
		"mov.b64		{ dummy, r2 }, b; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, c, d;\n\t"
		"and .b64			rd7, b, rd6;\n\t"
		"xor .b64			rd8, d, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, e, temp12;\n\t"
		"add.u64			rd11, rd10, wb_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			a, rd12, a;\n\t"

		"mov.u64			temp_a, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, f;\n\t"
		"mov.b64		{ dummy, r2 }, f;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, f, g;			\n\t"
		"and.b64			rd7, h, rd6;			\n\t"
		"and.b64			rd8, f, g;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			e, temp_a, rd10;\n\t"

		//"mov.u64			temp_e, rd10;\n\t"

		//SHA512_STEP(e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
		//h += d + 0x72be5d74f27b896f + wc_t + (((a >> 14) | (a << 50)) ^ ((a >> 18) | (a << 46)) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c)));
		//d = d + 0x72be5d74f27b896f + wc_t + (((a >> 14) | (a << (50))) ^ ((a >> 18) | (a << (46))) ^ ((a >> 41) | (a << 23))) + (c ^ (a & (b ^ c))) + (((e >> 28) | (e << 36)) ^ ((e >> 34) | (e << 30)) ^ ((e >> 39) | (e << 25))) + ((e & f) | (g & (e ^ f)));
		"mov.b64		{ r1, dummy }, a; \n\t"
		"mov.b64		{ dummy, r2 }, a; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, b, c;\n\t"
		"and .b64			rd7, a, rd6;\n\t"
		"xor .b64			rd8, c, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, d, temp13;\n\t"
		"add.u64			rd11, rd10, wc_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			h, rd12, h;\n\t"

		"mov.u64			temp_h, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, e;\n\t"
		"mov.b64		{ dummy, r2 }, e;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, e, f;			\n\t"
		"and.b64			rd7, g, rd6;			\n\t"
		"and.b64			rd8, e, f;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			d, temp_h, rd10;\n\t"

		//"mov.u64			temp_d, rd10;\n\t"

		//SHA512_STEP(d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
		//g += c + 0x80deb1fe3b1696b1 + wd_t + (((h >> 14) | (h << 50)) ^ ((h >> 18) | (h << 46)) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b)));
		//c = c + 0x80deb1fe3b1696b1 + wd_t + (((h >> 14) | (h << (50))) ^ ((h >> 18) | (h << (46))) ^ ((h >> 41) | (h << 23))) + (b ^ (h & (a ^ b))) + (((d >> 28) | (d << 36)) ^ ((d >> 34) | (d << 30)) ^ ((d >> 39) | (d << 25))) + ((d & e) | (f & (d ^ e)));
		"mov.b64		{ r1, dummy }, h; \n\t"
		"mov.b64		{ dummy, r2 }, h; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, a, b;\n\t"
		"and .b64			rd7, h, rd6;\n\t"
		"xor .b64			rd8, b, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, c, temp14;\n\t"
		"add.u64			rd11, rd10, wd_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			g, rd12, g;\n\t"

		"mov.u64			temp_g, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, d;\n\t"
		"mov.b64		{ dummy, r2 }, d;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, d, e;			\n\t"
		"and.b64			rd7, f, rd6;			\n\t"
		"and.b64			rd8, d, e;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			c, temp_g, rd10;\n\t"

		//"mov.u64			temp_c, rd10;\n\t"

		//SHA512_STEP(c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
		//f += b + 0x9bdc06a725c71235 + we_t + (((g >> 14) | (g << 50)) ^ ((g >> 18) | (g << 46)) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a)));
		//b = b + 0x9bdc06a725c71235 + we_t + (((g >> 14) | (g << (50))) ^ ((g >> 18) | (g << (46))) ^ ((g >> 41) | (g << 23))) + (a ^ (g & (h ^ a))) + (((c >> 28) | (c << 36)) ^ ((c >> 34) | (c << 30)) ^ ((c >> 39) | (c << 25))) + ((c & d) | (e & (c ^ d)));
		"mov.b64		{ r1, dummy }, g; \n\t"
		"mov.b64		{ dummy, r2 }, g; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"

		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, h, a;\n\t"
		"and .b64			rd7, g, rd6;\n\t"
		"xor .b64			rd8, a, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, b, temp15;\n\t"
		"add.u64			rd11, rd10, we_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			f, rd12, f;\n\t"

		"mov.u64			temp_f, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, c;\n\t"
		"mov.b64		{ dummy, r2 }, c;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, c, d;			\n\t"
		"and.b64			rd7, e, rd6;			\n\t"
		"and.b64			rd8, c, d;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			b, temp_f, rd10;\n\t"

		//"mov.u64			temp_b, rd10;\n\t"

		//SHA512_STEP(b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);
		//e += a + 0xc19bf174cf692694 + wf_t + (((f >> 14) | (f << 50)) ^ ((f >> 18) | (f << 46)) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h)));
		//a = a + 0xc19bf174cf692694 + wf_t + (((f >> 14) | (f << (50))) ^ ((f >> 18) | (f << (46))) ^ ((f >> 41) | (f << 23))) + (h ^ (f & (g ^ h))) + (((b >> 28) | (b << 36)) ^ ((b >> 34) | (b << 30)) ^ ((b >> 39) | (b << 25))) + ((b & c) | (d & (b ^ c)));
		"mov.b64		{ r1, dummy }, f; \n\t"
		"mov.b64		{ dummy, r2 }, f; \n\t"

		"shf.r.wrap.b32		r3, r2, r1, 14;	\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 14;	\n\t"

		"shf.r.wrap.b32		r5, r2, r1, 18;	\n\t"
		"shf.r.wrap.b32		r6, r1, r2, 18;	\n\t"


		"shf.l.wrap.b32		r7, r1, r2, 23;	\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 23;	\n\t"


		"mov.b64		rd1, { r4,r3 };			\n\t"
		"mov.b64		rd2, { r6, r5 };			\n\t"
		"xor .b64		rd3, rd2, rd1;			\n\t"
		"mov.b64		rd4, { r8, r7 };			\n\t"
		"xor .b64		rd5, rd3, rd4;	\n\t"

		"xor .b64			rd6, g, h;\n\t"
		"and .b64			rd7, f, rd6;\n\t"
		"xor .b64			rd8, h, rd7;\n\t"
		"add.u64			rd9, rd5, rd8;\n\t"
		"add.u64			rd10, a, temp16;\n\t"
		"add.u64			rd11, rd10, wf_t;\n\t"

		"add.u64			rd12, rd11, rd9;\n\t"
		"add.u64			e, rd12, e;\n\t"

		"mov.u64			temp_e, rd12;\n\t"

		//
		"mov.b64		{ r1, dummy }, b;\n\t"
		"mov.b64		{ dummy, r2 }, b;\n\t"

		"shf.r.wrap.b32		r3, r2, r1, 28;\n\t"
		"shf.r.wrap.b32		r4, r1, r2, 28;\n\t"

		"shf.l.wrap.b32		r5, r1, r2, 30;\n\t"
		"shf.l.wrap.b32		r6, r2, r1, 30;\n\t"

		"shf.l.wrap.b32		r7, r1, r2, 25;\n\t"
		"shf.l.wrap.b32		r8, r2, r1, 25;\n\t"

		"mov.b64		rd1, { r4, r3 };\n\t"
		"mov.b64		rd2, { r6, r5 };\n\t"
		"xor .b64		rd3, rd2, rd1;\n\t"
		"mov.b64		rd4, { r8, r7 };\n\t"
		"xor .b64		rd5, rd3, rd4;\n\t"

		"xor.b64			rd6, b, c;			\n\t"
		"and.b64			rd7, d, rd6;			\n\t"
		"and.b64			rd8, b, c;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;\n\t"
		"add.u64			a, temp_e, rd10;\n\t"

		//출력
		"mov.u64			%0, a;			\n\t"
		"mov.u64			%1, b;			\n\t"
		"mov.u64			%2, c;			\n\t"
		"mov.u64			%3, d;			\n\t"
		"mov.u64			%4, e;			\n\t"
		"mov.u64			%5, f;			\n\t"
		"mov.u64			%6, g;			\n\t"
		"mov.u64			%7, h;			\n\t"

		"mov.u64			%8, w0_t;			\n\t"
		"mov.u64			%9, w1_t;			\n\t"
		"mov.u64			%10, w2_t;			\n\t"
		"mov.u64			%11, w3_t;			\n\t"
		"mov.u64			%12, w4_t;			\n\t"
		"mov.u64			%13, w5_t;			\n\t"
		"mov.u64			%14, w6_t;			\n\t"
		"mov.u64			%15, w7_t;			\n\t"


		"}"
		//:"+l"(_prestate_1[0]), "+l"(_prestate_1[1]), "+l"(_prestate_1[2]), "+l"(_prestate_1[3]), "+l"(_prestate_1[4]), "+l"(_prestate_1[5]), "+l"(_prestate_1[6]), "+l"(_prestate_1[7]), "+l"(in[0]), "+l"(in[1]), "+l"(in[2]), "+l"(in[3]), "+l"(in[4]), "+l"(in[5]), "+l"(in[6]), "+l"(in[7])
		:"+l"(a), "+l"(b), "+l"(c), "+l"(d), "+l"(e), "+l"(f), "+l"(g), "+l"(h), "+l"(w0_t), "+l"(w1_t), "+l"(w2_t), "+l"(w3_t), "+l"(w4_t), "+l"(w5_t), "+l"(w6_t), "+l"(w7_t)
	);
#endif

#if 0
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
#endif

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

	_temp[0] ^= digest[0];
	_temp[1] ^= digest[1];
	_temp[2] ^= digest[2];
	_temp[3] ^= digest[3];
	_temp[4] ^= digest[4];
	_temp[5] ^= digest[5];
	_temp[6] ^= digest[6];
	_temp[7] ^= digest[7];

	in[0] = digest[0];
	in[1] = digest[1];
	in[2] = digest[2];
	in[3] = digest[3];
	in[4] = digest[4];
	in[5] = digest[5];
	in[6] = digest[6];
	in[7] = digest[7];
}

__device__ void _PBKDF2_HMAC_SHA512_core_test8(uint64_t* _prestate_1, uint64_t* _prestate_2, uint64_t* digest, uint64_t* in, uint64_t* _temp) {
	/*
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
	
	*/

	asm("{\n\t"
		".reg.b64			w0_t;			\n\t"
		".reg.b64			w1_t;			\n\t"
		".reg.b64			w2_t;			\n\t"
		".reg.b64			w3_t;			\n\t"
		".reg.b64			w4_t;			\n\t"
		".reg.b64			w5_t;			\n\t"
		".reg.b64			w6_t;			\n\t"
		".reg.b64			w7_t;			\n\t"

		".reg.b64			w8_t;			\n\t"
		".reg.b64			w9_t;			\n\t"
		".reg.b64			wa_t;			\n\t"
		".reg.b64			wb_t;			\n\t"
		".reg.b64			wc_t;			\n\t"
		".reg.b64			wd_t;			\n\t"
		".reg.b64			we_t;			\n\t"
		".reg.b64			wf_t;			\n\t"

		".reg.b64			a;			\n\t"
		".reg.b64			b;			\n\t"
		".reg.b64			c;			\n\t"
		".reg.b64			d;			\n\t"
		".reg.b64			e;			\n\t"
		".reg.b64			f;			\n\t"
		".reg.b64			g;			\n\t"
		".reg.b64			h;			\n\t"

		".reg.b64			rd0;			\n\t"
		".reg.b64			rd1;			\n\t"
		".reg.b64			rd2;			\n\t"
		".reg.b64			rd3;			\n\t"
		".reg.b64			rd4;			\n\t"
		".reg.b64			rd5;			\n\t"
		".reg.b64			rd6;			\n\t"
		".reg.b64			rd7;			\n\t"
		".reg.b64			rd8;			\n\t"
		".reg.b64			rd9;			\n\t"
		".reg.b64			rd10;			\n\t"

		".reg.b64			rd20;			\n\t"
		".reg.b64			rd21;			\n\t"
		".reg.b64			rd22;			\n\t"
		".reg.b64			rd23;			\n\t"
		".reg.b64			rd24;			\n\t"
		".reg.b64			rd25;			\n\t"
		".reg.b64			rd26;			\n\t"
		".reg.b64			rd27;			\n\t"
		".reg.b64			rd28;			\n\t"
		".reg.b64			rd29;			\n\t"
		".reg.b64			rd30;			\n\t"

		".reg.b64			rd40;			\n\t"
		".reg.b64			rd41;			\n\t"
		".reg.b64			rd42;			\n\t"
		".reg.b64			rd43;			\n\t"
		".reg.b64			rd44;			\n\t"
		".reg.b64			rd45;			\n\t"
		".reg.b64			rd46;			\n\t"
		".reg.b64			rd47;			\n\t"
		".reg.b64			rd48;			\n\t"
		".reg.b64			rd49;			\n\t"
		".reg.b64			rd50;			\n\t"

		".reg.b64			rd60;			\n\t"
		".reg.b64			rd61;			\n\t"
		".reg.b64			rd62;			\n\t"
		".reg.b64			rd63;			\n\t"
		".reg.b64			rd64;			\n\t"
		".reg.b64			rd65;			\n\t"
		".reg.b64			rd66;			\n\t"
		".reg.b64			rd67;			\n\t"
		".reg.b64			rd68;			\n\t"
		".reg.b64			rd69;			\n\t"
		".reg.b64			rd70;			\n\t"


		".reg.b64			lhs0;			\n\t"
		".reg.b64			rhs0;			\n\t"
		".reg.b64			lhs1;			\n\t"
		".reg.b64			rhs1;			\n\t"
		".reg.b64			lhs2;			\n\t"
		".reg.b64			rhs2;			\n\t"
		".reg.b64			lhs3;			\n\t"
		".reg.b64			rhs3;			\n\t"
		".reg.b64			lhs4;			\n\t"
		".reg.b64			rhs4;			\n\t"
		".reg.b64			lhs5;			\n\t"
		".reg.b64			rhs5;			\n\t"

		".reg.b64			lhs10;			\n\t"
		".reg.b64			rhs10;			\n\t"
		".reg.b64			lhs11;			\n\t"
		".reg.b64			rhs11;			\n\t"
		".reg.b64			lhs12;			\n\t"
		".reg.b64			rhs12;			\n\t"
		".reg.b64			lhs13;			\n\t"
		".reg.b64			rhs13;			\n\t"
		".reg.b64			lhs14;			\n\t"
		".reg.b64			rhs14;			\n\t"
		".reg.b64			lhs15;			\n\t"
		".reg.b64			rhs15;			\n\t"

		".reg.b64			lhs20;			\n\t"
		".reg.b64			rhs20;			\n\t"
		".reg.b64			lhs21;			\n\t"
		".reg.b64			rhs21;			\n\t"
		".reg.b64			lhs22;			\n\t"
		".reg.b64			rhs22;			\n\t"
		".reg.b64			lhs23;			\n\t"
		".reg.b64			rhs23;			\n\t"
		".reg.b64			lhs24;			\n\t"
		".reg.b64			rhs24;			\n\t"
		".reg.b64			lhs25;			\n\t"
		".reg.b64			rhs25;			\n\t"

		".reg.b64			lhs30;			\n\t"
		".reg.b64			rhs30;			\n\t"
		".reg.b64			lhs31;			\n\t"
		".reg.b64			rhs31;			\n\t"
		".reg.b64			lhs32;			\n\t"
		".reg.b64			rhs32;			\n\t"
		".reg.b64			lhs33;			\n\t"
		".reg.b64			rhs33;			\n\t"
		".reg.b64			lhs34;			\n\t"
		".reg.b64			rhs34;			\n\t"
		".reg.b64			lhs35;			\n\t"
		".reg.b64			rhs35;			\n\t"

		"mov.u64			w0_t, %24;			\n\t"
		"mov.u64			w1_t, %25;			\n\t"
		"mov.u64			w2_t, %26;			\n\t"
		"mov.u64			w3_t, %27;			\n\t"
		"mov.u64			w4_t, %28;			\n\t"
		"mov.u64			w5_t, %29;			\n\t"
		"mov.u64			w6_t, %30;			\n\t"
		"mov.u64			w7_t, %31;			\n\t"

		"mov.u64			w8_t, 0x8000000000000000;			\n\t"
		"mov.u64			w9_t, 0;			\n\t"
		"mov.u64			wa_t, 0;			\n\t"
		"mov.u64			wb_t, 0;			\n\t"
		"mov.u64			wc_t, 0;			\n\t"
		"mov.u64			wd_t, 0;			\n\t"
		"mov.u64			we_t, 0;			\n\t"
		"mov.u64			wf_t, 1536;			\n\t"

		"mov.u64			a, %0;			\n\t"
		"mov.u64			b, %1;			\n\t"
		"mov.u64			c, %2;			\n\t"
		"mov.u64			d, %3;			\n\t"
		"mov.u64			e, %4;			\n\t"
		"mov.u64			f, %5;			\n\t"
		"mov.u64			g, %6;			\n\t"
		"mov.u64			h, %7;			\n\t"

		//SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
		//{ h = (h + 0x428a2f98d728ae22 + w0_t); h = (h + ((((e) >> (14)) | ((e) << (64 - (14)))) ^ (((e) >> (18)) | ((e) << (64 - (18)))) ^ (((e) >> (41)) | ((e) << (64 - (41))))) + ((g) ^ ((e) & ((f) ^ (g)))));
		//d += h;
		//h = (h + (((((a) >> (28)) | ((a) << (64 - (28))))) ^ (((a) >> (34)) | ((a) << (64 - (34)))) ^ (((a) >> (39)) | ((a) << (64 - (39))))) + (((a) & (b)) | ((c) & ((a) ^ (b))))); }
		
		//pipeline code 1times
		"add.u64			rd0, h, 0x428a2f98d728ae22;			\n\t"

		"xor.b64			rd6, f, g;			\n\t"

		"shl.b64			lhs0, e, 50;			\n\t"
		"shr.b64			rhs0, e, 14;			\n\t"
		"add.u64			rd1, lhs0, rhs0;			\n\t"

		"shl.b64			lhs1, e, 46;			\n\t"
		"shr.b64			rhs1, e, 18;			\n\t"
		"add.u64			rd2, lhs1, rhs1;			\n\t"

		"and.b64			rd7, e, rd6;			\n\t"

		"shl.b64			lhs2, e, 23;			\n\t"
		"shr.b64			rhs2, e, 41;			\n\t"
		"add.u64			rd4, lhs2, rhs2;			\n\t"

		"xor.b64			rd3, rd1, rd2;			\n\t"
		"xor.b64			rd8, g, rd7;			\n\t"
		"add.u64			h, w0_t, rd0;			\n\t"


		"shl.b64			lhs3, a, 36;			\n\t"
		"shr.b64			rhs3, a, 28;			\n\t"
		"xor.b64			rd5, rd3, rd4;			\n\t"
		"add.u64			rd1, lhs3, rhs3;			\n\t"


		"shl.b64			lhs4, a, 30;			\n\t"
		"shr.b64			rhs4, a, 34;			\n\t"
		"add.u64			rd2, lhs4, rhs4;			\n\t"

		"add.u64			rd9, rd5, rd8;			\n\t"
		"shl.b64			lhs5, a, 25;			\n\t"
		"shr.b64			rhs5, a, 39;			\n\t"
		"xor.b64			rd3, rd1, rd2;			\n\t"
		"add.u64			rd4, lhs5, rhs5;			\n\t"
		"xor.b64			rd6, a, b;			\n\t"
		"and.b64			rd8, a, b;			\n\t"
		"add.u64			h, h, rd9;			\n\t"
		"xor.b64			rd5, rd3, rd4;			\n\t"
		"and.b64			rd7, c, rd6;			\n\t"
		"add.u64			d, d, h;			\n\t"
		"or.b64				rd9, rd7, rd8;			\n\t"
		"add.u64			rd10, rd5, rd9;			\n\t"
		"add.u64			h, h, rd10;			\n\t"

		//SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
		//{ g = (g + 0x7137449123ef65cd + w1_t); g = (g + ((((d) >> (14)) | ((d) << (64 - (14)))) ^ (((d) >> (18)) | ((d) << (64 - (18)))) ^ (((d) >> (41)) | ((d) << (64 - (41))))) + ((f) ^ ((d) & ((e) ^ (f)))));
		//c += g;
		//g = (g + (((((h) >> (28)) | ((h) << (64 - (28))))) ^ (((h) >> (34)) | ((h) << (64 - (34)))) ^ (((h) >> (39)) | ((h) << (64 - (39))))) + (((h) & (a)) | ((b) & ((h) ^ (a))))); }

		"add.u64			rd20, g, 0x7137449123ef65cd;			\n\t"

		"xor.b64			rd26, e, f;			\n\t"

		"shl.b64			lhs10, d, 50;			\n\t"
		"shr.b64			rhs10, d, 14;			\n\t"
		"add.u64			rd21, lhs10, rhs10;			\n\t"

		"shl.b64			lhs11, d, 46;			\n\t"
		"shr.b64			rhs11, d, 18;			\n\t"
		"add.u64			rd22, lhs11, rhs11;			\n\t"

		"and.b64			rd27, d, rd26;			\n\t"

		"shl.b64			lhs12, d, 23;			\n\t"
		"shr.b64			rhs12, d, 41;			\n\t"
		"add.u64			rd24, lhs12, rhs12;			\n\t"

		"xor.b64			rd23, rd21, rd22;			\n\t"
		"xor.b64			rd28, f, rd27;			\n\t"
		"add.u64			g, w1_t, rd20;			\n\t"


		"shl.b64			lhs13, h, 36;			\n\t"
		"shr.b64			rhs13, h, 28;			\n\t"
		"xor.b64			rd25, rd23, rd24;			\n\t"
		"add.u64			rd21, lhs13, rhs13;			\n\t"


		"shl.b64			lhs14, h, 30;			\n\t"
		"shr.b64			rhs14, h, 34;			\n\t"
		"add.u64			rd22, lhs14, rhs14;			\n\t"

		"add.u64			rd29, rd25, rd28;			\n\t"
		"shl.b64			lhs15, h, 25;			\n\t"
		"shr.b64			rhs15, h, 39;			\n\t"
		"xor.b64			rd23, rd21, rd22;			\n\t"
		"add.u64			rd24, lhs15, rhs15;			\n\t"
		"xor.b64			rd26, h, a;			\n\t"
		"and.b64			rd28, h, a;			\n\t"
		"add.u64			g, g, rd29;			\n\t"
		"xor.b64			rd25, rd23, rd24;			\n\t"
		"and.b64			rd27, b, rd26;			\n\t"
		"add.u64			c, c, g;			\n\t"
		"or.b64				rd29, rd27, rd28;			\n\t"
		"add.u64			rd30, rd25, rd29;			\n\t"
		"add.u64			g, g, rd30;			\n\t"
		
		//SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
		//{ f = (f + 0xb5c0fbcfec4d3b2f + w2_t);
		//f = (f + ((((c) >> (14)) | ((c) << (64 - (14)))) ^ (((c) >> (18)) | ((c) << (64 - (18)))) ^ (((c) >> (41)) | ((c) << (64 - (41))))) + ((e) ^ ((c) & ((d) ^ (e)))));
		//b += f;
		//f = (f + (((((g) >> (28)) | ((g) << (64 - (28))))) ^ (((g) >> (34)) | ((g) << (64 - (34)))) ^ (((g) >> (39)) | ((g) << (64 - (39))))) + (((g) & (h)) | ((a) & ((g) ^ (h))))); }

		"add.u64			rd40, f, 0xb5c0fbcfec4d3b2f;			\n\t"

		"xor.b64			rd46, d, e;			\n\t"

		"shl.b64			lhs20, c, 50;			\n\t"
		"shr.b64			rhs20, c, 14;			\n\t"
		"add.u64			rd41, lhs20, rhs20;			\n\t"

		"shl.b64			lhs21, c, 46;			\n\t"
		"shr.b64			rhs21, c, 18;			\n\t"
		"add.u64			rd42, lhs21, rhs21;			\n\t"

		"and.b64			rd47, c, rd46;			\n\t"

		"shl.b64			lhs22, c, 23;			\n\t"
		"shr.b64			rhs22, c, 41;			\n\t"
		"add.u64			rd44, lhs22, rhs22;			\n\t"

		"xor.b64			rd43, rd41, rd42;			\n\t"
		"xor.b64			rd48, e, rd47;			\n\t"
		"add.u64			f, w2_t, rd40;			\n\t"


		"shl.b64			lhs23, g, 36;			\n\t"
		"shr.b64			rhs23, g, 28;			\n\t"
		"xor.b64			rd45, rd43, rd44;			\n\t"
		"add.u64			rd41, lhs23, rhs23;			\n\t"


		"shl.b64			lhs24, g, 30;			\n\t"
		"shr.b64			rhs24, g, 34;			\n\t"
		"add.u64			rd42, lhs24, rhs24;			\n\t"

		"add.u64			rd49, rd45, rd48;			\n\t"
		"shl.b64			lhs25, g, 25;			\n\t"
		"shr.b64			rhs25, g, 39;			\n\t"
		"xor.b64			rd43, rd41, rd42;			\n\t"
		"add.u64			rd44, lhs25, rhs25;			\n\t"
		"xor.b64			rd46, g, h;			\n\t"
		"and.b64			rd48, g, h;			\n\t"
		"add.u64			f, f, rd49;			\n\t"
		"xor.b64			rd45, rd43, rd44;			\n\t"
		"and.b64			rd47, a, rd46;			\n\t"
		"add.u64			b, b, f;			\n\t"
		"or.b64				rd49, rd47, rd48;			\n\t"
		"add.u64			rd50, rd45, rd49;			\n\t"
		"add.u64			f, f, rd50;			\n\t"
		
		//SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
		//{ e = (e + 0xe9b5dba58189dbbc + w3_t);
		//e = (e + ((((b) >> (14)) | ((b) << (64 - (14)))) ^ (((b) >> (18)) | ((b) << (64 - (18)))) ^ (((b) >> (41)) | ((b) << (64 - (41))))) + ((d) ^ ((b) & ((c) ^ (d)))));
		//a += e;
		//e = (e + (((((f) >> (28)) | ((f) << (64 - (28))))) ^ (((f) >> (34)) | ((f) << (64 - (34)))) ^ (((f) >> (39)) | ((f) << (64 - (39))))) + (((f) & (g)) | ((h) & ((f) ^ (g))))); }
		"add.u64			rd60, e, 0xe9b5dba58189dbbc;			\n\t"

		"xor.b64			rd66, c, d;			\n\t"

		"shl.b64			lhs30, b, 50;			\n\t"
		"shr.b64			rhs30, b, 14;			\n\t"
		"add.u64			rd61, lhs30, rhs30;			\n\t"

		"shl.b64			lhs31, b, 46;			\n\t"
		"shr.b64			rhs31, b, 18;			\n\t"
		"add.u64			rd62, lhs31, rhs31;			\n\t"

		"and.b64			rd67, b, rd66;			\n\t"

		"shl.b64			lhs32, b, 23;			\n\t"
		"shr.b64			rhs32, b, 41;			\n\t"
		"add.u64			rd64, lhs32, rhs32;			\n\t"

		"xor.b64			rd63, rd61, rd62;			\n\t"
		"xor.b64			rd68, d, rd67;			\n\t"
		"add.u64			e, w3_t, rd60;			\n\t"


		"shl.b64			lhs33, f, 36;			\n\t"
		"shr.b64			rhs33, f, 28;			\n\t"
		"xor.b64			rd65, rd63, rd64;			\n\t"
		"add.u64			rd61, lhs33, rhs33;			\n\t"


		"shl.b64			lhs34, f, 30;			\n\t"
		"shr.b64			rhs34, f, 34;			\n\t"
		"add.u64			rd62, lhs34, rhs34;			\n\t"

		"add.u64			rd69, rd65, rd68;			\n\t"
		"shl.b64			lhs35, f, 25;			\n\t"
		"shr.b64			rhs35, f, 39;			\n\t"
		"xor.b64			rd63, rd61, rd62;			\n\t"
		"add.u64			rd64, lhs35, rhs35;			\n\t"
		"xor.b64			rd66, f, g;			\n\t"
		"and.b64			rd68, f, g;			\n\t"
		"add.u64			e, e, rd69;			\n\t"
		"xor.b64			rd65, rd63, rd64;			\n\t"
		"and.b64			rd67, h, rd66;			\n\t"
		"add.u64			a, a, e;			\n\t"
		"or.b64				rd69, rd67, rd68;			\n\t"
		"add.u64			rd70, rd65, rd69;			\n\t"
		"add.u64			e, e, rd70;			\n\t"

		//SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
		//SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
		//SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
		//SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
		//SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
		//SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
		//SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
		//SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
		//SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
		//SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
		//SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
		//SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);


		/*
			digest[0] = _prestate_2[0] + a;
			digest[1] = _prestate_2[1] + b;
			digest[2] = _prestate_2[2] + c;
			digest[3] = _prestate_2[3] + d;
			digest[4] = _prestate_2[4] + e;
			digest[5] = _prestate_2[5] + f;
			digest[6] = _prestate_2[6] + g;
			digest[7] = _prestate_2[7] + h;

			_temp[0] ^= digest[0];
			_temp[1] ^= digest[1];
			_temp[2] ^= digest[2];
			_temp[3] ^= digest[3];
			_temp[4] ^= digest[4];
			_temp[5] ^= digest[5];
			_temp[6] ^= digest[6];
			_temp[7] ^= digest[7];

			in[0] = digest[0];
			in[1] = digest[1];
			in[2] = digest[2];
			in[3] = digest[3];
			in[4] = digest[4];
			in[5] = digest[5];
			in[6] = digest[6];
			in[7] = digest[7];
		*/

		"add.u64			%16, %8, a;			\n\t"
		"add.u64			%17, %9, b;			\n\t"
		"add.u64			%18, %10, c;			\n\t"
		"add.u64			%19, %11, d;			\n\t"
		"add.u64			%20, %12, e;			\n\t"
		"add.u64			%21, %13, f;			\n\t"
		"add.u64			%22, %14, g;			\n\t"
		"add.u64			%23, %15, h;			\n\t"

		"xor.b64			%32, %32, %16;			\n\t"
		"xor.b64			%33, %33, %17;			\n\t"
		"xor.b64			%34, %34, %18;			\n\t"
		"xor.b64			%35, %35, %19;			\n\t"
		"xor.b64			%36, %36, %20;			\n\t"
		"xor.b64			%37, %37, %21;			\n\t"
		"xor.b64			%38, %38, %22;			\n\t"
		"xor.b64			%39, %39, %23;			\n\t"

		"mov.u64			%24, %16;			\n\t"
		"mov.u64			%25, %17;			\n\t"
		"mov.u64			%26,%18;			\n\t"
		"mov.u64			%27,%19;			\n\t"
		"mov.u64			%28,%20;			\n\t"
		"mov.u64			%29,%21;			\n\t"
		"mov.u64			%30,%22;			\n\t"
		"mov.u64			%31,%23;			\n\t"

		"}"
		:"+l"(_prestate_1[0]), "+l"(_prestate_1[1]), "+l"(_prestate_1[2]), "+l"(_prestate_1[3]), "+l"(_prestate_1[4]), "+l"(_prestate_1[5]), "+l"(_prestate_1[6]), "+l"(_prestate_1[7]),
		"+l"(_prestate_2[0]), "+l"(_prestate_2[1]), "+l"(_prestate_2[2]), "+l"(_prestate_2[3]), "+l"(_prestate_2[4]), "+l"(_prestate_2[5]), "+l"(_prestate_2[6]), "+l"(_prestate_2[7]),
		"+l"(digest[0]), "+l"(digest[1]), "+l"(digest[2]), "+l"(digest[3]), "+l"(digest[4]), "+l"(digest[5]), "+l"(digest[6]), "+l"(digest[7]),
		"+l"(in[0]), "+l"(in[1]), "+l"(in[2]), "+l"(in[3]), "+l"(in[4]), "+l"(in[5]), "+l"(in[6]), "+l"(in[7]),
		"+l"(_temp[0]), "+l"(_temp[1]), "+l"(_temp[2]), "+l"(_temp[3]), "+l"(_temp[4]), "+l"(_temp[5]), "+l"(_temp[6]), "+l"(_temp[7])
	);
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
	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);

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