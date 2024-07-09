#include "sha512.cuh"

__constant__ ST_UNDWORD K_SHA512_GPU[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

const ST_UNDWORD K_SHA512_CPU[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define ROTL64(x, n)			(((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n)			(((x) >> (n)) | ((x) << (64 - (n))))
#define	SF(x, n)				(x >> (n))

//THETA
#define WE0_512(x)				(ROTR64(x,  1) ^ ROTR64(x, 8) ^ SF(x, 7))
#define WE1_512(x)				(ROTR64(x,  19) ^ ROTR64(x, 61) ^ SF(x, 6))

//SIGMA
#define BS0_512(x)				((ROTR64(x,  28)) ^ ROTR64(x, 34) ^ ROTR64(x,  39))
#define BS1_512(x)				(ROTR64(x,  14) ^ ROTR64(x, 18) ^ ROTR64(x,  41))

//OPERATOR
#define CH(x, y, z)			((x & y) ^ (~(x) & (z)))
#define MAJ(x, y, z)		(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_F0(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA512_F1(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))
//ENDIAN
#define ENDIAN_CHANGE(val)	(\
(((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
(((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
(((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
(((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000))

//CORE OPERATION
#define SHA512_STEP(F0, F1, a, b, c ,d ,e ,f ,g ,h, x, K)	\
{															\
	h += K;													\
	h += x;													\
	h += BS1_512(e);										\
	h += F0(e, f, g);										\
	d += h;													\
	h += BS0_512(a);										\
	h += F1(a, b, c);										\
}

//Word Expansion
#define SHA512_EXPAND(x, y, z ,w) (WE1_512(x) + y + WE0_512(z) + w)

__host__ __device__ void ST_Process_SHA512(ST_UNDWORD* H, const ST_UNDWORD* input)
{
	ST_UNDWORD w0_t = input[0];
	ST_UNDWORD w1_t = input[1];
	ST_UNDWORD w2_t = input[2];
	ST_UNDWORD w3_t = input[3];
	ST_UNDWORD w4_t = input[4];
	ST_UNDWORD w5_t = input[5];
	ST_UNDWORD w6_t = input[6];
	ST_UNDWORD w7_t = input[7];
	ST_UNDWORD w8_t = input[8];
	ST_UNDWORD w9_t = input[9];
	ST_UNDWORD wa_t = input[10];
	ST_UNDWORD wb_t = input[11];
	ST_UNDWORD wc_t = input[12];
	ST_UNDWORD wd_t = input[13];
	ST_UNDWORD we_t = input[14];
	ST_UNDWORD wf_t = input[15];
	ST_UNDWORD a, b, c, d, e, f, g, h = 0;

	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

//#define ROUND_EXPAND()										\
//	{														\
//		w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
//		w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
//		w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
//		w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
//		w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
//		w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
//		w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
//		w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
//		w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
//		w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
//		wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
//		wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
//		wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
//		wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
//		we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
//		wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
//	}
//#ifdef __CUDA_ARCH__
//#define ROUND_STEP(i)																			\
//	{																							\
//		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, K_SHA512_GPU[i +  0]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, K_SHA512_GPU[i +  1]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, K_SHA512_GPU[i +  2]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, w3_t, K_SHA512_GPU[i +  3]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, w4_t, K_SHA512_GPU[i +  4]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, w5_t, K_SHA512_GPU[i +  5]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, K_SHA512_GPU[i +  6]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, K_SHA512_GPU[i +  7]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, K_SHA512_GPU[i +  8]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, K_SHA512_GPU[i +  9]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, K_SHA512_GPU[i + 10]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, wb_t, K_SHA512_GPU[i + 11]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, wc_t, K_SHA512_GPU[i + 12]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, wd_t, K_SHA512_GPU[i + 13]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, K_SHA512_GPU[i + 14]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, K_SHA512_GPU[i + 15]);	\
//	}
//#else
//#define ROUND_STEP(i)																			\
//	{																							\
//		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, K_SHA512_CPU[i +  0]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, K_SHA512_CPU[i +  1]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, K_SHA512_CPU[i +  2]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, w3_t, K_SHA512_CPU[i +  3]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, w4_t, K_SHA512_CPU[i +  4]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, w5_t, K_SHA512_CPU[i +  5]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, K_SHA512_CPU[i +  6]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, K_SHA512_CPU[i +  7]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, K_SHA512_CPU[i +  8]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, K_SHA512_CPU[i +  9]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, K_SHA512_CPU[i + 10]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, wb_t, K_SHA512_CPU[i + 11]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, wc_t, K_SHA512_CPU[i + 12]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, wd_t, K_SHA512_CPU[i + 13]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, K_SHA512_CPU[i + 14]);	\
//		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, K_SHA512_CPU[i + 15]);	\
//	}
//#endif
//
//	ROUND_STEP(0);
//	for (int i = 16; i < 80; i += 16) {
//		ROUND_EXPAND();
//		ROUND_STEP(i);
//	}
//	H[0] += a;
//	H[1] += b;
//	H[2] += c;
//	H[3] += d;
//	H[4] += e;
//	H[5] += f;
//	H[6] += g;
//	H[7] += h;
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

	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;
}

__host__ __device__ void st_sha512(ST_UNDWORD* output, const ST_UNDWORD* input, const ST_SNINT m_length)
{
	ST_SNWORD i = 0, j = 0;
	ST_SNINT tmp_len = 0, tmp_q = 0, tmp_r = 0;
	ST_UNDWORD pad = 0x8000000000000000;
	ST_UNDWORD buf[ST_HASH_SHA512_BUFFER_LENGTH] = { 0, };
	ST_UNDWORD h[8] =
	{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	};

	tmp_len = m_length;
	tmp_q = tmp_len / 8;
	tmp_r = tmp_len % 8;
	for (i = 0; i < tmp_q; i++)
	{
		buf[i] = input[i];
	}
	if (tmp_r > 0)
		buf[i] = input[i] + (pad >> (8 * (tmp_len % 8)));
	else
		buf[i] = pad;

	buf[ST_HASH_SHA512_BUFFER_LENGTH - 1] = m_length * 8;
	ST_Process_SHA512(h, buf);
	for (i = 0; i < ST_HASH_SHA512_OUTPUT_LENGTH; i++)
	{
		*(output + i) = *(h + i);
	}
}

__host__ __device__ void _iternal_st_sha512(ST_UNDWORD* output, const ST_UNDWORD* input)
{
	ST_SNWORD i = 0, j = 0;
	ST_SNINT tmp_len = 0;
	ST_UNDWORD buf[ST_HASH_SHA512_BUFFER_LENGTH] = { 0, };
	ST_UNDWORD h[8] =
	{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	};

	for (i = 0; i < 9; i++)
	{
		buf[i] = input[i];
	}

	buf[ST_HASH_SHA512_BUFFER_LENGTH - 1] = 544;
	ST_Process_SHA512(h, buf);
	for (i = 0; i < ST_HASH_SHA512_OUTPUT_LENGTH; i++)
	{
		*(output + i) = *(h + i);
	}
}

__host__ __device__ void _iternal_st_sha512_32(ST_UNWORD* output, const ST_UNWORD* input)
{
	ST_SNWORD i = 0, j = 0;
	ST_SNINT tmp_len = 0;
	ST_UNDWORD buf[ST_HASH_SHA512_BUFFER_LENGTH] = { 0, };
	ST_UNDWORD h[8] =
	{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	};

	for (i = 0; i < 9; i++)
	{
		buf[i] = (((ST_UNDWORD)input[(2 * i)] << 32) | (input[(2 * i) + 1]));
	}

	buf[ST_HASH_SHA512_BUFFER_LENGTH - 1] = 544;
	ST_Process_SHA512(h, buf);
	for (i = 0; i < ST_HASH_SHA512_OUTPUT_LENGTH; i++)
	{
		*(output + 2 * i) = (ST_UNDWORD)(*(h + i) >> 32);
		*(output + 2 * i + 1) = (ST_UNDWORD)(*(h + i) & 0xffffffff);
	}
}

__host__ __device__ void st_sha512_32(ST_UNWORD* output, const ST_UNWORD* input, const ST_SNINT m_length)
{
	ST_SNWORD i = 0, j = 0;
	ST_SNINT tmp_len = 0, tmp_q = 0, tmp_r = 0;
	ST_UNDWORD pad = 0x8000000000000000;
	ST_UNDWORD buf[ST_HASH_SHA512_BUFFER_LENGTH] = { 0, };
	ST_UNDWORD h[8] =
	{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	};

	tmp_len = m_length;
	tmp_q = tmp_len / 8;
	tmp_r = tmp_len % 8;

	for (i = 0; i < tmp_q; i++)
	{
		buf[i] = (((ST_UNDWORD)input[(2 * i)] << 32) | (input[(2 * i) + 1]));
	}

	if (tmp_r > 0)
		buf[i] = (((ST_UNDWORD)input[(2 * i)] << 32 | input[(2 * i) + 1])) + (pad >> (8 * (tmp_len % 8)));
	else
		buf[i] = pad;

	buf[ST_HASH_SHA512_BUFFER_LENGTH - 1] = m_length * 8;
	ST_Process_SHA512(h, buf);
	for (i = 0; i < ST_HASH_SHA512_OUTPUT_LENGTH; i++)
	{
		*(output + 2 * i) = (ST_UNDWORD)(*(h + i) >> 32);
		*(output + 2 * i + 1) = (ST_UNDWORD)(*(h + i) & 0xffffffff);
	}
}




void sha512_gpu_init()
{
	cudaMemcpyToSymbol(K_SHA512_GPU, K_SHA512_CPU, sizeof(ST_UNDWORD) * 80);
}