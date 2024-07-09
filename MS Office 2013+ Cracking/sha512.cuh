#ifndef _st_sha512_H_
#define _st_sha512_H_

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

// Data type
typedef unsigned long long	ST_UNDWORD;
typedef unsigned int		ST_UNWORD;
typedef signed int			ST_SNWORD;
typedef unsigned char		ST_UNBYTE;
typedef signed char		    ST_SNBYTE;

// Number type
typedef unsigned long long	ST_UNLONGLONG;
typedef unsigned int		ST_UNINT;
typedef signed int			ST_SNINT;
typedef unsigned char		ST_UNCHAR;
typedef signed char		    ST_SNCHAR;

// Return Value
typedef unsigned int		ST_RV;

#define ST_HASH_INPUT_LEN_MAX_SIZE_BYTE			2305843009213693952ull
#define ST_HASH_SHA512_OUTPUT_LEN_SIZE_BYTE		64
#define ST_HASH_SHA256_OUTPUT_LEN_SIZE_BYTE		32

#define ST_HASH_INIT_OK							0x01
#define ST_HASH_FROM_SELFTEST						0x02

#define SHA_INPUT_MIN_LEN_BYTE					0

#define SET_ZERO_ST_HASH_SHA256_VAR(A) { A.hash_sha256_input=NULL; A.hash_input_len_byte=0; \
	A.hash_sha256_output = NULL; A.hash_output_len_byte = 0; A.st_hash_state = 0;}
#define SET_ZERO_ST_HASH_SHA512_VAR(A) { A.hash_sha512_input=NULL; A.hash_input_len_byte=0; \
	A.hash_sha512_output = NULL; A.hash_output_len_byte = 0; A.st_hash_state = 0;}

typedef struct _ST_SHA256_INF
{
	ST_UNWORD* hash_sha256_input;
	ST_UNLONGLONG    hash_input_len_byte;
	ST_UNWORD* hash_sha256_output;
	ST_SNINT hash_output_len_byte;
	ST_UNWORD st_hash_state;
} ST_SHA256_INF;

typedef struct _ST_SHA512_INF
{
	ST_UNDWORD* hash_sha512_input;
	ST_UNLONGLONG    hash_input_len_byte;
	ST_UNDWORD* hash_sha512_output;
	ST_SNINT hash_output_len_byte;
	ST_UNWORD st_hash_state;
} ST_SHA512_INF;

// SHA512's macro
#define ST_HASH_SHA512_ROUNDNUM 80
#define ST_HASH_SHA512_BYTE_BLOCKSIZE 128
#define ST_HASH_SHA512_BYTE_BLOCKBORDER 111
#define ST_HASH_SHA512_BUFFER_LENGTH 16
#define ST_HASH_SHA512_OUTPUT_LENGTH 8

#define ST_MAC_KEY_3				0x5AA07A47 

#define ST_WRS_SHA512(x, n) (((x) >> (n)) | ((x) << (64-n)))
#define ST_LSIG0_SHA512(x) (ST_WRS_SHA512(x, 28) ^ ST_WRS_SHA512(x, 34) ^ ST_WRS_SHA512(x, 39))
#define ST_LSIG1_SHA512(x) (ST_WRS_SHA512(x, 14) ^ ST_WRS_SHA512(x, 18) ^ ST_WRS_SHA512(x, 41))
#define ST_SSIG0_SHA512(x) (ST_WRS_SHA512(x, 1) ^ ST_WRS_SHA512(x, 8) ^ (x >> 7))
#define ST_SSIG1_SHA512(x) (ST_WRS_SHA512(x, 19) ^ ST_WRS_SHA512(x, 61) ^ (x >> 6))
#define ST_CH_SHA512(e, f, g) ((e & f) ^ (~e & g))
#define ST_MAJ_SHA512(a, b, c) ((a & b) ^ (a & c) ^ (b & c))
#define ST_NW_SHA512(W,i) (W[(i-16)] + ST_SSIG0_SHA512(W[(i-15)]) + W[(i-7)] + ST_SSIG1_SHA512(W[(i-2)]))
#define ST_RoundFunction_SHA512(W, K, T, A, B, C, D, E, F, G, H)	\
{	\
	T1 = (H + ST_CH_SHA512(E, F, G) + ST_LSIG1_SHA512(E) + W[T] + K[T]);	\
	T2 = (ST_LSIG0_SHA512(A) + ST_MAJ_SHA512(A, B, C));	\
	H = G;	G = F;	F = E;	E = (D + T1);	D = C;	C = B;	B = A;	A = (T1 + T2);	\
}

__host__ __device__ void ST_Process_SHA512(ST_UNDWORD* H, const ST_UNDWORD* input);
__host__ __device__ void st_sha512(ST_UNDWORD* output, const ST_UNDWORD* input, const ST_SNINT m_length);
__host__ __device__ void _iternal_st_sha512(ST_UNDWORD* output, const ST_UNDWORD* input);
__host__ __device__ void _iternal_st_sha512_32(ST_UNWORD* output, const ST_UNWORD* input);
__host__ __device__ void st_sha512_32(ST_UNWORD* output, const ST_UNWORD* input, const ST_SNINT m_length);
#endif
