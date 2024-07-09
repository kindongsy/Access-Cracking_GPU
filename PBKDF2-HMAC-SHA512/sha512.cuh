#include "type.cuh"
#include "./ui/StarPrinter.cuh"

//
#define ROTL64(x, n)			(((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n)			(((x) >> (n)) | ((x) << (64 - (n))))
#define	SF(x, n)				(x >> (n))
#define SHA512_BLOCK	128
#define SHA512_DIGEST	64
//THETA
#define WE0_512(x)				(ROTR64(x,  1) ^ ROTR64(x, 8) ^ SF(x, 7))		//소시그마0
#define WE1_512(x)				(ROTR64(x,  19) ^ ROTR64(x, 61) ^ SF(x, 6))		//소시그마1

//SIGMA
#define BS0_512(x)				((ROTR64(x,  28)) ^ ROTR64(x, 34) ^ ROTR64(x,  39))		//큰시그마0
#define BS1_512(x)				(ROTR64(x,  14) ^ ROTR64(x, 18) ^ ROTR64(x,  41))		//큰시그마1

//OPERATOR
#define SHA512_F0(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA512_F1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define hc_add3(a, b, c) (a + b + c)

//ENDIAN
#define ENDIAN_CHANGE64(val)	(\
(((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
(((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
(((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
(((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000))

//CORE OPERATION
#define SHA512_STEP(F0, F1, a, b, c ,d ,e ,f ,g ,h, x, K)	\
{															\
	h = hc_add3(h, K, x);									\
	h = hc_add3(h, BS1_512(e), F1(e, f, g));				\
	d += h;													\
	h = hc_add3(h, BS0_512(a), F0(a, b, c));				\
}

//#define BS0_512(x)				((ROTR64(x,  28)) ^ ROTR64(x, 34) ^ ROTR64(x,  39))
//#define BS1_512(x)				(ROTR64(x,  14) ^ ROTR64(x, 18) ^ ROTR64(x,  41))
//#define ROTL64(x, n)			(((x) << (n)) | ((x) >> (64 - (n))))
//#define ROTR64(x, n)			(((x) >> (n)) | ((x) << (64 - (n))))
//#define SHA512_F0(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))
//#define SHA512_F1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

//#define SHA512_STEP(a, b, c ,d ,e ,f ,g ,h, x, K)	\
//{													\
//	d += h+K+x+(ROTR64(e,  14) ^ ROTR64(e, 18) ^ ROTR64(e,  41))+(g ^ (e & (f ^ g)));													\
//	h = h+K+x+(ROTR64(e,  14) ^ ROTR64(e, 18) ^ ROTR64(e,  41))+(g ^ (e & (f ^ g)))+((ROTR64(a,  28)) ^ ROTR64(a, 34) ^ ROTR64(a,  39))+((a & b) | (c & (a ^ b)));				\
//}

//structure
typedef struct {
	uint64_t digest[8];
	uint64_t ptLen;
	uint64_t lastLen;
	uint8_t BUF[SHA512_BLOCK];
}SHA512_INFO;

typedef struct {
	uint64_t IPAD[8];
	uint64_t OPAD[8];
	uint64_t ptLen;
}PBKDF2_HMAC_SHA512_INFO;

//Word Expansion
#define SHA512_EXPAND(x, y, z ,w) (WE1_512(x) + y + WE0_512(z) + w)

//Function Part
__global__ void PBKDF2_HMAC_SHA512_testVector_Check_Function();
void GPU_PBKDF2_SHA512_performance_analysis(uint64_t Blocksize, uint64_t Threadsize);
void PBKDF2_HMAC_SHA512_coalesed_test(uint64_t block_size, uint64_t thread_size);
