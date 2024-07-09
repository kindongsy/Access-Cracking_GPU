#include "office2013p_gpu.cuh"

//test salt
__constant__ uint8_t _test_salt[16] = {

};

__constant__ uint8_t _test_encryptedVerifierHashInput[MS_BlockSize] = {

};

__constant__ uint8_t _test_encryptedVerifierHashValue[MS_hashSize] = {

};

__constant__ uint8_t _test_password_library[32] = {

};

__global__ void office2013p_info_setting(struct MS13Info* d_encryptionInfo,
	char* d_keyDataCipherAlgorithm,	char* d_keyDataCipherChaining, char* d_keyDataHashAlgorithm,
	uint8_t* d_keyDataSaltValue, uint8_t* d_encryptedHmacKey, uint8_t* d_encryptedHmacValue,
	char* d_cipherAlgorithm, char* d_cipherChaining, char* d_hashAlgorithm, uint8_t* d_saltValue,
	uint8_t* d_encryptedVerifierHashInput, uint8_t* d_encryptedVerifierHashValue, uint8_t* d_encryptedKeyValue)
{
	d_encryptionInfo->encryptedKeyValue = d_encryptedKeyValue;
	d_encryptionInfo->encryptedVerifierHashValue = d_encryptedVerifierHashValue;
	d_encryptionInfo->encryptedVerifierHashInput = d_encryptedVerifierHashInput;
	d_encryptionInfo->saltValue = d_saltValue;
	d_encryptionInfo->hashAlgorithm = d_hashAlgorithm;
	d_encryptionInfo->cipherChaining = d_cipherChaining;
	d_encryptionInfo->cipherAlgorithm = d_cipherAlgorithm;
	d_encryptionInfo->encryptedHmacValue = d_encryptedHmacValue;
	d_encryptionInfo->encryptedHmacKey = d_encryptedHmacKey;
	d_encryptionInfo->keyDataSaltValue = d_keyDataSaltValue;
	d_encryptionInfo->keyDataHashAlgorithm = d_keyDataHashAlgorithm;
	d_encryptionInfo->keyDataCipherChaining = d_keyDataCipherChaining;
	d_encryptionInfo->keyDataCipherAlgorithm = d_keyDataCipherAlgorithm;

#if CRACK_MODE == DEBUG
	int i;

	// keyDataSaltValue
	printf("keyDataSalt (Size = %d)\n", d_encryptionInfo->keyDataSaltSize);
	for (i = 0; i < d_encryptionInfo->keyDataSaltSize; i++)
	{
		printf("%x ", d_encryptionInfo->keyDataSaltValue[i]);
	} printf("\n\n");
#else
	// TODO
#endif

	return;
}

#define PASS_INPUTLEN_3	3
__shared__ uint32_t input_3[2 * PASS_INPUTLEN_3 * 256];

__device__ void pbkdf_test_first(uint64_t* hash, uint64_t* password, int pSize)
{
	uint32_t i;
	//uint32_t input[2 * PASS_INPUTLEN * 256] = { 0x00, };

	uint32_t tmp;

	input_3[0 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = ((uint32_t)_test_salt[0] << 24) | (_test_salt[1] << 16) | (_test_salt[2] << 8) | _test_salt[3];
	input_3[1 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = ((uint32_t)_test_salt[4] << 24) | (_test_salt[5] << 16) | (_test_salt[6] << 8) | _test_salt[7];
	input_3[2 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = ((uint32_t)_test_salt[8] << 24) | (_test_salt[9] << 16) | (_test_salt[10] << 8) | _test_salt[11];
	input_3[3 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = ((uint32_t)_test_salt[12] << 24) | (_test_salt[13] << 16) | (_test_salt[14] << 8) | _test_salt[15];
	input_3[(PASS_INPUTLEN_3 << 1) + (PASS_INPUTLEN_3 << 1) * threadIdx.x] = 0xffffffff;


	for (i = 0; i < pSize; i++) {
		input_3[4 + (2 * i) + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (uint32_t)(password[(2 * i)] >> 32);
		input_3[5 + (2 * i) + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = password[(2 * i)] & 0xffffffff;
	}

	st_sha512_32(input_3 + 2 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x, input_3 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x, 16 + pSize);

	for (i = 0; i < 100000; i++) {

		input_3[1 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = ((((i & 0xff) << 8) | ((i >> 8) & 0xff)) << 16) | ((i >> 8) & 0xff00) | ((i >> 24) & 0xff);

		input_3[0 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[1 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[1 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[2 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[2 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[3 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[3 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[4 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[4 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[5 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[5 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[6 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[6 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[7 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[7 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[8 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[8 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[9 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[9 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[10 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[10 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[11 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[11 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[12 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[12 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[13 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[13 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[14 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[14 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[15 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[15 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[16 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);

		input_3[16 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = (input_3[17 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
		input_3[17 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] = 0x80000000;

		_iternal_st_sha512_32(input_3 + 2 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x, input_3 + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x);
	}

	for (int i = 0; i < 8; i++) {
		hash[i] = ((uint64_t)input_3[2 * (i + 1) + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x] << 32) | (input_3[1 + 2 * (i + 1) + ((PASS_INPUTLEN_3 << 1) + 1) * threadIdx.x]);
	}
}

__device__ void pbkdf_test(uint64_t* hash, uint64_t* password, int pSize)
{
	int i;

	uint64_t input[PASS_INPUTLEN] = { 0, };
	uint32_t tmp;
	uint64_t tmp64[16];

	for (i = 0; i < 16; i++) {
		tmp64[i] = _test_salt[i];
	}

	input[0] = (tmp64[0] << 56) | (tmp64[1] << 48) | (tmp64[2] << 40) | (tmp64[3] << 32) |
		(tmp64[4] << 24) | (tmp64[5] << 16) | (tmp64[6] << 8) | (tmp64[7]);
	input[1] = (tmp64[8] << 56) | (tmp64[9] << 48) | (tmp64[10] << 40) | (tmp64[11] << 32) |
		(tmp64[12] << 24) | (tmp64[13] << 16) | (tmp64[14] << 8) | (tmp64[15]);

	for (i = 0; i < pSize; i++)
		input[2 + i] = password[i];

	st_sha512(input + 1, input, 16 + pSize);

	for (i = 0; i < 100000; i++) {

		tmp = (i << 24) | ((i & 0xFF00) << 8) | ((i & 0xFF0000) >> 8) | (i >> 24);

		input[0] = tmp;

		for (int i = 0; i < 8; i++) {
			input[i] = (input[i] << 32) | (input[i + 1] >> 32);
		}

		input[8] = (input[8] << 32);
		input[8] = input[8] | (0x0000000080000000);

		_iternal_st_sha512(input + 1, input);
	}

	for (int i = 0; i < 8; i++) {
		hash[i] = input[i + 1];
	}
}

__device__ int password_verification_test(uint64_t* hash)
{
	int i;

	uint64_t blockKey1 = 0xFEA7D2763B4B9E79;
	uint64_t blockKey2 = 0xD7AA0F6D3061344E;

	uint64_t hash_final_1[8] = { 0 };
	uint64_t hash_final_2[8] = { 0 };
	uint64_t tmp1[9] = { 0 };
	uint64_t tmp2[9] = { 0 };
	uint64_t decrypted[2] = { 0 };
	uint64_t derived_hash[8] = { 0 };
	uint64_t expected_hash[8] = { 0 };

	uint8_t dec_input[64] = { 0 };
	uint8_t dec_key[32] = { 0 };
	uint8_t dec_iv[16] = { 0 };
	uint8_t tmp[64] = { 0 };
	uint64_t temp[64] = { 0 };
	int j = 7;
	int hash_size = 0;
	

	//1. encryptedVerifierHashInput
	for (i = 0; i < MS_hashSize / sizeof(uint64_t); i++)
	{
		tmp1[i] = hash[i];
	}

	tmp1[8] = blockKey1;

	hash_size = MS_hashSize + 8;

	st_sha512(hash_final_1, tmp1, hash_size);


	//plaintext - encryptedVerifierHashInput
	for (i = 0; i < MS_BlockSize; i++)
	{
		dec_input[i] = _test_encryptedVerifierHashInput[i];
	}


	//iv -salt
	for (i = 0; i < MS_saltSize; i++)
	{
		dec_iv[i] = _test_salt[i];
	}


	//key - hash_final_1
	hash_size = MS_keyBits / 8;
	for (i = 0; i < hash_size / sizeof(uint64_t); i++)
	{
		tmp[(i * 8) + 0] = hash_final_1[i] & 0xff;
		tmp[(i * 8) + 1] = (hash_final_1[i] >> 8) & 0xff;
		tmp[(i * 8) + 2] = (hash_final_1[i] >> 16) & 0xff;
		tmp[(i * 8) + 3] = (hash_final_1[i] >> 24) & 0xff;
		tmp[(i * 8) + 4] = (hash_final_1[i] >> 32) & 0xff;
		tmp[(i * 8) + 5] = (hash_final_1[i] >> 40) & 0xff;
		tmp[(i * 8) + 6] = (hash_final_1[i] >> 48) & 0xff;
		tmp[(i * 8) + 7] = (hash_final_1[i] >> 56) & 0xff;
	}

	j = 7;
	for (i = 0; i < 8; i++) {
		dec_key[i] = tmp[j];
		dec_key[i + 8] = tmp[j + 8];
		dec_key[i + 16] = tmp[j + 16];
		dec_key[i + 24] = tmp[j + 24];
		j--;
	}

	AES_ctx ctx1[] = {
	{0},
	{0}
	};

	AES_init_ctx_iv(ctx1, dec_key, dec_iv);

	AES_CBC_decrypt_buffer(ctx1, dec_input, MS_BlockSize);

	for (int i = 0; i < 16; i++) {
		temp[i] = dec_input[i];
	}

	decrypted[0] = (temp[0] << 56) | (temp[1] << 48) | (temp[2] << 40) | (temp[3] << 32) |
		(temp[4] << 24) | (temp[5] << 16) | (temp[6] << 8) | (temp[7]);
	decrypted[1] = (temp[8] << 56) | (temp[9] << 48) | (temp[10] << 40) | (temp[11] << 32) |
		(temp[12] << 24) | (temp[13] << 16) | (temp[14] << 8) | (temp[15]);

	st_sha512(derived_hash, decrypted, MS_BlockSize);


	//2. encryptedVerifierHashValue
	for (i = 0; i < MS_hashSize / sizeof(uint64_t); i++)
	{
		tmp2[i] = hash[i];
	}

	tmp2[8] = blockKey2;

	hash_size = MS_hashSize + 8;

	st_sha512(hash_final_2, tmp2, hash_size);


	//plaintext - encryptedVerifierHashValue
	for (i = 0; i < MS_hashSize; i++)
	{
		dec_input[i] = _test_encryptedVerifierHashValue[i];
	}


	//iv -salt
	for (i = 0; i < MS_saltSize; i++)
	{
		dec_iv[i] =_test_salt[i];
	}


	//key - hash_final_2
	hash_size = MS_keyBits / 8;
	for (i = 0; i < hash_size / sizeof(uint64_t); i++)
	{
		tmp[(i * 8) + 0] = hash_final_2[i] & 0xff;
		tmp[(i * 8) + 1] = (hash_final_2[i] >> 8) & 0xff;
		tmp[(i * 8) + 2] = (hash_final_2[i] >> 16) & 0xff;
		tmp[(i * 8) + 3] = (hash_final_2[i] >> 24) & 0xff;
		tmp[(i * 8) + 4] = (hash_final_2[i] >> 32) & 0xff;
		tmp[(i * 8) + 5] = (hash_final_2[i] >> 40) & 0xff;
		tmp[(i * 8) + 6] = (hash_final_2[i] >> 48) & 0xff;
		tmp[(i * 8) + 7] = (hash_final_2[i] >> 56) & 0xff;
	}

	j = 7;
	for (i = 0; i < 8; i++) {
		dec_key[i] = tmp[j];
		dec_key[i + 8] = tmp[j + 8];
		dec_key[i + 16] = tmp[j + 16];
		dec_key[i + 24] = tmp[j + 24];
		j--;
	}

	AES_ctx ctx2[] = {
	{0},
	{0}
	};

	AES_init_ctx_iv(ctx2, dec_key, dec_iv);

	AES_CBC_decrypt_buffer(ctx2, dec_input, MS_hashSize);

	for (i = 0; i < 64; i++) {
		temp[i] = dec_input[i];
	}

	expected_hash[0] = (temp[0] << 56) | (temp[1] << 48) | (temp[2] << 40) | (temp[3] << 32) |
		(temp[4] << 24) | (temp[5] << 16) | (temp[6] << 8) | (temp[7]);
	expected_hash[1] = (temp[8] << 56) | (temp[9] << 48) | (temp[10] << 40) | (temp[11] << 32) |
		(temp[12] << 24) | (temp[13] << 16) | (temp[14] << 8) | (temp[15]);
	expected_hash[2] = (temp[16] << 56) | (temp[17] << 48) | (temp[18] << 40) | (temp[19] << 32) |
		(temp[20] << 24) | (temp[21] << 16) | (temp[22] << 8) | (temp[23]);
	expected_hash[3] = (temp[24] << 56) | (temp[25] << 48) | (temp[26] << 40) | (temp[27] << 32) |
		(temp[28] << 24) | (temp[29] << 16) | (temp[30] << 8) | (temp[31]);
	expected_hash[4] = (temp[32] << 56) | (temp[33] << 48) | (temp[34] << 40) | (temp[35] << 32) |
		(temp[36] << 24) | (temp[37] << 16) | (temp[38] << 8) | (temp[39]);
	expected_hash[5] = (temp[40] << 56) | (temp[41] << 48) | (temp[42] << 40) | (temp[43] << 32) |
		(temp[44] << 24) | (temp[45] << 16) | (temp[46] << 8) | (temp[47]);
	expected_hash[6] = (temp[48] << 56) | (temp[49] << 48) | (temp[50] << 40) | (temp[51] << 32) |
		(temp[52] << 24) | (temp[53] << 16) | (temp[54] << 8) | (temp[55]);
	expected_hash[7] = (temp[56] << 56) | (temp[57] << 48) | (temp[58] << 40) | (temp[59] << 32) |
		(temp[60] << 24) | (temp[61] << 16) | (temp[62] << 8) | (temp[63]);

	for (i = 0; i < 8; i++) {
		if (derived_hash[i] != expected_hash[i]) {
			return INVALID;
		}
	}

	return VALID;
}

__global__ void office2013p_brute_force_kernel_test_first_process(uint64_t* d_hash, uint64_t* d_password, int sid)
{
	uint64_t hash[8] = { 0x0, };
	uint64_t password[3] = { 0x0, };
	uint64_t count = 0;
	uint8_t flag = ((4 * sid + (2 * (blockIdx.x / 128)) + (threadIdx.x / 128))) - 1;
	password[0] |= (uint64_t)(flag) << 56;
	password[0] |= (uint64_t)(blockIdx.x % 128) << 40;
	password[0] |= (uint64_t)(threadIdx.x % 128) << 24;

	if (blockIdx.x  == 0) {
		count = 1 + 2 * (threadIdx.x / 128);
	}
	else {
		count = 2 + ((blockIdx.x / 128) | (threadIdx.x / 128));
	}
	pbkdf_test_first(hash, password, count * 2);

	if (password_verification_test(hash) == VALID) {
		int i;

		for (i = 0; i < PASS_ARRAYLEN; i++)
			d_password[i] = password[i];

		for (i = 0; i < 8; i++)
			d_hash[i] = hash[i];
	}

	return;
}
__global__ void office2013p_brute_force_kernel_test_other_process(uint64_t* d_hash, uint64_t* d_password, int sid, int pSize)
{
	uint64_t hash[8] = { 0x0, };
	uint64_t password[PASS_ARRAYLEN] = { 0x0, };
	uint8_t in[32] = { 0, };
	
	in[0] = threadIdx.x % 128;
	in[1] = blockIdx.x % 128;
	in[2] = 4 * sid + (2 * (blockIdx.x / 128)) + (threadIdx.x / 128);
	for (int i = 31; i >= 3; i--) {
		in[i] = _test_password_library[i];
	}

	for (int i = 0; i < 8; i++) {
		password[i] = ((uint64_t)in[pSize - 1 - (i*4)] << 56) | ((uint64_t)in[pSize - 2 - (i * 4)] << 40) | ((uint64_t)in[pSize - 3 - (i * 4)] << 24) | ((uint64_t)in[pSize - 4 - (i * 4)] << 8);
	}

	pbkdf_test(hash, password, pSize * 2);

	if (password_verification_test(hash) == VALID) {
		int i;


		for (i = 0; i < PASS_ARRAYLEN; i++)
			d_password[i] = password[i];

		for (i = 0; i < 8; i++)
			d_hash[i] = hash[i];
	}

	return;
}

int office2013p_brute_force_gpu_first(uint64_t* h_hash, uint64_t* h_password, uint64_t* d_hash, uint64_t* d_password)
{
#if CRACK_MODE == DEBUG
	int i;

	cudaStream_t s[NSTREAM];

	for (i = 0; i < NSTREAM; i++)
		cudaStreamCreate(&s[i]);

	for (i = 0; i < NSTREAM; i++) {
		office2013p_brute_force_kernel_test_first_process << < 256, 256, 0, s[i] >> > (d_hash, d_password, i);
	}
	for (i = 0; i < NSTREAM; i++)
		cudaMemcpyAsync(h_hash, d_hash, sizeof(uint64_t) * 8, cudaMemcpyDeviceToHost, s[i]);

	for (i = 0; i < NSTREAM; i++)
		cudaMemcpyAsync(h_password, d_password, sizeof(uint64_t) * PASS_ARRAYLEN, cudaMemcpyDeviceToHost, s[i]);

	for (i = 0; i < NSTREAM; i++)
		cudaStreamDestroy(s[i]);
#else
	// TODO
#endif
	cudaDeviceSynchronize();

	if (h_password[0] != 0) return VALID;
	else return INVALID;
}
int office2013p_brute_force_gpu_other(uint64_t* h_hash, uint64_t* h_password, uint64_t* d_hash, uint64_t* d_password, int passlen)
{
#if CRACK_MODE == DEBUG
	int i;
	
	cudaStream_t s[NSTREAM];

	for (i = 0; i < NSTREAM; i++)
		cudaStreamCreate(&s[i]);

	for (i = 0; i < NSTREAM; i++) {
		office2013p_brute_force_kernel_test_other_process << < 256, 256, 0, s[i] >> > (d_hash, d_password, i, passlen);
	}
	for (i = 0; i < NSTREAM; i++)
		cudaMemcpyAsync(h_hash, d_hash, sizeof(uint64_t) * 8, cudaMemcpyDeviceToHost, s[i]);

	for (i = 0; i < NSTREAM; i++)
		cudaMemcpyAsync(h_password, d_password, sizeof(uint64_t) * PASS_ARRAYLEN, cudaMemcpyDeviceToHost, s[i]);

	for (i = 0; i < NSTREAM; i++)
		cudaStreamDestroy(s[i]);
#else
	// TODO
#endif
	cudaDeviceSynchronize();

	if (h_password[0] != 0) return VALID;
	else return INVALID;
}

void in_increase(uint8_t* in, uint32_t pw_len) {

	uint8_t flag = 0;

	for (int i = 3; i < pw_len; i++) {
		flag = in[i] + 1;
		if (flag >= 128) {
			in[i] = 00;
			//in[i + 1] = in[i + 1] + 1;
		}
		else {
			in[i] = flag;
			break;
		}
	}
}



//pw_sym is not used
int msoffice13(uint8_t* hitted_pw, const int pw_len, const uint8_t* pw_start, const uint32_t pw_num, const uint32_t pw_sym, const MS13Info info) {

	uint32_t inner_pw_num = pw_num / (128 * 128 * 128);

	uint8_t* inner_pw_start = (uint8_t*)malloc(pw_len);

	for (int i = 0; i < pw_len; i++) {
		inner_pw_start[i] = pw_start[pw_len - i - 1];
	}
	

	//GPU Information
	uint8_t gpu_error = 0;
	printf("[Time stamp]\n");
	time_t timer = time(NULL);
	struct tm* t = localtime(&timer);
	printf("\n%04d.%02d.%02d, %02d:%02d:%02d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

	//
	printf("\n\n[GPU Specification]\n");
	cudaDeviceProp  prop;
	int count;
	cudaGetDeviceCount(&count);

	for (int i = 0; i < count; i++) {
		cudaGetDeviceProperties(&prop, i);

		printf("\nGPU Count : %d\n", i);
		printf("Name:  %s\n", prop.name);
		printf("Compute capability:  %d.%d\n", prop.major, prop.minor);
		printf("Clock rate:  %d\n", prop.clockRate);

		printf("\n");
	}

	//Loading

	//Caution : Compute Capabiltiy
	cudaSetDevice(0);

	cudaError_t cudaStatus;

	// encryption info
	struct MS13Info h_EncInfo;

	// cpu encryption info initialize
	InitializeEncryptionInfo(h_EncInfo);

	h_EncInfo.saltValue = (uint8_t*)malloc(16);
	for (int i = 0; i < 16; i++) {
		h_EncInfo.saltValue[i] = info.saltValue[i];
	}

	h_EncInfo.encryptedVerifierHashInput = (uint8_t*)malloc(16);
	for (int i = 0; i < 16; i++) {
		h_EncInfo.encryptedVerifierHashInput[i] = info.encryptedVerifierHashInput[i];
	}


	h_EncInfo.encryptedVerifierHashValue = (uint8_t*)malloc(64);
	for (int i = 0; i < 64; i++) {
		h_EncInfo.encryptedVerifierHashValue[i] = info.encryptedVerifierHashValue[i];
	}

	h_EncInfo.saltSize = info.saltSize;

	// cpu param
	uint64_t* h_hash, * h_password;

	// we use cudaHostAlloc instead for pinned memory
	gpu_error= CUDA_SAFE_CALL(cudaHostAlloc((void**)&h_hash, sizeof(uint64_t) * 8, cudaHostAllocDefault));
	gpu_error = CUDA_SAFE_CALL(cudaHostAlloc((void**)&h_password, sizeof(uint64_t) * PASS_ARRAYLEN, cudaHostAllocDefault));

	// gpu param
	uint64_t* d_hash, * d_password;
	gpu_error = CUDA_SAFE_CALL(cudaMalloc((void**)&d_hash, sizeof(uint64_t) * 8));
	gpu_error = CUDA_SAFE_CALL(cudaMalloc((void**)&d_password, sizeof(uint64_t) * PASS_ARRAYLEN));

	uint8_t* d_salt_test = NULL;
	gpu_error = CUDA_SAFE_CALL(cudaMalloc((void**)&d_salt_test, sizeof(uint8_t) * 16));
	cudaMemcpy(d_salt_test, h_EncInfo.saltValue, sizeof(uint8_t) * h_EncInfo.saltSize, cudaMemcpyHostToDevice);

	// gpu constant init
	sha512_gpu_init();
	aes256_gpu_init();

	//CPU EncInfo -> GPU constant Memory
	gpu_error = CUDA_SAFE_CALL(cudaMemcpyToSymbol(_test_salt, h_EncInfo.saltValue, sizeof(uint8_t) * MS_saltSize));
	gpu_error = CUDA_SAFE_CALL(cudaMemcpyToSymbol(_test_encryptedVerifierHashValue, h_EncInfo.encryptedVerifierHashValue, sizeof(uint8_t) * MS_hashSize));
	gpu_error = CUDA_SAFE_CALL(cudaMemcpyToSymbol(_test_encryptedVerifierHashInput, h_EncInfo.encryptedVerifierHashInput, sizeof(uint8_t) * MS_BlockSize));

	// offset
	uint64_t offset = 0;
	cudaEvent_t start, end;
	float elapsed = 0;
	uint8_t flag = 0;
	cudaEventCreate(&start);
	cudaEventCreate(&end);

	if (pw_len <= 3) {
		// performance
		cudaEventRecord(start);
		flag = office2013p_brute_force_gpu_first(h_hash, h_password, d_hash, d_password);
		cudaEventRecord(end);
		cudaEventSynchronize(end);
		cudaEventElapsedTime(&elapsed, start, end);
		printf("offset = %llu, time = %f, speed = %f\n", PROC_SIZE, elapsed, PROC_SIZE * 1000.0 / elapsed);

		if (flag == VALID) {
			//Code for data type conversion
			hitted_pw[0] = (uint8_t)(h_password[0] >> 56);
			hitted_pw[1] = (uint8_t)(h_password[0] >> 40);
			hitted_pw[2] = (uint8_t)(h_password[0] >> 24);

			printf("\n[SUCCESS!]\n");
			printf("Hitted Password : ");
			for (int i = 0; i < pw_len; i++) {
				printf("%02X ", hitted_pw[i]);
			}
			printf("\n");
		}
	}

	else {
		//CPU_in[3] = 0x38;
		//password_library_init

		uint8_t CPU_in[32] = { 0, };
		uint8_t CPU_out[32] = { 0, };
		int passlen = pw_len;
		memcpy(CPU_in, inner_pw_start, pw_len);
		gpu_error = CUDA_SAFE_CALL(cudaMemcpyToSymbol(_test_password_library, CPU_in, sizeof(uint8_t) * 32));

		for(int i =0; i< inner_pw_num;i++) {

			printf("\ninput password = ");
			for (int i = 0; i < pw_len; i++) {
				printf("%02X ", CPU_in[pw_len -i-1]);
			}
			printf("\n");

			startLoadingAnimation();

			cudaEventRecord(start);
			flag = office2013p_brute_force_gpu_other(h_hash, h_password, d_hash, d_password, passlen);
			cudaEventRecord(end);
			cudaEventSynchronize(end);
			cudaEventElapsedTime(&elapsed, start, end);
			printf("\ntime : %4.2f ms\n", elapsed);

			stopLoadingAnimation();

			printf("\n\noffset = %llu, time = %f, speed = %f\n", PROC_SIZE, elapsed, PROC_SIZE * 1000.0 / elapsed);

			if (flag == VALID) {
				//break;

				//Code for data type conversion
				for (int i = 0; i < (pw_len - 1); i++) {
					hitted_pw[4*i+0] = (uint8_t)(h_password[i+0] >> 56);
					hitted_pw[4*i+1] = (uint8_t)(h_password[i+0] >> 40);
					hitted_pw[4*i+2] = (uint8_t)(h_password[i+0] >> 24);
					hitted_pw[4*i+3] = (uint8_t)(h_password[i+0] >> 8);
				}

				printf("\n[SUCCESS!]\n");
				printf("Hitted Password : ");
				for (int i = 0; i < pw_len; i++) {
					printf("%02X ", hitted_pw[i]);
				}
				printf("\n");

				memcpy(CPU_out, CPU_in, pw_len);

				break;
			}

			flag = INVALID;
			memcpy(CPU_out, CPU_in, pw_len);

			in_increase(CPU_in, pw_len);
			gpu_error = CUDA_SAFE_CALL(cudaMemcpyToSymbol(_test_password_library, CPU_in, sizeof(uint8_t) * 32));
		}

		printf("\nlast password = ");
		for (int i = 0; i < pw_len; i++) {
			printf("%02X ", CPU_out[pw_len - i - 1]);
		}
		printf("\n");
		
	}
	cudaFreeHost(h_hash);
	cudaFreeHost(h_password);
	cudaFree(d_hash);
	cudaFree(d_password);

	stopLoadingAnimation();

	if (flag == VALID) {
		return PW_HIT;
	}
	else if (flag == INVALID) {
		return PW_DONE;
	}
	else if (gpu_error == -1) {
		return PW_ERR;
	}
	else {
		return PW_ERR;
	}
}

int main() {

	struct MS13Info input_info;
	InitializeEncryptionInfo(input_info);



	//pw = 1234
	//uint8_t encryptedVerifierHashInput[16] = { 0xfd, 0xc2, 0x5b, 0x35, 0x65, 0x31, 0x4b, 0x5c, 0x70, 0x88, 0xba, 0x95, 0xbe, 0x81, 0x84, 0x32 };
	//uint8_t encryptedVerifierHashValue[64] = { 0x2a, 0x39, 0xa8, 0xf8, 0x45, 0xea, 0x7f ,0xcd ,0x73, 0x42,0x06,0x66,0x3a,0x74,0xe7,0x4e,0x69,0x96,0xe9,0xdd,0xcd,0x54,0x7c,0xdf,0x3,0x56,0x1a,0x7a,0xc0,0x12,0xd3,0x3c,0x1a,0x4d,0x24,0xa1,0xde,0xad,0xe,0x36,0xf4,0x7e,0x4f,0x1f,0x7e,0xee,0x4c,0x55,0x54,0x6e,0x1f,0xbc,0x31,0x73,0x3d,0x98,0x83,0xdb,0x54,0xf3,0x9e,0x7b,0x0a,0x8b };
	//uint8_t saltValue[16] = { 0xa1,0x91,0xd9,0xfb,0x5e,0x83,0xa3,0x58,0x83,0xe0,0x54,0xbb,0x62,0x23,0x5d,0xec };

	//pw = 123456
	//uint8_t encryptedVerifierHashInput[16] = { 0xd9, 0x8d , 0xd0 , 0x49 , 0x68 , 0x8d , 0x76 , 0x41 , 0x93 , 0x71 , 0x6d , 0x24 , 0x93 , 0x97 , 0x5e , 0x1b };
	//uint8_t encryptedVerifierHashValue[64] = { 0xe5, 0xc6 , 0x7e , 0xf6 , 0x0a , 0x24, 0x2d , 0x1d , 0x3f , 0x1b , 0xeb , 0x64 , 0xdb , 0x46 , 0xfb , 0x5a , 0xc7 , 0x96 , 0x4d , 0x50 , 0xac , 0xb9 , 0x6f , 0x50 , 0xed , 0x9a , 0x62 , 0x9b , 0x5e , 0x37 , 0xc4 , 0xaf , 0xb7 , 0x2b , 0xce , 0x4a , 0xbe , 0x1d , 0x86 , 0xa2 , 0x82 , 0xe4 , 0x75 , 0x5f , 0x84 , 0x62 , 0xc2 , 0x2b , 0x43 , 0xca , 0x87 , 0x3b , 0x1c , 0x24 , 0x65 , 0x15 , 0x0d , 0xa6 , 0x88 , 0x9b , 0x80 , 0x74 , 0x96 , 0x07};
	//uint8_t saltValue[16] = { 0xf8 , 0x2f , 0x6e , 0x64 , 0xdd , 0x35 , 0x3b , 0x6f , 0xa8 , 0x90 , 0x8a , 0x82 , 0x3e , 0x73 , 0xe1 , 0x64 };


	/*
	saltvalue : 0x2E, 0x8B, 0x8A, 0x92, 0xDA, 0x74, 0xE8, 0xE8, 0xBF, 0xA8, 0x70, 0xCB, 0x23, 0x67, 0xE7, 0x9A

	encryptedVerifierHashValue : 0x90, 0x86, 0x82, 0x38, 0x3A, 0xB8, 0x20, 0xEF, 0xE9, 0x14, 0x26, 0xFD, 0xBF, 0x7A, 0x7E, 0xA4, 0x1C, 0xC2, 0x0B, 0x1E, 0x50, 0x86, 0xEA, 0xEC, 0xB4, 0xA7, 0x9F, 0x08, 0x30, 0x40, 0x21, 0xDE, 0xD3, 0xC8, 0x6D, 0x85, 0x1E, 0x14, 0x0C, 0x75, 0x7B, 0x73, 0x73, 0xA6, 0xD4, 0x4C, 0xAA, 0x6E, 0x3E, 0xAA, 0xC2, 0x1F, 0xAC, 0x43, 0xE3, 0x08, 0xEA, 0xDA, 0xB9, 0x7F, 0x42, 0xD1, 0xE6, 0x56


	encryptedVerifierHashInput : 0x93, 0xE8, 0xBF, 0x84, 0x1E, 0x65, 0x83, 0xDF, 0x55, 0xB2, 0xF4, 0xC0, 0x78, 0x35, 0xA1, 0xF8
	
	*/
	//pw = 12345678912
	uint8_t encryptedVerifierHashInput[16] = { 0x93, 0xE8, 0xBF, 0x84, 0x1E, 0x65, 0x83, 0xDF, 0x55, 0xB2, 0xF4, 0xC0, 0x78, 0x35, 0xA1, 0xF8 };
	uint8_t encryptedVerifierHashValue[64] = { 0x90, 0x86, 0x82, 0x38, 0x3A, 0xB8, 0x20, 0xEF, 0xE9, 0x14, 0x26, 0xFD, 0xBF, 0x7A, 0x7E, 0xA4, 0x1C, 0xC2, 0x0B, 0x1E, 0x50, 0x86, 0xEA, 0xEC, 0xB4, 0xA7, 0x9F, 0x08, 0x30, 0x40, 0x21, 0xDE, 0xD3, 0xC8, 0x6D, 0x85, 0x1E, 0x14, 0x0C, 0x75, 0x7B, 0x73, 0x73, 0xA6, 0xD4, 0x4C, 0xAA, 0x6E, 0x3E, 0xAA, 0xC2, 0x1F, 0xAC, 0x43, 0xE3, 0x08, 0xEA, 0xDA, 0xB9, 0x7F, 0x42, 0xD1, 0xE6, 0x56 };
	uint8_t saltValue[16] = { 0x2E, 0x8B, 0x8A, 0x92, 0xDA, 0x74, 0xE8, 0xE8, 0xBF, 0xA8, 0x70, 0xCB, 0x23, 0x67, 0xE7, 0x9A };


	input_info.encryptedVerifierHashInput = (uint8_t*)malloc(16);

	for (int i = 0; i < 16; i++) {
		input_info.encryptedVerifierHashInput[i] = encryptedVerifierHashInput[i];
	}

	input_info.encryptedVerifierHashValue = (uint8_t*)malloc(64);

	for (int i = 0; i < 64; i++) {
		input_info.encryptedVerifierHashValue[i] = encryptedVerifierHashValue[i];
	}

	input_info.saltValue = (uint8_t*)malloc(16);

	for (int i = 0; i < 16; i++) {
		input_info.saltValue[i] = saltValue[i];
	}

	input_info.saltSize = 16;

	int pw_len = 11;
	uint8_t pw_start[11] = { 0x31, 0x32,0x33,0x34,0x35,0x36,0x37,0x37,0,0,0 };
	uint32_t pw_num = 128*128*128*3;	//2097152 * 2
	uint32_t pw_sym = 0;		//pw_sym is not used
	uint8_t hitted_pw[11] = { 0x00, };

	msoffice13(hitted_pw,pw_len,pw_start,pw_num,pw_sym,input_info);

	printf("\nhitted_pw = ");
	for (int i = 0; i < 11; i++) {
		printf("%02X ", hitted_pw[i]);
	}
	printf("\n");

}