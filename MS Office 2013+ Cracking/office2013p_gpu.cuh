#ifndef _OFFICE2013P_GPU_CUH_
#define _OFFICE2013P_GPU_CUH_

#include "base64.h"
#include "sha512.cuh"
#include "aes.cuh"
#include "config.cuh"

#define PW_DONE 0
#define PW_HIT 1
#define PW_ERR -1

#define VALID		0
#define INVALID		1

#define AES_128		10
#define AES_256		11

#define AES_8B		20
#define AES_32B		21

// choose 8-bit or 32-bit AES
#define AES_VERSION	AES_32B

// GPU PARAM CONFIG
#define TPB			256
#define BPG			32 * 256
#define NSTREAM		32
#define KERNEL_SIZE	(TPB * BPG)
#define PROC_SIZE	(TPB * BPG)

#define MAX_PASSLEN		32
#define PASS_ARRAYLEN	32
#define PASS_INPUTLEN	(8 + PASS_ARRAYLEN)

// max iteration for stop
#define BRUTE_FORCE_BREAK		96 * 96 * 32 // 0x20 0x20 0x20 ~ 0x80 0x80 0x40

//MS office 2013+ FIXED VALUE
#define MS_hashSize		64
#define MS_keyBits		256
#define MS_BlockSize	16
#define MS_saltSize		16


typedef struct MS13Info {
	int keyDataSaltSize;
	int keyDataBlockSize;
	int keyDataKeyBits;
	int keyDataHashSize;
	char* keyDataCipherAlgorithm;
	char* keyDataCipherChaining;
	char* keyDataHashAlgorithm;
	uint8_t* keyDataSaltValue;

	uint8_t* encryptedHmacKey;
	uint8_t* encryptedHmacValue;

	uint32_t spinCount;
	int saltSize;
	int blockSize;
	int keyBits;
	int hashSize;
	char* cipherAlgorithm;
	char* cipherChaining;
	char* hashAlgorithm;
	uint8_t* saltValue;
	uint8_t* encryptedVerifierHashInput;
	uint8_t* encryptedVerifierHashValue;
	uint8_t* encryptedKeyValue;
};

#define InitializeEncryptionInfo(A){ A.keyDataSaltSize = 0; A.keyDataBlockSize = 0; A.keyDataKeyBits = 0; A.keyDataHashSize = 0; \
	A.keyDataCipherAlgorithm = NULL; A.keyDataCipherChaining = NULL; A.keyDataHashAlgorithm = NULL; A.keyDataSaltValue = NULL; \
	A.encryptedHmacKey = NULL; A.encryptedHmacValue = NULL; A.spinCount = 0; A.saltSize = 0; A.blockSize = 0; A.keyBits = 0; \
	A.hashSize = 0; A.cipherAlgorithm = NULL; A.cipherChaining = NULL; A.hashAlgorithm = NULL; A.saltValue = NULL; \
	A.encryptedVerifierHashInput = NULL; A.encryptedVerifierHashValue = NULL; A.encryptedKeyValue = NULL; }

std::atomic<bool> running(false);
std::thread loadingThread;

void printLoadingFunction() {
	char loadingChars[] = { '/', '-', 'l' };
	int numChars = sizeof(loadingChars) / sizeof(char);

	while (running) {
		for (int i = 0; i < numChars; ++i) {
			std::cout << "\r" << loadingChars[i] << std::flush; // 커서를 줄의 시작으로 이동하고 문자 출력
			std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 0.2초 대기
		}
	}
	std::cout << "\r \r"; // 애니메이션이 종료될 때, 마지막 문자를 지웁니다.
}

void startLoadingAnimation() {
	running = true;
	loadingThread = std::thread(printLoadingFunction);
}

void stopLoadingAnimation() {
	running = false;
	if (loadingThread.joinable()) {
		loadingThread.join();
	}
}




#endif