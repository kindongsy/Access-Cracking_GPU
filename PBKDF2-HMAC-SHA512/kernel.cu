#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "type.cuh"
#include "sha512.cuh"
#include <stdio.h>
#include <time.h>
#include "./ui/selectGPU.cuh"

int main() {
	/* Device Selection */
	int deviceID = selectDevice();
	cudaSetDevice(deviceID);

	system("cls");

	srand(time(NULL));
	PBKDF2_HMAC_SHA512_coalesed_test(BLOCK_SIZE, THREAD_SIZE);


	return 0;
}