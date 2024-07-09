#ifndef _CONFIG_H_
#define _CONFIG_H_

// C/C++ HEADER
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include <process.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>

// CUDA HEADER
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

// DEBUG MODE
#define DEBUG			120
#define RELEASE			121
#define CRACK_MODE		DEBUG

// CUDA SAFE CALL
#define CUDA_SAFE_CALL(f) \
	cudaStatus = f;	\
	if(cudaStatus != cudaSuccess) \
	{ printf("cuda error (%s)\n", cudaGetErrorString(cudaStatus)); return -1; } \

#define CUDA_API_PER_THREAD_DEFAULT_STEAM


// CRACK FILE
int office2013p_crack_gpu();
void sha512_gpu_init();
void aes256_gpu_init();
 


#endif