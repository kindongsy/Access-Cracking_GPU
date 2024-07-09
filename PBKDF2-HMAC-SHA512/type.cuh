#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctime>

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define THREAD_SIZE		256
#define BLOCK_SIZE		2048
//#define Inner_print		//PBKDF2 inner data print per iteration

/*
	overclock
	no use = 0
	3090 use = 1
	4090 use = 2
*/

#define Overclock	0