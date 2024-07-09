#include "./selectGPU.cuh"


//select gpu
int selectDevice()
{
	int ngpus = 0;
	int selectedD = -1;

	cudaGetDeviceCount(&ngpus);

	printf("[ GPU Device List ]\n");

	/* shwo device list and ID*/
	for (int i = 0; i < ngpus; i++) {
		cudaDeviceProp prop;
		cudaGetDeviceProperties(&prop, i);
		printf("\nDevice Number: %d\n", i);
		printf("  Device name: %s\n", prop.name);
		printf("  Memory Clock Rate (KHz): %d\n", prop.memoryClockRate);
		printf("  Memory Bus Width (bits): %d\n", prop.memoryBusWidth);
		printf("  Peak Memory Bandwidth (GB/s): %f\n\n",
			2.0 * prop.memoryClockRate * (prop.memoryBusWidth / 8) / 1.0e6);
	}

	printf("\nPlease Enter Device : ");
	scanf("%d", &selectedD);

	while (selectedD < 0 && selectedD >= ngpus)
	{
		printf("Device ID error. Please Enter Device ID correctly : ");
		scanf("%d", &selectedD);
	}

	return selectedD;
}


//select file type
