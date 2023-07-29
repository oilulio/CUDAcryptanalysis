#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <cstdlib>

#include "stdcuda.h"

// ------------------------------------------------------------------------------
int findAndSetCUDADevice(int nDev,int verbose) {
	
int devCount;
CC(cudaGetDeviceCount(&devCount));

size_t mem_tot;
size_t mem_free;
cudaDeviceProp devProp;
for (int thisDev=0;thisDev<devCount;thisDev++) {
  CC(cudaGetDeviceProperties(&devProp,thisDev));
  CC(cudaMemGetInfo(&mem_free, &mem_tot));
  if (verbose) {
    printf("Device %d found %s with CC=%d%d\n",thisDev,devProp.name,devProp.major,devProp.minor);
    printf("Total memory %zu and free %zu\n",mem_tot,mem_free);
  }
}

if (nDev>=devCount) { printf("GPU devices does not exist"); return (1); }
else {
  CC(cudaGetDeviceProperties(&devProp,nDev));
  CC(cudaSetDevice(nDev));
  CC(cudaDeviceReset());
  if (verbose) printf("Using %s\n",devProp.name);
}
return (0);
}
// ------------------------------------------------------------------------------
