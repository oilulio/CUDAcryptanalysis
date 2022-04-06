#define CC(x) {const cudaError_t a=(x); if (a!=cudaSuccess) { printf("\nCUDA Error : %s (err_num=%d) \n",cudaGetErrorString(a),a); cudaDeviceReset(); assert(0);}}
// From Shane Cook, CUDA Programming

#define WHOLE_WARP   (0xFFFFFFFF)   

#define TX (threadIdx.x)
#define TY (threadIdx.y)

#define BDX (blockDim.x)
#define BDY (blockDim.y)
#define BDZ (blockDim.z)

#define BX (blockIdx.x)
#define BY (blockIdx.y)
#define BZ (blockIdx.z)

#define GDX (gridDim.x)
#define GDY (gridDim.y)
#define GDZ (gridDim.z)

#define FULL_SYNC() CC(cudaDeviceSynchronize())

#ifdef __unix__       
#define PRINT_TIME() system("date")  
#elif defined(_WIN32) || defined(WIN32) 
#define PRINT_TIME() system("echo TIME %time%")  
#endif

int findAndSetCUDADevice(int nDev,int verbose);
