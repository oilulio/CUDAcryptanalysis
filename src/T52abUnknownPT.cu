// CUDA program brute force attacking T52ab Sturgeon 
// i.e. a Siemens and Halske T52a or T52b (cryptographically identical)
// see https://en.wikipedia.org/w/index.php?title=Siemens_and_Halske_T52&oldid=887489719
// with ciphertext of c.500+ characters only.  
// Finds the XOR wheels and their offsets (but *not* their order), without 
// prior knowledge of any part of the key 

// Not guaranteed to score the correct key highest, just highly.
// Performance depends on the actual plaintext statistics and the ciphertext length.

// Can suffer OS-enforced timeouts if run on a system when GPU is also providing the display.

/*	 
Copyright (C) 2021-2022  S Combes

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. */

// Method is to create all candidate XOR streams made from a partition of 5
// wheels from the total 10.  Each XOR stream then has a cycle length of
// the product of the 5 wheel lengths and is packed into <0.7GB

// Then the likelihood of the actual CT being observed for each possible XOR
// sequence at all startpoints in the cicle length, summed over the characters in
// the CT, is used to rank the XOR sequences.  This works because the plaintext
// statistics for numbers of bits set is not uniform.

#include <stdio.h>
#include <assert.h>
#include <stdexcept>
#include <thrust/host_vector.h>
#include <thrust/device_vector.h>
#include <thrust/fill.h>

#include "stdcuda.h"

#define TRUE  (1==1)
#define FALSE (1==0)
#define VERBOSE (FALSE)

#define CEIL_A_DIV_B(A,B) ((((A)-1)/(B))+1)

#define MAX_RESULTS (40000) 
#define MAKE_BLOCK_DIM_Y (16)
#define SCORE_BLOCK_DIM_Y (1) // Designed to only be 1
#define STRIDE_IN_STEPS  (32) // Stride in keystream block to block.  Currently 1 warp

#define WHEEL_STORAGE (82)  // Greater than longest wheel (73) + margin (see below)
#define WHEEL_LENGTHS 73,71,69,67,65,64,61,59,53,47  // A feature of the machine
// Note worst case, product of 1st 5 wheels, is c 1.6 billion, i.e. <2^32, allows uint32 use
// Since we pack 2.5/byte we need c0.7GB.  A modern GPU is likely to have this.

int patternLength[10] = { WHEEL_LENGTHS };

__device__ int results=0;
__device__ int overflow=FALSE;

int patterns[10][WHEEL_STORAGE] = { // [w][x] = where w is wheel and x is position.  Note all same lengths - repeat from start
{0,1,1,0,1,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0,1,1,1,1,0,0,1,1,1,0,1,0,1,0,1,1,1,0,0,1,1,0,0,1,1,1,0,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,1,1,0,1,0,0,0,0,0,0,1,0,1,1,0,1,1,1,0,0}, // A 73
{0,1,1,1,1,0,0,1,1,1,1,1,1,0,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,0,0,0,1,1,0,1,0,1,0,1,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,1,1,1,1},
{0,1,1,1,1,1,0,1,0,1,1,0,0,1,0,1,1,0,0,0,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,1,0,1,1,1,0,0,0,1,0,0,1,0,0,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,1,0,1,0,1,1,0,0},
{0,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,0,1,1,0,1,0,0,0,0,1,0,0,1,1,1,0,0,1,1,1,0,0,1,0,1,1,1,0,0,0,1,1,0,0,1,0,0,1,0,1,1,1,1,0,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,0},
{0,1,0,0,0,1,0,0,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,0,1,0,0,1,1,0,1,0,0,0,0,1,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,0,1,1,0,0,0,1,0,1,0,0,0,1,0,0,0,1,0,1,1,1,1,1,1},
{0,1,0,1,0,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,0,0,1,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,0,0,0,0,1,0,1,1},
{0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,0,1,0,0,1,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,0,1,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1},
{0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,0,0,1,1,0,1,0,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,0,0,1,1,1},
{0,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,1,0,1,1,1,0,1,0,0,0,0,1,1,1,1,0,0,0,1,0,1,1,0,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,0,1,1,1},
{0,1,0,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,1,0,1,1,1,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1}}; // K 47

__constant__ double llRatioAt_Cn_Xn[6][6]={  // Log likelihood ratio at [popcCT][popcXOR]
{-8.047189562170502,    0.8064758658669484,  0.26911068686634554,-0.6694306539426292, -1.159636990505884,   0.054488185284069776},
{ 0.8064758658669484,   0.04602825837847435, 0.18498467421343837,-0.09351978352070435,-0.476746310113128,  -1.1596369905058843  },
{ 0.26911068686634554,  0.18498467421343837,-0.12852451938847337, 0.08139563820399406,-0.09351978352070435,-0.6694306539426292  },
{-0.6694306539426292,  -0.09351978352070435, 0.08139563820399406,-0.12852451938847337, 0.18498467421343837, 0.26911068686634554 },
{-1.1596369905058843,  -0.476746310113128,  -0.09351978352070435, 0.18498467421343837, 0.04602825837847435, 0.8064758658669484  },
{ 0.054488185284069776,-1.159636990505884,  -0.6694306539426292,  0.26911068686634554, 0.8064758658669484, -8.047189562170502   }};

// ------------------------------------------------------------------------------
int popc5(int word) { // Not designed to be fast, setup only.  Only low 5 bits.
int cnt=0;
for (int i=0;i<5;i++) if (word&(1<<i)) cnt++;
return cnt;
}
// ------------------------------------------------------------------------------
__global__ void makeStreamSumPacked10perWord(int * __restrict__ keyStream,  // Where to send data
    const int * __restrict__ wheelData,const int len0,const int len1,const int len2,const int len3,const int len4)    
{
// Each thread makes a word containing 10, 3-bit key popc settings from the key stream
// Hence each warp makes 32x10 = 320 key stream steps 	
	
int pointInStream=((TX+32*TY+32*MAKE_BLOCK_DIM_Y*BX)*10);
int result=0;  // Our creation

int w0=pointInStream%len0;
int w1=pointInStream%len1;
int w2=pointInStream%len2;
int w3=pointInStream%len3;
int w4=pointInStream%len4;

// The highest wn can be set initially is when it relates to wheel A with 73 pins,
// and hence max wn=72 (0-72 range)
// Below, wn is used after it is incremented 9 times.  Hence max used wn=81.
// Hence WHEEL_STORAGE must be at least 82 to enable us to use ++ and not modulus
for (int i=0;i<10;i++) { // Thread creates 10 steps in the stream and packs their 
                         // popcs into a word
  int subResult=0;
  if (wheelData[0*WHEEL_STORAGE+w0++]) subResult++;
  if (wheelData[1*WHEEL_STORAGE+w1++]) subResult++;
  if (wheelData[2*WHEEL_STORAGE+w2++]) subResult++;
  if (wheelData[3*WHEEL_STORAGE+w3++]) subResult++;
  if (wheelData[4*WHEEL_STORAGE+w4++]) subResult++;
  
  result|=(subResult<<(3*i));
  __syncwarp();
}
keyStream[TX+32*TY+32*MAKE_BLOCK_DIM_Y*BX]=result;          
}
// ------------------------------------------------------------------------------
__global__ void getLLscore(const int * __restrict__ keyStream,
                        unsigned int * __restrict__ successes,
                        const int * __restrict__ CT_popc,
					    const int CT_length,
              const int w0,const int w1,const int w2,const int w3,
	            const int w4,const int limit,const int offset)
{
// Gets the LL score for a set of start points (keys) in the xor stream
// one score per thread.  A warp works together on 32 consecutive
// keys, and covers the whole ciphertext length.

double score=0.0;
for (int pos=0;pos<CT_length;pos++) { // Relying on expecting a lot of cache hits given locality
	
  int CTn=CT_popc[pos]; // Same for whole warp	
  int XORn=0x07&(keyStream[(BX*STRIDE_IN_STEPS+TX+pos)/10]>>
                       (3*((BX*STRIDE_IN_STEPS+TX+pos)%10))); // Thread specific
  
  score+=llRatioAt_Cn_Xn[CTn][XORn];
}  
 
if (score>15.0) { // Adjustable threshold to minimise reporting.
  int position=offset+BX*STRIDE_IN_STEPS+TX;
  if (position<limit) { // Only report once, not wrap-around results
	if (results<MAX_RESULTS) { 
      int i=atomicAdd(&results,1); 
      successes[i*2+0]=position;    // 31 bits
      successes[i*2+1]=(unsigned int)(score*10000);    
	} else if (!overflow) { printf("ERROR Results buffer full.\n"); overflow=TRUE; } 
  }
}
}
// ------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
// We are called for a specific partition, i.e. 5 wheels.  Caller should have lengths st w0<w1<w2<w3<w4

int * deviceData;
int * deviceWheels;
int * deviceCT_popc;
int * iCT_popc;
unsigned int * deviceResults;
unsigned int * hostResults;

// Bletchley Park notation for Sturgeon letters
char * BPsturgeon=(char *)"/E4A9SIU3DRJNFCKTZLWHYPQOBG+MXV8";  

int myWheelNos[] ={0,1,2,3,4};  // Defaults

if (argc<3) {
  printf("Incorrect arguments\n");
  printf("Use T52abUnknownPT x abcde CT : Use GPU x, wheels abcde, and CT \n");
  printf("CT must use BP Sturgeon characters : %s\n",BPsturgeon);
  exit(0);
}

for (int i=0;i<5;i++) myWheelNos[i]=argv[2][i]-'0';
for (int i=0;i<5;i++) if (argv[2][i]>'9' || argv[2][i]<'0') { printf("Wheel number not in range 0-9\n"); exit(0); }

int specificWheels[5][WHEEL_STORAGE];
for (int i=0;i<5;i++) {
  for (int j=0;j<WHEEL_STORAGE;j++) {
	specificWheels[i][j]=patterns[myWheelNos[i]][j];
  }	
}
int CT_length=0;
while(argv[3][CT_length]) { CT_length++; }

printf("T52ab CUDA Brute Force XOR Cracker CT only : Wheels=%s CT length=%d\n",argv[2],CT_length); 

if (findAndSetCUDADevice(atoi(argv[1]),VERBOSE)) exit(0);

CC(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));

#define EXEC_STREAMS (1)
cudaStream_t streamExec[EXEC_STREAMS];
for (int i=0;i<EXEC_STREAMS;i++) CC(cudaStreamCreate(&streamExec[i]));

int keyStreamLength=patternLength[myWheelNos[0]]*patternLength[myWheelNos[1]]*
      patternLength[myWheelNos[2]]*patternLength[myWheelNos[3]]*
	    patternLength[myWheelNos[4]]+200+CT_length; // margin to avoid need for wrap
int wordsRequired=CEIL_A_DIV_B(keyStreamLength,10); 

dim3 makeBlockDim(32,MAKE_BLOCK_DIM_Y);   
dim3 makeGridDim(CEIL_A_DIV_B(keyStreamLength,10*32*MAKE_BLOCK_DIM_Y));

dim3 scoreBlockDim(32,SCORE_BLOCK_DIM_Y);
dim3 scoreGridDim(keyStreamLength/STRIDE_IN_STEPS); // Margin above means we can do pure integer division

CC(cudaMalloc((void **)&deviceData,wordsRequired*sizeof(int)));
CC(cudaMalloc((void **)&deviceWheels,WHEEL_STORAGE*5*sizeof(int)));  // Only the 5 we are using 
CC(cudaMalloc((void **)&deviceCT_popc,CT_length*sizeof(int))); 
CC(cudaMalloc((void **)&deviceResults,2*MAX_RESULTS*sizeof(unsigned int)));

CC(cudaHostAlloc((void **) &hostResults,2*MAX_RESULTS*sizeof(unsigned int),cudaHostAllocDefault));
CC(cudaHostAlloc((void **) &iCT_popc,CT_length*sizeof(unsigned int),cudaHostAllocDefault));

for (int i=0;i<CT_length;i++) {
  char * ptr=strchr(BPsturgeon,argv[3][i]);
  if (!ptr) { printf("Invalid CT character %c\n",argv[3][i]); exit(0); }
  iCT_popc[i]=popc5((int)(ptr-BPsturgeon));
}

CC(cudaMemcpy((void *)deviceWheels,specificWheels,WHEEL_STORAGE*5*sizeof(int),cudaMemcpyHostToDevice));
CC(cudaMemcpy((void *)deviceCT_popc,iCT_popc,CT_length*sizeof(int),cudaMemcpyHostToDevice));

thrust::device_ptr<unsigned int> devResThr(deviceResults);
thrust::fill(devResThr,devResThr+2*MAX_RESULTS,0xFFFFFFFF);  // Use a signal that the result is invalid

makeStreamSumPacked10perWord<<<makeGridDim,makeBlockDim,0,streamExec[0]>>>
           (deviceData,deviceWheels,patternLength[myWheelNos[0]],
	   patternLength[myWheelNos[1]],patternLength[myWheelNos[2]],
	   patternLength[myWheelNos[3]],patternLength[myWheelNos[4]]);

getLLscore<<<scoreGridDim,scoreBlockDim,0,streamExec[0]>>>
       (deviceData,deviceResults,deviceCT_popc,CT_length,
        myWheelNos[0],myWheelNos[1],myWheelNos[2],myWheelNos[3],myWheelNos[4],
		  patternLength[myWheelNos[0]]*patternLength[myWheelNos[1]]*
	    patternLength[myWheelNos[2]]*patternLength[myWheelNos[3]]*
		  patternLength[myWheelNos[4]],0);

CC(cudaStreamSynchronize(streamExec[0]));
CC(cudaMemcpy(hostResults,deviceResults,2*MAX_RESULTS*sizeof(unsigned int),cudaMemcpyDeviceToHost))

for (int result=0;result<(2*MAX_RESULTS);result+=2) { 

  int tmp[5];
  int position=hostResults[result+0];
  double score=hostResults[result+1];
  
  if (position!=0xFFFFFFFF) {
	
    printf("Match with Wheel Order %d%d%d%d%d ",myWheelNos[0],myWheelNos[1],
                                  myWheelNos[2],myWheelNos[3],myWheelNos[4]);

    tmp[0]=position%patternLength[myWheelNos[0]]+1; // Historic representation starts at 1
    tmp[1]=position%patternLength[myWheelNos[1]]+1;
    tmp[2]=position%patternLength[myWheelNos[2]]+1;
    tmp[3]=position%patternLength[myWheelNos[3]]+1;
    tmp[4]=position%patternLength[myWheelNos[4]]+1;
	
    printf("Score=%6.3f Start points %d %d %d %d %d \n",(score/10000.0),tmp[0],tmp[1],tmp[2],tmp[3],tmp[4]);
  }
}

CC(cudaFree(deviceData));
CC(cudaFree(deviceWheels));
CC(cudaFree(deviceCT_popc));
CC(cudaFreeHost(hostResults));
CC(cudaFreeHost(iCT_popc));
CC(cudaFree(deviceResults));

for (int i=0;i<EXEC_STREAMS;i++) CC(cudaStreamDestroy(streamExec[i]));
cudaDeviceReset();
return(0);
}
