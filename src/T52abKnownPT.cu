// CUDA program brute force attacking T52ab Sturgeon 
// i.e. a Siemens and Halske T52a or T52b (cryptographically identical)
// see https://en.wikipedia.org/w/index.php?title=Siemens_and_Halske_T52&oldid=887489719
// with known plaintext of up to 32 characters, wildcards allowed.  
// Finds the XOR wheels and their offsets, without prior knowledge of
// any part of the key 

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

// Works on the basis that the if we apply the correct XOR to the 5 plaintext lanes 
// (bit positions) then the number of set bits in the resultant 'intermediate' 
// character will be the same as the number of set bits in the ciphertext 
// character (as the later permutation does not change the number of set bits)

// For example consider that the LSb of the plaintext is associated with wheel 6 
// as its XOR. If that XOR is at offset x at the first character, it will be at
// x+1 at the next et seq.

// Having assumed an XOR wheel and offset for every lane, we can reject the XOR 
// settings if the PT XOR with our assumption does not have the same number of 
// set bits as the CT.

// We use the whole warp (assumed 32 lanes) to test all known PT letters 
// simultaneously.

// A given invocation considers five wheels.  These are supplied, and all 
// 120 permutations of their ordering are automatically generated.

// To be precise, in fact only one ordering of the wheel key is used, and 120 
// permutations of the plaintext are used.  This is because the plaintext 
// can be permuted once for all keys. i.e. the permutations can be precomputed

// This does not affect the result because it is the bit count, not the bit
// order, that is used.

// 252 runs are needed to cover all possible partitions of 5 wheels from the 10.

// Method : Fill the memory needed to do exhaustive test then test it

// Experiments suggest this creates unique result with c22 characters of known PT.
// Lower values still produce the correct answer, just within increasingly 
// many false alarms

// Tests. The corner cases below where the XOR wheels are 0-4 and all set at 1;
// 5-9 and all set at 1; 0-4 and all set to their maxima; 5-9 and all set at maxima.

// ./T52abKnownPT 0 01234 EVERYTHINGS9COMING9UP9MILHOUSE EEFNJAX/CRL+AMWAYFO8YBJQNNISI8
// ./T52abKnownPT 0 65897 EVERYTHINGS9COMING9UP9MILHOUSE EEAT+JLVQOVN9CZHLBNDEGY/NX/HYE
// ./T52abKnownPT 0 34210 EVERYTHINGS9COMING9UP9MILHOUSE VVKRW8EQNLUYAEZKHRJKCP4LS/LM99
// ./T52abKnownPT 0 85796 EVERYTHINGS9COMING9UP9MILHOUSE VVX3XVIVLGYFRVIF/UURRG9ZAOQ8EK

// Wildcard test
// ./T52abKnownPT 0 85796 EVERYTHINGS9COMING9??9MIL??? VVX3XVIVLGYFRVIF/UURRG9ZAOQ8EK

// Also tested for 250+ results with PT length between 20 and 32
// and 250+ results with PT length 32, with up to 12 wildcards

// Can suffer OS-enforced timeouts if run on a system when GPU is also providing the display.

#include <stdio.h>
#include <assert.h>

#include "stdcuda.h"

#define TRUE  (1==1)
#define FALSE (1==0)

#define VERBOSE (FALSE)

#define CEIL_A_DIV_B(A,B) ((((A)-1)/(B))+1)

#define MAX_RESULTS (4000) 
#define MAKE_BLOCK_DIM_Y (16)
#define STRIDE_IN_WORDS  (2)   // Will do COMPARE_BLOCK_DIM_Y compares, at 6 steps/word
#define COMPARE_BLOCK_DIM_Y (6*STRIDE_IN_WORDS)  // Must be <=32.

#define WHEEL_STORAGE (80)  // Greater than longest wheel (73) + margin (see below)
#define WHEEL_LENGTHS 73,71,69,67,65,64,61,59,53,47  // A feature of the machine
// Longest wheel lengths must be the first five.
// Worst case, product of 1st 5 wheels, is c 1.6 billion, <2^32
// Since we pack 1.5/byte we need slightly over 1GB.  A modern GPU is likely to have this.

int patternLength[10] = { WHEEL_LENGTHS };

__device__ int results=0;
__device__ int overflow=FALSE;

int patterns[10][WHEEL_STORAGE] = { // [w][x] = where w is wheel and x is position.  Note all same lengths - repeat from start
{0,1,1,0,1,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0,1,1,1,1,0,0,1,1,1,0,1,0,1,0,1,1,1,0,0,1,1,0,0,1,1,1,0,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,1,1,0,1,0,0,0,0,0,0,1,0,1,1,0,1,1,1}, // A 73
{0,1,1,1,1,0,0,1,1,1,1,1,1,0,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,0,0,0,1,1,0,1,0,1,0,1,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,1,1},
{0,1,1,1,1,1,0,1,0,1,1,0,0,1,0,1,1,0,0,0,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,1,0,1,1,1,0,0,0,1,0,0,1,0,0,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,1,0,1,0,1,1},
{0,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,0,1,1,0,1,0,0,0,0,1,0,0,1,1,1,0,0,1,1,1,0,0,1,0,1,1,1,0,0,0,1,1,0,0,1,0,0,1,0,1,1,1,1,0,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1},
{0,1,0,0,0,1,0,0,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,0,1,0,0,1,1,0,1,0,0,0,0,1,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,0,1,1,0,0,0,1,0,1,0,0,0,1,0,0,0,1,0,1,1,1,1},
{0,1,0,1,0,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,0,0,1,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,0,0,0,0,1,0},
{0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,0,1,0,0,1,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,0,1,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0},
{0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,0,0,1,1,0,1,0,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,0,0,1},
{0,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,1,0,1,1,1,0,1,0,0,0,0,1,1,1,1,0,0,0,1,0,1,1,0,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,0,1},
{0,1,0,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,1,0,1,1,1,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,1,0,0}}; // K 47

int fivePerm[120][5]={  // All 120 permutations of 5 items
{0,1,2,3,4},{0,1,2,4,3},{0,1,3,2,4},{0,1,3,4,2},{0,1,4,2,3},
{0,1,4,3,2},{0,2,1,3,4},{0,2,1,4,3},{0,2,3,1,4},{0,2,3,4,1},
{0,2,4,1,3},{0,2,4,3,1},{0,3,1,2,4},{0,3,1,4,2},{0,3,2,1,4},
{0,3,2,4,1},{0,3,4,1,2},{0,3,4,2,1},{0,4,1,2,3},{0,4,1,3,2},
{0,4,2,1,3},{0,4,2,3,1},{0,4,3,1,2},{0,4,3,2,1},{1,0,2,3,4},
{1,0,2,4,3},{1,0,3,2,4},{1,0,3,4,2},{1,0,4,2,3},{1,0,4,3,2},
{1,2,0,3,4},{1,2,0,4,3},{1,2,3,0,4},{1,2,3,4,0},{1,2,4,0,3},
{1,2,4,3,0},{1,3,0,2,4},{1,3,0,4,2},{1,3,2,0,4},{1,3,2,4,0},
{1,3,4,0,2},{1,3,4,2,0},{1,4,0,2,3},{1,4,0,3,2},{1,4,2,0,3},
{1,4,2,3,0},{1,4,3,0,2},{1,4,3,2,0},{2,0,1,3,4},{2,0,1,4,3},
{2,0,3,1,4},{2,0,3,4,1},{2,0,4,1,3},{2,0,4,3,1},{2,1,0,3,4},
{2,1,0,4,3},{2,1,3,0,4},{2,1,3,4,0},{2,1,4,0,3},{2,1,4,3,0},
{2,3,0,1,4},{2,3,0,4,1},{2,3,1,0,4},{2,3,1,4,0},{2,3,4,0,1},
{2,3,4,1,0},{2,4,0,1,3},{2,4,0,3,1},{2,4,1,0,3},{2,4,1,3,0},
{2,4,3,0,1},{2,4,3,1,0},{3,0,1,2,4},{3,0,1,4,2},{3,0,2,1,4},
{3,0,2,4,1},{3,0,4,1,2},{3,0,4,2,1},{3,1,0,2,4},{3,1,0,4,2},
{3,1,2,0,4},{3,1,2,4,0},{3,1,4,0,2},{3,1,4,2,0},{3,2,0,1,4},
{3,2,0,4,1},{3,2,1,0,4},{3,2,1,4,0},{3,2,4,0,1},{3,2,4,1,0},
{3,4,0,1,2},{3,4,0,2,1},{3,4,1,0,2},{3,4,1,2,0},{3,4,2,0,1},
{3,4,2,1,0},{4,0,1,2,3},{4,0,1,3,2},{4,0,2,1,3},{4,0,2,3,1},
{4,0,3,1,2},{4,0,3,2,1},{4,1,0,2,3},{4,1,0,3,2},{4,1,2,0,3},
{4,1,2,3,0},{4,1,3,0,2},{4,1,3,2,0},{4,2,0,1,3},{4,2,0,3,1},
{4,2,1,0,3},{4,2,1,3,0},{4,2,3,0,1},{4,2,3,1,0},{4,3,0,1,2},
{4,3,0,2,1},{4,3,1,0,2},{4,3,1,2,0},{4,3,2,0,1},{4,3,2,1,0}};

int perms[120][32] = { // [n][x] = where x is permuted by the nth permutation
{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31},
{0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23,8,9,10,11,12,13,14,15,24,25,26,27,28,29,30,31},
{0,1,2,3,8,9,10,11,4,5,6,7,12,13,14,15,16,17,18,19,24,25,26,27,20,21,22,23,28,29,30,31},
{0,1,2,3,8,9,10,11,16,17,18,19,24,25,26,27,4,5,6,7,12,13,14,15,20,21,22,23,28,29,30,31},
{0,1,2,3,16,17,18,19,4,5,6,7,20,21,22,23,8,9,10,11,24,25,26,27,12,13,14,15,28,29,30,31},
{0,1,2,3,16,17,18,19,8,9,10,11,24,25,26,27,4,5,6,7,20,21,22,23,12,13,14,15,28,29,30,31},
{0,1,4,5,2,3,6,7,8,9,12,13,10,11,14,15,16,17,20,21,18,19,22,23,24,25,28,29,26,27,30,31},
{0,1,4,5,2,3,6,7,16,17,20,21,18,19,22,23,8,9,12,13,10,11,14,15,24,25,28,29,26,27,30,31},
{0,1,4,5,8,9,12,13,2,3,6,7,10,11,14,15,16,17,20,21,24,25,28,29,18,19,22,23,26,27,30,31},
{0,1,4,5,8,9,12,13,16,17,20,21,24,25,28,29,2,3,6,7,10,11,14,15,18,19,22,23,26,27,30,31},
{0,1,4,5,16,17,20,21,2,3,6,7,18,19,22,23,8,9,12,13,24,25,28,29,10,11,14,15,26,27,30,31},
{0,1,4,5,16,17,20,21,8,9,12,13,24,25,28,29,2,3,6,7,18,19,22,23,10,11,14,15,26,27,30,31},
{0,1,8,9,2,3,10,11,4,5,12,13,6,7,14,15,16,17,24,25,18,19,26,27,20,21,28,29,22,23,30,31},
{0,1,8,9,2,3,10,11,16,17,24,25,18,19,26,27,4,5,12,13,6,7,14,15,20,21,28,29,22,23,30,31},
{0,1,8,9,4,5,12,13,2,3,10,11,6,7,14,15,16,17,24,25,20,21,28,29,18,19,26,27,22,23,30,31},
{0,1,8,9,4,5,12,13,16,17,24,25,20,21,28,29,2,3,10,11,6,7,14,15,18,19,26,27,22,23,30,31},
{0,1,8,9,16,17,24,25,2,3,10,11,18,19,26,27,4,5,12,13,20,21,28,29,6,7,14,15,22,23,30,31},
{0,1,8,9,16,17,24,25,4,5,12,13,20,21,28,29,2,3,10,11,18,19,26,27,6,7,14,15,22,23,30,31},
{0,1,16,17,2,3,18,19,4,5,20,21,6,7,22,23,8,9,24,25,10,11,26,27,12,13,28,29,14,15,30,31},
{0,1,16,17,2,3,18,19,8,9,24,25,10,11,26,27,4,5,20,21,6,7,22,23,12,13,28,29,14,15,30,31},
{0,1,16,17,4,5,20,21,2,3,18,19,6,7,22,23,8,9,24,25,12,13,28,29,10,11,26,27,14,15,30,31},
{0,1,16,17,4,5,20,21,8,9,24,25,12,13,28,29,2,3,18,19,6,7,22,23,10,11,26,27,14,15,30,31},
{0,1,16,17,8,9,24,25,2,3,18,19,10,11,26,27,4,5,20,21,12,13,28,29,6,7,22,23,14,15,30,31},
{0,1,16,17,8,9,24,25,4,5,20,21,12,13,28,29,2,3,18,19,10,11,26,27,6,7,22,23,14,15,30,31},
{0,2,1,3,4,6,5,7,8,10,9,11,12,14,13,15,16,18,17,19,20,22,21,23,24,26,25,27,28,30,29,31},
{0,2,1,3,4,6,5,7,16,18,17,19,20,22,21,23,8,10,9,11,12,14,13,15,24,26,25,27,28,30,29,31},
{0,2,1,3,8,10,9,11,4,6,5,7,12,14,13,15,16,18,17,19,24,26,25,27,20,22,21,23,28,30,29,31},
{0,2,1,3,8,10,9,11,16,18,17,19,24,26,25,27,4,6,5,7,12,14,13,15,20,22,21,23,28,30,29,31},
{0,2,1,3,16,18,17,19,4,6,5,7,20,22,21,23,8,10,9,11,24,26,25,27,12,14,13,15,28,30,29,31},
{0,2,1,3,16,18,17,19,8,10,9,11,24,26,25,27,4,6,5,7,20,22,21,23,12,14,13,15,28,30,29,31},
{0,2,4,6,1,3,5,7,8,10,12,14,9,11,13,15,16,18,20,22,17,19,21,23,24,26,28,30,25,27,29,31},
{0,2,4,6,1,3,5,7,16,18,20,22,17,19,21,23,8,10,12,14,9,11,13,15,24,26,28,30,25,27,29,31},
{0,2,4,6,8,10,12,14,1,3,5,7,9,11,13,15,16,18,20,22,24,26,28,30,17,19,21,23,25,27,29,31},
{0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31},
{0,2,4,6,16,18,20,22,1,3,5,7,17,19,21,23,8,10,12,14,24,26,28,30,9,11,13,15,25,27,29,31},
{0,2,4,6,16,18,20,22,8,10,12,14,24,26,28,30,1,3,5,7,17,19,21,23,9,11,13,15,25,27,29,31},
{0,2,8,10,1,3,9,11,4,6,12,14,5,7,13,15,16,18,24,26,17,19,25,27,20,22,28,30,21,23,29,31},
{0,2,8,10,1,3,9,11,16,18,24,26,17,19,25,27,4,6,12,14,5,7,13,15,20,22,28,30,21,23,29,31},
{0,2,8,10,4,6,12,14,1,3,9,11,5,7,13,15,16,18,24,26,20,22,28,30,17,19,25,27,21,23,29,31},
{0,2,8,10,4,6,12,14,16,18,24,26,20,22,28,30,1,3,9,11,5,7,13,15,17,19,25,27,21,23,29,31},
{0,2,8,10,16,18,24,26,1,3,9,11,17,19,25,27,4,6,12,14,20,22,28,30,5,7,13,15,21,23,29,31},
{0,2,8,10,16,18,24,26,4,6,12,14,20,22,28,30,1,3,9,11,17,19,25,27,5,7,13,15,21,23,29,31},
{0,2,16,18,1,3,17,19,4,6,20,22,5,7,21,23,8,10,24,26,9,11,25,27,12,14,28,30,13,15,29,31},
{0,2,16,18,1,3,17,19,8,10,24,26,9,11,25,27,4,6,20,22,5,7,21,23,12,14,28,30,13,15,29,31},
{0,2,16,18,4,6,20,22,1,3,17,19,5,7,21,23,8,10,24,26,12,14,28,30,9,11,25,27,13,15,29,31},
{0,2,16,18,4,6,20,22,8,10,24,26,12,14,28,30,1,3,17,19,5,7,21,23,9,11,25,27,13,15,29,31},
{0,2,16,18,8,10,24,26,1,3,17,19,9,11,25,27,4,6,20,22,12,14,28,30,5,7,21,23,13,15,29,31},
{0,2,16,18,8,10,24,26,4,6,20,22,12,14,28,30,1,3,17,19,9,11,25,27,5,7,21,23,13,15,29,31},
{0,4,1,5,2,6,3,7,8,12,9,13,10,14,11,15,16,20,17,21,18,22,19,23,24,28,25,29,26,30,27,31},
{0,4,1,5,2,6,3,7,16,20,17,21,18,22,19,23,8,12,9,13,10,14,11,15,24,28,25,29,26,30,27,31},
{0,4,1,5,8,12,9,13,2,6,3,7,10,14,11,15,16,20,17,21,24,28,25,29,18,22,19,23,26,30,27,31},
{0,4,1,5,8,12,9,13,16,20,17,21,24,28,25,29,2,6,3,7,10,14,11,15,18,22,19,23,26,30,27,31},
{0,4,1,5,16,20,17,21,2,6,3,7,18,22,19,23,8,12,9,13,24,28,25,29,10,14,11,15,26,30,27,31},
{0,4,1,5,16,20,17,21,8,12,9,13,24,28,25,29,2,6,3,7,18,22,19,23,10,14,11,15,26,30,27,31},
{0,4,2,6,1,5,3,7,8,12,10,14,9,13,11,15,16,20,18,22,17,21,19,23,24,28,26,30,25,29,27,31},
{0,4,2,6,1,5,3,7,16,20,18,22,17,21,19,23,8,12,10,14,9,13,11,15,24,28,26,30,25,29,27,31},
{0,4,2,6,8,12,10,14,1,5,3,7,9,13,11,15,16,20,18,22,24,28,26,30,17,21,19,23,25,29,27,31},
{0,4,2,6,8,12,10,14,16,20,18,22,24,28,26,30,1,5,3,7,9,13,11,15,17,21,19,23,25,29,27,31},
{0,4,2,6,16,20,18,22,1,5,3,7,17,21,19,23,8,12,10,14,24,28,26,30,9,13,11,15,25,29,27,31},
{0,4,2,6,16,20,18,22,8,12,10,14,24,28,26,30,1,5,3,7,17,21,19,23,9,13,11,15,25,29,27,31},
{0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15,16,20,24,28,17,21,25,29,18,22,26,30,19,23,27,31},
{0,4,8,12,1,5,9,13,16,20,24,28,17,21,25,29,2,6,10,14,3,7,11,15,18,22,26,30,19,23,27,31},
{0,4,8,12,2,6,10,14,1,5,9,13,3,7,11,15,16,20,24,28,18,22,26,30,17,21,25,29,19,23,27,31},
{0,4,8,12,2,6,10,14,16,20,24,28,18,22,26,30,1,5,9,13,3,7,11,15,17,21,25,29,19,23,27,31},
{0,4,8,12,16,20,24,28,1,5,9,13,17,21,25,29,2,6,10,14,18,22,26,30,3,7,11,15,19,23,27,31},
{0,4,8,12,16,20,24,28,2,6,10,14,18,22,26,30,1,5,9,13,17,21,25,29,3,7,11,15,19,23,27,31},
{0,4,16,20,1,5,17,21,2,6,18,22,3,7,19,23,8,12,24,28,9,13,25,29,10,14,26,30,11,15,27,31},
{0,4,16,20,1,5,17,21,8,12,24,28,9,13,25,29,2,6,18,22,3,7,19,23,10,14,26,30,11,15,27,31},
{0,4,16,20,2,6,18,22,1,5,17,21,3,7,19,23,8,12,24,28,10,14,26,30,9,13,25,29,11,15,27,31},
{0,4,16,20,2,6,18,22,8,12,24,28,10,14,26,30,1,5,17,21,3,7,19,23,9,13,25,29,11,15,27,31},
{0,4,16,20,8,12,24,28,1,5,17,21,9,13,25,29,2,6,18,22,10,14,26,30,3,7,19,23,11,15,27,31},
{0,4,16,20,8,12,24,28,2,6,18,22,10,14,26,30,1,5,17,21,9,13,25,29,3,7,19,23,11,15,27,31},
{0,8,1,9,2,10,3,11,4,12,5,13,6,14,7,15,16,24,17,25,18,26,19,27,20,28,21,29,22,30,23,31},
{0,8,1,9,2,10,3,11,16,24,17,25,18,26,19,27,4,12,5,13,6,14,7,15,20,28,21,29,22,30,23,31},
{0,8,1,9,4,12,5,13,2,10,3,11,6,14,7,15,16,24,17,25,20,28,21,29,18,26,19,27,22,30,23,31},
{0,8,1,9,4,12,5,13,16,24,17,25,20,28,21,29,2,10,3,11,6,14,7,15,18,26,19,27,22,30,23,31},
{0,8,1,9,16,24,17,25,2,10,3,11,18,26,19,27,4,12,5,13,20,28,21,29,6,14,7,15,22,30,23,31},
{0,8,1,9,16,24,17,25,4,12,5,13,20,28,21,29,2,10,3,11,18,26,19,27,6,14,7,15,22,30,23,31},
{0,8,2,10,1,9,3,11,4,12,6,14,5,13,7,15,16,24,18,26,17,25,19,27,20,28,22,30,21,29,23,31},
{0,8,2,10,1,9,3,11,16,24,18,26,17,25,19,27,4,12,6,14,5,13,7,15,20,28,22,30,21,29,23,31},
{0,8,2,10,4,12,6,14,1,9,3,11,5,13,7,15,16,24,18,26,20,28,22,30,17,25,19,27,21,29,23,31},
{0,8,2,10,4,12,6,14,16,24,18,26,20,28,22,30,1,9,3,11,5,13,7,15,17,25,19,27,21,29,23,31},
{0,8,2,10,16,24,18,26,1,9,3,11,17,25,19,27,4,12,6,14,20,28,22,30,5,13,7,15,21,29,23,31},
{0,8,2,10,16,24,18,26,4,12,6,14,20,28,22,30,1,9,3,11,17,25,19,27,5,13,7,15,21,29,23,31},
{0,8,4,12,1,9,5,13,2,10,6,14,3,11,7,15,16,24,20,28,17,25,21,29,18,26,22,30,19,27,23,31},
{0,8,4,12,1,9,5,13,16,24,20,28,17,25,21,29,2,10,6,14,3,11,7,15,18,26,22,30,19,27,23,31},
{0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15,16,24,20,28,18,26,22,30,17,25,21,29,19,27,23,31},
{0,8,4,12,2,10,6,14,16,24,20,28,18,26,22,30,1,9,5,13,3,11,7,15,17,25,21,29,19,27,23,31},
{0,8,4,12,16,24,20,28,1,9,5,13,17,25,21,29,2,10,6,14,18,26,22,30,3,11,7,15,19,27,23,31},
{0,8,4,12,16,24,20,28,2,10,6,14,18,26,22,30,1,9,5,13,17,25,21,29,3,11,7,15,19,27,23,31},
{0,8,16,24,1,9,17,25,2,10,18,26,3,11,19,27,4,12,20,28,5,13,21,29,6,14,22,30,7,15,23,31},
{0,8,16,24,1,9,17,25,4,12,20,28,5,13,21,29,2,10,18,26,3,11,19,27,6,14,22,30,7,15,23,31},
{0,8,16,24,2,10,18,26,1,9,17,25,3,11,19,27,4,12,20,28,6,14,22,30,5,13,21,29,7,15,23,31},
{0,8,16,24,2,10,18,26,4,12,20,28,6,14,22,30,1,9,17,25,3,11,19,27,5,13,21,29,7,15,23,31},
{0,8,16,24,4,12,20,28,1,9,17,25,5,13,21,29,2,10,18,26,6,14,22,30,3,11,19,27,7,15,23,31},
{0,8,16,24,4,12,20,28,2,10,18,26,6,14,22,30,1,9,17,25,5,13,21,29,3,11,19,27,7,15,23,31},
{0,16,1,17,2,18,3,19,4,20,5,21,6,22,7,23,8,24,9,25,10,26,11,27,12,28,13,29,14,30,15,31},
{0,16,1,17,2,18,3,19,8,24,9,25,10,26,11,27,4,20,5,21,6,22,7,23,12,28,13,29,14,30,15,31},
{0,16,1,17,4,20,5,21,2,18,3,19,6,22,7,23,8,24,9,25,12,28,13,29,10,26,11,27,14,30,15,31},
{0,16,1,17,4,20,5,21,8,24,9,25,12,28,13,29,2,18,3,19,6,22,7,23,10,26,11,27,14,30,15,31},
{0,16,1,17,8,24,9,25,2,18,3,19,10,26,11,27,4,20,5,21,12,28,13,29,6,22,7,23,14,30,15,31},
{0,16,1,17,8,24,9,25,4,20,5,21,12,28,13,29,2,18,3,19,10,26,11,27,6,22,7,23,14,30,15,31},
{0,16,2,18,1,17,3,19,4,20,6,22,5,21,7,23,8,24,10,26,9,25,11,27,12,28,14,30,13,29,15,31},
{0,16,2,18,1,17,3,19,8,24,10,26,9,25,11,27,4,20,6,22,5,21,7,23,12,28,14,30,13,29,15,31},
{0,16,2,18,4,20,6,22,1,17,3,19,5,21,7,23,8,24,10,26,12,28,14,30,9,25,11,27,13,29,15,31},
{0,16,2,18,4,20,6,22,8,24,10,26,12,28,14,30,1,17,3,19,5,21,7,23,9,25,11,27,13,29,15,31},
{0,16,2,18,8,24,10,26,1,17,3,19,9,25,11,27,4,20,6,22,12,28,14,30,5,21,7,23,13,29,15,31},
{0,16,2,18,8,24,10,26,4,20,6,22,12,28,14,30,1,17,3,19,9,25,11,27,5,21,7,23,13,29,15,31},
{0,16,4,20,1,17,5,21,2,18,6,22,3,19,7,23,8,24,12,28,9,25,13,29,10,26,14,30,11,27,15,31},
{0,16,4,20,1,17,5,21,8,24,12,28,9,25,13,29,2,18,6,22,3,19,7,23,10,26,14,30,11,27,15,31},
{0,16,4,20,2,18,6,22,1,17,5,21,3,19,7,23,8,24,12,28,10,26,14,30,9,25,13,29,11,27,15,31},
{0,16,4,20,2,18,6,22,8,24,12,28,10,26,14,30,1,17,5,21,3,19,7,23,9,25,13,29,11,27,15,31},
{0,16,4,20,8,24,12,28,1,17,5,21,9,25,13,29,2,18,6,22,10,26,14,30,3,19,7,23,11,27,15,31},
{0,16,4,20,8,24,12,28,2,18,6,22,10,26,14,30,1,17,5,21,9,25,13,29,3,19,7,23,11,27,15,31},
{0,16,8,24,1,17,9,25,2,18,10,26,3,19,11,27,4,20,12,28,5,21,13,29,6,22,14,30,7,23,15,31},
{0,16,8,24,1,17,9,25,4,20,12,28,5,21,13,29,2,18,10,26,3,19,11,27,6,22,14,30,7,23,15,31},
{0,16,8,24,2,18,10,26,1,17,9,25,3,19,11,27,4,20,12,28,6,22,14,30,5,21,13,29,7,23,15,31},
{0,16,8,24,2,18,10,26,4,20,12,28,6,22,14,30,1,17,9,25,3,19,11,27,5,21,13,29,7,23,15,31},
{0,16,8,24,4,20,12,28,1,17,9,25,5,21,13,29,2,18,10,26,6,22,14,30,3,19,11,27,7,23,15,31},
{0,16,8,24,4,20,12,28,2,18,10,26,6,22,14,30,1,17,9,25,5,21,13,29,3,19,11,27,7,23,15,31}};

// ------------------------------------------------------------------------------
int popc5(int word) { // Not designed to be fast, used in setup.  Counts low 5 bits.
int cnt=0;
for (int i=0;i<5;i++) if (word&(1<<i)) cnt++;
return cnt;
}
// ------------------------------------------------------------------------------
__global__ void makeStreamPacked6perWord(int * __restrict__ keyStream,
      const int * __restrict__ wheelData,
      const int len0,const int len1,const int len2,const int len3,const int len4)    
{
// Each thread makes a word containing 6, 5-bit key settings from the key stream
// Hence each warp makes 32x6 = 192 key stream steps 
int pointInStream=((TX+32*TY+32*MAKE_BLOCK_DIM_Y*BX)*6);
int result=0;  // Our created word

int w0=pointInStream%len0;
int w1=pointInStream%len1;
int w2=pointInStream%len2;
int w3=pointInStream%len3;
int w4=pointInStream%len4;
// The highest wn can be set initially is when it relates to wheel A with 73 pins,
// and hence max wn=72 (0-72 range)
// Below, wn is used after it is incremented 5 times.  Hence max used wn=77.
// Hence WHEEL_STORAGE must be at least 78 to enable us to use ++ and not modulus

for (int i=0;i<6;i++) { // The 6 steps in the stream in a word
  // Any bit order will do, but we must decode it later
  if (wheelData[0*WHEEL_STORAGE+w0++]) result|=(1<<(0+5*i)); 
  if (wheelData[1*WHEEL_STORAGE+w1++]) result|=(1<<(1+5*i)); 
  if (wheelData[2*WHEEL_STORAGE+w2++]) result|=(1<<(2+5*i));
  if (wheelData[3*WHEEL_STORAGE+w3++]) result|=(1<<(3+5*i));
  if (wheelData[4*WHEEL_STORAGE+w4++]) result|=(1<<(4+5*i));
  __syncwarp();
}
keyStream[TX+32*TY+32*MAKE_BLOCK_DIM_Y*BX]=result;          
}
// ------------------------------------------------------------------------------
__global__ void compare(const int * __restrict__ keyStream,
                        unsigned int * __restrict__ successes,
                        const int * __restrict__ iPT_perm,
                        const int * __restrict__ iCT_popc,
    const int w0,const int w1,const int w2,const int w3,
	  const int w4,const int mask,const int limit,const int offset)
{
#define DATA_WORDS_NEEDED (1+CEIL_A_DIV_B(30+COMPARE_BLOCK_DIM_Y,6))
__shared__ int data[DATA_WORDS_NEEDED];

if (TY==0 && TX<DATA_WORDS_NEEDED) data[TX]=keyStream[offset+BX*STRIDE_IN_WORDS+TX];		
__syncthreads();

for (int perm=0;perm<120;perm++) {
  int xorkey=0x1F&(data[(TX+TY)/6]>>(5*((TX+TY)%6)));
  bool pass=((1<<TX)&mask)||(__popc(xorkey^iPT_perm[TX+32*perm])==iCT_popc[TX]);
  
  if (__all_sync(WHOLE_WARP,pass)) { // 'all' is all of 32 characters (all threads)
 
    int position=offset+BX*STRIDE_IN_WORDS*6+TY;
	if (TX==0 && position<limit) { // Only report once, not wrap-around results
	
	  if (results<MAX_RESULTS) { 
        int i=atomicAdd(&results,1); 
        successes[i*2+0]=position;    // 31 bits
        successes[i*2+1]=perm;        // 7 bits
	  } else if (!overflow) { printf("ERROR Results buffer full.\n"); overflow=TRUE; } 
    }
  }
}
}
// ------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
// We are run for a specific partition, i.e. 5 wheels.

int * deviceData;
int * deviceWheels;
int * devicePT_perm;
int * deviceCT_popc;
unsigned int * deviceResults;
unsigned int * hostResults;

// Bletchley Park notation for Sturgeon letters
char * BPsturgeon=(char *)"/E4A9SIU3DRJNFCKTZLWHYPQOBG+MXV8";  

int myWheelNos[] ={0,1,2,3,4};  // Defaults

if (argc<3) {
  printf("Incorrect arguments\n");
  printf("Use T52abKnownPT x abcde PT CT : Use GPU x, wheels abcde, and PT,CT \n");
  printf("Both PT/CT must use BP Sturgeon characters : %s, but PT can also use wildcard '?'\n",BPsturgeon);
  exit(0);
}

for (int i=0;i<5;i++) myWheelNos[i]=argv[2][i]-'0';
for (int i=0;i<5;i++) if (argv[2][i]>'9' || argv[2][i]<'0') { printf("Wheel no not in range 0-9\n"); exit(0); }

int specificWheels[5][WHEEL_STORAGE];
for (int i=0;i<5;i++) {
  for (int j=0;j<WHEEL_STORAGE;j++) {
	specificWheels[i][j]=patterns[myWheelNos[i]][j];
  }	
}
int iPT_perm[120][32];
int iCT_popc[32];

int length=32;    // Maximum
int wildcards=0;
int mask=0;  // Set bits indicate 'don't care' positions for matches
// We default to the smallest of plaintext/ciphertext, capped at 32
// We allow non-contiguous matches for a partial crib with '?' in PT
for (int i=0;i<32;i++) {
  char * ptr=strchr(BPsturgeon,argv[3][i]);
  if (argv[3][i]==0) { length=i; break; } // Terminating null
  if (argv[3][i]=='?') {
	mask|=(1<<i);
	wildcards++;
	iPT_perm[0][i]=0; // Dummy
  } else {
	if (!ptr) { printf("Invalid PT character %c\n",argv[3][i]); exit(0); }
    iPT_perm[0][i]=(int)(ptr-BPsturgeon);
  }
  ptr=strchr(BPsturgeon,argv[4][i]);
  if (argv[4][i]==0) { length=i; break; } // Terminating null
  if (!ptr) { printf("Invalid CT character %c\n",argv[4][i]); exit(0); }
  iCT_popc[i]=popc5((int)(ptr-BPsturgeon));
}
printf("T52ab CUDA Brute Force XOR Cracker for known PT : Matching Length=%d Effective length=%d Wheels=%s\n",
              length,(length-wildcards),argv[2]);

if (length<32) // Avoid C's undefined behaviour of <<
  mask|=(0xFFFFFFFF<<length);

for (int i=1;i<120;i++) { // Create all permuted copies of PT
  for (int j=0;j<32;j++) {
    iPT_perm[i][j]=perms[i][iPT_perm[0][j]];
  }
}

if (VERBOSE) {
  printf("GPU=%s Wheels=%d%d%d%d%d\n",argv[1],myWheelNos[0],myWheelNos[1],myWheelNos[2],
                                              myWheelNos[3],myWheelNos[4]);
  for (int i=2;i<argc;i++) printf("   %s\n",argv[i]);
}

if (findAndSetCUDADevice(atoi(argv[1]),VERBOSE)) exit(0);

#define EXEC_STREAMS (1)
cudaStream_t streamExec[EXEC_STREAMS];
for (int i=0;i<EXEC_STREAMS;i++) CC(cudaStreamCreate(&streamExec[i]));

int keyStreamLength=patternLength[myWheelNos[0]]*patternLength[myWheelNos[1]]*
      patternLength[myWheelNos[2]]*patternLength[myWheelNos[3]]*
	  patternLength[myWheelNos[4]]+40; // margin to avoid need for wrap
int wordsRequired=CEIL_A_DIV_B(keyStreamLength,6); 

// Since keyStreamLength and wordsRequired are functions of chosen wheels, so are Block and Grid dimensions

dim3 makeBlockDim(32,MAKE_BLOCK_DIM_Y);   
dim3 makeGridDim(CEIL_A_DIV_B(keyStreamLength,6*32*MAKE_BLOCK_DIM_Y));
dim3 compareBlockDim(32,COMPARE_BLOCK_DIM_Y);
dim3 compareGridDim(wordsRequired/STRIDE_IN_WORDS); // Margin above means we can do pure integer division

CC(cudaMalloc((void **)&deviceData,wordsRequired*sizeof(int)));
CC(cudaMalloc((void **)&deviceWheels,WHEEL_STORAGE*5*sizeof(int)));  // Only the 5 we are using 
CC(cudaMalloc((void **)&devicePT_perm,32*120*sizeof(int)));          // All perms of 32 char PT
CC(cudaMalloc((void **)&deviceCT_popc,32*sizeof(int))); 
CC(cudaMalloc((void **)&deviceResults,MAX_RESULTS*2*sizeof(unsigned int)));

CC(cudaMemcpy((void *)deviceWheels,specificWheels,WHEEL_STORAGE*5*sizeof(int),cudaMemcpyHostToDevice));
CC(cudaMemcpy((void *)devicePT_perm,iPT_perm,32*120*sizeof(int),cudaMemcpyHostToDevice));
CC(cudaMemcpy((void *)deviceCT_popc,iCT_popc,32*sizeof(int),cudaMemcpyHostToDevice));

CC(cudaHostAlloc((void **) &hostResults,MAX_RESULTS*2*sizeof(unsigned int),cudaHostAllocDefault));

for (int i=0;i<MAX_RESULTS*2;i++) hostResults[i]=0xFFFFFFFF;
CC(cudaMemcpy((void *)deviceResults,hostResults,2*MAX_RESULTS*sizeof(int),cudaMemcpyHostToDevice));

makeStreamPacked6perWord<<<makeGridDim,makeBlockDim,0,streamExec[0]>>>
           (deviceData,deviceWheels,patternLength[myWheelNos[0]],
	   patternLength[myWheelNos[1]],patternLength[myWheelNos[2]],
	   patternLength[myWheelNos[3]],patternLength[myWheelNos[4]]);

compare<<<compareGridDim,compareBlockDim,0,streamExec[0]>>>
       (deviceData,deviceResults,devicePT_perm,deviceCT_popc,
        myWheelNos[0],myWheelNos[1],myWheelNos[2],myWheelNos[3],myWheelNos[4],mask,
		patternLength[myWheelNos[0]]*patternLength[myWheelNos[1]]*
	    patternLength[myWheelNos[2]]*patternLength[myWheelNos[3]]*
		patternLength[myWheelNos[4]],0);
    
CC(cudaStreamSynchronize(streamExec[0]));
CC(cudaMemcpy(hostResults,deviceResults,MAX_RESULTS*2*sizeof(unsigned int),cudaMemcpyDeviceToHost))

for (int result=0;result<(MAX_RESULTS*2);result+=2) { 

  int tmp[5];
  int position=hostResults[result];
  int perm    =hostResults[result+1];
  
  if (position!=0xFFFFFFFF) {
	
    printf("Match with Wheel Order %d%d%d%d%d ",myWheelNos[fivePerm[perm][0]],
	              myWheelNos[fivePerm[perm][1]],myWheelNos[fivePerm[perm][2]],
		          myWheelNos[fivePerm[perm][3]],myWheelNos[fivePerm[perm][4]]);

    tmp[0]=position%patternLength[myWheelNos[0]]+1; // Historic representation starts at 1
    tmp[1]=position%patternLength[myWheelNos[1]]+1;
    tmp[2]=position%patternLength[myWheelNos[2]]+1;
    tmp[3]=position%patternLength[myWheelNos[3]]+1;
    tmp[4]=position%patternLength[myWheelNos[4]]+1;
	
    printf("Start points %d %d %d %d %d\n",           tmp[fivePerm[perm][0]],
	    tmp[fivePerm[perm][1]],tmp[fivePerm[perm][2]],tmp[fivePerm[perm][3]],
		tmp[fivePerm[perm][4]]);
  }
}

CC(cudaFree(deviceData));
CC(cudaFree(deviceWheels));
CC(cudaFree(devicePT_perm));
CC(cudaFree(deviceCT_popc));
CC(cudaFreeHost(hostResults));
CC(cudaFree(deviceResults));

for (int i=0;i<EXEC_STREAMS;i++) CC(cudaStreamDestroy(streamExec[i]));
cudaDeviceReset();  // CUDA exit -- flushes printf write buffer
return(0);
}
