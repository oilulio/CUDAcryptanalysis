# CUDAcryptanalysis

Various CUDA programs for cryptanalysis, these run from the command line and work with NVIDIA CUDA-capable GPUs

<b>T52abKnownPT</b> : takes a short ciphertext/plaintext pair and solve for the XOR wheels of the T52ab Sturgeon cipher machine.  the algorithm is explained at https://oilulio.wordpress.com/2022/04/06/cuda-versus-t52ab-known-plaintext/

The wheels (from the set 0-9) must be specified, although their order is immaterial.

Example usage : ./T52abKnownPT 0 01234 EVERYTHINGS9COMING9UP9MILHOUSE EEFNJAX/CRL+AMWAYFO8YBJQNNISI8

This uses GPU 0 and wheels 01234 to solve for the wheel order and the wheel start points.

the script scripts/PrepKnown.py will generate the 252 invocations to test all possible wheels
