# CUDAcryptanalysis

Various CUDA programs for cryptanalysis, these run from the command line and work with NVIDIA CUDA-caable GPUs

T52abKnownPT : takes a short ciphertext/plaintext pair and solve for the XOR wheels of the T52ab Sturgeon cipher machine.

The wheels (from the set 0-9) must be specified, although their order is immaterial.
Example usage : ./T52abKnownPT 0 01234 EVERYTHINGS9COMING9UP9MILHOUSE EEFNJAX/CRL+AMWAYFO8YBJQNNISI8
This uses GPU 0 and wheels 01234 to solve for the wheel order and the wheel start points.
