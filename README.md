# CUDAcryptanalysis

Various CUDA programs for cryptanalysis, these run from the command line and work with NVIDIA CUDA-capable GPUs

<b>T52abKnownPT</b> : takes a short ciphertext/plaintext pair and solve for the XOR wheels of the T52ab Sturgeon cipher machine.  The algorithm is explained at https://oilulio.wordpress.com/2022/04/06/cuda-versus-t52ab-known-plaintext/

The wheels (from the set 0-9) must be specified, although their order is immaterial.

Example usage : ./T52abKnownPT 0 01234 EVERYTHINGS9COMING9UP9MILHOUSE EEFNJAX/CRL+AMWAYFO8YBJQNNISI8

This uses GPU 0 and wheels 01234 to solve for the wheel order and the wheel start points.

the script scripts/PrepKnown.py will generate the 252 invocations to test all possible wheels

b>T52abUnknownPT</b> : takes a short ciphertext/plaintext pair and solve for the XOR wheels of the T52ab Sturgeon cipher machine.  The algorithm is explained at https://oilulio.wordpress.com/2022/04/08/cuda-versus-t52ab-unknown-plaintext/

The wheels (from the set 0-9) must be specified, although their order is immaterial.

Example usage : ./T52abUnknownPT 0 56789 GYLRTZAA8QFQIWNVFXPYJDDXFUWCM3UEUJX/FG3KUEWQGBGF+O9C94NUGOIJWPGROO4D9MGKJPKFXWH//DIYWLPYAY+EW/YXY/DANYETL9GIOPDYGOJQ4F+4MIHB8GUW9IY9B4DUA9LGKGUC4VLYRNJYBLHAJBEDE4AB9DHRNRC+FPY/GPDGLWPLEYLFQDUZKBNJW/AWEPQILPN/WYENKNMLCGYDHKNO+UPZSHJ4DTN9FGOBNS+OTSQXQF/WTKMHZP4JWZP9RNG8ONUYMZOV94THOOWIMTMCWWVO9DVSAQDX3MSBEZOPXVYBOKB+YDXWYJP/NHCA3QKEPJ/VQWJRGJBVEE3UCTDMNMSTZ/DSTOFQ9ATQYLPFYHHMCFIKK+UYEOUWOSEPWFXGDYFQXB+8DA4UPFRIQQM4WDC9KGAZ9ICPCGQPZ8PKSJU998TXMIXYNILKC9QHB9EECIA8ZBNIS3XOGQ9ZS398I+MKFQX9KT4MF94PVVZJ

This uses GPU 0 and wheels 56789 to solve for the wheel start points.

the script scripts/PrepUnknown.py will generate the 252 invocations to test all possible wheels
