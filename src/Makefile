objects1      = T52abKnownPT.obj     CUDAutil.obj
objects2      = T52abUnknownPT.obj   CUDAutil.obj

ARCH1 = compute_35
CODE1 = sm_35

#ARCH2 = compute_50
#CODE2 = sm_50

OPTS = -O3 -Wno-deprecated-gpu-targets

all: T52abKnownPT T52abUnknownPT T52cUnknownPT

T52abKnownPT: $(objects1)
	nvcc -arch=$(ARCH1) $(OPTS) $(objects1) -o T52abKnownPT

T52abUnknownPT: $(objects2)
	nvcc -arch=$(ARCH1) $(OPTS) $(objects2) -o T52abUnknownPT
	#nvcc -gencode arch=$(ARCH1),code=$(CODE1) -gencode arch=$(ARCH2),code=$(CODE2) $(OPTS) $(objects2) -o T52abUnknownPT

%.obj: %.cu
	nvcc -x cu -arch=$(ARCH1) $(OPTS) -I. -dc $< -o $@
	#nvcc -x cu -gencode arch=$(ARCH1),code=$(CODE1) -gencode arch=$(ARCH2),code=$(CODE2) $(OPTS) -I. -dc $< -o $@

clean:
	rm -f *.obj T52abKnownPT T52abUnknownPT

