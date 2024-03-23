CLANG ?= clang-14
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPFTOOL ?= /usr/local/sbin/bpftool

LIBBPF_TOP = /root/libbpf

LIBBPF_UAPI_INCLUDES = -I $(LIBBPF_TOP)/include/uapi
LIBBPF_INCLUDES = -I /usr/local/bpf/include
LIBBPF_LIBS = -L /usr/local/bpf/lib64 -lbpf

HS_INCLUDES = -I/usr/local/include/hs
HS_LIBS = -L/usr/local/lib -lhs

INCLUDES=$(LIBBPF_UAPI_INCLUDES) $(LIBBPF_INCLUDES) $(HS_INCLUDES)
INCLUDE_USR=$(LIBBPF_INCLUDES) $(HS_INCLUDES)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

all: build

build: hs_user

hs_kern.o: hs_kern.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c hs_kern.c

hs_user: hs_kern.o hs_user.c
	gcc -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDE_USR) $(CLANG_BPF_SYS_INCLUDES) -o hs_user hs_user.c $(LIBBPF_LIBS) -lelf -lz $(HS_LIBS) -lm -lstdc++


clean:
	rm hs_user hs_kern.o