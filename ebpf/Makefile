# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# Builds the XDP object. Requirements: Linux, clang/llvm >= 16, libbpf
# headers (libbpf-dev >= 1.0), Linux UAPI headers (linux-libc-dev).
#
#   make                 build $(OUT)/em_xdp.bpf.o
#   make dump            disassemble the object with source interleaved
#   make clean

CLANG        ?= clang
LLVM_STRIP   ?= llvm-strip
LLVM_OBJDUMP ?= llvm-objdump
OUT          ?= build

OBJ  := $(OUT)/em_xdp.bpf.o
SRCS := src/em_xdp.c
HDRS := $(wildcard src/*.h)

# <asm/types.h> lives in the multiarch include dir on Debian/Ubuntu; clang
# -target bpf does not search it by default.
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
ARCH_INC  := $(if $(MULTIARCH),-idirafter /usr/include/$(MULTIARCH))

# -mcpu=v3: ALU32 + JMP32 + atomics (kernel >= 5.12; our floor is 6.1).
# -g is mandatory: it produces the .BTF/.BTF.ext sections libbpf needs for
# BTF-defined maps. DWARF is stripped afterwards; BTF stays.
BPF_CFLAGS := -g -O2 -target bpf -mcpu=v3 -std=gnu11 \
	-Wall -Wextra -Werror -Wno-unused-parameter \
	-I src $(ARCH_INC)

.PHONY: all dump clean
all: $(OBJ)

$(OUT):
	mkdir -p $@

$(OBJ): $(SRCS) $(HDRS) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -c $(SRCS) -o $@
	$(LLVM_STRIP) -g $@

dump: $(OBJ)
	$(CLANG) $(BPF_CFLAGS) -c $(SRCS) -o $(OUT)/em_xdp.debug.o
	$(LLVM_OBJDUMP) -d -S --no-show-raw-insn $(OUT)/em_xdp.debug.o

clean:
	rm -f $(OBJ) $(OUT)/em_xdp.debug.o
