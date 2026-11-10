# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# Builds the XDP object. Linux only (needs kernel UAPI + libbpf headers).

CLANG    ?= clang
OUT      ?= ../build/ebpf
ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu

BPF_CFLAGS := -target bpf -O2 -g -std=gnu11 \
	-Wall -Wextra -Werror -Wno-unused-parameter \
	-Iinclude -Isrc -I$(ARCH_INC)

SRCS := src/xdp_main.c
HDRS := $(wildcard include/*.h src/*.h)
OBJS := $(patsubst src/%.c,$(OUT)/%.o,$(SRCS))

.PHONY: all clean
all: $(OBJS)

$(OUT)/%.o: src/%.c $(HDRS)
	@mkdir -p $(OUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
