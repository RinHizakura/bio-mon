ARCH =

BUILD_FEATURE=

# AARCH64 build
ifeq ($(ARCH), aarch64)
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	CROSS_COMPILE = aarch64-unknown-linux-gnu
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)-gcc
	CARGO_OPT = --target $(CROSS_COMPILE)
	VMLINUX_BTF = vmlinux.btf
endif

# Host build
ifeq ($(ARCH), )
	CROSS_COMPILE =
	EXPORT_PATH =
	CARGO_OPT =

ifneq ("$(wildcard /sys/kernel/btf/vmlinux)", "")
	VMLINUX_BTF = /sys/kernel/btf/vmlinux
else
	VMLINUX_BTF = vmlinux.btf
endif

endif

OUT = target/$(CROSS_COMPILE)/debug

VMLINUX_H = vmlinux.h
BIN = $(OUT)/biomon
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

CFLAGS = -Wall -Wextra -Werror

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	$(EXPORT_PATH) cargo build $(BUILD_FEATURE) $(CARGO_OPT)

$(VMLINUX_BTF):
ifeq ($(VMLINUX), )
	$(error Please specific vmlinux with VMLINUX=)
endif
	pahole --btf_encode_detached $@ $(VMLINUX)

$(VMLINUX_H): $(VMLINUX_BTF)
	bpftool btf dump file $< format c > $@

clean:
	cargo clean
	$(RM) $(VMLINUX_H)
	$(RM) vmlinux.btf

