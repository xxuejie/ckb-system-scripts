cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/..

CLANG := $(shell $(TOP)/scripts/find_clang)
CLANGXX := $(subst clang,clang++,$(CLANG))

HFUZZ_CLANG := hfuzz-clang
HFUZZ_CLANGXX := hfuzz-clang++

AFLXX_CLANG := afl-clang-fast
AFLXX_CLANGXX := afl-clang-fast++

LLVM_FUZZER_SETTINGS := -fsanitize=fuzzer,address,undefined -fno-sanitize=alignment
HONGGFUZZ_SETTINGS := -fsanitize=address,undefined -fno-sanitize=alignment
AFLXX_SETTINGS := -fsanitize=address,undefined -fno-sanitize=alignment

COMMON_CFLAGS := -Wall -Werror -Wno-unused-function \
	-g -O3 -DFUZZING -I $(cur_dir)

USE_TEXT_PROTO :=
ifeq (true,$(USE_TEXT_PROTO))
	COMMON_CFLAGS += -DCKB_FUZZING_USE_TEXT_PROTO
endif
FUZZING_EMBED_DATA :=
ifeq (true,$(FUZZING_EMBED_DATA))
	COMMON_CFLAGS += -DFUZZING_EMBED_DATA
	export FUZZING_SKIP_HASH_CHECKING=1
endif

SCRIPT_CFLAGS := $(COMMON_CFLAGS) \
		-I $(TOP)/deps/molecule -I $(TOP)/deps/secp256k1/src -I $(TOP)/deps/secp256k1 \
		-I $(TOP)/c -I $(TOP)/build
LLVM_FUZZER_CFLAGS := $(COMMON_CFLAGS) \
	$(shell pkg-config --silence-errors --cflags libprotobuf-mutator) \
	-DCKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE
HONGGFUZZ_CFLAGS := $(COMMON_CFLAGS) \
	-DCKB_FUZZING_DEFINE_FILENAME_INTERFACE
AFLXX_CFLAGS := $(COMMON_CFLAGS) \
	-DCKB_FUZZING_DEFINE_AFLXX_INTERFACE

LDFLAGS := -lprotobuf
LLVM_FUZZER_LDFLAGS := $(LDFLAGS) $(shell pkg-config --silence-errors --libs libprotobuf-mutator)

DOCKER := docker
DOCKER_IMAGE := docker.io/xxuejie/ckb-script-fuzzing-toolkit:20250409
DOCKER_RUN_ARGS :=

FILES := $(shell find $(TOP)/c -type f -name "*.h" -o -name "*.c")

all: prepare build

repl:
	$(DOCKER) run --rm -it $(DOCKER_RUN_ARGS) -v $(TOP):/code $(DOCKER_IMAGE) || true
	$(DOCKER) run --rm $(DOCKER_RUN_ARGS) -e UID=`id -u` -e GID=`id -g` \
		-v $(TOP):/code $(DOCKER_IMAGE) bash -c 'chown -R -f $$UID:$$GID target fuzzing'

prepare: fuzzing_syscalls_all_in_one.h binary_to_text_converter
	./regenerate_corpus.sh

build: multisig_llvm_fuzzer multisig_honggfuzz_fuzzer multisig_aflxx_fuzzer

fuzzing_syscalls_all_in_one.h:
	curl -sSf https://raw.githubusercontent.com/xxuejie/ckb-script-fuzzing-toolkit/refs/heads/main/build_single_header.sh | sh

binary_to_text_converter: fuzzer.cc fuzzing_syscalls_all_in_one.h
	$(CLANGXX) $< -o $@ \
		$(COMMON_CFLAGS) -DCKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER \
		$(LDFLAGS)

multisig_llvm_fuzzer.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(CLANG) $(SCRIPT_CFLAGS) $(LLVM_FUZZER_SETTINGS) \
		-c $(TOP)/c/secp256k1_blake160_multisig_all.c -o $@

multisig_honggfuzz.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(HFUZZ_CLANG) $(SCRIPT_CFLAGS) $(HONGGFUZZ_SETTINGS) \
		-c $(TOP)/c/secp256k1_blake160_multisig_all.c -o $@

multisig_aflxx.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(AFLXX_CLANG) $(SCRIPT_CFLAGS) $(AFLXX_SETTINGS) \
		-c $(TOP)/c/secp256k1_blake160_multisig_all.c -o $@

multisig_llvm_fuzzer: multisig_llvm_fuzzer.o fuzzer.cc
	$(CLANGXX) $^ -o $@ $(LLVM_FUZZER_CFLAGS) $(LLVM_FUZZER_LDFLAGS) $(LLVM_FUZZER_SETTINGS)

multisig_honggfuzz_fuzzer: multisig_honggfuzz.o fuzzer.cc
	$(HFUZZ_CLANGXX) $^ -o $@ $(HONGGFUZZ_CFLAGS) $(LDFLAGS) $(HONGGFUZZ_SETTINGS)

multisig_aflxx_fuzzer: multisig_aflxx.o fuzzer.cc
	$(AFLXX_CLANGXX) $^ -o $@ $(AFLXX_CFLAGS) $(LDFLAGS) $(AFLXX_SETTINGS)

clean:
	rm -rf *.o *_fuzzer fuzzing_syscalls_all_in_one.h dumps corpus* binary_to_text_converter
.PHONY: build clean prepare repl
