# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Cisco and/or its affiliates.

VPP_DIR?=$(PWD)/../vpp

build_dir = $(PWD)/_build
debug_build_dir = $(build_dir)/debug
release_build_dir = $(build_dir)/release
common_flags =-g -fstack-protector -fno-common -Wall -Werror
debug_flags = -O0 $(common_flags) -DCLIB_DEBUG
release_flags =-O3 $(common_flags)

CFLAGS += -I./_build/debug/plugins

define configure
	@mkdir -p $($(1)_build_dir)
	@cd $($(1)_build_dir) && cmake -G Ninja \
	  -DCMAKE_PREFIX_PATH:PATH=$(VPP_DIR)/build-root/install-$(2)-native/vpp \
	  -DCMAKE_INSTALL_PREFIX::PATH=$(VPP_DIR)/build-root/install-$(2)-native/vpp \
	  -DCMAKE_C_FLAGS="$($(1)_flags)" \
	  $(PWD)
endef

$(debug_build_dir):
	$(call configure,debug,vpp_debug)

$(release_build_dir):
	$(call configure,release,vpp)

.PHONY: build build-release
build: $(debug_build_dir)
	@cmake --build $<

build-release: $(release_build_dir)
	@cmake --build $<

pkg-deb: build-release
	@cd $(release_build_dir) && cpack -G DEB
pkg-deb-debug: build
	@cd $(debug_build_dir) && cpack -G DEB

install: $(debug_build_dir)
	@cmake --build $< -- install

install-release: $(release_build_dir)
	@cmake --build $< -- install

run run-release debug debug-release:
	@make -C $(VPP_DIR) STARTUP_DIR=$(PWD) $@

test-debug: build
	make -C $(VPP_DIR) EXTERN_TESTS=$(PWD)/test EXTERN_APIDIR=$(debug_build_dir) EXTERN_PLUGINS=$(debug_build_dir)/lib/vpp_plugins $@
	# make -C $(VPP_DIR) EXTERN_APIDIR=$(debug_build_dir) EXTERN_TESTS=$(PWD)/test EXTERN_PLUGINS=$(debug_build_dir)/lib/vpp_plugins $@
	# @make -C $(VPP_DIR) EXTERN_APIDIR=$(debug_build_dir) EXTERN_TESTS=$(PWD)/test EXTERN_PLUGINS=$(debug_build_dir)/lib/vpp_plugins TEST=nataascpe DEBUG=gdb $@
test: build-release
	@make -C $(VPP_DIR) EXTERN_APIDIR=$(release_build_dir) EXTERN_TESTS=$(PWD)/test EXTERN_PLUGINS=$(release_build_dir)/lib/vpp_plugins TEST=nataas $@

check: build
	@ctest --test-dir $(debug_build_dir)

clean:
	@rm -rf $(build_dir)

fixstyle:
	@for i in plugins/*/*.[ch] plugins/*/*/*.[ch] ; do clang-format -i $$i; done

.PHONY: compdb
compdb:
	@ninja -C $(debug_build_dir) -t compdb \
	  $$(ninja -C $(debug_build_dir) -t rules \
	     | sed -ne '/C_COMPILER.*debug/p' -e '/C_COMPILER__vpptoys/p') \
	  | sed -e 's/-Werror/-Werror -Wno-unused-function/' \
	  | sed -e 's/-Werror/-Werror -include vppinfra\/format.h/' \
	  > compile_commands.json

.DEFAULT_GOAL := help
help:
	@echo "Make Targets:"
	@echo " build                - build debug binaries"
	@echo " build-release        - build release binaries"
	@echo " install              - install debug binaries"
	@echo " install-release      - install release binaries"
	@echo " run                  - run debug binary"
	@echo " run-release          - run release binary"
	@echo " test                 - run feature tests on release binary"
	@echo " test-debug           - run feature tests on debug binary"
	@echo " debug                - run debug binary with debugger"
	@echo " debug-release        - run release binary with debugger"
	@echo " clean                - wipe all build products"
	@echo " compdb               - (re)generate compile_commands.json"
	@echo " pkg-deb	             - build DEB packages"
	@echo " pkg-deb-debug        - build DEB debug packages"
	@echo ""
	@echo "Make Arguments:"
	@echo " VPP_DIR=<path>       - path to VPP directory"

