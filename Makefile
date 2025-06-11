#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2025 MNX Cloud, Inc.
#

NAME = cloud-load-balancer
DIR_NAME = clb
#
# Tools
#
RUST_TOOLCHAIN = 1.84.1


#
# Files
#
SMF_MANIFESTS    = smf/manifests/postboot.xml

ENGBLD_USE_BUILDIMAGE   = true
ENGBLD_REQUIRE          := $(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
include ./deps/eng/tools/mk/Makefile.rust.defs
TOP ?= $(error Unable to access eng.git submodule Makefiles.)

BUILD_PLATFORM  = 20210826T002459Z
include ./deps/eng/tools/mk/Makefile.smf.defs

ROOT            := $(shell pwd)
RELEASE_TARBALL := $(NAME)-pkg-$(STAMP).tar.gz
RELSTAGEDIR     := $(ROOT)/proto

#
# Repo-specific targets
#
DEHYDRATED = v1.5.4.1

CLEAN_FILES += bits dehydrated dehydrated.tar.gz target

# triton-origin-x86_64-21.4.0
BASE_IMAGE_UUID = 502eeef2-8267-489f-b19c-a206906f57ef
BUILDIMAGE_NAME = $(NAME)
BUILDIMAGE_DESC = Triton Cloud Load Balancer
BUILDIMAGE_PKGSRC = \
        openssl-1.1.1t \
        haproxy-2.6.1

dehydrated:
	mkdir $@
	curl --progress-bar -L -O https://github.com/TritonDataCenter/triton-dehydrated/releases/download/$(DEHYDRATED)/dehydrated.tar.gz
	gtar -zxvf dehydrated.tar.gz -C dehydrated

.PHONY: release_build
release_build: $(RS_FILES) | $(CARGO_EXEC)
	$(CARGO) build --release

.PHONY: debug
debug: $(RS_FILES) | $(CARGO_EXEC)
	$(CARGO) build

.PHONY: fmt
fmt: | $(CARGO_EXEC)
	$(CARGO) fmt

.PHONY: clippy
clippy: | $(CARGO_EXEC)
	$(CARGO) clippy

.PHONY: test
test: | $(CARGO_EXEC)
	$(CARGO) test

.PHONY: all
all: dehydrated release_build

.PHONY: release
release: all
	@echo "Building $(RELEASE_TARBALL)"
	@rm -rf $(RELSTAGEDIR)
	@mkdir -p $(RELSTAGEDIR)/root/opt/triton/boot
	@mkdir -p $(RELSTAGEDIR)/root/opt/triton/$(DIR_NAME)/
	@mkdir -p $(RELSTAGEDIR)/root/opt/triton/tls
	@mkdir -p $(RELSTAGEDIR)/root/opt/local/etc/haproxy.cfg
	@mkdir -p $(RELSTAGEDIR)/root/opt/custom/smf
	@mkdir -p $(RELSTAGEDIR)/site
	@touch $(RELSTAGEDIR)/site/.do-not-delete-me
	cp -PR $(ROOT)/dehydrated/ $(RELSTAGEDIR)/root/opt/triton/
	cp $(ROOT)/dehydrated.cfg $(RELSTAGEDIR)/root/opt/triton/dehydrated/config.overrides
	cp $(ROOT)/dehydrated-hook $(RELSTAGEDIR)/root/opt/triton/dehydrated/override-hook
	cp $(ROOT)/dhparam.pem $(RELSTAGEDIR)/root/opt/triton/tls
	cp $(CARGO_TARGET_DIR)/release/reconfigure $(RELSTAGEDIR)/root/opt/triton/$(DIR_NAME)/
	cp -PR $(ROOT)/smf/* $(RELSTAGEDIR)/root/opt/custom/smf/
	cp -PR $(ROOT)/templates/*.cfg $(RELSTAGEDIR)/root/opt/local/etc/haproxy.cfg/
	cp -PR $(ROOT)/boot/* $(RELSTAGEDIR)/root/opt/triton/boot/
	(cd $(RELSTAGEDIR) && $(TAR) -I pigz -cf $(ROOT)/$(RELEASE_TARBALL) root site)

.PHONY: install
install: release
	rm -rf /root/opt/triton/$(DIR_NAME)/
	rsync -av $(RELSTAGEDIR)/root/ /

.PHONY: check
check:: fmt clippy test
	@echo "Checking code quality"

.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/$(NAME)
	cp $(ROOT)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)

include ./deps/eng/tools/mk/Makefile.deps
include ./deps/eng/tools/mk/Makefile.rust.targ
include ./deps/eng/tools/mk/Makefile.smf.targ
include ./deps/eng/tools/mk/Makefile.targ
