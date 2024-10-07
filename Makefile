#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2024 MNX Cloud, Inc.
#


# The prebuilt sdcnode version we want. See
# "tools/mk/Makefile.node_prebuilt.targ" for details.
NODE_PREBUILT_VERSION=v6.17.1
ifeq ($(shell uname -s),SunOS)
        NODE_PREBUILT_TAG=zone64
        # minimal-64-lts@21.4.0
        NODE_PREBUILT_IMAGE=a7199134-7e94-11ec-be67-db6f482136c2
endif

NAME = lb

#
# Tools
#
NODEUNIT  := ./node_modules/.bin/nodeunit

#
# Files
#
JS_FILES        := $(shell find . -name '*.js')
ESLINT_FILES     = $(JS_FILES)
JSSTYLE_FILES    = server.js $(JS_FILES)
JSSTYLE_FLAGS    = -o indent=4,doxygen,unparenthesized-return=0,leading-right-paren-ok=1
SMF_MANIFESTS    = smf/manifests/$(NAME).xml

ENGBLD_USE_BUILDIMAGE   = true
ENGBLD_REQUIRE          := $(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
TOP ?= $(error Unable to access eng.git submodule Makefiles.)

BUILD_PLATFORM  = 20210826T002459Z

ifeq ($(shell uname -s),SunOS)
        include ./deps/eng/tools/mk/Makefile.node_prebuilt.defs
        # include ./deps/eng/tools/mk/Makefile.agent_prebuilt.defs
else
        NPM=npm
        NODE=node
        NPM_EXEC=$(shell which npm)
        NODE_EXEC=$(shell which node)
endif
include ./deps/eng/tools/mk/Makefile.smf.defs

ROOT            := $(shell pwd)
RELEASE_TARBALL := $(NAME)-pkg-$(STAMP).tar.gz
RELSTAGEDIR          := /tmp/$(NAME)-$(STAMP)

#
# Repo-specific targets
#
DEHYDRATED = v1.5.4.1

CLEAN_FILES += bits node_modules dehydrated dehydrated.tar.gz

# triton-origin-x86_64-21.4.0
BASE_IMAGE_UUID = 502eeef2-8267-489f-b19c-a206906f57ef
BUILDIMAGE_NAME = $(NAME)
BUILDIMAGE_DESC = TRITON-LOADBALANCER
BUILDIMAGE_PKGSRC = \
        openssl-1.1.1t \
        haproxy-2.6.1

dehydrated:
	mkdir $@
	curl --progress-bar -L -O https://github.com/TritonDataCenter/triton-dehydrated/releases/download/$(DEHYDRATED)/dehydrated.tar.gz
	gtar -zxvf dehydrated.tar.gz -C dehydrated

.PHONY: all
all: dehydrated

.PHONY: release
release: all
	@echo "Building $(RELEASE_TARBALL)"
	@mkdir -p $(RELSTAGEDIR)/root/opt/triton/boot
	@mkdir -p $(RELSTAGEDIR)/root/opt/triton/$(NAME)/build
	@mkdir -p ${RELSTAGEDIR}/root/opt/triton/dehydrated
	@mkdir -p ${RELSTAGEDIR}/root/opt/local/etc/haproxy.cfg
	@mkdir -p ${RELSTAGEDIR}/root/opt/custom/smf
	@mkdir -p $(RELSTAGEDIR)/site
	@touch $(RELSTAGEDIR)/site/.do-not-delete-me
	cp -PR $(NODE_INSTALL) $(RELSTAGEDIR)/root/opt/triton/$(NAME)/build/node || true
	cp -PR $(ROOT)/dehydrated/ $(RELSTAGEDIR)/root/opt/triton/dehydrated/
	cp -R ${ROOT}/dehydrated.cfg ${RELSTAGEDIR}/root/opt/triton/dehydrated/config.overrides
	cp -r \
    $(ROOT)/parser.js \
    $(ROOT)/haproxy.cfg \
    $(ROOT)/Makefile \
    $(ROOT)/package.json \
    $(RELSTAGEDIR)/root/opt/triton/$(NAME)/
	cp -R $(ROOT)/smf/* ${RELSTAGEDIR}/root/opt/custom/smf
	cp -R ${ROOT}/haproxy.cfg/* ${RELSTAGEDIR}/root/opt/local/etc/haproxy.cfg
	cp -R $(ROOT)/boot/* $(RELSTAGEDIR)/root/opt/triton/boot/
	(cd $(RELSTAGEDIR) && $(TAR) -I pigz -cf $(ROOT)/$(RELEASE_TARBALL) root site)
	@rm -rf $(RELSTAGEDIR)

.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/$(NAME)
	cp $(ROOT)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)

include ./deps/eng/tools/mk/Makefile.deps
ifeq ($(shell uname -s),SunOS)
        include ./deps/eng/tools/mk/Makefile.node_prebuilt.targ
        include ./deps/eng/tools/mk/Makefile.agent_prebuilt.targ
endif
include ./deps/eng/tools/mk/Makefile.smf.targ
include ./deps/eng/tools/mk/Makefile.targ


































