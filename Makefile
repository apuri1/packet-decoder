include Make.inc

BUILD_DIR=$(shell pwd)

DEPENDENCIES=$(BUILD_DIR)/deps

LKSCTP_VERSION=lksctp-tools-1.0.17
LKSCTP_PATH=$(DEPENDENCIES)/lksctp
LKSCTP_SPECIFIC_PATH=$(LKSCTP_PATH)/$(LKSCTP_VERSION)
LKSCTP_LIB= $(LKSCTP_SPECIFIC_PATH)/src/lib/.libs

JSON=$(DEPENDENCIES)/json


DECODERS=$(BUILD_DIR)/decoders

.PHONY: lksctp json decoders

all:    lksctp json decoders

lksctp:
	cd $(LKSCTP_PATH)/ && rm -rf $(LKSCTP_SPECIFIC_PATH) && tar xvzf $(LKSCTP_VERSION).tar.gz \
        && cd $(LKSCTP_VERSION) && unset LDFLAGS && unset CFLAGS && unset GCC && unset CC \
        && scl enable devtoolset-7 && ./configure && $(MAKE)

json:
	cd $(JSON); scl enable devtoolset-7 $(MAKE)

decoders:
	cd $(DECODERS); scl enable devtoolset-7 $(MAKE)

clean:
	cd $(DECODERS); $(MAKE) clean
	cd $(JSON); $(MAKE) clean
	rm -rf $(LKSCTP_SPECIFIC_PATH)


