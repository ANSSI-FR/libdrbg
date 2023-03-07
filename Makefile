LIBHASH_DIR = libhash

LIBHASH_SRC_DIR = $(LIBHASH_DIR)/
LIBHASH_BUILD_DIR = $(LIBHASH_DIR)/
LIBHASH_LIB = $(LIBHASH_BUILD_DIR)/libhash.a

AES_SRC_DIR = aes/
TDES_SRC_DIR = $(LIBHASH_SRC_DIR)
SELF_TESTS_SRC_DIR = drbg_tests/

CFLAGS ?= -O3 -fPIC -std=c99 -Wall -Wextra -I./ -I$(LIBHASH_SRC_DIR) -I$(AES_SRC_DIR) -I$(TDES_SRC_DIR) -I$(SELF_TESTS_SRC_DIR)

CFLAGS += $(EXTRA_CFLAGS)

# By default, activate all the backends
CFLAGS += -DWITH_HASH_DRBG -DWITH_HMAC_DRBG -DWITH_CTR_DRBG

# By default, activate all the BC (block ciphers)
CFLAGS += -DWITH_BC_TDEA -DWITH_BC_AES

# If we are asked to remove backend, remove it
ifeq ($(NO_HASH_DRBG),1)
CFLAGS := $(patsubst -DWITH_HASH_DRBG,,$(CFLAGS))
endif
ifeq ($(NO_HMAC_DRBG),1)
CFLAGS := $(patsubst -DWITH_HMAC_DRBG,,$(CFLAGS))
endif
ifeq ($(NO_CTR_DRBG),1)
CFLAGS := $(patsubst -DWITH_CTR_DRBG,,$(CFLAGS))
# NOTE: when removing the CTR DRBG, we can remove
# TDEA and AES
CFLAGS := $(patsubst -DWITH_BC_TDEA,,$(CFLAGS))
CFLAGS := $(patsubst -DWITH_BC_AES,,$(CFLAGS))
endif

# If we are asked to remove a BC, remove it
ifeq ($(NO_BC_TDEA),1)
CFLAGS := $(patsubst -DWITH_BC_TDEA,,$(CFLAGS))
endif
ifeq ($(NO_BC_AES),1)
CFLAGS := $(patsubst -DWITH_BC_AES,,$(CFLAGS))
endif


ifeq ($(GCC_ANALYZER),1)
ifeq ($(GCC),)
$(error "Sorry, you ask for GCC_ANALYZER with no GCC compiler!")
endif
CFLAGS += -fanalyzer
endif

ifeq ($(DEBUG),1)
CFLAGS += -g
endif
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif
ifeq ($(STATIC),1)
CFLAGS += -static
endif
ifeq ($(WITH_TEST_ENTROPY_SOURCE),1)
CFLAGS += -DWITH_TEST_ENTROPY_SOURCE
endif

LDFLAGS += -fPIE $(LIBHASH_LIB)

# By default, we activate the NIST strict mode unless
# the user overrides it
STRICT_NIST_SP800_90A ?= 1

ifeq ($(USE_SANITIZERS),1)
CFLAGS += -fsanitize=undefined -fsanitize=address -fsanitize=leak
endif
ifeq ($(VERBOSE),1)
CFLAGS += -DHASH_DRBG_SELF_TESTS_VERBOSE -DHMAC_DRBG_SELF_TESTS_VERBOSE -DCTR_DRBG_SELF_TESTS_VERBOSE
endif
ifeq ($(STRICT_NIST_SP800_90A),1)
CFLAGS += -DSTRICT_NIST_SP800_90A
ifeq ($(WITH_HASH_CONF_OVERRIDE),)
# When we are asked to use strict mode, we only need the SHA-1 and SHA-2 hashes
WITH_HASH_CONF_OVERRIDE  = -DWITH_HASH_CONF_OVERRIDE
WITH_HASH_CONF_OVERRIDE += -DWITH_HASH_SHA1 -DWITH_HASH_SHA224 -DWITH_HASH_SHA256 -DWITH_HASH_SHA384
WITH_HASH_CONF_OVERRIDE += -DWITH_HASH_SHA512 -DWITH_HASH_SHA512_224 -DWITH_HASH_SHA512_256
endif
endif
ifeq ($(SMALL_MEMORY_FOOTPRINT),1)
CFLAGS += -DSMALL_MEMORY_FOOTPRINT
endif

# Apply the hash configuration override
CFLAGS += $(WITH_HASH_CONF_OVERRIDE)

CLANG :=  $(shell $(CROSS_COMPILE)$(CC) -v 2>&1 | grep clang)
ifneq ($(CLANG),)
CFLAGS += -Weverything -Werror \
	  -Wno-reserved-id-macro -Wno-padded \
	  -Wno-packed -Wno-covered-switch-default \
	  -Wno-used-but-marked-unused -Wno-switch-enum
# NOTE: we use variadic macro aguments here ...
CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
# Add warnings if we are in pedantic mode
ifeq ($(PEDANTIC),1)
CFLAGS += -Werror -Walloca -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wvla -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum -Wbad-function-cast -Wconditional-uninitialized -Wconversion -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses -Wimplicit-fallthrough -Wloop-analysis -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32 -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive -Wthread-safety -Wthread-safety-beta -Wcomma
endif
# Clang version >= 13? Adapt
CLANG_VERSION_GTE_13 := $(shell echo `$(CROSS_COMPILE)$(CC) -dumpversion | cut -f1-2 -d.` \>= 13.0 | sed -e 's/\./*100+/g' | bc)
  ifeq ($(CLANG_VERSION_GTE_13), 1)
  # We have to do this because the '_' prefix seems now reserved to builtins
  CFLAGS += -Wno-reserved-identifier
  endif
else
CFLAGS += -W -Werror -Wextra -Wall -Wunreachable-code
# Add warnings if we are in pedantic mode
ifeq ($(PEDANTIC),1)
CFLAGS += -Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=2 -Wundef -Wstrict-prototypes -Wswitch-default -Wcast-align=strict -Wjump-misses-init
endif
endif

### C++ compilers quirks
# Do we have a C++ compiler instead of a C compiler?
GPP := $(shell $(CROSS_COMPILE)$(CC) -v 2>&1 | grep g++)
CLANGPP := $(shell echo $(CROSS_COMPILE)$(CC) | grep clang++)
# g++ case
ifneq ($(GPP),)
CFLAGS := $(patsubst -std=c99, -std=c++2a, $(CFLAGS))
CFLAGS += -Wno-deprecated
# Remove C++ unused pedantic flags
CFLAGS := $(patsubst -Wstrict-prototypes,,$(CFLAGS))
CFLAGS := $(patsubst -Wjump-misses-init,,$(CFLAGS))
CFLAGS := $(patsubst -Wduplicated-branches,,$(CFLAGS))
endif
# clang++ case
ifneq ($(CLANGPP),)
CFLAGS := $(patsubst -std=c99, -std=c++2a, $(CFLAGS))
CFLAGS += -Wno-deprecated -Wno-c++98-c++11-c++14-c++17-compat-pedantic -Wno-old-style-cast -Wno-zero-as-null-pointer-constant -Wno-c++98-compat-pedantic
# NOTE: we use variadic macro aguments here ...
CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
endif

ifeq ($(WNOERROR), 1)
# Sometimes "-Werror" might be too much, this can be overriden
CFLAGS := $(subst -Werror,,$(CFLAGS))
endif

PROG = drbg

SRCS  = $(wildcard *.c)
SRCS += $(wildcard $(AES_SRC_DIR)/*.c)
SRCS += $(wildcard $(SELF_TESTS_SRC_DIR)/*.c)
OBJS  = $(patsubst %.c,%.o,$(SRCS))

%.o: %.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -o $@ $<

drbg: $(OBJS) _libhash
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

_libhash:
	cd $(LIBHASH_DIR) && CROSS_COMPILE=$(CROSS_COMPILE) USE_SANITIZERS=$(USE_SANITIZERS) WERROR=$(WERROR) WITH_HASH_CONF_OVERRIDE="$(WITH_HASH_CONF_OVERRIDE)" LIB_CFLAGS="$(CFLAGS)" EXTRA_CFLAGS="$(EXTRA_CFLAGS)" make

all: _libhash $(OBJS) drbg

clean:
	@cd $(LIBHASH_DIR) && make clean
	@rm -f $(OBJS) drbg
