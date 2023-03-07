LIB_CFLAGS ?= -fPIC -O3 -std=c99 -Wall -Wextra -Werror
AR_FLAGS ?= rcs

RANLIB ?= ranlib

LIB_CFLAGS += $(EXTRA_CFLAGS)

ifeq ($(GCC_ANALYZER),1)
LIB_CFLAGS += -fanalyzer
endif
ifeq ($(DEBUG),1)
LIB_CFLAGS += -g
endif
ifeq ($(WERROR),1)
LIB_CFLAGS += -Werror
endif
ifeq ($(USE_SANITIZERS),1)
LIB_CFLAGS += -fsanitize=undefined -fsanitize=address -fsanitize=leak
endif

CLANG :=  $(shell $(CROSS_COMPILE)$(CC) -v 2>&1 | grep clang)
ifneq ($(CLANG),)
LIB_CFLAGS += -Weverything -Werror \
                 -Wno-reserved-id-macro -Wno-padded \
                 -Wno-packed -Wno-covered-switch-default \
                 -Wno-used-but-marked-unused -Wno-switch-enum
# Add warnings if we are in pedantic mode
ifeq ($(PEDANTIC),1)
LIB_CFLAGS += -Werror -Walloca -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wvla -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum -Wbad-function-cast -Wconditional-uninitialized -Wconversion -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses -Wimplicit-fallthrough -Wloop-analysis -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32 -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive -Wthread-safety -Wthread-safety-beta -Wcomma
endif
# Clang version >= 13? Adapt
CLANG_VERSION_GTE_13 := $(shell echo `$(CROSS_COMPILE)$(CC) -dumpversion | cut -f1-2 -d.` \>= 13.0 | sed -e 's/\./*100+/g' | bc)
  ifeq ($(CLANG_VERSION_GTE_13), 1)
  # We have to do this because the '_' prefix seems now reserved to builtins
  LIB_CFLAGS += -Wno-reserved-identifier
  endif
else
LIB_CFLAGS += -W -Werror -Wextra -Wall -Wunreachable-code
# Add warnings if we are in pedantic mode
ifeq ($(PEDANTIC),1)
LIB_CFLAGS += -Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=2 -Wundef -Wstrict-prototypes -Wswitch-default -Wcast-align=strict -Wjump-misses-init
endif
endif

### C++ compilers quirks
# Do we have a C++ compiler instead of a C compiler?
GPP := $(shell $(CROSS_COMPILE)$(CC) -v 2>&1 | grep g++)
CLANGPP := $(shell echo $(CROSS_COMPILE)$(CC) | grep clang++)
# g++ case
ifneq ($(GPP),)
LIB_CFLAGS := $(patsubst -std=c99, -std=c++2a, $(LIB_CFLAGS))
LIB_CFLAGS += -Wno-deprecated
# Remove C++ unused pedantic flags
LIB_CFLAGS := $(patsubst -Wstrict-prototypes,,$(LIB_CFLAGS))
LIB_CFLAGS := $(patsubst -Wjump-misses-init,,$(LIB_CFLAGS))
LIB_CFLAGS := $(patsubst -Wduplicated-branches,,$(LIB_CFLAGS))
endif
# clang++ case
ifneq ($(CLANGPP),)
LIB_CFLAGS := $(patsubst -std=c99, -std=c++2a, $(LIB_CFLAGS))
LIB_CFLAGS += -Wno-deprecated -Wno-c++98-c++11-c++14-c++17-compat-pedantic -Wno-old-style-cast -Wno-zero-as-null-pointer-constant -Wno-c++98-compat-pedantic
endif

# Main hashes
HASHES = sha224.c sha256.c sha384.c sha512_core.c sha512.c sha512-224.c sha512-256.c sha3.c sha3-224.c sha3-384.c sha3-256.c sha3-512.c sm3.c shake.c shake256.c streebog.c ripemd160.c belt-hash.c bash.c bash224.c bash256.c bash384.c bash512.c
# Deprecated hashes
HASHES += gostr34_11_94.c md2.c md4.c md5.c mdc2.c sha0.c sha1.c tdes.c
# High level hash API
HASHES += hash.c
# HMAC
HASHES += hmac.c

ifneq ($(WITH_HASH_CONF_OVERRIDE),)
LIB_CFLAGS += $(WITH_HASH_CONF_OVERRIDE)
endif

ifeq ($(WNOERROR), 1)
# Sometimes "-Werror" might be too much, this can be overriden
LIB_CFLAGS := $(subst -Werror,,$(LIB_CFLAGS))
endif

all:	libhash.a

libhash.a: $(HASHES)
	$(CROSS_COMPILE)$(CC) $(LIB_CFLAGS) $(HASHES) -c
	$(CROSS_COMPILE)$(AR) $(AR_FLAGS) libhash.a *.o
	$(CROSS_COMPILE)$(RANLIB) $(RANLIB_FLAGS) libhash.a

clean:
	@rm -f *.o libhash.a
