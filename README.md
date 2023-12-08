[![compilation](https://github.com/ANSSI-FR/libdrbg/actions/workflows/libdrbg_compilation_tests.yml/badge.svg?branch=main)](https://github.com/ANSSI-FR/libdrbg/actions/workflows/libdrbg_compilation_tests.yml)

# libdrbg project
Copyright (C) 2022

This software is licensed under a dual BSD and GPL v2 license.
See [LICENSE](LICENSE) file at the root folder of the project.

## Authors

  * Ryad BENADJILA (<mailto:ryadbenadjila@gmail.com>)
  * Arnaud EBALARD (<mailto:arnaud.ebalard@ssi.gouv.fr>)

## Description

This software implements DRBG (Deterministic Random Bit Generators) as
specified in the [NIST Special Publication 800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
standard. Namely, it implements the three standardized variants:
  * <ins>Hash-DRBG</ins>: DRBG based on hash functions.
  * <ins>HMAC-DRBG</ins>: DRBG based on HMAC.
  * <ins>CTR-DRBG</ins>: DRBG based on block ciphers in counter mode.

The current implementations of Hash-DRBG and HMAC-DRBG go beyond the
strict list of the specified hash functions in the standard (only
SHA-{1,224,256,384,512,512-224,512-256} are allowed in the
standard): they accept any of the following hash functions - or HMAC based
on them - that are implemented in the internal `libhash` subproject:
  * SHA-{224,256,384,512,512-224,512-256}, SHA-3-{224,256,384,512},
  RIPEMD-160, SM3, STREEBOG-{256,512} ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986)),
  SHAKE-256 (with 114 bytes output),
  BELT-HASH ([STB 34.101.31-2011](https://github.com/bcrypto/belt)),
  BASH-{224,256,384,512} ([STB 34.101.77-2020](http://apmi.bsu.by/assets/files/std/bash-spec24.pdf)).
  * Deprecated hash functions: SHA-{0,1}, MD-{2,4,5}, MDC2, GOST34-11-94.

**NOTE**: please consider the deprecated hash functions with care, as they are
mainly here for compatibility and tests reasons.
By **default**, the strict NIST mode is activated meaning that only
SHA-{1,224,256,384,512,512-224,512-256} hash functions are activated during
compilation. It is possible to force the strict NIST mode using `STRICT_NIST_SP800_90A=1`
or to force its deactivation with the `STRICT_NIST_SP800_90A=0` toggle during compilation.
Beware that SHA-1 is in the list of the available hashes for conformance
with the standard but should **not be used** as it is deprecated and broken
by [practical collision attacks](https://shattered.io/).

The implementation of CTR-DRBG strictly conforms to the standard as only AES and
TDEA (TDES) are supported as possible block ciphers, although it would be possible
to (easily) expand the library with other block ciphers. Please note that TDEA is in
the process of [being fully deprecated](https://csrc.nist.gov/news/2017/update-to-current-use-and-deprecation-of-tdea),
hence AES is the only choice in practice for production code.

All the variants of the NIST standard should be implemented and selectable through
options: with Prediction Resistance or not, with DF or not, etc. This exhaustive
compatibility has been one of the leitmotivs of developing the library as we have
not found small, portable and complete implementations in C (one of the most complete
implementations is in the [Linux kernel](https://github.com/torvalds/linux/blob/master/crypto/drbg.c)
but its adherence to external modules makes it hard to be used in a standalone fashion).

The source code is pure C-99 only using `stdint.h` (mainly for `uint` with strict sizes types),
`stdbool.h` (for booleans), and basic `stdlib.h` (mainly for `memcpy`, `memset` and `memcmp`).
It should be compatible with any decent C (or C++) compiler, and portable across platforms as
no external dependency is needed. **No allocation** is used across the project, which
makes it suitable for embedded contexts.
Finally, `printf` is used but only in the tests and main files using the DRBG API: the core
files and algorithms do not use it.

The source code aims at being portable and compatible with as many platforms as possible,
but the low-level primitive APIs should be simple enough and self-explanatory to replace
the underlying algorithms with assembly optimized and/or hardware accelerated alternatives.
For instance on recent Intel and AMD `x86` platforms, the AES encryption core in [aes/aes.c](aes/aes.c) can be replaced
with [AES-NI](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf)
instructions to accelerate the CTR-DRBG backend, and the SHA-{1,224,256} in `libhash` can
be replaced with [Intel SHA extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)
to accelerate the Hash-DRBG and HMAC-DRBG backends.

## Compiling

Compiling is as simple as:

<pre>
	$ make
</pre>

Some options can be provided in the form of toggles:
  * `STRICT_NIST_SP800_90A=0` will deactivate the strict mode for the hash functions.
  When `WITH_HASH_CONF_OVERRIDE` is not used (see below), the NIST approved hash functions
  are selected for compilation, and checked at runtime (namely SHA-1, SHA-224, SHA-512-224, SHA-256,
  SHA-512-256, and SHA-512).
  * `SMALL_MEMORY_FOOTPRINT=1` will use small footprint implementations, this mostly
  concerns AES where table based or compact SBOX variants are selected.
  * `VERBOSE=1` will activate self-tests verbosity.
  * `USE_SANITIZERS=1` will compile with the sanitizers (address, undefined behaviour, leak).
  This is useful for checks before shipping production code, but usually heavily impacts performance
  and hence should be deactivated when not debugging. However, if performance is not an issue, it
  is advised to leave them as they will catch (potentially dangerous) runtime errors.
  * `PEDANTIC=1` allows to activate strict(er) compilation flags (by default the usual
  `-Wall -Wextra -Wunreachable-code -Werror` is used, this activates more picky options).
  * `WNOERROR=1` will force compilation **without** the `-Werror` flag, i.e. compiler warning
  are not treated as errors (this can be useful for cases where some warnings are false
  alarms or for toolchains with picky warnings).
  * `WITH_TEST_ENTROPY_SOURCE=1` activates a default entropy backend depending on the OS
  (`/dev/random` on UNIX based including MacOS, crypto provider under Windows). See
  [entropy.c](entropy.c) for more details. These implementations are examples, and you are
  encouraged to add more entropy sources to improve them (see the discussion below).
  * `NO_XXX_DRBG=1` is used to remove a specific DRBG backend (where `XXX` is one of `HASH`,
  `HMAC` or `CTR`). More than one toggle can be specified, but beware that removing the three
  backends all together will trigger a compilation error.
  * `NO_BC_TDEA=1` and/or `NO_BC_AES=1` are used to remove TDEA and AES algorithms when they
  are not necessary (i.e. the user wants to use the CTR-DRBG without one of the algorithms).
  Beware that removing both TDEA and AES will render the CTR-DRBG unusable.
  * `DEBUG=1` activates the `-g` options to embed the symbols and make debugging sessions
  easier (should not be activated for production code).
  * `WITH_HASH_CONF_OVERRIDE` is used to select an explicit subset of the hash functions, see
  below for more details. Beware that using this flag will **override** the NIST strict
  hash functions list in any case, but if the strict mode is active checks will be performed
  at runtime (meaning that only the subset of hash functions present in `WITH_HASH_CONF_OVERRIDE`
  and conforming to the standard will be accepted, the others will trigger an error).
  * `GCC_ANALYZER=1` is used to activate the `gcc` static analyzer. This is only relevant
  for `gcc` versions >= 10 (where this static analyzer has been introduced).

It is possible to provide (cross-)compilation options using the toggles:
  * `CC=XXX` that will use the `XXX` compiler.
  * `CROSS_COMPILE=YYY` that will use the `YYY` prefix for a toolchain (e.g. `arm-none-eabi-`).
  * `EXTRA_CFLAGS=ZZZ` will add additional user defined `CFLAGS`.

For example, the following invocation will compile the project using the `sparc64-linux-gnu-` toolchain
and produce a `static` ELF binary (that it will be possible to emulate with `qemu-user` for instance):
<pre>
        $ make clean && CROSS_COMPILE=sparc64-linux-gnu- CC=gcc WITH_TEST_ENTROPY_SOURCE=1 VERBOSE=1 EXTRA_CFLAGS="-static" make
</pre>

`WITH_TEST_ENTROPY_SOURCE=1` activates the default entropy source on the OS (as we use a Linux based
toolchain, `/dev/random` is used) and `VERBOSE=1` activates verbose self-tests. Note that the same
compilation could have been equally performed with `CC=sparc64-linux-gnu-gcc`.

Another example of coss-compilation is for Windows using the MinGW toolchain:
<pre>
        $ make clean && WNOERROR=1 CROSS_COMPILE=i686-w64-mingw32- CC=gcc WITH_TEST_ENTROPY_SOURCE=1 EXTRA_CFLAGS="-static" make
</pre>


As we target embedded and constrained platforms, we also provide ways to only embed a subset of the hash
functions in order to decrease the (flash) memory footprint:
  * The [libhash/libhash_config.h](libhash/libhash_config.h) configuration file where it is possible
  to only select the needed hash functions.
  * The more convenient `WITH_HASH_CONF_OVERRIDE` toggle can be used when compiling to tune the hash
  functions list to be embedded. Remember to deactivate the NIST strict mode with `STRICT_NIST_SP800_90A=0`
  when hash functions not approved by the standard are selected.

For example, the following invocation will only select SHA-256 and SHA-3-256 (note the `STRICT_NIST_SP800_90A=0`
as SHA-3-256 is not in the standard approved list):
<pre>
        $ STRICT_NIST_SP800_90A=0 WITH_HASH_CONF_OVERRIDE="-DWITH_HASH_CONF_OVERRIDE -DWITH_HASH_SHA256 -DWITH_HASH_SHA3_256" make
</pre>

**NOTE**: please beware that when selecting specific hash functions, it is still possible to ask for the
non-selected ones in the API but an **error** will be triggered by the main wrapper at initialization
or instantiation. Hence, depending on the selected primitives self-tests might fail (for good reasons
when the concerned hash functions are not compiled!).

**NOTE**: using `WITH_HASH_CONF_OVERRIDE` will override `STRICT_NIST_SP800_90A` selection of
hash functions for compilation (but the strict runtime check still holds, meaning that the user
must be careful when using these two toggles together).

**NOTE**: since `libhash.a` is an autonomous compilation unit, and since the DRBG source code
depends for Hash-DRBG and HMAC-DRBG on the `MAX_DIGEST_SIZE` static size (that is statically computed
from the embedded hashes), some kind of **compilation time sanity check** is used to ensure that
the compiled `libhash` is on par with the currently compiled sources of the DRBG algorithm. This
sanity check is in [libhash/hash.h](libhash/hash.h), and it will trigger a compilation error when
an inconsistency is detected.

Using the `NO_BC_TDEA=1` and `NO_BC_AES=1` toggles will remove either TDEA or AES, or both when used
together. In this last case, the CTR-DRBG becomes an empty shell as no block cipher is usable then.

There is a specific compilation selection for the backends (e.g. when one only
wants to use Hash-DRBG and not the other backends). By default, the **three backends** are
activated. If one wants to remove a specific backend, a `NO_XXX_DRBG=1` toggle can be used,
where `XXX` can be either `HASH`, `HMAC` or `CTR`. For example, to remove the CTR-DRBG you can
use:

<pre>
        $ NO_CTR_DRBG=1 make
</pre>

Removing the three backends will trigger a compilation error as at least one is required:

<pre>
        $ NO_CTR_DRBG=1 NO_HASH_DRBG=1 NO_HMAC_DRBG=1 make
	...
	drbg_common.h:18:2: error: #error "No DRBG backend compiled! Please activate at least one!"
   18 | #error "No DRBG backend compiled! Please activate at least one!"
</pre>


## APIs and architecture

The project can be mainly divided in five parts:
  * The **main DRBG APIs** in [drbg.c](drbg.c) and [drbg.h](drbg.h). These APIs consist in the usual
  `drbg_instantiate`, `drbg_generate`, `drbg_reseed` and `drbg_uninstantiate` as specified in
  the SP800-90A publication. For power users, specific options can be passed to drbg_instantiate().
  * The three possible **backends** to the DRBG: Hash-DRBG, HMAC-DRBG and CTR-DRBG. The main DRBG APIs
  are "plugged" to the backend and transparently use them depending on the type of DRBG that has been
  instantiated. It is also possible to access, for each backend, to the dedicated raw APIs: for example,
  [hash_drbg.h](hash_drbg.h) exposes `hash_drbg_instantiate`, `hash_drbg_generate`, `hash_drbg_reseed`,
  and `hash_drbg_uninstantiate`. Each backend exposes a unified API in the form of **callbacks** in
  a `drbg_methods` structure (see [drbg_common.h](drbg_common.h)).
  * The **hash library** `libhash` in the [libhash/](libhash/) folder that contains all the hash primitives
  used by the DRBG backends. This should be a standalone library with its dedicated `Makefile`.
  * The **AES block cipher** implementation in the [aes/](aes/) folder. Please note that the **TDEA implementation**
  actually comes with `libhash` as it is used by the MDC2 hash function. AES and TDEA are only used in the
  CTR-DRBG.
  * The **self-tests** framework and tests extracted from the NIST test vectors in the [drbg_tests/](drbg_tests/)
  folder, as well as a [main.c](main.c) `main` file that provides API usage examples as well as self-tests
  execution.

The NIST test vectors are extracted and formatted for our framework from the original
[CAVS 14.3](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators#DRBG) NIST tests.
This explains the rather large sizes of header files in [drbg_tests/test_vectors/](drbg_tests/test_vectors/): please note
that these must of course **NOT** be included "as is" when compiling for constrained devices. Only a subset
of representative self-tests should be included to preserve the memory footprint (the full set of NIST tests
is present for completeness).

### Basic usage of the DRBG API

**Instantiating** a DRBG without specific option is very simple. For instance, to instantiate a
Hash-DRBG with a security strength of 128 bits and no Prediction Resistance:

```c
drbg_ctx drbg;
drbg_error ret;
const unsigned char pers_string[] = "DRBG_PERS";
uint32_t asked_strength = 128;

/* '128' is the desired security strength, 'false' is the Prediction Resistance flag,
 * and the last NULL argument is for "NULL" specific options.
 *
 */
ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1, &asked_strength, true,
                       DRBG_HASH, NULL);
if(ret != DRBG_OK){
...
/* The asked_strength is updated with the "real" instantiated strength, which will be
 * greater than or equal to given one.
 */
```

Then it is possible to **generate** random bits without additional data and no Prediction Resistance
request:
```c
unsigned char output[1024] = { 0 };
/* NULL and 0 are additional data: none here, and we generate with
 * no Prediction Resistance request.
 */
ret = drbg_generate(&drbg, NULL, 0, output, sizeof(output), false);
if(ret != DRBG_OK){
...
```

It is also possible to explicitly **reseed** the instance (with no Prediction Resistance
request and no additional data):
```c
/* NULL and 0 are additional data: none here, and we reseed with
 * no Prediction Resistance request.
 */
ret = drbg_reseed(&drbg, NULL, 0, false);
if(ret != DRBG_OK){
...
```

You can of course adapt the additional data and Prediction Resistance flags and requests at
your will.

Finally, it is possible to **uninstantiate** a DRBG using:
```c
ret = drbg_unsinsantiate(&drbg);
if(ret != DRBG_OK){
...
```

**NOTE**: please refer to the standard for more insight on how these notions (additional data,
prediction resistance, etc.) interact, since incompatible combinations will trigger an error.

This simple usage of the API will automatically choose the most appropriate algorithm (hash for
Hash-DRBG/HMAC-DRBG and block cipher for CTR-DRBG) depending on the asked security strength.
<span style="color:red">Behind the scene, these APIs make calls to the `get_entropy_input`
callback that brings the necessary entropy to the critical steps of the DRBG. Please see below
the dedicated section on entropy for more information on how **critical** this is and what the
user should implement</span>.

Finally, extended versions of these APIs exist, where the user can instead directly provide his own
entropy in buffers and where no call to `get_entropy_input` is performed, so that the user can
completely control the DRBG.

### Advanced usage of the DRBG API

1) <ins>**Using dedicated options**:</ins>

For each DRBG type, some options can be possibly provided when instantiating.
For **Hash-DRBG** and **HMAC-DRBG**: it is possible to specify the underlying hash function to be used using
the dedicated `DRBG_HASH_OPTIONS_INIT` and `DRBG_MAC_OPTIONS_INIT`.

```c
drbg_error ret;
drbg_ctx drbg
drbg_options opt;
uint32_t asked_strength = 128;
DRBG_HASH_OPTIONS_INIT(opt, HASH_RIPEMD160); /* Use RIPEMD-160 as hash */
ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1,
                       &asked_strength, true, DRBG_HASH, &opt);
...
DRBG_HMAC_OPTIONS_INIT(opt, HASH_SHA3_256); /* Use SHA-3-256 as hash */
ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1,
                       NULL, true, DRBG_HMAC, &opt);
...
/* Get the actual security strength of the instance */
ret = drbg_get_drbg_strength(&drbg, &security_strength);
...
```

For **CTR-DRBG**: it is possible to specify the underlying block cipher to be used (AES, TDEA),
if a DF (Derivation Function) is used or not, and the "counter" size (please refer to the standard
for more insight on these options). For the counter, a specific value of `0` means that the backend
will choose the default value (as 0 is a forbidden value by the specification), which is encryption
function block size.

```c
drbg_error ret;
drbg_ctx drbg
drbg_options opt;
uint32_t asked_strength = 100;
DRBG_CTR_OPTIONS_INIT(opt, CTR_DRBG_BC_TDEA, true, 5); /* Use TDEA, a derivation function
                                                        * and a counter on 5 bytes */
ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1,
                       &asked_strength, true, DRBG_CTR, &opt);
...
DRBG_CTR_OPTIONS_INIT(opt, CTR_DRBG_BC_AES, false, 0); /* Use AES, no derivation function
                                                        * and a counter on default size
                                                        * (block size of AES here,
                                                        * i.e. 16 bytes) */
asked_strength = 100;
ret = drbg_instantiate(&drbg, pers_string, sizeof(pers_string) - 1,
                       &asked_strength, true, DRBG_CTR, &opt);
...
```
**NOTE**: when both options and strength are passed to `drbg_instantiate`, the actual strength is
compared to the one associated with the options and if it is less than the asked strength, an error
is returned. `NULL` can be passed in place of an `asked_strength`, in which case the options are applied
and the actual strength is internally computed, and can be checked later by the user through the
`drbg_get_drbg_strength` API after instantiation or using the `drbg_get_lengths` API before or after
instantiation.

**NOTE**: please beware that the user is **responsible** of the options he provides and the possible
inconsistencies that they can raise. A major inconsistency is regarding the DRBG strength that can vary
depending on the options, and the `drbg_instantiate` and similar backend APIs will return errors when
the strength and the options are inconsistent, or when the options are incompatible. Also, when calling
`drbg_generate` the maximum size that can be requested also depends on these options. You can check this
size using the `drbg_get_max_asked_length` API after instantiation.

**NOTE**: these options are passed to the backend APIs, so if it is more convenient to directly use the
backend, it is possible to perform:
```c
drbg_error ret;
drbg_ctx drbg
drbg_options opt;

DRBG_HASH_OPTIONS_INIT(opt, HASH_RIPEMD160); /* Use RIPEMD-160 as hash */
ret = drbg_hash_instantiate(&drbg, entropy_input, sizeof(entropy_input_input),
                            nonce, sizeof(nonce), pers_string, sizeof(pers_string) - 1,
                            NULL, true, &opt);
...
```

2) <ins>**Advanced DRBG API**:</ins>

As exposed in [drbg.h](drbg.h), in addition to the simple and straightforward APIs for the DRBG,
advanced APIs exist: `drbg_instantiate_with_user_entropy`, `drbg_generate_with_user_entropy` and
`drbg_reseed_with_user_entropy`. These APIs take additional parameters that will replace calls to
`get_entropy_input` with user provided buffers, for the `entropy_input` and the `nonce` buffers.
<span style="color:red">Please refer to the standard to understand the ins and outs of these parameters,
and why the entropy quality of these buffers is critical</span>.

**NOTE**: the advanced APIs are in fact a generalization of the simple APIs since providing a **NULL**
buffer for `entropy_input` or `nonce` will instead make calls to `get_entropy_input` when getting
these data.

**NOTE**: these advanced APIs are mainly here for situations where the user wants a full control
over the entropy buffers, and/or when the `get_entropy_input` API rationale does not fit the specific
use case. Use these APIs with care and knowingly.

3) <ins>**Accessing the DRBG backends API**:</ins>

Each one of the DRBG backend exposes its own API (Hash-DRBG in [hash_drbg.h](hash_drbg.h),
HMAC-DRBG in [hmac_drbg.h](hmac_drbg.h), CTR-DRBG in [ctr_drbg.h](ctr_drbg.h)) offering
dedicated low-level `instantiate`, `reseed`, `generate`, `uninstantiate` as specified in the
standard, as well as a `get_lengths` API. The same unified `drbg_ctx` context type is used, and
in order to access the internal data of an instance the user can dereference the dedicated fields
as exposed in [drbg_common.h](drbg_common.h):

```c
struct drbg_ctx {
        /* Elements specific to high level interface */
        uint64_t magic;
        bool is_instantiated;
        drbg_type type;

        /* Elements common to all engines */
        uint64_t engine_magic;
        uint32_t drbg_strength; /* in bits */
        uint32_t min_entropy_input_length;
        uint32_t max_entropy_input_length;
        uint32_t max_pers_string_length;
        uint32_t max_addin_length;
        uint32_t max_asked_length;
        uint64_t reseed_counter;
        uint64_t reseed_interval;
        bool engine_is_instantiated;
        bool prediction_resistance;
        bool reseed_required_flag;

        /* Methods for the current engine */
        drbg_methods *methods;

        /* Data/state specific to current engine */
        engine_data data;
};
```

As we can see, data common to all engines (e.g. the `drbg_strength`) can be accessed using
`ctx->drbg_strength` where `ctx` is the pointer to the `drbg_ctx` context. Beware that the
engine **must be instantiated** for these fields to be meaningful (i.e. `engine_is_instantiated`
is `true` after a call to the `instantiate` method, and the `engine_magic` set to the proper
value).

Beyond the data common to all engines, the context **specific to each engine** is in the
`engine_data` union, also defined in the [drbg_common.h](drbg_common.h) file for each
DRBG type. You can access internal data though this union: for example, accessing the
`V` internal value of the Hash-DRBG instance can be done using the following
accessor:

```c
ctx->data.hash_data.V
```

**NOTE**: please note that accessing the low-level raw DRBG contexts data while bypassing
the exposed APIs is not a "nominal" use case of the library, it is possible to do so for
advanced usages, expanding/modifying the library or advanced debugging purposes. In any case,
be aware that reading such raw data can be **hazardous** (depending on the instantiation state of
the DRBG), and writing/modifying them can be **dangerous**. Use at your own risks.

## About entropy and entropy sources

### Entropy quality
The three DRBG backends (Hash-DRBG, HMAC-DRBG, CTR-DRBG) are **deterministic engines**, while the upper level
main DRBG algorithm makes use of **external entropy sources** during its instantiation and its reseeding.
All-in-all, the current implementation is about the algorithmic core of DRBGs: bad entropy sources will
result in bad randomness no matter the post-processing primitive is (although some guarantees such as backward
and/or forward secrecy - also called backtracking and predictive resistance - are ensured when using the DRBG
engine, as an inherent property of the design depending on the Prediction Resistance option). The security
of your instantiation of any DRBG will heavily rely on the security and non-predictability of the entropy sources.

Such entropy sources are implemented in the [entropy.c](entropy.c) source file, with the `get_entropy_input`
API. This **MUST be provided** by the user following the recommendations of
[NIST SP 800-90B "Recommendation for the Entropy Sources Used for Random Bit Generation"](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90b.pdf),
with ideally multiple sources that are mixed (e.g. with a `xor`, and with at least one high quality random source, e.g.
using a Physical/True Random Number Generator in the form of a hardware IP whose stochastic model has been
formally specified and physical model analyzed). A valuable resource on this topic is also the BSI
[AIS20/31](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/Interpretationen/AIS_31_pdf.html).

Although entropy sources are NOT the subject of the current project, here are some high level hints:
  * When hardware entropy is available such as [Intel's `rdrand`](https://en.wikipedia.org/wiki/RDRAND) or
  equivalent it is advised to use it among the sources.
  * Physical noise when available through a sensor can be a valuable source, but beware of the real entropy
  brought (as quantization can be applied by the sensor) as well as the fact that a potential attacker can
  inject faulty measures or manipulate the environment (e.g bring heat or cold on a temperature sensor).
  * It is always advised to process the raw entropy sources using dedicated entropy extractors and mixers.
  * On a wide range of CPUs, it is possible to use highly volatile (parts of) counters, such as performance
  counters and/or CPU cycles counters, as (cheap) entropy sources. See [here](https://lwn.net/Articles/642166/) and
  [here](https://www.pcg-random.org/posts/simple-portable-cpp-seed-entropy.html) for interesting discussions
  about this. Beware however of the limitation of the quality of such sources (implying processing multiple
  samples to extract low bit-rate entropy), as well as possible "fault injections" of an attacker that
  controls the software/hardware environment (OS, hypervisor catching and emulating instructions, performance
  counters poisoning with cache and branch prediction flooding, backdoored hardware, etc.).
  * It is possible to "chain" DRBGs, meaning that a DRBG is used as an entropy source for another DRBG: in this
  case the DRBG is used as entropy post-processing. This design pattern, although very acceptable, does obviously
  not prevent from feeding at least the "last" DRBG with "real" entropy sources. Beware that if you choose such an
  approach when using the current library, you will at some point have to use the **advanced API** or implement
  calling DRBG awareness in `get_entropy_input` to switch between entropy sources.

By default, compiling with nothing will **return an error** at runtime encouraging the user to provide
his implementation of `get_entropy_input` in [entropy.c](entropy.c):

<pre>
Error: please provide your implementation of entropy gathering in the file 'entropy.c'!
</pre>

**NOTE**: this claim is however not entirely true when using the advanced API with `with_user_entropy`
suffix as all the entropy is provided by the user as parameters to the functions, hence no call to
`get_entropy_input` should occur in such cases!

It is possible to override this behaviour with the `WITH_TEST_ENTROPY_SOURCE=1` toggle, that will
use **default implementations** for entropy gathering (in the `_get_entropy_input_from_os` function):
using `/dev/random` under UNIX based OSes, and `CryptGenRandom` under Windows. Please note that this
is mainly here for **testing purposes**, and one must think twice before using this in a production code,
especially in contexts with critical security considerations. This indeed heavily relies on the underlying
OS implementation (OS flavour and version, used hardware, etc.).

When using the advanced DRBG APIs where buffers are provided as inputs to the functions in place of
the `get_entropy_input` usage, the same recommendations obviously apply for the quality of the entropy in
the provided buffers.

### The `get_entropy_input` API

The rationale behind `get_entropy_input` is to be called with a pointer to a buffer pointer (`uint8_t **buf`)
and a length, and return an "allocated" buffer with fresh entropy of the asked length. In the example implementation
of [entropy.c](entropy.c), there is no dynamic allocation per se: we use a static circular buffer to
provide this feature (this is mainly to avoid `malloc` and keep things simple).

After calling `get_entropy_input` and getting a fresh entropy buffer back, it is the responsibility of the
calling application to explicitly execute `clear_entropy_input` with the buffer pointer for garbage collection
and memory maintenance (this would be the place for a `free` and a zeroization for instance). Calling
`clear_entropy_input` must obviously take place **after** the buffer has been used by the DRBG!

The user is invited and encouraged to adapt/modify these specific implementations of `get_entropy_input` and
`clear_entropy_input`.

## Comparative performance and security of DRBG instances

All the DRBGs are neither equal in terms of formal security, nor in terms of performance. And mostly, the
**choice of the parameters** is crucial: the security strength is of course important, but Prediction
Resistance, frequent reseeding as well as feeding additional input with good entropy can make a big difference
when making calls to a DRBG instance as discussed [here](https://eprint.iacr.org/2018/349.pdf). The choice of
the underlying hash function or block cipher is also a great deal (in a real life scenario instance, choosing
TDEA over AES or SHA-1 over SHA-2 based primitives has no rationality at all).

Regarding the backends, CTR-DRBG has the great advantage of **speed**, but lacks a clean/simple design
when compared to Hash-DRBG, or even a [formal security proof](https://www.cs.princeton.edu/~appel/papers/verified-hmac-drbg.pdf)
as for HMAC-DRBG. In addition, the variant of CTR-DRBG without a DF (Derivation Function) is **not advisable at
all** because of degraded security properties.

All-in-all, the current library offers many possible instances of DRBG mainly for exhaustiveness, testing and
implementation reference purposes, which does not mean that the user can safely use all of them in
production critical code. **Use this library with care and knowingly!**


## About side-channel (SCA) and fault attacks

The implementations of the block ciphers (AES, TDEA), the hash functions, the HMAC and the DRBG core **have neither
been made side-channel resistant** (for instance, the optimized AES uses classical T-tables) **nor fault attacks
resistant**. This is left for future work. Having said that, we discuss these attack contexts a bit more hereafter.

Although the DRBG sensitiveness to SCA heavily depends on how the API is used (Prediction Resistance set to `true` and
always using **secret** additional data brings protection), the CTR-DRBG variant seems more susceptible than the two
other variants as discussed in [this article](hmac_drbg_hmac_internal) (which does not mean at all that
the two other variants are immune to SCA). Despite its performance advantages, we strongly discourage using
CTR-DRBG in SCA and faults critical contexts. Anyways, the user is encouraged to replace the block cipher current code
with constant time and microarchitectural-attacks free implementations (e.g. using dedicated instructions with AES-NI, or
bitsliced variants). This is also true for the hash and HMAC primitives.

As a general rule of thumb, in both attack contexts (SCA and fault), it is advised to use Prediction
Resistance, **explicitly reseed** very frequently with secret and high quality entropy, use secret additional data,
and ask for **small buffer chunks** when calling `generate` (small size data will limit the "long term" secret data
manipulation time frame before they are updated with fresh entropy). Applying these rules will bring
defense-in-depth and heavily limit attackers impact.
