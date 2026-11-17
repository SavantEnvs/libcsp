#!/usr/bin/env bash
#
# mayhem/build.sh — build libcsp's fuzz harnesses and its unit-test suite.
#
# 1) libcsp as a static library (CMake, upstream's own build) with $SANITIZER_FLAGS + $DEBUG_FLAGS,
#    routing table enabled (fuzz_rtable) and the ZeroMQ interface (libzmq from /opt/toolchains/deps,
#    uninstrumented, found by upstream's CMake through pkg-config), into build/fuzz (gitignored by
#    upstream's `build` entry). A copy of libcsp.a with a few statics made global lets the harnesses
#    reset per-input state (mayhem/harnesses/fuzz_common.h); no library code is changed.
# 2) every mayhem/harnesses/fuzz_*.c twice: libFuzzer binary /mayhem/<name> and the run-once
#    reproducer /mayhem/<name>-standalone, both linked with mayhem/lsan_off.cc.
# 3) upstream's libcheck unit tests (unittests/, csp_tests) with the project's normal flags, into
#    build/tests, for mayhem/test.sh to run.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) sanitized static libcsp. CMAKE_BUILD_TYPE=None: no build-type -g/-O flags after ours, so
#    -gdwarf-3 stays in effect. Harnesses need fuzzer-no-link instrumentation in the library too.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
LIB_CFLAGS="$FUZZ_CFLAGS"
[ -z "$LIB_FUZZING_ENGINE" ] || LIB_CFLAGS="$LIB_CFLAGS -fsanitize=fuzzer-no-link"
ZMQ_DEP=/opt/toolchains/deps/libzmq-4.3.5
PKG_CONFIG_PATH="$ZMQ_DEP/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
cmake -S . -B build/fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=None \
  -DBUILD_SHARED_LIBS=OFF \
  -DCSP_USE_RTABLE=ON \
  -DCMAKE_PROJECT_INCLUDE="$SRC/mayhem/fuzz-relax.cmake" \
  -DCMAKE_C_FLAGS="$LIB_CFLAGS"
grep -q 'CSP_HAVE_LIBZMQ 1' build/fuzz/include/csp/autoconfig.h
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target csp
# statics the harnesses reset between inputs: dedup ring, connection allocator cursor, ARP table
objcopy \
  --globalize-symbol=csp_dedup_array --globalize-symbol=csp_dedup_timestamp \
  --globalize-symbol=csp_dedup_in --globalize-symbol=csp_conn_last_given \
  --globalize-symbol=arp_used --globalize-symbol=arp_list \
  build/fuzz/libcsp.a build/fuzz/libcsp-harness.a

INC="-Ibuild/fuzz/include -Iinclude -Isrc -I$ZMQ_DEP/include"
LIBS="build/fuzz/libcsp-harness.a -L$ZMQ_DEP/lib -lzmq -lpthread -lm"
$CXX $FUZZ_CFLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
$CC $FUZZ_CFLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o

# 2) harnesses
for h in mayhem/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  $CC $LIB_CFLAGS $INC -c "$h" -o "build/fuzz/$name.o"
  $CXX $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "build/fuzz/$name.o" build/fuzz/lsan_off.o \
    $LIBS -o "$SRC/$name"
  $CXX $FUZZ_CFLAGS build/fuzz/standalone_main.o "build/fuzz/$name.o" build/fuzz/lsan_off.o \
    $LIBS -o "$SRC/$name-standalone"
done

# 3) unit tests, normal flags (the project's own default build type)
cmake -S . -B build/tests -G Ninja \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS" --target csp_tests
test -x build/tests/unittests/csp_tests
