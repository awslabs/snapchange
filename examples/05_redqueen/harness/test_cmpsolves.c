#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef KLEE_FUZZ
#include <klee/klee.h>
#endif

#define INPUT_SIZE (0x4000)
char input[INPUT_SIZE] = {
    0xcd
};

// based on the public domain code from
// **** start https://xorshift.di.unimi.it/splitmix64.c
/*  Written in 2015 by Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

uint64_t splitmix64(uint64_t x) {
  uint64_t z = (x += 0x9e3779b97f4a7c15);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
  return z ^ (z >> 31);
}
// **** end https://xorshift.di.unimi.it/splitmix64.c

// based on the public domain code from
// **** start https://prng.di.unimi.it/xoshiro256plus.c ****
/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */
static inline uint64_t rotl(const uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}

uint64_t xoshiro256p_next(uint64_t *s) {
  const uint64_t result = s[0] + s[3];
  const uint64_t t = s[1] << 17;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rotl(s[3], 45);
  return result;
}

// **** end https://prng.di.unimi.it/xoshiro256plus.c ****

// initialize an array with a quasi constant data (i.e., the data does not
// change as long as the relevant source parts do not change).
void rand_init(uint64_t *p, size_t sz, uint64_t seed_i_part,
               const char *seed_s_part) {
  uint64_t seed[4] = {0x8458519673b446c1, 0xf1977db837449513,
                      0xf7cde9408114ac1b, 0x7c1738b0167706c5};
  uint64_t x = splitmix64(seed_i_part);
  for (size_t i = 0; *seed_s_part != 0; i++, seed_s_part++) {
    x ^= ((*seed_s_part) << i);
  }
  seed[0] ^= splitmix64(x);
  seed[1] ^= splitmix64(seed[0]);
  seed[2] ^= splitmix64(seed[1]);
  seed[3] ^= splitmix64(seed[2]);
  for (size_t i = 0; i < sz; i++) {
    p[i] = xoshiro256p_next(seed);
  }
}

// constant time memcmp - only check for equal
int memcmpct(char *a, char *b, size_t sz) {
  char x = 0;
  for (size_t i = 0; i < sz; i++) {
    x |= a[i] ^ b[i];
  }
  return x == 0;
}

bool failed = false;
size_t succeeded = 0;
size_t ignored = 0;
bool do_prints = true;
bool exit_on_fail = true;

void print_check_status(const char *func, int line, const char *expr,
                        bool succeeded) {
#ifndef KLEE_FUZZ
  if (do_prints) {
    char *status = "FAIL";
    if (succeeded) {
      status = "SUCCESS";
    }
    printf("CHECK-%s: %s:%d - %s\n", status, func, line, expr);
  }
#endif
}

void (*success_ptr)() = NULL;
void exit_func();

#define CHECK(EXP)                                                             \
  {                                                                            \
    bool yes = false;                                                          \
    if (EXP) {                                                                 \
      succeeded += 1;                                                          \
      yes = true;                                                              \
    } else {                                                                   \
      failed = true;                                                           \
      yes = false;                                                             \
    };                                                                         \
    print_check_status(__func__, __LINE__, #EXP, yes);                         \
    if (exit_on_fail && (!yes)) {                                              \
      exit_func();                                                             \
    }                                                                          \
  }

#define CHECK_AND_IGNORE(EXP)                                                  \
  {                                                                            \
    bool yes = false;                                                          \
    if (EXP) {                                                                 \
      ignored += 1;                                                            \
      yes = true;                                                              \
    } else {                                                                   \
      failed = true;                                                           \
      yes = false;                                                             \
    };                                                                         \
    print_check_status(__func__, __LINE__, #EXP, yes);                         \
  }

/****
 * basic magic value comparisons of a lot of different integer and float types
 ****/

char *const_u16_compares(uint16_t *data) {
  CHECK((data[0] == 0x1101));
  CHECK((data[1] >= 0x1102));
  CHECK((data[2] >= 0x1103));
  CHECK((data[3] < 0x1104));
  CHECK((data[4] > 0x1105));
  return (char *)(data + 5);
}

char *const_i16_compares(int16_t *data) {
  CHECK((data[0] == 0x1201));
  CHECK((data[1] >= 0x1202));
  CHECK((data[2] >= 0x1203));
  CHECK((data[3] < 0x1204));
  CHECK((data[4] > 0x1205));
  return (char *)(data + 5);
}

char *const_i32_compares(int32_t *data) {
  CHECK((data[0] == 0x01dead01));
  CHECK((data[1] >= 0x01dead02));
  CHECK((data[2] >= 0x01dead03));
  CHECK((data[3] < 0x01dead04));
  CHECK((data[4] > 0x01dead05));
  return (char *)(data + 5);
}

char *const_u32_compares(uint32_t *data) {
  CHECK((data[0] == 0x02dead01));
  CHECK((data[1] >= 0x02dead02));
  CHECK((data[2] >= 0x02dead03));
  CHECK((data[3] < 0x02dead04));
  CHECK((data[4] > 0x02dead05));
  return (char *)(data + 5);
}

char *const_i64_compares(int64_t *data) {
  CHECK((data[0] == 0x01deadbeefcafe01));
  CHECK((data[1] >= 0x01deadbeefcafe02));
  CHECK((data[2] >= 0x01deadbeefcafe03));
  CHECK((data[3] < 0x01deadbeefcafe04));
  CHECK((data[4] > 0x01deadbeefcafe05));
  return (char *)(data + 5);
}

char *const_u64_compares(uint64_t *data) {
  CHECK((data[0] == 0x02deadbeefcafe01));
  CHECK((data[1] >= 0x02deadbeefcafe02));
  CHECK((data[2] >= 0x02deadbeefcafe03));
  CHECK((data[3] < 0x02deadbeefcafe04));
  CHECK((data[4] > 0x02deadbeefcafe05));
  return (char *)(data + 5);
}

char *const_f32_compares(float *data) {
  CHECK((data[0] == 1010101.01010101f));
  CHECK((data[1] <= 2020202.02020202f));
  CHECK((data[2] >= 3030303.03030303f));
  CHECK((data[3] < 4040404.04040404f));
  CHECK((data[4] > 5050505.05050505f));
  CHECK((data[5] != 6060606.06060606f));
  return (char *)(data + 6);
}

char *const_f64_compares(double *data) {
  CHECK((data[0] == 1010101.01010101));
  CHECK((data[1] <= 2020202.02020202));
  CHECK((data[2] >= 3030303.03030303));
  CHECK((data[3] < 4040404.04040404));
  CHECK((data[4] > 5050505.05050505));
  CHECK((data[5] != 6060606.06060606));
  return (char *)(data + 6);
}

char *const_long_double_compares(long double *data) {
  CHECK((isnormal(data[0])));
  CHECK((3.1415926535897932384626433832795029L <  data[0]));
  CHECK((0.2222222222222222222222222222222222L <= data[1] && data[1] <= 0.3333333333333333333333333333333333L));
  CHECK((4.1414141414141414141414141414141414L == data[2]));
  CHECK((3.1415926535897932384626433832795029L >  data[3]));
  CHECK((5.9999999999999999999999999999999999L >= data[4]));
  return (char *)(data + 5);
}

// several variants of stdlib comparison functions.
char *const_strmemcmp(char *data) {
  CHECK((strcmp(data, "password1234567") == 0));
  data = data + 4;
  CHECK((memcmp(data, "word1234567\x00\x01\x02\x03\x04\x05\x06\x07", 19) == 0));
  data = data + 19;
  CHECK((strncasecmp(data, "wordpassblablub", 6) == 0));
  CHECK((strncasecmp(data + 1, "ordpass\x00", 32) == 0));
  data = data + 10;
  CHECK((memcmpct("IjKFl", data, 5) == 0));
  data = data + 5;
  return data;
}

// randomly initialize array at runtime -> impossible for auto-dict; requires
// redqueen or concolic.
char *check_dynamic_compares(char *buf) {
  uint64_t *data = (uint64_t *)buf;
  uint64_t arr[5];
  rand_init(arr, 5, __LINE__, __func__);

  CHECK((data[0] == arr[0]));
  CHECK((data[1] <= arr[1]));
  CHECK((data[2] >= arr[2]));
  CHECK((data[3] > arr[3]));
  CHECK((data[4] < arr[4]));
  return (char *)(data + 5);
}

// compare 5 uint64_t in a constant time loop
bool constanttime_compare5_loop(const uint64_t *a, const uint64_t *b) {
  bool chain = true;

#pragma clang loop unroll(disable)
  for (size_t i = 0; i < 5; i++) {
    chain &= (a[i] == b[i]);
  }

  return chain;
}

// branchless; constant time equality of four uint64_t; e.g., in crypto code
// using uint256_t bigints.
bool branchless_compare4_unrolled(const uint64_t *a, const uint64_t *b) {
  bool chain = true;
  bool r = false;
  r = (a[0] == b[0]);
  chain &= r;
  r = (a[1] == b[1]);
  chain &= r;
  r = (a[2] == b[2]);
  chain &= r;
  r = (a[3] == b[3]);
  chain &= r;
  return chain;
}

// compare 16 magic value constants (chosen randomly) using constant time code.
// Theoretically possible with auto-dict, but the constant-time comparison
// chaining with bitops is tricky to detect.
char *const_u64_compares_constanttime(char *data) {
  const uint64_t arr[16] = {
      0x4d9796955beb5e4d, 0x2b4bcc7a21962c13, 0xb039b4a8f5dd646,
      0x2a3ed570f85e7ca4, 0x496449cf41aa9e8d, 0xbaeb8dd838e8eaa8,
      0xef2e6bd6ac4c22c9, 0x8ce06197cc1bb72,  0xa495dcf96695873,
      0x9ac587e542e74827, 0x4358cd8ef8c0c888, 0x78e47f54184f28b3,
      0xebb560dd53dbead3, 0xa7522b08dcf7604b, 0x5d71c2393c43626d,
      0x1cb4c8a0eaeed020};

  CHECK((branchless_compare4_unrolled((uint64_t *)data, arr)));
  data = data + (8 * 4);
  CHECK((constanttime_compare5_loop((uint64_t *)data, arr)));
  data = data + (8 * 16);
  return data;
}

// compare 16 magic value constants that are initialized at runtime (auto-dict
// not possible).
char *check_dynamic_branchless_compares(char *data) {
  uint64_t arr[16];
  rand_init(arr, 16, __LINE__, __func__);

  CHECK((branchless_compare4_unrolled((uint64_t *)data, arr)));
  data = data + (8 * 4);
  CHECK((constanttime_compare5_loop((uint64_t *)data, arr)));
  data = data + (8 * 16);
  return data;
}

// 
char *u32_compare_within(char *buf) {
  uint32_t *data = (uint32_t *)buf;

  // ensure data[0] is not a common filler
  CHECK((data[0] != 0));
  CHECK((data[0] != 0x41414141));
  CHECK((data[0] != 0x61616161));
  CHECK((data[0] == data[1]));
  CHECK((data[0] > data[2]));
  CHECK((data[0] < data[3]));

  return (char *)(data + 4);
}

char *check_memcmp_within(char *data) {
  const size_t sz = 0x20;
  // ensure data is not a common filler, but properly mutated
  CHECK((memchr(data, '\0', sz) == NULL));
  CHECK((memchr(data, 'a', sz) == NULL));
  CHECK((memchr(data, 'A', sz) == NULL));
  CHECK((memcmp(data, data + (sz), sz) == 0));
  return data + (sz * 2);
}

/// Return the sum of `len` bytes starting at `buffer` and negate.
int64_t compute_checksum(char *buffer, size_t len) {
  uint64_t result = 0;
  for (size_t x = 0; x < len; x++) {
    result += buffer[x];
  }
  return -(int64_t)result;
}

/// tests [ checksum | data ], where checksum must match data
char *check_the_sum(char *data) {
  const size_t sz = 0x18;
  int64_t checksum = *(int64_t *)(data + sz);
  CHECK((checksum == (compute_checksum(data, sz))));
  return data + sizeof(int64_t) + sz;
}

char parity_byte(const char *buffer, size_t len) {
  uint8_t result = 0;
  for (size_t x = 0; x < len; x++) {
    result ^= (uint8_t)buffer[x];
  }
  return (char)result;
}

char *check_the_parity_byte(char *data) {
  const size_t sz = 0x18;
  CHECK((data[sz] == parity_byte(data, sz)));
  return data + 1 + sz;
}

char *arithmetic_adjustments(char *data) {
  // Mixed type u16 and u8 with arithmetic checks
  uint16_t len1 = *(uint16_t*)data;
  data += 2;
  uint8_t val1 = *(uint8_t*)data;
  data += 1;
  CHECK(len1 == (val1 * 1) + 9);

  uint16_t len4 = *(uint16_t*)data;
  data += 2;
  uint8_t val4 = *(uint8_t*)data;
  data += 1;
  CHECK((len4 - 0x1000) == (val4 * 0x10) + 9);

  uint16_t len11 = *(uint16_t*)data;
  data += 2;
  uint8_t val11 = *(uint8_t*)data;
  data += 1;
  CHECK((len11 + 4) == (val11 * 150) + 9);

  // Mixed type u32 and u16 with arithmetic checks
  uint32_t len12 = *(uint32_t*)data;
  data += 4;
  uint16_t val12 = *(uint16_t*)data;
  data += 2;
  CHECK((len12 - 0x100) == (val12 * 0x3) + 0x1234);

  // Mixed type u32 and u32 with arithmetic checks
  uint32_t len13 = *(uint32_t*)data;
  data += 4;
  uint32_t val13 = *(uint32_t*)data;
  data += 4;
  CHECK((len13 + 6) == (((((val13 << 2) >> 3) + 6) * 5) - 15));

  // Mixed type u64 and u64 with arithmetic checks
  uint64_t len14 = *(uint64_t*)data;
  data += 8;
  uint64_t val14 = *(uint64_t*)data;
  data += 8;
  CHECK((len14 - 8) == (((((val14 / 8) + 5) * 15) - 2) >> 3) << 4);

  // Mixed type u64 and u8 with arithmetic checks
  uint64_t len15 = *(uint64_t*)data;
  data += 8;
  uint8_t val15 = *(uint8_t*)data;
  data += 1;
  CHECK(((len15 * 2) - 5) == (val15 + 4));
    
  return data;
}


int fuzzme(const char *buf, size_t sz) {
  if (sz > INPUT_SIZE) {
    return -1;
  }
  if (buf == NULL) {
    buf = input;
    sz = INPUT_SIZE;
  }
  if (buf != input) {
    memcpy(input, buf, sz);
  }
  // input is a very large buffer that should accomodate for all the following
  // memory accesses
  char *data = input;

  // Check some basic arithmetic adjustments from the input bytes
  data = arithmetic_adjustments(data);

  // we have multiple compares with constants - most should be relatively easy
  // to handle for current fuzzers.
  data = const_i16_compares((int16_t *)data);
  data = const_u16_compares((uint16_t *)data);
  data = const_i32_compares((int32_t *)data);
  data = const_u32_compares((uint32_t *)data);
  data = const_i64_compares((int64_t *)data);
  data = const_u64_compares((uint64_t *)data);
  data = const_strmemcmp(data);
  data = const_f32_compares((float *)data);
  data = const_f64_compares((double *)data);
  data = const_long_double_compares((long double *)data);

  // this is the first tricky check. we still compare with constants, but we
  // use branchless code (i.e., something you would find in constant-time
  // code), that doesn't exhibit a code coverage signal.
  data = const_u64_compares_constanttime(data);

  // now we try to check whether the fuzzer can solve compares within the input
  // data, i.e., something like data[i] == data[j] with i != j.
  data = u32_compare_within(data);
  data = check_memcmp_within(data);

  // here we init quasi constants at runtime based on hashing. These are hard
  // to identify statically (i.e., with auto-dict). However, with redqueen
  // (input-to-state) they are easy to identify.
  data = check_dynamic_compares(data);
  data = check_dynamic_branchless_compares(data);


  // here we do some some basic checksum tests, i.e., to capture the pattern
  // [ data | checksum(data) ], common to various file formats or network
  // packets.
  data = check_the_parity_byte(data);
  data = check_the_sum(data);

  if (do_prints) {
#ifndef KLEE_FUZZ
    printf("succeeded checks: %zd\n", succeeded);
    printf("ignored checks: %zd\n", ignored);
    if (ignored == 0 && !failed) {
      puts("** ALL CHECKS PASSED **");
    }
#endif
  }
  if (success_ptr != NULL) {
#ifdef KLEE_FUZZ
    abort();
#else
    success_ptr();
#endif
  }

  return 0;
}

void success_func() {
  if (!failed) {
    // induce a crash
    *(int *)0xcafecafe = 0x41414141;
  }
}

#ifdef LLVM_FUZZ

#include <setjmp.h>
jmp_buf _jmp_buf;

void exit_func() { longjmp(_jmp_buf, 1); }
bool __fuzz_init = false;

extern "C" {
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!__fuzz_init) {
        success_ptr = &abort;
        do_prints = (getenv("CHECK_PRINTS") != 0);
        __fuzz_init = true;
    }
    // this is sane, because we don't do any heap alloc, etc.
    if (setjmp(_jmp_buf)) {
        return 0;
    } else {
        return fuzzme((const char *)data, size);
    }
    }
}

#else

void exit_func() { exit(0); }

int main(int argc, char *argv[]) {
#ifdef KLEE_FUZZ
  klee_make_symbolic(input, INPUT_SIZE, "a");
#else
  success_ptr = &success_func;
  if (argc == 2) {
    FILE *f = NULL;
    if (strcmp(argv[1], "-") == 0) {
      f = stdin;
    } else {
      f = fopen(argv[1], "r");
    }
    assert(fseek(f, 0L, SEEK_END) == 0);
    size_t fsize = ftell(f);
    assert(fsize <= sizeof(input));
    assert(fseek(f, 0L, SEEK_SET) == 0);
    fread(input, 1, fsize, f);
    fclose(f);
  }

  if (getenv("SNAPSHOT") != 0) {
    // disable prints if we are being run in snapchange
    do_prints = false;

    // Print the memory buffer address and pid address for fuzzing
    printf("SNAPSHOT Data buffer: %p\n", input);

    // Ensure the stdout has been flushed
    fflush(stdout);

    // Snapshot taken here
    __asm("int3 ; vmcall");
  } else {
    do_prints = true;
  }
#endif

  // Call the fuzzme function
  return fuzzme(input, sizeof(input));
}

#endif

