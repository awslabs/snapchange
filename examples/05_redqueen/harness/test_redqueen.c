// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// clang -ggdb -O0 example1.c -o example1

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

/// Return the sum of `len` bytes starting at `buffer`
int sum(char *buffer, int len) {
    int result = 0;

    for(int x = 0; x < len; x++) {
        result += buffer[x];
    }

    return result;
}

// shamelessly plucked from the ijon project
__attribute__((always_inline))
static inline uint64_t ijon_simple_hash(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

/// Returns 1 if found hash, 0 otherwise
int branchless(char *buf) {
  uint32_t *p32;
  uint64_t hash = ijon_simple_hash((uint64_t)&branchless);
  bool chain = true;
  bool r = false;

  p32 = (uint32_t *)(buf);
  r = (*p32 == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  chain &= r;

  p32 = (uint32_t *)(buf + 4);
  r = (*p32 == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  chain &= r;

  p32 = (uint32_t *)(buf + 8);
  r = (*p32 == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  chain &= r;

  p32 = (uint32_t *)(buf + 12);
  r = (*p32 == (uint32_t)hash);
  hash = ijon_simple_hash(hash); 
  chain &= r;

  return chain;
}

void fuzzme(char* data) {
    int index = 0;

    // Offset 0x00..0x20, int
    if (*(int*)(data + 0x00) == 0x41414141) 
    if (*(int*)(data + 0x04) >= 0x41414141) 
    if (*(int*)(data + 0x08) <= 0x41414141) 
    if (*(int*)(data + 0x0c)  > 0x41414141) 
    if (*(int*)(data + 0x10)  < 0x41414141) 

    // Offset 0x20..0x40, unsigned int
    if (*(unsigned int*)(data + 0x20) == 0x42424242) 
    if (*(unsigned int*)(data + 0x24) >= 0x42424242) 
    if (*(unsigned int*)(data + 0x28) <= 0x42424242) 
    if (*(unsigned int*)(data + 0x2c)  > 0x42424242) 
    if (*(unsigned int*)(data + 0x30)  < 0x42424242) 

    // Offset 0x40..0x60, short
    if (*(short*)(data + 0x40) == 0x4343) 
    if (*(short*)(data + 0x42) >= 0x4343) 
    if (*(short*)(data + 0x44) <= 0x4343) 
    if (*(short*)(data + 0x46)  > 0x4343) 
    if (*(short*)(data + 0x48)  < 0x4343) 

    // Offset 0x60..0x80, unsigned short
    if (*(unsigned short*)(data + 0x60) == 0x4444) 
    if (*(unsigned short*)(data + 0x62) >= 0x4444) 
    if (*(unsigned short*)(data + 0x64) <= 0x4444) 
    if (*(unsigned short*)(data + 0x66)  > 0x4444) 
    if (*(unsigned short*)(data + 0x68)  < 0x4444) 

    // Offset 0x80..0xb0, unsigned long long
    if (*(unsigned long long*)(data + 0x80) == 0x4545454545454545) 
    if (*(unsigned long long*)(data + 0x88) >= 0x4545454545454545) 
    if (*(unsigned long long*)(data + 0x90) <= 0x4545454545454545) 
    if (*(unsigned long long*)(data + 0x98)  > 0x4545454545454545) 
    if (*(unsigned long long*)(data + 0xa0)  < 0x4545454545454545) 

    // MAGICHDR
    // Offset 0xb0..0x100, long long
    if (*(long long*)(data + 0xb0) == 0x524448434947414d) 
    if (*(long long*)(data + 0xb8) >= 0x524448434947414d) 
    if (*(long long*)(data + 0xc0) <= 0x524448434947414d) 
    if (*(long long*)(data + 0xc8)  > 0x524448434947414d) 
    if (*(long long*)(data + 0xd0)  < 0x524448434947414d) 

    // Offset 0x100..0x110 Branchless check
    if (branchless(&data[0x100]))

    // Offset 0x110..0x120 strcmp
    // Offset 0x120..0x130 memcmp
    if (!strcmp(&data[0x110], "password1234567")) 
    if (!memcmp(&data[0x120], &data[0x150], 0x30)) 

    // Offset 0x180..0x190 Simple "checksum"
    if (*(long long*)&data[0x180] == sum(&data[0x188], 0x18))

    // Offset 0x1a0..0x1c0 Double checks
    if (*(double *)&data[0x1a0] == 111.01)
    if (*(double *)&data[0x1b0] >= 123.01)
    if (*(double *)&data[0x1c0] <= 11.01)
    if (*(double *)&data[0x1d0]  > 111.01)
    if (*(double *)&data[0x1e0]  < 222.01)
    if (*(double *)&data[0x1f0] == 3.14)
    if (*(double *)&data[0x200] != 3.14)

    // Offset 0x220..0x290 Float checks
    if (*(float *)&data[0x220] == 1230000.01f)
    if (*(float *)&data[0x230] >= 123.01f)
    if (*(float *)&data[0x240] <= 10.01f)
    if (*(float *)&data[0x250]  > 1230000.01f)
    if (*(float *)&data[0x260]  < 1230000.01f)
    if (*(float *)&data[0x270] == 3.1415926535f)
    if (*(float *)&data[0x280] != 3.1415926535f)

    // Offset 0x210..0x280 Long Double checks
    // if (*(long double *)&data[0x210] == 55555555.01L)
    // if (*(long double *)&data[0x220] >= 55555555.02L)
    // if (*(long double *)&data[0x230] <= 55555555.03L)
    // if (*(long double *)&data[0x240]  > 55555555.04L)
    // if (*(long double *)&data[0x250]  < 55555555.05L)
    // if (*(long double *)&data[0x260] == 1234.5678L)
    // if (*(long double *)&data[0x270] != 1234.5678L)

    // Last byte checks
    if (data[0x2f0] == '!' && data[0x2f1] == '!') {
        int pid = getpid();
        if (pid == 0xdeadbeef) {
            *(int*)0xcafecafe = 0x41414141;
        }
    }

    return;
}

int main() {
    char* data = malloc(0x400);
    memset(data, 'a', 0x400);

    if(getenv("SNAPSHOT") != 0) {
        // Print the memory buffer address and pid address for fuzzing
        printf("SNAPSHOT Data buffer: %p\n", data);

        // Ensure the stdout has been flushed
        fflush(stdout);

        // Snapshot taken here
        __asm("int3 ; vmcall"); 
    }

    // Call the fuzzme function
    fuzzme(data);

    return 0;
}
