// Example test case for snapshot fuzzing

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void finality(char *data) {
  uint16_t x = *(uint16_t *)data;
  if (x < 0xcafe || x > 0xdead) {
    return;
  }

  if ((*(uint64_t *)(data + 2)) != 0xdeadbeefcafecafe) {
    return;
  }
  // GOAL:
  *(int *)0xcafecafe = 0x41414141;
}

void fuzzme(char *data) {
  if (data[0] == 'f') {
    if (data[1] == 'u') {
      if (data[2] == 'z') {
        if (data[3] == 'z') {
          if (data[4] == 'm') {
            if (data[5] == 'e') {
              if (data[6] == 't') {
                if (data[7] == 'o') {
                  if (data[8] == 's') {
                    if (data[9] == 'o') {
                      if (data[10] == 'l') {
                        if (data[11] == 'v') {
                          if (data[12] == 'e') {
                            if (data[13] == 'm') {
                              if (data[14] == 'e') {
                                if (data[15] == '!') {
                                  finality(data + 16);
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < (16 + 2 + 8)) {
    return -1;
  }
  fuzzme((char *)Data);
  return 0;
}
