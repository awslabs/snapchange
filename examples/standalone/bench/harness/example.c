// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// clang -ggdb -O0 example1.c -o example1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

char data[1024] = "ABCDABCD_DEFAULT_DATA";

void finality(char *data) {
  uint16_t x = *(uint16_t*)data;
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
          sched_yield();
          sched_yield();
          sched_yield();
          sched_yield();

          if (data[4] == 'm') {
            if (data[5] == 'e') {
              int r = system("/bin/ls");
              if (r != 0) {
                exit(r);
              }

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

  exit(0);
}

int main() {
  char *data_init = getenv("DATA_INIT");
  if (data_init != NULL) {
    printf("attempting to initialize data from %s\n", data_init);
    FILE *f = fopen(data_init, "r");
    if (f != NULL) {
      fread(data, 1, sizeof(data), f);
      fclose(f);
    }
  }

  if (getenv("SNAPSHOT") != 0) {
    // Print the memory buffer address and pid address for fuzzing
    printf("SNAPSHOT Data buffer: %p\n", data);

    // Ensure the stdout has been flushed
    fflush(stdout);

    // Snapshot taken here
    __asm("int3 ; vmcall");
  }

  data[1023] = 0;
  // Call the fuzzme function
  fuzzme(data);

  return 0;
}
