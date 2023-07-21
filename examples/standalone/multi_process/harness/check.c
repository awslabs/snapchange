// Helper

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc == 2) {
    if (strcmp(argv[1], "YOLO") == 0) {
      return EXIT_SUCCESS;
    }
  }
  return EXIT_FAILURE;
}
