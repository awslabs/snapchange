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

char data[1024] = "ABCDABCD_DEFAULT_DATA";

void fuzzme(char *data) {
  char path[1024] = {
      0,
  };
  char file_magic[4] = {
      0,
  };

  puts("hello");

  // first basic fuzzing roadblock
  uint16_t *u16ptr = (uint16_t *)data;
  if (u16ptr[0] != 0xdead) {
    exit(1);
  }
  if (u16ptr[1] != 0xbeef) {
    exit(2);
  }
  puts("magic check passed");

  // second roadblock: require a file on the FS
  char *c = getcwd(path, sizeof(path) - 1);
  if (c == NULL) {
    puts("getcwd failed");
    exit(3);
  }
  printf("pwd: %s\n", c);
  FILE *f = fopen("./what", "r");
  if (f == NULL) {
    puts("failed to open file ./what");
    f = fopen("/root/what", "r");
    if (f == NULL) {
      puts("failed to open file /root/what - giving up");
      exit(4);
    }
  }
  ssize_t r = fread(file_magic, 1, 4, f);
  if (r != 4) {
    puts("failed to read enough data from file");
    exit(5);
  }
  if (memcmp(file_magic, "ABCD", 4) != 0) {
    puts("wrong file contents");
    exit(6);
  }

  // bonus: writing a file should work
  FILE* fw = fopen("./tahw", "w");
  if (fw == NULL) {
    puts("failed to open file ./tahw");
    exit(7);
  }
  ssize_t written = fwrite("DCBA", 1, 4, fw);
  if (written != 4) {
    puts("failed to write 4 bytes to file");
    exit(8);
  }
  fflush(fw);
  fclose(fw);
  fw = fopen("./tahw", "r");
  if (fw == NULL) {
    puts("failed to open file ./tahw for reading");
    exit(9);
  }
  char buf[4];
  ssize_t read_bytes = fread(buf, 1, 4, fw);
  if (memcmp(buf, "DCBA", 4) != 0) {
    puts("invalid contents in ./tahw");
    exit(10);
  }
  fclose(fw);

  // third roadblock: execute another command
  int ret = system("/bin/ls");
  if (ret != 0) {
    puts("system(/bin/ls) failed");
    exit(11);
  }

  // fourth roadblock: check using another command
  char cmd_arg[8] = {
      0,
  };
  char *input_str = data + 4;
  for (size_t i = 0; i < 4; i += 1) {
    char c = input_str[i];
    if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || c == 0) {
      cmd_arg[i] = c;
    }
    if (c == 0) {
      break;
    }
  }

  pid_t pid = fork();
  if (pid == -1) {
    puts("failed to fork()");
    exit(12);
  } else if (pid > 0) {
    int status;
    do {
      pid_t p = waitpid(pid, &status, 0);
      if (p == -1) {
        puts("waitpid failed");
        exit(13);
      }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    if (WIFSIGNALED(status)) {
      puts("child irregular exit");
      exit(14);
    }

    int child_ret = WEXITSTATUS(status);
    if (child_ret != 0) {
      puts("child signaled failure");
      exit(15);
    }
  } else {
    // we are the child
    char *argv[] = {"./check", cmd_arg, NULL};
    execve(argv[0], argv, NULL);
    puts("execve failed");
    exit(16);
  }

  // GOAL:
  *(int *)0xcafecafe = 0x41414141;

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
