// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// clang -ggdb -O0 example1.c -o example1

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fuzzme(char* data) {
    int pid    = getpid();

    // Correct solution: data == "fuzzmetosolveme!", pid == 0xdeadbeef
    if (data[0]  == 'f') {
    if (data[1]  == 'u') {
    if (data[2]  == 'z') {
    if (data[3]  == 'z') {
    if (data[4]  == 'm') {
    if (data[5]  == 'e') {
    if (data[6]  == 't') {
    if (data[7]  == 'o') {
    if (data[8]  == 's') {
    if (data[9]  == 'o') {
    if (data[10] == 'l') {
    if (data[11] == 'v') {
    if (data[12] == 'e') {
    if (data[13] == 'm') {
    if (data[14] == 'e') {
    if (data[15] == '!') {
        pid = getpid();
        if (pid == 0xdeadbeef) {
            *(int*)0xcafecafe = 0x41414141;
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

    return;
}

int main() {
    char* data = "aaaaaaaaaaaaaaaa";

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
