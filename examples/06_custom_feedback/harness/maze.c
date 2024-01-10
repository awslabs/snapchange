// example harness code
//
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*****************************************************************************/
// basic obfuscation code.
__attribute__((noinline, optnone)) uint8_t eq16(const uint8_t *x,
                                                const uint8_t *y) {
  uint8_t r = 0;
  for (size_t i = 0; i < 16; i++) {
    r |= (x[i] ^ y[i]);
  }
  return r;
}

void obfuscate(const uint8_t *code, uint8_t *out) {
  uint8_t K[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0xff, 0xfe, 0xfd, 0xfc, 0xaf, 0xae, 0xad, 0xac};
  uint8_t S[256];
  for (size_t i = 0; i < 256; i++) {
    S[i] = i;
  }
  uint8_t j = 0;
  for (size_t i = 0; i < 256; i++) {
    j = (j + S[i] + K[i % 16]);
    S[i] ^= S[j];
    S[j] ^= S[i];
    S[i] ^= S[j];
  }

  uint8_t i = 0;
  j = 0;
  for (size_t c = 0; c < 16; c++) {
    j = (j + S[i]);
    S[i] ^= S[j];
    S[j] ^= S[i];
    S[i] ^= S[j];
    uint8_t t = (S[i] + S[j]);
    out[c] = code[i] ^ S[t];

    i++;
  }
}

uint8_t CONTRA_CODE[16] = {
    0x80, 0xa9, 0xcf, 0x63, 0x36, 0xa6, 0xc4, 0xe9,
    0x07, 0x76, 0x93, 0x0a, 0x29, 0xaa, 0xf6, 0x4b,
};

bool check_contra_code(const char *program, size_t cur, size_t size) {
  if (cur < size && size > 10 && cur < (size - 10)) {
    uint8_t r = 0;
    // 0 1 2 3 4 5 6 7 8 9
    // w w s s a d a d x y
    const uint8_t *code = (const uint8_t *)program + cur + 1;
    if (*code == 0 || *code == '\n') {
      return false;
    }
    r |= (uint8_t)(code[0] != code[1]);
    r ^= (code[2] ^ code[3]);
    r |= (code[4] ^ code[6]);
    r += ((code[4] | code[6]) & 0xe);
    uint8_t buf[16] = {
        0,
    };
    bzero(buf, 16);
    if (memcmp(buf, code, 10) == 0) {
      // all 0 input...
      return false;
    }
    memcpy(buf, code, 10);
    buf[15] = buf[0];
    buf[13] = buf[4];
    buf[12] = buf[2] + buf[5];
    buf[11] = 0x42;
    uint8_t out[16] = {
        0,
    };
    bzero(out, 16);
    obfuscate(buf, out);
    r |= eq16(out, CONTRA_CODE);
#if 0
    // for debugging purposes ;)
    puts("buf");
    for (size_t i = 0; i < 16; ++i) {
      printf("0x%02x, ", buf[i]);
    }
    puts("");
    puts("CONTRA_CODE");
    for (size_t i = 0; i < 16; ++i) {
      printf("0x%02x, ", CONTRA_CODE[i]);
    }
    puts("");
    puts("out");
    for (size_t i = 0; i < 16; ++i) {
      printf("0x%02x, ", out[i]);
    }
    puts("");
    printf("r = %d\n", r);
#endif
    return (r == 0);
  } else {
    return false;
  }
}

/*****************************************************************************/
// The maze demo is taken from Felipe Andres Manzano's blog:
// http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
// adapted according to the changes from the ijon paper:
// https://github.com/RUB-SysSec/ijon-data/tree/master/maze

// maze settings - defaults to small maze with backtracking.
uint8_t MAZE_NO_BT = false;
uint8_t CHECK_CODE = true;
uint32_t USE_MAZE = 0;

// struct to contain the maze
#define MAZE_DIM_SIZE (32)
typedef struct maze {
  int h;
  int w;
  char maze[MAZE_DIM_SIZE][MAZE_DIM_SIZE];
} maze_t;

// two mazes
maze_t maze_big = {13,
                   17,
                   {
                       "+-+-------------+",
                       "| |             |",
                       "| | +-----* *---+",
                       "|   |           |",
                       "+---+-* *-------+",
                       "|               |",
                       "+ +-------------+",
                       "| |       |   |#|",
                       "| | *---+ * * * |",
                       "| |     |   |   |",
                       "| +---* +-------+",
                       "|               |",
                       "+---------------+",
                   }};

maze_t maze_small = {7,
                     11,
                     {
                         "+-+---+---+",
                         "| |     |#|",
                         "| | --+ | |",
                         "| |   | | |",
                         "| +-- | | |",
                         "|     |   |",
                         "+-----+---+",
                     }};

__attribute__((noinline, optnone)) void log_pos(uint16_t x, uint16_t y) {
  printf("pos = (%u, %u)\n", x, y);
}

__attribute__((noinline, optnone)) void bye(int i) {
  printf("bye(%d)\n", i);
  exit(i);
}

void draw(maze_t *maze) {
  int i, j;
  for (i = 0; i < maze->h; i++) {
    for (j = 0; j < maze->w; j++)
      printf("%c", maze->maze[i][j]);
    printf("\n");
  }
  printf("\n");
}

void logmsg(const char *msg) { puts(msg); }

__attribute__((noinline, optnone)) void lose(const char *msg, uint16_t x,
                                             uint16_t y) {
  printf("You lose: '%s'\n", msg);
  log_pos(x, y);
  bye(1);
}

__attribute__((noinline, optnone)) void win(uint16_t x, uint16_t y) {
  puts("You Win!!!!");
  log_pos(x, y);
}

void walk_maze(const char *program, const size_t iters, maze_t maze) {
  uint16_t x, y;   // Player position
  uint16_t ox, oy; // Old player position
  size_t i = 0;    // Iteration number
  x = 1;
  y = 1;
  ox = x;
  oy = y;
  maze.maze[y][x] = 'X';
  draw(&maze);
  while (i < iters) {
    if (x > maze.w || y > maze.h) {
      lose("OOB", x, y);
    }
    if (MAZE_NO_BT) {
      maze.maze[y][x] = ' ';
    }
    ox = x; // Save old player position
    oy = y;

    log_pos(x, y);

    switch (program[i]) {
    case 'w':
      y--;
      break;
    case 's':
      y++;
      break;
    case 'a':
      x--;
      break;
    case 'd':
      x++;
      break;
    case 'x':
    case 'y':
      draw(&maze);
      break;
    case '\n':
    case '\0':
      logmsg("final state");
      draw(&maze);
      lose("You give up", ox, oy);
    default:
      lose("Wrong command! (only w,s,a,d,x,y accepted!)", ox, oy);
    }
    if (maze.maze[y][x] == '#') {
      win(x, y);
      if (CHECK_CODE) {
        if (check_contra_code(program, i, iters)) {
          logmsg("oh oh..");
          assert(0);
        } else {
          logmsg("... or did you really?");
          bye(0);
        }
      } else {
        // notify fuzzer
        assert(0);
      }
    }
    if (maze.maze[y][x] != ' ') {
      x = ox;
      y = oy;
    }
    if (MAZE_NO_BT) {
      if (ox == x && oy == y) {
        lose("No movement", ox, oy);
      }
    }

    maze.maze[y][x] = 'X';
    draw(&maze); // draw it
    i++;
  }

  lose("exhausted allowed steps", x, y);
}

// end maze code
/*****************************************************************************/

#define MAX_ITERS 1024
char program[MAX_ITERS] = {
    0,
};

int main(int argc, char *argv[]) {

  char *e = getenv("USE_MAZE");
  if (e != NULL) {
    USE_MAZE = atoi(e);
  }
  e = getenv("MAZE_NO_BT");
  if (e != NULL) {
    MAZE_NO_BT = atoi(e);
  }
  e = getenv("CHECK_CODE");
  if (e != NULL) {
    CHECK_CODE = atoi(e);
  }

  if (getenv("SNAPSHOT") != NULL) {
    printf("SNAPSHOT Data buffer: %p\n", program);
    fflush(stdout);

    __asm("int3 ; vmcall");
  } else {
    if (argc == 1) {
      read(0, program, MAX_ITERS);
    } else {
      FILE *f = fopen(argv[1], "r");
      if (f != NULL) {
        fread(program, 1, MAX_ITERS, f);
      }
      fclose(f);
    }
  }
  // dynamically select the maze
  maze_t maze;
  if (USE_MAZE == 0) {
    maze = maze_small;
  } else if (USE_MAZE == 1) {
    maze = maze_big;
  } else {
    maze = maze_small;
  }
  walk_maze(program, MAX_ITERS, maze);
  bye(0);
}
