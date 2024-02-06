#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mujs.h"

static void jsB_gc(js_State *J) {
  int report = js_toboolean(J, 1);
  js_gc(J, report);
  js_pushundefined(J);
}

static void jsB_print(js_State *J) {
  int i, top = js_gettop(J);
  for (i = 1; i < top; ++i) {
    const char *s = js_tostring(J, i);
    if (i > 1)
      putchar(' ');
    fputs(s, stdout);
  }
  putchar('\n');
  js_pushundefined(J);
}

int64_t magic_values[] = {0xdeadbeef, 0xcafecafe, 0x42424242, 0x41414141};

static void magic(js_State *J) {
  if (js_isnumber(J, 1)) {
    double idx = js_tonumber(J, 1);
    if (idx < 4) {
      js_pushnumber(J, (double)magic_values[(int)idx]);
      return;
    }
  }
  js_pushnumber(J, 0);
}

int party_counter = 0;

static void party(js_State *J) {
  int i, top = js_gettop(J);
  for (i = 1; i < top; ++i) {
    if (js_isnumber(J, i)) {
      int val = (int)js_tonumber(J, i);
      party_counter += val;
      if (party_counter > 1000) {
        party_counter = 0;
      }
      if (party_counter > 42) {
        abort();
      }
    } else {
      goto err;
    }
  }

good:
  js_pushboolean(J, 1);
  return;

err:
  js_pushboolean(J, 0);
}

static void jsB_quit(js_State *J) { exit(js_tonumber(J, 1)); }

static void jsB_repr(js_State *J) { js_repr(J, 1); }

static const char *require_js =
    "function require(name) {\n"
    "var cache = require.cache;\n"
    "if (name in cache) return cache[name];\n"
    "var exports = {};\n"
    "cache[name] = exports;\n"
    "Function('exports', read(name+'.js'))(exports);\n"
    "return exports;\n"
    "}\n"
    "require.cache = Object.create(null);\n";

static const char *stacktrace_js =
    "Error.prototype.toString = function() {\n"
    "var s = this.name;\n"
    "if ('message' in this) s += ': ' + this.message;\n"
    "if ('stackTrace' in this) s += this.stackTrace;\n"
    "return s;\n"
    "};\n";

static const char *console_js =
    "var console = { log: print, debug: print, warn: print, error: print };";

static char *read_stdin(void) {
  int n = 0;
  int t = 512;
  char *s = NULL;

  for (;;) {
    char *ss = realloc(s, t);
    if (!ss) {
      free(s);
      fprintf(stderr, "cannot allocate storage for stdin contents\n");
      return NULL;
    }
    s = ss;
    n += fread(s + n, 1, t - n - 1, stdin);
    if (n < t - 1)
      break;
    t *= 2;
  }

  if (ferror(stdin)) {
    free(s);
    fprintf(stderr, "error reading stdin\n");
    return NULL;
  }

  s[n] = 0;
  return s;
}

int main(int argc, char **argv) {
  char *input = NULL;
  js_State *J = NULL;
  int status = 0;
  int i = 0;
  int c = 0;

  J = js_newstate(NULL, NULL, 0);
  if (!J) {
    fprintf(stderr, "Could not initialize MuJS.\n");
    exit(-1);
  }

  js_newcfunction(J, jsB_gc, "gc", 0);
  js_setglobal(J, "gc");

  js_newcfunction(J, jsB_print, "print", 0);
  js_setglobal(J, "print");

  js_newcfunction(J, jsB_repr, "repr", 0);
  js_setglobal(J, "repr");

  js_dostring(J, stacktrace_js);
  js_dostring(J, console_js);

  // intentially vulnerable function here to test the fuzzer.
  js_newcfunction(J, magic, "magic", 0);
  js_setglobal(J, "magic");
  js_newcfunction(J, party, "party", 0);
  js_setglobal(J, "party");

  if (getenv("SNAPCHANGE_SNAPSHOT") != NULL) {
    input = malloc(0x4000);
    memset(input, 0, 0x4000);
    printf("SNAPSHOT buffer: %p\n", input);

    // Ensure the stdout has been flushed
    fflush(stdout);
    fflush(stderr);

    // Snapshot taken here
    __asm("int3");
    sleep(1);
    __asm("vmcall");

  } else {
    input = read_stdin();
  }

  // JS exec
  if (input == NULL) {
    status = 1;
  } else {
    status = js_dostring(J, input);
  }
  free(input);

  js_gc(J, 0);
  js_freestate(J);

  exit(status);
}
