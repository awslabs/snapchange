ifeq ($(origin CC),default)
CC = clang
endif
# CFLAGS ?= -O3 -ggdb -fuse-ld=lld -fsanitize=address -fno-omit-frame-pointer -flto
CFLAGS ?= -O3 -ggdb -fuse-ld=lld -fno-omit-frame-pointer -flto

mujs_harness: main.c mujs-1.3.4 Makefile
	$(CC) $(CFLAGS) -o $@ $< ./mujs-1.3.4/one.c -I./mujs-1.3.4/ -lm

mujs_harness.asan: main.c mujs-1.3.4 Makefile
	$(CC) $(CFLAGS) -fsanitize=address -o $@ $< ./mujs-1.3.4/one.c -I./mujs-1.3.4/ -lm

clean:
	-$(RM) mujs_harness

mujs-1.3.4:
	curl -q https://mujs.com/downloads/mujs-1.3.4.tar.gz | tar xz
