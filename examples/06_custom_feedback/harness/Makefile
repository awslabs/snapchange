ifeq ($(origin CC),default)
CC = clang
endif
CFLAGS ?= -O3 -ggdb -fuse-ld=lld

all: maze

clean:
	-$(RM) maze
