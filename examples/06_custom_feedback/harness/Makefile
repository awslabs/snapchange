ifeq ($(origin CC),default)
CC = clang
endif
CFLAGS ?= -O3 -ggdb -fuse-ld=lld -DCHECK_CODE

all: maze.small maze.big maze.big.nobt maze.small.nobt

maze.small: maze.c
	$(CC) $(CFLAGS) -DMAZE_SMALL -o $@ $<

maze.big: maze.c
	$(CC) $(CFLAGS) -DMAZE_BIG -o $@ $<

maze.small.nobt: maze.c
	$(CC) $(CFLAGS) -DMAZE_SMALL -DMAZE_NO_BT -o $@ $<

maze.big.nobt: maze.c
	$(CC) $(CFLAGS) -DMAZE_BIG -DMAZE_NO_BT -o $@ $<

clean:
	-$(RM) maze.small maze.big maze.big.nobt maze.small.nobt maze.small.fuzz maze.big.fuzz maze.big.bt.fuzz maze.small.bt.fuzz
