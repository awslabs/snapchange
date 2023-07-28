CFLAGS=-ggdb -O0 -static

all: example check what

what:
	echo "ABCD" > what

solution:
	bash -c 'printf "\xad\xde\xef\xbeYOLO" > solution'

clean:
	-$(RM) example check what tahw solution

.PHONY: clean all solution
