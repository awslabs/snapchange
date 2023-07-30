CC=clang
CFLAGS=-fsanitize=fuzzer -ggdb -O0

all: example

clean:
	-$(RM) example

solution:
	bash -c 'printf "fuzzmetosolveme!\xff\xca\xfe\xca\xfe\xca\xef\xbe\xad\xde" > solution'

.PHONY: clean all solution
