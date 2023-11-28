CC ?= clang-15

BASE_ADDR ?= 0x555555554000

all: test_cmpsolves test_cmpsolves.cmps

test_cmpsolves.cmps: test_cmpsolves
	python3 ../../../docker/coverage_scripts/bn_snapchange.py --cmp --analysis --bps --base-addr $(BASE_ADDR) ./test_cmpsolves
