all:
	clang-15 test_cmpsolves.c -o test_cmpsolves
	python3 ../../../docker/coverage_scripts/bn_snapchange.py --cmp --analysis --bps --base-addr 0x555555554000 ./test_cmpsolves
