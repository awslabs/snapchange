all:
	echo "targets: clean test"

clean:
	-$(MAKE) -C ./01_getpid clean
	-$(MAKE) -C ./02_libtiff clean
	-$(MAKE) -C ./03_ffmpeg_custom_mutator clean
	-$(MAKE) -C ./04_syscall_fuzzer clean
	-$(MAKE) -C ./05_redqueen clean
	-$(MAKE) -C ./06_custom_feedback clean
	-$(MAKE) -C ./07_libfuzzer clean
	find . -name snapshot -exec sudo rm -rf \{\} \;

test:
	./test.sh
