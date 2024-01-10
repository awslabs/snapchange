DOCKER ?= docker
FUZZ_CORES ?= /2

all: test

base_images:
	# Build the base snapchange image used for snapshotting
	cd ../../docker && make

snapshot_image: Dockerfile
	$(DOCKER) build -q -t snapchange_example7:snapshot . -f $< | tee $@ || { rm $@; exit 1; }

snapshot: snapshot_image harness/example.c
	# mkdir -p snapshot/
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$$(cat snapshot_image) >/dev/null 2>&1
	# Remove odd dictionary entries just to speed up the example
	find ./snapshot/dict -type f | grep -v cafe | grep -v dead | xargs rm
	# Remove the unneeded angr covbps since we are using the sancov bps
	rm snapshot/*angr.covbps
	cp config.toml snapshot/

fuzzer:
	cargo build -r >/dev/null 2>&1

fuzz: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES)

fuzz-%: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES) --stop-after-time $(shell echo $@ | sed 's/fuzz-//g')m
# .PHONY: fuzz-1 fuzz-2 fuzz-3 fuzz-4 fuzz-5

test: snapshot fuzzer reset
	./test.sh

reset: snapshot
	cd snapshot && ./reset.sh

clean: clean-docker
	-$(RM) -rf snapshot target

clean-docker:
	-$(DOCKER) rmi `cat ./dockers/snapshot_image`
	-rm ./dockers/snapshot_image
	-$(DOCKER) rmi `cat ./dockers/target_image`
	-rm ./dockers/target_image

.PHONY: fuzzer all base_images test reset fuzz
