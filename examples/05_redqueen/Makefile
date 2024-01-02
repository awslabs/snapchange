DOCKER ?= docker
FUZZ_CORES ?= /2

all: base_images test

base_images:
	# Build the base snapchange image used for snapshotting
	$(MAKE) -C ../../docker

snapshot_image: Dockerfile.snapshot harness/test_cmpsolves harness/test_cmpsolves.cmps harness/test_cmpsolves.covbps
	$(DOCKER) build -q -t snapchange_example5:snapshot . -f $< | tee $@

snapshot: snapshot_image
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		$(shell cat $<)
	cp harness/*cmps ./snapshot/
	cp harness/*covbps ./snapshot/
	cp harness/*analysis ./snapshot/
	cp harness/config.toml ./snapshot/config.toml

fuzzer:
	cargo build -r

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
	-$(RM) -rf snapshot

clean-docker:
	-$(DOCKER) rmi `cat ./snapshot_image`
	-$(RM) snapshot_image

.PHONY: fuzzer all base_images test reset fuzz
