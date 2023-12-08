DOCKER ?= docker
FUZZ_CORES ?= /2

all: test

base_images:
	# Build the base snapchange image used for snapshotting
	cd ../../docker && make

dockers/target_image:
	$(DOCKER) build -q -t snapchange_example1:target . -f dockers/Dockerfile.target | tee dockers/target_image

dockers/snapshot_image: dockers/target_image
	$(DOCKER) build -q -t snapchange_example1:snapshot . -f dockers/Dockerfile.snapshot | tee dockers/snapshot_image

snapshot: dockers/snapshot_image harness/example1.c
	# mkdir -p snapshot/
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$(shell cat dockers/snapshot_image)

fuzzer:
	cargo build -r

fuzz: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES)

fuzz-%: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES) --stop-after-time $(shell echo $@ | sed 's/fuzz-//g')m
# .PHONY: fuzz-1 fuzz-2 fuzz-3 fuzz-4 fuzz-5


test: base_images snapshot fuzzer reset
	./test.sh

reset: snapshot
	cd snapshot && ./reset.sh

clean: clean-docker
	-$(RM) -rf snapshot

clean-docker:
	-$(DOCKER) rmi `cat ./dockers/snapshot_image`
	-rm ./dockers/snapshot_image
	-$(DOCKER) rmi `cat ./dockers/target_image`
	-rm ./dockers/target_image

.PHONY: fuzzer all base_images test reset fuzz
