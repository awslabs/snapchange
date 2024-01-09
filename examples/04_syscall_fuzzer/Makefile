DOCKER ?= docker
FUZZ_CORES ?= /2

DOCKER_IMAGE_NAME ?= snapchange_example4

all: test

base_images:
	$(MAKE) -C ../../docker/

base_images_old:
	# Build the base snapchange image used for snapshotting
	cd ../../docker && \
		$(DOCKER) build \
			-t snapchange_snapshot_linux_v5.4 \
			--build-arg LINUX_VERSION="v5.4" \
			--build-arg UBUNTU_VERSION="20.04" \
			. \
			-f Dockerfile.snapshot

dockers/target_image: dockers/Dockerfile.target
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):target . -f $< > $@ || { rm $@; exit 1; }

dockers/snapshot_image: dockers/Dockerfile.snapshot dockers/target_image
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):snapshot . -f $< > $@ || { rm $@; exit 1; }

snapshot: dockers/snapshot_image syscall_harness/Cargo.toml syscall_harness/src/main.rs
	# base_images is PHONY and we don't want that as dependency
	$(MAKE) base_images
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$$(cat dockers/snapshot_image) >/dev/null 2>&1

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
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):snapshot
	-rm ./dockers/snapshot_image
	-$(DOCKER) rmi `cat ./dockers/target_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):target
	-rm ./dockers/target_image

.PHONY: fuzzer all base_images test reset fuzz
