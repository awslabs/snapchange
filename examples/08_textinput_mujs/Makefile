DOCKER ?= docker
FUZZ_CORES ?= /2

DOCKER_IMAGE_NAME ?= snapchange_example8

all: base_images test

base_images:
	# Build the base snapchange image used for snapshotting
	$(MAKE) -C ../../docker

snapshot_image: Dockerfile harness/main.c harness/Makefile
ifeq ($(VERBOSE),1)
	$(DOCKER) build -t $(DOCKER_IMAGE_NAME):snapshot . -f $<
endif
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):snapshot . -f $< > $@

snapshot: snapshot_image
ifeq ($(VERBOSE),1)
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$(shell cat $<)
else
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$(shell cat $<) \
		>/dev/null 2>&1
endif
	cd snapshot; if ! test -L input; then rm -rf input || true; ln -s ../input; fi
	cd snapshot; if ! test -L dict; then rm -rf dict || true; ln -s ../dict/; fi

dict: dict.txt
	-mkdir -p dict
	python make_dict.py $<
	echo "magic" > dict/magic
	echo "party" > dict/party

fuzzer: dict
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
	-$(RM) -rf snapshot target

clean-docker:
	-$(DOCKER) rmi `cat ./snapshot_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):snapshot
	-$(RM) snapshot_image

.PHONY: fuzzer all base_images test reset fuzz
