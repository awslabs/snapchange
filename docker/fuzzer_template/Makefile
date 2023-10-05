PROJECT ?= $(shell basename $(PWD))
DOCKER ?= docker

all: snapshot fuzzer

fuzzer:
	cargo build --release

snapshot: snapshot_image
	$(DOCKER) run --rm -it -v $(PWD)/snapshot:/snapshot $(PROJECT).snapshot

snapshot_image: ./Dockerfile.snapshot harness_image
	$(DOCKER) build -f Dockerfile.snapshot --build-arg BASEIMG=$(PROJECT).harness -t $(PROJECT).snapshot .

harness_image: ./Dockerfile.harness
	$(DOCKER) build -f Dockerfile.harness -t $(PROJECT).harness .

shell: harness_image
	$(DOCKER) run --rm -it -v $(PWD)/snapshot:/snapshot --cap-add=SYS_PTRACE --security-opt seccomp=unconfined $(PROJECT).harness

.PHONY: snapshot snapshot_image harness_image shell fuzzer
