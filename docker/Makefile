CTRT ?= docker
GLOBAL_TAG ?= ghcr.io/awslabs/snapchange
KVM_GID ?= $(shell /bin/ls -lan /dev/kvm | cut -d' ' -f4)

all: snapshot_image base_fuzzer_image base_target_image

snapshot_image:
	$(CTRT) build -f Dockerfile.snapshot -t snapchange -t snapchange_snapshot -t $(GLOBAL_TAG) .

# mostly for testing
build-template:
	cd ./fuzzer_template && cargo --config 'patch."https://github.com/awslabs/snapchange".snapchange.path = "../../"' build

base_fuzzer_image:
	$(CTRT) build -t snapchange_base_fuzzer \
		--build-arg user=$(USER) \
		--build-arg group=kvm \
		--build-arg gid=$(KVM_GID) \
		-f Dockerfile.base_fuzzer \
		..

fuzzer_image: base_fuzzer_image
	$(CTRT) build -t snapchange_fuzzer \
		-f Dockerfile.fuzzer \
		..

base_target_image:
	# Build the base snapchange target container
	docker build -t snapchange_base_target \
	  -f Dockerfile.base_target \
	  .
