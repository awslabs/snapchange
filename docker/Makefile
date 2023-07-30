CTRT ?= docker
GLOBAL_TAG ?= ghcr.io/awslabs/snapchange

image:
	$(CTRT) build -t snapchange -t $(GLOBAL_TAG) .

build-template:
	cd ./fuzzer_template && cargo --config 'patch."https://github.com/awslabs/snapchange".snapchange.path = "../../"' build
