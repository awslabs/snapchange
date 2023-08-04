#!/bin/bash
rm -rf snapshot
rm -rf target
rm fuzzer.log

docker rmi --force snapchange_example4:fuzzer
docker rmi --force snapchange_example4:snapshot
docker rmi --force snapchange_example4:target
