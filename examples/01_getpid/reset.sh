#!/bin/bash
rm -rf snapshot
rm -rf target
rm fuzzer.log

docker rmi --force snapchange_example1:fuzzer
docker rmi --force snapchange_example1:snapshot
docker rmi --force snapchange_example1:target
