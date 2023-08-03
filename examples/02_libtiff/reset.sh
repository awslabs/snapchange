#!/bin/bash
rm -rf snapshot
rm -rf target
rm fuzzer.log

docker rmi --force snapchange_example2:fuzzer
docker rmi --force snapchange_example2:snapshot
docker rmi --force snapchange_example2:target
