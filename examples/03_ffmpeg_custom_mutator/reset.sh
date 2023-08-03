#!/bin/bash
rm -rf snapshot
rm -rf target
rm fuzzer.log
docker rmi --force snapchange_example3:fuzzer
docker rmi --force snapchange_example3:snapshot
docker rmi --force snapchange_example3:target
