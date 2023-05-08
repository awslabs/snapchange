#!/bin/bash
scp -i ./IMAGE/bookworm.id_rsa -P 10021 -o "StrictHostKeyChecking no" $1 root@localhost:/root
