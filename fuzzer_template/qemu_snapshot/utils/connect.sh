#!/bin/bash
ssh -i ./IMAGE/bookworm.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
