#!/bin/bash
rm -rf snapshot
rm -rf target
rm fuzzer.log

docker rmi --force ctf_suboptimal:fuzzer
docker rmi --force ctf_suboptimal:snapshot
docker rmi --force ctf_suboptimal:target
