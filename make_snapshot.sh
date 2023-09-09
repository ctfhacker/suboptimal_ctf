#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
if [[ "$(docker images -q snapchange_snapshot 2> /dev/null)" == "" ]]; then
    echo "Create snapchange_snapshot docker from snapchange github"
    exit 1
fi

# Create the patched binary with `int3 ; vmcall` at `main`
cp suboptimal suboptimal.patched
r2 -q -w -c 's main ; wx cc0f01c1cdcdcdcd' suboptimal.patched

# Build the target Dockerfile
docker build -t ctf_suboptimal:target . -f dockers/Dockerfile.target

# Combine the target the snapshot mechanism
docker build -t ctf_suboptimal:snapshot . -f dockers/Dockerfile.snapshot

# Run the image to take the snapshot
docker run --rm -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    ctf_suboptimal:snapshot

# Replace the original bytes that we overwrote to take the snapshot
BYTES=`r2 -q -c 'p8 16 @ main' suboptimal`
r2 -w -q -c "/x cc0f01c1cdcdcdcd ; wx $BYTES @ hit0_0" ./snapshot/fuzzvm.physmem
