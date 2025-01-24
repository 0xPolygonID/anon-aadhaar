#!/bin/bash

CIRCUIT=$(pwd)/src

ALL_HASH=""

# Determine which command to use for hashing
if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
    HASH_FIELD="{print \$1}"
elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
    HASH_FIELD="{print \$1}"
else
    echo "Error: Neither sha256sum nor shasum is available on this system."
    exit 1
fi

# Compute hashes for all files
for file in $(find "$CIRCUIT" -type f); do 
    ALL_HASH+="$($HASH_CMD "$file" | awk "$HASH_FIELD")"
done 

# Compute the final hash
if [[ "$HASH_CMD" == "sha256sum" ]]; then
    FINAL_HASH=$(echo -n "$ALL_HASH" | sha256sum | cut -d" " -f 1)
else
    FINAL_HASH=$(echo -n "$ALL_HASH" | shasum -a 256 | awk '{print $1}')
fi

echo "$FINAL_HASH"
