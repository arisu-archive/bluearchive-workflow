#!/bin/bash

package_name=$1

cat output.json | jq -r '.[0].url' | \
    go run github.com/melbahja/got/cmd/got@latest -o output.xapk

if [ $? -ne 0 ]; then
    echo "Failed to download APK"
    exit 1
fi

echo "APK downloaded successfully"
