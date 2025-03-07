#!/bin/bash

package_name=$1

go run github.com/pokeguys/apk-crawler/cmd/crawler@v1.1.2 apkpure \
    -p $package_name --json > output.json
