#!/bin/bash

package_name=$1
force_update=$2

if [ ! -f output.json ]; then
    echo "APK version not found. Skipping..."
    echo "skip=true" >> $GITHUB_OUTPUT
    exit 0
fi

latest_version=$(cat output.json | jq -jr '.[0].version')
echo "version=$latest_version" >> $GITHUB_OUTPUT
echo "::notice title=Latest APK Version::$latest_version"
if [ -z "$latest_version" ]; then
    echo "Latest version not found. Skipping..."
    echo "skip=true" >> $GITHUB_OUTPUT
    exit 0
fi

if [ "$force_update" = "true" ]; then
    echo "Skipping version check. Force update"
    echo "skip=false" >> $GITHUB_OUTPUT
    exit 0
fi

current_version=$(curl -s https://ba.pokeguy.dev/$package_name/version.txt)
if [ "$current_version" = "$latest_version" ]; then
    echo "No update needed. Skipping..."
    echo "skip=true" >> $GITHUB_OUTPUT
    exit 0
fi
echo "skip=false" >> $GITHUB_OUTPUT
