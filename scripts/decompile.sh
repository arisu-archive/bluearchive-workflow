#!/bin/bash

./.tools/Cpp2IL --force-binary-path ./libil2cpp.so \
    --force-metadata-path global-metadata.dat --force-unity-version 29 \
    --use-processor attributeinjector \
    --output-as diffable-cs --output-to ./

echo "Extracting protocolConverter VA offset value..."
offset=$(rg -o --no-filename -B 2 -F "public int TypeConversion(uint crc, Protocol protocol)" ./DiffableCs/BlueArchive/MX/NetworkProtocol/ProtocolConverter.cs | rg -o -r '$1' 'Offset = "(0x[0-9A-Z]+)"')
echo "::notice title=VA Offset::$offset"
echo "offset=$offset" >> $GITHUB_OUTPUT
echo "Offset extracted."
