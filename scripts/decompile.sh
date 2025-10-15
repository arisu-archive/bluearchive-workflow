#!/bin/bash

./.tools/Il2CppInspector.Redux.CLI -i ./libil2cpp.so -m global-metadata.dat \
    -l tree -c DiffableCs \
    --suppress-metadata --suppress-dll-metadata --select-outputs cs

echo "Extracting protocolConverter VA offset value..."
offset=$(rg -o --no-filename -B 2 -F "public int TypeConversion(uint crc, Protocol protocol)" ./DiffableCs/BlueArchive/MX/NetworkProtocol/ProtocolConverter.cs | rg -o -r '$1' 'Offset = "(0x[0-9A-Z]+)"')
echo "::notice title=VA Offset::$offset"
echo "offset=$offset" >> $GITHUB_OUTPUT
echo "Offset extracted."
