#!/bin/bash

./.tools/Il2CppInspector.Redux.CLI -i ./libil2cpp.so -m global-metadata.dat \
    -l tree -c DiffableCs \
    --suppress-metadata --suppress-dll-metadata --select-outputs cs

echo "Extracting protocolConverter VA offset value..."
offset=$(rg "^\s+public int TypeConversion\(uint crc, Protocol protocol\);.*// (0x[0-9A-F]+)-" -o --no-filename -r '$1' ./DiffableCs/BlueArchive/MX/NetworkProtocol/ProtocolConverter.cs)
echo "::notice title=VA Offset::$offset"
echo "offset=$offset" >> $GITHUB_OUTPUT
echo "Offset extracted."
