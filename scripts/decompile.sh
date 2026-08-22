#!/bin/bash

./.tools/Il2CppInspector.Redux.CLI process libil2cpp.so global-metadata.dat \
    -s --layout tree --suppress-dll-metadata

echo "Extracting protocolConverter VA offset value..."
offset=$(rg "^\s+public int TypeConversion\(uint crc, Protocol protocol\);.*// (0x[0-9A-F]+)-" -o --no-filename -r '$1' ./cs/BlueArchive/Mx/NetworkProtocol/ProtocolConverter.cs)
echo "::notice title=VA Offset::$offset"
echo "offset=$offset" >> $GITHUB_OUTPUT
echo "Offset extracted."
