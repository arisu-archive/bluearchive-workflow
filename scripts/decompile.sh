#!/bin/bash

./.tools/Il2CppInspector -i ./libil2cpp.so \
    -m ./global-metadata.dat \
    -l tree \
    -c DiffableCs \
    --suppress-dll-metadata \
    --select-outputs cs

echo "Extracting protocolConverter VA offset value..."
offset=$(rg "^\s+public int TypeConversion\(uint crc, Protocol protocol\);.*// (0x[0-9A-F]+)-" -o --no-filename -r '$1' ./DiffableCs/BlueArchive/MX/NetworkProtocol/ProtocolConverter.cs)
echo "::notice title=VA Offset::$offset"
echo "offset=$offset" >> $GITHUB_OUTPUT
echo "Offset extracted."

echo "Extracting the public key"
python ./scripts/extract_key.py --binary libil2cpp.so --metadata global-metadata.dat --find "BEGIN PUBLIC KEY" --output key.pem
