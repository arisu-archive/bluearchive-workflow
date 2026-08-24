#!/usr/bin/env python3
"""Recover concatenated byte-array blobs from IL2CPP native binaries.

Unity splits a large `byte[]` literal into several `RuntimeHelpers.InitializeArray`
calls, each copying one chunk out of `global-metadata.dat`. This script recovers
those chunks straight from the shipped files:

On AMD64 Windows builds the chunk layout is recovered from PE code and
`Il2CppMetadataRegistration`. On AArch64 Android builds a PEM public key is
reassembled directly from its metadata-backed fragments.

Nothing depends on symbol names, an IDA database, or a prior Il2CppInspector run,
so it works on a freshly shipped binary.

AMD64 PE images and AArch64 ELF images are supported.
"""

import argparse
import base64
import bisect
import re
import struct
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs
from capstone.x86 import (
    X86_REG_DH,
    X86_REG_DL,
    X86_REG_DX,
    X86_REG_EDX,
    X86_REG_RDX,
    X86_REG_RIP,
)
from Crypto.PublicKey import RSA

METADATA_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31

# Kind stored in bits 31..29 of an unresolved metadata-usage token. The runtime
# resolver switches on this value; kind 4 selects the field-reference table.
FIELD_USAGE_KIND = 4

TYPE_DEFINITION_SIZE = 88
FIELD_DEFINITION_SIZE = 12
FIELD_DEFAULT_VALUE_SIZE = 12
FIELD_REF_SIZE = 8

PEM_BEGIN = b"-----BEGIN PUBLIC KEY-----"
PEM_END = b"-----END PUBLIC KEY-----"
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/=\r\n]{32,}")
BASE64_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
)

RDX_ALIASES = frozenset(
    (X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL, X86_REG_DH)
)

# Ordered offset/size pairs of Il2CppGlobalMetadataHeader, after sanity+version.
METADATA_SECTIONS = (
    "stringLiteral",
    "stringLiteralData",
    "string",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "fieldRefs",
    "referencedAssemblies",
    "attributeData",
    "attributeDataRange",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
    "exportedTypeDefinitions",
)


class ExtractionError(Exception):
    """Raised when the input files do not match the expected layout."""


class PE64:
    """Minimal read-only PE32+ reader (no third-party dependency)."""

    architecture = "amd64"

    def __init__(self, path):
        with open(path, "rb") as handle:
            self.data = handle.read()

        if self.data[:2] != b"MZ":
            raise ExtractionError(f"{path}: not a DOS/PE image")

        pe_off = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_off:pe_off + 4] != b"PE\0\0":
            raise ExtractionError(f"{path}: missing PE signature")

        coff = pe_off + 4
        machine, section_count = struct.unpack_from("<HH", self.data, coff)
        size_of_optional = struct.unpack_from("<H", self.data, coff + 16)[0]

        if machine != 0x8664:
            raise ExtractionError(f"{path}: unsupported machine {machine:#x}")

        self.optional_header = coff + 20
        magic = struct.unpack_from("<H", self.data, self.optional_header)[0]
        if magic != 0x20B:
            raise ExtractionError(f"{path}: not a PE32+ image (magic {magic:#x})")

        self.image_base = struct.unpack_from(
            "<Q", self.data, self.optional_header + 24
        )[0]
        self.size_of_image = struct.unpack_from(
            "<I", self.data, self.optional_header + 56
        )[0]

        table = self.optional_header + size_of_optional
        self.sections = []
        for i in range(section_count):
            base = table + i * 40
            name = self.data[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", self.data, base + 8
            )
            characteristics = struct.unpack_from("<I", self.data, base + 36)[0]

            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_pointer": raw_pointer,
                    "executable": bool(characteristics & 0x20000000),
                }
            )

    def data_directory(self, index):
        base = self.optional_header + 112 + index * 8
        return struct.unpack_from("<II", self.data, base)

    def section_body(self, section):
        start = section["raw_pointer"]
        return self.data[start:start + section["raw_size"]]

    def offset_from_rva(self, rva):
        for section in self.sections:
            span = max(section["virtual_size"], section["raw_size"])
            start = section["virtual_address"]
            if not start <= rva < start + span:
                continue

            delta = rva - start
            if delta >= section["raw_size"]:
                # Uninitialized tail; the image carries no bytes for this address.
                return None
            return section["raw_pointer"] + delta
        return None

    def read(self, va, size):
        offset = self.offset_from_rva(va - self.image_base)
        if offset is None:
            return None
        chunk = self.data[offset:offset + size]
        return chunk if len(chunk) == size else None

    def read_u64(self, va):
        chunk = self.read(va, 8)
        return None if chunk is None else int.from_bytes(chunk, "little")

    def in_image(self, va):
        return self.image_base < va < self.image_base + self.size_of_image


class Metadata:
    """Reader for the subset of global-metadata.dat this tool needs."""

    def __init__(self, path):
        with open(path, "rb") as handle:
            self.data = handle.read()

        magic, self.version = struct.unpack_from("<Ii", self.data, 0)
        if magic != METADATA_MAGIC:
            raise ExtractionError(f"{path}: bad metadata magic {magic:#x}")
        if self.version != METADATA_VERSION:
            raise ExtractionError(
                f"{path}: metadata version {self.version} unsupported "
                f"(expected {METADATA_VERSION})"
            )

        self.sections = {}
        for i, name in enumerate(METADATA_SECTIONS):
            offset, size = struct.unpack_from("<II", self.data, 8 + i * 8)
            if offset + size > len(self.data):
                raise ExtractionError(f"{path}: section {name} runs past end of file")
            self.sections[name] = (offset, size)

        self.type_definition_count = self._count(
            "typeDefinitions", TYPE_DEFINITION_SIZE
        )

    def _count(self, name, entry_size):
        _offset, size = self.sections[name]
        if size % entry_size:
            raise ExtractionError(
                f"section {name} size {size:#x} is not a multiple of {entry_size}"
            )
        return size // entry_size

    def string(self, index):
        offset, _size = self.sections["string"]
        start = offset + index
        end = self.data.index(b"\0", start)
        return self.data[start:end].decode("utf-8", "replace")

    def type_definition(self, index):
        offset, _size = self.sections["typeDefinitions"]
        base = offset + index * TYPE_DEFINITION_SIZE
        name_index, namespace_index = struct.unpack_from("<ii", self.data, base)
        field_start = struct.unpack_from("<i", self.data, base + 32)[0]
        return {
            "name_index": name_index,
            "namespace_index": namespace_index,
            "field_start": field_start,
        }

    def field_definition(self, index):
        offset, _size = self.sections["fields"]
        name_index, type_index, token = struct.unpack_from(
            "<iiI", self.data, offset + index * FIELD_DEFINITION_SIZE
        )
        return {"name_index": name_index, "type_index": type_index, "token": token}

    def field_refs(self):
        offset, size = self.sections["fieldRefs"]
        return [
            struct.unpack_from("<ii", self.data, offset + i * FIELD_REF_SIZE)
            for i in range(size // FIELD_REF_SIZE)
        ]

    def field_default_values(self):
        offset, size = self.sections["fieldDefaultValues"]
        out = {}
        for i in range(size // FIELD_DEFAULT_VALUE_SIZE):
            field_index, _type_index, data_index = struct.unpack_from(
                "<iii", self.data, offset + i * FIELD_DEFAULT_VALUE_SIZE
            )
            out[field_index] = data_index
        return out

    def default_value_offset(self, data_index):
        offset, _size = self.sections["fieldAndParameterDefaultValueData"]
        return offset + data_index

    def default_value_bytes(self, data_index, length):
        offset, size = self.sections["fieldAndParameterDefaultValueData"]
        if data_index < 0 or data_index + length > size:
            return None
        start = offset + data_index
        return self.data[start:start + length]


def binary_architecture(path):
    """Return the supported architecture identified by the native header."""
    with open(path, "rb") as handle:
        header = handle.read(20)

    if header[:2] == b"MZ":
        return "amd64"
    if header[:4] != b"\x7fELF":
        raise ExtractionError(f"{path}: unsupported binary format")
    if len(header) < 20 or header[4:6] != b"\x02\x01":
        raise ExtractionError(f"{path}: expected little-endian ELF64")

    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != 0xB7:
        raise ExtractionError(f"{path}: unsupported ELF machine {machine:#x}")
    return "aarch64"


def _without_line_breaks(data):
    return data.replace(b"\r", b"").replace(b"\n", b"")


def _expected_base64_length(prefix):
    padded = prefix + b"=" * (-len(prefix) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except ValueError as error:
        raise ExtractionError("public-key prefix is not valid base64") from error

    if len(decoded) < 2 or decoded[0] != 0x30:
        raise ExtractionError("public-key prefix is not a DER sequence")
    length_byte = decoded[1]
    if length_byte < 0x80:
        der_length = 2 + length_byte
    else:
        length_size = length_byte & 0x7F
        if not 0 < length_size <= 4 or len(decoded) < 2 + length_size:
            raise ExtractionError("public-key DER length is malformed")
        content_length = int.from_bytes(decoded[2:2 + length_size], "big")
        der_length = 2 + length_size + content_length
    return ((der_length + 2) // 3) * 4


def recover_public_key(data):
    """Reassemble one PEM public key split across metadata byte arrays."""
    if data.count(PEM_BEGIN) != 1 or data.count(PEM_END) != 1:
        raise ExtractionError("expected exactly one PEM public-key marker pair")

    begin = data.index(PEM_BEGIN)
    end = data.index(PEM_END)
    if end <= begin:
        raise ExtractionError("PEM public-key markers are out of order")

    prefix_start = begin + len(PEM_BEGIN)
    if data[prefix_start:prefix_start + 2] == b"\r\n":
        prefix_start += 2
    elif data[prefix_start:prefix_start + 1] in (b"\r", b"\n"):
        prefix_start += 1

    prefix_end = prefix_start
    while prefix_end < len(data) and data[prefix_end] in BASE64_BYTES:
        prefix_end += 1

    suffix_start = end
    while suffix_start > 0 and data[suffix_start - 1] in BASE64_BYTES:
        suffix_start -= 1

    prefix = _without_line_breaks(data[prefix_start:prefix_end])
    suffix = _without_line_breaks(data[suffix_start:end])
    expected_length = _expected_base64_length(prefix)
    missing_length = expected_length - len(prefix) - len(suffix)
    if missing_length < 0:
        raise ExtractionError("PEM fragments exceed the encoded DER length")

    middles = [b""] if missing_length == 0 else []
    for match in BASE64_RUN.finditer(data):
        if match.start() < prefix_end and match.end() > prefix_start:
            continue
        if match.start() < end and match.end() > suffix_start:
            continue
        candidate = _without_line_breaks(match.group())
        if len(candidate) == missing_length:
            middles.append(candidate)

    valid = set()
    for middle in middles:
        payload = prefix + middle + suffix
        lines = [payload[i:i + 64] for i in range(0, len(payload), 64)]
        pem = b"\n".join((PEM_BEGIN, *lines, PEM_END, b""))
        try:
            RSA.import_key(pem)
        except (IndexError, ValueError, TypeError):
            continue
        valid.add(pem)

    if len(valid) != 1:
        raise ExtractionError(f"expected one valid public key, found {len(valid)}")
    return valid.pop()


def pdata_index(pe):
    """Sorted function start/end RVAs from the PE exception directory."""
    rva, size = pe.data_directory(3)
    if not rva or not size:
        raise ExtractionError("image has no exception directory (.pdata)")

    base = pe.offset_from_rva(rva)
    if base is None:
        raise ExtractionError("exception directory is not backed by file data")

    starts, ends = [], []
    for i in range(size // 12):
        start, end, _unwind = struct.unpack_from("<III", pe.data, base + i * 12)
        starts.append(start)
        ends.append(end)

    order = sorted(range(len(starts)), key=lambda i: starts[i])
    return [starts[i] for i in order], [ends[i] for i in order]


def function_bounds(pe, index, va):
    """Containing function for a virtual address, or None."""
    starts, ends = index
    rva = va - pe.image_base
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0 or not starts[i] <= rva < ends[i]:
        return None
    return pe.image_base + starts[i], pe.image_base + ends[i]


def find_metadata_registration(pe, type_definition_count):
    """Locate Il2CppMetadataRegistration by its two typedef-count fields.

    `fieldOffsetsCount` and `typeDefinitionsSizesCount` both equal the typedef
    count and are separated by one pointer, which pins the structure without
    needing any symbol.
    """
    matches = []

    for section in pe.sections:
        if section["executable"] or section["name"] not in (".data", ".rdata"):
            continue

        body = pe.section_body(section)
        va_base = pe.image_base + section["virtual_address"]

        for offset in range(0, max(0, len(body) - 32), 8):
            if struct.unpack_from("<Q", body, offset)[0] != type_definition_count:
                continue
            if struct.unpack_from("<Q", body, offset + 16)[0] != type_definition_count:
                continue

            field_offsets = struct.unpack_from("<Q", body, offset + 8)[0]
            sizes = struct.unpack_from("<Q", body, offset + 24)[0]
            if not (pe.in_image(field_offsets) and pe.in_image(sizes)):
                continue

            # fieldOffsetsCount is the 11th field; rewind to the structure start.
            matches.append(va_base + offset - 80)

    if len(matches) != 1:
        raise ExtractionError(
            f"expected exactly one Il2CppMetadataRegistration, found {len(matches)}"
        )

    base = matches[0]
    types_count = pe.read_u64(base + 6 * 8)
    types = pe.read_u64(base + 7 * 8)
    if types is None or types_count is None or not pe.in_image(types):
        raise ExtractionError(f"metadata registration at {base:#x} looks malformed")

    return {"base": base, "types": types, "types_count": types_count}


def build_field_ref_table(pe, metadata, registration):
    """Map metadata-usage index to a global field-definition index.

    A fieldRef stores an `Il2CppType` index, which only the binary can resolve,
    plus a field index relative to the owning type's `fieldStart`.
    """
    table = {}

    for usage_index, (type_index, field_index) in enumerate(metadata.field_refs()):
        if not 0 <= type_index < registration["types_count"]:
            continue

        type_ptr = pe.read_u64(registration["types"] + type_index * 8)
        if type_ptr is None:
            continue

        type_data = pe.read_u64(type_ptr)
        if type_data is None:
            continue

        klass = type_data & 0xFFFFFFFF
        if klass >= metadata.type_definition_count:
            continue

        field_start = metadata.type_definition(klass)["field_start"]
        table[usage_index] = field_start + field_index

    return table


def decode_field_token(pe, slot_va):
    """Return `(token, usage_index)` if the slot holds a field token."""
    token = pe.read_u64(slot_va)
    if token is None or token > 0xFFFFFFFF:
        return None

    # The low bit marks a token the runtime has not resolved to a pointer yet.
    if not token & 1 or token >> 29 != FIELD_USAGE_KIND:
        return None

    return token, (token >> 1) & 0x0FFFFFFF


def is_rip_relative_rdx_load(insn):
    operands = insn.operands
    return (
        insn.mnemonic == "mov"
        and len(operands) == 2
        and operands[0].type == CS_OP_REG
        and operands[0].reg == X86_REG_RDX
        and operands[1].type == CS_OP_MEM
        and operands[1].mem.base == X86_REG_RIP
        and operands[1].mem.index == 0
    )


def is_edx_immediate(insn):
    operands = insn.operands
    return (
        insn.mnemonic == "mov"
        and len(operands) == 2
        and operands[0].type == CS_OP_REG
        and operands[0].reg == X86_REG_EDX
        and operands[1].type == CS_OP_IMM
    )


def analyze_function(pe, disassembler, start, end):
    """Recover the ordered chunk list emitted by one function.

    Returns `(chunks, warnings)`. Each chunk carries the metadata-usage index of
    the destination field and the element count passed to the array allocation.
    """
    code = pe.read(start, end - start)
    if code is None:
        return [], [f"function {start:#x} is not backed by file data"]

    chunks = []
    warnings = []

    staged_length = None  # `mov edx, imm32` seen since the last call.
    call_length = None  # Length that was live when the last call executed.
    call_va = None

    for insn in disassembler.disasm(code, start):
        if is_edx_immediate(insn):
            staged_length = insn.operands[1].imm
            continue

        if insn.mnemonic == "call":
            call_va = insn.address
            call_length = staged_length
            staged_length = None
            continue

        if is_rip_relative_rdx_load(insn):
            slot_va = insn.address + insn.size + insn.operands[1].mem.disp
            decoded = decode_field_token(pe, slot_va)
            if decoded is None:
                continue

            token, usage_index = decoded
            if call_length is None or call_va is None:
                warnings.append(
                    f"field load at {insn.address:#x} has no preceding "
                    "length/allocation pair"
                )
                continue

            chunks.append(
                {
                    "load_va": insn.address,
                    "slot_va": slot_va,
                    "token": token,
                    "usage_index": usage_index,
                    "length": call_length,
                    "allocation_va": call_va,
                }
            )
            call_length = None
            continue

        # Any other write to RDX/EDX invalidates a staged length.
        _read, written = insn.regs_access()
        if any(reg in RDX_ALIASES for reg in written):
            staged_length = None
            call_length = None

    return chunks, warnings


def scan_field_token_loads(pe):
    """Every `mov rdx, [rip+disp32]` whose slot holds a field token."""
    hits = []

    for section in pe.sections:
        if not section["executable"]:
            continue

        body = pe.section_body(section)
        va_base = pe.image_base + section["virtual_address"]

        pos = body.find(b"\x48\x8b\x15")
        while pos >= 0:
            disp = struct.unpack_from("<i", body, pos + 3)[0]
            va = va_base + pos
            if decode_field_token(pe, va + 7 + disp) is not None:
                hits.append(va)
            pos = body.find(b"\x48\x8b\x15", pos + 1)

    return hits


def resolve_chunks(metadata, field_refs, default_values, chunks):
    """Attach metadata provenance and payload bytes to each chunk."""
    resolved = []

    for chunk in chunks:
        field_index = field_refs.get(chunk["usage_index"])
        if field_index is None:
            raise ExtractionError(
                f"usage index {chunk['usage_index']:#x} at {chunk['load_va']:#x} "
                "has no field reference"
            )

        data_index = default_values.get(field_index)
        if data_index is None:
            raise ExtractionError(
                f"field {field_index} at {chunk['load_va']:#x} has no default value"
            )

        payload = metadata.default_value_bytes(data_index, chunk["length"])
        if payload is None:
            raise ExtractionError(
                f"default value for field {field_index} does not hold "
                f"{chunk['length']:#x} bytes"
            )

        field = metadata.field_definition(field_index)
        resolved.append(
            {
                **chunk,
                "field_index": field_index,
                "field_name": metadata.string(field["name_index"]),
                "data_index": data_index,
                "file_offset": metadata.default_value_offset(data_index),
                "payload": payload,
            }
        )

    return resolved


def candidate_functions(pe, metadata, field_refs, default_values, index, minimum):
    """Functions that concatenate at least `minimum` metadata-backed chunks."""
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True

    seen = set()
    found = []

    for load_va in scan_field_token_loads(pe):
        bounds = function_bounds(pe, index, load_va)
        if bounds is None or bounds[0] in seen:
            continue
        seen.add(bounds[0])

        chunks, warnings = analyze_function(pe, disassembler, *bounds)
        if warnings or len(chunks) < minimum:
            continue

        try:
            resolved = resolve_chunks(metadata, field_refs, default_values, chunks)
        except ExtractionError:
            continue

        found.append({"start": bounds[0], "end": bounds[1], "chunks": resolved})

    return found


def blob_of(chunks):
    return b"".join(chunk["payload"] for chunk in chunks)


def describe(function, verbose):
    blob = blob_of(function["chunks"])
    lines = [
        f"function {function['start']:#x}-{function['end']:#x} "
        f"({len(function['chunks'])} chunks, {len(blob)} bytes)"
    ]

    if verbose:
        for chunk in function["chunks"]:
            lines.append(
                f"  load {chunk['load_va']:#x}  token {chunk['token']:#010x}  "
                f"usage {chunk['usage_index']:#x}  field {chunk['field_index']}  "
                f"metadata {chunk['file_offset']:#x}  length {chunk['length']:#x}  "
                f"{chunk['field_name'][:32]}"
            )

    return "\n".join(lines)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Recover concatenated IL2CPP byte-array blobs from GameAssembly.dll "
            "or libil2cpp.so and global-metadata.dat without symbols."
        )
    )
    parser.add_argument(
        "--binary", required=True, help="path to GameAssembly.dll or libil2cpp.so"
    )
    parser.add_argument("--metadata", required=True, help="path to global-metadata.dat")

    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument(
        "--function-va",
        help="virtual address inside the function that builds the blob",
    )
    selector.add_argument(
        "--find",
        help="select the function whose blob contains this text (e.g. PUBLIC KEY)",
    )
    selector.add_argument(
        "--list",
        action="store_true",
        help="list every candidate function instead of extracting one",
    )

    parser.add_argument(
        "--min-chunks",
        type=int,
        default=2,
        help="minimum chunk count for --find/--list (default: 2)",
    )
    parser.add_argument("--output", help="write the blob here instead of stdout")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="report each chunk's token, field, and metadata offset",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    metadata = Metadata(args.metadata)
    architecture = binary_architecture(args.binary)

    if architecture == "aarch64":
        if not args.find or "PUBLIC KEY" not in args.find:
            raise ExtractionError(
                "AArch64 extraction supports --find PUBLIC KEY only"
            )

        offset, size = metadata.sections["fieldAndParameterDefaultValueData"]
        blob = recover_public_key(metadata.data[offset:offset + size])
        print(f"metadata public key ({len(blob)} bytes)", file=sys.stderr)
        if args.output:
            with open(args.output, "wb") as handle:
                handle.write(blob)
            print(f"wrote {len(blob)} bytes to {args.output}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(blob)
        return 0

    pe = PE64(args.binary)
    registration = find_metadata_registration(pe, metadata.type_definition_count)
    field_refs = build_field_ref_table(pe, metadata, registration)
    default_values = metadata.field_default_values()
    index = pdata_index(pe)

    if args.verbose:
        print(
            f"metadata registration {registration['base']:#x}, "
            f"{len(field_refs)} field references",
            file=sys.stderr,
        )

    if args.function_va:
        va = int(args.function_va, 0)
        bounds = function_bounds(pe, index, va)
        if bounds is None:
            raise ExtractionError(f"no .pdata function contains {va:#x}")

        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        chunks, warnings = analyze_function(pe, disassembler, *bounds)

        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        if not chunks:
            raise ExtractionError(f"function {bounds[0]:#x} builds no blob")

        selected = {
            "start": bounds[0],
            "end": bounds[1],
            "chunks": resolve_chunks(metadata, field_refs, default_values, chunks),
        }
    else:
        functions = candidate_functions(
            pe, metadata, field_refs, default_values, index, args.min_chunks
        )

        if args.list:
            for function in sorted(functions, key=lambda f: f["start"]):
                print(describe(function, args.verbose))
            print(f"{len(functions)} candidate functions", file=sys.stderr)
            return 0

        needle = args.find.encode()
        matched = [f for f in functions if needle in blob_of(f["chunks"])]
        if len(matched) != 1:
            raise ExtractionError(
                f"{len(matched)} functions produce a blob containing {args.find!r}"
            )
        selected = matched[0]

    blob = blob_of(selected["chunks"])
    print(describe(selected, args.verbose), file=sys.stderr)

    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(blob)
        print(f"wrote {len(blob)} bytes to {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(blob)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ExtractionError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
