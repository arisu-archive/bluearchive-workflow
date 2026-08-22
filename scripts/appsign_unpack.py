#!/usr/bin/env python3
"""Full unpacker for AppSign-packed shared objects (libappsign4a.so wrappers such
as libgentater.so / librontatre.so).

Give it the packed .so; it recovers every embedded entry in its original form.

Pipeline, all of it read out of the loader rather than guessed:

  1. trailer          sub_44B78: fseek(-44, SEEK_END), magic 0x4C54464D "MFTL",
                      then u32 version and four u64 fields
                      (payload offset, payload size, index offset, index size)

  2. index            sub_517DC decodes MessagePack; sub_450DC type-checks each
                      entry, which is what makes the key/IV roles unambiguous:

                        entry[0] str            name
                        entry[1] uint           payload offset
                        entry[2] uint           payload size
                        entry[3] bin, len == 16 AES IV
                        entry[4] bin, len == 32 AES key
                        entry[5] uint           size hint
                        entry[6] str            build tag

                      sub_582E8 picks AES-256 for a 32-byte key, so field 4 can
                      only be the key and field 3 only the IV.

  3. outer layer      AES-256-CBC over [offset, offset+size) -> TARA v3 container

  4. TARA header      sub_83284, 32 bytes:
                        +0  "TARA" + version 3 (checked as u64 0x341524154)
                        +8  ident
                        +12 wrapped key length (128 = RSA-1024)
                        +16 packed size, consumed rounded up to 16
                        +20 unpacked size
                        +24 LZMA props, 5 bytes

  5. key unwrap       the 128 bytes after the header are the RSA-wrapped session
                      key. sub_54E70 loads a public key as two equal MPIs (N||E),
                      sub_54E00 then does the public-key operation, so the unwrap
                      is a plain modexp with the key pair embedded in this same
                      file. This script finds that pair by scanning for an MPI
                      whose value is 65537 and taking the MPI in front of it as N,
                      then validates by PKCS#1 v1.5 structure.

                      The recovered plaintext is the first 32 bytes of the ORIGINAL
                      file: the packer (sub_83860) takes plaintext[0:32] as the AES
                      key and wraps it. Self-keying, which is why the wrapped blob
                      is identical across builds of the same product.

  6. inner layer      AES-256-CBC with that 32-byte key and an all-zero IV
                      (sub_83284 passes a zeroed 16-byte IV buffer)

  7. LZMA             sub_520EC = LzmaUncompress(dst, &dstlen, src, &srclen,
                      props, 5); raw LZMA1 stream, parameters from the props byte
                      and dictionary size

Usage:
  appsign_unpack.py libgentater.so                     # unpack into ./unpacked
  appsign_unpack.py libgentater.so -o out              # choose output directory
  appsign_unpack.py libgentater.so --verify-only       # parse + decode 1 MB, write nothing
  appsign_unpack.py libgentater.so --keep-intermediate # also write .tara / .wrappedkey

Requires pycryptodome. LZMA comes from the standard library.
"""

import argparse
import hashlib
import lzma
import os
import struct
import sys

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None

TRAILER_LEN = 44
TRAILER_MAGIC = 0x4C54464D  # "MFTL"
TARA_MAGIC_V3 = 0x341524154  # "TARA" + version 3
CHUNK = 8 << 20


class FormatError(Exception):
    pass


# --- MessagePack subset ----------------------------------------------------

def mp_read(buf, i):
    b = buf[i]
    i += 1
    if b <= 0x7F:
        return b, i
    if 0x80 <= b <= 0x8F:
        out = {}
        for _ in range(b & 0xF):
            k, i = mp_read(buf, i)
            v, i = mp_read(buf, i)
            out[k] = v
        return out, i
    if 0x90 <= b <= 0x9F:
        return mp_array(buf, i, b & 0xF)
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return buf[i:i + n].decode("utf-8", "replace"), i + n
    if b == 0xC0:
        return None, i
    if b == 0xC4:
        n = buf[i]
        i += 1
        return buf[i:i + n], i + n
    if b == 0xC5:
        n = struct.unpack_from(">H", buf, i)[0]
        i += 2
        return buf[i:i + n], i + n
    if b == 0xCC:
        return buf[i], i + 1
    if b == 0xCD:
        return struct.unpack_from(">H", buf, i)[0], i + 2
    if b == 0xCE:
        return struct.unpack_from(">I", buf, i)[0], i + 4
    if b == 0xCF:
        return struct.unpack_from(">Q", buf, i)[0], i + 8
    if b == 0xD9:
        n = buf[i]
        i += 1
        return buf[i:i + n].decode("utf-8", "replace"), i + n
    if b == 0xDC:
        n = struct.unpack_from(">H", buf, i)[0]
        return mp_array(buf, i + 2, n)
    raise FormatError("unsupported msgpack byte 0x%02x at %d" % (b, i - 1))


def mp_array(buf, i, n):
    out = []
    for _ in range(n):
        v, i = mp_read(buf, i)
        out.append(v)
    return out, i


# --- container -------------------------------------------------------------

def read_trailer(data):
    if len(data) < TRAILER_LEN:
        raise FormatError("file too small for a trailer")
    t = data[-TRAILER_LEN:]
    magic, version = struct.unpack_from("<II", t, 0)
    if magic != TRAILER_MAGIC:
        raise FormatError("no MFTL trailer (got 0x%08x) - not an AppSign package" % magic)
    off, size, idx_off, idx_len = struct.unpack_from("<QQQQ", t, 8)
    return {"version": version, "payload_off": off, "payload_size": size,
            "index_off": idx_off, "index_len": idx_len,
            "trailer_off": len(data) - TRAILER_LEN}


def parse_index(data, trailer):
    raw = data[trailer["index_off"]:trailer["index_off"] + trailer["index_len"]]
    root, _ = mp_read(raw, 0)
    if not isinstance(root, list):
        raise FormatError("index root is not an array")
    entries = []
    for item in root:
        if not isinstance(item, list) or len(item) != 7:
            raise FormatError("entry is not a 7-element array")
        name, off, size, iv, key, hint, tag = item
        if not isinstance(name, str):
            raise FormatError("entry[0] is not a string")
        if not isinstance(off, int) or not isinstance(size, int):
            raise FormatError("entry[1]/entry[2] are not uints")
        if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
            raise FormatError("entry[3] is not a 16-byte bin (IV)")
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise FormatError("entry[4] is not a 32-byte bin (key)")
        entries.append({"name": name, "offset": off, "size": size,
                        "iv": bytes(iv), "key": bytes(key),
                        "hint": hint, "tag": tag})
    return entries


def parse_tara(buf):
    if len(buf) < 32:
        raise FormatError("TARA shorter than its header")
    magic_ver = struct.unpack_from("<Q", buf, 0)[0]
    if magic_ver != TARA_MAGIC_V3:
        raise FormatError("not TARA v3 (u64 header is 0x%x)" % magic_ver)
    ident, wrapped_len, packed, unpacked = struct.unpack_from("<IIII", buf, 8)
    props = bytes(buf[24:29])
    return {"ident": ident, "wrapped_len": wrapped_len, "packed": packed,
            "packed_aligned": (packed + 15) & ~15, "unpacked": unpacked,
            "props": props, "wrapped_key": bytes(buf[32:32 + wrapped_len]),
            "body_off": 32 + wrapped_len}


# --- RSA public key recovery ----------------------------------------------

def find_public_keys(data, mpi_len, limit=64):
    """Locate embedded (N, E) pairs stored as two equal-size raw MPIs.

    sub_54E70 splits the blob in half and reads both halves with
    mbedtls_mpi_read_binary, so E is a full-width MPI: zeros then 01 00 01.
    """
    needle = b"\x00" * (mpi_len - 8) + b"\x01\x00\x01"
    out = []
    pos = 0
    while len(out) < limit:
        i = data.find(needle, pos)
        if i < 0:
            break
        pos = i + 1
        e_end = i + len(needle)
        e_start = e_end - mpi_len
        n_start = e_start - mpi_len
        if n_start < 0:
            continue
        n = int.from_bytes(data[n_start:e_start], "big")
        e = int.from_bytes(data[e_start:e_end], "big")
        if n >> (mpi_len * 8 - 8) == 0 or e != 65537:
            continue
        out.append({"offset": n_start, "n": n, "e": e})
    return out


def rsa_public_unwrap(wrapped, keys):
    """Public-key operation, then strip PKCS#1 v1.5 padding."""
    c = int.from_bytes(wrapped, "big")
    for k in keys:
        m = pow(c, k["e"], k["n"]).to_bytes(len(wrapped), "big")
        if m[0] != 0x00 or m[1] not in (0x01, 0x02):
            continue
        try:
            sep = m.index(b"\x00", 2)
        except ValueError:
            continue
        payload = m[sep + 1:]
        if len(payload) >= 32:
            return payload[:32], k
    return None, None


# --- LZMA ------------------------------------------------------------------

def lzma_filters(props):
    d = props[0]
    if d >= 9 * 5 * 5:
        raise FormatError("bad LZMA props byte 0x%02x" % d)
    lc = d % 9
    rem = d // 9
    lp = rem % 5
    pb = rem // 5
    dict_size = struct.unpack_from("<I", props, 1)[0]
    return [{"id": lzma.FILTER_LZMA1, "dict_size": max(dict_size, 4096),
             "lc": lc, "lp": lp, "pb": pb}], (lc, lp, pb, dict_size)


def lzma_stream(src, filters, expected, sink, limit=None):
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    written = 0
    pos = 0
    digest = hashlib.sha256()
    while pos < len(src) and (limit is None or written < limit):
        want = CHUNK if limit is None else min(CHUNK, limit - written)
        out = dec.decompress(src[pos:pos + CHUNK], max_length=want)
        pos += CHUNK
        if out:
            digest.update(out)
            sink(out)
            written += len(out)
        if dec.eof:
            break
    while limit is None and not dec.eof and written < expected:
        out = dec.decompress(b"", max_length=CHUNK)
        if not out:
            break
        digest.update(out)
        sink(out)
        written += len(out)
    return written, digest.hexdigest()


# --- main ------------------------------------------------------------------

def unpack(path, outdir, verify_only=False, keep_intermediate=False):
    if AES is None:
        raise FormatError("pycryptodome is required (pip install pycryptodome)")

    data = open(path, "rb").read()
    trailer = read_trailer(data)
    print("file    : %s (%d bytes)" % (path, len(data)))
    print("trailer : 0x%x  version %d" % (trailer["trailer_off"], trailer["version"]))
    print("payload : 0x%x + %d" % (trailer["payload_off"], trailer["payload_size"]))
    print("index   : 0x%x + %d" % (trailer["index_off"], trailer["index_len"]))

    entries = parse_index(data, trailer)
    print("entries : %d" % len(entries))

    rc = 0
    for e in entries:
        print()
        print("=== %s   (tag %s)" % (e["name"], e["tag"]))
        print("  outer offset : 0x%x" % e["offset"])
        print("  outer size   : %d" % e["size"])
        print("  outer key    : %s" % e["key"].hex())
        print("  outer IV     : %s" % e["iv"].hex())

        if e["offset"] + e["size"] > len(data):
            print("  ERROR: entry runs past end of file")
            rc = 1
            continue

        blob = data[e["offset"]:e["offset"] + e["size"]]
        plain = AES.new(e["key"], AES.MODE_CBC, e["iv"]).decrypt(blob[:len(blob) // 16 * 16])

        try:
            t = parse_tara(plain)
        except FormatError as exc:
            print("  ERROR: %s" % exc)
            rc = 1
            continue

        total = 32 + t["wrapped_len"] + t["packed_aligned"]
        print("  TARA ident   : 0x%08x" % t["ident"])
        print("  wrapped key  : %d bytes (RSA-%d)" % (t["wrapped_len"], t["wrapped_len"] * 8))
        print("  packed       : %d (aligned %d)" % (t["packed"], t["packed_aligned"]))
        print("  unpacked     : %d" % t["unpacked"])
        print("  layout check : %d vs %d -> %s"
              % (total, e["size"], "OK" if total == e["size"] else "MISMATCH"))
        if total != e["size"]:
            rc = 1

        keys = find_public_keys(data, t["wrapped_len"])
        inner_key, used = rsa_public_unwrap(t["wrapped_key"], keys)
        if inner_key is None:
            print("  ERROR: no embedded RSA public key unwrapped the session key "
                  "(%d candidates tried)" % len(keys))
            rc = 1
            if keep_intermediate and not verify_only:
                os.makedirs(outdir, exist_ok=True)
                base = os.path.join(outdir, e["name"])
                open(base + ".tara", "wb").write(plain)
                open(base + ".wrappedkey", "wb").write(t["wrapped_key"])
                print("  wrote        : %s.tara, %s.wrappedkey" % (base, base))
            continue

        print("  RSA pubkey   : file offset 0x%x, e=%d" % (used["offset"], used["e"]))
        print("  inner key    : %s" % inner_key.hex())
        print("  inner IV     : %s (zero, per sub_83284)" % (b"\x00" * 16).hex())

        body = plain[t["body_off"]:t["body_off"] + t["packed_aligned"]]
        stream = AES.new(inner_key, AES.MODE_CBC, bytes(16)).decrypt(body)[:t["packed"]]

        filters, (lc, lp, pb, dsz) = lzma_filters(t["props"])
        print("  LZMA         : props %s  lc=%d lp=%d pb=%d dict=%d"
              % (t["props"].hex(), lc, lp, pb, dsz))

        if verify_only:
            got = bytearray()
            n, _ = lzma_stream(stream, filters, t["unpacked"], got.extend, limit=1 << 20)
            print("  verify       : %d bytes decoded, head %s%s"
                  % (n, bytes(got[:4]).hex(),
                     "  (ELF)" if bytes(got[:4]) == b"\x7fELF" else ""))
            if bytes(got[:4]) != b"\x7fELF":
                print("  NOTE: output does not start with an ELF header")
            continue

        os.makedirs(outdir, exist_ok=True)
        base = os.path.join(outdir, e["name"])
        if keep_intermediate:
            open(base + ".tara", "wb").write(plain)
            open(base + ".wrappedkey", "wb").write(t["wrapped_key"])
        with open(base, "wb") as fh:
            written, sha = lzma_stream(stream, filters, t["unpacked"], fh.write)
        ok = written == t["unpacked"]
        print("  wrote        : %s" % base)
        print("  size         : %d vs header %d -> %s"
              % (written, t["unpacked"], "OK" if ok else "MISMATCH"))
        print("  sha256       : %s" % sha)
        head = open(base, "rb").read(4)
        print("  magic        : %s%s" % (head.hex(), "  (ELF)" if head == b"\x7fELF" else ""))
        if not ok:
            rc = 1

    return rc


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("path", help="packed .so")
    p.add_argument("-o", "--outdir", default="unpacked", help="output directory")
    p.add_argument("--verify-only", action="store_true",
                   help="parse and decode the first 1 MB only, write nothing")
    p.add_argument("--keep-intermediate", action="store_true",
                   help="also write the .tara container and .wrappedkey blob")
    args = p.parse_args(argv)
    try:
        return unpack(args.path, args.outdir, args.verify_only, args.keep_intermediate)
    except FormatError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
