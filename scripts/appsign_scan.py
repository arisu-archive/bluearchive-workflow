#!/usr/bin/env python3
"""Fingerprint scanner for Wellbia AppSign / XIGNCODE artifacts.

Point it at files, directories or APKs. It identifies each artifact by structure,
never by filename, because the vendor randomizes names every release.

What it recognizes
------------------
  appsign-wrapper   packed .so: 44-byte "MFTL" trailer at EOF, decoy ELF in front.
                    Reports the MessagePack index: packed name, AES-256 key, IV,
                    build tag, plus the TARA v3 header behind the outer layer.
                    Also recovers the AES string key and the encrypted strings,
                    which is how you learn the CURRENT asset filename and the
                    randomized JNI class names.

  must3-container   Wellbia block container. Bare (asset, base 0) or appended to
                    a decoy ELF (base 0x4620). Lists its directory entries.

  tara              raw TARA v2/v3 module (packed sub-module, e.g. *.xem).

  xdna              "XdNa" key/value store record.

  elf               any other ELF: reports soname and notable exports
                    (JNI_OnLoad, ZCWAVE_*, ArdwProc).

  il2cpp-metadata   Unity global-metadata.dat (magic 0xFAB11BAF).

  dex               classes*.dex, with a note when it is a tiny loader stub.

Usage
-----
  appsign_scan.py <path> [<path> ...]      files, directories, or .apk/.zip
  appsign_scan.py jp/ --deep               also parse containers found inside APKs
  appsign_scan.py jp/base.apk --json       machine-readable output

Reading is done in slices, so a 44 MB wrapper costs a few KB of I/O.
AES work needs pycryptodome; without it the wrapper's keys are still reported
(they are plaintext in the index) but strings and TARA headers are skipped.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

TRAILER_LEN = 44
TRAILER_MAGIC = 0x4C54464D          # "MFTL"
TARA_MAGIC = b"TARA"
MUST_KEY0 = 0x7473754D
MUST_BASES = (0, 0x4620)
BS = 4096
IL2CPP_MAGIC = 0xFAB11BAF
NAME_RE = re.compile(rb"^[A-Za-z0-9_./+-]{5,120}$")
INTERESTING_EXPORTS = ("JNI_OnLoad", "ZCWAVE_", "ArdwProc", "il2cpp_init",
                       "Java_com_wellbia")


# --- readers ---------------------------------------------------------------

class FileReader:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self._fh = open(path, "rb")

    def read(self, off, n):
        if off < 0:
            off = max(0, self.size + off)
        self._fh.seek(off)
        return self._fh.read(n)

    def close(self):
        self._fh.close()


class BytesReader:
    def __init__(self, data, path):
        self.path = path
        self.size = len(data)
        self._d = data

    def read(self, off, n):
        if off < 0:
            off = max(0, self.size + off)
        return self._d[off:off + n]

    def close(self):
        pass


# --- ELF helpers -----------------------------------------------------------

def elf_segments(r):
    hdr = r.read(0, 64)
    if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
        return None
    e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", hdr, 0x36)
    ph = r.read(e_phoff, e_phentsize * e_phnum)
    loads, dyn = [], None
    for i in range(e_phnum):
        o = i * e_phentsize
        if o + 56 > len(ph):
            break
        p_type = struct.unpack_from("<I", ph, o)[0]
        p_off, p_va, _, p_fsz, _ = struct.unpack_from("<QQQQQ", ph, o + 8)
        if p_type == 1:
            loads.append((p_va, p_off, p_fsz))
        elif p_type == 2:
            dyn = (p_off, p_fsz)
    return {"loads": loads, "dyn": dyn}


def elf_info(r):
    seg = elf_segments(r)
    if not seg:
        return None
    info = {"soname": None, "needed": [], "exports": []}

    def v2o(v):
        for va, off, fsz in seg["loads"]:
            if va <= v < va + fsz:
                return off + (v - va)
        return None

    if seg["dyn"]:
        off, sz = seg["dyn"]
        raw = r.read(off, sz)
        ents = [struct.unpack_from("<QQ", raw, i * 16) for i in range(len(raw) // 16)]
        strv = [v for t, v in ents if t == 5]
        if strv:
            stro = v2o(strv[0])
            strsz = next((v for t, v in ents if t == 10), 0x2000)
            strtab = r.read(stro, min(strsz or 0x2000, 0x20000)) if stro is not None else b""

            def s(x):
                e = strtab.find(b"\0", x)
                return strtab[x:e].decode("latin1", "replace") if e >= 0 else ""

            for t, v in ents:
                if t == 14:
                    info["soname"] = s(v)
                elif t == 1:
                    info["needed"].append(s(v))
                elif t == 0:
                    break

    # exports: walk .dynsym via section headers (cheap enough)
    hdr = r.read(0, 64)
    e_shoff = struct.unpack_from("<Q", hdr, 0x28)[0]
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", hdr, 0x3A)
    if e_shoff and e_shnum and e_shoff + e_shentsize * e_shnum <= r.size:
        sh = r.read(e_shoff, e_shentsize * e_shnum)
        secs = [struct.unpack_from("<IIQQQQIIQQ", sh, i * e_shentsize) for i in range(e_shnum)]
        for s_ in secs:
            if s_[1] != 11:  # SHT_DYNSYM
                continue
            st = secs[s_[6]]
            strtab = r.read(st[4], min(st[5], 1 << 20))
            symtab = r.read(s_[4], min(s_[5], 1 << 20))
            for j in range(len(symtab) // 24):
                nm, _, _, shndx, _, _ = struct.unpack_from("<IBBHQQ", symtab, j * 24)
                if not nm or not shndx:
                    continue
                e = strtab.find(b"\0", nm)
                name = strtab[nm:e].decode("latin1", "replace")
                if any(k in name for k in INTERESTING_EXPORTS):
                    info["exports"].append(name)
    return info


# --- AppSign wrapper -------------------------------------------------------

def mp_read(buf, i):
    b = buf[i]
    i += 1
    if b <= 0x7F:
        return b, i
    if 0x90 <= b <= 0x9F:
        out = []
        for _ in range(b & 0xF):
            v, i = mp_read(buf, i)
            out.append(v)
        return out, i
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return buf[i:i + n].decode("utf-8", "replace"), i + n
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
        i += 2
        out = []
        for _ in range(n):
            v, i = mp_read(buf, i)
            out.append(v)
        return out, i
    raise ValueError("msgpack byte 0x%02x" % b)


def appsign_trailer(r):
    if r.size < TRAILER_LEN:
        return None
    t = r.read(r.size - TRAILER_LEN, TRAILER_LEN)
    if len(t) < TRAILER_LEN:
        return None
    magic, version = struct.unpack_from("<II", t, 0)
    if magic != TRAILER_MAGIC:
        return None
    off, size, idx_off, idx_len = struct.unpack_from("<QQQQ", t, 8)
    if idx_off + idx_len > r.size or off + size > r.size:
        return None
    return {"version": version, "payload_off": off, "payload_size": size,
            "index_off": idx_off, "index_len": idx_len}


def appsign_index(r, tr):
    raw = r.read(tr["index_off"], tr["index_len"])
    root, _ = mp_read(raw, 0)
    out = []
    for e in root:
        if not isinstance(e, list) or len(e) != 7:
            continue
        name, off, size, iv, key, hint, tag = e
        out.append({"name": name, "offset": off, "size": size,
                    "iv": bytes(iv).hex(), "key": bytes(key).hex(),
                    "tag": tag})
    return out


def appsign_tara(r, entry):
    """Decrypt just the first block to expose the TARA header."""
    if AES is None:
        return None
    blob = r.read(entry["offset"], 64)
    pt = AES.new(bytes.fromhex(entry["key"]), AES.MODE_CBC,
                 bytes.fromhex(entry["iv"])).decrypt(blob[:len(blob) // 16 * 16])
    if pt[:4] != TARA_MAGIC:
        return None
    ver = struct.unpack_from("<I", pt, 4)[0]
    ident, wrapped, packed, unpacked = struct.unpack_from("<IIII", pt, 8)
    props = pt[24:29]
    total = 32 + wrapped + ((packed + 15) & ~15)
    return {"version": ver, "ident": ident, "wrapped_len": wrapped,
            "packed": packed, "unpacked": unpacked, "props": props.hex(),
            "layout_ok": total == entry["size"]}


def appsign_strings(r, limit=12):
    """Recover the per-build AES string key/IV and the strings behind it.

    The key and IV sit immediately in front of the first encrypted blob. Scan the
    mapped image, treat [i:i+16] as key and [i+16:i+32] as IV, and accept the
    offset only when the blob at i+32 decrypts to a NUL-terminated name.
    """
    if AES is None:
        return None
    seg = elf_segments(r)
    if not seg:
        return None

    def harvest(data, i, key, iv):
        """Collect distinct plausible strings behind a candidate key/IV."""
        out = []
        for j in range(i + 32, min(len(data) - 256, i + 32 + 0x800), 8):
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data[j:j + 256])
            h = pt.split(b"\0")[0]
            if len(h) >= 6 and NAME_RE.match(h) and pt[len(h)] == 0:
                s = h.decode()
                if s not in out:
                    out.append(s)
                if len(out) >= limit:
                    break
        return out

    best = None
    for va, off, fsz in seg["loads"]:
        data = r.read(off, min(fsz, 1 << 22))
        for i in range(0, max(0, len(data) - 320), 8):
            key = data[i:i + 16]
            iv = data[i + 16:i + 32]
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data[i + 32:i + 96])
            h = pt.split(b"\0")[0]
            # a real record is a name of useful length holding a path or class separator
            if len(h) < 6 or not NAME_RE.match(h) or len(pt) <= len(h) or pt[len(h)] != 0:
                continue
            if b"." not in h and b"/" not in h:
                continue
            strings = harvest(data, i, key, iv)
            cand = {"key": key.hex(), "iv": iv.hex(), "va": va + i, "strings": strings}
            if best is None or len(strings) > len(best["strings"]):
                best = cand
            if len(strings) >= 4:      # asset name + two classes + two methods
                return best
    # a single lucky match is more likely noise than a real key table
    return best if best and len(best["strings"]) >= 2 else None


# --- Must3 container -------------------------------------------------------

def must_directory(r):
    for base in MUST_BASES:
        if base + BS > r.size:
            continue
        raw = r.read(base, BS)
        if len(raw) < BS:
            continue
        out = bytearray()
        for j in range(BS // 4):
            v = struct.unpack_from("<I", raw, 4 * j)[0] ^ ((MUST_KEY0 + j) & 0xFFFFFFFF)
            out += struct.pack("<I", v)
        if out[:5] not in (b"Must2", b"Must3"):
            continue
        blocks = (r.size - base) // BS
        ents = []
        for i in range(16, BS - 68, 68):
            e = out[i:i + 68]
            name = e[:32].split(b"\0")[0]
            if not name:
                break
            flags, size, count, start, fat = struct.unpack_from("<IIIII", e, 48)
            # reject noise: names are ASCII, data must fit, FAT block must exist
            if not NAME_RE.match(name) or size > r.size or fat >= blocks:
                return None
            ents.append({"name": name.decode("ascii", "replace"), "flags": flags,
                         "size": size, "fat": fat,
                         "mode": "indirect" if flags & 0x40000000 else "direct"})
        if not ents:
            return None
        return {"base": base, "version": chr(out[4]), "entries": ents}
    return None


# --- classification --------------------------------------------------------

def classify(r):
    res = {"path": r.path, "size": r.size, "kind": "unknown", "detail": {}}
    head = r.read(0, 64)

    tr = appsign_trailer(r)
    if tr:
        res["kind"] = "appsign-wrapper"
        res["detail"]["trailer"] = tr
        try:
            res["detail"]["index"] = appsign_index(r, tr)
        except Exception as exc:
            res["detail"]["index_error"] = str(exc)
        for e in res["detail"].get("index", []):
            t = appsign_tara(r, e)
            if t:
                e["tara"] = t
        info = elf_info(r)
        if info:
            res["detail"]["soname"] = info["soname"]
        st = appsign_strings(r)
        if st:
            res["detail"]["strings"] = st
        return res

    must = must_directory(r)
    if must:
        res["kind"] = "must3-container"
        res["detail"] = must
        return res

    if head[:4] == TARA_MAGIC:
        ver = struct.unpack_from("<I", head, 4)[0]
        ident, wrapped, packed, unpacked = struct.unpack_from("<IIII", head, 8)
        res["kind"] = "tara"
        res["detail"] = {"version": ver, "ident": ident, "wrapped_len": wrapped,
                         "packed": packed, "unpacked": unpacked,
                         "props": head[24:29].hex()}
        return res

    if r.read(30, 4) == b"XdNa":
        packed, unpacked = struct.unpack_from("<II", r.read(34, 8), 0)
        res["kind"] = "xdna"
        res["detail"] = {"name": r.read(0, 30).split(b"\0")[0].decode("latin1", "replace"),
                         "packed": packed, "unpacked": unpacked}
        return res

    if head[:8] in (b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00"):
        fs = struct.unpack_from("<I", r.read(32, 4), 0)[0]
        res["kind"] = "dex"
        res["detail"] = {"file_size": fs, "truncated": fs != r.size,
                         "stub": r.size < 100000}
        return res

    if len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] == IL2CPP_MAGIC:
        res["kind"] = "il2cpp-metadata"
        return res

    if head[:4] == b"\x7fELF":
        info = elf_info(r) or {}
        res["kind"] = "elf"
        res["detail"] = {"soname": info.get("soname"),
                         "exports": info.get("exports", [])[:8]}
        return res

    if head[:2] == b"PK":
        res["kind"] = "zip/apk"
        return res

    return res


# --- reporting -------------------------------------------------------------

def report(res, verbose=True):
    print("%-52s %-16s %10d" % (short(res["path"]), res["kind"], res["size"]))
    d = res["detail"]
    if res["kind"] == "appsign-wrapper":
        print("    soname       : %s" % d.get("soname"))
        tr = d["trailer"]
        print("    trailer      : v%d  payload 0x%x+%d  index 0x%x+%d"
              % (tr["version"], tr["payload_off"], tr["payload_size"],
                 tr["index_off"], tr["index_len"]))
        for e in d.get("index", []):
            print("    entry        : %s  (tag %s)" % (e["name"], e["tag"]))
            print("      offset/size: 0x%x / %d" % (e["offset"], e["size"]))
            print("      AES key    : %s" % e["key"])
            print("      AES IV     : %s" % e["iv"])
            t = e.get("tara")
            if t:
                print("      TARA v%d    : ident 0x%08x  wrapped %d  packed %d  unpacked %d  layout %s"
                      % (t["version"], t["ident"], t["wrapped_len"], t["packed"],
                         t["unpacked"], "OK" if t["layout_ok"] else "MISMATCH"))
        st = d.get("strings")
        if st:
            print("    string key   : %s  iv %s  (va 0x%x)" % (st["key"], st["iv"], st["va"]))
            print("    strings      : %s" % ", ".join(st["strings"]))
            assets = [s for s in st["strings"] if "/" not in s and "." in s]
            if assets:
                print("    -> asset name: %s" % ", ".join(assets))
    elif res["kind"] == "must3-container":
        print("    base 0x%x  Must%s  %d entries" % (d["base"], d["version"], len(d["entries"])))
        for e in d["entries"]:
            print("      %-28s flags=%#010x size=%-10d fat=%-6d %s"
                  % (e["name"], e["flags"], e["size"], e["fat"], e["mode"]))
    elif res["kind"] == "tara":
        print("    v%d ident 0x%08x wrapped %d packed %d unpacked %d props %s"
              % (d["version"], d["ident"], d["wrapped_len"], d["packed"],
                 d["unpacked"], d["props"]))
    elif res["kind"] == "xdna":
        print("    name %s  packed %d  unpacked %d" % (d["name"], d["packed"], d["unpacked"]))
    elif res["kind"] == "dex":
        note = " STUB" if d["stub"] else ""
        note += " TRUNCATED" if d["truncated"] else ""
        print("    file_size %d%s" % (d["file_size"], note))
    elif res["kind"] == "elf":
        print("    soname %s  exports %s" % (d.get("soname"), ", ".join(d.get("exports", [])) or "-"))


def short(p, n=52):
    p = p.encode("ascii", "replace").decode("ascii")
    return p if len(p) <= n else "..." + p[-(n - 3):]


# --- walking ---------------------------------------------------------------

def scan_path(path, deep, results):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in sorted(files):
                scan_path(os.path.join(root, f), deep, results)
        return

    if path.lower().endswith((".apk", ".zip", ".xapk", ".apks")):
        scan_zip(path, deep, results)
        return

    try:
        r = FileReader(path)
    except OSError as exc:
        print("%-52s open failed: %s" % (short(path), exc))
        return
    try:
        res = classify(r)
    finally:
        r.close()
    if res["kind"] != "unknown":
        results.append(res)
        report(res)


def scan_zip(path, deep, results):
    print("== %s" % path)
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        print("   not a zip: %s" % exc)
        return
    for info in z.infolist():
        if info.file_size < 64:
            continue
        interesting = (info.filename.endswith((".so", ".dex", ".dat"))
                       or info.filename.startswith("assets/")
                       or info.file_size > 1 << 20)
        if not interesting:
            continue
        if info.file_size > (256 << 20):
            continue
        try:
            data = z.read(info.filename)
        except Exception as exc:
            print("   %s: read failed (%s)" % (info.filename, exc))
            continue
        r = BytesReader(data, "%s!%s" % (os.path.basename(path), info.filename))
        res = classify(r)
        if res["kind"] in ("unknown", "zip/apk"):
            continue
        results.append(res)
        report(res)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("paths", nargs="+")
    p.add_argument("--deep", action="store_true", help="reserved for nested containers")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = p.parse_args(argv)

    results = []
    if args.json:
        import io
        buf, sys.stdout = sys.stdout, io.StringIO()
        for path in args.paths:
            scan_path(path, args.deep, results)
        sys.stdout = buf
        print(json.dumps(results, indent=1, default=str))
    else:
        if AES is None:
            print("note: pycryptodome missing - TARA headers and strings skipped\n")
        for path in args.paths:
            scan_path(path, args.deep, results)
        print("\n%d artifact(s) identified" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
