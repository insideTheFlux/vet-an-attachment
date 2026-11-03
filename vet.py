#!/usr/bin/env python3
"""attachment-vet: check files a stranger attached on GitHub, on a throwaway machine, before anyone downloads them.

Usage: python3 -I vet.py [--work DIR] URL...   (or the URLs, separated by spaces, in the URLS environment variable)

Nothing downloaded is ever run, imported or opened in a viewer. The files are only read as bytes, by `file`, by
exiftool and by ClamAV. README.md describes each step.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

MIB = 1024 * 1024
MAX_DOWNLOAD = 200 * MIB  # bytes curl may fetch for one link
MAX_EXTRACT = 200 * MIB  # bytes written when unpacking one archive
MAX_RATIO = 100  # unpacked:packed above this, for an entry over 1 MiB, is a zip bomb
MAX_ENTRIES = 1000
MAX_URLS = 10
MAX_PRINT = 30_000  # characters of one XMP regions block printed as written
MAX_XMP_PARSE = 8 * MIB
MAX_SAMSUNG_BLOCK = 64 * 1024  # a Samsung trailer block larger than this (a motion photo's video…) is a warning

URL_RE = re.compile(
    r"https://github\.com/(?:user-attachments/files|[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/files)"
    r"/[0-9]{1,20}/[A-Za-z0-9._%-]{1,200}"
)

# Extensions that run code when opened (DANGER), can carry scripts or macros (WARN), or are archives we don't open.
RUN_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".lnk", ".url", ".msi", ".msp", ".cpl", ".jar", ".reg", ".iso", ".img", ".vhd", ".vhdx",
    ".appx", ".msix", ".application", ".sh", ".py", ".pyw", ".pl", ".rb", ".app", ".dmg", ".pkg", ".command",
    ".scpt", ".so", ".dylib", ".sys", ".chm", ".library-ms", ".settingcontent-ms",
}
ACTIVE_EXTS = {".svg", ".html", ".htm", ".xhtml", ".pdf", ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab", ".arj", ".lzh", ".zst"}
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}

BINARY_SIGS = [
    (b"MZ\x90\x00", "Windows/DOS executable header", "DANGER"),
    (b"This program cannot be run in DOS mode", "Windows executable stub", "DANGER"),
    (b"\x7fELF", "Linux executable", "DANGER"),
    (b"\xcf\xfa\xed\xfe", "macOS executable", "DANGER"),
    (b"PK\x03\x04", "ZIP archive", "WARN"),
    (b"%PDF-", "PDF document", "WARN"),
    (b"Rar!\x1a\x07", "RAR archive", "WARN"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "WARN"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Microsoft Office (OLE) file", "WARN"),
]
TEXT_SIGS = [  # matched without regard to case
    (b"<script", "script tag"),
    (b"<?php", "PHP code"),
    (b"<html", "HTML page"),
    (b"<iframe", "iframe"),
    (b"javascript:", "javascript: link"),
    (b"#!/bin/", "shell script line"),
    (b"#!/usr/", "script interpreter line"),
    (b"powershell", "PowerShell"),
    (b"cmd.exe", "cmd.exe"),
]

RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
X_NS = "adobe:ns:meta/"
XML_NS = "http://www.w3.org/XML/1998/namespace"
MWG_RS = "http://www.metadataworkinggroup.com/schemas/regions/"
ST_DIM = "http://ns.adobe.com/xap/1.0/sType/Dimensions#"
ST_AREA = "http://ns.adobe.com/xmp/sType/Area#"
MP_NS = "http://ns.microsoft.com/photo/1.2/"
TIFF = "http://ns.adobe.com/tiff/1.0/"
EXIF = "http://ns.adobe.com/exif/1.0/"
XMP_NS = "http://ns.adobe.com/xap/1.0/"
RDF_CONTAINERS = {f"{{{RDF}}}Bag", f"{{{RDF}}}Seq", f"{{{RDF}}}Alt"}
WANTED_XMP_VALUES = {
    (TIFF, "Orientation"), (TIFF, "ImageWidth"), (TIFF, "ImageLength"),
    (EXIF, "PixelXDimension"), (EXIF, "PixelYDimension"), (XMP_NS, "CreatorTool"),
}
REGION_ROOTS = [(MWG_RS, "Regions"), (MP_NS, "RegionInfo")]

XMP_ID = b"http://ns.adobe.com/xap/1.0/"
XMP_EXT_ID = b"http://ns.adobe.com/xmp/extension/"
KNOWN_APP = (
    b"JFIF", b"JFXX", b"Exif", XMP_ID, XMP_EXT_ID, b"ICC_PROFILE", b"MPF", b"Adobe", b"Photoshop 3.0", b"Ducky",
    b"FPXR", b"Meta", b"AROT", b"HDR_GAIN_INFO", b"urn:iso:std:iso:ts:21496:-1",
)
SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
MARKER_NAMES = {0xC4: "DHT", 0xCC: "DAC", 0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xDC: "DNL",
                0xDD: "DRI", 0xDE: "DHP", 0xDF: "EXP", 0xFE: "COM"}
COMPRESSION = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 99: "AES"}

# exiftool tags printed with their values; every other tag is listed by name only (GPS, dates, people, serials…).
SHOWN_TAGS = {
    "FileType", "MIMEType", "ImageWidth", "ImageHeight", "ExifImageWidth", "ExifImageHeight", "Orientation", "Make",
    "Model", "Software", "CreatorTool", "ImageSize", "PixelXDimension", "PixelYDimension", "ImageLength",
    "EncodingProcess", "ColorComponents", "BitsPerSample", "Warning", "Error",
}

LEVELS = {"NOTE": 0, "WARN": 1, "DANGER": 2}
VERDICTS = ("SAFE", "SUSPICIOUS", "DANGEROUS")


# ---------------------------------------------------------------- small helpers

def finding(level: str, what: str) -> dict:
    return {"level": level, "what": what}


def verdict(findings: list[dict]) -> str:
    return VERDICTS[max((LEVELS[f["level"]] for f in findings), default=0)]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable(raw, limit: int = 200) -> str:
    """Bytes or text shown safely on one log line: control and invisible characters escaped, cut at `limit`."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    out = []
    for c in text[:limit]:
        if unicodedata.category(c)[0] == "C":
            out.append(f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return "".join(out) + ("…" if len(text) > limit else "")


def find_all(hay: bytes, needle: bytes, limit: int = 5) -> list[int]:
    out, start = [], 0
    while len(out) < limit:
        j = hay.find(needle, start)
        if j < 0:
            break
        out.append(j)
        start = j + 1
    return out


def run_tool(cmd: list[str], data: bytes | None = None, timeout: int = 120) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def file_type(path: Path) -> str:
    r = run_tool(["file", "-b", str(path)])
    return printable(r.stdout.decode("utf-8", "replace").strip(), 300) if r else "(the file command is not available)"


def file_type_bytes(data: bytes) -> str:
    r = run_tool(["file", "-b", "-"], data=data[:MIB])
    return printable(r.stdout.decode("utf-8", "replace").strip(), 200) if r else "(unknown)"


def flat_name(name: str, idx: int, used: set[str]) -> str:
    """A safe file name for an archive entry: no folders, no `..`, only plain characters, unique (case-blind)."""
    parts = [p for p in re.split(r"[\\/]", name) if p not in ("", ".", "..")]
    base = re.sub(r"[^A-Za-z0-9 ._-]", "_", "__".join(parts)).strip(" .")[:150] or f"entry{idx}"
    candidate, n = base, 1
    while candidate.lower() in used:
        candidate, n = f"{n}_{base}", n + 1
    used.add(candidate.lower())
    return candidate


# ---------------------------------------------------------------- step 4: download

def download(url: str, dest: Path, limit: int = MAX_DOWNLOAD) -> tuple[Path, dict]:
    out = dest / flat_name(url.rsplit("/", 1)[-1], 0, set())
    cmd = [
        "curl", "--silent", "--show-error", "--location", "--fail", "--proto", "=https", "--proto-redir", "=https",
        "--max-redirs", "5", "--max-time", "180", "--max-filesize", str(limit), "--output", str(out),
        "--write-out", "%{url_effective}\\n%{content_type}\\n%{http_code}", url,
    ]
    r = run_tool(cmd, timeout=240)
    if r is None:
        raise RuntimeError("curl could not be started")
    if r.returncode != 0:
        raise RuntimeError(f"download failed (curl exit {r.returncode}): {printable(r.stderr.strip())}")
    final, ctype, code = (r.stdout.decode("utf-8", "replace").split("\n") + ["", "", ""])[:3]
    if out.stat().st_size > limit:
        out.unlink()
        raise RuntimeError(f"larger than {limit} bytes")
    # the signed storage link's query string is a credential for a few minutes: never print it
    return out, {"served_from": printable(final.split("?", 1)[0], 300), "content_type": printable(ctype, 100), "http": code}


# ---------------------------------------------------------------- step 5: the archive, before unpacking

def entry_kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & 0xFFFF
    if info.create_system == 3 and stat.S_ISLNK(mode):
        return "symlink"
    return "dir" if info.is_dir() else "file"


def is_mac_extra(name: str) -> bool:
    parts = re.split(r"[\\/]", name)
    return parts[0] == "__MACOSX" or parts[-1].startswith("._") or parts[-1] == ".DS_Store"


def check_name(name: str) -> list[dict]:
    f = []
    parts = re.split(r"[\\/]", name)
    if name.startswith(("/", "\\")):
        f.append(finding("DANGER", "absolute path: it unpacks outside the target folder"))
    if re.match(r"[A-Za-z]:", name):
        f.append(finding("DANGER", "drive letter: it unpacks outside the target folder on Windows"))
    elif ":" in name:
        f.append(finding("DANGER", "colon in the name: a hidden Windows alternate data stream"))
    if ".." in parts:
        f.append(finding("DANGER", "`..` in the path: it unpacks outside the target folder"))
    if "\\" in name:
        f.append(finding("WARN", "backslash in the path: unpackers disagree on what it means"))
    if any(unicodedata.category(c) in ("Cc", "Cf") for c in name):
        f.append(finding("DANGER", "control or invisible characters in the name (such as a right-to-left override "
                                   "that hides the real extension)"))
    if len(name.encode("utf-8", "replace")) > 255:
        f.append(finding("WARN", "name longer than 255 bytes"))
    for p in parts:
        if p in ("", ".", ".."):
            continue
        if p.split(".")[0].strip().upper() in RESERVED:
            f.append(finding("DANGER", f"`{printable(p)}` is a reserved device name on Windows"))
        if p != p.rstrip(". "):
            f.append(finding("WARN", f"`{printable(p)}` ends in a dot or a space, which Windows drops"))
    ext = os.path.splitext(parts[-1])[1].lower()
    if ext in RUN_EXTS:
        f.append(finding("DANGER", f"`{printable(ext)}` file: it can run code"))
    elif ext in ACTIVE_EXTS:
        f.append(finding("WARN", f"`{printable(ext)}` file: it can carry scripts or macros"))
    elif ext in ARCHIVE_EXTS:
        f.append(finding("WARN", f"`{printable(ext)}` archive inside the archive: its contents aren't checked"))
    return f


def check_entry(info: zipfile.ZipInfo, data: bytes) -> dict:
    kind = entry_kind(info)
    size, packed = info.file_size, info.compress_size
    ratio = size / packed if packed else (None if size else 0.0)
    e = {
        "name": info.filename, "kind": kind, "size": size, "packed": packed,
        "ratio": None if ratio is None else round(ratio, 1),
        "method": COMPRESSION.get(info.compress_type, f"#{info.compress_type}"),
        "encrypted": bool(info.flag_bits & 0x1),
        "mode": oct((info.external_attr >> 16) & 0xFFFF) if info.create_system == 3 else "-",
        "findings": check_name(info.filename),
    }
    f = e["findings"]
    if kind == "symlink":
        f.append(finding("DANGER", "symbolic link: once unpacked it can point anywhere on the disk"))
    if e["encrypted"]:
        f.append(finding("WARN", "encrypted: its contents can't be checked"))
    if info.compress_type not in COMPRESSION:
        f.append(finding("WARN", f"unknown compression method {info.compress_type}"))
    if (ratio is None and size > 0) or (ratio is not None and ratio > MAX_RATIO and size > MIB):
        f.append(finding("DANGER", f"packs {size} bytes into {packed}: a zip bomb"))
    if is_mac_extra(info.filename):
        f.append(finding("NOTE", "macOS Finder metadata: not unpacked"))
    off = info.header_offset
    if off < 0 or off + 30 > len(data) or data[off:off + 4] != b"PK\x03\x04":
        f.append(finding("DANGER", "the archive's index points at no entry here: unpackers disagree on what the "
                                   "archive holds"))
    else:
        (nlen,) = struct.unpack_from("<H", data, off + 26)
        local = data[off + 30:off + 30 + nlen]
        central = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437", "replace")
        if local != central:
            f.append(finding("WARN", f"its own header names it `{printable(local)}`: unpackers disagree on the name"))
    return e


def looks_like_zip(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04" or b"PK\x05\x06" in data[-(65535 + 22):]


def inspect_zip(data: bytes, max_total: int = MAX_EXTRACT) -> tuple[list[dict], list[dict]]:
    """Every entry of the archive and what is wrong with it, read from its index without unpacking anything."""
    findings: list[dict] = []
    entries: list[dict] = []
    if not data.startswith(b"PK\x03\x04"):
        findings.append(finding("WARN", f"something sits in front of the archive (first bytes {data[:8].hex(' ')}): "
                                        "a file that is two formats at once"))
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        findings.append(finding("DANGER", "no end-of-archive record: not a whole ZIP file"))
        return entries, findings
    (comment_len,) = struct.unpack_from("<H", data, eocd + 20)
    after = len(data) - (eocd + 22 + comment_len)
    if after > 0:
        findings.append(finding("WARN", f"{after} bytes after the end of the archive: something is appended"))
    elif after < 0:
        findings.append(finding("WARN", "the archive comment runs past the end of the file"))
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as err:  # a hostile archive can make zipfile raise almost anything
        findings.append(finding("DANGER", f"not a readable ZIP: {printable(err)}"))
        return entries, findings
    with zf:
        if zf.comment:
            findings.append(finding("NOTE", f"archive comment: {printable(zf.comment)}"))
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            findings.append(finding("WARN", f"{len(infos)} entries: only the first {MAX_ENTRIES} are checked"))
            infos = infos[:MAX_ENTRIES]
        seen: set[str] = set()
        declared = 0
        for info in infos:
            e = check_entry(info, data)
            key = info.filename.replace("\\", "/").lower()
            if key in seen:
                e["findings"].append(finding("WARN", "two entries with this name: unpackers keep different ones"))
            seen.add(key)
            declared += info.file_size
            entries.append(e)
            findings.extend(finding(x["level"], f"`{printable(info.filename)}`: {x['what']}") for x in e["findings"])
        if declared > max_total:
            findings.append(finding("DANGER", f"unpacks to {declared} bytes, over the {max_total}-byte limit: a zip "
                                              "bomb, or not a photo attachment"))
    return entries, findings


# ---------------------------------------------------------------- step 6: unpacking

def extract(data: bytes, dest: Path, max_total: int = MAX_EXTRACT) -> tuple[list[tuple[Path, str]], list[dict]]:
    """Unpack the plain files into `dest` under safe flat names, never more than `max_total` bytes in all."""
    files: list[tuple[Path, str]] = []
    findings: list[dict] = []
    written = 0
    used: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for idx, info in enumerate(zf.infolist()[:MAX_ENTRIES]):
            if entry_kind(info) != "file" or info.flag_bits & 0x1 or is_mac_extra(info.filename):
                continue
            target = dest / flat_name(info.filename, idx, used)
            try:
                with zf.open(info) as src, open(target, "xb") as out:
                    while chunk := src.read(MIB):
                        written += len(chunk)
                        if written > max_total:
                            raise OverflowError(f"unpacking passed {max_total} bytes")
                        out.write(chunk)
            except OverflowError as err:
                target.unlink(missing_ok=True)
                findings.append(finding("DANGER", f"`{printable(info.filename)}`: {err}; stopped"))
                break
            except Exception as err:  # bad CRC, damaged deflate data, unsupported method…
                target.unlink(missing_ok=True)
                findings.append(finding("WARN", f"`{printable(info.filename)}` could not be unpacked: {printable(err)}"))
                continue
            files.append((target, info.filename))
    return files, findings


# ---------------------------------------------------------------- step 7: each file

def scan_signatures(data: bytes) -> list[dict]:
    """Other kinds of file hidden inside this one."""
    found = []
    for sig, what, level in BINARY_SIGS:
        hits = find_all(data, sig)
        if hits:
            found.append(finding(level, f"{what} signature at byte {', '.join(map(str, hits))} "
                                        f"(context {data[hits[0]:hits[0] + 24].hex(' ')})"))
    low = data.lower()
    for sig, what in TEXT_SIGS:
        hits = find_all(low, sig)
        if hits:
            found.append(finding("WARN", f"{what} at byte {', '.join(map(str, hits))} "
                                         f"(context `{printable(data[hits[0]:hits[0] + 40], 40)}`)"))
    return found


def sniff(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "xml" if b"<" in data[2:8].replace(b"\x00", b"") else "other"
    head = data[:512]
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    head = head.lstrip()
    return "xml" if head.startswith((b"<?xpacket", b"<x:xmpmeta", b"<?xml", b"<rdf:RDF", b"<x:xapmeta")) else "other"


def marker_name(m: int) -> str:
    if m in SOF_MARKERS:
        return f"SOF{m - 0xC0}"
    if 0xE0 <= m <= 0xEF:
        return f"APP{m - 0xE0}"
    if 0xD0 <= m <= 0xD7:
        return f"RST{m - 0xD0}"
    return MARKER_NAMES.get(m, f"0x{m:02X}")


def walk_jpeg(d: bytes, max_segments: int = 10_000) -> dict:
    """Walk a JPEG's segments to its end-of-image marker, through every scan, and look at what follows it."""
    r = {"segments": [], "sof": None, "eoi": None, "trailing": 0, "exif": False, "xmp": [], "extended_xmp": 0,
         "findings": []}
    f = r["findings"]
    if d[:2] != b"\xff\xd8":
        f.append(finding("WARN", "does not start like a JPEG"))
        return r
    n, i, scan = len(d), 2, False
    while i < n and len(r["segments"]) < max_segments:
        if scan:  # entropy-coded data: skip stuffed bytes, restart markers and fill bytes
            j = d.find(b"\xff", i)
            if j < 0 or j + 1 >= n:
                i = n
                break
            nxt = d[j + 1]
            if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                i = j + 2
            elif nxt == 0xFF:
                i = j + 1
            else:
                i, scan = j, False
            continue
        if d[i] != 0xFF:
            f.append(finding("WARN", f"expected a marker at byte {i}, found 0x{d[i]:02X}: damaged or crafted"))
            break
        while i < n and d[i] == 0xFF:
            i += 1
        if i >= n:
            break
        m, start = d[i], i - 1
        i += 1
        if m == 0xD9:
            r["eoi"] = i
            break
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            r["segments"].append({"marker": marker_name(m), "offset": start, "length": 0})
            continue
        if i + 2 > n:
            f.append(finding("WARN", "cut short inside a segment header"))
            break
        length = (d[i] << 8) | d[i + 1]
        if length < 2 or i + length > n:
            f.append(finding("WARN", f"{marker_name(m)} at byte {start} claims {length} bytes, past the end of the "
                                     "file"))
            break
        payload = d[i + 2:i + length]
        seg = {"marker": marker_name(m), "offset": start, "length": length}
        if 0xE0 <= m <= 0xEF:
            nul = payload.find(b"\x00", 0, 64)
            ident = payload[:nul] if nul >= 0 else payload[:16]
            seg["id"] = printable(ident, 64)
            if m == 0xE1 and payload.startswith(b"Exif\x00"):
                r["exif"] = True
            elif m == 0xE1 and ident == XMP_ID:
                r["xmp"].append(payload[nul + 1:])
            elif m == 0xE1 and ident == XMP_EXT_ID:
                r["extended_xmp"] += 1
            if not any(ident.startswith(k) for k in KNOWN_APP):
                f.append(finding("NOTE", f"unusual {seg['marker']} segment `{seg['id']}` ({length} bytes)"))
        elif m == 0xFE:
            seg["text"] = printable(payload, 80)
        elif m in SOF_MARKERS and len(payload) >= 6:
            h, w = struct.unpack_from(">HH", payload, 1)
            r["sof"] = {"marker": seg["marker"], "precision": payload[0], "width": w, "height": h,
                        "components": payload[5]}
        r["segments"].append(seg)
        i += length
        if m == 0xDA:
            scan = True
    if len(r["segments"]) >= max_segments:
        f.append(finding("WARN", f"more than {max_segments} segments: not walked to the end"))
    if r["eoi"] is None:
        f.append(finding("WARN", "no end-of-image marker: cut short, or crafted"))
    else:
        tail = d[r["eoi"]:]
        r["trailing"] = len(tail)
        if tail and not tail.strip(b"\x00\xff\r\n "):
            f.append(finding("NOTE", f"{len(tail)} bytes of padding after the image"))
        elif tail.startswith(b"\xff\xd8\xff"):
            f.append(finding("NOTE", f"{len(tail)} bytes after the image start with another JPEG (a camera's or "
                                     "phone's second image)"))
        elif tail and (blocks := samsung_trailer(tail)) is not None:
            names = ", ".join(f"{name} ({size} bytes)" for name, size in blocks)
            big = [name for name, size in blocks if size > MAX_SAMSUNG_BLOCK]
            if big:
                f.append(finding("WARN", f"{len(tail)}-byte Samsung phone trailer with blocks over "
                                         f"{MAX_SAMSUNG_BLOCK} bytes, whose contents aren't checked: {names}"))
            else:
                f.append(finding("NOTE", f"{len(tail)}-byte Samsung phone trailer, every byte accounted for: {names}"))
        elif tail:
            f.append(finding("WARN", f"{len(tail)} bytes of something else after the image: "
                                     f"{file_type_bytes(tail)}; {dump(tail)}"))
    if r["sof"] is None:
        f.append(finding("WARN", "no frame header, so no image size"))
    return r


def dump(data: bytes, limit: int = 128) -> str:
    """The first bytes in hex and as text (anything unprintable as a dot)."""
    head = data[:limit]
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in head)
    return f"first {len(head)} bytes: {head.hex(' ')} |{text}|"


def samsung_trailer(tail: bytes) -> list[tuple[str, int]] | None:
    """Samsung phones end a photo with named blocks and a directory of them: "SEFH", a version, a count, then per
    block (2 bytes, a 2-byte type, how far before "SEFH" it starts, its length), then the directory's length and
    "SEFT". Each block starts with 2 bytes, a 2-byte type, the length of its name, and the name. Returns the blocks'
    names and sizes only when the blocks and the directory together cover every byte of `tail`, once."""
    if len(tail) < 20 or tail[-4:] != b"SEFT":
        return None
    (dir_len,) = struct.unpack_from("<I", tail, len(tail) - 8)
    start = len(tail) - 8 - dir_len
    if start < 0 or dir_len < 12 or tail[start:start + 4] != b"SEFH":
        return None
    (count,) = struct.unpack_from("<I", tail, start + 8)
    if not 0 < count <= 100 or 12 + 12 * count != dir_len:
        return None
    spans = [(start, len(tail))]
    blocks = []
    for k in range(count):
        _pad, _kind, back, length = struct.unpack_from("<HHII", tail, start + 12 + 12 * k)
        at = start - back
        if back == 0 or at < 0 or length < 8 or at + length > start:
            return None
        (name_len,) = struct.unpack_from("<I", tail, at + 4)
        name = tail[at + 8:at + 8 + name_len]
        if not 0 < name_len <= 64 or 8 + name_len > length or not re.fullmatch(rb"[A-Za-z0-9_.-]+", name):
            return None
        blocks.append((name.decode("ascii"), length))
        spans.append((at, at + length))
    pos = 0
    for a, z in sorted(spans):
        if a != pos:  # a gap holding something else, or blocks that overlap
            return None
        pos = z
    return blocks if pos == len(tail) else None


def decode_text(raw: bytes) -> tuple[str | None, str | None]:
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw[3:].decode("utf-8"), "UTF-8 with BOM"
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16"), "UTF-16"
        return raw.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        return None, None


def split_tag(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        uri, local = tag[1:].split("}", 1)
        return uri, local
    return "", tag


def first_desc(el: ET.Element) -> ET.Element:
    d = el.find(f"{{{RDF}}}Description")
    return d if d is not None else el


def prop(el: ET.Element, uri: str, local: str) -> str | None:
    """A simple property, written as an attribute or as an element, directly or inside an rdf:Description."""
    key = f"{{{uri}}}{local}"
    for node in (el, el.find(f"{{{RDF}}}Description")):
        if node is None:
            continue
        if key in node.attrib:
            return printable(node.attrib[key].strip(), 200)
        child = node.find(key)
        if child is not None:
            if child.text and child.text.strip():
                return printable(child.text.strip(), 200)
            li = child.find(f".//{{{RDF}}}li")
            if li is not None and li.text:
                return printable(li.text.strip(), 200)
    return None


def struct_of(el: ET.Element, uri: str, local: str) -> ET.Element | None:
    key = f"{{{uri}}}{local}"
    for node in (el, el.find(f"{{{RDF}}}Description")):
        if node is None:
            continue
        child = node.find(key)
        if child is not None:
            return first_desc(child)
    return None


def parse_mwg_regions(root: ET.Element) -> tuple[list[dict], list[dict]]:
    applied, regions = [], []
    for reg in root.iter(f"{{{MWG_RS}}}Regions"):
        node = first_desc(reg)
        dims = struct_of(node, MWG_RS, "AppliedToDimensions")
        if dims is not None:
            applied.append({k: prop(dims, ST_DIM, k) for k in ("w", "h", "unit")})
        lst = struct_of(node, MWG_RS, "RegionList")
        container = None if lst is None else next((c for c in lst if c.tag in RDF_CONTAINERS), None)
        for li in ([] if container is None else container.findall(f"{{{RDF}}}li"))[:MAX_ENTRIES]:
            item = first_desc(li)
            r = {"name": prop(item, MWG_RS, "Name"), "type": prop(item, MWG_RS, "Type"),
                 "rotation": prop(item, MWG_RS, "Rotation")}
            area = struct_of(item, MWG_RS, "Area")
            for k in ("x", "y", "w", "h", "unit"):
                r[k] = prop(area, ST_AREA, k) if area is not None else None
            regions.append(r)
    return applied, regions


def region_blocks(text: str, prefix: dict[str, str], limit: int = MAX_PRINT) -> list[str]:
    """The regions as the file writes them (MWG and Microsoft Photo), for a person to read."""
    out = []
    for uri, local in REGION_ROOTS:
        p = prefix.get(uri)
        if not p:
            continue
        tag = re.escape(f"{p}:{local}")
        for m in re.finditer(rf"<{tag}\b[\s\S]*?</{tag}\s*>", text):
            block = m.group(0)
            out.append(block[:limit] + ("\n…(cut)" if len(block) > limit else ""))
            if len(out) >= 4:
                return out
    return out


def check_xmp(raw: bytes) -> dict:
    """Is it plain, harmless XML, and what does it say about orientation, size and regions?"""
    r = {"size": len(raw), "encoding": None, "values": {}, "properties": [], "applied_to": [], "regions": [],
         "blocks": [], "findings": []}
    f = r["findings"]
    text, enc = decode_text(raw)
    if text is None:
        f.append(finding("WARN", "not UTF-8 or UTF-16 text"))
        return r
    r["encoding"] = enc
    ctrl = sum(1 for c in text if unicodedata.category(c) == "Cc" and c not in "\t\n\r")
    if ctrl:
        f.append(finding("WARN", f"{ctrl} control characters in the text"))
    low = text.lower()
    has_doctype = "<!doctype" in low or "<!entity" in low
    if has_doctype:
        f.append(finding("WARN", "declares a DOCTYPE or ENTITY, which XMP never needs (the pattern of XML entity "
                                 "attacks); not parsed"))
    if "xinclude" in low or "xi:include" in low:
        f.append(finding("WARN", "uses XInclude to pull in other files"))
    xmlns = re.findall(r"xmlns:([A-Za-z0-9_.-]+)\s*=\s*[\"']([^\"']*)[\"']", text)
    ns_uris = {u for _, u in xmlns}
    links = sorted({u.rstrip(".,;)") for u in re.findall(r"https?://[^\s\"'<>]+", text)} - ns_uris)
    if links:
        f.append(finding("NOTE", "links that aren't namespace names: "
                                 + ", ".join(printable(u, 120) for u in links[:10])))
    prefix: dict[str, str] = {}
    for p, u in xmlns:
        prefix.setdefault(u, p)
    r["blocks"] = region_blocks(text, prefix)
    if has_doctype:
        return r
    if len(raw) > MAX_XMP_PARSE:
        f.append(finding("NOTE", f"over {MAX_XMP_PARSE} bytes: not parsed"))
        return r
    body = raw.rstrip(b"\x00 \t\r\n") if enc and enc.startswith("UTF-8") else raw
    try:
        root = ET.fromstring(body)  # no DOCTYPE, so no entities to expand or fetch
    except Exception as err:
        f.append(finding("WARN", f"not well-formed XML: {printable(err)}"))
        return r

    def qn(tag: str) -> str:
        uri, local = split_tag(tag)
        return f"{prefix.get(uri, uri)}:{local}" if uri else local

    props: set[str] = set()
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        uri, local = split_tag(el.tag)
        if uri not in (RDF, X_NS):
            props.add(qn(el.tag))
        if (uri, local) in WANTED_XMP_VALUES and el.text and el.text.strip():
            r["values"][qn(el.tag)] = printable(el.text.strip(), 100)
        for k, v in el.attrib.items():
            kuri, klocal = split_tag(k)
            if kuri not in (RDF, X_NS, XML_NS):
                props.add(qn(k))
            if (kuri, klocal) in WANTED_XMP_VALUES:
                r["values"][qn(k)] = printable(v, 100)
    r["properties"] = sorted(props)
    r["applied_to"], r["regions"] = parse_mwg_regions(root)
    return r


def filter_exif(records: list) -> dict:
    """exiftool's tags: values for the image-shape and region tags, names only for everything else."""
    rec = records[0] if records and isinstance(records[0], dict) else {}
    shown, names = {}, []
    for key, val in rec.items():
        group, _, tag = key.rpartition(":")
        if key == "SourceFile" or group == "System" or tag == "ExifToolVersion":
            continue
        if tag in SHOWN_TAGS or tag.startswith("Region"):
            text = json.dumps(val, ensure_ascii=False) if not isinstance(val, str) else val
            shown[key] = printable(text, 2000)
        else:
            names.append(key)
    return {"shown": shown, "names_only": names}


def exiftool_facts(path: Path) -> dict | None:
    if not shutil.which("exiftool"):
        return None
    r = run_tool(["exiftool", "-j", "-n", "-G1", "-a", "-s", "-api", "LargeFileSupport=1", str(path)])
    if r is None:
        return {"error": "exiftool could not be started"}
    try:
        return filter_exif(json.loads(r.stdout.decode("utf-8", "replace") or "[]"))
    except json.JSONDecodeError:
        return {"error": printable(r.stderr.decode("utf-8", "replace").strip() or "no output", 300)}


def analyse_file(path: Path) -> dict:
    data = path.read_bytes()
    a = {"name": path.name, "size": len(data), "sha256": sha256(data), "file": file_type(path),
         "head": data[:16].hex(" "), "findings": []}
    f = a["findings"]
    kind = sniff(data)
    ext = path.suffix.lower()
    expected = {".jpg": "jpeg", ".jpeg": "jpeg", ".xmp": "xml"}.get(ext)
    if expected and kind != expected:
        f.append(finding("WARN", f"named `{printable(ext)}` but its bytes are not {expected}"))
    elif not expected:
        f.append(finding("NOTE", f"`{printable(ext) or 'no extension'}` files are only checked for hidden "
                                 "signatures and by ClamAV"))
    f.extend(scan_signatures(data))
    if kind == "jpeg":
        j = walk_jpeg(data)
        f.extend(j.pop("findings"))
        xmps = j.pop("xmp")
        a["jpeg"] = j
        a["embedded_xmp"] = []
        for x in xmps:
            c = check_xmp(x)
            f.extend(finding(y["level"], f"embedded XMP: {y['what']}") for y in c.pop("findings"))
            a["embedded_xmp"].append(c)
    elif kind == "xml":
        c = check_xmp(data)
        f.extend(c.pop("findings"))
        a["xmp"] = c
    a["exiftool"] = exiftool_facts(path)
    return a


# ---------------------------------------------------------------- step 8: virus scan

def clamscan(paths: list[Path]) -> dict:
    if not shutil.which("clamscan"):
        return {"status": "skipped", "why": "ClamAV is not installed", "hits": [], "summary": []}
    if not any(Path("/var/lib/clamav").glob("*.c[lv]d")):
        return {"status": "skipped", "why": "no virus signatures (the freshclam update failed)", "hits": [],
                "summary": []}
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        return {"status": "skipped", "why": "nothing was downloaded", "hits": [], "summary": []}
    r = run_tool(["clamscan", "--recursive", "--scan-archive=yes", "--alert-encrypted=yes", "--max-filesize=200M",
                  "--max-scansize=400M", "--infected", *existing], timeout=1200)
    if r is None:
        return {"status": "error", "why": "clamscan could not run or timed out", "hits": [], "summary": []}
    lines = r.stdout.decode("utf-8", "replace").splitlines()
    return {
        "status": {0: "clean", 1: "found"}.get(r.returncode, "error"),
        "why": printable(r.stderr.decode("utf-8", "replace").strip(), 500) if r.returncode > 1 else "",
        "hits": [ln for ln in lines if ln.endswith(" FOUND")],
        "summary": [ln for ln in lines if ln.startswith(("Known viruses", "Engine version", "Scanned files",
                                                          "Infected files", "Data scanned"))],
    }


# ---------------------------------------------------------------- one link, start to end

def vet_download(rep: dict, path: Path, xdir: Path) -> None:
    data = path.read_bytes()
    rep.update(name=path.name, size=len(data), sha256=sha256(data), file=file_type(path))
    if looks_like_zip(data):
        rep["entries"], f = inspect_zip(data)
        rep["findings"].extend(f)
        if verdict(f) == "DANGEROUS":
            return  # not unpacked
        xdir.mkdir(parents=True, exist_ok=False)
        files, f2 = extract(data, xdir)
        rep["findings"].extend(f2)
        rep["extracted"] = True
    else:
        files = [(path, path.name)]
    for p, original in files:
        a = analyse_file(p)
        a["original"] = original
        rep["files"].append(a)
        rep["findings"].extend(finding(x["level"], f"{printable(original)}: {x['what']}") for x in a["findings"])


def vet_url(n: int, url: str, work: Path) -> dict:
    rep = {"n": n, "url": url, "name": None, "findings": [], "entries": [], "files": [], "extracted": False,
           "error": None}
    try:
        if not URL_RE.fullmatch(url):
            raise ValueError("not a GitHub attachment link (https://github.com/user-attachments/files/<id>/<name> "
                             "or https://github.com/<owner>/<repo>/files/<id>/<name>)")
        dl = work / "dl" / str(n)
        dl.mkdir(parents=True, exist_ok=False)
        path, served = download(url, dl)
        rep.update(served)
        vet_download(rep, path, work / "x" / str(n))
    except Exception as err:  # one bad link must not stop the others
        rep["error"] = f"{type(err).__name__}: {printable(err, 500)}"
    return rep


def apply_clam(reports: list[dict], clam: dict, work: Path) -> None:
    for line in clam["hits"]:
        where, _, sig = line.rpartition(": ")
        for rep in reports:
            mine = (str(work / "dl" / str(rep["n"])), str(work / "x" / str(rep["n"])))
            if where.startswith(mine):
                rep["findings"].append(finding("DANGER", f"ClamAV: {printable(sig)} in "
                                                         f"{printable(Path(where).name)}"))


# ---------------------------------------------------------------- step 9: the report

def say(line: str = "") -> None:
    print(line, flush=True)


def quote(text: str, indent: str = "        | ") -> None:
    for line in str(text).splitlines() or [""]:
        say(indent + printable(line, 2000))


def print_xmp(c: dict, label: str) -> None:
    say(f"    {label}: {c['size']} bytes, {c['encoding'] or 'not text'}")
    for k, v in c["values"].items():
        say(f"      {k} = {v}")
    for d in c["applied_to"]:
        say(f"      mwg-rs:AppliedToDimensions  w={d['w']}  h={d['h']}  unit={d['unit']}")
    if c["regions"]:
        say(f"      {len(c['regions'])} MWG regions (x, y = centre; all fractions of AppliedToDimensions):")
        say("        type      x         y         w         h         unit        rotation  name")
        for r in c["regions"]:
            say(f"        {r['type'] or '-':<9} {r['x'] or '-':<9} {r['y'] or '-':<9} {r['w'] or '-':<9} "
                f"{r['h'] or '-':<9} {r['unit'] or '-':<11} {r['rotation'] or '-':<9} {r['name'] or '-'}")
    if c["properties"]:
        say(f"      properties: {', '.join(c['properties'])}")
    for b in c["blocks"]:
        say("      as written:")
        quote(b)


def print_report(rep: dict) -> None:
    say("=" * 100)
    say(f"{printable(rep.get('name') or rep['url'])}: {rep['verdict']}")
    say("=" * 100)
    say(f"  link       {rep['url']}")
    if rep["error"]:
        say(f"  error      {rep['error']}")
        return
    say(f"  served by  {rep.get('served_from')} ({rep.get('content_type')}, HTTP {rep.get('http')})")
    say(f"  size       {rep.get('size')} bytes")
    say(f"  sha256     {rep.get('sha256')}")
    say(f"  type       {rep.get('file')}")
    if rep["entries"]:
        say("  entries (read from the archive's index, before unpacking):")
        say("    kind     size        packed      ratio   method    enc  mode      name")
        for e in rep["entries"]:
            say(f"    {e['kind']:<8} {e['size']:<11} {e['packed']:<11} {str(e['ratio']):<7} {e['method']:<9} "
                f"{'yes' if e['encrypted'] else 'no':<4} {e['mode']:<9} {printable(e['name'])}")
    say(f"  unpacked   {'yes' if rep['extracted'] else 'no'}")
    for a in rep["files"]:
        say(f"  -- {printable(a['original'])} (saved as {printable(a['name'])})")
        say(f"    size {a['size']} bytes, sha256 {a['sha256']}")
        say(f"    type {a['file']}; first bytes {a['head']}")
        j = a.get("jpeg")
        if j:
            sof = j["sof"] or {}
            say(f"    JPEG: {sof.get('marker', '?')} frame {sof.get('width', '?')} x {sof.get('height', '?')} "
                f"(as stored), {sof.get('precision', '?')}-bit, {sof.get('components', '?')} components; "
                f"Exif {'yes' if j['exif'] else 'no'}; XMP segments {len(a['embedded_xmp'])}; extended XMP "
                f"{j['extended_xmp']}; ends at byte {j['eoi']}; {j['trailing']} bytes after the end")
            say("    segments: " + ", ".join(
                f"{s['marker']}@{s['offset']}" + (f"[{s['id']}]" if s.get("id") else "") for s in j["segments"][:60]))
            for i, c in enumerate(a["embedded_xmp"], 1):
                print_xmp(c, f"embedded XMP #{i}")
        if a.get("xmp"):
            print_xmp(a["xmp"], "XMP")
        ex = a.get("exiftool")
        if ex is None:
            say("    exiftool: not installed")
        elif "error" in ex:
            say(f"    exiftool: {ex['error']}")
        else:
            say("    exiftool (values shown only for image-shape and region tags):")
            for k, v in ex["shown"].items():
                say(f"      {k} = {v}")
            say(f"      other tags present, names only: {', '.join(ex['names_only']) or 'none'}")
    if rep["findings"]:
        say("  findings:")
        for x in rep["findings"]:
            say(f"    [{x['level']}] {x['what']}")
    else:
        say("  findings: none")


def md(text) -> str:
    return printable(text, 300).replace("`", "'").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def write_summary(reports: list[dict], clam: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    icon = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "DANGEROUS": "⛔", "NOT VETTED": "❔"}
    out = ["## attachment-vet", "", f"ClamAV: **{clam['status']}** {md(clam.get('why', ''))}", "",
           "| Attachment | Verdict | Size | sha256 |", "|---|---|---|---|"]
    for r in reports:
        out.append(f"| {md(r.get('name') or r['url'])} | {icon.get(r['verdict'], '')} {r['verdict']} | "
                   f"{r.get('size', '')} | `{r.get('sha256', '')}` |")
    out += ["", "### Files", "", "| Attachment | File | Type | Size | sha256 |", "|---|---|---|---|---|"]
    for r in reports:
        for a in r["files"]:
            out.append(f"| {md(r.get('name'))} | {md(a['original'])} | {md(a['file'][:60])} | {a['size']} | "
                       f"`{a['sha256']}` |")
    out += ["", "### Findings", ""]
    for r in reports:
        if r["error"]:
            out.append(f"- **{md(r.get('name') or r['url'])}** not vetted: {md(r['error'])}")
        out += [f"- **{md(r.get('name'))}** [{x['level']}] {md(x['what'])}" for x in r["findings"]]
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    except OSError as err:
        say(f"(could not write the job summary: {printable(err)})")


def compact(reports: list[dict], clam: dict) -> dict:
    def facts(a: dict) -> dict:
        x = {"name": a["original"], "saved_as": a["name"], "size": a["size"], "sha256": a["sha256"]}
        if a.get("jpeg"):
            x["sof"] = a["jpeg"]["sof"]
            x["xmp"] = [{"values": c["values"], "applied_to": c["applied_to"], "regions": c["regions"]}
                        for c in a["embedded_xmp"]]
        if a.get("xmp"):
            c = a["xmp"]
            x["xmp"] = [{"values": c["values"], "applied_to": c["applied_to"], "regions": c["regions"]}]
        if a.get("exiftool") and "shown" in a["exiftool"]:
            x["exif"] = a["exiftool"]["shown"]
        return x

    return {
        "clamav": {"status": clam["status"], "why": clam.get("why", ""), "hits": clam["hits"]},
        "attachments": [{
            "url": r["url"], "name": r.get("name"), "verdict": r["verdict"], "size": r.get("size"),
            "sha256": r.get("sha256"), "error": r["error"], "findings": r["findings"],
            "files": [facts(a) for a in r["files"]],
        } for r in reports],
    }


def main(argv: list[str]) -> int:
    work: Path | None = None
    urls: list[str] = []
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--work" and args:
            work = Path(args.pop(0))
        elif a in ("-h", "--help"):
            say(__doc__ or "")
            return 0
        else:
            urls.append(a)
    urls = urls or os.environ.get("URLS", "").split()
    if work is None:
        work = Path(os.environ.get("RUNNER_TEMP") or ".") / "attachment-vet"
    if not urls:
        say("usage: vet.py [--work DIR] URL...  (or URLS in the environment)")
        return 2
    if len(urls) > MAX_URLS:
        say(f"at most {MAX_URLS} links per run")
        return 2
    # In GitHub Actions a log line can be a workflow command ("::…"). Nothing a stranger wrote may be one: commands
    # are switched off until the report is printed, and every quoted line is indented as well.
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    token = "vet" + os.urandom(16).hex()
    if in_actions:
        say(f"::stop-commands::{token}")
    try:
        reports = [vet_url(n, u, work) for n, u in enumerate(urls, 1)]
        clam = clamscan([work / "dl", work / "x"])
        apply_clam(reports, clam, work)
        for rep in reports:
            rep["verdict"] = "NOT VETTED" if rep["error"] else verdict(rep["findings"])
            print_report(rep)
        say("=" * 100)
        say(f"ClamAV: {clam['status']} {clam.get('why', '')}")
        for line in clam["summary"] + clam["hits"]:
            say(f"  {printable(line, 500)}")
    finally:
        if in_actions:
            say(f"::{token}::")
    write_summary(reports, clam)
    say("VET-JSON " + json.dumps(compact(reports, clam), ensure_ascii=True))
    all_safe = all(r["verdict"] == "SAFE" for r in reports)
    if clam["status"] != "clean":
        say("The virus scan did not run to a clean result, so this run is not a full pass.")
    return 0 if all_safe and clam["status"] == "clean" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
