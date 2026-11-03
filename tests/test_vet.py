"""Tests for vet.py, on archives and files built here: nothing is downloaded and no real photo is used.

Run: python3 -I tests/test_vet.py -v
"""
import io
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vet  # noqa: E402


def seg(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def jpeg(width=6000, height=4000, xmp=None, trailing=b"", progressive=False, cut=False) -> bytes:
    """A JPEG's structure: real markers and lengths, made-up table and image bytes (it doesn't decode to a picture)."""
    parts = [b"\xff\xd8", seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"),
             seg(0xE1, b"Exif\x00\x00II*\x00\x08\x00\x00\x00\x00\x00")]
    if xmp is not None:
        parts.append(seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp))
    parts.append(seg(0xDB, bytes(65)))
    sof = 0xC2 if progressive else 0xC0
    parts.append(seg(sof, bytes([8]) + struct.pack(">HH", height, width) + bytes([3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1])))
    parts.append(seg(0xC4, bytes(20)))
    sos = seg(0xDA, bytes([3, 1, 0, 2, 0x11, 3, 0x11, 0, 63, 0]))
    data = b"\x12\x34\xff\x00\x56\xff\xd0\x78\xff\xff\x00\x9a"  # a stuffed byte, a restart marker, a fill byte
    parts += [sos, data]
    if progressive:
        parts += [seg(0xC4, bytes(20)), sos, data]
    if not cut:
        parts.append(b"\xff\xd9" + trailing)
    return b"".join(parts)


XMP_ATTR = b"""<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:tiff="http://ns.adobe.com/tiff/1.0/"
    xmlns:mwg-rs="http://www.metadataworkinggroup.com/schemas/regions/"
    xmlns:stDim="http://ns.adobe.com/xap/1.0/sType/Dimensions#"
    xmlns:stArea="http://ns.adobe.com/xmp/sType/Area#"
    tiff:Orientation="6">
   <mwg-rs:Regions rdf:parseType="Resource">
    <mwg-rs:AppliedToDimensions stDim:w="6000" stDim:h="4000" stDim:unit="pixel"/>
    <mwg-rs:RegionList>
     <rdf:Bag>
      <rdf:li>
       <rdf:Description mwg-rs:Name="Person A" mwg-rs:Type="Face">
        <mwg-rs:Area stArea:x="0.25" stArea:y="0.4" stArea:w="0.1" stArea:h="0.15" stArea:unit="normalized"/>
       </rdf:Description>
      </rdf:li>
     </rdf:Bag>
    </mwg-rs:RegionList>
   </mwg-rs:Regions>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

XMP_ELEMENTS = b"""<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:mwg-rs="http://www.metadataworkinggroup.com/schemas/regions/"
 xmlns:stDim="http://ns.adobe.com/xap/1.0/sType/Dimensions#" xmlns:stArea="http://ns.adobe.com/xmp/sType/Area#">
<mwg-rs:Regions><rdf:Description>
 <mwg-rs:AppliedToDimensions><rdf:Description><stDim:w>4000</stDim:w><stDim:h>6000</stDim:h><stDim:unit>pixel</stDim:unit></rdf:Description></mwg-rs:AppliedToDimensions>
 <mwg-rs:RegionList><rdf:Bag><rdf:li><rdf:Description>
  <mwg-rs:Name>Person B</mwg-rs:Name><mwg-rs:Type>Face</mwg-rs:Type><mwg-rs:Rotation>-1.5708</mwg-rs:Rotation>
  <mwg-rs:Area><rdf:Description><stArea:x>0.5</stArea:x><stArea:y>0.6</stArea:y><stArea:w>0.2</stArea:w><stArea:h>0.1</stArea:h><stArea:unit>normalized</stArea:unit></rdf:Description></mwg-rs:Area>
 </rdf:Description></rdf:li></rdf:Bag></mwg-rs:RegionList>
</rdf:Description></mwg-rs:Regions>
</rdf:Description></rdf:RDF></x:xmpmeta>"""


def make_zip(entries, comment=b"") -> bytes:
    """entries: (name, data) or (name, data, unix mode) tuples."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate names on purpose
        with zipfile.ZipFile(buf, "w") as zf:
            for e in entries:
                zi = zipfile.ZipInfo(e[0], date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (e[2] if len(e) > 2 else 0o100644) << 16
                zf.writestr(zi, e[1])
            zf.comment = comment
    return buf.getvalue()


def levels(findings):
    return [f["level"] for f in findings]


def worst(findings):
    return vet.verdict(findings)


class Archive(unittest.TestCase):
    def test_a_photo_and_its_sidecar_are_safe_and_unpack(self):
        data = make_zip([("Example 1/photo.jpg", jpeg()), ("Example 1/photo.xmp", XMP_ATTR)])
        entries, f = vet.inspect_zip(data)
        self.assertEqual(worst(f), "SAFE", f)
        self.assertEqual([e["kind"] for e in entries], ["file", "file"])
        with tempfile.TemporaryDirectory() as d:
            files, f2 = vet.extract(data, Path(d))
            self.assertEqual(f2, [])
            self.assertEqual([p.name for p, _ in files], ["Example 1__photo.jpg", "Example 1__photo.xmp"])
            self.assertEqual(files[0][0].read_bytes(), jpeg())

    def test_paths_that_leave_the_folder_are_dangerous(self):
        for name in ("../evil.jpg", "/etc/evil.jpg", "C:/Windows/evil.jpg", "a\\..\\..\\evil.jpg", "\\evil.jpg"):
            with self.subTest(name=name):
                _, f = vet.inspect_zip(make_zip([(name, b"x")]))
                self.assertEqual(worst(f), "DANGEROUS", f)

    def test_hidden_streams_device_names_and_invisible_characters_are_dangerous(self):
        for name in ("photo.jpg:hidden", "CON.jpg", "nul", "photo\u202egpj.exe", "photo\x01.jpg"):
            with self.subTest(name=name):
                _, f = vet.inspect_zip(make_zip([(name, b"x")]))
                self.assertEqual(worst(f), "DANGEROUS", f)

    def test_a_symbolic_link_is_dangerous_and_not_unpacked(self):
        data = make_zip([("link.jpg", b"/etc/passwd", 0o120777), ("ok.jpg", jpeg())])
        entries, f = vet.inspect_zip(data)
        self.assertEqual(entries[0]["kind"], "symlink")
        self.assertEqual(worst(f), "DANGEROUS")
        with tempfile.TemporaryDirectory() as d:
            files, _ = vet.extract(data, Path(d))
            self.assertEqual([p.name for p, _ in files], ["ok.jpg"])

    def test_programs_are_dangerous_and_other_active_files_suspicious(self):
        for name, want in (("invoice.pdf.exe", "DANGEROUS"), ("x.lnk", "DANGEROUS"), ("x.ps1", "DANGEROUS"),
                           ("x.svg", "SUSPICIOUS"), ("x.html", "SUSPICIOUS"), ("inner.zip", "SUSPICIOUS")):
            with self.subTest(name=name):
                _, f = vet.inspect_zip(make_zip([(name, b"x")]))
                self.assertEqual(worst(f), want, f)

    def test_a_zip_bomb_is_dangerous(self):
        _, f = vet.inspect_zip(make_zip([("big.jpg", bytes(20 * vet.MIB))]))
        self.assertEqual(worst(f), "DANGEROUS")
        self.assertTrue(any("zip bomb" in x["what"] for x in f), f)

    def test_more_than_the_limit_in_all_is_dangerous(self):
        data = make_zip([("a.jpg", b"x" * 600), ("b.jpg", b"y" * 600)])
        _, f = vet.inspect_zip(data, max_total=1000)
        self.assertEqual(worst(f), "DANGEROUS")

    def test_unpacking_stops_at_the_limit_and_removes_the_partial_file(self):
        data = make_zip([("a.jpg", b"x" * 600), ("b.jpg", b"y" * 600)])
        with tempfile.TemporaryDirectory() as d:
            files, f = vet.extract(data, Path(d), max_total=1000)
            self.assertEqual([p.name for p, _ in files], ["a.jpg"])
            self.assertEqual(worst(f), "DANGEROUS")
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["a.jpg"])

    def test_bytes_before_or_after_the_archive_are_suspicious(self):
        data = make_zip([("a.jpg", jpeg())])
        for name, blob in (("after", data + b"MORE"), ("before", jpeg() + data)):
            with self.subTest(name=name):
                _, f = vet.inspect_zip(blob)
                self.assertEqual(worst(f), "SUSPICIOUS", f)

    def test_an_encrypted_entry_is_suspicious_and_not_unpacked(self):
        data = bytearray(make_zip([("a.jpg", b"secret")]))
        for sig, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            at = data.find(sig) + flag_at
            data[at] |= 0x01
        entries, f = vet.inspect_zip(bytes(data))
        self.assertTrue(entries[0]["encrypted"])
        self.assertEqual(worst(f), "SUSPICIOUS")
        with tempfile.TemporaryDirectory() as d:
            files, _ = vet.extract(bytes(data), Path(d))
            self.assertEqual(files, [])

    def test_two_entries_with_one_name_are_suspicious(self):
        _, f = vet.inspect_zip(make_zip([("a.jpg", b"1"), ("A.jpg", b"2")]))
        self.assertEqual(worst(f), "SUSPICIOUS")

    def test_names_that_differ_between_index_and_entry_are_suspicious(self):
        data = bytearray(make_zip([("a.jpg", b"1")]))
        at = data.find(b"a.jpg")  # the entry's own header comes first; the index keeps "a.jpg"
        data[at:at + 5] = b"b.jpg"
        _, f = vet.inspect_zip(bytes(data))
        self.assertIn("SUSPICIOUS", worst(f))

    def test_not_a_zip_is_dangerous(self):
        _, f = vet.inspect_zip(b"PK\x03\x04 this is not an archive")
        self.assertEqual(worst(f), "DANGEROUS")

    def test_unpacked_names_are_flat_and_unique(self):
        used = set()
        self.assertEqual(vet.flat_name("../../a/b.jpg", 0, used), "a__b.jpg")
        self.assertEqual(vet.flat_name("A/B.jpg", 1, used), "1_A__B.jpg")
        self.assertEqual(vet.flat_name("..", 2, used), "entry2")
        self.assertEqual(vet.flat_name("ph\u00f6to:x.jpg", 3, used), "ph_to_x.jpg")


class Files(unittest.TestCase):
    def analyse(self, name, data):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_bytes(data)
            return vet.analyse_file(p)

    def test_a_plain_jpeg_is_walked_to_its_end(self):
        a = self.analyse("p.jpg", jpeg(width=6000, height=4000, xmp=XMP_ATTR))
        self.assertEqual(worst(a["findings"]), "SAFE", a["findings"])
        j = a["jpeg"]
        self.assertEqual((j["sof"]["width"], j["sof"]["height"]), (6000, 4000))
        self.assertTrue(j["exif"])
        self.assertEqual(j["trailing"], 0)
        self.assertEqual(len(a["embedded_xmp"]), 1)
        self.assertEqual(a["embedded_xmp"][0]["regions"][0]["x"], "0.25")

    def test_a_progressive_jpeg_with_two_scans_is_walked_to_its_end(self):
        j = vet.walk_jpeg(jpeg(progressive=True))
        self.assertEqual(levels(j["findings"]), [])
        self.assertEqual([s["marker"] for s in j["segments"]].count("SOS"), 2)
        self.assertEqual(j["eoi"], len(jpeg(progressive=True)))

    def test_a_program_after_the_image_is_dangerous(self):
        exe = b"MZ\x90\x00" + bytes(60) + b"This program cannot be run in DOS mode"
        a = self.analyse("p.jpg", jpeg(trailing=exe))
        self.assertEqual(worst(a["findings"]), "DANGEROUS")
        self.assertEqual(a["jpeg"]["trailing"], len(exe))

    def test_a_second_jpeg_or_padding_after_the_image_is_only_noted(self):
        for tail in (jpeg(width=160, height=120), bytes(100)):
            with self.subTest(tail=len(tail)):
                a = self.analyse("p.jpg", jpeg(trailing=tail))
                self.assertEqual(worst(a["findings"]), "SAFE", a["findings"])
                self.assertIn("NOTE", levels(a["findings"]))

    def test_unknown_bytes_after_the_image_are_suspicious(self):
        a = self.analyse("p.jpg", jpeg(trailing=b"\x01\x02\x03 something else"))
        self.assertEqual(worst(a["findings"]), "SUSPICIOUS")

    def test_a_jpeg_cut_short_is_suspicious(self):
        a = self.analyse("p.jpg", jpeg(cut=True))
        self.assertEqual(worst(a["findings"]), "SUSPICIOUS")

    def test_a_segment_claiming_more_than_the_file_is_suspicious(self):
        j = vet.walk_jpeg(b"\xff\xd8\xff\xe1\xff\xff" + bytes(10))
        self.assertEqual(worst(j["findings"]), "SUSPICIOUS")

    def test_a_script_hidden_in_a_photo_is_suspicious(self):
        a = self.analyse("p.jpg", jpeg(xmp=b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><SCRIPT>alert(1)</SCRIPT></x:xmpmeta>"))
        self.assertEqual(worst(a["findings"]), "SUSPICIOUS")

    def test_a_file_whose_bytes_dont_match_its_name_is_suspicious(self):
        for name, data in (("p.jpg", b"hello"), ("p.xmp", jpeg())):
            with self.subTest(name=name):
                self.assertEqual(worst(self.analyse(name, data)["findings"]), "SUSPICIOUS")

    def test_sidecar_regions_are_read_in_both_rdf_forms(self):
        a = self.analyse("p.xmp", XMP_ATTR)
        self.assertEqual(worst(a["findings"]), "SAFE", a["findings"])
        x = a["xmp"]
        self.assertEqual(x["values"], {"tiff:Orientation": "6"})
        self.assertEqual(x["applied_to"], [{"w": "6000", "h": "4000", "unit": "pixel"}])
        self.assertEqual(x["regions"], [{"name": "Person A", "type": "Face", "rotation": None, "x": "0.25", "y": "0.4",
                                         "w": "0.1", "h": "0.15", "unit": "normalized"}])
        self.assertEqual(len(x["blocks"]), 1)
        self.assertTrue(x["blocks"][0].startswith("<mwg-rs:Regions"))
        b = vet.check_xmp(XMP_ELEMENTS)
        self.assertEqual(b["findings"], [])
        self.assertEqual(b["applied_to"], [{"w": "4000", "h": "6000", "unit": "pixel"}])
        self.assertEqual(b["regions"], [{"name": "Person B", "type": "Face", "rotation": "-1.5708", "x": "0.5",
                                         "y": "0.6", "w": "0.2", "h": "0.1", "unit": "normalized"}])

    def test_xml_entities_are_suspicious_and_never_parsed(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
                b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>&b;</x:xmpmeta>")
        c = vet.check_xmp(bomb)
        self.assertEqual(worst(c["findings"]), "SUSPICIOUS")
        self.assertEqual(c["properties"], [])
        external = b'<?xml version="1.0"?><!DOCTYPE x SYSTEM "http://example.com/x.dtd"><x/>'
        self.assertEqual(worst(vet.check_xmp(external)["findings"]), "SUSPICIOUS")

    def test_xmp_that_isnt_text_is_suspicious(self):
        self.assertEqual(worst(vet.check_xmp(b"<x:xmpmeta>\xff\xfe\xfa</x:xmpmeta>")["findings"]), "SUSPICIOUS")

    def test_malformed_xmp_is_suspicious_not_a_crash(self):
        self.assertEqual(worst(vet.check_xmp(b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><a></x:xmpmeta>")["findings"]),
                         "SUSPICIOUS")


class Reporting(unittest.TestCase):
    def test_only_github_attachment_links_are_fetched(self):
        ok = ["https://github.com/user-attachments/files/34311610/Example.1.zip",
              "https://github.com/owner/repo/files/123/a_b-c.zip"]
        bad = ["http://github.com/user-attachments/files/1/a.zip", "https://evil.example/user-attachments/files/1/a.zip",
               "https://github.com/user-attachments/files/1/a.zip?x=1", "https://github.com/user-attachments/files/1/a/b.zip",
               "https://github.com.evil.example/user-attachments/files/1/a.zip", "file:///etc/passwd"]
        for u in ok:
            self.assertTrue(vet.URL_RE.fullmatch(u), u)
        for u in bad:
            self.assertFalse(vet.URL_RE.fullmatch(u), u)

    def test_exiftool_values_are_shown_only_for_shape_and_region_tags(self):
        out = vet.filter_exif([{
            "SourceFile": "/tmp/x.jpg", "System:FileName": "x.jpg", "File:FileType": "JPEG",
            "IFD0:Orientation": 6, "ExifIFD:ExifImageWidth": 6000, "GPS:GPSLatitude": 51.5,
            "ExifIFD:DateTimeOriginal": "2020:01:01 10:00:00", "XMP-mwg-rs:RegionAreaX": [0.25, 0.5],
            "XMP-iptcExt:PersonInImage": ["Someone"], "ExifIFD:SerialNumber": "123",
        }])
        self.assertEqual(set(out["shown"]), {"File:FileType", "IFD0:Orientation", "ExifIFD:ExifImageWidth",
                                             "XMP-mwg-rs:RegionAreaX"})
        self.assertEqual(out["shown"]["XMP-mwg-rs:RegionAreaX"], "[0.25, 0.5]")
        self.assertEqual(sorted(out["names_only"]), ["ExifIFD:DateTimeOriginal", "ExifIFD:SerialNumber",
                                                     "GPS:GPSLatitude", "XMP-iptcExt:PersonInImage"])
        self.assertNotIn("Someone", str(out))
        self.assertNotIn("51.5", str(out))

    def test_untrusted_text_can_never_start_a_log_line(self):
        buf = io.StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            vet.quote("::error::forged\n::add-mask::x\r\nok\x1b[31m")
        finally:
            sys.stdout = old
        for line in buf.getvalue().splitlines():
            self.assertTrue(line.startswith("        | "), line)
        self.assertNotIn("\x1b", buf.getvalue())

    def test_a_whole_run_on_a_local_archive(self):
        data = make_zip([("Example 2/p.jpg", jpeg(width=4000, height=6000)), ("Example 2/p.xmp", XMP_ELEMENTS)])
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "dl" / "1"
            src.mkdir(parents=True)
            (src / "Example.2.zip").write_bytes(data)
            rep = {"n": 1, "url": "local", "findings": [], "entries": [], "files": [], "extracted": False, "error": None}
            vet.vet_download(rep, src / "Example.2.zip", Path(d) / "x" / "1")
            rep["verdict"] = vet.verdict(rep["findings"])
            self.assertEqual(rep["verdict"], "SAFE", rep["findings"])
            self.assertEqual(rep["sha256"], vet.sha256(data))
            self.assertEqual([a["original"] for a in rep["files"]], ["Example 2/p.jpg", "Example 2/p.xmp"])
            out = vet.compact([rep], {"status": "skipped", "why": "test", "hits": []})
            self.assertEqual(out["attachments"][0]["files"][0]["sof"]["width"], 4000)
            self.assertEqual(out["attachments"][0]["files"][1]["xmp"][0]["applied_to"][0]["h"], "6000")


if __name__ == "__main__":
    unittest.main()
