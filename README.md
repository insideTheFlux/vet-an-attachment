# Vet an attachment.
Checks files that people attach to GitHub issues and pull requests on a throwaway GitHub machine, before anyone
downloads them.

Someone sends a ZIP of example photos to help test a fix. It's probably fine, but it comes from a stranger and I want
it on my own PC only once I know what's inside. This repository holds a script and a workflow. The workflow runs the
script on one of GitHub's servers, which downloads the files, takes them apart and reports what it found. The machine
is deleted when the run ends. Only after a clean report do I download the files myself, and then only if their
fingerprints match the ones the report gives.

It never runs anything it downloads. The files are only read as bytes, by the `file` command, by exiftool and by
ClamAV.

## The process, step by step

### 1. I start a run

From any terminal with the GitHub CLI:

```bash
gh workflow run vet.yml -R insideTheFlux/vet-an-attachment \
  -f urls="https://github.com/user-attachments/files/123/Example.1.zip https://github.com/user-attachments/files/456/Example.2.zip"
```

Or on GitHub: **Actions → vet → Run workflow**, then paste the links. The links are the ones on the attachments in the
issue or comment (right-click → copy link). Up to ten per run.

### 2. GitHub starts a fresh machine

The job runs on `ubuntu-24.04`, a virtual machine GitHub creates for this one job and deletes afterwards. Nothing from
an earlier run is on it, and nothing from this run is left on it later. The job has 30 minutes at most.

### 3. It gets the tools

- **This repository's scripts.** They're checked out without leaving GitHub's access token on the disk
  (`persist-credentials: false`), and the job's token can only read this repository. So a file that managed to do
  anything still couldn't reach the account.
- **exiftool** reads photo metadata. **ClamAV** is a virus scanner. **`file`** names a file's type from its bytes.
- **ClamAV's virus signatures** are updated from ClamAV's servers. If that fails, the run goes on, but the result says
  the virus scan was skipped, and the run is marked as failed so it isn't mistaken for a full pass.

### 4. It checks the links and downloads the files

- Only GitHub attachment links are accepted: `https://github.com/user-attachments/files/<id>/<name>` or
  `https://github.com/<owner>/<repo>/files/<id>/<name>`. Anything else is refused before any download.
- Each download goes into its own new, empty folder. It's HTTPS only, at most 5 redirects, 200 MB and 3 minutes.
- The report records the size and the **sha256**, a fingerprint of the exact bytes. Step 11 relies on it.
- GitHub serves the file from a signed storage link. Its query string works as a password for a few minutes, so the
  report shows only the host and path.

### 5. It reads the archive's index before unpacking anything

A ZIP has an index that lists its files. The script reads that list and flags:

| Check | Why it matters | Verdict |
|---|---|---|
| `..`, an absolute path or a drive letter in a name | unpacks outside the folder (overwrites other files) | dangerous |
| a symbolic link | after unpacking it can point anywhere on the disk | dangerous |
| a colon in a name, or a Windows device name (`CON`, `NUL`, `COM1`…) | hidden data streams, or names that break Windows | dangerous |
| control or invisible characters (such as a right-to-left override) | hide the real extension: `photo‮gpj.exe` | dangerous |
| programs and scripts (`.exe`, `.lnk`, `.ps1`, `.js`, `.bat`, `.msi`, `.iso`…) | run code when opened | dangerous |
| unpacks to over 100× its packed size (for an entry over 1 MiB), or over 200 MB in all | a "zip bomb" that fills the disk | dangerous |
| the index points at an entry that isn't there | unpackers disagree on what's inside | dangerous |
| bytes in front of or after the archive | a file that is two formats at once | suspicious |
| an entry's own header names it differently from the index | different unpackers write different files | suspicious |
| two entries with the same name (ignoring case) | different unpackers keep different ones | suspicious |
| encrypted entries | can't be checked | suspicious |
| archives, HTML, SVG, PDF and Office files inside | can carry more files, scripts or macros | suspicious |
| macOS `__MACOSX` folders and `._` files | Finder clutter, harmless | note, not unpacked |

If anything is dangerous, the archive is not unpacked at all.

### 6. It unpacks only plain files, carefully

Folders, links and encrypted entries are skipped. Each file is written under a new flat name made only of letters,
digits, spaces and `._-`: `Example 1/photo.jpg` becomes `Example 1__photo.jpg`. Unpacking stops at 200 MB, however
big the index says the files are, and a part-written file is deleted.

### 7. It checks each file

- **Type:** the bytes must match the name. A `.jpg` must start like a JPEG, and an `.xmp` must be XML text. Other types
  only get the hidden-content and virus checks.
- **Hidden content:** a search through every byte for the signatures of other kinds of file: Windows, Linux and macOS
  programs, ZIP, RAR, 7-Zip, PDF and Office files, and text such as `<script`, `<html`, `<?php`, `javascript:`,
  `powershell` and `#!/bin/`.
- **JPEG structure:** every segment is walked, through every scan, to the end-of-image marker. A segment that claims to
  run past the end of the file, or a missing end, is suspicious. The script then looks at what comes **after** the end
  of the image, the usual place to hide something. Padding or a second JPEG (phones store a preview there) is normal.
  So is the trailer Samsung phones write there (named blocks, then a directory from `SEFH` to `SEFT`), but only when
  its blocks and directory account for every byte, once, and no block is over 64 KiB. The report gives the block
  names and sizes but not what they hold (a timestamp, a country code…). Anything else is suspicious: named with
  `file`, with its first 128 bytes in hex and as text. The report lists the segments and gives the image size as
  stored.
- **XMP (sidecar files and XMP embedded in a JPEG):** it must be UTF-8 or UTF-16 text with no control characters. A
  `DOCTYPE` or `ENTITY` is suspicious and the file isn't parsed: XMP never needs one, and it is how XML "billion
  laughs" and external-entity attacks work. XInclude is suspicious too. Links that aren't namespace names are listed.
  Then the XML is parsed. Python's parser fetches nothing from the network, and there's no DOCTYPE left to expand. The
  report gives the orientation and size fields, every property name, and the face regions: `mwg-rs:Regions` with
  `AppliedToDimensions` and each box as a table, plus MWG and Microsoft Photo region blocks exactly as written.
- **exiftool:** values are printed only for image-shape tags (size, orientation, make, model, software) and region
  tags. Every other tag (GPS position, dates, serial numbers, people, keywords) is listed by name only, so the log
  says that they're there but not what they say.

### 8. It scans for viruses

ClamAV scans the downloads, archives included, and the unpacked files. A detection makes that attachment dangerous.

### 9. It writes the report

- **The run's log** has the full report: for each attachment, the verdict, its sha256 and its entries; for each file,
  its sha256, type, JPEG structure, XMP fields and regions, and every finding marked `[NOTE]`, `[WARN]` or
  `[DANGER]`. The last line, `VET-JSON {...}`, is the same in JSON for scripts.
- **The run's summary page** has a table of verdicts and fingerprints.
- **The verdict:** *SAFE* (notes at most), *SUSPICIOUS* (one or more warnings), *DANGEROUS*, or *NOT VETTED* (a
  download failed or a link was refused).
- **The run's result:** ✅ only when every attachment is SAFE and the virus scan ran clean, ❌ otherwise. A red run
  means "don't download yet, read the report".

Text from the files can't pose as a workflow command in the log (a line starting with `::`). Commands are switched off
while the report prints, and every quoted line starts with `|`.

### 10. GitHub deletes the machine

The downloads and the unpacked files are deleted with it. Nothing is uploaded as an artifact. The log stays with the
run (90 days by default). Delete a run with `gh run delete <run-id> -R insideTheFlux/attachment-vet`.

### 11. Bringing the files home

Only for a SAFE attachment:

1. Download it into a new, empty folder.
2. Check that its sha256 matches the report's: `sha256sum Example.1.zip`, or in PowerShell
   `Get-FileHash Example.1.zip -Algorithm SHA256`.
3. If it matches, these are the bytes that were checked. If it doesn't, the link served something else: don't use it.
4. Unpack it into another new, empty folder, and check the unpacked files' sha256 against the report the same way.

## What a clean result doesn't prove

- ClamAV only finds known threats. A new one, made for one person, wouldn't be in its signatures.
- A photo can be a perfectly valid JPEG and still be built to crash a particular viewer. The checks prove there's
  nothing hidden in or after the image, not that every decoder will read it safely. Opening it in an up-to-date app is
  the remaining risk.
- Formats other than ZIP, JPEG and XMP only get the hidden-content and virus checks.
- The verdict depends on the limits above (200 MB, 1000 entries, 10,000 JPEG segments). A file beyond them is marked
  suspicious or not vetted rather than passed.

## Privacy

The log holds region names and the metadata property names of the files checked. If the repository is private, only
people with access to it can read the log. Location, dates, people, keywords and serial numbers are never printed.

## Tests

```bash
python3 -I tests/test_vet.py -v
```

The tests build their own archives and files (path traversal, symlinks, zip bombs, encrypted entries, a program after
a JPEG's end, an XML entity bomb, both RDF forms of MWG regions, forged log commands…). Nothing is downloaded and no
real photo is used. The `tests` workflow runs them on every push.

Needs Python 3.9 or later and nothing outside its standard library. `file`, exiftool and ClamAV are used when they're
installed.

## Licence

MIT, see [LICENSE](LICENSE).
