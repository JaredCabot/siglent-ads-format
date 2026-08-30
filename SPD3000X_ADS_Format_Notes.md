# The SPD3000X `.ADS` container

A companion to `SDG2000X_ADS_Format_Specification.pdf` in this repository,
covering the one Siglent family whose `.ADS` payload is not a ZIP archive.

The Siglent **SPD3000X / SPD3303X** programmable DC power supply ships firmware in
a `.ADS` file that uses the **same outer container format as the SDG2000X**,
described in `SDG2000X_ADS_Format_Specification.pdf`: the same 112-byte encrypted
header, the same non-standard two-key 3DES with the same key, the same two
encrypted payload regions and the same three-stage obfuscation. It differs in
exactly one place: **what the container holds**. The SDG2000X payload is a ZIP
archive; the SPD3000X payload is a raw ARM firmware image.

Sample analysed:

| | |
|---|---|
| File | `SPD3303X_E_V100R001B01D03P12R1_GD32F427.ADS` |
| Size | 504,780 bytes |
| Instrument | SPD3303X-E, hardware V6.1 |
| Firmware | 1.01.01.03.12R1 (2025-06-13) |
| Target | GD32F427VET6, Cortex-M4F |

---

## 1. What is identical to the SDG2000X

Everything down to the de-obfuscated payload. No change to the decoder is needed
to reach that point.

* **Header.** The first 112 bytes are the encrypted header; the payload is
  `file[112:]`.
* **Cipher.** The same non-standard 2-key 3DES (ECB, EDE), same key
  `63 03 21 01 0f 01 00 07 17 10 18 4e 5b 69 37 06`, same three inner-loop
  deviations (LSB-first bit/byte order, LSB-first S-box output, mirrored decrypt
  round). A stock 3DES library still will not do.
* **Encrypted regions.** The same two: payload `[0x00000, +0x2800)` and
  `[0x2E777, +0x1400)`. Both are used; see §3.
* **Obfuscation.** `dev_deconfuse_buff` unchanged: whole-payload byte reversal,
  complement of the second half, complement of every triangular offset
  `n(n+1)/2`.
* **Container record.** The de-obfuscated payload still begins with the 52-byte
  (`0x34`) record of Table 2-3 in the specification, with the same three used
  fields in the same places.

Running `firmware_extract/ads_decode_full.py` unmodified against this file
produces a correct header decode and a correct de-obfuscated payload:

```
header: crc=fd82e704 size=0x7b35c product_id=71 vendor='SIGLENT' usb='ISP1763'
decoded length: 0x7b35c (header size field matches)
  container: not a zip (File is not a zip file)
```

The length cross-check passes. Only the final ZIP walk fails, because there is
no ZIP.

---

## 2. What is different: a raw image, not an archive

| Payload offset | Contents |
|---|---|
| `0x00000` – `0x00033` | Container record (52 bytes) |
| `0x00034` – `0x7B35B` | **Raw ARM binary**, 504,616 bytes, with no `PK\x03\x04`, no member records and no central directory |

The container record for this file:

| Offset | Type | Value | Meaning |
|---|---|---|---|
| `$00` | u32 | `$FABD9BA6` | Check word over the member region (§4) |
| `$04` | u32 | `$0007B328` | Length of the member region: 504,616 = payload − 52 |
| `$08` | u8 | `7` | Type code, the same value as the SDG2000X releases |
| `$09`+ | u8[] | 0 | Reserved, zero to `$33` |

The type code being 7 in both families means it does **not** discriminate ZIP
payloads from raw ones. A decoder has to sniff the member region: if it starts
with `50 4B 03 04` it is an archive, otherwise treat it as an opaque blob.

The blob here is a bare Cortex-M image with a vector table at offset 0:

```
0007b328 bytes
+0x0000  f8 85 02 20   initial SP   = 0x200285F8
+0x0004  f9 03 04 08   reset vector = 0x080403F9  (Thumb)
+0x0008  cf d5 04 08   NMI
...
```

The vector entries are all `0x0804xxxx`, so the image is linked to run at
**`0x08040000`**, 256 KiB into the GD32F427's flash, above a bootloader that
is not shipped in the `.ADS`. It is a plain binary: load it at `0x08040000` and
disassemble.

Header fields for this file, for comparison with the SDG2000X values in the
specification:

| Offset | Field | SPD3303X-E | SDG2000X P39R7 |
|---|---|---|---|
| `$00` | File check word (§4) | `$FD82E704` | `$CC677E5E` |
| `$04` | Decoded payload length | `$0007B35C` | `$026A5DD7` |
| `$0C` | Product id | `71` | `10600` |
| `$26` | Vendor tag | `SIGLENT` | `SIGLENT` |
| `$3A` | USB host tag | `ISP1763` | `ISP1763` |

**The header's product id is the model discriminator.** An SPD3303X on the bench
answers `system:product:id?` with **70**; the SPD3303X-E update file analysed here
carries **71** in its header. The two models therefore take different `.ADS` files
of the same firmware release, and the header field is the check a decoder (or the
bootloader) can use to refuse a file meant for the other model. Both units report
firmware `1.01.01.03.12R1`.

---

## 3. A trap worth documenting: skipping the cipher *looks* like it works

Because the obfuscation stage reverses the whole payload, the encrypted region
at payload offset `0x00000` ends up as the **last** `0x2800` bytes of the
de-obfuscated image, and the region at `0x2E777` lands around image offset
`0x4B7B1`. Neither is near the vector table.

So if you de-obfuscate without decrypting, you still get a valid-looking vector
table, correct string pools, a working command table and readable code across
most of the image. The damage is confined to 10,240 bytes at the end and a
5,120-byte window in the middle, which is exactly where the ARM Compiler puts
`Region$$Table` and the compressed `.data` initialiser.

The container check word of §4 does catch this — it is computed over the member
region *after* decoding, and a skipped 3DES stage changes it (on P17R5 the sum
comes out `$9A85B8BB` against `$9A8F97D2` stored). That check was an open
question when these notes were first written, which is why the structural test
below was needed. Keep both: the check word is one number and model-independent,
while the test below is independent of the check-word formula and shows *where*
the damage is.

**Check the decode this way too.** For any ARMCC-built image:

1. Read the two words at image offset `0x1BC` (the `adr`-relative pair loaded by
   `__scatterload_rt2`).
2. `Region$$Table` base = `0x080401BC + word0`, limit = `+ word1`.
3. Each 16-byte entry there must read as
   `{src in image, dst in 0x2000xxxx, plausible size, fn in image}`.

For this file that gives `$080BAE78`…`$080BAE97`, two entries:

```
src=$080BB04C dst=$20000000 size=$00000B28 fn=$080401C4  (__decompress)
src=$080BB328 dst=$20000B28 size=$00027AD0 fn=$08040220  (zero fill)
```

Skip the 3DES step and those words come back as noise. It is a cheap,
unambiguous pass/fail test on a raw-payload `.ADS`, and it is the one that
caught the mistake here.

A second, cruder check: measure per-block Shannon entropy across the recovered
image. A correct decode of this file has **no** 1 KiB block above 7.3 bits/byte.
An undecrypted one has a solid run of them from image offset `0x78B28` to the
end.

---

## 4. The check words: negated byte sums

Both integrity fields in the format — the container record's checksum at `$00`
and the file header's word at `$00` — are the **two's-complement negation of a
32-bit running byte sum**. The vendor stores `-sum` so that adding the region
*and* the stored word together gives zero, which is what the firmware's
`crc_lib_verify_check_number` tests for. `crc_lib_get_check_sum` computes the
plain sum; the negation happens where the result is stored and checked.

**The specification PDF Rev 1.1, Chapter 5, describes the stored value as the
plain un-negated sum. That is an error** — see `ERRATA.md`. The values printed
in the PDF are correct; only the description of what produces them is wrong.

### Container record checksum

`checksum = (-sum(payload[0x34 : 0x34+length])) & 0xFFFFFFFF`

| Release | Byte sum | Stored | |
|---|---|---|---|
| SDG2000X P39R7 | `$3C0C0D5D` | `$C3F3F2A3` | sums to 2³² |
| SDG2000X P17R5 | `$6570682E` | `$9A8F97D2` | sums to 2³² |
| SPD3303X-E | `$0542645A` | `$FABD9BA6` | sums to 2³² |

The value tabulated as a non-match in an earlier draft of these notes,
`$0542645A`, was the answer: it is the negation of the stored word, not an
unrelated candidate.

### File header check word

The header's `$00` field is **not a CRC** despite being named one in earlier
drafts. It covers the **raw** payload — still encrypted and still obfuscated,
i.e. `file[112:]` exactly as it sits on disk — plus the *decrypted* header
from offset 4, so the field excludes itself:

`crc = (-(sum(file[112:]) + sum(decrypted_header[4:112]))) & 0xFFFFFFFF`

| Release | Stored | Recomputed |
|---|---|---|
| SDG2000X P39R7 | `$CC677E5E` | `$CC677E5E` |
| SDG2000X P17R5 | `$9EB260FA` | `$9EB260FA` |
| SPD3303X-E | `$FD82E704` | `$FD82E704` |

For the SPD3303X-E, whose `.ADS` was not to hand, the raw payload was
reconstructed from the extracted image by re-obfuscating and re-encrypting it.
That it lands on the stored word exactly also confirms the reconstruction is
byte-exact and that the container record's reserved bytes really are zero.

Both formulas are implemented as `check_word()` in `ads_decode_full.py` and
`ads_decode_menu.py`, which now verify them on load and recompute them on
repackage. `rebuild_header()` in the menu tool reproduces the original 112-byte
header of both SDG releases byte-for-byte from their own decoded payloads.

**Repackaging is no longer blocked on this question**, but it remains untested
on hardware: no repackaged file has been flashed to an instrument, and any
further check the bootloader applies below `0x08040000` is still unknown.

---

## 5. Reference decoder

Pure standard library, no changes to the existing cipher code. Everything up to
the de-obfuscated payload is `ads_decode_full.decode()` unchanged — the SPD3000X
needs no separate copy of the pipeline.

```python
#!/usr/bin/env python3
"""Extract the raw firmware image from an SPD3000X .ADS file."""
import sys, struct
import ads_decode_full as A          # from firmware_extract/

RECORD = 0x34
BASE   = 0x08040000                  # SPD3303X-E application link address


def main(path):
    ads = open(path, 'rb').read()
    hdr = A.decode_header(ads)
    out = A.decode(ads)              # identical to the SDG2000X path

    assert hdr['size'] == len(out), "header length field disagrees with decode"
    assert A.check_word(ads[112:], sum(A._des3(ads[:112])[4:])) == hdr['crc'], \
        "file check word does not verify"

    chk, length, kind = struct.unpack_from('<IIB', out, 0)
    body = out[RECORD:RECORD + length]
    assert len(body) == length, "container record length disagrees with payload"
    assert A.check_word(body) == chk, "container check word does not verify"

    print("product id %d  vendor %r  usb %r" %
          (hdr['product_id'], hdr['vendor'], hdr['usb_host']))
    print("record: checksum $%08X  length $%X  type %d" % (chk, length, kind))

    if body[:4] == b'PK\x03\x04':
        print("member region is a ZIP archive - use the SDG2000X path")
        return

    # Raw image. Verify it with the ARMCC scatter-load table.
    w0, w1 = struct.unpack_from('<2I', body, 0x1BC)
    tbl, lim = 0x1BC + w0, 0x1BC + w1
    ok = True
    for o in range(tbl, lim, 16):
        src, dst, size, fn = struct.unpack_from('<4I', body, o)
        ok &= (BASE <= src <= BASE + len(body) and 0x20000000 <= dst < 0x20040000
               and 0 < size < 0x40000 and BASE <= fn < BASE + len(body))
        print("  scatter: src=$%08X dst=$%08X size=$%08X fn=$%08X" %
              (src, dst, size, fn))
    print("Region$$Table sane:", ok, "(if False, the 3DES step is wrong)")

    open(path + '.bin', 'wb').write(body)
    print("wrote %s.bin  (%d bytes, load at $%08X)" % (path, len(body), BASE))


if __name__ == '__main__':
    main(sys.argv[1])
```

Output for the sample:

```
product id 71  vendor 'SIGLENT'  usb 'ISP1763'
record: checksum $FABD9BA6  length $7B328  type 7
  scatter: src=$080BB04C dst=$20000000 size=$00000B28 fn=$080401C4
  scatter: src=$080BB328 dst=$20000B28 size=$00027AD0 fn=$08040220
Region$$Table sane: True
wrote ....ADS.bin  (504616 bytes, load at $08040000)
```

The two `Region$$Table` bounds are `$080BAE78` (base) and `$080BAE98`
(limit, exclusive), giving the two 16-byte entries above.

---

## 6. Changes to the existing tools

**Done.** Both decoders now carry `check_word()` and verify the file check word
and the container checksum on every decode; `ads_decode_menu.py` (v1.5)
recomputes both when repackaging, via `rebuild_header()`, instead of copying a
reference header verbatim and writing an un-negated sum. Its repackage warning
no longer claims the checksum may be wrong, because it no longer is — only the
"never flashed to an instrument" caveat remains.

**Still outstanding**, and untestable here until an SPD3000X `.ADS` is to hand
rather than just the extracted image:

1. **Sniff the member region.** `PK\x03\x04` at offset `0x34` selects the archive
   path; anything else is a raw image. Do not use the record's type code, which
   is 7 either way. Today `ads_decode_menu.py` refuses a raw-payload file
   outright — `Session.open` raises *"no archive members found"* — so the menu
   tool cannot open an SPD3000X release at all.
2. **Add an "extract raw image" action** that writes `payload[0x34:0x34+length]`
   to a `.bin` and reports the link address inferred from the vector table
   (`vector[1] & 0xFFFF0000`, which gives `$08040000` here).
3. **Add the `Region$$Table` check of §3 to the verify action** for raw-payload
   files, as a second opinion. It is no longer the only test: the container
   check word of §4 covers the member region as decoded and so catches a skipped
   3DES stage on its own (measured on P17R5: `$9A85B8BB` computed against
   `$9A8F97D2` stored). `Region$$Table` remains worth having because it is
   independent of the check-word formula rather than derived from it, and it
   points at *where* a decode went wrong rather than only that it did.

---

## 7. What this file is, once extracted

Out of scope for the container documentation, but useful context: the 504,616-byte
image is the complete SPD3303X-E application: front-panel UI, regulation loops,
an RTOS, an lwIP-based stack with a VXI-11 server and a raw SCPI socket on TCP
5025, and the whole remote command set. The command table is built at run time
by 147 registration calls and contains 65 command spellings that do not appear in
Siglent's Quick Start guide, including an undocumented screen dump, a remote
front-panel key-injection command and the whole calibration interface. That
analysis, now confirmed against a physical SPD3303X, is written up separately in
*SPD3303X Firmware Technical Reference* (document SPD3303X-90T01), in
https://github.com/JaredCabot/spd3303x-service-tools.

---

*Reverse engineering and documentation by Jared Cabot, with Claude (Anthropic).
Not a Siglent publication; no affiliation with or endorsement from Siglent
Technologies. Siglent's firmware images are not redistributed here.*
