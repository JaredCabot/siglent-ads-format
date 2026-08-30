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
| `$00` | u32 | `$FABD9BA6` | Checksum of the member region (see §4) |
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
| `$00` | File CRC | `$FD82E704` | `$CC677E5E` |
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

**Check the decode this way.** For any ARMCC-built image:

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

## 4. Open question: the container checksum

The specification records that `crc_lib_get_check_sum` on the SDG2000X is a plain
32-bit running sum of the member-region bytes. **That does not reproduce the
SPD3000X value**, and neither do the obvious alternatives. For this file the
record's checksum field is `$FABD9BA6` and the candidates are:

| Candidate over member region `payload[0x34 : 0x34+0x7B328]` | Value |
|---|---|
| 32-bit byte sum (the SDG2000X algorithm) | `$0542645A` |
| 32-bit halfword sum | `$CFBCACCA` |
| 32-bit word sum | `$FCD21B07` |
| CRC-32 (zlib) | `$CA6BC10B` |
| CRC-32 complemented | `$35943EF4` |

The same is true of the outer header's file-CRC field, `$FD82E704`: no byte sum,
word sum or CRC-32 over the raw payload, the decrypted payload or the
de-obfuscated payload matches it.

Two readings are possible, and the evidence does not yet separate them:

* the SPD3000X bootloader uses a different check routine from the SDG2000X's
  `crc_lib_get_check_sum`; or
* the sum is taken over a span that is offset or truncated relative to the one
  assumed here.

This is worth settling before anyone tries to **repackage** an SPD3000X `.ADS`.
The recovered image itself is not in doubt, since the `Region$$Table` test above
passes, the header length field matches exactly, and the whole image
disassembles cleanly with no high-entropy residue. But a repackaged file will
be rejected by the instrument unless this field can be recomputed.

The routine to read is the SPD3000X bootloader's equivalent of
`dev_upgrade_detail_acitve`. It is **not** in the application image shipped in
the `.ADS`, which starts at `0x08040000`; it lives in the bootloader below that,
so recovering it needs a flash dump rather than another update file.

---

## 5. Reference decoder

Pure standard library, no changes to the existing cipher code. Uses
`ads_decode_full` from this repository for the 3DES and the header.

```python
#!/usr/bin/env python3
"""Extract the raw firmware image from an SPD3000X .ADS file."""
import sys, struct
import ads_decode_full as A          # from firmware_extract/

HEADER  = 112
REGIONS = [(0x00000, 0x2800), (0x2E777, 0x1400)]
RECORD  = 0x34
BASE    = 0x08040000                 # SPD3303X-E application link address


def deconfuse(payload: bytes) -> bytes:
    b = bytearray(payload)[::-1]
    L = len(b)
    for i in range(L - L // 2, L):
        b[i] ^= 0xFF
    n = 1
    while True:
        t = n * (n + 1) // 2
        if t >= L:
            break
        b[t] ^= 0xFF
        n += 1
    return bytes(b)


def decode(ads: bytes) -> bytes:
    payload = bytearray(ads[HEADER:])
    for off, ln in REGIONS:
        n = ln // 8 * 8
        payload[off:off + n] = A._des3(bytes(payload[off:off + n]))
    return deconfuse(bytes(payload))


def main(path):
    ads = open(path, 'rb').read()
    hdr = A.decode_header(ads)
    out = decode(ads)

    assert hdr['size'] == len(out), "header length field disagrees with decode"
    chk, length, kind = struct.unpack_from('<IIB', out, 0)
    body = out[RECORD:RECORD + length]
    assert len(body) == length, "container record length disagrees with payload"

    print("product id %d  vendor %r  usb %r" %
          (hdr['product_id'], hdr['vendor'], hdr['usb_host']))
    print("record: checksum $%08X  length $%X  type %d" % (chk, length, kind))

    if body[:4] == b'PK\x03\x04':
        print("member region is a ZIP archive - use the SDG2000X path")
        return

    # Raw image. Verify it with the ARMCC scatter-load table.
    w0, w1 = struct.unpack_from('<2I', body, 0x1BC)
    tbl = (BASE + 0x1BC + w0) - BASE
    lim = (BASE + 0x1BC + w1) - BASE
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

---

## 6. Suggested changes to the existing tools

`firmware_extract/ads_decode_menu.py` assumes the member region is a ZIP. Three
small changes make it handle both families:

1. **Sniff the member region.** `PK\x03\x04` at offset `0x34` selects the archive
   path; anything else is a raw image. Do not use the record's type code, which
   is 7 either way.
2. **Add a "extract raw image" action** that writes `payload[0x34:0x34+length]`
   to a `.bin` and reports the link address inferred from the vector table
   (`vector[1] & 0xFFFF0000`, which gives `$08040000` here).
3. **Refuse to repackage a raw-payload file** until the checksum of §4 is
   understood, rather than emitting one whose record field cannot be verified.

The `Region$$Table` check of §3 is worth adding to the "verify" action for
raw-payload files; it is the only integrity test currently available for them,
and it is decisive.

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
