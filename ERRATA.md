# Errata — `SDG2000X_ADS_Format_Specification.pdf` Rev 1.1

**All of these corrections are applied in Revision 1.2 of the specification**,
which supersedes Rev 1.1; the PDF in this repository is Rev 1.2 and Chapter 7
summarises the changes. This file is kept as the working record: it carries the
measurements behind each correction in more detail than the specification does.
The decoders in `firmware_extract/` implement the corrected behaviour.

---

## E1. The container checksum is a *negated* byte sum (Chapter 5, "Integrity Checks"; Chapter 2, Table 2-3)

**The PDF says.** Chapter 5: *"The routine `crc_lib_get_check_sum` that computes
it is a plain running sum: it adds every byte of the region into a 32-bit
accumulator and stores the result. A decoder that wants to reproduce it sums the
bytes from payload offset `$34` for the length in the record's length field."*

**Correction.** Summing the bytes gives the *negation* of the stored word, not
the stored word. The field holds

```
checksum = (-sum(payload[0x34 : 0x34+length])) & 0xFFFFFFFF
```

so that the region and the stored word together sum to zero. That is what
`crc_lib_verify_check_number` tests: it accumulates both and compares against
zero, rather than recomputing a sum and comparing values. `crc_lib_get_check_sum`
does compute the plain sum, as the PDF says — the negation happens where the
result is stored and verified, which is the step the original reading missed.

Measured on every release available:

| Release | Byte sum | Stored word (PDF value) |
|---|---|---|
| SDG2000X P39R7 | `$3C0C0D5D` | `$C3F3F2A3` |
| SDG2000X P17R5 | `$6570682E` | `$9A8F97D2` |
| SPD3303X-E | `$0542645A` | `$FABD9BA6` |

Each pair sums to exactly 2³². **The stored values printed in the PDF are
correct** — Table 2-3's `$C3F3F2A3` is right. Only the description of how to
reproduce them is wrong.

## E2. The header's `$00` field is a check word, not a CRC (Chapter 2, "The Encrypted Header")

The 112-byte header's first field is documented as a CRC and named `crc` in the
reference decoder. It is not a CRC. It is the same negated byte sum as E1, taken
over the **raw** payload — still encrypted and still obfuscated, exactly as the
bytes sit on disk — plus the decrypted header from offset 4, so that the field
excludes itself:

```
crc = (-(sum(file[112:]) + sum(decrypted_header[4:112]))) & 0xFFFFFFFF
```

| Release | Stored | Recomputed |
|---|---|---|
| SDG2000X P39R7 | `$CC677E5E` | `$CC677E5E` |
| SDG2000X P17R5 | `$9EB260FA` | `$9EB260FA` |
| SPD3303X-E | `$FD82E704` | `$FD82E704` |

Because this word covers the payload *before* decryption, it verifies whether or
not a decoder ran the 3DES stage. The container checksum of E1 does not: it is
computed after decoding, and a skipped 3DES stage changes it (on P17R5 the sum
comes out `$9A85B8BB` against `$9A8F97D2` stored). Use E1's word as the decode
test, not E2's.

## E3. Consequence for repackaging (Chapter 5; `ads_decode_menu.py` before v1.5)

`ads_decode_menu.py` up to v1.4 wrote the un-negated sum into the container
record and copied the 112-byte header verbatim from a reference file. **Every
`.ADS` it repackaged therefore carried two wrong integrity words** and would
have been rejected by an instrument's bootloader. v1.5 computes both correctly;
`rebuild_header()` reproduces the original header of both SDG releases
byte-for-byte from their own decoded payloads.

Repackaged files remain untested on hardware. Nothing here changes that warning.

## E4. The payload is not always a ZIP archive (Chapter 2; Chapter 5, "Member Payloads")

The PDF describes the member region as a ZIP archive throughout. That holds for
the SDG2000X but not for the whole format: the SPD3000X / SPD3303X power
supplies use the same container with a **raw ARM firmware image** in place of
the archive. The record's type code is `7` in both cases and does not
discriminate; sniff for `50 4B 03 04` at payload offset `$34` instead. See
`SPD3000X_ADS_Format_Notes.md`.

---

*Raised and resolved 2026-08-30. Folded into Rev 1.2; rebuild the PDF with
`doc/build_ads_format_spec.py`.*
