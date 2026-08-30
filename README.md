# Siglent .ADS Firmware Format

Tools and documentation from a community reverse-engineering of the **Siglent
`.ADS` firmware-update container format** — the packaging Siglent uses for
firmware updates across much of its instrument line (SDG arbitrary waveform
generators, SDS oscilloscopes, SSA spectrum analysers, SPD power supplies and
others).

This repository covers the *format*: how an `.ADS` file is framed, obfuscated,
encrypted and packed, and how to decode one. It is an independent project with
no affiliation with or endorsement from Siglent Technologies.

## What's here

| Path | What it is |
|------|------------|
| `SDG2000X_ADS_Format_Specification.pdf` | The full format specification (Rev 1.2): the 112-byte header, the obfuscation transform, the non-standard two-key 3DES layer, the ZIP container, member payloads, integrity checks, and a reference decoder. Derived from an SDG2000X release and cross-checked against the instrument's own application binary. |
| `firmware_extract/ads_decode_menu.py` | Interactive, menu-driven `.ADS` tool: inspect, verify, extract to a `.zip` or folder, and repackage back into a `.ADS`. Pure standard-library Python 3, no dependencies. |
| `firmware_extract/ads_decode_full.py` | Minimal, dependency-free reference decoder and verifier (the exact decode pipeline). |
| `SPD3000X_ADS_Format_Notes.md` | The SPD3000X / SPD3303X power supplies, whose `.ADS` uses the same container but holds a raw ARM image instead of a ZIP archive. Includes the check that tells a correct decode from a plausible-looking wrong one. |
| `ERRATA.md` | The corrections that produced Rev 1.2 of the specification, with the measurements behind each. Kept as the working record; all of it is applied in the PDF above. |
| `doc/build_ads_format_spec.py` | The build script that renders the specification PDF. The script is the source; the PDF is its output. Needs `hpmanual.py` from the hp-manual-template skill and `reportlab`. |

## Quick start

The decoders need nothing but Python 3:

```
python firmware_extract/ads_decode_menu.py path/to/firmware.ADS
```

Bring your own `.ADS` file. Both container layouts are handled: the newer
nested-package layout (e.g. SDG2000X P39R7) and the older flat layout (e.g.
P17R5).

## The `.ADS` format in brief

A `.ADS` file looks like ciphertext (flat entropy, no magic number), but most of
it is only obfuscation over compressed data:

1. The first 112 bytes are an encrypted header (CRC, decoded length, product id,
   vendor tags).
2. Two small payload regions are encrypted with a **non-standard** two-key 3DES
   (ECB, EDE): standard DES tables, but LSB-first bit/byte and S-box handling and
   a mirrored decrypt, so a stock 3DES library will **not** decrypt them.
3. The payload is de-obfuscated: a whole-payload byte reversal, a second-half
   complement, and a triangular-offset complement.
4. What remains is a 52-byte container header followed by the payload proper:
   a genuine ZIP archive on most models (members, central directory and
   end-of-directory record), or, on the SPD3000X power supplies, a raw ARM
   firmware image with no archive around it at all.

Two integrity words guard the file — one in the 112-byte header, one in the
container record. Both are the two's-complement negation of a 32-bit byte sum,
so region plus stored word comes to zero. The decoders verify both on every
decode. Revision 1.1 of the specification described them as plain un-negated
sums; Revision 1.2 corrects that, and `ERRATA.md` records the evidence.

The 16-byte 3DES key is a fixed constant embedded in shipping firmware; it is
reproduced in the specification only because it is necessary to read the format.
The full method, byte layouts and worked examples are in the specification PDF.

## References and discussion

This work builds on, and is cross-checked against, the long-running EEVblog
forum thread where the Siglent `.ADS` format has been investigated by the
community since 2016:

> **Siglent .ads firmware file format** — EEVblog Test Equipment forum
> https://www.eevblog.com/forum/testgear/siglent-ads-firmware-file-format

Please take questions, corrections and new findings there — it is the natural
home for continuing this discussion, and where format variants for other Siglent
models (SDS oscilloscopes, SDG1000X Plus, and more) are being worked out. The
non-standard 3DES cipher documented here matches `pyDesSiglent.py`, the reference
implementation posted to that thread by **analogNewbie**; earlier structural
work by **janekivi**, **tv84**, **fenugrec** and others in the same thread
mapped the obfuscation, the container and the per-model differences.

## Not included (copyright)

Siglent's firmware update images (`.ADS` files) are **not** part of this
repository — bring your own. The community reference cipher `pyDesSiglent.py`,
posted to the EEVblog thread by its author, is likewise not redistributed here.

## Disclaimer

This is not a Siglent publication. Building or installing a modified `.ADS` can
render an instrument unbootable with **no remote recovery path**. The repackage
feature round-trips exactly through these tools, but a repackaged image is
**not** verified against an instrument's own integrity checks. Use at your own
risk.

## Credits

Reverse engineering and documentation by Jared Cabot, with Claude (Anthropic),
building on the EEVblog community thread linked above.

## Related

SDG2000X remote-interface (SCPI) tools and reference:
https://github.com/JaredCabot/sdg2000x-firmware

SPD3303X service tooling and firmware reference, the instrument whose image the
SPD3000X notes here decode:
https://github.com/JaredCabot/spd3303x-service-tools
