#!/usr/bin/env python3
"""Build SDG2000X_ADS_Format_Specification.pdf in the HP/Agilent house style.

This script is the source of truth for the specification; the PDF is its output.
Regenerate rather than patching the PDF, and never edit the PDF by hand.

Requires hpmanual.py and its img/ folder (the Note and Warning icons) from the
hp-manual-template skill, copied into this directory, plus reportlab:

    pip install reportlab
    python build_ads_format_spec.py

Rev 1.1 was rendered without keeping this script, which is why the errata had to
be carried in a separate file for a while. Keep it with the document from now on.

Revision 1.2 (August 2026) folds in the corrections raised in ERRATA.md:
both integrity words are NEGATED byte sums, the header's first field is a check
word and not a CRC, and the member region is not always a ZIP archive.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hpmanual as H

H.TIGHT_SECTIONS = True


def esc(s):
    """Escape text before it reaches reportlab's mini-HTML parser."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def mono(s):
    return "<font face='Courier'>%s</font>" % esc(s)


def code(m, text):
    """Emit a code block. Manual.code() escapes the text itself, so do not
    pre-escape here or the markup entities show through literally."""
    m.code(text)


TOC = [
    (1, "1. Overview", "1-1"),
    (2, "What a .ADS File Is", "1-1"),
    (2, "The Four Layers", "1-1"),
    (2, "How the Instrument Reads It", "1-2"),
    (1, "2. Container Structure", "2-1"),
    (2, "File Layout", "2-1"),
    (2, "The Encrypted Header", "2-1"),
    (2, "The Container Record", "2-2"),
    (2, "Member Records", "2-2"),
    (1, "3. The Obfuscation Transform", "3-1"),
    (2, "Byte Reversal", "3-1"),
    (2, "Second-Half Complement", "3-1"),
    (2, "Triangular Complement", "3-1"),
    (2, "Why It Looks Encrypted", "3-1"),
    (1, "4. The Triple-DES Layer", "4-1"),
    (2, "The Cipher", "4-1"),
    (2, "The Key and Key Schedule", "4-1"),
    (2, "The Encrypted Regions", "4-2"),
    (2, "What the Regions Cover", "4-2"),
    (1, "5. Member Payloads", "5-1"),
    (2, "The Two Packages", "5-1"),
    (2, "The Zynq-7000 Package", "5-1"),
    (2, "The AM3359 Package", "5-2"),
    (2, "Installation", "5-2"),
    (2, "Integrity Checks", "5-2"),
    (2, "Payloads That Are Not Archives", "5-3"),
    (1, "6. Reference Decoder", "6-1"),
    (2, "The Decode Pipeline", "6-1"),
    (2, "Python Implementation", "6-1"),
    (1, "7. Recovery and Verification", "7-1"),
    (2, "How the Format Was Recovered", "7-1"),
    (2, "Verification Results", "7-1"),
    (2, "The Former AM3359 Residual", "7-2"),
    (2, "Corrections in Revision 1.2", "7-3"),
    (1, "8. Field Reference", "8-1"),
    (1, "9. Constants", "9-1"),
]


def main():
    m = H.Manual("SDG2000X_ADS_Format_Specification.pdf",
                 doc_title="SDG2000X .ADS Firmware Container Format",
                 part_number="SDG2000X-90A01")

    # ---------------------------------------------------------------- cover
    m.cover("SIGLENT SDG2000X Arbitrary Waveform Generator",
            ["The .ADS", "Firmware", "Container"],
            "Format Specification and Reference Decoder",
            ["Community Reverse-Engineering Document",
             "Jared Cabot &nbsp;&bull;&nbsp; with Claude (Anthropic)",
             "Revision 1.2 &nbsp;&bull;&nbsp; August 2026"])

    # --------------------------------------------------------------- notice
    m.notice([
        ("Scope",
         "This document specifies the on-disk format of the SIGLENT .ADS firmware update "
         "file used by the SDG2000X series, completely: the container framing, the "
         "obfuscation transform, the two-key triple-DES layer, the member payloads, and "
         "the integrity checks. It gives a reference decoder and a full account of how the "
         "format was recovered and verified. It is derived from a single release, "
         "SDG2000X_P39R7.ADS, and cross-checked against the instrument's own application "
         "binary."),
        ("Provenance",
         "Every structural claim is traced to one of two primary sources: the bytes of the "
         ".ADS file itself, and the routines in the instrument's application binary that "
         "read it. Where a function is named it is the name in the binary's dynamic symbol "
         "table. The non-standard cipher was independently cross-checked against the "
         "long-running EEVblog community thread on this format and against analogNewbie's "
         "reference implementation posted there (pyDesSiglent.py); the two agree "
         "byte-for-byte. Nothing here is guessed."),
        ("Applicability",
         "The format is shared across the SDG2000X hardware generations. One .ADS carries "
         "images for both the Xilinx Zynq-7000 hardware and the earlier Texas Instruments "
         "Sitara AM3359 hardware. The transform, keys and framing described here apply to "
         "both; only the member payloads differ.\n\n"
         "The same container is used beyond the SDG2000X. The SPD3000X and SPD3303X "
         "programmable power supplies carry an identical header, cipher, key, region layout "
         "and obfuscation, but hold a raw ARM firmware image where the SDG2000X holds a ZIP "
         "archive. Chapter 5 gives the test that tells the two apart."),
        ("Conventions",
         "Hexadecimal takes a $ prefix. Byte offsets are decimal or hexadecimal as "
         "convenient and always absolute unless a base is named. this_type denotes a "
         "function in the application binary. Bit and byte order is little-endian "
         "throughout, matching the ARM target."),
        ("Revisions",
         "Revision 1.0, the first release. Revision 1.1 corrected the cipher to the "
         "non-standard form of Chapter 4 and withdrew the reported AM3359 residual. "
         "Revision 1.2 corrects both integrity words to the negated byte sums they are, "
         "reclassifies the header's first field as a check word rather than a CRC, and "
         "records that the member region is not always a ZIP archive. Chapter 7 lists the "
         "1.2 corrections in full."),
        ("Disclaimer",
         "This is not a SIGLENT publication and carries no endorsement from SIGLENT "
         "Technologies. It documents an update format for the purpose of inspection and "
         "recovery. The triple-DES key given here is a fixed constant embedded in shipping "
         "firmware; it is reproduced because it is necessary to read the format and is not "
         "secret in any meaningful sense. Building or installing a modified .ADS risks "
         "rendering an instrument unbootable with no remote recovery path."),
    ])

    m.contents("Contents", TOC)

    # ------------------------------------------------------------ chapter 1
    m.chapter(1, "Overview", footer_title="Overview")

    m.h1("What a .ADS File Is")
    m.body(
        "A .ADS file is the firmware update package for the SIGLENT SDG2000X. The instrument "
        "reads it from a USB drive, unpacks it, writes the results to its boot and root "
        "partitions, and reboots. The release documented here, %s, is 40,525,383 bytes and is "
        "dated 5 January 2026." % mono("SDG2000X_P39R7.ADS"))
    m.body(
        "Opened in a hex editor the file looks like ciphertext: its byte histogram is flat, it "
        "carries no recognisable magic number at any offset, and a signature scanner finds "
        "nothing. That appearance is the result of a light obfuscation over ordinary compressed "
        "data, not of encryption of the whole file. Most of the package is recovered by undoing "
        "three reversible transforms. A small part of it, and only a small part, is genuinely "
        "encrypted with triple-DES; the key for that is a fixed constant in the instrument's own "
        "firmware and is given in Chapter 4.")

    m.h1("The Four Layers")
    m.body(
        "The format is best understood as four layers, outermost first. This document takes them "
        "in the order a decoder unwinds them.")
    m.table("Table 1-1. The Layers of a .ADS File",
            ["Layer", "What it is", "Chapter"],
            [["Header",
              "A 112-byte encrypted header carrying a check word, the decoded length, a product "
              "id and vendor tags.", "2"],
             ["Cipher",
              "A non-standard two-key triple-DES over two small regions of the payload.", "4"],
             ["Obfuscation",
              "A whole-payload byte reversal and two exclusive-OR masks.", "3"],
             ["Container",
              "A short record header, then the member region: a genuine ZIP archive on the "
              "SDG2000X, a raw firmware image on some other models.", "2, 5"]],
            col_widths=[70, 330, 55])
    m.body(
        "The layering is not strictly nested. The header is a separate 112-byte read. The cipher "
        "and the obfuscation both operate on the payload that follows it, the cipher first and "
        "the obfuscation second, and the container structure only becomes visible once both are "
        "undone.")

    m.h1("How the Instrument Reads It")
    m.body(
        "The application binary drives the update from %s. That routine reads the 112-byte "
        "header, decrypts it, and checks the product and version. It then calls %s, which reads "
        "the rest of the file, verifies a check word, calls %s to decrypt the two cipher regions "
        "and undo the obfuscation, and finally calls %s to split the container into its members "
        "and unzip them into place."
        % (mono("dev_update_system"), mono("dev_upgrade_detail_acitve"),
           mono("dev_decode_data"), mono("dev_fw_update_ads")))
    m.body(
        "Every routine named in this document is a real, named function in the shipping binary. "
        "The binary is stripped of its ordinary symbol table but retains a dynamic symbol table "
        "of 40,601 defined symbols, so each step can be followed to a named function and read "
        "directly rather than inferred. The build path compiled into the binary, %s, shows it is "
        "one product of a source tree that serves the whole SDG line."
        % mono("/home/brus_peng/workdir/sdg2000x_zynq/trunk/"))

    # ------------------------------------------------------------ chapter 2
    m.chapter(2, "Container Structure", footer_title="Container Structure")

    m.h1("File Layout")
    m.body(
        "At the coarsest level the file is a 112-byte header followed by a payload of 40,525,271 "
        "bytes. The header is consumed separately; everything else is the payload, and all the "
        "transforms in Chapters 3 and 4 operate on it.")
    m.table("Table 2-1. Top-Level File Layout",
            ["Offset", "Length", "Contents"],
            [["$0000", "112", "Encrypted header (Chapter 2)"],
             ["$0070", "40,525,271", "Payload: cipher + obfuscation + container"]],
            col_widths=[70, 100, 285])

    m.h1("The Encrypted Header")
    m.body(
        "The first 112 bytes are read into their own buffer and passed to %s, which decrypts them "
        "with the same cipher and key as the payload regions. The header is not obfuscated: "
        "unlike the payload it is neither reversed nor masked, only decrypted. Decrypted, it is a "
        "structured record whose fields are given in Table 2-2. The instrument uses it for a "
        "pre-flight check, reading a vendor tag and a product code before committing to the "
        "update." % mono("dev_decode_header_data"))
    m.table("Table 2-2. The Decrypted 112-Byte Header",
            ["Offset", "Type", "Value in P39R7", "Meaning"],
            [["$00", "u32", "$CC677E5E", "File check word (Chapter 5). Not a CRC."],
             ["$04", "u32", "$026A5DD7", "Decoded payload length (= 40,525,271)"],
             ["$0C", "u32", "$00002968", "Product id (10600)"],
             ["$26", "char[]", "SIGLENT", "Vendor tag (NUL-terminated)"],
             ["$3A", "char[]", "ISP1763", "USB host-controller tag"],
             ["other", "u8[]", "0", "Zero padding"]],
            col_widths=[55, 50, 100, 250])
    m.body(
        "The length field at $04 equals the decoded payload length exactly, in every release "
        "examined, which makes the decrypted header a useful cross-check on a decode. The header "
        "is not part of the container and is not needed to recover the members, so a decoder that "
        "only wants the payload may discard it.")
    m.note(
        "What matters for decoding is that the payload begins at file offset 112, not at zero. A "
        "decoder that reverses the whole file rather than the payload will misplace every member.")

    m.h1("The Container Record")
    m.body(
        "Once the payload is decrypted and de-obfuscated (Chapters 3 and 4), its first 52 bytes "
        "($34) are a small record header, and the members follow at offset $34. The header has "
        "three used fields and is otherwise zero.")
    m.table("Table 2-3. The Container Record at Payload Offset $00",
            ["Offset", "Type", "Value in P39R7", "Meaning"],
            [["$00", "u32", "$C3F3F2A3", "Check word over the member region (see Chapter 5)"],
             ["$04", "u32", "$026A5DA3",
              "Length of the member region: 40,525,219 = payload − 52"],
             ["$08", "u8", "7", "Type code"],
             ["$09+", "u8[]", "0", "Reserved, zero to $33"]],
            col_widths=[55, 50, 100, 250])
    m.body(
        "The length field is exactly the payload length less the 52-byte record, so the member "
        "region runs from offset $34 to the end of the payload. The check word is verified by %s "
        "before the members are unpacked. It is not a CRC: it is the negation of a 32-bit sum of "
        "the member-region bytes, described in Chapter 5." % mono("crc_lib_verify_check_number"))

    m.h1("Member Records")
    m.body(
        "From offset $34 the payload is a genuine ZIP archive. It opens with the members as ZIP "
        "local file records, each the four-byte signature %s, a 26-byte local header carrying the "
        "compression method and the compressed and uncompressed sizes, the member name, and then "
        "the DEFLATE data. The members are followed by a proper ZIP central directory (one %s "
        "record per member) and an end-of-central-directory record %s. A standard ZIP reader "
        "opens the container as-is once the payload is decoded."
        % (mono("50 4B 03 04"), mono("50 4B 01 02"), mono("50 4B 05 06")))
    m.body(
        "This release carries three members: the two hardware-family packages and an installer "
        "script. Offsets below are payload-relative, from the start of the decoded payload.")
    m.table("Table 2-4. Members in P39R7 (payload offsets)",
            ["Member", "Local hdr", "Data", "Compressed", "Uncompressed", "CRC-32"],
            [["zynq_packet.zip", "$34", "$61", "25,028,713", "25,169,906", "$B4FD77AB"],
             ["335x_packet.zip", "$17DE8CA", "$17DE8F7", "15,495,737", "15,599,338", "$39B5F32F"],
             ["update.sh", "$26A5B30", "$26A5B57", "333", "1,138", "$4EF70333"]],
            small=True)
    m.body(
        "The central directory begins at payload offset $26A5CA4 and holds three 46-byte entries "
        "plus their names, 285 bytes in all; the end-of-central-directory record follows at "
        "$26A5DC1 and closes the payload at $26A5DD7. An earlier revision of this document "
        "mistook the third member, the central directory and the EOCD -- 679 bytes together "
        "-- for trailing filler, because the cipher error described in Chapter 4 had "
        "corrupted them beyond recognition. With the correct cipher they resolve into ordinary "
        "ZIP structure and the whole container validates.")
    m.note(
        "The third member, %s, is the installer the updater runs after unpacking (Chapter 5). It, "
        "the central directory and the EOCD all fall inside the first cipher region, which is why "
        "a correct cipher is required even to see that the container is a well-formed ZIP."
        % mono("update.sh"))

    # ------------------------------------------------------------ chapter 3
    m.chapter(3, "The Obfuscation Transform", footer_title="The Obfuscation Transform")
    m.body(
        "The obfuscation is performed by %s, which a decoder inverts by applying the same three "
        "steps, because each is its own inverse. In the order the function applies them: a full "
        "byte reversal, a complement of the second half, and a complement of a sparse set of "
        "triangular offsets. The description below is the function read instruction by "
        "instruction; a small buffer run through both the function and this description "
        "byte-for-byte confirms the reading." % mono("dev_deconfuse_buff"))

    m.h1("Byte Reversal")
    m.body(
        "The function first reverses the whole payload. It does this in an unusual way that a "
        "casual reading mistakes for something cleverer: one loop reverses each half of the "
        "buffer in place, and a second loop swaps the two halves. The net effect is a plain full "
        "reversal, %s in one line, and it is equivalent for every length, odd or even, including "
        "the payload's odd length. Let L be the payload length; then output byte i is input byte "
        "L-1-i." % mono("payload[::-1]"))

    m.h1("Second-Half Complement")
    m.body(
        "The function then complements, by exclusive-OR with $FF, every byte in the second half "
        "of the reversed buffer. With %s, the complemented range is %s: the byte at %s and "
        "everything after it. On this file H is 20,262,635 and the boundary L-H is 20,262,636, "
        "which falls inside the first member, so the member spans the boundary and a correct "
        "decode reproduces it exactly across the seam."
        % (mono("H = L // 2"), mono("[L-H : L)"), mono("L-H")))

    m.h1("Triangular Complement")
    m.body(
        "Finally the function complements the byte at every triangular offset, that is, at %s for "
        "n = 1, 2, 3, ... while %s is less than L. These offsets are 1, 3, 6, 10, 15, ...: nine "
        "thousand of them across the forty-megabyte payload, one part in four thousand. Because "
        "they are so sparse and so regularly spaced, they defeat a signature scan without "
        "materially changing the byte statistics."
        % (mono("n(n+1)/2"), mono("n(n+1)/2")))
    m.note(
        "The triangular series begins at n = 1, so payload offset 0 is never complemented by this "
        "step, and it lies outside the second-half range, so it is never complemented at all. An "
        "implementation that starts the series at n = 0 will corrupt the first byte of the "
        "container record. It happens not to matter for the members, which begin at $34, but it "
        "is wrong.")

    m.h1("Why It Looks Encrypted")
    m.body(
        "None of these steps is cryptographic. A chi-square test on the raw file scores 25,219 "
        "against a uniform distribution on 255 degrees of freedom, where true ciphertext over "
        "forty megabytes would score about 255; the serial correlation is −0.0128 and a "
        "Monte-Carlo estimate of pi over the file errs by a tenth of a per cent. These are the "
        "signatures of a good compressor's output, seen through a reversal and a sparse mask, not "
        "of a cipher. What genuine encryption the file contains is confined to the two regions of "
        "Chapter 4.")

    # ------------------------------------------------------------ chapter 4
    m.chapter(4, "The Triple-DES Layer", footer_title="The Triple-DES Layer")

    m.h1("The Cipher")
    m.body(
        "The application binary contains a full DES implementation, %s at $002C5820, with a "
        "two-key triple-DES mode selected by a run-time flag. Its permutation and S-box tables "
        "are the standard DES tables: the initial-permutation table at $00631374 matches the DES "
        "IP table byte for byte, and the expansion, P-box, S-box, PC-1 and PC-2 tables all match "
        "their standard values." % mono("Des_Go"))
    m.body(
        "The tables are standard; the algorithm is not. Three details of the round and block "
        "plumbing deviate from textbook DES, so a stock DES or 3DES library given the key below "
        "will NOT decrypt these regions -- it returns noise. This is the single fact that "
        "most obstructs recovery, and it is why earlier work on this format reported the cipher "
        "as &ldquo;implemented the wrong way.&rdquo; The three deviations are:")
    m.steps([
        "Bytes are converted to bits least-significant-bit first. Where textbook DES numbers the "
        "bits of each input byte from the most significant, this implementation numbers them from "
        "the least significant, and packs its output bytes the same way.",
        "Each S-box's four-bit output is written into the round buffer least-significant-bit "
        "first, the reverse of the usual order.",
        "The final permutation is applied to the halves as L||R with no closing swap, and "
        "decryption is a mirrored round whose active half is L rather than the textbook "
        "&ldquo;same round with the subkeys reversed.&rdquo; Encrypt and decrypt are exact "
        "inverses, but the construction is not standard DES."])
    m.body(
        "In triple-DES mode the cipher runs three of these single-DES operations over each "
        "eight-byte block in place: the first and third with the first key, the middle one with "
        "the second key in the opposite direction -- a two-key EDE arrangement. The update "
        "path calls it in the decrypt direction, so a block is recovered as %s. "
        "Electronic-codebook mode is used: blocks are independent, with no chaining and no "
        "initialisation vector." % mono("D(K1, E(K2, D(K1, C)))"))

    m.h1("The Key and Key Schedule")
    m.body(
        "The 16-byte key is a constant in the binary's data segment at $008A87AC. The key "
        "schedule, the routine at $2C59D4, clears a 16-byte working key, copies the constant into "
        "it, schedules the first eight bytes as the first DES key, and, because the key length is "
        "sixteen, schedules the second eight bytes as the second DES key and sets the triple-DES "
        "flag.")
    code(m, """key (16 bytes) = 63 03 21 01 0f 01 00 07 17 10 18 4e 5b 69 37 06

K1 = 63 03 21 01 0f 01 00 07             (first DES key)

K2 = 17 10 18 4e 5b 69 37 06             (second DES key)

mode = two-key triple-DES, EDE, ECB, decrypt""")
    m.note(
        "The same DES engine and a run-time key are used elsewhere in the firmware to encrypt the "
        "instrument's serial-number licence backup on its own filesystem. That path is unrelated "
        "to the update format and is not covered here.")

    m.h1("The Encrypted Regions")
    m.body(
        "The update decoder, %s, decrypts exactly two regions of the payload, in place, before "
        "handing the buffer to the obfuscation step. Both offsets are relative to the start of "
        "the payload, that is, to file offset 112." % mono("dev_decode_data"))
    m.table("Table 4-1. Triple-DES Regions (payload-relative)",
            ["Region", "Offset", "Length", "Blocks"],
            [["1", "$00000", "$2800 = 10,240", "1,280"],
             ["2", "$2E777", "$1400 = 5,120", "640"]],
            col_widths=[75, 100, 150, 130])
    m.body(
        "Each length is a whole number of eight-byte blocks. The second region begins at an "
        "offset that is not a multiple of eight; the cipher nonetheless treats that offset as its "
        "first block boundary, and a decoder must do the same.")

    m.h1("What the Regions Cover")
    m.body(
        "The two regions sit at the very start of the payload. After the byte reversal, the start "
        "of the payload becomes the end of the container, so both regions map to the tail of the "
        "decoded container. Region 1, the larger, covers the compressed tail of %s, the whole of "
        "the third member %s, and the container's entire central directory and end-of-directory "
        "record. Region 2 covers a slab deeper inside %s. The first member, %s, occupies the "
        "front of the container and never overlaps either region."
        % (mono("335x_packet.zip"), mono("update.sh"), mono("335x_packet.zip"),
           mono("zynq_packet.zip")))
    m.body(
        "Two consequences follow. First, because region 1 lands on the central directory and "
        "EOCD, a decode with the wrong cipher does not merely damage one member -- it "
        "destroys the ZIP end structure, so the container will not even open as an archive. "
        "Getting the cipher right is what turns the tail back into a well-formed ZIP. Second, the "
        "cipher still does not touch the current-hardware image: %s lies wholly in front of both "
        "regions and decodes correctly from the obfuscation alone. A reader interested only in "
        "the Zynq firmware can ignore the cipher; a reader who wants a valid container, the "
        "AM3359 image, or the installer needs it." % mono("zynq_packet.zip"))

    # ------------------------------------------------------------ chapter 5
    m.chapter(5, "Member Payloads", footer_title="Member Payloads")

    m.h1("The Two Packages")
    m.body(
        "The container holds three members: two complete firmware images, one per "
        "system-on-chip family, and a short installer script %s. One .ADS therefore serves both "
        "hardware generations from a single file, and the instrument's updater installs whichever "
        "package matches the board it is running on. Table 5-1 gives the members' sizes, stored "
        "CRC-32 values and, for the two packages, their inner entry counts." % mono("update.sh"))
    m.table("Table 5-1. Members of the Container",
            ["Member", "Compressed", "Uncompressed", "CRC-32", "Entries"],
            [["zynq_packet.zip", "25,028,713", "25,169,906", "$B4FD77AB", "420"],
             ["335x_packet.zip", "15,495,737", "15,599,338", "$39B5F32F", "299"],
             ["update.sh", "333", "1,138", "$4EF70333", "--"]])

    m.h1("The Zynq-7000 Package")
    m.body(
        "%s is a standard ZIP archive of 420 members holding the complete Zynq-7000 system: the "
        "application binary %s, the root filesystem %s, the boot image, the FPGA bitstream, the "
        "Linux kernel %s, the 216 built-in waveform tables, and the driver and configuration "
        "trees. It decompresses to 25,169,906 bytes and its stored CRC-32 verifies exactly. This "
        "is the member a current SDG2000X installs. Table 5-2 lists its principal members."
        % (mono("zynq_packet.zip"), mono("awg.app"), mono("rootfs.cramfs"), mono("uImage")))
    m.table("Table 5-2. Principal Members of zynq_packet.zip",
            ["Member", "Size", "Content"],
            [["awg.app", "12,489,120",
              "Main application. Stripped ARM EABI5 ELF, dynamically linked."],
             ["rootfs.cramfs", "10,858,496",
              "Root filesystem, cramfs v2, 2,102 files, BusyBox based."],
             ["BOOT.bin", "4,588,024", "Zynq first-stage boot image."],
             ["config/fpga/top_unicorn_zynq.bit", "4,045,674", "FPGA bitstream."],
             ["uImage", "3,132,776", "Linux kernel image."],
             ["devicetree.dtb", "15,724", "Flattened device tree."],
             ["config/arb/*.bin", "varies",
              "216 built-in waveform tables, all but three of 32,768 bytes."],
             ["drivers/*.ko", "varies",
              "siglent_vdma, xilinx_axidma, g_usbtmc, gpib, siglent_touch_irq."]],
            col_widths=[150, 75, 230], small=True)
    m.body(
        "The application binary is a stripped ARM EABI5 ELF, dynamically linked against the "
        "BusyBox-based root filesystem. Its symbol names survive in run-time type information and "
        "in assertion strings, and the build path %s appears throughout, which identifies the "
        "binary as the SDG2000X Zynq build rather than one of the other families the source tree "
        "serves." % mono("/home/brus_peng/workdir/sdg2000x_zynq/trunk/sdg/lib/src/"))
    m.body(
        "The same source tree evidently builds the whole SDG line. Type names recovered from the "
        "binary include driver classes for the SDG1000, SDG2000, SDG6000 and SDS2000X Plus. This "
        "shared lineage is why the binary carries, parses and then discards parameters that "
        "belong to other models.")

    m.h1("The AM3359 Package")
    m.body(
        "%s is the corresponding archive for the earlier hardware, built around the Texas "
        "Instruments Sitara AM3359 processor rather than the Zynq. It is itself a ZIP of 299 "
        "entries: a boot script, the MLO second-stage bootloader, a U-Boot environment, and the "
        "AM3359 application %s, a 12.9-megabyte ARM ELF. It decompresses to 15,599,338 bytes and, "
        "with the corrected cipher, every one of its entries -- including %s -- "
        "inflates bit-exact and CRC-valid."
        % (mono("335x_packet.zip"), mono("sdg2000.app"), mono("sdg2000.app")))
    m.body(
        "One .ADS therefore serves both hardware generations from a single file; the instrument "
        "installs whichever member matches the board it is running on. On a Zynq instrument the "
        "AM3359 member is carried but not installed.")

    m.h1("Installation")
    m.body(
        "The container's third member is a top-level %s (a POSIX shell script that begins %s); "
        "the updater runs it after unpacking to drive the install. Each hardware package in turn "
        "carries its own installer, %s, which writes the boot image and kernel to raw NAND "
        "partitions and then copies the application and configuration files into place."
        % (mono("update.sh"), mono("#! /bin/sh"), mono("zynq_update.sh")))
    code(m, """flash_erase /dev/mtd<n> 0 0

nandwrite -s 0 -p /dev/mtd<n> /usr/bin/siglent/usr/usr/upgrade/<uImage>

cp -pf  /usr/bin/siglent/usr/usr/upgrade/*.app  /usr/bin/siglent/

cp -rpf /usr/bin/siglent/usr/usr/upgrade/bin    /usr/bin/siglent/""")
    m.warning(
        "The kernel and boot image are written by erasing a raw NAND partition and writing it "
        "again. An interruption between the erase and the write leaves the instrument without a "
        "bootable image, which is why the manufacturer's update instructions say not to remove "
        "power during an update. There is no recovery path over the remote interface.")

    m.h1("Integrity Checks")
    m.body(
        "The format carries integrity checks at three levels. Each ZIP member, inner and outer, "
        "has the usual stored CRC-32 of its uncompressed data. Above them sit two check words: "
        "one in the container record of Chapter 2, covering the member region, and one in the "
        "file header, covering the payload. Both are verified before anything is unpacked.")
    m.body(
        "Neither check word is a CRC, and neither is a plain sum. Both are the two's-complement "
        "negation of a 32-bit running byte sum, so that the region and its stored word added "
        "together come to zero. That is what %s tests for: it accumulates both and compares the "
        "total against zero rather than recomputing a sum and comparing values. The routine %s "
        "does compute the plain sum; the negation happens where the result is stored and checked."
        % (mono("crc_lib_verify_check_number"), mono("crc_lib_get_check_sum")))
    m.h2("The Container Check Word")
    m.body("The container record's field at $00 covers the member region as decoded:")
    code(m, "checksum = (-sum(payload[0x34 : 0x34+length])) & 0xFFFFFFFF")
    m.table("Table 5-3. Container Check Word, Measured",
            ["Release", "Byte sum", "Stored word"],
            [["SDG2000X P39R7", "$3C0C0D5D", "$C3F3F2A3"],
             ["SDG2000X P17R5", "$6570682E", "$9A8F97D2"],
             ["SPD3303X-E", "$0542645A", "$FABD9BA6"]],
            col_widths=[180, 135, 140])
    m.body(
        "Each pair sums to exactly 2<super>32</super>. Because this word is computed over the "
        "member region <i>after</i> decoding, it also detects a decode that skipped the cipher "
        "stage of Chapter 4: on P17R5 an undecrypted decode sums to $9A85B8BB against the "
        "$9A8F97D2 stored. It is the single best test that a decode is correct.")
    m.h2("The File Check Word")
    m.body(
        "The header's field at $00 covers the <i>raw</i> payload -- still encrypted and "
        "still obfuscated, exactly as the bytes sit on disk -- plus the decrypted header "
        "from offset 4, so that the field excludes itself:")
    code(m, "crc = (-(sum(file[112:]) + sum(decrypted_header[4:112]))) & 0xFFFFFFFF")
    m.table("Table 5-4. File Check Word, Measured",
            ["Release", "Stored word", "Recomputed"],
            [["SDG2000X P39R7", "$CC677E5E", "$CC677E5E"],
             ["SDG2000X P17R5", "$9EB260FA", "$9EB260FA"],
             ["SPD3303X-E", "$FD82E704", "$FD82E704"]],
            col_widths=[180, 135, 140])
    m.body(
        "Because this word covers the payload before decryption, it verifies whether or not a "
        "decoder ran the cipher stage. Use the container check word, not this one, to test a "
        "decode.")
    m.caution(
        "A .ADS rebuilt with new members must have both words recomputed. A repackager that "
        "writes a plain un-negated sum, or that copies a reference file's 112-byte header "
        "verbatim, produces a file whose integrity words are wrong and which the instrument's "
        "bootloader will reject.")

    m.h1("Payloads That Are Not Archives")
    m.body(
        "The member region is a ZIP archive on the SDG2000X, but that is a property of the model "
        "rather than of the container. The SPD3000X and SPD3303X power supplies use everything "
        "described in Chapters 2 to 4 unchanged -- the same header, key, regions and "
        "obfuscation, and the same 52-byte record -- and then hold a raw ARM firmware image "
        "in place of the archive, with no local file records and no central directory.")
    m.body(
        "The record's type code is 7 in both families, so it does not discriminate. A decoder "
        "must sniff the member region instead: %s at payload offset $34 selects the archive path, "
        "and anything else is an opaque image to be written out as-is."
        % mono("50 4B 03 04"))

    # ------------------------------------------------------------ chapter 6
    m.chapter(6, "Reference Decoder", footer_title="Reference Decoder")

    m.h1("The Decode Pipeline")
    m.body("To recover the members from a .ADS file, in order:")
    m.steps([
        "Take the payload as the file from offset 112 to the end.",
        "Decrypt payload region $00000 for $2800 bytes, and region $2E777 for $1400 bytes, each "
        "with the non-standard two-key triple-DES of Chapter 4 in ECB decrypt mode. A stock DES "
        "library will not do; the three inner-loop deviations must be reproduced.",
        "Reverse the whole payload.",
        "Complement (XOR $FF) every byte from offset %s to the end." % mono("L - L//2"),
        "Complement every byte at a triangular offset %s for n = 1, 2, ... below L."
        % mono("n(n+1)/2"),
        "Verify the two check words of Chapter 5. The container word is the decisive test that "
        "steps 2 to 5 were done correctly.",
        "From offset $34, open the payload as an ordinary ZIP archive and inflate each member "
        "(recursing into the two nested ZIP packages)."])

    m.h1("Python Implementation")
    m.body(
        "The following decoder is complete and dependency-free: it uses only the standard "
        "library, and carries the non-standard cipher itself because no stock library implements "
        "it. The three deviations of Chapter 4 are marked. It reproduces the results in Chapter "
        "7. (Standard DES tables are elided here for space; the shipped %s carries them in full.)"
        % mono("ads_decode_full.py"))
    code(m, """import struct, io, zipfile, zlib
IP,FP,E,P,PC1,PC2,SHIFT,SBOX = _standard_des_tables()   # see ads_decode_full.py
KEY = bytes.fromhex('630321010f0100071710184e5b693706')
K1, K2 = KEY[:8], KEY[8:16]
REGIONS = [(0x0, 0x2800), (0x2e777, 0x1400)]

def perm(b, t): return [b[i-1] for i in t]
def b2b(bs):                                 # (1) bytes->bits, LSB-first
    return [(by >> i) & 1 for by in bs for i in range(8)]
def b2s(bits):                               # (1) bits->bytes, LSB-first
    return bytes(sum(bit << j for j, bit in enumerate(bits[i:i+8]))
                 for i in range(0, len(bits), 8))
def subkeys(k):
    k = perm(b2b(k), PC1); C, D = k[:28], k[28:]; ks = []
    for s in SHIFT:
        C = C[s:]+C[:s]; D = D[s:]+D[:s]; ks.append(perm(C+D, PC2))
    return ks
def sbox(x):                                 # (2) S-box output, LSB-first
    o = []
    for i in range(8):
        b = x[i*6:i*6+6]; r = (b[0]<<1)|b[5]
        c = (b[1]<<3)|(b[2]<<2)|(b[3]<<1)|b[4]; v = SBOX[i][r*16+c]
        o += [v&1, (v>>1)&1, (v>>2)&1, (v>>3)&1]
    return perm(o, P)
def enc(b8, ks):                             # active half = R
    x = perm(b2b(b8), IP); L, R = x[:32], x[32:]
    for k in ks:
        L, R = R, [a^b for a,b in zip(L, sbox([a^b for a,b in zip(perm(R,E),k)]))]
    return b2s(perm(L+R, FP))                # (3) FP over L||R, no closing swap
def dec(b8, ks):                             # (3) mirrored round, active half = L
    x = perm(b2b(b8), IP); L, R = x[:32], x[32:]
    for k in reversed(ks):
        L, R = [a^b for a,b in zip(sbox([a^b for a,b in zip(perm(L,E),k)]), R)], L
    return b2s(perm(L+R, FP))""")
    code(m, """def des3(d):                                 # 2-key EDE decrypt: D(K1,E(K2,D(K1,x)))
    a, b = subkeys(K1), subkeys(K2)
    return b''.join(dec(enc(dec(d[i:i+8], a), b), a)
                    for i in range(0, len(d)//8*8, 8))
def decode(ads):
    p = bytearray(ads[112:])                 # payload = file[112:]
    for off, ln in REGIONS:                  # decrypt the two regions in place
        n = ln // 8 * 8; p[off:off+n] = des3(bytes(p[off:off+n]))
    b = bytearray(p)[::-1]; L = len(b); H = L // 2
    for i in range(L-H, L): b[i] ^= 0xFF     # complement second half
    n = 1
    while n*(n+1)//2 < L:                    # complement triangular offsets
        b[n*(n+1)//2] ^= 0xFF; n += 1
    return bytes(b)
def check_word(data, extra=0):               # Chapter 5: NEGATED byte sum
    return (-(sum(data) + extra)) & 0xffffffff

ads = open('SDG2000X_P39R7.ADS','rb').read()
st  = decode(ads)
chk, length = struct.unpack_from('<II', st, 0)
assert check_word(st[0x34:0x34+length]) == chk          # the decode is correct
zf = zipfile.ZipFile(io.BytesIO(st[st.find(b'PK\\x03\\x04'):]))  # a real ZIP""")

    # ------------------------------------------------------------ chapter 7
    m.chapter(7, "Recovery and Verification", footer_title="Recovery and Verification")

    m.h1("How the Format Was Recovered")
    m.body(
        "The container transforms were recovered first, from the file alone, by recognising the "
        "reversal and fitting the two masks so that the first member inflated and its CRC "
        "verified. That gave the Zynq package in full and left the AM3359 package failing "
        "partway through, which is what led to the cipher.")
    m.body(
        "The cipher was then read from the binary rather than guessed. The update routines were "
        "located through the dynamic symbol table, %s and %s and %s read in turn, and the key and "
        "regions taken from the constants those routines pass. The DES tables in %s matched the "
        "standard tables, which at first suggested a standard cipher -- but a standard-DES "
        "decrypt of the regions returned noise. Reading the round and block routines instruction "
        "by instruction exposed the three deviations of Chapter 4: LSB-first bit ordering, an "
        "LSB-first S-box output, and a non-standard final permutation with a mirrored decrypt. A "
        "dependency-free implementation of exactly those steps decrypts the header and both "
        "regions, and agrees byte-for-byte with the community's independently derived %s. The "
        "obfuscation was likewise confirmed by reading %s instruction by instruction rather than "
        "by fitting."
        % (mono("dev_update_system"), mono("dev_upgrade_detail_acitve"), mono("dev_decode_data"),
           mono("Des_Go"), mono("pyDesSiglent.py"), mono("dev_deconfuse_buff")))

    m.h1("Verification Results")
    m.body(
        "The decoder of Chapter 6 was run against two releases, the current P39R7 and the "
        "earliest available P17R5. Every member of both, at every level of nesting, inflates and "
        "verifies its stored CRC-32 exactly; the decrypted header's length field matches the "
        "decoded payload length in each; and both check words of Chapter 5 verify.")
    m.table("Table 7-1. Decode Results",
            ["Check", "P39R7", "P17R5"],
            [["Header length field = decoded length", "yes ($26A5DD7)", "yes ($C547F5)"],
             ["File check word verifies", "yes ($CC677E5E)", "yes ($9EB260FA)"],
             ["Container check word verifies", "yes ($C3F3F2A3)", "yes ($9A8F97D2)"],
             ["Container opens as a valid ZIP", "yes, 3 members", "yes, flat"],
             ["zynq_packet.zip (420 entries)", "all CRC-exact", "n/a"],
             ["335x_packet.zip (299 entries)", "all CRC-exact", "n/a"],
             ["sdg2000.app (12.9 MB ELF)", "bit-exact", "n/a"],
             ["Total files, bad CRCs", "679, 0", "272, 0"]],
            col_widths=[235, 110, 110])
    m.body(
        "Both packages, and the AM3359 application that earlier stopped short, are now recovered "
        "bit-for-bit and verified against their own checksums. The container opens directly in "
        "any ZIP tool once the payload is decoded. There is no residual.")

    m.h1("The Former AM3359 Residual")
    m.body(
        "An earlier revision of this document reported that the AM3359 application recovered to "
        "within 733 bytes of its stated size and no further, and attributed the shortfall to a "
        "structural alignment inconsistency in Siglent's packaging. That conclusion was wrong, "
        "and is corrected here.")
    m.body(
        "The shortfall was an artifact of the cipher, not of the format. The earlier decoder used "
        "a stock triple-DES library, on the reasonable but mistaken assumption that standard DES "
        "tables meant a standard cipher. Because the two encrypted regions land on the tail of "
        "the container -- the end of %s, the whole of %s, and the central directory and EOCD "
        "-- a wrong cipher corrupts exactly that tail. The visible symptom was a compressed "
        "stream that ended early and a container with no readable directory; the 733-byte figure "
        "was simply how far into the last member the corruption happened to begin."
        % (mono("335x_packet.zip"), mono("update.sh")))
    m.body(
        "With the non-standard cipher of Chapter 4 the same regions decrypt correctly, the tail "
        "of %s completes, %s and the central directory reappear, and %s inflates to its full "
        "12,896,400 bytes with a matching CRC-32. The section-header table that was thought lost "
        "is present. The same holds in P17R5, whose corresponding member also now verifies. "
        "Nothing about the format is undecoded."
        % (mono("335x_packet.zip"), mono("update.sh"), mono("sdg2000.app")))
    m.note(
        "The lesson worth recording: standard permutation and S-box tables do not imply a "
        "standard cipher. The three inner-loop deviations of Chapter 4 are invisible in the "
        "tables and are only found by reading the round logic. This is the trap that gave the "
        "format a reputation for being only partly recoverable; it is fully recoverable.")

    m.h1("Corrections in Revision 1.2")
    m.body(
        "Revision 1.1 described both integrity words as plain 32-bit sums, on a reading of %s "
        "alone. Measured against every release available they are the negation of that sum. The "
        "values it printed were right; a decoder following its description reproduced none of "
        "them. The negation happens at the store-and-verify step, in %s."
        % (mono("crc_lib_get_check_sum"), mono("crc_lib_verify_check_number")))
    m.caution(
        "Any tool built against Revision 1.1 that <i>writes</i> a .ADS wrote both words wrongly "
        "and produced files an instrument would reject. Readers are unaffected: nothing about "
        "the decode path has changed.")
    m.body("The corrections carried into this revision are:")
    m.bullets([
        "Chapter 5, Integrity Checks: both check words are negated byte sums, with the formula "
        "and the measured values for each (Tables 5-3 and 5-4).",
        "Chapter 2: the header's $00 field is a check word over the raw payload, not a CRC of "
        "the file, and the record's word is verified by %s. Chapters 8 and 9 follow."
        % mono("crc_lib_verify_check_number"),
        "Chapter 5, Payloads That Are Not Archives: the member region is a ZIP on the SDG2000X "
        "but a raw image on the SPD3000X family, and the type code does not distinguish them.",
        "Chapter 6: the pipeline now verifies the container check word, the decisive test that "
        "the cipher and obfuscation stages were done correctly.",
    ])

    # ------------------------------------------------------------ chapter 8
    m.chapter(8, "Field Reference", footer_title="Field Reference")

    m.h1("File and Payload")
    m.deflist([
        ("File header",
         "Bytes $0000 to $006F, 112 bytes. Encrypted (Chapter 4), not obfuscated. Decrypts to: "
         "file check word (u32 $00), decoded length (u32 $04), product id (u32 $0C), vendor tag "
         "SIGLENT ($26), USB host-controller tag ISP1763 ($3A). Consumed by %s for the "
         "pre-flight check; not part of the container." % mono("dev_update_system")),
        ("Payload",
         "Bytes $0070 to end. All transforms operate here. Length on P39R7 is 40,525,271 "
         "($26A5DD7)."),
    ])

    m.h1("Container Record (payload offset $00)")
    m.deflist([
        ("$00 checksum (u32)",
         "Negated 32-bit sum of the member-region bytes (Chapter 5). P39R7: $C3F3F2A3."),
        ("$04 length (u32)",
         "Member-region length, payload minus 52. P39R7: $026A5DA3 = 40,525,219."),
        ("$08 type (u8)",
         "Type code. P39R7: 7. Does not distinguish an archive payload from a raw image."),
        ("$09 to $33", "Reserved, zero."),
        ("$34 onward",
         "Member region. ZIP local file records back to back on the SDG2000X; a raw firmware "
         "image on the SPD3000X family."),
    ], term_w=118)

    m.h1("ZIP Local File Header (per member)")
    m.deflist([
        ("$00 signature", mono("50 4B 03 04") + "."),
        ("$08 method (u16)", "8 = deflate."),
        ("$0E crc-32 (u32)", "CRC of the uncompressed member."),
        ("$12 comp size (u32)", "Compressed length; distance to the next member."),
        ("$16 uncomp size (u32)", "Uncompressed length."),
        ("$1A name len / $1C extra len (u16)", "Header extends by these before the data."),
    ], term_w=145)

    # ------------------------------------------------------------ chapter 9
    m.chapter(9, "Constants", footer_title="Constants")

    m.h1("Cipher")
    m.deflist([
        ("Algorithm",
         "Non-standard two-key triple-DES, EDE, ECB, decrypt direction. Standard DES tables, "
         "three inner-loop deviations (Chapter 4): LSB-first byte/bit conversion, LSB-first "
         "S-box output, and a final permutation over L||R with a mirrored decrypt. A stock "
         "DES/3DES library will not decrypt these regions."),
        ("Key (16 bytes)", mono("63 03 21 01 0F 01 00 07 17 10 18 4E 5B 69 37 06")),
        ("As 24-byte EDE", mono("K1 || K2 || K1")),
        ("Region 1", "payload $00000, length $2800 (10,240 bytes)."),
        ("Region 2", "payload $2E777, length $1400 (5,120 bytes)."),
        ("Key constant", "application binary data segment $008A87AC."),
        ("DES engine", "%s at $002C5820; standard IP table at $00631374." % mono("Des_Go")),
        ("Cross-check",
         "agrees byte-for-byte with the community %s (EEVblog thread)." % mono("pyDesSiglent.py")),
    ])

    m.h1("Obfuscation")
    m.deflist([
        ("Step 1", "Full byte reversal of the payload."),
        ("Step 2", "Complement $FF from offset %s to end." % mono("L - L//2")),
        ("Step 3", "Complement $FF at %s, n &gt;= 1, below L." % mono("n(n+1)/2")),
    ])

    m.h1("Check Words")
    m.deflist([
        ("Container record $00",
         mono("(-sum(payload[0x34 : 0x34+length])) & 0xFFFFFFFF") +
         ". P39R7: $C3F3F2A3."),
        ("File header $00",
         mono("(-(sum(file[112:]) + sum(header[4:112]))) & 0xFFFFFFFF") +
         ", over the raw payload and the decrypted header, the field excluding itself. "
         "P39R7: $CC677E5E."),
        ("Property", "Region plus stored word sums to zero in 32 bits."),
    ], term_w=118)

    m.h1("Firmware Routines")
    m.deflist([
        ("dev_update_system", "Drives the update; reads and checks the header."),
        ("dev_decode_header_data", "Decrypts the 112-byte header."),
        ("dev_upgrade_detail_acitve",
         "Reads the payload, verifies the check word, decrypts and de-obfuscates."),
        ("dev_decode_data", "Decrypts the two cipher regions, then calls the de-obfuscator."),
        ("dev_deconfuse_buff", "The obfuscation: reverse, complement, triangular."),
        ("Des_Go / $2C59D4", "The DES engine and its key schedule."),
        ("crc_lib_get_check_sum", "Computes the plain byte sum behind a check word."),
        ("crc_lib_verify_check_number",
         "Verifies a check word: sums the region and the stored word and tests for zero."),
    ], term_w=145)

    m.build()
    print("wrote SDG2000X_ADS_Format_Specification.pdf")


if __name__ == "__main__":
    main()
