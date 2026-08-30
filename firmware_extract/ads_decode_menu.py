#!/usr/bin/env python3
"""Menu-driven SDG2000X .ADS firmware decoder.

An interactive front-end over the firmware-exact decode of ads_decode_full.py:
open a .ADS update file, inspect it, verify it, extract its contents to a .zip
or a folder, and repackage a folder or .zip back into a .ADS.

Two container layouts exist and both are handled. Newer files (e.g. P39R7)
wrap everything in two nested zips, extracted under their own top-level folders
(zynq_packet/..., 335x_packet/...). Older files (e.g. P17R5) are a flat archive
of file members, extracted with their own paths. Repackage reproduces whichever
layout the source uses. The repackaged file re-decodes with this tool exactly,
but is NOT verified for flashing to an instrument -- see option 6.

No external dependencies -- pure standard-library Python 3. Just run it:

    python ads_decode_menu.py            (or double-click it on Windows)
    python ads_decode_menu.py file.ADS   (open a file straight away)

The decode pipeline (from awg.app: dev_decode_data, dev_deconfuse_buff):
  1. payload = file[112:]  (the first 112 bytes are the encrypted header).
  2. 3DES-decrypt two payload regions in place: [0x0:0x2800] and
     [0x2e777:0x2e777+0x1400]  (Siglent's non-standard LSB-first 2-key 3DES,
     ECB, EDE, key = K1||K2||K1 -- see the cipher note below).
  3. de-obfuscate: reverse the payload, complement its second half, then
     complement every triangular offset n(n+1)/2 for n = 1, 2, ... < len.
  4. from offset 0x34, walk back-to-back ZIP local records (no central
     directory): zynq_packet.zip (Zynq-7000) and 335x_packet.zip (AM335x).

All inner files recover bit-exact and CRC-valid, including the AM335x
sdg2000.app. (Earlier tool versions left it ~733 bytes short at its ELF section
table; that was the wrong DES bit-ordering corrupting the encrypted regions --
now fixed -- not a packaging limitation.)
"""
import os
import sys
import io
import struct
import zlib
import zipfile

VERSION = "1.4 (2026-08-29)"   # corrected non-standard LSB-first 3DES; both P39R7 (nested) and P17R5 (flat) layouts


def _pause(msg=None):
    """Print an optional message and wait, so a double-clicked window on
    Windows never closes before the user can read what happened."""
    if msg:
        print(msg)
    try:
        input("\nPress Enter to close...")
    except (EOFError, KeyboardInterrupt):
        pass


# --------------------------------------------------------------------------
# Siglent's non-standard 2-key 3DES-ECB, pure Python. Standard DES tables, but
# three inner-loop deviations from textbook DES (see below) -- a stock 3DES
# library will NOT decrypt an .ADS region. Verified byte-identical to the
# firmware cipher (awg.app Des_Go / des_block) and to analogNewbie's
# pyDesSiglent.py from the EEVblog thread. Key = awg.app .data const @ 0x8a87ac.
#   1. bytes<->bits is LSB-first (textbook DES is MSB-first);
#   2. each S-box's 4-bit output is stored LSB-first;
#   3. final permutation is over L||R with no closing swap, and decrypt is a
#      mirrored round (active half L) -- a true inverse of encrypt, not the
#      usual "same round, reversed subkeys".
# --------------------------------------------------------------------------
_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
       64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
       61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
       37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
       34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
      16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
      2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
        60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
        29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
        41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_SBOX = [
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]


def _perm(bits, tbl):
    return [bits[i - 1] for i in tbl]


def _bytes2bits(b):
    # LSB-first (Siglent deviation): bit 0 of each byte is emitted first.
    out = []
    for by in b:
        for i in range(8):
            out.append((by >> i) & 1)
    return out


def _bits2bytes(bits):
    # LSB-first (Siglent deviation).
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for j, bit in enumerate(bits[i:i + 8]):
            v |= bit << j
        out.append(v)
    return bytes(out)


def _subkeys(key8):
    k = _perm(_bytes2bits(key8), _PC1)
    C, D = k[:28], k[28:]
    ks = []
    for s in _SHIFT:
        C = C[s:] + C[:s]
        D = D[s:] + D[:s]
        ks.append(_perm(C + D, _PC2))
    return ks


def _feistel(R, k):
    x = [a ^ b for a, b in zip(_perm(R, _E), k)]
    out = []
    for i in range(8):
        blk = x[i * 6:i * 6 + 6]
        row = (blk[0] << 1) | blk[5]
        col = (blk[1] << 3) | (blk[2] << 2) | (blk[3] << 1) | blk[4]
        v = _SBOX[i][row * 16 + col]
        # S-box 4-bit output written LSB-first (Siglent deviation).
        out += [v & 1, (v >> 1) & 1, (v >> 2) & 1, (v >> 3) & 1]
    return _perm(out, _P)


def _des_enc(b8, key8):
    # Encrypt round: active half = R; final FP over L||R with no closing swap.
    ks = _subkeys(key8)
    bits = _perm(_bytes2bits(b8), _IP)
    L, R = bits[:32], bits[32:]
    for k in ks:
        L, R = R, [a ^ b for a, b in zip(L, _feistel(R, k))]
    return _bits2bytes(_perm(L + R, _FP))


def _des_dec(b8, key8):
    # Mirrored decrypt round: active half = L (true inverse of _des_enc; not the
    # textbook "same round with reversed subkeys").
    ks = list(reversed(_subkeys(key8)))
    bits = _perm(_bytes2bits(b8), _IP)
    L, R = bits[:32], bits[32:]
    for k in ks:
        L, R = [a ^ b for a, b in zip(_feistel(L, k), R)], L
    return _bits2bytes(_perm(L + R, _FP))


def des3_ecb_decrypt(data, k1, k2):
    """2-key 3DES-ECB decrypt (EDE, key = K1||K2||K1)."""
    out = bytearray()
    for i in range(0, len(data) // 8 * 8, 8):
        blk = data[i:i + 8]
        out += _des_dec(_des_enc(_des_dec(blk, k1), k2), k1)
    return bytes(out)


def des3_ecb_encrypt(data, k1, k2):
    """2-key 3DES-ECB encrypt (EDE, key = K1||K2||K1). Inverse of decrypt."""
    out = bytearray()
    for i in range(0, len(data) // 8 * 8, 8):
        blk = data[i:i + 8]
        out += _des_enc(_des_dec(_des_enc(blk, k1), k2), k1)
    return bytes(out)


# --------------------------------------------------------------------------
# Decode core -- identical result to ads_decode_full.py.
# --------------------------------------------------------------------------
DESKEY = bytes.fromhex("630321010f0100071710184e5b693706")
K1, K2 = DESKEY[:8], DESKEY[8:16]
REGIONS = [(0x0, 0x2800), (0x2e777, 0x1400)]
HEADER = 112


def decode(ads: bytes) -> bytes:
    """Return the de-obfuscated payload (container header + ZIP records)."""
    payload = bytearray(ads[HEADER:])
    for off, ln in REGIONS:
        n = ln // 8 * 8
        payload[off:off + n] = des3_ecb_decrypt(bytes(payload[off:off + n]), K1, K2)
    b = bytearray(payload)[::-1]                  # full reverse
    L = len(b); H = L // 2
    for i in range(L - H, L):                     # complement second half
        b[i] ^= 0xFF
    n = 1
    while True:                                   # triangular complement, n>=1
        t = n * (n + 1) // 2
        if t >= L:
            break
        b[t] ^= 0xFF
        n += 1
    return bytes(b)


def confuse(stream: bytes) -> bytes:
    """The exact inverse of decode's de-obfuscation and cipher: turn a decoded
    stream back into a file payload. Apply the triangular complement, then the
    second-half complement, then reverse; finally 3DES-ENCRYPT the two regions."""
    b = bytearray(stream)
    L = len(b); H = L // 2
    n = 1
    while True:
        t = n * (n + 1) // 2
        if t >= L:
            break
        b[t] ^= 0xFF
        n += 1
    for i in range(L - H, L):
        b[i] ^= 0xFF
    b = b[::-1]
    for off, ln in REGIONS:
        nn = ln // 8 * 8
        b[off:off + nn] = des3_ecb_encrypt(bytes(b[off:off + nn]), K1, K2)
    return bytes(b)


def build_member(name: str, data: bytes) -> bytes:
    """One container ZIP local record (deflate) wrapping `data`."""
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    defl = comp.compress(data) + comp.flush()
    nb = name.encode("utf-8")
    hdr = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0,
                      zlib.crc32(data) & 0xffffffff, len(defl), len(data), len(nb), 0)
    return hdr + nb + defl


def build_dir_member(name: str) -> bytes:
    """One container ZIP local record for a directory entry (stored, empty)."""
    if not name.endswith("/"):
        name += "/"
    nb = name.encode("utf-8")
    return struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0,
                       0, 0, 0, len(nb), 0) + nb


def assemble_stream(records) -> bytes:
    """records: list of member-record bytes. Return the decoded-form stream:
    0x34-byte container header + back-to-back member records."""
    body = b"".join(records)
    checksum = sum(body) & 0xffffffff
    header = struct.pack("<III", checksum, len(body), 7) + b"\x00" * (0x34 - 12)
    return header + body


def build_package_zip(entries) -> bytes:
    """entries: list of (arcname, data) with data=None for a directory entry.
    Return standard .zip bytes (DEFLATE, with a central directory)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arc, data in entries:
            if data is None:
                z.writestr(arc if arc.endswith("/") else arc + "/", b"")
            else:
                z.writestr(arc, data)
    return buf.getvalue()


def walk_zip(buf: bytes, start: int):
    """Yield (name, method, crc, csize, usize, data) for each ZIP local record
    from `start`, stopping at the first byte that is not a local header. Works
    without a central directory and tolerates a truncated tail."""
    p = start
    while p + 30 <= len(buf) and buf[p:p + 4] == b"PK\x03\x04":
        (sig, ver, flg, meth, tm, dt, crc,
         csize, usize, fnlen, exlen) = struct.unpack_from("<IHHHHHIIIHH", buf, p)
        name = buf[p + 30:p + 30 + fnlen].decode("utf-8", "replace")
        ds = p + 30 + fnlen + exlen
        yield name, meth, crc, csize, usize, buf[ds:ds + csize]
        p = ds + csize


def inflate(meth: int, data: bytes):
    """Return (out_bytes, complete_bool). Stored -> as is; deflate -> inflate,
    tolerating a truncated stream by returning what decompressed."""
    if meth == 0:
        return data, True
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(data) + d.flush()
        return out, True
    except zlib.error:
        out = bytearray()
        e = zlib.decompressobj(-15)
        i = 0
        try:
            while i < len(data):
                out += e.decompress(data[i:i + 65536])
                i += 65536
        except zlib.error:
            pass
        return bytes(out), False


# --------------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.path = None
        self.raw = None        # original .ADS bytes
        self.stream = None     # decoded payload
        self.members = []      # [(name, meth, crc, csize, usize, data), ...]

    @property
    def loaded(self):
        return self.stream is not None

    def open(self, path):
        path = path.strip().strip('"').strip("'")
        path = os.path.expanduser(path)
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) <= HEADER:
            raise ValueError("file is too small to be a .ADS container")
        print("  Decoding (this takes a moment)...")
        stream = decode(raw)
        members = list(walk_zip(stream, 0x34))
        if not members:
            raise ValueError("no archive members found -- not a SDG2000X .ADS, "
                             "or an unsupported variant")
        self.path, self.raw, self.stream, self.members = path, raw, stream, members


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def human(n):
    return "{:,}".format(n)


def default_outdir(sess):
    return os.path.dirname(os.path.abspath(sess.path)) or "."


def pkg_dirname(member_name):
    """zynq_packet.zip -> zynq_packet  (the folder that namespaces a package)."""
    return member_name[:-4] if member_name.lower().endswith(".zip") else member_name


PACKAGE_NAMES = ("zynq_packet", "335x_packet")


def iter_files(sess):
    """Yield (arcname, method, crc, csize, usize, data) for every extractable
    entry in the .ADS, handling both container layouts. A member that is itself
    a .zip (a nested package, as in P39R7) is recursed into and namespaced under
    its own folder; any other member is a flat file (as in P17R5) and yielded
    with its own path."""
    for name, meth, crc, csize, usize, data in sess.members:
        content, _ = inflate(meth, data)
        if name.lower().endswith(".zip") and content[:4] == b"PK\x03\x04":
            pkgdir = pkg_dirname(name)
            for inm, im, ic, ics, ius, idata in walk_zip(content, 0):
                yield (pkgdir + "/" + inm, im, ic, ics, ius, idata)
        else:
            yield (name, meth, crc, csize, usize, data)


def read_source(path):
    """Read a repackage source (a folder or a .zip) as a flat, ordered list of
    (arcname, data) entries, data=None for a directory entry."""
    path = os.path.expanduser(path.strip().strip('"').strip("'"))
    entries = []
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs.sort()
            rel = os.path.relpath(root, path).replace("\\", "/")
            base = "" if rel == "." else rel + "/"
            for dn in sorted(dirs):
                entries.append((base + dn + "/", None))
            for fn in sorted(files):
                with open(os.path.join(root, fn), "rb") as f:
                    entries.append((base + fn, f.read()))
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist():
                nm = zi.filename.replace("\\", "/")
                entries.append((nm, None if zi.is_dir() else z.read(zi)))
    else:
        raise ValueError("input must be a folder or a .zip file")
    if not entries:
        raise ValueError("the source is empty")
    return entries


# --------------------------------------------------------------------------
# Menu actions
# --------------------------------------------------------------------------
def act_open(sess):
    path = input("Path to the .ADS file: ").strip()
    if not path:
        return
    try:
        sess.open(path)
    except FileNotFoundError:
        print("  File not found.")
        return
    except Exception as e:
        print("  Could not open: %s" % e)
        return
    print("  Loaded %s (%s bytes), %d member(s)."
          % (os.path.basename(sess.path), human(len(sess.raw)), len(sess.members)))


def act_info(sess):
    st = sess.stream
    chksum, length, ctype = struct.unpack_from("<III", st, 0)
    print()
    print("  File            : %s" % sess.path)
    print("  File size       : %s bytes" % human(len(sess.raw)))
    print("  Payload         : %s bytes (file[112:])" % human(len(sess.raw) - HEADER))
    print("  Container header:")
    print("     checksum word : 0x%08X  (32-bit byte-sum, not a CRC)" % chksum)
    print("     length word   : 0x%08X  (%s bytes)" % (length, human(length)))
    print("     type word     : 0x%08X" % ctype)
    print("  Packages        :")
    for name, meth, crc, csize, usize, data in sess.members:
        print("     %-18s compressed %s, uncompressed %s, CRC-32 0x%08X"
              % (name, human(csize), human(usize), crc))


def act_list(sess):
    print()
    print("  %d container member(s)." % len(sess.members))
    print("  %-34s %13s %13s   %s" % ("member", "uncompressed", "stored", "CRC-32"))
    print("  " + "-" * 74)
    for i, (name, meth, crc, csize, usize, data) in enumerate(sess.members):
        if i >= 40:
            print("  ... and %d more (use option 4 or 5 to extract them all)"
                  % (len(sess.members) - 40))
            break
        out, complete = inflate(meth, data)
        good = complete and (zlib.crc32(out) & 0xffffffff) == crc and len(out) == usize
        if good:
            status = "OK"
        elif complete:
            status = "CRC MISMATCH"
        else:
            status = "partial %s/%s" % (human(len(out)), human(usize))
        nm = name if len(name) <= 34 else "..." + name[-31:]
        print("  %-34s %13s %13s   %s" % (nm, human(usize), human(csize), status))
    ans = input("\nAlso count and verify every file inside? [y/N] ").strip().lower()
    if ans != "y":
        return
    ok = bad = 0
    for arc, meth, crc, cs, us, data in iter_files(sess):
        if arc.endswith("/") or (cs == 0 and us == 0):
            continue
        out, complete = inflate(meth, data)
        if complete and (zlib.crc32(out) & 0xffffffff) == crc and len(out) == us:
            ok += 1
        else:
            bad += 1
    note = "" if bad == 0 else "  (%d not bit-exact -- the known .ADS tail residual)" % bad
    print("  %d files verify%s" % (ok, note))


def act_extract_zip(sess):
    """Extract the entire .ADS into one .zip, preserving the original layout
    (nested packages under their own folder; flat members at the top)."""
    base = os.path.splitext(os.path.basename(sess.path))[0] + ".zip"
    dest = input("Save .zip as [%s]: " % base).strip() or base
    dest = os.path.expanduser(dest.strip('"').strip("'"))
    if not os.path.isabs(dest):
        dest = os.path.join(default_outdir(sess), dest)
    n = part = 0
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for arc, meth, crc, cs, us, data in iter_files(sess):
            arc = arc.replace("\\", "/")
            if arc.endswith("/") or (cs == 0 and us == 0):
                z.writestr(arc if arc.endswith("/") else arc + "/", b"")
                continue
            out, complete = inflate(meth, data)
            z.writestr(arc, out)
            n += 1
            if not complete or len(out) != us:
                part += 1
                print("     partial: %s (%s/%s bytes)" % (arc, human(len(out)), human(us)))
    print("  Wrote %s  (%d files)" % (dest, n))
    if part:
        print("  %d file(s) written truncated (the known .ADS tail residual)." % part)


def act_extract_folder(sess):
    """Extract the entire .ADS to a folder, preserving the original structure."""
    base = os.path.splitext(os.path.basename(sess.path))[0] + "_files"
    outdir = input("Output folder [%s]: " % base).strip() or base
    outdir = os.path.expanduser(outdir.strip('"').strip("'"))
    if not os.path.isabs(outdir):
        outdir = os.path.join(default_outdir(sess), outdir)
    root = os.path.normpath(outdir)
    n = part = 0
    for arc, meth, crc, cs, us, data in iter_files(sess):
        safe = arc.replace("\\", "/").lstrip("/")
        target = os.path.normpath(os.path.join(outdir, *[p for p in safe.split("/") if p]))
        if not (target == root or target.startswith(root + os.sep)):
            continue  # guard against path traversal in a member name
        if arc.endswith("/") or (cs == 0 and us == 0):
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        out, complete = inflate(meth, data)
        with open(target, "wb") as f:
            f.write(out)
        n += 1
        if not complete or len(out) != us:
            part += 1
            print("     partial: %s (%s/%s bytes)" % (safe, human(len(out)), human(us)))
    print("  Extracted %d files to %s" % (n, outdir))
    if part:
        print("  %d file(s) written truncated (the known .ADS tail residual)." % part)


def act_repackage(sess):
    """Rebuild a .ADS from a folder or .zip produced by option 4 or 5. The
    original layout is reproduced: top-level zynq_packet/ and 335x_packet/
    folders are re-wrapped as nested-zip members (P39R7 style); anything else is
    written as flat file members (P17R5 style)."""
    src = input("Folder or .zip to repackage: ").strip()
    if not src:
        return
    entries = read_source(src)

    # The 112-byte file header is copied verbatim from a reference .ADS.
    if sess.loaded:
        header = sess.raw[:112]
        print("  Using the header from the loaded file (%s)." % os.path.basename(sess.path))
    else:
        rp = input("Reference .ADS to copy the 112-byte header from: ").strip()
        rp = os.path.expanduser(rp.strip('"').strip("'"))
        with open(rp, "rb") as f:
            header = f.read(112)
        if len(header) < 112:
            print("  Reference file is too small.")
            return

    tops = set(e[0].split("/")[0] for e in entries if e[0].split("/")[0])
    records = []
    if tops and tops <= set(PACKAGE_NAMES):
        # nested-package layout (P39R7): re-wrap each package folder as a .zip
        groups = {}
        for arc, data in entries:
            parts = arc.split("/", 1)
            if len(parts) < 2 or not parts[1]:
                continue  # the package folder entry itself
            groups.setdefault(parts[0], []).append((parts[1], data))
        for d in sorted(groups, key=lambda x: {"zynq_packet": 0, "335x_packet": 1}.get(x, 9)):
            pkgbytes = build_package_zip(groups[d])
            records.append(build_member(d + ".zip", pkgbytes))
            print("  Built %-18s from %d entries (%s bytes)"
                  % (d + ".zip", len(groups[d]), human(len(pkgbytes))))
    else:
        # flat layout (P17R5): every entry is its own container member
        nf = nd = 0
        for arc, data in entries:
            if data is None:
                records.append(build_dir_member(arc)); nd += 1
            else:
                records.append(build_member(arc, data)); nf += 1
        print("  Built %d file members and %d directory members." % (nf, nd))

    out = header + confuse(assemble_stream(records))

    base = "repacked.ADS"
    dest = input("Save .ADS as [%s]: " % base).strip() or base
    dest = os.path.expanduser(dest.strip('"').strip("'"))
    if not os.path.isabs(dest):
        outdir = default_outdir(sess) if sess.loaded else os.getcwd()
        dest = os.path.join(outdir, dest)
    with open(dest, "wb") as f:
        f.write(out)
    print("  Wrote %s (%s bytes)" % (dest, human(len(out))))
    print()
    print("  This file re-decodes with this tool exactly. It is NOT verified to")
    print("  be accepted by the instrument: the 112-byte header is copied from a")
    print("  reference file and the container checksum uses the documented byte-sum,")
    print("  which may not match the firmware's own integrity check. Flashing a")
    print("  modified image can render an instrument unbootable with no recovery.")


# --------------------------------------------------------------------------
# Menu loop
# --------------------------------------------------------------------------
MENU = [
    ("Open a .ADS file", act_open, False),
    ("Show file and container info", act_info, True),
    ("List archive members (verify CRC-32)", act_list, True),
    ("Extract the whole .ADS to a .zip", act_extract_zip, True),
    ("Extract the whole .ADS to a folder", act_extract_folder, True),
    ("Repackage a folder or .zip into a .ADS", act_repackage, False),
]


def main():
    sess = Session()
    if len(sys.argv) > 1:            # allow a file path on the command line
        try:
            sess.open(sys.argv[1])
            print("Loaded %s (%d member(s))." % (os.path.basename(sess.path), len(sess.members)))
        except Exception as e:
            print("Could not open %s: %s" % (sys.argv[1], e))
    while True:
        print()
        print("=" * 60)
        print("  SDG2000X .ADS firmware decoder    v%s" % VERSION)
        print("=" * 60)
        print("  File: %s" % (os.path.basename(sess.path) if sess.loaded else "(none loaded)"))
        print("-" * 60)
        for i, (label, _fn, needs_file) in enumerate(MENU, 1):
            gate = "" if (not needs_file or sess.loaded) else "  (open a file first)"
            print("  %d. %s%s" % (i, label, gate))
        print("  0. Quit")
        print("-" * 60)
        try:
            choice = input("Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(MENU)):
            print("  Please enter a number from the menu.")
            continue
        label, fn, needs_file = MENU[int(choice) - 1]
        if needs_file and not sess.loaded:
            print("  Open a .ADS file first (option 1).")
            continue
        try:
            fn(sess)
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
        except Exception as e:
            print("  Error: %s" % e)
    print("Bye.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        import traceback
        traceback.print_exc()
        _pause("\nAn unexpected error occurred (shown above).")
