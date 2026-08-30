#!/usr/bin/env python3
"""Complete, dependency-free SDG2000X .ADS decoder + verifier (reference).

Pipeline (from awg.app: dev_update_system, dev_decode_data, dev_deconfuse_buff):

  1. The file's first 112 bytes are a header, encrypted with the same cipher as
     the payload regions (below). Decrypted, it carries a CRC, the decoded
     payload length, a product id, and the ASCII tags "SIGLENT" / "ISP1763".
     The payload is file[112:].
  2. dev_decode_data decrypts two payload regions in place:
        [0x0 : 0x2800]  and  [0x2e777 : 0x2e777+0x1400]
     with Siglent's NON-STANDARD 2-key 3DES (ECB, EDE, key = K1||K2||K1),
     deskey = 63 03 21 01 0f 01 00 07 17 10 18 4e 5b 69 37 06
     (awg.app .data @ 0x8a87ac). The tables are standard DES, but three
     inner-loop details deviate from textbook DES, so a stock 3DES library
     CANNOT decrypt these regions:
       a. bytes<->bits is LSB-first (textbook DES is MSB-first);
       b. each S-box's 4-bit output is stored LSB-first;
       c. the final permutation is over L||R with no closing swap, and the
          decrypt path is a mirrored round (active half L) -- a true inverse of
          encrypt, not the usual "same round, reversed subkeys".
     This matches analogNewbie's pyDesSiglent.py from the EEVblog thread
     (https://www.eevblog.com/forum/testgear/siglent-ads-firmware-file-format/).
  3. dev_deconfuse_buff(payload, len):
        a. full byte reversal of payload[:len]
        b. complement (XOR 0xFF) the second half [len-len//2 : len)
        c. complement every triangular offset n(n+1)/2 for n = 1,2,... < len
  4. The deconfused payload is a 0x34-byte container header followed by a
     genuine ZIP archive -- local file records, a central directory, and an
     EOCD. Newer files (P39R7) wrap 3 members (zynq_packet.zip, 335x_packet.zip,
     update.sh); older files (P17R5) are a flat archive of members.

With the correct cipher every inner file recovers bit-exact and CRC-valid,
including the AM335x sdg2000.app ELF. (The old "~733 bytes short" residual was
the wrong DES bit-ordering, now fixed.)
"""
import sys, struct, io, zipfile, zlib

# --- Siglent non-standard DES tables (standard DES tables) ------------------
_IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E=[32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFT=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_SBOX=[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]

def _perm(b,t): return [b[i-1] for i in t]
def _b2b(bs):                       # LSB-first
    o=[]
    for by in bs:
        for i in range(8): o.append((by>>i)&1)
    return o
def _b2s(bits):                     # LSB-first
    o=bytearray()
    for i in range(0,len(bits),8):
        v=0
        for j,bit in enumerate(bits[i:i+8]): v|=bit<<j
        o.append(v)
    return bytes(o)
def _subkeys(k8):
    k=_perm(_b2b(k8),_PC1); C,D=k[:28],k[28:]; ks=[]
    for s in _SHIFT:
        C=C[s:]+C[:s]; D=D[s:]+D[:s]; ks.append(_perm(C+D,_PC2))
    return ks
def _sbox(x48):
    o=[]
    for i in range(8):
        b=x48[i*6:i*6+6]; row=(b[0]<<1)|b[5]; col=(b[1]<<3)|(b[2]<<2)|(b[3]<<1)|b[4]
        v=_SBOX[i][row*16+col]; o+=[v&1,(v>>1)&1,(v>>2)&1,(v>>3)&1]   # LSB-first
    return _perm(o,_P)
def _enc(b8,ks):
    bits=_perm(_b2b(b8),_IP); L,R=bits[:32],bits[32:]
    for k in ks: L,R=R,[a^b for a,b in zip(L,_sbox([a^b for a,b in zip(_perm(R,_E),k)]))]
    return _b2s(_perm(L+R,_FP))
def _dec(b8,ks):                    # mirrored round, active half = L
    bits=_perm(_b2b(b8),_IP); L,R=bits[:32],bits[32:]
    for k in reversed(ks): L,R=[a^b for a,b in zip(_sbox([a^b for a,b in zip(_perm(L,_E),k)]),R)],L
    return _b2s(_perm(L+R,_FP))
DESKEY=bytes.fromhex("630321010f0100071710184e5b693706")
K1,K2=DESKEY[:8],DESKEY[8:16]
REGIONS=[(0x0,0x2800),(0x2e777,0x1400)]
HEADER=112

def _des3(data): return b"".join(_dec(_enc(_dec(data[i:i+8],_subkeys(K1)),_subkeys(K2)),_subkeys(K1)) for i in range(0,len(data)//8*8,8))

def decode(ads: bytes) -> bytes:
    payload=bytearray(ads[HEADER:])
    for off,ln in REGIONS:
        n=ln//8*8
        payload[off:off+n]=_des3(bytes(payload[off:off+n]))
    b=bytearray(payload)[::-1]
    L=len(b); H=L//2
    for i in range(L-H,L): b[i]^=0xFF
    n=1
    while True:
        t=n*(n+1)//2
        if t>=L: break
        b[t]^=0xFF; n+=1
    return bytes(b)

def decode_header(ads: bytes):
    h=_des3(ads[:HEADER])
    return {"crc":struct.unpack('<I',h[0:4])[0],
            "size":struct.unpack('<I',h[4:8])[0],
            "product_id":struct.unpack('<I',h[0xc:0x10])[0],
            "vendor":h[0x26:0x2d].decode('latin1'),
            "usb_host":h[0x3a:0x41].decode('latin1')}

def _walk(data,name,depth,acc):
    try: z=zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        print("  "*depth+"%s: not a zip (%s)"%(name,e)); return
    files=bad=0
    for zi in z.infolist():
        if zi.filename.endswith('/'): continue
        files+=1
        try:
            b=z.read(zi.filename); ok=(zlib.crc32(b)&0xffffffff)==zi.CRC
        except Exception: ok=False; b=b''
        if not ok: bad+=1; print("  "*depth+"BAD CRC: %s/%s"%(name,zi.filename))
        if zi.filename.endswith('.zip') and ok: _walk(b,zi.filename,depth+1,acc)
    acc[0]+=files; acc[1]+=bad
    print("  "*depth+"%s: %d files, %d bad CRC"%(name,files,bad))

if __name__=="__main__":
    ads=open(sys.argv[1],"rb").read()
    hdr=decode_header(ads)
    st=decode(ads)
    print("header: crc=%08x size=0x%x product_id=%d vendor=%r usb=%r"%(
        hdr["crc"],hdr["size"],hdr["product_id"],hdr["vendor"],hdr["usb_host"]))
    print("decoded length: 0x%x (header size field %s)"%(
        len(st),"matches" if hdr["size"]==len(st) else "MISMATCH"))
    z0=st.find(b"PK\x03\x04")
    acc=[0,0]; _walk(st[z0:],"container",1,acc)
    print("TOTAL: %d files, %d bad CRC"%(acc[0],acc[1]))
