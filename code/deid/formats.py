"""Format knowledge: where identity fields live, and container readers/writers."""
from __future__ import annotations
import re, struct, zlib
from .core import is_common

# ---------------------------------------------------------------- STEP (ISO 10303-21)
def _args(s: str, pos: int, limit: int = 20000):
    """Parse a parenthesised argument list starting at s[pos]=='('.
    Returns [(start, end, top_level_arg_index)] for every quoted string."""
    out, depth, arg, i, n = [], 0, 0, pos, min(len(s), pos + limit)
    while i < n:
        c = s[i]
        if c == "'":
            j = i + 1
            while j < n:
                if s[j] == "'":
                    if j + 1 < n and s[j + 1] == "'":
                        j += 2; continue
                    break
                j += 1
            out.append((i + 1, j, arg)); i = j + 1; continue
        if c == "/" and s.startswith("/*", i):
            j = s.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1:
            arg += 1
        i += 1
    return out

_STEP_ENT = re.compile(r"(?<![A-Za-z_])(PERSON|ORGANIZATION)\s*\(")

def step_spans(s: str):
    spans = []  # (start, end, kind)
    h = s.find("FILE_NAME", 0, 200000)
    if h >= 0:
        p = s.find("(", h)
        if p >= 0:
            for a, b, k in _args(s, p):
                if k in (2, 3, 6):
                    spans.append((a, b, "person" if k != 3 else "org"))
    for m in _STEP_ENT.finditer(s):
        ent = m.group(1)
        for a, b, k in _args(s, m.end() - 1, 2000):
            if ent == "PERSON" or k in (0, 1):
                spans.append((a, b, "person" if ent == "PERSON" else "org"))
    return spans

# ---------------------------------------------------------------- IGES
def iges_spans(s: str):
    """Author (global parameter 21) and organisation (22), Hollerith strings."""
    pos, chars = [], []
    off = 0
    for line in s.splitlines(keepends=True)[:400]:
        body = line.rstrip("\r\n")
        if len(body) >= 73 and body[72] == "G":
            for i in range(72):
                chars.append(body[i]); pos.append(off + i)
        elif len(body) >= 73 and body[72] in "DP":
            break
        off += len(line)
    g = "".join(chars)
    if not g:
        return []
    pd, rd = ",", ";"
    i = 0
    m = re.match(r"1H(.)", g)
    if m:
        pd = m.group(1); i = 3
        if g[i:i + 1] == pd: i += 1
        m2 = re.match(r"1H(.)", g[i:])
        if m2: rd = m2.group(1)
        i = 0
    params, n = [], len(g)
    while i < n and len(params) < 26:
        j = i
        while j < n and g[j] == " ": j += 1
        m = re.match(r"(\d+)H", g[j:])
        if m:
            ln = int(m.group(1)); a = j + m.end(); b = a + ln
            params.append((a, min(b, n))); j = b
            while j < n and g[j] not in (pd, rd): j += 1
        else:
            params.append(None)
            while j < n and g[j] not in (pd, rd): j += 1
        if j >= n or g[j] == rd: break
        i = j + 1
    spans = []
    for idx, kind in ((20, "person"), (21, "org")):
        if idx < len(params) and params[idx]:
            a, b = params[idx]
            # split into contiguous file ranges (strings may wrap lines)
            st = a
            for k in range(a + 1, b + 1):
                if k == b or pos[k] != pos[k - 1] + 1:
                    spans.append((pos[st], pos[k - 1] + 1, kind)); st = k
    return spans

# ---------------------------------------------------------------- DXF / XML-ish
_DXF = re.compile(r"\$LASTSAVEDBY\r?\n\s*1\r?\n([^\r\n]*)")
_XML = [
    (re.compile(r"<(?:dc:creator|cp:lastModifiedBy|dc:contributor|dc:publisher|Manager|Author|LastAuthor|"
                r"meta:initial-creator|pdf:Author|xmp:Author)(?:\s[^>]*)?>([^<]{1,200})<"), "person"),
    (re.compile(r"<(?:Company)(?:\s[^>]*)?>([^<]{1,200})<"), "org"),
    (re.compile(r'<Property name="(?:CreatedBy|LastModifiedBy)"[^>]*>\s*<String value="([^"]{1,200})"'), "person"),
    (re.compile(r'<Property name="(?:Company)"[^>]*>\s*<String value="([^"]{1,200})"'), "org"),
    (re.compile(r'<metadata name="(?:Designer|Author|Copyright)"[^>]*>([^<]{1,200})<', re.I), "person"),
    (re.compile(r"<dc:(?:creator|publisher|rights|contributor)>\s*<cc:Agent>\s*<dc:title>([^<]{1,200})</dc:title>"), "person"),
]

def dxf_spans(s): return [(m.start(1), m.end(1), "person") for m in _DXF.finditer(s[:2_000_000])]

def xml_spans(s):
    out = []
    for rx, kind in _XML:
        out += [(m.start(1), m.end(1), kind) for m in rx.finditer(s)]
    return out

STEP_EXT = {".step", ".stp", ".p21", ".stpnc", ".ifc"}
IGES_EXT = {".igs", ".iges"}
XML_EXT = {".xml", ".svg", ".model", ".rels", ".x3d", ".dae", ".urdf", ".xacro", ".html", ".htm", ".rdf", ".xmp"}

def field_spans(text: str, ext: str):
    if ext in STEP_EXT or text.startswith("ISO-10303-21"):
        return step_spans(text)
    if ext in IGES_EXT:
        return iges_spans(text)
    if ext == ".dxf":
        return dxf_spans(text)
    if ext in XML_EXT or text[:200].lstrip().startswith(("<?xml", "<svg", "<!DOCTYPE")):
        return xml_spans(text)
    return []

# ---------------------------------------------------------------- SOLIDWORKS 2015+ container
# Layout (reverse engineered): 8-byte file header, then zip-like records.
#   local  : sig4 | 14 00 06 00 08 00 | stamp4 | crc32 | csize | usize | namelen4 | name (nibble-swapped) | raw deflate
#   central: sig4 00 00 | same marker | stamp | crc | csize | usize | namelen | 10 bytes | offset4 (file pos - 8) | name
#   end    : ... count2 count2 size4 offset4
# The 4-byte signatures differ per file, and decoy records are mixed in, so records are
# validated structurally (stream inflates to the declared size; directory points at a real record).
SW_MARK = bytes.fromhex("140006000800")
_SW_MARK_RX = re.compile(re.escape(SW_MARK))

def _swap(b: bytes) -> bytes:
    return bytes(((x << 4) & 0xF0) | (x >> 4) for x in b)

def is_sw(data: bytes) -> bool:
    return len(data) > 64 and data[4:8] == b"\x00\x00\x00\x04" and data.find(SW_MARK, 8, 4096) >= 0

def sw_streams(data: bytes):
    """Real streams as dicts: sig (file pos of 4-byte signature), name, raw, ds, cs."""
    out, n, end = [], len(data), 0
    for m in _SW_MARK_RX.finditer(data):
        o = m.start()
        if o < end or o < 4 or o + 26 > n:
            continue
        A, crc, cs, us, nl = struct.unpack_from("<IIIII", data, o + 6)
        ds = o + 26 + nl
        if nl == 0 or nl > 1024 or ds + cs > n:
            continue
        try:
            z = zlib.decompressobj(-15)
            raw = z.decompress(data[ds:ds + cs])
        except zlib.error:
            continue
        if len(raw) != us or not z.eof or z.unused_data or (zlib.crc32(raw) & 0xFFFFFFFF) != crc:
            continue
        out.append({"sig": o - 4, "name": _swap(data[o + 26:ds]).decode("utf-8", "replace"), "raw": raw,
                    "ds": ds, "cs": cs})
        end = ds + cs
    return out

def sw_rebuild(data: bytes, streams, new_raw: dict) -> bytes:
    """Rewrite changed streams; fix sizes, CRCs and directory offsets."""
    changed = {i: r for i, r in new_raw.items() if r != streams[i]["raw"]}
    if not changed:
        return data
    out, cur, shifts, delta, upd = [], 0, [], 0, {}
    for i, st in enumerate(streams):
        if i not in changed:
            continue
        raw = changed[i]
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        comp = c.compress(raw) + c.flush()
        s, ds, cs = st["sig"], st["ds"], st["cs"]
        new = (zlib.crc32(raw) & 0xFFFFFFFF, len(comp), len(raw))
        out.append(data[cur:s + 14]); out.append(struct.pack("<III", *new)); out.append(data[s + 26:ds]); out.append(comp)
        cur = ds + cs
        delta += len(comp) - cs
        shifts.append((cur, delta)); upd[s - 8] = new
    out.append(data[cur:])
    buf = bytearray(b"".join(out))

    def d_at(old_pos):
        d = 0
        for p, dl in shifts:
            if old_pos >= p: d = dl
            else: break
        return d

    locs = {st["sig"] - 8 for st in streams}
    tail_old = streams[-1]["ds"] + streams[-1]["cs"]
    cd_first = None
    for m in _SW_MARK_RX.finditer(data, tail_old):
        o = m.start()
        if o + 40 > len(data):
            continue
        off = struct.unpack_from("<I", data, o + 36)[0]
        if off not in locs:
            continue
        n = o + d_at(o)
        if data[o - 2:o] == b"\0\0" and data[o + 26:o + 30] == b"\0" * 4:
            if cd_first is None: cd_first = o - 6
        if off in upd and struct.unpack_from("<I", data, o + 14)[0] == next(
                st["cs"] for st in streams if st["sig"] - 8 == off):
            struct.pack_into("<III", buf, n + 10, *upd[off])
        struct.pack_into("<I", buf, n + 36, off + d_at(off + 8))
    if cd_first is not None:
        old = struct.pack("<I", cd_first - 8)
        new = struct.pack("<I", cd_first - 8 + d_at(cd_first))
        j = data.find(old, tail_old)
        while j >= 0:
            c1, c2 = struct.unpack_from("<HH", data, j - 8)
            if c1 == c2 and c1 > 0:
                k = j + d_at(j); buf[k:k + 4] = new
            j = data.find(old, j + 1)
    return bytes(buf)

def sw_check(data: bytes) -> bool:
    """Every directory entry that points at a stream agrees with that stream's header."""
    st = sw_streams(data)
    if not st:
        return False
    by = {s["sig"] - 8: s for s in st}
    seen = set()
    for m in _SW_MARK_RX.finditer(data, st[-1]["ds"] + st[-1]["cs"]):
        o = m.start()
        if o + 40 > len(data) or data[o - 2:o] != b"\0\0":
            continue
        off = struct.unpack_from("<I", data, o + 36)[0]
        if off in by and data[o + 26:o + 30] == b"\0" * 4:
            s = by[off]
            if struct.unpack_from("<III", data, o + 10) == struct.unpack_from("<III", data, s["sig"] + 14):
                seen.add(off)
    return len(seen) == len(st)

# ---------------------------------------------------------------- names in running text
_CUE = re.compile(
    r"(?i:(?:designed|drawn|created|made|written|modell?ed|developed|checked|approved|authored|maintained|engineered)\s+by"
    r"|(?:authors?|maintainers?|designer|drawn|checked|approved|engineer|contact)\s*[:=]"
    r"|copyright\s*(?:\(c\)|\xa9|\xc2\xa9)?\s*(?:\d{4}(?:\s*[-,]\s*\d{4})*)?,?)"
    r"[ \t]*(?:\r?\n[ \t]*)?((?:[A-Z][A-Za-z'\-]+\.?)(?:[ \t]+[A-Z][A-Za-z'\-]+\.?){1,3})")
_NOT_NAME = re.compile(r"(?i)\b(foundation|contributors?|authors?|rights|reserved|license|software|project|team|the|inc|"
                       r"corporation|version|all|this|and|for|notice|holders?|permission|see|file)\b")

def text_names(text: str):
    """Person/organisation names introduced by a cue word in prose (README, licence, title block text)."""
    out = []
    for m in _CUE.finditer(text):
        toks = m.group(1).strip(" .").split()
        while len(toks) > 2 and is_common(toks[-1].strip(".")):
            toks.pop()  # "Jane Doe Use ..." -> "Jane Doe"
        v = " ".join(toks)
        if len(toks) >= 2 and not _NOT_NAME.search(v) and not all(is_common(t.strip(".")) for t in toks):
            out.append(v)
    return out
