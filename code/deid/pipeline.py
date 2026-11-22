"""Traversal: one recursive bytes->bytes processor used by discover / transform / verify."""
from __future__ import annotations
import bz2, gzip, io, lzma, os, re, shutil, tarfile, tempfile, zipfile
from collections import Counter
from . import formats as F
from .core import Engine, Registry, USERPATH, is_placeholder

SW_EXT = {".sldprt", ".sldasm", ".slddrw", ".prtdot", ".asmdot", ".drwdot"}
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UP_RX = re.compile(USERPATH)
HEX = re.compile(r"^[0-9a-f]{7,40}$")
MAX_DEPTH = 8


class Ctx:
    def __init__(self, mode: str, engine: Engine | None = None):
        self.mode = mode            # discover | transform | verify
        self.engine = engine
        self.reg = Registry()
        self.stats: Counter = Counter()
        self.issues: list[tuple[str, str]] = []

    def issue(self, name, what):
        self.issues.append((name, what)); self.stats["issue:" + what.split(":")[0]] += 1


def _ext(name: str) -> str:
    return os.path.splitext(name)[1].lower()


# ------------------------------------------------------------------ names / paths
def map_relpath(rel: str, ctx: Ctx) -> str:
    """Pseudonymise a corpus-relative path. Extension and neutral parts are kept."""
    parts = rel.split("/")
    out = []
    for i, comp in enumerate(parts):
        forced = None
        if (i == 2 and parts[0] == "sources" and parts[1] in ("github", "gitlab")) or (i == 1 and parts[0] == "archives"):
            stem, ext = (comp, "")
            if i == len(parts) - 1:
                stem, ext = os.path.splitext(comp)
            segs = stem.split("__")
            if len(segs) >= 2:
                owner, repo, rest = segs[0], segs[1], segs[2:]
                if ctx.mode == "discover":
                    ctx.reg.note("path-owner", owner); ctx.reg.note("path-repo", repo)
                else:
                    m = ctx.engine.m
                    forced = "__".join([m.words(owner), m.words(repo)] + rest) + ext
        if ctx.mode == "discover":
            out.append(comp)
        else:
            out.append(forced if forced is not None else ctx.engine.apply(comp))
    return "/".join(out)


def map_name(name: str, ctx: Ctx) -> str:
    if ctx.mode != "transform":
        return name
    return ctx.engine.apply(name)


# ------------------------------------------------------------------ generic
def _ole_words(data: bytes, ctx: Ctx):
    words = []
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(data))
        md = ole.get_metadata()
        for attr, kind in (("author", "person"), ("last_saved_by", "person"), ("company", "org"), ("manager", "person")):
            v = getattr(md, attr, None)
            if isinstance(v, bytes):
                v = v.decode("latin-1", "replace")
            if v and not is_placeholder(v):
                words += re.findall(r"[A-Za-z0-9]+", v)
                if ctx.mode == "discover":
                    ctx.reg.note(kind, v)
        ole.close()
    except Exception:
        pass
    return words


def generic(data: bytes, name: str, ctx: Ctx) -> bytes:
    ext = _ext(name)
    textlike = b"\0" not in data[:8192]
    s = data.decode("latin-1")
    spans = F.field_spans(s, ext) if textlike else []
    local = _ole_words(data, ctx) if data[:8] == OLE else []
    if ctx.mode == "discover":
        for a, b, kind in spans:
            ctx.reg.note(kind, s[a:b])
        for m in UP_RX.finditer(s):
            ctx.reg.note("person", re.split(r"[\\/]+", m.group(0), 1)[1])
        if not textlike:
            for r in U16.finditer(data):
                for m in UP_RX.finditer(r.group(0).decode("utf-16-le")):
                    ctx.reg.note("person", re.split(r"[\\/]+", m.group(0), 1)[1])
        return data
    eng = ctx.engine
    if ctx.mode == "verify":
        ctx.stats["residual"] += eng.count_terms(s)
        if not textlike:
            ctx.stats["residual"] += sum(eng.count_terms(r.group(0).decode("utf-16-le")) for r in U16.finditer(data))
        return data
    out = eng.apply(s, spans=[(a, b) for a, b, _ in spans], local_words=local, stats=ctx.stats).encode("latin-1")
    if not textlike or data[:2] in (b"\xff\xfe",):
        out = U16.sub(lambda r: eng.apply(r.group(0).decode("utf-16-le"), local_words=local, stats=ctx.stats).encode("utf-16-le"), out)
    assert len(out) == len(data)
    return out


# ------------------------------------------------------------------ containers
def do_sw(data, name, ctx, depth):
    streams = F.sw_streams(data)
    if not streams:
        raise ValueError("sw: no streams")
    new = {}
    for i, st in enumerate(streams):
        sub = st["name"]
        new[i] = generic(st["raw"], sub if "." in sub.rsplit("/", 1)[-1] else sub + ".bin", ctx)
    if ctx.mode != "transform":
        return data
    out = F.sw_rebuild(data, streams, new)
    if out is not data and not F.sw_check(out):
        raise ValueError("sw: rebuilt container failed self-check")
    ctx.stats["sw_rewritten"] += out is not data
    return out


def do_zip(data, name, ctx, depth):
    zin = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) if ctx.mode == "transform" else None
    for info in zin.infolist():
        if info.flag_bits & 0x1:
            raise ValueError("zip: encrypted member")
        body = b"" if info.is_dir() else zin.read(info)
        new = body if info.is_dir() else process(body, info.filename, ctx, depth + 1)
        if zout is not None:
            ni = zipfile.ZipInfo(map_name(info.filename, ctx), date_time=info.date_time)
            ni.compress_type = zipfile.ZIP_STORED if info.compress_type == zipfile.ZIP_STORED else zipfile.ZIP_DEFLATED
            ni.external_attr = info.external_attr
            ni.create_system = info.create_system
            if info.comment:
                ni.comment = ctx.engine.apply(info.comment.decode("latin-1")).encode("latin-1")
            zout.writestr(ni, new)
    if zout is None:
        return data
    if zin.comment:
        zout.comment = ctx.engine.apply(zin.comment.decode("latin-1")).encode("latin-1")
    zout.close()
    return buf.getvalue()


def do_tar(data, name, ctx, depth, wmode="w"):
    tin = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    buf = io.BytesIO()
    tout = tarfile.open(fileobj=buf, mode="w", format=tin.format or tarfile.PAX_FORMAT) if ctx.mode == "transform" else None
    for ti in tin:
        body = tin.extractfile(ti).read() if ti.isfile() else None
        new = process(body, ti.name, ctx, depth + 1) if body is not None else None
        if tout is not None:
            ti.name = map_name(ti.name, ctx)
            if ti.linkname:
                ti.linkname = map_name(ti.linkname, ctx)
            for attr in ("uname", "gname"):
                v = getattr(ti, attr)
                if v and not is_placeholder(v):
                    setattr(ti, attr, ctx.engine.m.words(v))
            ti.pax_headers = {}
            if new is not None:
                ti.size = len(new)
            tout.addfile(ti, io.BytesIO(new) if new is not None else None)
    if tout is None:
        return data
    tout.close()
    return buf.getvalue()


def do_stream(data, name, ctx, depth, mod):
    inner = mod.decompress(data)
    base = name[:-len(_ext(name))] if _ext(name) in (".gz", ".bz2", ".xz", ".tgz") else name
    if _ext(name) == ".tgz":
        base += ".tar"
    new = process(inner, base, ctx, depth + 1)
    if ctx.mode != "transform":
        return data
    if mod is gzip:
        b = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=b, mtime=0) as g:
            g.write(new)
        return b.getvalue()
    return mod.compress(new)


def do_7z(data, name, ctx, depth):
    import py7zr
    with tempfile.TemporaryDirectory(prefix="deid7z") as td:
        src, dst = os.path.join(td, "in"), os.path.join(td, "out.7z")
        with py7zr.SevenZipFile(io.BytesIO(data)) as z:
            if z.needs_password():
                raise ValueError("7z: encrypted")
            z.extractall(path=src)
        zout = py7zr.SevenZipFile(dst, "w") if ctx.mode == "transform" else None
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for fn in sorted(files):
                p = os.path.join(root, fn)
                rel = os.path.relpath(p, src).replace(os.sep, "/")
                if os.path.islink(p):
                    continue
                new = process(open(p, "rb").read(), rel, ctx, depth + 1)
                if zout is not None:
                    zout.writestr(new, map_name(rel, ctx))
        if zout is None:
            return data
        zout.close()
        return open(dst, "rb").read()


def do_pdf(data, name, ctx, depth):
    import pymupdf
    doc = pymupdf.open(stream=data, filetype="pdf")
    if doc.needs_pass:
        raise ValueError("pdf: encrypted")
    md = doc.metadata or {}
    eng = ctx.engine
    if ctx.mode == "discover":
        if md.get("author"):
            ctx.reg.note("person", md["author"])
        for n in doc.embfile_names():
            process(doc.embfile_get(n), n, ctx, depth + 1)
        return data
    if ctx.mode == "verify":
        txt = "\n".join(str(v) for v in md.values() if v) + "\n" + (doc.get_xml_metadata() or "")
        for page in doc:
            txt += page.get_text() + "\n".join(l.get("uri", "") for l in page.get_links())
        ctx.stats["residual"] += eng.count_terms(txt)
        for n in doc.embfile_names():
            process(doc.embfile_get(n), n, ctx, depth + 1)
        return data
    changed = False
    new_md = dict(md)
    for k in ("title", "subject", "keywords", "author"):
        v = md.get(k)
        if v:
            new_md[k] = eng._span(v) if (k == "author" and not is_placeholder(v)) else eng.apply(v, stats=ctx.stats)
    if new_md != md:
        doc.set_metadata(new_md); changed = True
    xmp = doc.get_xml_metadata()
    if xmp:
        nx = eng.apply(xmp, spans=[(a, b) for a, b, _ in F.xml_spans(xmp)], stats=ctx.stats)
        if nx != xmp:
            doc.set_xml_metadata(nx); changed = True
    for page in doc:
        lines: dict = {}
        for w in page.get_text("words"):
            lines.setdefault((w[5], w[6]), []).append(w)
        red = 0
        for ws in lines.values():
            old = " ".join(w[4] for w in ws)
            new = eng.apply(old, stats=ctx.stats)
            if new == old:
                continue
            for w, nw in zip(ws, new.split(" ")):
                if nw != w[4]:
                    r = pymupdf.Rect(w[:4])
                    page.add_redact_annot(r, text=nw, fontsize=max(4, min(r.height * 0.75, 24)), fill=False, cross_out=False)
                    red += 1
        if red:
            page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE, graphics=pymupdf.PDF_REDACT_LINE_ART_NONE)
            ctx.stats["pdf_words"] += red; changed = True
        for xref, atype, _ in page.annot_xrefs():
            if atype != pymupdf.PDF_ANNOT_LINK or xref <= 0:
                continue
            kind, u = doc.xref_get_key(xref, "A/URI")
            if kind == "string" and u:
                nu = eng.apply(u, stats=ctx.stats)
                if nu != u:
                    doc.xref_set_key(xref, "A/URI", pymupdf.get_pdf_str(nu)); changed = True
        # link annotations stored inline in the page's /Annots array have no object of their own
        kind, raw = doc.xref_get_key(page.xref, "Annots")
        if kind == "array" and "/URI" in raw:
            nraw = re.sub(r"(/URI\s*\()((?:\\.|[^\\)])*)", lambda m: m.group(1) + eng.apply(m.group(2), stats=ctx.stats), raw)
            if nraw != raw:
                doc.xref_set_key(page.xref, "Annots", nraw); changed = True
    toc = doc.get_toc(simple=False)
    if toc:
        nt = [[t[0], eng.apply(t[1]), t[2]] + list(t[3:]) for t in toc]
        if [t[1] for t in nt] != [t[1] for t in toc]:
            doc.set_toc(nt); changed = True
    for n in list(doc.embfile_names()):
        body = doc.embfile_get(n)
        info = doc.embfile_info(n)
        nb = process(body, info.get("filename") or n, ctx, depth + 1)
        nf = eng.apply(info.get("filename") or n)
        if nb != body or nf != (info.get("filename") or n):
            doc.embfile_upd(n, buffer_=nb, filename=nf, ufilename=nf, desc=eng.apply(info.get("description") or ""))
            changed = True
    if not changed:
        return data
    return doc.tobytes(garbage=3, deflate=True)


def process(data: bytes, name: str, ctx: Ctx, depth: int = 0) -> bytes:
    if not data:
        return data
    ext = _ext(name)
    h = None
    if depth < MAX_DEPTH:
        if data[:4] == b"PK\x03\x04":
            h = do_zip
        elif data[:6] == b"7z\xbc\xaf\x27\x1c":
            h = do_7z
        elif data[:2] == b"\x1f\x8b":
            h = lambda d, n, c, k: do_stream(d, n, c, k, gzip)
        elif data[:3] == b"BZh" and ext in (".bz2", ".tbz2"):
            h = lambda d, n, c, k: do_stream(d, n, c, k, bz2)
        elif data[:6] == b"\xfd7zXZ\x00":
            h = lambda d, n, c, k: do_stream(d, n, c, k, lzma)
        elif data[257:262] == b"ustar" or ext == ".tar":
            h = do_tar
        elif data[:5] == b"%PDF-":
            h = do_pdf
        elif ext in SW_EXT and F.is_sw(data):
            h = do_sw
        elif data[:4] == b"Rar!" or (data[:2] == b"\x1f\x9d" and ext == ".z"):
            ctx.issue(name, "container-not-rebuilt: rar/compress archive passed through the binary handler only")
    if h is not None:
        try:
            out = h(data, name, ctx, depth)
            ctx.stats["h:" + getattr(h, "__name__", "stream")] += 1
            return out
        except Exception as e:  # never drop a file: fall back to the length-preserving binary pass
            ctx.issue(name, "fallback: %s: %s" % (getattr(h, "__name__", "stream"), str(e)[:120]))
    ctx.stats["h:generic"] += 1
    return generic(data, name, ctx)
