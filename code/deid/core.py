"""Pseudonym mapping and the replacement engine.

Every pseudonym has the same length and character classes as the original
(letter->letter keeping case and vowel/consonant class, digit->digit), keyed by
HMAC of the lower-cased word with a private key. Same word -> same pseudonym
everywhere; length preservation keeps binary containers, fixed-column formats
and file references valid without re-serialising geometry.
"""
from __future__ import annotations
import bisect, hashlib, hmac, json, re
from collections import Counter

VOW = "aeiou"
CON = "bcdfghjklmnpqrstvwxyz"
TOKEN = re.compile(r"[A-Za-z0-9]+")

# values that are software defaults / placeholders, not identities
STOP_VALUES = {
    "", "unknown", "none", "n/a", "na", "null", "unspecified", "not specified", "anonymous",
    "user", "users", "admin", "administrator", "owner", "author", "default", "guest", "pc",
    "root", "public", "all users", "default user", "system", "test", "student", "home",
    "name", "company", "organization", "nobody", "-", "?", "x", "xx", "xxx", "tbd", "your name",
    "runner", "ubuntu", "user1", "desktop", "documents", "downloads", "shared",
}
VENDOR_HINTS = (
    "solidworks", "dassault", "autodesk", "siemens", "microsoft", "freecad", "ptc", "parametric technology",
    "opencascade", "open cascade", "cadquery", "onshape", "inventor", "fusion 360", "catia", "solid edge",
    "st-developer", "steptools", "kicad", "blender", "inkscape", "adobe", "acrobat", "ghostscript", "spatial",
    "mcneel", "rhinoceros", "creo", "pro/engineer", "unigraphics", "datakit", "cadexchanger", "gmsh", "openscad",
)
STOP_TOKENS = {
    "the", "and", "of", "for", "inc", "ltd", "llc", "gmbh", "corp", "co", "company", "university", "institute",
    "dept", "department", "engineering", "design", "group", "team", "lab", "labs", "www", "com", "org", "net",
    "mr", "mrs", "dr", "ing", "sa", "srl", "ag", "bv", "pty", "plc", "de", "la", "el", "van", "von", "da",
}
# single words too common to replace corpus-wide even if they appear as an author value
COMMON = set("""bill mark art rod will grant dean chase miles bolt nut pin gear shaft plate frame base cover mount
bracket assembly part model drawing sheet steel iron wood glass stone rose lily ivy dawn hope faith grace joy
june april may august summer winter spring autumn north south east west king queen prince duke earl baron
smith mason carter cooper turner taylor baker miller fisher hunter parker porter sawyer tanner walker weaver
young long short brown black white green gray grey gold silver copper bronze major minor general private
angel victor max rex ray jack jimmy bob tom tim sam dan ben ken jim joe ron don ted rob pat lee kim jay roy
desktop rope main core body head arm leg hand foot wheel motor robot machine tool tools test tests demo sample example
project projects cad step parts library public open source free standard metric drive pump valve spring
final draft rev revision version copy backup temp new old work home office shop store house school class
admin user users owner author guest default system server client local remote master slave primary
china india japan korea france spain italy germany england canada mexico brazil texas paris london berlin
""".split())

EMAIL = r"[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9][A-Za-z0-9\-]{0,62}(?:\.[A-Za-z0-9\-]{1,63}){1,4}"
URL = r"(?:https?://|ftp://|www\.)[A-Za-z0-9][A-Za-z0-9.\-]{2,200}"
USERPATH = r"(?:[Uu]sers|USERS|Documents and Settings|home)(?:\\\\|[\\/])[^\\/\x00-\x1f\"'<>|:*?]{1,48}(?=[\\/])"
SAFE_HOSTS = (
    "w3.org", "openxmlformats.org", "purl.org", "solidworks.com", "microsoft.com", "adobe.com", "autodesk.com",
    "freecad.org", "freecadweb.org", "freecad.org", "inkscape.org", "sourceforge.net", "creativecommons.org",
    "opengis.net", "3mf.io", "iso.org", "steptools.com", "apache.org", "gnu.org", "python.org", "npmjs.org",
    "npmjs.com", "github.com", "githubusercontent.com", "gitlab.com", "xmlsoap.org", "mozilla.org", "opensource.org",
    "wikipedia.org", "google.com", "googleapis.com", "example.com", "example.org", "localhost", "pypi.org",
    "khronos.org", "web3d.org", "dublincore.org", "oasis-open.org", "omg.org", "ietf.org", "schema.org",
    "3ds.com", "siemens.com", "ptc.com", "opencascade.com", "opencascade.org", "kicad.org", "blender.org",
    "json-schema.org", "nist.gov", "grabcad.com", "thingiverse.com", "printables.com", "youtube.com", "youtu.be",
)


class Mapper:
    def __init__(self, key: bytes):
        self.key = key
        self.cache: dict[str, str] = {}

    def _low(self, low: str) -> str:
        out = self.cache.get(low)
        if out is not None:
            return out
        n = 0
        while True:
            stream = b""
            c = 0
            while len(stream) < len(low):
                stream += hmac.new(self.key, f"{n}:{c}:{low}".encode(), hashlib.sha256).digest()
                c += 1
            res = []
            for ch, b in zip(low, stream):
                if ch in VOW:
                    res.append(VOW[b % 5])
                elif ch in CON:
                    res.append(CON[b % 21])
                elif ch.isdigit():
                    res.append(str(b % 10))
                else:
                    res.append(ch)
            out = "".join(res)
            if out != low or not any(ch.isalnum() for ch in low):
                break
            n += 1
        self.cache[low] = out
        return out

    def word(self, w: str) -> str:
        m = self._low(w.lower())
        return "".join(c.upper() if o.isupper() else c for o, c in zip(w, m))

    def words(self, s: str, skip_stop: bool = False) -> str:
        def f(m):
            t = m.group(0)
            if skip_stop and t.lower() in STOP_TOKENS:
                return t
            return self.word(t)
        return TOKEN.sub(f, s)


def is_placeholder(value: str) -> bool:
    v = " ".join(value.lower().split())
    if v in STOP_VALUES or not TOKEN.search(v):
        return True
    return any(h in v for h in VENDOR_HINTS)


class Registry:
    """Identity terms found in discovery. Raw identifiers: keep this file private."""

    def __init__(self):
        self.words: Counter = Counter()
        self.phrases: Counter = Counter()
        self.sources: dict[str, set] = {}

    def note(self, kind: str, value: str):
        value = value.strip()
        if is_placeholder(value) or len(value) > 80:
            return
        toks = [t for t in TOKEN.findall(value)]
        sig = [t.lower() for t in toks if t.lower() not in STOP_TOKENS]
        if not sig:
            return
        key = None
        if len(sig) == 1:
            w = sig[0]
            if len(w) >= 4 and not w.isdigit() and (w not in COMMON):
                key = w
                self.words[w] += 1
        else:
            key = " ".join(t.lower() for t in toks)
            if len("".join(sig)) >= 6:
                self.phrases[key] += 1
            # distinctive individual words of a multi-word identity are identities too
            for w in sig:
                if len(w) >= 6 and not w.isdigit() and w not in COMMON and kind == "person":
                    self.words[w] += 1
        if key:
            self.sources.setdefault(key, set()).add(kind)

    def merge(self, other: "Registry"):
        self.words.update(other.words)
        self.phrases.update(other.phrases)
        for k, v in other.sources.items():
            self.sources.setdefault(k, set()).update(v)

    def dump(self, path):
        json.dump({"words": dict(self.words), "phrases": dict(self.phrases),
                   "sources": {k: sorted(v) for k, v in self.sources.items()}}, open(path, "w"), indent=1, sort_keys=True)

    @classmethod
    def load(cls, path):
        r = cls()
        d = json.load(open(path))
        r.words.update(d["words"]); r.phrases.update(d["phrases"])
        r.sources = {k: set(v) for k, v in d.get("sources", {}).items()}
        return r


_LOW = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_AN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_EMAIL_RX = re.compile(EMAIL)
_URL_RX = re.compile(URL, re.I)
_UP_RX = re.compile(USERPATH)
_EM_LEFT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
_UP_ANCH = ("users\\", "users/", "home/", "documents and settings")
_PRI = {"em": 0, "url": 1, "up": 2, "t": 3}


class Engine:
    """Finds identity terms, e-mail addresses, URLs and user-profile paths, and maps them.

    Matching is anchored with an Aho-Corasick automaton over an ASCII-lower-cased copy of the
    text (falls back to str.find loops when pyahocorasick is missing), so cost is roughly
    independent of the number of registry terms.
    """

    def __init__(self, mapper: Mapper, registry: Registry, allow=frozenset(), extra=()):
        self.m = mapper
        words = {w for w in registry.words if w not in allow}
        phrases = {p for p in registry.phrases if p not in allow}
        for e in extra:
            e = " ".join(TOKEN.findall(e.lower()))
            if e:
                (phrases if " " in e else words).add(e)
        self.n_terms = len(words) + len(phrases)
        keys: dict[str, list] = {}
        for w in words:
            keys.setdefault(w, []).append(("w", None))
        for p in phrases:
            toks = p.split()
            rx = re.compile(r"[^a-z0-9]{1,3}".join(map(re.escape, toks)) + r"(?![a-z0-9])")
            keys.setdefault(toks[0], []).append(("p", rx))
        self.term_keys = {k: list(v) for k, v in keys.items()}
        keys.setdefault("@", []).append(("em", None))
        keys.setdefault("://", []).append(("url", None))
        keys.setdefault("www.", []).append(("www", None))
        for a in _UP_ANCH:
            keys.setdefault(a, []).append(("up", None))
        self.keys = keys
        self.ac = self.ac_terms = None
        try:
            import ahocorasick
            for attr, src in (("ac", keys), ("ac_terms", self.term_keys)):
                if src:
                    A = ahocorasick.Automaton()
                    for k, v in src.items():
                        A.add_word(k, (len(k), v))
                    A.make_automaton()
                    setattr(self, attr, A)
        except ImportError:
            pass

    # -- candidate search ---------------------------------------------------
    def _hits(self, low: str, keys, ac):
        if ac is not None:
            for end, (ln, v) in ac.iter(low):
                yield end - ln + 1, ln, v
        else:
            for k, v in keys.items():
                i = low.find(k)
                while i >= 0:
                    yield i, len(k), v
                    i = low.find(k, i + 1)

    def _matches(self, s: str, low: str, terms_only: bool, local=()):
        n = len(low)
        out = []
        keys, ac = (self.term_keys, self.ac_terms) if terms_only else (self.keys, self.ac)
        for st, ln, v in self._hits(low, keys, ac) if keys else ():
            for kind, rx in v:
                if kind == "w":
                    if (st == 0 or low[st - 1] not in _AN) and (st + ln == n or low[st + ln] not in _AN):
                        out.append((st, st + ln, "t"))
                elif kind == "p":
                    if st == 0 or low[st - 1] not in _AN:
                        m = rx.match(low, st)
                        if m:
                            out.append((st, m.end(), "t"))
                elif kind == "em":
                    a = st
                    while a > 0 and st - a < 64 and s[a - 1] in _EM_LEFT:
                        a -= 1
                    while a < st and not s[a].isalnum():
                        a += 1
                    m = _EMAIL_RX.match(s, a) if a < st else None
                    if m and m.end() > st:
                        out.append((a, m.end(), "em"))
                elif kind == "url":
                    a = st
                    while a > 0 and st - a < 6 and low[a - 1].isalpha():
                        a -= 1
                    m = _URL_RX.match(s, a)
                    if m:
                        out.append((a, m.end(), "url"))
                elif kind == "www":
                    if st == 0 or low[st - 1] not in _AN:
                        m = _URL_RX.match(s, st)
                        if m:
                            out.append((st, m.end(), "url"))
                elif kind == "up":
                    m = _UP_RX.match(s, st)
                    if m:
                        out.append((st, m.end(), "up"))
        for w in local:
            i = low.find(w)
            while i >= 0:
                if (i == 0 or low[i - 1] not in _AN) and (i + len(w) == n or low[i + len(w)] not in _AN):
                    out.append((i, i + len(w), "t"))
                i = low.find(w, i + 1)
        out.sort(key=lambda t: (t[0], _PRI[t[2]], -t[1]))
        return out

    # -- callbacks ----------------------------------------------------------
    def _email(self, s):
        local, dom = s.rsplit("@", 1)
        labels = dom.split(".")
        return self.m.words(local) + "@" + ".".join([self.m.words(x) for x in labels[:-1]] + labels[-1:])

    def _url(self, s):
        i = s.find("//")
        pre, host = (s[: i + 2], s[i + 2:]) if i >= 0 else ("", s)
        h = host.lower().rstrip(".")
        if any(h == sh or h.endswith("." + sh) for sh in SAFE_HOSTS) or h.replace(".", "").isdigit() or "." not in h:
            return s
        labels = host.split(".")
        return pre + ".".join([l if l.lower() == "www" else self.m.words(l) for l in labels[:-1]] + labels[-1:])

    def _up(self, s):
        m = re.match(r"(.*?(?:\\\\|[\\/]))(.*)$", s, re.S)
        head, name = m.group(1), m.group(2)
        return s if is_placeholder(name) else head + self.m.words(name)

    def _rep(self, kind, s):
        if kind == "t":
            return self.m.words(s)
        if kind == "em":
            return self._email(s)
        if kind == "url":
            return self._url(s)
        return self._up(s)

    def _span(self, val: str) -> str:
        """An identity field: e-mails/URLs keep their shape, every other word is mapped."""
        out, last = [], 0
        for m in re.finditer(r"(?P<em>%s)|(?P<url>%s)" % (EMAIL, URL), val):
            out.append(self.m.words(val[last:m.start()], skip_stop=True))
            out.append(self._rep(m.lastgroup, m.group(0))); last = m.end()
        out.append(self.m.words(val[last:], skip_stop=True))
        return "".join(out)

    # -- public ---------------------------------------------------------------
    def apply(self, s: str, spans=(), local_words=(), stats=None) -> str:
        """Length-preserving replacement on a str (latin-1 decoded bytes or real text)."""
        edits = []  # (start, end, replacement)
        for a, b in sorted(set(spans)):
            if b > a and (not edits or a >= edits[-1][1]) and not is_placeholder(s[a:b]):
                edits.append((a, b, self._span(s[a:b])))
                if stats is not None: stats["field"] += 1
        lw = sorted({w.lower() for w in local_words if len(w) >= 3 and not w.isdigit() and w.lower() not in STOP_TOKENS
                     and w.lower() not in STOP_VALUES})
        low = s.translate(_LOW)
        prot = [(a, b) for a, b, _ in edits]
        starts = [p[0] for p in prot]
        last = -1
        for a, b, kind in self._matches(s, low, False, lw):
            if a < last:
                continue
            if prot:
                i = bisect.bisect_right(starts, b - 1) - 1
                if i >= 0 and prot[i][1] > a:
                    continue
            old = s[a:b]
            new = self._rep(kind, old)
            if new == old and kind != "t":
                continue  # e.g. a URL on a standard host: let terms inside it match
            last = b
            if new != old:
                edits.append((a, b, new))
                if stats is not None: stats[kind] += 1
        if not edits:
            return s
        edits.sort()
        parts, cur = [], 0
        for a, b, new in edits:
            parts.append(s[cur:a]); parts.append(new); cur = b
        parts.append(s[cur:])
        return "".join(parts)

    def count_terms(self, s: str) -> int:
        last, n = -1, 0
        for a, b, _ in self._matches(s, s.translate(_LOW), True):
            if a >= last:
                n += 1; last = b
        return n
