#!/usr/bin/env python3
"""CAD de-identification pipeline.

  python3 run.py discover  --input ./input --state ./state
  python3 run.py transform --input ./input --state ./state --output ./cleaned-corpus
  python3 run.py verify    --state ./state --output ./cleaned-corpus

--state holds the private key, the identifier registry and run logs. Never upload it.
"""
from __future__ import annotations
import argparse, json, os, secrets, sys, time
from collections import Counter
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deid.core import Engine, Mapper, Registry
from deid.pipeline import Ctx, map_relpath, process

G = {}

def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x != ".get-input")
        for f in sorted(files):
            p = os.path.join(d, f)
            if os.path.isfile(p) and not os.path.islink(p):
                yield os.path.relpath(p, root).replace(os.sep, "/")

def load_engine(state):
    key = open(os.path.join(state, "key.bin"), "rb").read()
    reg = Registry.load(os.path.join(state, "registry.json"))
    here = os.path.dirname(os.path.abspath(__file__))
    rd = lambda n: [l.strip() for l in open(os.path.join(here, "config", n), encoding="utf-8") if l.strip() and not l.startswith("#")] \
        if os.path.exists(os.path.join(here, "config", n)) else []
    extra = rd("extra_terms.txt")
    pe = os.path.join(state, "extra_terms.txt")
    if os.path.exists(pe):
        extra += [l.strip() for l in open(pe, encoding="utf-8") if l.strip() and not l.startswith("#")]
    return Engine(Mapper(key), reg, allow={a.lower() for a in rd("allow.txt")}, extra=extra)

def w_discover(rel):
    ctx = Ctx("discover")
    try:
        map_relpath(rel, ctx)
        process(open(os.path.join(G["input"], rel), "rb").read(), rel, ctx)
    except Exception as e:
        ctx.issue(rel, "error: " + repr(e)[:200])
    return rel, ctx.reg, ctx.stats, ctx.issues, None

def w_transform(rel):
    ctx = Ctx("transform", G["engine"])
    out_rel = map_relpath(rel, ctx)
    dst = os.path.join(G["output"], out_rel)
    if os.path.exists(dst) and not G["force"]:
        return rel, None, Counter(skipped=1), [], out_rel
    src = os.path.join(G["input"], rel)
    try:
        data = open(src, "rb").read()
        new = process(data, rel, ctx)
    except Exception as e:
        ctx.issue(rel, "error-copied-unmodified: " + repr(e)[:200])
        new = open(src, "rb").read()
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".part~"
    with open(tmp, "wb") as f:
        f.write(new)
    os.replace(tmp, dst)
    ctx.stats["files"] += 1
    ctx.stats["changed"] += new != data if "data" in dir() else 0
    return rel, None, ctx.stats, ctx.issues, out_rel

def w_verify(rel):
    ctx = Ctx("verify", G["engine"])
    try:
        process(open(os.path.join(G["output"], rel), "rb").read(), rel, ctx)
        ctx.stats["residual_path"] += G["engine"].count_terms(rel)
    except Exception as e:
        ctx.issue(rel, "error: " + repr(e)[:200])
    if ctx.stats["residual"] or ctx.stats["residual_path"]:
        ctx.issue(rel, "residual: %d" % (ctx.stats["residual"] + ctx.stats["residual_path"]))
    return rel, None, ctx.stats, ctx.issues, None

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["discover", "transform", "verify"])
    ap.add_argument("--input"); ap.add_argument("--output"); ap.add_argument("--state", required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--force", action="store_true"); ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    os.makedirs(a.state, exist_ok=True)
    kp = os.path.join(a.state, "key.bin")
    if not os.path.exists(kp):
        open(kp, "wb").write(secrets.token_bytes(32))
    G.update(input=a.input, output=a.output, force=a.force)
    root = a.output if a.cmd == "verify" else a.input
    files = list(walk(root))
    if a.limit:
        files = files[:a.limit]
    if a.cmd != "discover":
        G["engine"] = load_engine(a.state)
        print("terms:", G["engine"].n_terms, flush=True)
    fn = {"discover": w_discover, "transform": w_transform, "verify": w_verify}[a.cmd]
    reg, stats, issues, pathmap = Registry(), Counter(), [], {}
    t0 = time.time()
    with Pool(a.jobs) as pool:
        for i, (rel, r, st, iss, out_rel) in enumerate(pool.imap_unordered(fn, files, chunksize=4), 1):
            if r is not None: reg.merge(r)
            stats.update(st); issues += iss
            if out_rel: pathmap[rel] = out_rel
            if i % 500 == 0 or i == len(files):
                print(f"  {i}/{len(files)} files, {time.time() - t0:.0f}s", flush=True)
    if a.cmd == "discover":
        reg.dump(os.path.join(a.state, "registry.json"))
        print("words:", len(reg.words), "phrases:", len(reg.phrases))
    json.dump({"stats": dict(stats), "issues": issues, "paths": pathmap},
              open(os.path.join(a.state, f"report-{a.cmd}.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in sorted(stats.items())}, indent=1))
    print("issues:", len(issues))

if __name__ == "__main__":
    main()
