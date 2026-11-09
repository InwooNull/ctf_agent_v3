#!/usr/bin/env python3
"""Build vol3's FULL symbol-identifier index at image-build time.

vol3 resolves a dump's kernel to an ISF by scanning every bundled symbol file once
and caching each file's identifier (PDB GUID for Windows, banner hash for Linux/Mac)
in an sqlite `identifier.cache`. That first scan walks the 801 MB windows.zip (3000+
ISFs) and takes minutes — far past the sandbox's per-experiment timeout, which is why
the runtime path kept degrading to a `strings` fallback.

Running `SqliteCache.update()` here (build time, network allowed but NOT used — this is
a pure local scan) bakes the complete index into the image. At run time the driver copies
this baked cache into the writable /work, so offline symbol resolution is a cache hit and
`windows.*` / `mac.*` plugins return real structure within the timeout.
"""
import os
import time

# CACHE_PATH is derived from XDG_CACHE_HOME at import; the caller sets it to the bake dir.
os.environ.setdefault("HOME", "/root")

from volatility3.framework import constants  # noqa: E402
from volatility3.framework.automagic.symbol_cache import SqliteCache  # noqa: E402

# Construct the sqlite cache directly (load_cache_manager() refuses a not-yet-existing
# file). SqliteCache(path) creates the db; update() then enumerates every on-disk ISF via
# IntermediateSymbolTable.file_symbol_url and records each file's identifier. Self-contained.
cache_path = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
os.makedirs(constants.CACHE_PATH, exist_ok=True)
mgr = SqliteCache(cache_path)
print("cache file:", cache_path)
t = time.time()
mgr.update()
dt = time.time() - t

# report what got indexed, per OS
try:
    for osname in ("windows", "linux", "mac"):
        ids = mgr.get_identifiers(osname)
        print(f"indexed {osname}: {len(ids)} identifiers")
except Exception as e:  # get_identifiers is best-effort reporting only
    print("identifier count unavailable:", e)
print(f"vol3 symbol index built in {dt:.1f}s")
