# Bugfixing Progress Report

## Branch: `debt/bugfixing`
## Pushed to: `rnts08/WWC3 debt/bugfixing`
## Date: 2026-05-27

---

## Completed Bugs (7 commits)

| Bug | Description | Commit |
|-----|-------------|--------|
| #3 | Fix `__`-prefixed include guards (crypter.h, walletdb.h, keystore.h, wallet.h) | `bfd1e67` |
| #3 (cont.) | Dockerfile.qt-static for Ubuntu 16.04 build environment | `df7f508` |
| #15 | Remove redundant C-style casts in wallet crypter | `33992ec` |
| #18 | Replace printf with BOOST_MESSAGE in test output | `f2370b5` |
| #19 | Add comment warning about CScript vector inheritance | `02313c1` |
| #21 | Remove 3 blocks of commented-out debug code | `1bc6c0d` |
| #25 | Rename reserved `__CRYPTER_H__` include guard | `6e620d6` |
| #22 | Fix clear-cut TODO/FIXME/XXX items (4 resolved) | `e421207` |
| #24 | Replace (unsigned char*) C-style casts (8 files) | `78dde09` |

## Bug #24 Post-Fix Issue

`src/uint256.h:304` — `GetHex()` const method casts away const with `reinterpret_cast<unsigned char*>(pn)`. Fixed with `reinterpret_cast<const unsigned char*>(pn)`.

## Remaining Work

### Build Verification (in progress)

The daemon (`wayawolfcoind`) needs to build cleanly. Qt GUI build separately.

**Current state:**
- `make clean` done
- LevelDB rebuilt successfully
- Daemon build (`make -f makefile.unix`) started but timed out at 5 minutes — needs longer run

### TODO Audit — Left for Future Pass

33 TODO/FIXME/HACK/XXX items categorized:

**Upstream (don't fix):**
- `src/crypto/sph_types.h:990` — external crypto detection
- `src/leveldb/` (3 items) — imported library

**Document (not this pass):**
- `src/net.h:409,418,428` — document pre/post-conditions

**Too broad / not clear-cut (29 items deferred):**
- `addrman.cpp:231` — re-add node logic
- `init.cpp:274` — remaining sanity checks (#4081)
- `key.cpp:718` — EC functionality question
- `protocol.h:42,90,121` — make private (getters + callers)
- `sync.h:81` — recursive lock refactor
- `rpcwallet.cpp:1362,1407,1463` — SecureString::operator=(std::string)
- `qt/askpassphrasedialog.cpp:91` — same SecureString issue
- `qt/rpcconsole.cpp:19,20,21` — scrollback/filter/errors features
- `qt/guiutil.cpp:424` — OSX startup
- `qt/walletmodel.cpp:286` — decrypt not supported
- `qt/wayawolfcoingui.cpp:935,943` — decrypt not supported
- `rpcmining.cpp:357` — coinbase deserialization hack
- `wallet.cpp:648` — change output handling
- `wallet.cpp:950` — scan optimization
- `wallet.cpp:1452` — pass scriptChange
- `wallet.h:372` — calculate nOrderPos elsewhere

## How to Resume

```bash
cd /home/timh/Projects/WWC3
git checkout debt/bugfixing
# Generate missing build file:
mkdir -p obj && share/genbuild.sh obj/build.h
# Build daemon:
cd src/leveldb && make libleveldb.a
cd .. && make -f makefile.unix -j$(nproc)
```
