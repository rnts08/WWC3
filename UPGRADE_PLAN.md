# WWC3 (Wayawolfcoin V3) — Modernization & Bug Fix Plan

## Project Overview

**Wayawolfcoin V3** is an experimental PoW+PoS hybrid cryptocurrency (ticker: WW) built on the Bitcoin/PPCoin/DiminutiveCoin lineage. It uses the custom HMQ1725 multi-hash algorithm. The codebase targets very old library versions and contains approximately 30 identified bugs and logical issues across critical paths.

### Current Library Versions

| Library | Current Version | Status |
|---|---|---|
| OpenSSL | 1.0.1j / 1.0.2g / 1.0.2u | EOL Dec 2019 |
| Berkeley DB | 4.8.30.NC | EOL (2010) |
| Qt | Qt5 (with Qt4 compat) | Qt5 EOL 2024 |
| Boost | 1.52–1.65 (varies by platform) | Multiple old releases |
| LevelDB | 1.17 (bundled, circa 2013) | Unpatched security vulns |
| miniupnpc | 1.6 / 1.9+ (3 APIs supported) | Obsolete baseline |
| libqrencode | 4.0.2 | Current |

---

## Phase 1: Library Version Upgrades

### 1A. OpenSSL: 1.0.x → 1.1.x (or 3.x)

**Why:** Security fixes, modern distros ship 1.1.x+, 1.0.x has been EOL since 2019. The code currently depends on 17 deprecated/removed APIs.

**Required changes:**

| Deprecated API | File(s) | Replacement |
|---|---|---|
| `BN_init()` | `src/bignum.h` (lines 62, 67, 88–98, 102), `src/key.cpp:154` | `BN_new()` + manual init |
| `CRYPTO_set_locking_callback()` | `src/util.cpp:110,125` | Remove entirely (OpenSSL 1.1+ is thread-safe by default) |
| `CRYPTO_num_locks()` | `src/util.cpp:107,108,126` | Remove |
| `RAND_screen()` | `src/util.cpp:114` | Remove (Windows-only, removed in 1.1) |
| `RAND_cleanup()` | `src/util.cpp:123` | Remove |
| `EVP_CIPHER_CTX_init()` | `src/crypter.cpp:80,107` | `EVP_CIPHER_CTX_new()` |
| `EVP_CIPHER_CTX_cleanup()` | `src/crypter.cpp:84,111` | `EVP_CIPHER_CTX_free()` / `EVP_CIPHER_CTX_reset()` |
| `SSLeay_version()` / `SSLEAY_VERSION` | `src/init.cpp:474`, `src/qt/rpcconsole.cpp:212` | `OpenSSL_version()` / `OPENSSL_VERSION` |
| `EC_GROUP_get_curve_GFp()` | `src/key.cpp:87` | `EC_GROUP_get_curve()` |
| `EC_POINT_set_compressed_coordinates_GFp()` | `src/key.cpp:90` | `EC_POINT_set_compressed_coordinates()` |
| `BN_is_prime()` | `src/bignum.h:531` | `BN_is_prime_ex()` |

**Strategy:** Use `#if OPENSSL_VERSION_NUMBER >= 0x10100000L` guards to support both 1.0.x and 1.1.x+ during the transition period. Update `wayawolfcoin.pro`, all `makefile.*`, `snapcraft.yaml`, and build docs to reference OpenSSL 1.1.x or 3.x.

---

### 1B. Berkeley DB: 4.8.30.NC → 5.3.x (or 6.2.x)

**Why:** Modern distros no longer ship 4.8. Debian 12 ships 5.3.x. The bundled snap build compiles from source, but the version is ancient.

**Risk:** BDB databases are **not forward-compatible** between major versions (4.x vs 5.x vs 6.x). Wallet files (`wallet.dat`) created with 4.8 could become unreadable if not properly migrated.

**Wallet safety — upgrade path:**

1. **Add BDB version detection at runtime** (currently absent):
   - Call `db_version(NULL, NULL, NULL)` to detect the linked BDB version
   - Log it at startup alongside the OpenSSL version

2. **Implement an automatic upgrade flow in `CDBEnv::Open()`:**
   ```
   On open failure with version-mismatch error:
     1. Backup: copy wallet.dat → wallet.dat.bak.<timestamp>
     2. Open with DB_CREATE to allow access
     3. Call CDB::Rewrite() to read all records at the key-value level
        and write them into a fresh database file.
        (This is BDB-version-neutral since it operates on data,
        not on BDB's internal page format.)
     4. If Rewrite() succeeds, replace original; if it fails, restore backup.
   ```

3. **Add `--upgrade-wallet` CLI flag** to force upgrade without loading normally.

4. **Remove the forward-compatibility warning** from `doc/readme-qt.rst` once the upgrade path is verified.

5. **Build updates:** Change BDB suffix from `-4.8` to `-5.3` (or version-detected) in all build files. Update snapcraft to build 5.3.x from source. Update all documentation.

---

### 1C. Qt5: Fix Deprecated APIs

**Why:** Qt5 EOL in 2024. Several deprecated APIs are used unconditionally and will break under Qt6. Deprecation warnings are suppressed via `QT_DISABLE_DEPRECATED_BEFORE=0`.

**Required changes:**

| Deprecated API | File(s) | Replacement |
|---|---|---|
| `Qt::escape()` | `src/qt/guiutil.cpp:146`, `src/qt/sendcoinsdialog.cpp:145` | `QString::toHtmlEscaped()` |
| `QDesktopServices::storageLocation()` | `src/qt/guiutil.cpp:181`, `src/qt/wayawolfcoingui.cpp:962` | `QStandardPaths::writableLocation()` |
| `QLibraryInfo::location()` | `src/qt/wayawolfcoin.cpp:193,197` | `QLibraryInfo::path()` |
| `QStyle::standardPixmap()` | `src/qt/notificator.cpp:255` | `QStyle::standardIcon().pixmap()` |

**Optional:**
- Remove `#if QT_VERSION < 0x050000` guards (drop Qt4 support entirely)
- Change `QT_DISABLE_DEPRECATED_BEFORE=0` to `QT_DISABLE_DEPRECATED_BEFORE=0x050000` to surface future deprecations
- Remove Qt4 plugin imports (`qcncodecs`, `qjpcodecs`, `qtwcodecs`, `qkrcodecs`)

---

### 1D. Boost: Minimum Version Bump

**Why:** The docs specify Boost 1.58 but individual build files reference versions as low as 1.52. Several workarounds exist for pre-1.50 and pre-1.58 compatibility that can be removed once the minimum is raised.

**Changes:**
- Raise minimum to Boost 1.58 across all build files
- Remove `util.h` sleep fallback (`#if BOOST_VERSION >= 105000`)
- Remove `walletdb.cpp` copy_file fallback (`#if BOOST_VERSION >= 105800`)
- Update snapcraft to build Boost 1.58+ from source

---

### 1E. LevelDB: Upgrade Bundled Copy

**Why:** The bundled LevelDB (v1.17, circa 2013) has known vulnerabilities including CVE-2018-1000630 (buffer overflow from malformed LDB files).

**Strategy:**
- Replace `src/leveldb/` with a current snapshot from upstream Google LevelDB
- Keep the build integration unchanged (builds as `libleveldb.a`, linked statically)
- The API surface used (`DB::Open/Get/Put/Delete/Write/NewIterator` and `WriteBatch`) is stable and unchanged in modern versions

---

### 1F. Other Dependencies

| Dependency | Action |
|---|---|
| **miniupnpc** (3 API versions supported in `net.cpp:960–1008`) | Bump minimum to 1.8+, remove pre-1.6 compatibility code |
| **libqrencode** (v4.0.2) | Keep unless build issues arise |
| **json_spirit** (embedded) | Keep (stable, no issues) |
| **sphlib / crypto/** (embedded, custom HMQ1725) | Keep (custom algorithm, no upstream) |

---

## Phase 2: Bug Fixes (by Severity)

### CRITICAL

| # | Bug | File:Line | Fix |
|---|---|---|---|
| 1 | **File descriptor leak** — `fopen()` for BDB error log never closed | `src/db.cpp:92` | Store the `FILE*` returned by `fopen()` in a member variable; call `fclose()` in `Close()` / the destructor |
| 2 | **`exit(1)` during wallet encryption** — bypasses all cleanup, can corrupt wallet state | `src/wallet.cpp:305,314` | Replace with `StartShutdown()` to trigger graceful shutdown instead of immediate `exit()` |
| 3 | **`CBigNum` inherits from OpenSSL `BIGNUM`** — C++ object inheriting from C struct is undefined behavior; `BIGNUM` has no virtual destructor | `src/bignum.h:57` | Replace inheritance with composition (private `BIGNUM*` member). The BIGNUM is the first member so addresses coincide as an extension, but this is fragile and non-portable. |
| 4 | **Lock ordering violation** — `cs_wallet` and `cs_KeyStore` can be acquired in different orders in different code paths, creating deadlock potential | `src/keystore.h:18`, `src/crypter.h:131`, `src/wallet.cpp` | Establish a consistent lock ordering (always acquire `cs_wallet` first, then `cs_KeyStore`). Audit all `LOCK()` sites in `wallet.cpp`, `keystore.cpp`, `crypter.cpp`. |
| 5 | **Potential use-after-free** in orphan block processing loop — iterates `mapOrphanBlocksByPrev` while deleting entries from `mapOrphanBlocks`; if `AcceptBlock()` recursively modifies these maps, iterators are invalidated | `src/main.cpp:2253–2268` | Collect items to delete in a separate vector first, then delete them outside the iteration loop |
| 6 | **Integer overflow / precision loss in subsidy calculation** — `std::pow(0.5, ...)` loses precision above 2^53 and can produce incorrect subsidy amounts | `src/main.cpp:963–971` | Replace floating-point halving calculation with integer arithmetic (shift-based division) |
| 7 | **C-style casts removing `const`** in `EncryptSecret`/`DecryptSecret` — casts away const on `vchPlaintext` and passes to functions taking non-const references | `src/crypter.cpp:127,137` | Change `Encrypt`/`Decrypt` signatures to take `const CKeyingMaterial&` (they don't modify the input), remove the casts |

### HIGH

| # | Bug | File:Line | Fix |
|---|---|---|---|
| 8 | **Missing mutex lock** around orphan map access in `ProcessBlock()` — maps `mapOrphanBlocksByPrev`, `mapOrphanBlocks`, `setStakeSeenOrphan` are modified without holding `cs_main` | `src/main.cpp:2247–2270` | Add `LOCK(cs_main)` before accessing or modifying orphan maps |
| 9 | **Thread-unsafe `mapNewBlock`** — acknowledged with `// FIXME: thread safety` comment | `src/rpcmining.cpp:389` | Add a mutex guard around all `mapNewBlock` accesses |
| 10 | **Memory leak in `CDB::Rewrite()` error path** — `new Db()` is leaked if `pdbCopy->open()` fails (line 367) because the cleanup at line 412 is skipped when `fSuccess` is false | `src/db.cpp:359–412` | Wrap `pdbCopy` in a `unique_ptr` (or add an explicit `delete` on the error path) |
| 11 | **`strncpy` does not null-terminate** — if `pszCommand` is >= `COMMAND_SIZE` characters, `pchCommand` will not be null-terminated, causing buffer over-read when used as a C-string | `src/protocol.cpp:33` | Add explicit null termination: `pchCommand[COMMAND_SIZE - 1] = '\0'` or switch to `memcpy` + manual null |
| 12 | **Integer underflow in `CBigNum::getuint64()` and `getuint256()`** — if `vch.size() < 4`, `vch.size()-1` wraps to a huge unsigned value, causing out-of-bounds reads | `src/bignum.h:218–219, 288–289` | Add early-return guard: `if (vch.size() < 4) return 0;` |
| 13 | **Missing virtual destructor in `CScript`** — inherits from `std::vector<unsigned char>` which has no virtual destructor; deleting through base pointer is UB | `src/script.h:292` | Add a virtual destructor or ensure no deletion occurs through base pointers |

### MEDIUM

| # | Bug | File:Line | Fix |
|---|---|---|---|
| 14 | **Unchecked `fopen()` return values** — potential NULL pointer passed to BDB `set_errfile()` or wrapped in `CAutoFile` | `src/db.cpp:92`, `src/net.cpp:1752,1777` | Add NULL checks after `fopen()`; log warning and skip on failure |
| 15 | **`assert()` in production crypto code** — assertions are compiled out in `NDEBUG` builds, allowing NULL/invalid pointers in cryptographic operations | `src/key.cpp:135,144,147,152–158` | Replace with runtime checks: `if (!x) throw std::runtime_error("...");` |
| 16 | **`sprintf` instead of `snprintf`** — hardcoded buffer sizes without bounds checking | `src/uint256.h:304` | Replace with `snprintf` |
| 17 | **Potential use-after-free in `ProcessMessages()`** — `msg` reference (obtained from iterator) is used after the vector element is erased | `src/main.cpp:3400,3486–3487` | Move processing before the erase, or copy data first, then erase |
| 18 | **`printf` in test files instead of `LogPrintf`** — output lacks log timestamps and prefixes | `src/test/key_tests.cpp:35–48` | Replace with `LogPrintf` or Boost.Test macros |

---

## Phase 3: Other Improvements

### Security

- **Directory traversal protection** for `importwallet`/`dumpwallet` RPCs (`src/rpcdump.cpp:170,278`): validate that filenames resolve within the data directory
- **Add BDB runtime version detection** (`db_version()`) and log it at startup
- **Wallet backup before upgrade:** `CDB::Rewrite()` and wallet migration flows must always create `wallet.dat.bak.<timestamp>` before modifying

### Code Quality (C++11 available, `-std=gnu++11`)

- Add `override` keyword on virtual method overrides
- Replace C-style casts with `static_cast<>`, `const_cast<>`, `reinterpret_cast<>`
- Replace `NULL` with `nullptr`
- Use `= default` for trivial destructors instead of empty `{}`
- Replace `BOOST_FOREACH` with range-based `for` (256+ occurrences — scope separately)
- Replace `boost::bind` with lambdas where readability improves

### Build & Housekeeping

- Remove Boost version workarounds for pre-1.50 and pre-1.58 (once minimum is bumped)
- Remove commented-out code blocks (`src/main.cpp:3403–3406,2496–2498`, `src/walletdb.cpp:375–380`)
- Remove the unused `obj/` directory
- Update install docs (`doc/build-unix.txt`, `doc/build-msw.txt`, `doc/build-osx.txt`, `doc/readme-qt.rst`) to reference actual library versions
- Remove `QT_DISABLE_DEPRECATED_BEFORE=0` and set to `0x050000` to surface future deprecation warnings

---

## Proposed Implementation Order

1. **Phase 1E** — LevelDB upgrade (lowest risk, security fix)
2. **Phase 2: Critical #1** — FD leak fix (trivial, prevents resource exhaustion)
3. **Phase 2: Critical #2** — `exit()` → `StartShutdown()` (prevents wallet corruption)
4. **Phase 2: Critical #4** — Lock ordering fix (prevents rare deadlocks)
5. **Phase 2: High #10** — Memory leak in Rewrite error path
6. **Phase 1B** — BDB upgrade + wallet migration path (highest impact, most complex)
7. **Phase 1A** — OpenSSL upgrade (medium complexity, use compat shims)
8. **Phase 1C** — Qt5 deprecated API fixes
9. **Phase 1D** — Boost minimum version bump
10. **Phase 1F** — miniupnpc compatibility cleanup
11. **Phase 2: remaining** — Other bug fixes
12. **Phase 3** — Improvements

---

## Wallet Upgrade Path Detail (BDB Migration)

This is the highest-risk change. The plan is designed so no wallets are lost:

```
At startup:
 1. Detect linked BDB version via db_version()
 2. Try to open wallet.dat normally
 3. If open fails with a version mismatch:
    a. Copy wallet.dat → wallet.dat.bak.<timestamp>
    b. Log the detected version mismatch
    c. Open the database with DB_CREATE
    d. Call existing CDB::Rewrite() — this reads every key-value pair
       via cursor and writes them into a fresh database file. Since it
       operates at the serialized data level (not BDB's internal page
       format), it works across BDB versions.
    e. If Rewrite succeeds: rename new file over wallet.dat
    f. If Rewrite fails: restore from backup, log error
    g. Log completion of version upgrade
 4. Additionally provide --upgrade-wallet CLI flag for manual forcing
```

The key insight is that `CDB::Rewrite()` already exists and provides a robust version-neutral migration mechanism. Bitcoin Core used the same approach historically when moving between BDB versions.

---

## Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| BDB upgrade corrupts wallet | Always backup before upgrade; test with copy of real wallet first |
| OpenSSL 1.1.x API changes break ECDSA | `#if OPENSSL_VERSION_NUMBER` compat shims during transition |
| Qt5 deprecated API cleanup introduces UI bugs | Manual testing of all 15+ dialogs after changes |
| Boost version bump breaks snap builds | Build Boost from source in snapcraft.yaml |
| LevelDB API differences in new version | Keep API usage minimal (basic Get/Put/Delete/Iterator only); no comparator or env customization |
| `CBigNum` refactor introduces subtle math errors | Extensive testing with known test vectors for key generation, signing, and BIP32 derivation |
