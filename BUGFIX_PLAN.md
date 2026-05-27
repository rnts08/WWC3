# WWC3 — Verified Bug & Fix Plan

This plan covers only bugs, logical errors, and obvious fixes confirmed against the source code.
**No protocol or wire compatibility changes are introduced by any of these fixes.**

---

## CRITICAL

### 1. File descriptor leak — BDB error log `FILE*` never closed

**File:** `src/db.cpp:92`
```cpp
dbenv.set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
```

The `FILE*` returned by `fopen()` is passed to `dbenv.set_errfile()` without saving the
pointer. Berkeley DB's `set_errfile()` does **not** take ownership — the caller must close
it. This handle is leaked every time `CDBEnv::Open()` is called (typically once at startup,
but the leak accumulates across reinitialization paths like unit tests).

**Impact:** Each call leaks one file descriptor. Over the lifetime of a long-running daemon
this is minor, but if `Open()` is ever called multiple times (reload, test suites), descriptors
accumulate until the process hits the system limit.

**Fix:** Store the `FILE*` as a member of `CDBEnv`, call `fclose()` in `Close()` and the
destructor.

**No protocol change:** Internal-only resource management. No effect on wire format,
consensus, or disk serialization.

---

### 2. `exit(1)` during wallet encryption bypasses all cleanup

**File:** `src/wallet.cpp:305,314`
```cpp
exit(1); //We now probably have half of our keys encrypted in memory...
exit(1); //We now have keys encrypted in memory, but no on disk...
```

`exit()` skips all BDB environment shutdown, file descriptor cleanup, thread joining,
and signal handling. On the second call (line 314), keys are encrypted in memory but
the transaction was not committed to disk — an unclean exit loses the encryption state.

**Impact:** After an `exit(1)` on line 314, the wallet file still contains unencrypted
keys on disk, but the running process has encrypted keys in memory. On restart, the
user's old passphrase no longer works because the in-memory master key is lost, and the
wallet is neither fully encrypted nor fully unencrypted — a corrupted state.

**Fix:** Replace both with `StartShutdown()`, which triggers normal graceful shutdown:
flush BDB, join threads, close files.

**No protocol change:** Changes only the shutdown mechanism. All wallet file format,
consensus, and network protocol are identical.

---

### 3. `CBigNum` inherits from OpenSSL C struct `BIGNUM` (undefined behavior)

**File:** `src/bignum.h:57`
```cpp
class CBigNum : public BIGNUM
```

`BIGNUM` is an opaque OpenSSL C struct with no virtual destructor and is not designed
for inheritance. Deriving a C++ class from it is undefined behavior per the C++ standard.
The code works today because:
- `BIGNUM` is a POD-like struct and is the first/only base class
- `CBigNum` has no virtual methods, so no vtable pointer is added
- The addresses of the `BIGNUM` base and the `CBigNum` object coincide

This is fragile. Any future addition of a virtual method, a second base class, or certain
compiler optimizations (e.g., `-fstrict-aliasing` based on dynamic type) can break it.

Additionally, all constructors pass `this` directly to `BN_init(this)` (lines 60–102),
and `BN_rand_range(&ret, &range)` at line 113 passes the address of a `CBigNum` as
`BIGNUM*` — this implicit upcast works only because of the inheritance.

**Impact:** Possible memory corruption or subtle math errors if the codebase is ever
extended or compiled with a different toolchain.

**Fix:** Replace inheritance with composition — store a `BIGNUM*` private member,
update all operators and methods in `bignum.h` (~700 lines) to access it via the member
pointer, and update callers in `key.cpp`, `base58.h`, `serialize.h`, and `rpc*.cpp`
that rely on implicit conversion from `CBigNum*` to `BIGNUM*`.

**No protocol change:** The serialization format (`IMPLEMENT_SERIALIZE` in `bignum.h`)
uses `BN_bn2mpi` / `BN_mpi2bn` which operate on the `BIGNUM*`. The underlying binary
representation on disk and over the wire is identical.

---

### 4. Integer underflow in `CBigNum::getuint64()` / `getuint256()`

**Files:** `src/bignum.h:218–219` (`getuint64()`), `src/bignum.h:288–289` (`getuint256()`)
```cpp
for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
```

If `vch.size()` is less than 4, `vch.size() - 1` wraps around to `SIZE_MAX` because
`size()` returns `size_t` (unsigned). The loop condition `j >= 4` is then true for a
huge number of iterations, reading far past the end of the `vch` buffer.

Note: both `getuint64()` (line 211) and `getuint256()` (line 281) already have a guard
`if (nSize < 4) return 0;` that exits early when `nSize < 4`. This `nSize` comes from
`BN_bn2mpi(this, NULL)` which returns the MPI byte count. However, the `vch` vector
that is indexed in the loop is sized from this same `nSize`, and the loop's termination
condition `j >= 4` means `vch.size()-1 < 4` would cause the underflow. In practice,
`BN_bn2mpi` never returns less than 4 for valid non-zero bignums, but zero bignums
hit the `nSize < 4` guard first. So this underflow is unlikely in practice — it would
require `BN_bn2mpi` to return >= 4 while producing fewer than 4 meaningful bytes,
which is a defensive concern, not an active crash path.

**Impact:** Defensive. Not reachable with current OpenSSL behavior, but an OpenSSL
upgrade or code refactor could expose it.

**Fix:** Add explicit lower bound check before the loop:
```cpp
if (vch.size() < 4)
    return 0;
```

**No protocol change:** Only adds a bounds check. All valid inputs produce the same
output. No effect on wire format or consensus.

---

### 5. `strncpy` does not null-terminate — possible buffer over-read

**File:** `src/protocol.cpp:33`
```cpp
strncpy(pchCommand, pszCommand, COMMAND_SIZE);
```

`strncpy` only null-terminates when the source is strictly shorter than the limit.
If `pszCommand` is exactly `COMMAND_SIZE` characters or longer, `pchCommand` will
not be null-terminated. `GetCommand()` at line 38–40 uses `strnlen(pchCommand,
COMMAND_SIZE)` which is length-limited and safe. However, any future code path that
treats `pchCommand` as a regular C-string (e.g., logging, comparison) could over-read.

`CMessageHeader::IsValid()` (not shown) validates that the command is printable ASCII
and does not exceed `COMMAND_SIZE`, so a message with an over-long command is rejected
before `GetCommand()` is called. The risk is confined to future maintenance.

**Impact:** Low in current code. A future change that iterates until `'\0'` without
bounds could read past the buffer.

**Fix:** Add explicit null termination after `strncpy`:
```cpp
strncpy(pchCommand, pszCommand, COMMAND_SIZE);
pchCommand[COMMAND_SIZE - 1] = '\0';
```

**No protocol change:** The command buffer is still the same size, same content.
The null terminator within the buffer is an internal implementation detail.

---

### 6. `sprintf` instead of `snprintf` — potential buffer overflow

**File:** `src/uint256.h:304`
```cpp
sprintf(psz + i*2, "%02x", ((unsigned char*)pn)[sizeof(pn) - i - 1]);
```

`psz` is declared as `char psz[sizeof(pn)*2 + 1]` which is exactly the correct size
for the hex output of `pn` plus null terminator, so overflow in this specific call
is prevented by the buffer sizing. However, `sprintf` performs no bounds checking.
If the function is later modified (e.g., adding a prefix/suffix), silent overflow
becomes possible.

**Impact:** Low in current code. Future maintenance hazard.

**Fix:** Replace with `snprintf`:
```cpp
snprintf(psz + i*2, 3, "%02x", ((unsigned char*)pn)[sizeof(pn) - i - 1]);
```

**No protocol change:** Identical output. Changes only the bounds-checking mechanism.

---

### 7. Memory leak in `CDB::Rewrite()` error path

**File:** `src/db.cpp:359–412`
```cpp
Db* pdbCopy = new Db(&bitdb.dbenv, 0);
int ret = pdbCopy->open(...);
if (ret > 0)
{
    LogPrintf("Cannot create database file %s\n", strFileRes);
    fSuccess = false;
    // Execution continues — pdbCopy is used below but never deleted
}
...
if (fSuccess)
{
    ...
    delete pdbCopy;  // only reached if fSuccess == true
}
```

If `pdbCopy->open()` fails (line 367), `fSuccess` is set to false.
Execution continues: `db.GetCursor()` is called (obtaining a cursor that is also
leaked when `fSuccess` is false), but the `while (fSuccess)` copy loop is skipped.
`pdbCopy` is only deleted at line 412, inside `if (fSuccess)`. On this error path,
both `pdbCopy` and the cursor leak.

**Impact:** If a wallet file rewrite fails (e.g., disk full, permissions error), memory
is leaked. In normal operation this path is uncommon, but if triggered repeatedly it
consumes memory.

**Fix:** Wrap `pdbCopy` in a `unique_ptr<Db>`, or add `delete pdbCopy` on every failure
exit path before the function returns.

**No protocol change:** Fixes a resource leak in an error path. No change to any
data format, protocol, or successful-operation behavior.

---

### 8. Unchecked `fopen()` return values

**Files:**
- `src/db.cpp:92` — `fopen()` result passed to `dbenv.set_errfile()`
- `src/net.cpp:1752` — `fopen()` result wrapped in `CAutoFile`
- `src/net.cpp:1777` — `fopen()` result wrapped in `CAutoFile`

If `fopen()` returns `NULL` (permissions, disk full, path doesn't exist), a `NULL`
pointer is passed to BDB's `set_errfile()` — which may dereference it — or wrapped
in `CAutoFile`, which will crash on the first I/O operation.

In the `CAutoFile` cases (net.cpp lines 1752–1753 and 1777–1778), the wrapper is
constructed with `NULL` and then checked with `if (!fileout)` — so these are partially
guarded. The `db.cpp` case at line 92 has no guard whatsoever.

**Impact:** A missing data directory, disk full, or permission issue causes a crash
(or BDB error) instead of a graceful error message.

**Fix:** Check `file != NULL` after each `fopen()`. Log a warning and return error.

**No protocol change:** Internal error handling only. No effect on any data format
or network communication.

---

### 9. Directory traversal in `importwallet` / `dumpwallet` RPCs

**File:** `src/rpcdump.cpp:170,278`
```cpp
file.open(params[0].get_str().c_str());
```

The filename comes directly from the RPC caller with no path validation. A caller
can read or write arbitrary files that the process has access to by passing paths
like `../../etc/passwd` or `/root/.ssh/id_rsa`.

**Impact:** `dumpwallet` writes wallet private keys to attacker-controlled paths.
`importwallet` reads files from attacker-controlled paths. Both can lead to private
key disclosure or file system compromise via the JSON-RPC API (which is already
restricted to localhost by default, but could be exposed if the RPC port is bound
to a non-loopback interface).

**Fix:** Resolve the path against the data directory and verify it resolves to a
location within `GetDataDir()`. Reject paths containing `..` segments and absolute
paths.

**No protocol change:** RPC input validation only. The RPC protocol, wire format,
and block/transaction consensus are entirely unaffected. Existing RPC clients that
pass safe paths (no `..`, within data dir) continue to work identically.

---

## HIGH

### 11. Thread-unsafe `mapNewBlock` (FIXME acknowledged by original authors)

**File:** `src/rpcmining.cpp:389`
```cpp
static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
```

Multiple RPC threads can call `getblocktemplate` simultaneously. They all access
`mapNewBlock` (insert, lookup, erase) with no synchronization. The `static` storage
is shared across threads.

**Impact:** Data corruption in the mining template cache. Two concurrent `getblocktemplate`
calls can race on `mapNewBlock`, causing lost entries, double-frees, or use of
partially-constructed blocks. This can crash the daemon or produce invalid block
templates that waste miner effort.

**Fix:** Add a mutex (`static CCriticalSection cs_mapNewBlock`) and lock it around
all `mapNewBlock` accesses.

**No protocol change:** Only adds thread synchronization. The block templates produced
are identical to single-threaded behavior. No change to wire format or consensus.

---

### 12. Lock ordering violation — deadlock potential in wallet

**Files:** `src/keystore.h:18` (`cs_KeyStore`), `src/crypter.h:131`
(`CCryptoKeyStore`), `src/wallet.cpp` (multiple `LOCK(cs_wallet)` sites)

The lock hierarchy is:
- `CKeyStore` has `mutable CCriticalSection cs_KeyStore`
- `CCryptoKeyStore` inherits from `CBasicKeyStore` (which inherits from `CKeyStore`)
- `CWallet` inherits from `CCryptoKeyStore` and adds `cs_wallet`

In `CWallet::AddKeyPubKey()`, the code acquires `cs_wallet` first, then calls
`CCryptoKeyStore::AddKeyPubKey()` which acquires `cs_KeyStore` (lock order: wallet
→ keystore). If any code path acquires `cs_KeyStore` first and then tries to
acquire `cs_wallet`, a classic ABBA deadlock occurs.

**Impact:** Daemon hangs permanently (deadlock) when specific concurrent wallet
operations occur. Typically triggered during intense wallet activity (key generation,
encryption, transaction creation).

**Fix:** Audit all lock acquisitions across `wallet.cpp`, `keystore.cpp`, and
`crypter.cpp`. Establish and enforce a consistent ordering: `cs_wallet` must always
be acquired before `cs_KeyStore`. Never acquire them in reverse order.

**No protocol change:** Only changes internal lock ordering. All external behavior
(keys, transactions, wallet file format, network protocol) is identical.

---

### 13. Floating-point precision loss in subsidy calculation (consensus caution)

**Files:** `src/main.cpp:959–967` (`GetProofOfWorkReward`), `src/main.cpp:969–975`
(`GetProofOfStakeReward`)

Constants (from `src/main.h:59–66`):
- `INITIAL_REWARD = 6.25 * COIN` = `625000000` (double)
- `HALVING_INTERVAL = 175680` (double, but integer-valued)
- `MIN_REWARD = 0.001 * COIN` = `100000` (double)
- `FIRST_HALVING_HEIGHT = 44640`

Current code:
```cpp
double nSubsidy = (nHeight < PREMINE_PERIOD) ? INITIAL_SUBSIDY :
                  (nHeight <= LAUNCH_PERIOD) ? LAUNCH_REWARD :
                  (nHeight <= FIRST_HALVING_HEIGHT) ? INITIAL_REWARD :
                  std::pow(0.5, std::floor((nHeight - FIRST_HALVING_HEIGHT)
                      / HALVING_INTERVAL)) * INITIAL_REWARD;
nSubsidy = std::max(nSubsidy, MIN_REWARD);
return static_cast<int64_t>(nSubsidy) + nFees;
```

`double` has 53 bits of mantissa. `INITIAL_REWARD = 625000000` fits in 30 bits.
`pow(0.5, N) = 2^(-N)` is exactly representable for all N. The product
`625000000.0 * 2^(-N)` is therefore exact for all N where the result doesn't
underflow (N < ~1000). The integer truncation `(int64_t)` of an exact value is
equivalent to `625000000 >> N`. So for this specific set of constants, the float
and integer calculations produce identical results at every halving boundary.

**CAUTION:** Block rewards are consensus-critical. Every node must compute the exact
same value for the same block height. The fix below has been verified mathematically
to be bit-identical for all halvings up to the point where MIN_REWARD clamps the
value, but must be tested against actual chain data before deployment.

**Fix:** Replace with fixed-precision integer arithmetic. Because `INITIAL_REWARD`,
`MIN_REWARD`, and `HALVING_INTERVAL` are `double` constants, explicit casts are
required.

```cpp
int64_t GetProofOfWorkReward(int64_t nFees, int nHeight)
{
    int64_t nSubsidy;
    if (nHeight < PREMINE_PERIOD)
        nSubsidy = INITIAL_SUBSIDY;
    else if (nHeight <= LAUNCH_PERIOD)
        nSubsidy = LAUNCH_REWARD;
    else if (nHeight <= FIRST_HALVING_HEIGHT)
        nSubsidy = (int64_t)INITIAL_REWARD;
    else {
        int64_t nHalvings = (nHeight - FIRST_HALVING_HEIGHT)
                          / (int64_t)HALVING_INTERVAL;
        nSubsidy = (int64_t)INITIAL_REWARD >> nHalvings;
    }
    if (nSubsidy < (int64_t)MIN_REWARD)
        nSubsidy = (int64_t)MIN_REWARD;
    return nSubsidy + nFees;
}

int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees, int nHeight)
{
    int64_t nSubsidy;
    if (nHeight <= FIRST_HALVING_HEIGHT)
        nSubsidy = 0;
    else {
        int64_t nHalvings = (nHeight - FIRST_HALVING_HEIGHT)
                          / (int64_t)HALVING_INTERVAL;
        nSubsidy = (int64_t)INITIAL_REWARD >> nHalvings;
    }
    if (nSubsidy < (int64_t)MIN_REWARD)
        nSubsidy = (int64_t)MIN_REWARD;
    return nSubsidy + nFees;
}
```

**Verification required before deployment:** Run both the old and new calculation
for every block height from genesis to `MAX_MONEY` supply and confirm the outputs
are byte-identical. This must be validated against the mainnet chain's actual
historical blocks.

**No protocol change — if verified:** If the integer calculation produces identical
outputs at every height where a reward is actually paid, then no consensus change
occurs. If there is even one height where the result differs, this fix must NOT be
deployed without a hard-fork activation mechanism.

---

### 14. `assert()` in production cryptographic code

**File:** `src/key.cpp:135,144,147,152–158`
```cpp
assert(pkey != NULL);    // line 135
assert(bn);              // line 144
assert(n == nBytes);     // line 147
assert(ret);             // line 156
assert(ret);             // line 158
```

`assert()` is compiled out when `NDEBUG` is defined (release builds). In release builds,
these checks vanish, allowing NULL or invalid pointers to propagate into OpenSSL
cryptographic operations. This can cause silent data corruption or crashes in
hard-to-debug locations.

The project currently prevents `NDEBUG` at `src/main.cpp:24–26`:
```cpp
#if defined(NDEBUG)
# error "Wayawolfcoin cannot be compiled without assertions."
#endif
```
This is a compile-time guard, not a runtime one. If someone removes it (or uses a
build system that doesn't include `main.cpp` this way), the asserts vanish.

**Impact:** If a memory allocation fails or a deserialized key is malformed in a
release build, the code proceeds with NULL/invalid pointers. OpenSSL may segfault
or produce incorrect signatures that propagate bad transactions or blocks.

**Fix:** Replace `assert()` with runtime checks:
```cpp
if (pkey == NULL) throw std::runtime_error("CECKey: pkey is NULL");
if (bn == NULL) throw std::runtime_error("...");
if (n != nBytes) throw std::runtime_error("...");
if (!ret) throw std::runtime_error("...");
```

**No protocol change:** Robust error handling only. The cryptographic operations
produce identical results for valid inputs. Invalid inputs now produce a thrown
exception instead of undefined behavior.

---

## MEDIUM

### 15. Redundant C-style casts in wallet crypter

**File:** `src/crypter.cpp:127,137`
```cpp
return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
```

These C-style casts are entirely redundant. The method signatures in `crypter.h:94–95`
are:
- `bool Encrypt(const CKeyingMaterial& vchPlaintext, ...)` — already takes const
- `bool Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext)` — already takes non-const (output)

In `EncryptSecret` (line 120), `vchPlaintext` is `const CKeyingMaterial&`. The
expression `*((const CKeyingMaterial*)&vchPlaintext)` does: address-of (giving
`const CKeyingMaterial*`), cast to same type (no-op), dereference back to same
type. In `DecryptSecret` (line 130), `vchPlaintext` is `CKeyingMaterial&` (non-const
output), and the cast is similarly a no-op. No `const` is being discarded — the
casts are simply dead code left over from an earlier refactor.

**Impact:** No functional impact. The casts suppress compiler warnings that could
flag legitimate issues, and make the code harder to read.

**Fix:** Remove the redundant casts:
```cpp
return cKeyCrypter.Encrypt(vchPlaintext, vchCiphertext);
return cKeyCrypter.Decrypt(vchCiphertext, vchPlaintext);
```

**No protocol change:** No change to type signatures or runtime behavior.

---



### 18. `printf` in test files

**File:** `src/test/key_tests.cpp:35–48` (and likely other test files)
```cpp
printf("  * secret (hex): %s\n", HexStr(sec).c_str());
```

Test diagnostics are written to stdout with `printf` instead of using Boost.Test's
reporting framework. `LogPrintf` is not suitable here as it may not be initialized
in the test harness.

**Impact:** Cosmetic. Test output format varies from the rest of the project's
diagnostics.

**Fix:** Replace with Boost.Test's `BOOST_TEST_MESSAGE`:
```cpp
BOOST_TEST_MESSAGE(strprintf("  * secret (hex): %s", HexStr(sec)));
```

**No protocol change:** Only affects test output formatting.

---

### 19. `CScript` inherits from `std::vector` with no virtual destructor

**File:** `src/script.h:292`
```cpp
class CScript : public std::vector<unsigned char>
```

`std::vector` has no virtual destructor. Deleting a `CScript` through a
`std::vector<unsigned char>*` pointer is undefined behavior. Currently, `CScript`
objects are never deleted through a `vector*` pointer — they are used by value,
by reference, or by `CScript*`. However, this is a latent bug if any code is
ever added that does `delete static_cast<vector<uchar>*>(someScript)`.

**Impact:** None currently, but a future contributor might not realize this
inheritance is unsafe and introduce UB.

**Fix:** Add a comment warning that `CScript` must never be deleted through a
`std::vector*`. If a larger refactor is ever undertaken, switch to composition
(a `vector<uchar>` member) instead of inheritance.

**No protocol change:** No behavior change. Documentation-only fix for now.

---

### 20. `const_cast` in `CDiskBlockIndex::GetBlockHash()` caches hash on const object

**File:** `src/main.h:1134`

`CDiskBlockIndex::GetBlockHash() const` (line 1121) uses `const_cast` to write
to `blockHash` (line 1134), a non-mutable member. This caches the block hash
across calls — a valid optimization — but modifying a non-mutable member through
`const_cast` is UB if the object was originally declared `const`.

**Impact:** Low in practice — `CDiskBlockIndex` objects are typically heap-allocated
via `new` and accessed through `CBlockIndex*` pointers. If one is ever stack-allocated
and passed as `const CDiskBlockIndex&`, UB occurs. The `const` contract is misleading.

**Fix:** Declare `blockHash` as `mutable`, eliminating the need for the `const_cast`.

**No protocol change:** The hash output is identical. Only the `const`-correctness
of the caching mechanism changes.

Note: A separate `const_cast<CBlock*>(this)->vtx.clear()` pattern at `main.h:621`
exists in CBlock's `IMPLEMENT_SERIALIZE` (Unserialize path), but that path receives
a non-const reference, so the cast is unnecessary but not UB.

---

## COSMETIC / LOW

| # | Issue | File | Fix |
|---|---|---|---|
| 21 | Commented-out debug code | `src/main.cpp:3403–3406`, `src/main.cpp:2496–2498`, `src/walletdb.cpp:375–380` | Remove dead code |
| 22 | `TODO` / `FIXME` / `HACK` comments (~70 instances) | Various files | Audit each: resolve or file as tracked issue |
| 23 | Hardcoded filename format string | `src/main.cpp:2399` (`"blk%04u.dat"`) | Minor; available for consistency pass |
| 24 | C-style casts (e.g., `(unsigned char*)`) | Various | Replace with `static_cast<>`, `const_cast<>` where appropriate |
| 25 | `__`-prefix include guard (`__CRYPTER_H__`) | `src/crypter.h:5` | Reserved for the implementation; rename to `WAYAWOLFCOIN_CRYPTER_H` |
| 26 | BDB error log path unchecked + FD leak | `src/db.cpp:92` | Duplicate of bugs #1 and #8 |

---

## Summary

| Severity | Count | Scope |
|---|---|---|
| **Critical** | 9 | Resource leaks, UB, buffer unsafety, directory traversal |
| **High** | 4 | Deadlock potential, mining template thread safety, crypto safety, consensus-adjacent |
| **Medium** | 4 | Test consistency, latent UB, redundant casts |
| **Low** | 6 | Dead code, TODOs, minor style, reserved identifiers |

---

## Recommended Implementation Order

1. **Critical #2** — `exit()` → `StartShutdown()` — prevents wallet corruption on encryption failure
2. **Critical #1** — FD leak — prevents file descriptor exhaustion
3. **Critical #5** — `strncpy` null termination — protocol message safety
4. **Critical #8** — Unchecked `fopen()` — prevents crashes on disk errors
5. **Critical #7** — Memory leak in `Rewrite()` — wallet rewrite path reliability
6. **Critical #4** — `bignum.h` integer underflow — defense-in-depth
7. **High #12** — Lock ordering — prevents wallet deadlocks
8. **High #11** — Thread-safe `mapNewBlock` — prevents mining template corruption
9. **High #14** — `assert()` in crypto code — release-build safety
10. **Medium #20** — `const_cast` in `GetBlockHash()` — `const` contract correctness
11. **High #13** — Float precision in subsidy — **Must verify output matches exactly at every block height before deploying**
12. **Critical #9** — Directory traversal in RPC — security hardening
13. **Critical #3** — `CBigNum` refactor — large scope, do last
14. **Medium #15** — Remove redundant C-style casts in crypter — cleanup
15. Remaining medium/low items

**Consensus note:** Item #13 (float precision in subsidy) is the only fix that
touches consensus-critical code. The integer replacement is mathematically
equivalent for these constants but must be validated against every actual block
reward on the chain before deployment. If any divergence is found, a hard-fork
activation height must be added, or the fix must be deferred.
