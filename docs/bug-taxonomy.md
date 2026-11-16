# KQL Detection Engineering: Common Implementation Errors

**Author:** Ala Dabat · **Framework:** Minimum Truth Detection Framework (MTDF)
**First edition:** March 2026 (review of 11 composite rules) · **Revised:** November 2026 (lint of 44 rule files and live testing against recorded adversary telemetry)

Each bug class below is enforced by a check in [`tools/lint_kql.py`](../tools/lint_kql.py). The **Lint** column says which.

---

## Why these bugs exist

None of them invalidate the detection logic. They cluster around four root causes:

1. **Baseline design:** prevalence and rarity patterns built once and copied without edge-case hardening.
2. **Join semantics:** multi-table correlation with gaps in how `leftouter` and bins behave.
3. **Schema assumptions:** anchors and columns written for a schema the data does not have (Sysmon vs Defender, `HKLM` vs `HKEY_LOCAL_MACHINE`).
4. **Convergence design:** confidence that grows with event volume rather than with independent evidence.

Classes 1 to 5 came from code review. Classes 6 to 8 were found only by running the rules against real attack telemetry; review missed them, because the queries were valid and simply never matched, or matched too much.

| # | Class | Severity | Found by | Lint |
|---|---|---|---|---|
| 1 | Prevalence window overlap | HIGH | Review | W01 |
| 2 | Null SHA256 false rarity | HIGH | Review | W02 |
| 3 | `leftouter` converted to inner join | CRITICAL | Review, confirmed by test | W03 |
| 4 | `any()` non-determinism | MEDIUM-HIGH | Review | W04 |
| 5 | Negative score floors | LOW | Review | W05 |
| 6 | Dead anchors and phantom columns | CRITICAL (silent) | **Live testing** | E01, E05, W07, W09, W10 |
| 7 | Convergence by event count | HIGH (false positives) | **Benign testing** | - (logic) |
| 8 | Invalid functions and syntax | CRITICAL (rule won't run) | **Lint + engine** | E02, E03, E04, E06 |

---

## Class 1: Prevalence window overlap (HIGH, W01)

A rarity baseline must exclude the active detection window. If the two overlap, an attacker active for two or more days inflates `DeviceSeenDays` / `WriterDeviceCount`, which suppresses the rarity flag on the very intrusion it should escalate.

```kusto
// broken                                         // fixed
| where Timestamp >= ago(RarityLB)                | where Timestamp >= ago(RarityLB) and Timestamp < ago(lookback)
```

**Rule of thumb:** the baseline ends where detection begins.

## Class 2: Null SHA256 false rarity (HIGH, W02)

Built-in binaries often carry no SHA256. The prevalence join returns null, `coalesce(count, 0)` makes it 0, and `count <= 2` marks `powershell.exe` as rare, with a free score boost on every alert.

```kusto
// broken
ChildIsRare = iff(ChildDeviceCount <= 2, 1, 0)
// fixed
ChildIsRare = iff(isnotempty(ChildSHA) and ChildDeviceCount <= 2, 1, 0)
```

**Rule of thumb:** a missing hash is missing telemetry, not rarity.

## Class 3: `leftouter` converted to inner join (CRITICAL, W03)

A `where` on right-side columns after a `leftouter` join drops every left row with no match. The rule then alerts only when reinforcement exists, and the minimum-truth gate becomes meaningless.

**Confirmed by test:** `WmiPrvSE_Secondary_Execution_Victim` filtered on the nearest web connection after its join. On a device that had *any* web traffic outside the window, the Empire WMI attack vanished. Regression test: `detections/lateral_movement/wmiprvse_remote_execution/test_busy_device.yml`.

```kusto
Base
| join kind=leftouter (FileArtifacts) on DeviceId
| extend IsFileMatch = WriterProcessId == ProcessId
                       and abs(datetime_diff("minute", Timestamp, FileTime)) <= NearWindowMins
| summarize
    FileNear     = iff(countif(IsFileMatch) > 0, 1, 0),      // correction, see below
    DroppedFiles = make_set_if(DroppedFile, IsFileMatch, 10),
    arg_max(Timestamp, *)
  by DeviceId, ProcessId
```

> **Correction (Nov 2026):** the first edition used `FileNear = max(toint(IsFileMatch))`. On an unmatched row `IsFileMatch` is null, `max()` over nulls is null, and `25 * FileNear` then turns the whole `RiskScore` null, so the row is dropped by the severity gate. `countif()` ignores nulls and always returns a number.

**Rule of thumb:** after a `leftouter`, flag matches and aggregate; never filter on the right side.

## Class 4: `any()` non-determinism (MEDIUM-HIGH, W04)

Several `any()` pass-throughs in one `summarize` can take each column from a different row. The analyst then sees a command line that doesn't explain the score.

```kusto
// fixed: every column locked to the same source row
| summarize FileNear = iff(countif(IsFileMatch) > 0, 1, 0), arg_max(Timestamp, *) by DeviceId, ProcessId
```

## Class 5: Negative score floors (LOW, W05)

Penalty modifiers can drive a score below zero. The severity gate hides it, but the raw output and downstream consumers see it.

```kusto
| extend BeaconScore = max_of(BeaconScore, 0)
```

## Class 6: Dead anchors and phantom columns (CRITICAL, silent; E01, E05, W07, W09, W10)

The query is valid and runs, but part of it can never match. Nothing errors, and coverage is quietly zero. Only real telemetry exposes it.

| Pattern | Why it never matches | Fix |
|---|---|---|
| Registry anchor `@"hklm\system\..."` | Defender writes `HKEY_LOCAL_MACHINE\...`; Sysmon writes `HKLM\...` | Hive-agnostic: `@"system\currentcontrolset\..."` (E01) |
| `InitiatingProcessSigner` | Not a column in any Defender `Device*` table | `join` `DeviceFileCertificateInfo` on `InitiatingProcessSHA1`, use `Signer` / `IsTrusted` (E05, W10) |
| `AccountName` on `DeviceRegistryEvents` | Not a column of that table | `InitiatingProcessAccountName` (W09) |
| `TargetProcessName` in `DeviceEvents` | Sysmon field name, not Defender | `FileName` / `FolderPath` (E05) |
| `comsvcs.dll` in a list matched against `DeviceProcessEvents.FileName` | `FileName` is the executable, never a DLL | Match `ProcessCommandLine`, or use `DeviceImageLoadEvents` (W07) |

`column_ifexists("InitiatingProcessSigner", "")` stops the crash but leaves the signer logic permanently empty. It is a Class 6 bug in disguise (W10).

**Found by:** `Registry_Persistence_LSA_SecurityProviders`. Both anchors used `hklm\` (one also typo'd `hk lm\`), so the rule could never match a Defender event. Testing against Empire's WDigest downgrade exposed it.

**Rule of thumb:** an anchor is only proven when it has matched real telemetry.

## Class 7: Convergence by event count (HIGH, false positives)

A convergence boost meant to reward *independent* evidence (`SignalCount > 1`) was computed with `count()`. Routine, repeated activity of one signal type (LSASS handle access by `svchost.exe` / `services.exe`) therefore crosses the threshold on its own.

```kusto
// broken                                      // fixed
SignalCount = count()                          SignalTypes = dcount(Technique)
| extend Boost = iff(SignalCount > 1, 15, 0)   | extend Boost = iff(SignalTypes > 1, 15, 0)
```

**Found by:** the benign control for `COMPOSITE_L3_LSASS_CREDENTIAL_THEFT_MASTER`, a capture with no credential theft in it, which the rule scored 65. Tracked as a `known_issue` until fixed: `detections/credential_access/lsass_credential_theft/test_benign.yml`.

**Rule of thumb:** converge on distinct kinds of evidence, never on volume.

## Class 8: Invalid functions and syntax (CRITICAL, the rule won't run; E02, E03, E04, E06)

| Pattern | Problem | Fix |
|---|---|---|
| `base64_decode_string(x)` | Function does not exist | `base64_decode_tostring(x)` (E02) |
| `min(strlen(Cmd), 240)` | `min()` is an aggregation, valid only in `summarize` | `min_of(strlen(Cmd), 240)` (E03) |
| `case(a, "X", b, "Y")` | No default value | Add a final default (E04) |
| `...;` followed by `\| where` | The `;` ends the query and the pipe starts an invalid statement | Remove the `;` (E06) |

> **Correction (Nov 2026):** the first edition recommended `substring(Cmd, 0, min(strlen(Cmd), 240))` and `iif(isnotempty(c), base64_decode_string(c), "")`. Both "fixes" were themselves Class 8 bugs and failed in production; the lint found three copies of the `min()` pattern across the rule set. Kusto's `substring()` tolerates a length past the end of the string, so the guard is optional; if you want it, use `min_of()`.

---

## Rule-specific findings

- **Undefined field:** `HasHive = max(IsHive)` where the column is `IsHiveDump` (LSASS master). Runtime error.
- **Regex escaping:** named-pipe regex with the wrong backslash escaping in a raw string; the `ForkNRunHex` pattern never matched real pipe paths. Validate regex against sample telemetry.
- **Bin boundary:** `BinSize = 5m` with `CorrWindow = 15m` missed events two seconds apart across a bin edge. Setting `BinSize = CorrWindow` **narrows the miss but does not remove it**: two events either side of any bin edge still land in different bins. The complete fix matches each event against its own bin and the previous one (W08):

  ```kusto
  let Right = Events2
      | extend BinTime = range(bin(Timestamp - CorrWindow, CorrWindow), bin(Timestamp, CorrWindow), CorrWindow)
      | mv-expand BinTime to typeof(datetime);
  Events1
  | extend BinTime = bin(Timestamp, CorrWindow)
  | join kind=inner Right on DeviceId, BinTime
  | where abs(datetime_diff("second", Timestamp, Timestamp1)) <= CorrWindow / 1s
  ```
- **HunterDirective after `project`:** define it before `project` and list it explicitly, or later `project` statements drop it.

---

## Portability: the local test engine (not production bugs)

The local Azure Data Explorer emulator (Kustainer) used for testing is stricter than Defender and Sentinel. These conventions run identically everywhere, so MTDF adopts them as house style:

| Convention | Reason | Lint |
|---|---|---|
| `iff(<condition>, 1, 0)` instead of `toint(<condition>)` | The emulator rejects arithmetic on `toint()` of a boolean (`SEM0001`) | P01 |
| One `extend` per dependency layer | The emulator cannot resolve a column used in the same `extend` that defines it | P02 |

---

## Pre-deployment checklist

```bash
python tools/lint_kql.py <rules> --no-port      # ERRORs block; review every WARN
python tools/fix_kql.py <rules> --dry-run --diff   # mechanical fixes, previewed
python tools/run_tests.py -k <detection>           # proves the anchor matches real telemetry
```

A rule is production-ready when it lints clean, **fires on at least one real implementation of the technique, and stays silent on a benign capture.**

## Doctrine reminder

The framework's principle (anchor on what must be true, reinforce with what raises confidence, suppress what is known good) holds across every rule reviewed. These are engineering hardening issues, not design failures, and the only reliable way to find Classes 6 and 7 is to test against real telemetry.
