# Tools

The same engine as [MTDF-Detection-Tests](https://github.com/azdabat/MTDF-Detection-Tests), plus the threat-format tools.

## Threat format

| Script | Job |
|---|---|
| `new_threat.py` | Start `threats/<slug>/` from the template |
| `add_detection.py` | Add a rule to a threat: lab build + `detection.yml` (+ its test, once the capture exists) |
| `add_capture.py` | Register a lab capture: store it in `telemetry/`, write its metadata, build every test that uses it |
| `validate_threats.py` | The format gate: every threat has the same parts and a consistent matrix |
| `build_threat_docs.py` | Generate every threat README (matrix, kill chain, detections, telemetry), the index and ATT&CK layers |
| `threatkit.py` | The threat format in code, shared by the scripts above |

## Engine

| Script | Job |
|---|---|
| `lint_kql.py` / `fix_kql.py` | Find / mechanically fix the MTDF bug classes ([bug taxonomy](../docs/bug-taxonomy.md)) |
| `semantic_check.py` | Compile every rule, test query and **hunting query in the docs** with Microsoft's Kusto language service against the Defender schema |
| `run_tests.py` | Run every test on a Kusto engine: PASS / FAIL / KNOWN; `-k` filter, `--out` a paste-ready query |
| `promote.py` | experimental → stable for tests that passed |
| `prod_build.py` | Restore production lookbacks from the `// LAB:` markers |
| `tenant_setup.py` / `ingest_to_adx.py` / `hunt_all.py` | Defender-shaped local tenant, load all telemetry, run every rule over it |
| `mordor_to_mde.py` / `mde_mapping.py` / `sysmon_to_mde.py` | Sysmon (lab captures or OTRF) → Defender tables, with acting-process enrichment |
| `lab_build.py` | Widen `ago()` windows for historical captures, each change marked |
| `Export-SysmonWindow.ps1` | Export a Sysmon time window to JSON on a lab VM |
| `kql_testkit.py` | Defender schema, datatable builder, Kusto REST client, assertions |
