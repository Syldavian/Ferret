# RANSpector RFC 2136 Dynamic-Update Corpus

This directory contains the 169 unsigned RFC 2136 Dynamic Update tests exported
from RANSpector into Ferret format.

The corpus is self-contained:

- `Queries/`: Ferret dynamic-update scenarios.
- `ZoneFiles/`: authoritative zone fixtures for each scenario.
- `ExpectedDivergence/`: per-test RANSpector scenario rationale.
- `ExpectedResults/`: expected post-Technitium-fix divergent and non-divergent
  case lists.

## Implementations

The corpus is intended to run against the unsigned dynamic-update adapters:

```text
bind, knot, yadifa, technitium
```

The Ferret flags for that set are:

```text
-n -p -c -m -t
```

## Recommended Reproduction Command

From the Ferret `DifferentialTesting/` directory:

```bash
python3 -m Scripts.rerun_ranspector_rfc2136_dynamic_update
```

The wrapper copies this corpus into a timestamped directory under
`DifferentialTesting/Runs/`, runs Ferret, and writes:

```text
ranspector_rfc2136_dynamic_update_summary.json
```

That summary lists:

- all observed divergent tests,
- all observed non-divergent tests,
- load failures,
- Technitium `NXRRSET` UPDATE replies,
- differences from the bundled expected post-fix summary.

By default the wrapper asserts the bundled expected count:

```text
169 total tests
102 divergent tests
67 non-divergent tests
```

Use this while debugging an unfixed or local Technitium build:

```bash
python3 -m Scripts.rerun_ranspector_rfc2136_dynamic_update --no-assert-expected
```

That still runs the same tests and writes the same summary, but it does not fail
when the observed counts differ from the expected post-fix counts.

## Technitium Zone Loading

The wrapper sets `FERRET_TECHNITIUM_ZONE_LOAD_METHOD=update` by default, which
loads fixture records through RFC 2136 UPDATE instead of the older per-record API
loader.

Available modes:

```bash
python3 -m Scripts.rerun_ranspector_rfc2136_dynamic_update --technitium-zone-load-method update
python3 -m Scripts.rerun_ranspector_rfc2136_dynamic_update --technitium-zone-load-method import
python3 -m Scripts.rerun_ranspector_rfc2136_dynamic_update --technitium-zone-load-method api
```

Notes:

- `update` avoids the zone-file/API record-construction path that can leave
  Technitium RDATA length metadata uninitialized on unfixed builds.
- `import` preserves fixture apex records using Technitium zone-file import, but
  it does not avoid that RDLENGTH artifact on unfixed builds.
- `api` preserves the older per-record loader.

## Direct Ferret Command

The raw Ferret command is still available:

```bash
python3 -m Scripts.test_with_valid_zone_files \
  -path CustomTests/RANSpectorRFC2136DynamicUpdate \
  -id 1 \
  -n -p -c -m -t
```

This writes Ferret artifacts directly into this corpus directory:

```text
Differences/
LoadFailures/
Transcripts/
```

Prefer the wrapper for reproducible fresh runs because it keeps the checked-in
corpus untouched.
