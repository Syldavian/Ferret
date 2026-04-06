# RFC 2136 Dynamic Update Support in Ferret

## Summary

Ferret now supports state-changing authoritative tests by extending the existing `ZoneFiles/ + Queries/ + Docker execution + Differences/ + triage` pipeline rather than introducing a separate harness.

The initial zone is still loaded exactly as before. The new behavior is that a `Queries/<test>.json` file may describe an ordered scenario with one or more RFC 2136 `UPDATE` steps followed by ordinary DNS queries used to observe post-update state. The runner executes those steps against one live authoritative instance per implementation and compares both the update replies and the later observations.

Phase 1 support is intentionally narrow:

- Dynamic update is enabled only for `bind` and `knot`
- Authentication is modeled but only `Auth.Mode = "none"` is implemented
- UPDATE transport is `udp` only
- Final state is compared via normalized follow-up query observations rather than AXFR/IXFR

## Scenario Schema

Legacy query lists still work. The canonical format is:

```json
{
  "Mode": "DynamicUpdate",
  "Origin": "campus.edu.",
  "Auth": {"Mode": "none"},
  "Category": "add_rr_absent",
  "Steps": [
    {
      "Id": "u1",
      "Kind": "UPDATE",
      "Transport": "udp",
      "Prerequisites": [],
      "Operations": [
        {"Kind": "add_rr", "Rr": "added.campus.edu. 500 IN A 198.51.100.7"}
      ]
    },
    {
      "Id": "q1",
      "Kind": "QUERY",
      "Name": "added.campus.edu.",
      "Type": "A",
      "Normalize": "message",
      "IgnoreTTL": true
    }
  ]
}
```

Supported prerequisite kinds:

- `rrset_exists`
- `rrset_equals`
- `rrset_absent`
- `name_in_use`
- `name_absent`

Supported operation kinds:

- `add_rr`
- `delete_rr`
- `delete_rrset`
- `delete_name`

## Execution Model

For each test case:

1. Load the initial zone file into each enabled implementation.
2. Wait for SOA readiness.
3. Execute the scenario steps in order.
4. For `UPDATE`, build a `dnspython` `dns.update.Update` message and send it over UDP.
5. For `QUERY`, send an ordinary authoritative query over UDP.
6. Record a transcript per implementation in `Transcripts/<test>.json`.
7. Compare observable behavior across implementations and emit grouped divergences in `Differences/<test>.json`.

The runner will restart a container only before any UPDATE has been sent. Once a stateful step has executed, transport failures abort that implementation's remaining steps instead of resetting state.

## Normalization and Differential Oracle

Dynamic update differences are based on:

- Normalized UPDATE reply outcome (`rcode`, relevant flags, timeout/error)
- Normalized post-state observation vectors

Query observations ignore TTL by default and compare sections as unordered RR collections. Message IDs are never part of the oracle.

Each dynamic divergence is classified as one of:

- `reply_only`
- `post_state_only`
- `reply_and_post_state`

## Fingerprinting

Dynamic update fingerprints combine:

- scenario category
- prerequisite shape
- operation shape
- divergence kind
- reply grouping signature
- post-state grouping signature

This reduces many individual scenario failures to a smaller set of likely root causes while keeping the raw transcripts available for debugging.

## Files Added or Changed

- `Scripts/dynamic_update.py`
- `Scripts/test_with_valid_zone_files.py`
- `Scripts/triaging.py`
- `Scripts/generate_dynamic_update_tests.py`
- `Implementations/Bind/prepare.py`
- `Implementations/Knot/prepare.py`

## Seed Scenarios

The handcrafted generator emits these canonical dynamic update scenarios into `ferret_tests/`:

- `test_100_dynamic_update_add_rr_absent`
- `test_101_dynamic_update_delete_existing_rr`
- `test_102_dynamic_update_delete_missing_rr`
- `test_103_dynamic_update_delete_rrset`
- `test_104_dynamic_update_prereq_name_in_use_add`
- `test_105_dynamic_update_prereq_name_absent_rejects`
- `test_106_dynamic_update_duplicate_add_retry`
- `test_107_dynamic_update_delete_name`

The existing mixed-case prerequisite scenario `test_002_prerequisite_matching_rdata_canonicalization_and_c` has also been migrated to the canonical schema and now includes explicit post-update observation queries.
