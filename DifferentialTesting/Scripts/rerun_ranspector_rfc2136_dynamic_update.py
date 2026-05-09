#!/usr/bin/env python3
"""Run and summarize the RANSpector RFC 2136 dynamic-update corpus.

The script is self-contained inside the Ferret repository. It copies the
canonical 169-test corpus into a fresh run directory, executes Ferret, compares
the observed divergent and non-divergent tests with the bundled expected
post-Technitium-fix summary, and writes a compact rerun summary JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


IMPLEMENTATION_FLAGS = ['-n', '-p', '-c', '-m', '-t']
EXPECTED_TOTAL_TESTS = 169


def differential_testing_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_corpus_dir() -> Path:
    return differential_testing_root() / 'CustomTests' / 'RANSpectorRFC2136DynamicUpdate'


def default_expected_summary() -> Path:
    return default_corpus_dir() / 'ExpectedResults' / 'dns_gap_run_update_after_technitium_fix_divergences.json'


def default_run_dir() -> Path:
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return differential_testing_root() / 'Runs' / f'ranspector_rfc2136_dynamic_update_{stamp}'


def load_json(path: Path) -> Any:
    with path.open() as handle:
        return json.load(handle)


def prepare_run_dir(source: Path, run_dir: Path, overwrite: bool) -> None:
    if run_dir.exists():
        if not overwrite:
            raise SystemExit(f'Run directory already exists: {run_dir}. Use --overwrite or choose another --run-dir.')
        shutil.rmtree(run_dir)

    run_dir.mkdir(parents=True)
    for dirname in ['Queries', 'ZoneFiles', 'ExpectedDivergence', 'ExpectedResults']:
        src = source / dirname
        if src.exists():
            shutil.copytree(src, run_dir / dirname)

    readme = source / 'README.md'
    if readme.exists():
        shutil.copy2(readme, run_dir / 'README.md')


def run_command(cmd: list[str], cwd: Path, log_path: Path, env: dict[str, str] | None = None) -> None:
    print(f'Running: {" ".join(cmd)}')
    print(f'  cwd: {cwd}')
    print(f'  log: {log_path}')
    if env and env.get('FERRET_TECHNITIUM_ZONE_LOAD_METHOD'):
        print(f'  FERRET_TECHNITIUM_ZONE_LOAD_METHOD={env["FERRET_TECHNITIUM_ZONE_LOAD_METHOD"]}')
    with log_path.open('w') as log:
        subprocess.run(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, text=True, check=True)


def case_names_from(directory: Path) -> set[str]:
    if not directory.exists():
        return set()
    return {path.stem for path in directory.glob('*.json')}


def expected_divergent_names(expected_summary: Path | None) -> set[str]:
    if expected_summary is None or not expected_summary.exists():
        return set()
    data = load_json(expected_summary)
    return {case['ferret_test_name'] for case in data.get('true_divergences_after_technitium_fix', [])}


def expected_nondivergent_names(expected_summary: Path | None) -> set[str]:
    if expected_summary is None or not expected_summary.exists():
        return set()
    data = load_json(expected_summary)
    return {case['ferret_test_name'] for case in data.get('nondivergent_after_technitium_fix', [])}


def expected_divergence_count(expected_summary: Path | None) -> int | None:
    if expected_summary is None or not expected_summary.exists():
        return None
    data = load_json(expected_summary)
    summary = data.get('summary', {})
    return summary.get('divergence_count_after_technitium_fix')


def update_reply_rcode(step: dict[str, Any]) -> str | None:
    reply = step.get('NormalizedReply') or step.get('normalized_reply') or {}
    return reply.get('rcode')


def technitium_update_nxrrset_cases(transcripts_dir: Path) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    if not transcripts_dir.exists():
        return cases

    for transcript_path in sorted(transcripts_dir.glob('*.json')):
        try:
            transcript = load_json(transcript_path)
        except json.JSONDecodeError:
            continue
        technitium = transcript.get('Implementations', {}).get('technitium')
        if not technitium:
            continue
        for step in technitium.get('steps', []):
            if step.get('Kind') != 'UPDATE':
                continue
            if update_reply_rcode(step) == 'NXRRSET':
                cases.append(
                    {
                        'ferret_test_name': transcript_path.stem,
                        'update_step': step.get('StepId', ''),
                    }
                )
    return cases


def summarize_run(run_dir: Path, expected_summary: Path | None, technitium_zone_load_method: str) -> dict[str, Any]:
    all_tests = case_names_from(run_dir / 'Queries')
    divergent = case_names_from(run_dir / 'Differences')
    load_failures = case_names_from(run_dir / 'LoadFailures')
    nondivergent = all_tests - divergent - load_failures
    expected_divergent = expected_divergent_names(expected_summary)
    expected_nondivergent = expected_nondivergent_names(expected_summary)
    nxrrset_cases = technitium_update_nxrrset_cases(run_dir / 'Transcripts')

    comparison = {}
    if expected_divergent:
        comparison = {
            'extra_divergent_cases': sorted(divergent - expected_divergent),
            'missing_divergent_cases': sorted(expected_divergent - divergent),
            'unexpected_nondivergent_cases': sorted(nondivergent - expected_nondivergent) if expected_nondivergent else [],
        }

    return {
        'run_dir': str(run_dir),
        'expected_summary': str(expected_summary) if expected_summary else None,
        'technitium_zone_load_method': technitium_zone_load_method,
        'summary': {
            'total_dynamic_update_tests': len(all_tests),
            'divergence_count': len(divergent),
            'nondivergence_count': len(nondivergent),
            'load_failure_count': len(load_failures),
            'technitium_update_nxrrset_count': len(nxrrset_cases),
        },
        'divergent_cases': sorted(divergent),
        'nondivergent_cases': sorted(nondivergent),
        'load_failure_cases': sorted(load_failures),
        'technitium_update_nxrrset_cases': nxrrset_cases,
        'comparison_to_expected': comparison,
    }


def main() -> int:
    root = differential_testing_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, default=default_corpus_dir(), help='Canonical corpus directory.')
    parser.add_argument('--run-dir', type=Path, default=None, help='Fresh output directory for this rerun.')
    parser.add_argument('--overwrite', action='store_true', help='Delete and recreate --run-dir if it already exists.')
    parser.add_argument('--container-id', default='1', help='Ferret -id value used to derive container names and ports.')
    parser.add_argument('--expected-summary', type=Path, default=default_expected_summary())
    parser.add_argument('--expect-total', type=int, default=EXPECTED_TOTAL_TESTS)
    parser.add_argument('--expect-divergences', type=int, default=None)
    parser.add_argument('--no-assert-expected', action='store_true', help='Do not fail if observed counts differ.')
    parser.add_argument(
        '--technitium-zone-load-method',
        choices=['update', 'import', 'api'],
        default='update',
        help=(
            'How Ferret seeds Technitium zone-file records. update uses RFC2136 UPDATE; '
            'import uses Technitium zone-file import; api preserves the older per-record loader.'
        ),
    )
    parser.add_argument('--skip-ferret', action='store_true', help='Reuse existing artifacts in --run-dir.')
    args = parser.parse_args()

    run_dir = (args.run_dir or default_run_dir()).resolve()
    corpus_dir = args.corpus_dir.resolve()
    expected_summary = args.expected_summary.resolve() if args.expected_summary else None

    if not args.skip_ferret:
        prepare_run_dir(corpus_dir, run_dir, args.overwrite)
        env = os.environ.copy()
        env['FERRET_TECHNITIUM_ZONE_LOAD_METHOD'] = args.technitium_zone_load_method
        run_command(
            [
                sys.executable,
                '-m',
                'Scripts.test_with_valid_zone_files',
                '-path',
                str(run_dir),
                '-id',
                str(args.container_id),
                *IMPLEMENTATION_FLAGS,
            ],
            root,
            run_dir / 'ferret.log',
            env=env,
        )
    elif not run_dir.exists():
        raise SystemExit(f'--skip-ferret requires an existing --run-dir: {run_dir}')

    result = summarize_run(run_dir, expected_summary, args.technitium_zone_load_method)
    summary_path = run_dir / 'ranspector_rfc2136_dynamic_update_summary.json'
    summary_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary'], indent=2))
    print(f'Summary JSON: {summary_path}')

    if not args.no_assert_expected:
        observed_total = result['summary']['total_dynamic_update_tests']
        observed_divergences = result['summary']['divergence_count']
        expected_divergences = args.expect_divergences
        if expected_divergences is None:
            expected_divergences = expected_divergence_count(expected_summary)

        if args.expect_total is not None and observed_total != args.expect_total:
            raise SystemExit(f'Expected {args.expect_total} total tests, saw {observed_total}')
        if expected_divergences is not None and observed_divergences != expected_divergences:
            nx_count = result['summary']['technitium_update_nxrrset_count']
            detail = ''
            if nx_count:
                detail = f' Technitium returned NXRRSET in {nx_count} UPDATE replies; inspect {summary_path}.'
            raise SystemExit(f'Expected {expected_divergences} divergences, saw {observed_divergences}.{detail}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
