# Active PMORG test suite

Run the active PMORG suite from the repository root with:

```bash
python3 -m unittest discover -s pmorg/tests -t . -p 'test_*.py'
```

The explicit top-level directory makes `pmorg.tests.load_tests` part of discovery.
That hook derives active CI seam protectors from
`pmorg/policies/seam-allowlist.json` and excludes only CI protector modules that
are no longer referenced by an active seam.

Retired protector files remain byte-identical historical evidence. Running
discovery without `-t .` bypasses the package hook and incorrectly executes
those frozen historical assertions against the current tree, so that form is
not an acceptance command.

The hook does not suppress non-protector modules, active protector modules, or
collection errors. Its exact active and retired sets are pinned by
`pmorg/tests/test_active_suite_discovery.py`.
