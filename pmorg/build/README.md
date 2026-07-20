# PMORG CE source build substrate

This directory defines `1-BUILD-A/B`, the offline source stage of `1-BUILD`.
It provides a byte-reproducible source-artifact builder, a fail-closed input
gate, and a deterministic PMORG-owned CE overlay. The artifact format is an
uncompressed canonical tar archive containing the Community source selection
and an embedded, sorted file manifest.

The stage is deliberately narrower than a runnable image build. It proves the
source input boundary before package installation or image assembly and does
not claim an RBDP, BQM/BQA, admission, release, or `G3-A` verdict. A later
1-BUILD stage may consume this artifact as an input, but must qualify its own
network egress and image-layer reproducibility separately.

## Determinism controls

- input bytes and executable modes are read from one Git tree, never from
  working-tree timestamps or untracked files;
- the spec and overlay are read from that same named Git commit;
- every overlay target is pinned by base/result SHA-256 and non-overlapping
  line spans; any upstream or recipe drift fails closed;
- entries are sorted by UTF-8 path bytes;
- uid/gid, owner/group, mtime and tar format are fixed;
- the embedded manifest uses canonical JSON;
- the builder is standard-library-only and may invoke only local, read-only
  `git rev-parse`, `git ls-tree`, and `git cat-file` operations.

## Gates

```bash
python3 -B -m unittest pmorg.tests.test_ce_build_substrate -v
```

`verify_ce_build.py` scans every PMORG-owned working-tree path and the selected
artifact inputs. It rejects Enterprise path components/imports, exact copied
EE source bytes, unsafe symlinks, undeclared builder egress, or spec drift. It
then builds twice and requires identical SHA-256 digests.

At the end of `1-BUILD-B`, the verifier applies the committed PMORG overlay to
the pinned mixed-source Onyx tree, rejects any remaining Enterprise path,
import or exact-copy evidence, and requires two byte-identical real-tree
rebuilds. This qualifies only the CE source artifact; it does not claim a
runnable image or any RBDP, BQM/BQA, admission, release, or `G3-A` verdict.
