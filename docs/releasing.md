# Release checklist

1. Confirm all rule additions have original or documented compatible provenance.
2. Update `SOURCES.md`, `CREDITS.md`, and `NOTICE` if references or third-party
   material changed.
3. Run `python3 tools/agentsec.py validate`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Review adapter instructions against supported agent versions.
6. Review changed schemas for backward compatibility and increment the version
   according to `GOVERNANCE.md`.
7. Update `CHANGELOG.md`, tag the release, and publish checksums/SBOM when the
   release process is established.
8. Do not publish real secrets, customer repositories, active-test output, or
   unredacted security reports.
