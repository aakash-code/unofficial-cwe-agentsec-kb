# CWE source coverage

## Included canonical content

Unofficial CWE AgentSec KB includes the entire official CWE **4.20** XML catalog, downloaded
from MITRE on 2026-10-09 and pinned by SHA-256. Its manifest is at
`data/cwe/4.20/manifest.json`.

| Content type | Included count |
| --- | ---: |
| Weaknesses | 969 |
| Categories | 422 |
| Views | 59 |
| External references | 1,026 |

The catalog preserves all XML attributes, text, and ordered child elements.
That includes descriptions, extended descriptions, alternate terms, affected
resources, consequences, mitigations, detection methods, relationships,
applicable platforms, demonstrative and observed examples, taxonomy mappings,
maintenance notes, content history, views, categories, and references whenever
they are present in the official source.

`index.json` supports compact search. `relationships.json` exposes membership
and related-weakness edges. `catalog.json` is the lossless full-content
representation. The canonical source archive remains in `vendor/cwe/4.20/`.

## Retrieval

```sh
python3 tools/agentsec.py cwe-status
python3 tools/agentsec.py cwe-search "authentication"
python3 tools/agentsec.py cwe-get CWE-287
```

Coding agents should search first, then retrieve only the required entry. They
must not load the entire catalog into a prompt.

## Website material not mirrored

The CWE web application also contains changing news, navigation, videos,
podcasts, cookies/legal pages, and links to third-party material. Those are not
part of the versioned CWE catalog and are not mirrored. Official guidance,
guidelines, and reports outside the XML catalog are registered as source links
in `SOURCES.md`; the project should import any such document only after its
license and update policy are recorded.

This boundary avoids falsely presenting a static repository as a complete mirror
of a live website while preserving the full authoritative weakness knowledge
base that agents need for analysis.

## Updating safely

Download the next official XML ZIP, verify its hash, preserve the release
archive under `vendor/cwe/<version>/`, update its notice, then regenerate:

```sh
python3 tools/import_cwe.py --archive vendor/cwe/<version>/cwec_v<version>.xml.zip --output data/cwe/<version>
```

Update `tools/agentsec.py` only after validation and tests. CWE has announced
that CWE 5.0 / Schema 8.0 is a breaking change, so the first 5.0 import should
be reviewed as a compatibility update rather than silently replacing 4.20.
