# Third-party sources and notices

The root [MIT license](LICENSE) covers VEP-authored platform code, scripts and
rules, not a blanket relicensing of vendored third-party content. Existing
copyright and license headers remain intact. No analyzer executable or database
is distributed in the closeout evidence pack.

| Component / paths | Upstream | Terms / retained license |
|---|---|---|
| `dataset/benchmark/`, `expectedresults-1.2.csv`, archive GT and Benchmark-derived fixtures | [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), local Maven artifact `org.owasp:benchmark:1.2`; Java source headers credit Dave Wichers / OWASP | GPL version 2; [full license](third_party/licenses/OWASP-Benchmark-GPL-2.0.txt), also in `dataset/benchmark/LICENSE` and the replay archive |
| `rules/codeql-query/` upstream queries, associated examples | [GitHub CodeQL](https://github.com/github/codeql) | MIT, Copyright (c) 2006-2025 GitHub, Inc.; [upstream license text](third_party/licenses/CodeQL-MIT.txt). Imported query content remains under its upstream terms; VEP local adaptations are also distributed under MIT |
| External CodeFuse-Query / Sparrow / Godel engine and COREF APIs referenced by `rules/codefuse-query/` | [CodeFuse-Query](https://github.com/codefuse-ai/CodeFuse-Query) | Upstream Apache-2.0 [license reference](third_party/licenses/CodeFuse-Query-Apache-2.0.txt); engine not bundled. VEP's local Godel checker/model files are authored in this repository and covered by root MIT |
| Benchmark `jquery.min.js`, header v2.1.4 | [jQuery](https://github.com/jquery/jquery/tree/2.1.4) | MIT [license](third_party/licenses/jQuery-2.1.4-MIT.txt); retain original Foundation copyright header |
| Benchmark `js.cookie.js`, header v2.1.3 | [js-cookie](https://github.com/js-cookie/js-cookie/tree/v2.1.3) | MIT [license](third_party/licenses/js-cookie-2.1.3-MIT.txt) |
| Benchmark `normalize.css`, header v3.0.2 | [normalize.css](https://github.com/necolas/normalize.css/tree/3.0.2) | MIT [license](third_party/licenses/normalize-css-3.0.2-MIT.txt) |
| Benchmark `skeleton.css`, header v2.0.4 | [Skeleton](https://github.com/dhg/Skeleton/tree/2.0.4) | MIT [license](third_party/licenses/Skeleton-2.0.4-MIT.txt); Dave Gamache copyright retained |
| Python packages | `requirements.lock` | Separate upstream package terms apply. Runtime packages are installed separately, not copied into the evidence pack |

## Provenance and changes

- [Pinned license retrievals and SHA256](third_party/provenance.json) identify
  the exact upstream license documents checked during closeout. These revisions
  are **not** asserted to be the original dataset/query import revisions.
- OWASP source is distributed as source, with original headers retained. Local
  build configuration changes are recorded in Git history; the imported tree
  is a research benchmark rather than an unmodified upstream distribution.
  Its original import revision is unknown; Maven version 1.2, retained headers,
  committed source and GT checksum identify this snapshot.
- CodeQL original import revisions are unknown. Local query/pack hashes are
  recorded in `repro/archive-v3.0.1/rule-inventory.json` and the pack lock.
  CodeQL library packs and CLI are resolved/installed separately; the CLI's
  own distribution/use terms are not replaced by this source MIT notice.
- Normalized output CSVs preserve all input rows. Source paths and hashes are
  in the archive manifest. CodeQL source SARIF embeds version 2.25.3; CodeFuse
  run version is unknown, explicitly recorded as null, not inferred from
  a different environment snapshot.
- The archive contains the GT and corresponding license; the complete vendored
  Benchmark source is available in the same release's Git source snapshot.
  No compiled Benchmark binary is included in the closeout evidence asset.

For per-file notices within the benchmark source, the retained file headers
remain authoritative. Reuse must preserve the corresponding component terms.

Benchmark CSS references externally hosted Raleway fonts; no font binary is
bundled. Embedded Benchmark assets retain their own notices; the Benchmark
GPL notice does not override the web assets' separate MIT terms. OWASP names
and logos identify the upstream benchmark, not an endorsement.
