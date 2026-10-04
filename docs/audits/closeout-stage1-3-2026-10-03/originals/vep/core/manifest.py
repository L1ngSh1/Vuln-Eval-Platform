"""VEP Core: CWE manifest loader (Phase 3).

Loads configs/cwe_manifest.yml into typed entries so pipeline and tool code
never parse the YAML themselves. Entry paths are resolved against the project
root at load time.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from vep.core.normalization import normalize_cwe_id

MANIFEST_FILE = Path("configs/cwe_manifest.yml")


@dataclass
class CweEntry:
    """One CWE entry from the manifest, with paths resolved to absolute."""
    id: str
    name: str
    slug: str
    slug_compact: str
    description: str = ""
    codefuse_rule_file: Optional[Path] = None
    codeql_rule_directory: Optional[Path] = None
    tests_directory: Optional[Path] = None
    experiments_directory: Optional[Path] = None

    def matches(self, token: str) -> bool:
        """Match a user-supplied token against id / name / slug / slug_compact."""
        token = token.strip().lower()
        candidates = {token}
        try:
            candidates.add(normalize_cwe_id(token).lower())
        except Exception:
            pass
        known = {
            self.id.lower(),
            self.name.lower(),
            self.slug.lower(),
            self.slug_compact.lower(),
        }
        return bool(candidates & known)


@dataclass
class Manifest:
    """Parsed cwe_manifest.yml."""
    path: Path
    ground_truth_file: Path
    codefuse_db: Optional[Path]
    codeql_db: Optional[Path]
    local_lib: Optional[Path]
    cwes: List[CweEntry] = field(default_factory=list)

    def find(self, token: str) -> Optional[CweEntry]:
        for entry in self.cwes:
            if entry.matches(token):
                return entry
        return None

    def resolve(self, tokens: List[str]) -> List[CweEntry]:
        """Resolve CWE tokens ("022", "CWE-022", "cwe-022", ...) to entries.

        The single token "all" resolves to every manifest entry. Unknown
        tokens raise ValueError.
        """
        if len(tokens) == 1 and tokens[0].strip().lower() == "all":
            return list(self.cwes)
        resolved = []
        for token in tokens:
            entry = self.find(token)
            if entry is None:
                valid = ", ".join(entry.id for entry in self.cwes)
                raise ValueError(f"Unknown CWE token '{token}'. Valid ids: {valid}")
            resolved.append(entry)
        return resolved


def load_manifest(
    manifest_file: Optional[Path] = None,
    project_root: Optional[Path] = None,
) -> Manifest:
    """Load the CWE manifest. Raises FileNotFoundError if the file is missing."""
    root = _project_root(project_root)
    path = manifest_file if manifest_file is not None else root / MANIFEST_FILE
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        raise FileNotFoundError(f"Manifest not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    ground_truth = Path((data.get("ground_truth") or {}).get("file", "expectedresults-1.2.csv"))
    databases = data.get("databases") or {}
    libraries = (data.get("libraries") or {}).get("codefuse") or {}

    entries: List[CweEntry] = []
    for raw in data.get("cwes", []):
        codefuse = raw.get("codefuse") or {}
        codeql = raw.get("codeql") or {}
        tests = raw.get("tests") or {}
        experiments = raw.get("experiments") or {}
        entries.append(CweEntry(
            id=str(raw.get("id", "")),
            name=str(raw.get("name") or f"CWE-{raw.get('id', '')}"),
            slug=str(raw.get("slug") or ""),
            slug_compact=str(raw.get("slug_compact") or ""),
            description=str(raw.get("description") or ""),
            codefuse_rule_file=_resolve(root, codefuse.get("rule_file")),
            codeql_rule_directory=_resolve(root, codeql.get("rule_directory")),
            tests_directory=_resolve(root, tests.get("directory")),
            experiments_directory=_resolve(root, experiments.get("directory")),
        ))

    return Manifest(
        path=path,
        ground_truth_file=_resolve(root, ground_truth),
        codefuse_db=_resolve(root, databases.get("codefuse")),
        codeql_db=_resolve(root, databases.get("codeql")),
        local_lib=_resolve(root, libraries.get("local")),
        cwes=entries,
    )


def _resolve(root: Path, value: Optional[str]) -> Optional[Path]:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def _project_root(project_root: Optional[Path]) -> Path:
    if project_root is not None:
        return project_root
    return Path(__file__).resolve().parents[2]
