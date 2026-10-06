"""Discover installed Bundles without importing their implementations."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

from vllm_hust_ext.manifest import BundleManifest, ManifestError, load_manifest

ENTRY_POINT_GROUP = "vllm_hust.extension_bundles"
MANIFEST_FILENAMES = (
    "vllm-hust-extension-v0.3.json",
    "vllm-hust-extension-v0.2.json",
    "vllm-hust-extension-v1.json",
    "extension-bundle-v1.json",
)
_MODULE_PATH = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


class DiscoveryError(ValueError):
    """Installed Bundle metadata is invalid or ambiguous."""


@dataclass(frozen=True, slots=True)
class InstalledBundle:
    bundle_id: str
    distribution_name: str
    distribution_version: str
    manifest_path: Path
    manifest: BundleManifest
    entry_points: tuple[EntryPoint, ...]


@dataclass(frozen=True, slots=True)
class DiscoveryDiagnostic:
    """One installed registration that could not be admitted as a Bundle."""

    bundle_id: str
    error: str


def _flatten_entry_points(value: object) -> tuple[EntryPoint, ...]:
    """Normalize importlib.metadata results across Python 3.10 and 3.12+."""

    values = getattr(value, "values", None)
    if callable(values):
        return tuple(entry_point for group in values() for entry_point in group)
    return tuple(value)  # type: ignore[arg-type]


def _manifest_path(entry_point: EntryPoint) -> Path:
    if not _MODULE_PATH.fullmatch(entry_point.value):
        raise DiscoveryError(
            f"{entry_point.name!r} must register a static module directory"
        )
    distribution = entry_point.dist
    if distribution is None:
        raise DiscoveryError(f"{entry_point.name!r} has no distribution metadata")
    relative = tuple(
        PurePosixPath(*entry_point.value.split("."), filename)
        for filename in MANIFEST_FILENAMES
    )
    files = distribution.files or ()
    matches = [
        Path(str(distribution.locate_file(file)))
        for file in files
        if PurePosixPath(str(file)) in relative
    ]
    if not matches:
        direct_url_text = distribution.read_text("direct_url.json")
        if direct_url_text:
            try:
                direct_url = json.loads(direct_url_text)
            except json.JSONDecodeError as error:
                raise DiscoveryError("editable direct_url.json is invalid") from error
            parsed = urlparse(direct_url.get("url", ""))
            if (
                direct_url.get("dir_info", {}).get("editable") is True
                and parsed.scheme == "file"
                and parsed.netloc in ("", "localhost")
            ):
                path = unquote(parsed.path)
                if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
                    path = path[1:]
                root = Path(path)
                matches = [
                    candidate
                    for source_root in (root, root / "src")
                    for path in relative
                    if (candidate := source_root / path).is_file()
                ]
    if len(matches) != 1:
        raise DiscoveryError(
            f"{entry_point.name!r} must contain exactly one Bundle v1 manifest"
        )
    return matches[0]


def _is_editable(entry_point: EntryPoint) -> bool:
    if entry_point.dist is None:
        return False
    direct_url_text = entry_point.dist.read_text("direct_url.json")
    if not direct_url_text:
        return False
    try:
        direct_url = json.loads(direct_url_text)
    except json.JSONDecodeError as error:
        raise DiscoveryError("editable direct_url.json is invalid") from error
    return direct_url.get("dir_info", {}).get("editable") is True


def _entry_point_target_is_packaged(entry_point: EntryPoint) -> bool:
    """Check entry-point module ownership without importing third-party code."""

    distribution = entry_point.dist
    if distribution is None:
        return False
    module = entry_point.value.partition(":")[0].strip()
    if not _MODULE_PATH.fullmatch(module):
        return False
    module_path = PurePosixPath(*module.split("."))

    def matches(path: PurePosixPath) -> bool:
        if path == module_path.with_suffix(".py"):
            return True
        if path == module_path / "__init__.py":
            return True
        return (
            path.parent == module_path.parent
            and path.name.startswith(f"{module_path.name}.")
            and path.suffix.lower() in {".pyd", ".so"}
        )

    if any(matches(PurePosixPath(str(path))) for path in distribution.files or ()):
        return True
    direct_url_text = distribution.read_text("direct_url.json")
    if not direct_url_text:
        return False
    try:
        direct_url = json.loads(direct_url_text)
    except json.JSONDecodeError as error:
        raise DiscoveryError("editable direct_url.json is invalid") from error
    parsed = urlparse(direct_url.get("url", ""))
    if (
        direct_url.get("dir_info", {}).get("editable") is not True
        or parsed.scheme != "file"
        or parsed.netloc not in ("", "localhost")
    ):
        return False
    path = unquote(parsed.path)
    if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    root = Path(path)
    return any(
        candidate.is_file()
        for source_root in (root, root / "src")
        for candidate in (
            source_root / module_path.with_suffix(".py"),
            source_root / module_path / "__init__.py",
        )
    )


def discover_bundles(
    selected: Iterable[str] | None = None,
    *,
    registrations: Sequence[EntryPoint] | None = None,
    all_entry_points: Sequence[EntryPoint] | None = None,
) -> tuple[InstalledBundle, ...]:
    wanted = None if selected is None else tuple(selected)
    wanted_set = None if wanted is None else frozenset(wanted)
    discovered = (
        tuple(entry_points(group=ENTRY_POINT_GROUP))
        if registrations is None
        else tuple(registrations)
    )
    candidates: dict[str, list[EntryPoint]] = {}
    for entry_point in discovered:
        if wanted_set is None or entry_point.name in wanted_set:
            candidates.setdefault(entry_point.name, []).append(entry_point)
    for bundle_id, items in candidates.items():
        if len(items) == 1:
            continue
        manifests: dict[bytes, list[EntryPoint]] = {}
        for registration in items:
            try:
                content = _manifest_path(registration).read_bytes()
            except (DiscoveryError, OSError) as error:
                raise DiscoveryError(
                    f"duplicate Bundle registration {bundle_id!r} cannot be verified"
                ) from error
            manifests.setdefault(content, []).append(registration)
        if len(manifests) != 1:
            raise DiscoveryError(f"duplicate Bundle registrations: {[bundle_id]}")
        # A wheel plus an editable install can publish the same static Bundle
        # descriptor. Treat that as one registration, while still rejecting
        # any disagreement in descriptor bytes. Prefer the wheel path so the
        # selected distribution remains independent of a source checkout.
        candidates[bundle_id] = [
            sorted(
                items,
                key=lambda item: (
                    _is_editable(item),
                    item.dist.metadata["Name"] or "" if item.dist else "",
                ),
            )[0]
        ]
    if wanted_set is not None:
        missing = wanted_set - candidates.keys()
        if missing:
            raise DiscoveryError(
                f"enabled Bundles are not installed: {sorted(missing)}"
            )

    every_entry_point = (
        _flatten_entry_points(entry_points())
        if all_entry_points is None
        else tuple(all_entry_points)
    )
    loaded: dict[str, InstalledBundle] = {}
    for bundle_id, items in candidates.items():
        registration = items[0]
        distribution = registration.dist
        if distribution is None:
            raise DiscoveryError(f"{bundle_id!r} has no distribution metadata")
        name = distribution.metadata["Name"]
        if not isinstance(name, str) or not name:
            raise DiscoveryError(f"{bundle_id!r} has no distribution name")
        try:
            manifest_path = _manifest_path(registration)
            manifest = load_manifest(manifest_path)
        except ManifestError as error:
            raise DiscoveryError(
                f"{bundle_id!r} manifest is invalid: {error}"
            ) from error
        if manifest.bundle_id != bundle_id:
            raise DiscoveryError(
                f"registration {bundle_id!r} does not match {manifest.bundle_id!r}"
            )
        related = tuple(
            entry_point
            for entry_point in every_entry_point
            if entry_point.dist is not None
            and entry_point.dist.metadata["Name"] == name
            and entry_point.group != ENTRY_POINT_GROUP
        )
        declared = {
            (entry_point.group, entry_point.name)
            for entry_point in manifest.activation.entry_points
        }
        installed = {(entry_point.group, entry_point.name) for entry_point in related}
        missing_entry_points = declared - installed
        if missing_entry_points:
            rendered = [
                f"{group}:{entry_name}"
                for group, entry_name in sorted(missing_entry_points)
            ]
            raise DiscoveryError(
                f"{bundle_id!r} declares uninstalled activation entry points: "
                f"{rendered}"
            )
        dangling_entry_points = [
            entry_point
            for entry_point in related
            if (entry_point.group, entry_point.name) in declared
            and not _entry_point_target_is_packaged(entry_point)
        ]
        if dangling_entry_points:
            rendered = [
                f"{entry_point.group}:{entry_point.name} -> "
                f"{entry_point.value.partition(':')[0]}"
                for entry_point in sorted(
                    dangling_entry_points,
                    key=lambda item: (item.group, item.name),
                )
            ]
            raise DiscoveryError(
                f"{bundle_id!r} declares activation entry-point targets not "
                f"packaged by its distribution: {rendered}"
            )
        loaded[bundle_id] = InstalledBundle(
            bundle_id,
            name,
            distribution.version,
            manifest_path,
            manifest,
            related,
        )
    order = wanted if wanted is not None else tuple(sorted(loaded))
    return tuple(loaded[bundle_id] for bundle_id in order)


def discover_bundle_inventory(
    *,
    registrations: Sequence[EntryPoint] | None = None,
    all_entry_points: Sequence[EntryPoint] | None = None,
) -> tuple[tuple[InstalledBundle, ...], tuple[DiscoveryDiagnostic, ...]]:
    """Discover every registration while quarantining failures by Bundle id.

    Inventory is intentionally tolerant so one broken, disabled distribution
    cannot hide unrelated installed Bundles. Targeted operations and launch
    continue to call :func:`discover_bundles` and therefore remain strict.
    """

    discovered = (
        tuple(entry_points(group=ENTRY_POINT_GROUP))
        if registrations is None
        else tuple(registrations)
    )
    every_entry_point = (
        _flatten_entry_points(entry_points())
        if all_entry_points is None
        else tuple(all_entry_points)
    )
    bundles: list[InstalledBundle] = []
    diagnostics: list[DiscoveryDiagnostic] = []
    for bundle_id in sorted({registration.name for registration in discovered}):
        try:
            bundles.extend(
                discover_bundles(
                    (bundle_id,),
                    registrations=discovered,
                    all_entry_points=every_entry_point,
                )
            )
        except (DiscoveryError, OSError) as error:
            diagnostics.append(DiscoveryDiagnostic(bundle_id, str(error)))
    return tuple(bundles), tuple(diagnostics)
