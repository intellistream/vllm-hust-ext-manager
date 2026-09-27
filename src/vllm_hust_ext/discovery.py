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
    matches = [file for file in files if PurePosixPath(str(file)) in relative]
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
    match = matches[0]
    return match if isinstance(match, Path) else Path(distribution.locate_file(match))


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
                    item.dist.metadata.get("Name", "") if item.dist else "",
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
        name = distribution.metadata.get("Name")
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
            and entry_point.dist.metadata.get("Name") == name
            and entry_point.group != ENTRY_POINT_GROUP
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
