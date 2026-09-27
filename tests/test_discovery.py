from __future__ import annotations

from types import SimpleNamespace

import pytest

from vllm_hust_ext import discovery


class Distribution:
    def __init__(self, name: str, *, editable: bool) -> None:
        self.metadata = {"Name": name}
        self.version = "1.0"
        self._editable = editable

    def read_text(self, name: str) -> str | None:
        if name != "direct_url.json":
            return None
        return '{"dir_info":{"editable": true}}' if self._editable else None


def registration(name: str, distribution: Distribution):
    return SimpleNamespace(
        name="org.vllm-hust.example",
        value="example.manifests",
        group=discovery.ENTRY_POINT_GROUP,
        dist=distribution,
    )


def test_identical_wheel_and_editable_registrations_select_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("same descriptor")
    wheel = registration("wheel", Distribution("example-wheel", editable=False))
    editable = registration("editable", Distribution("example-source", editable=True))
    monkeypatch.setattr(discovery, "_manifest_path", lambda _item: manifest)

    monkeypatch.setattr(
        discovery,
        "load_manifest",
        lambda _path: SimpleNamespace(bundle_id="org.vllm-hust.example"),
    )
    bundles = discovery.discover_bundles(
        registrations=(editable, wheel), all_entry_points=()
    )

    assert len(bundles) == 1
    assert bundles[0].distribution_name == "example-wheel"


def test_different_duplicate_descriptors_remain_ambiguous(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    wheel_path = tmp_path / "wheel.json"
    source_path = tmp_path / "source.json"
    wheel_path.write_text("wheel descriptor")
    source_path.write_text("source descriptor")
    wheel = registration("wheel", Distribution("example-wheel", editable=False))
    editable = registration("editable", Distribution("example-source", editable=True))
    monkeypatch.setattr(
        discovery,
        "_manifest_path",
        lambda item: wheel_path if item is wheel else source_path,
    )

    with pytest.raises(discovery.DiscoveryError, match="duplicate Bundle"):
        discovery.discover_bundles(registrations=(wheel, editable), all_entry_points=())
