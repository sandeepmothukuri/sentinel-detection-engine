"""Sigma converter tests: covers the documented supported subset and the
documented limitations (unsupported categories fail loudly, complex
conditions degrade predictably)."""
from __future__ import annotations

import pytest

from sigma_to_kql import convert

PROCESS_SIGMA = {
    "title": "Suspicious PowerShell Encoded Command",
    "id": "12345678-abcd-4321-ffff-000000000001",
    "description": "Test rule.",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection_img": {"Image": "|\\powershell.exe", "OriginalFileName": "powershell.exe"},
        "selection_cli": {"CommandLine|contains": ["-enc", "-EncodedCommand"]},
        "condition": "1 of selection_*",
    },
    "tags": ["attack.execution", "attack.t1059.001"],
}


def test_process_creation_basic():
    out = convert({
        "title": "T",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image": "|\\mimikatz.exe"}, "condition": "selection"},
        "tags": ["attack.t1003.001"],
    })
    assert out.startswith("// T")
    assert "DeviceProcessEvents" in out
    assert "FolderPath" in out
    assert "T1003.001" in out


def test_selection_values_map_to_mde_fields():
    out = convert(PROCESS_SIGMA)
    assert "InitiatingProcessFolderPath" not in out  # Image -> FolderPath
    assert "FolderPath =~" in out
    assert "has_any" in out


def test_condition_one_of_expansion():
    out = convert(PROCESS_SIGMA)
    # "1 of selection_*" must render as OR of the two selections
    assert ") or (" in out


def test_unsupported_category_raises():
    with pytest.raises(ValueError):
        convert({
            "title": "T",
            "logsource": {"category": "file_event", "product": "linux"},
            "detection": {"selection": {"TargetFilename": "/etc/passwd"}, "condition": "selection"},
        })


def test_network_connection_mapping():
    out = convert({
        "title": "T",
        "logsource": {"category": "network_connection"},
        "detection": {"selection": {"DestinationPort": 4444}, "condition": "selection"},
    })
    assert "DeviceNetworkEvents" in out
    assert "RemotePort" in out


def test_attacks_tags_extracted():
    out = convert(PROCESS_SIGMA)
    assert "ATT&CK: T1059.001" in out


def test_multiple_values_use_in():
    out = convert({
        "title": "T",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"Image": ["|\\a.exe", "|\\b.exe"]}, "condition": "selection"},
    })
    assert "in~" in out
