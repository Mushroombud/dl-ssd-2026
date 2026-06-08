#!/usr/bin/env python3
"""Endless score-focused probe loop for hidden-test-like solver misses.

This loop intentionally does not edit code, sync the server, or submit.
It generates high-value wrapper/state-machine trajectories, compares them
against the current solver, and appends only misclassified probes to a queue.
Codex can then inspect the queue and make a generalized repair.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.solver import NOT_AUTHORIZED, SUCCESS, parse_event, predict_trajectory
from src.solver_components.constants import C_EC_DEFAULT_CURVE_COLUMNS
from tools.run_synthetic_edges import (
    ADMIN1,
    ADMIN_SP,
    C_PIN_SID,
    LOCKING_RANGE1,
    LOCKING_SP,
    SID,
    activated_locking_context,
    end_session,
    function_record,
    HOST_PROPS_INITIAL,
    host_read,
    host_read_status,
    host_props_with,
    host_write,
    host_write_status,
    level0_opal_v2,
    locking_admin_open,
    method_record,
    owned_admin_context,
    set_values,
    start_session,
)


DEFAULT_QUEUE = ROOT / "analysis" / "score_probe_queue.jsonl"
DEFAULT_STATUS = ROOT / "analysis" / "score_probe_loop_status.md"
DEFAULT_HISTORY = ROOT / "analysis" / "score_probe_loop_history.jsonl"


@dataclass(frozen=True)
class Probe:
    name: str
    trajectory: list[dict[str, Any]]
    expected: str
    family: str
    why: str


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def compact_event(raw: dict[str, Any]) -> dict[str, Any]:
    event = parse_event(raw)
    return {
        "kind": event.kind,
        "method": event.method,
        "invoking_symbol": event.invoking_symbol,
        "status": event.status,
        "authority": event.authority,
        "values": dict(event.values),
        "columns": sorted(event.columns),
        "sp": event.sp,
    }


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def operation_payload(function: str, payload: dict[str, Any], *, key: str, output: dict[str, Any] | None = None) -> dict[str, Any]:
    if key == "args1":
        inp = {"function": function, "args": [payload]}
    elif key == "kwargs":
        inp = {"function": function, "kwargs": payload}
    elif key == "params":
        inp = {"function": function, "params": payload}
    elif key == "request":
        inp = {"function": function, "request": payload}
    elif key == "call":
        inp = {"call": {"function": function, **payload}}
    else:
        inp = {"function": function, **payload}
    return {"input": inp, "output": output or {"return": True}}


def properties_wrapper_probes() -> Iterable[Probe]:
    high_host_props = host_props_with(MaxComPacketSize=4096)
    for alias in ("setHostProperties", "hostProperties", "negotiateProperties"):
        yield Probe(
            f"{alias} wrapper accepts HostProperties negotiation",
            [{"input": {"function": alias, "kwargs": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}}, "output": {"return": {"HostProperties": high_host_props}}}],
            "PASS",
            "session-wrapper",
            f"{alias} should lower to Session Manager Properties and preserve submitted HostProperties.",
        )
    for wrapper, payload in (
        ("hostPropertiesRequest", {"hostPropertiesRequest": {"values": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}}}),
        ("propertiesRequest", {"propertiesRequest": {"ComID": 1, "properties": {"MaxComPacketSize": 4096}}}),
        ("sessionRequest", {"sessionRequest": {"values": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}}}),
        ("comIdRequest", {"comIdRequest": {"ComID": 1, "hostProperties": {"MaxComPacketSize": 4096}}}),
    ):
        yield Probe(
            f"setHostProperties preserves {wrapper} state",
            [{"input": {"function": "setHostProperties", "kwargs": payload}, "output": {"return": {"HostProperties": high_host_props}}}],
            "PASS",
            "host-properties-envelope-doc",
            f"{wrapper} must preserve ComID and HostProperties before lowering to Session Manager Properties.",
        )
        yield Probe(
            f"setHostProperties rejects stale {wrapper} state",
            [{"input": {"function": "setHostProperties", "kwargs": payload}, "output": {"return": {"HostProperties": HOST_PROPS_INITIAL}}}],
            "FAIL",
            "host-properties-envelope-doc",
            f"{wrapper} must not drop submitted HostProperties and accept stale default negotiation state.",
        )
    for wrapper, set_payload, get_payload in (
        (
            "operation",
            {"operation": {"target": {"ComID": 1}, "command": {"HostProperties": {"MaxComPacketSize": 4096}}}},
            {"operation": {"target": {"ComID": 2}, "command": {}}},
        ),
        (
            "operationRequest",
            {"operationRequest": {"target": {"ComID": 1}, "command": {"HostProperties": {"MaxComPacketSize": 4096}}}},
            {"operationRequest": {"target": {"ComID": 2}, "command": {}}},
        ),
        (
            "command",
            {"command": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}},
            {"command": {"ComID": 2}},
        ),
        (
            "action",
            {"action": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}},
            {"action": {"ComID": 2}},
        ),
    ):
        yield Probe(
            f"setHostProperties preserves {wrapper} operation state",
            [{"input": {"function": "setHostProperties", "kwargs": set_payload}, "output": {"return": {"HostProperties": high_host_props}}}],
            "PASS",
            "host-properties-operation-envelope-doc",
            f"{wrapper} must preserve submitted HostProperties and ComID before lowering to Session Manager Properties.",
        )
        yield Probe(
            f"setHostProperties rejects stale {wrapper} operation state",
            [{"input": {"function": "setHostProperties", "kwargs": set_payload}, "output": {"return": {"HostProperties": HOST_PROPS_INITIAL}}}],
            "FAIL",
            "host-properties-operation-envelope-doc",
            f"{wrapper} must not drop submitted HostProperties and accept stale defaults.",
        )
        yield Probe(
            f"getHostProperties preserves {wrapper} operation ComID isolation",
            [
                {"input": {"function": "setHostProperties", "kwargs": set_payload}, "output": {"return": {"HostProperties": high_host_props}}},
                {"input": {"function": "getHostProperties", "kwargs": get_payload}, "output": {"return": {"HostProperties": HOST_PROPS_INITIAL}}},
            ],
            "PASS",
            "host-properties-operation-envelope-doc",
            f"{wrapper} getter selectors must validate the target ComID state without leaking another ComID.",
        )
        yield Probe(
            f"getHostProperties rejects {wrapper} operation cross-ComID leak",
            [
                {"input": {"function": "setHostProperties", "kwargs": set_payload}, "output": {"return": {"HostProperties": high_host_props}}},
                {"input": {"function": "getHostProperties", "kwargs": get_payload}, "output": {"return": {"HostProperties": high_host_props}}},
            ],
            "FAIL",
            "host-properties-operation-envelope-doc",
            f"{wrapper} getter selectors must not accept ComID 1 values for ComID 2.",
        )
    yield Probe(
        "getHostProperties wrapper preserves per-ComID state",
        [
            {"input": {"function": "setHostProperties", "kwargs": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}}, "output": {"return": {"HostProperties": high_host_props}}},
            {"input": {"function": "getHostProperties", "kwargs": {"ComID": 2}}, "output": {"return": {"HostProperties": HOST_PROPS_INITIAL}}},
        ],
        "PASS",
        "session-wrapper",
        "HostProperties are tracked per ComID, so ComID 2 must retain the initial defaults.",
    )
    yield Probe(
        "getHostProperties wrapper rejects cross-ComID leak",
        [
            {"input": {"function": "setHostProperties", "kwargs": {"ComID": 1, "HostProperties": {"MaxComPacketSize": 4096}}}, "output": {"return": {"HostProperties": high_host_props}}},
            {"input": {"function": "getHostProperties", "kwargs": {"ComID": 2}}, "output": {"return": {"HostProperties": high_host_props}}},
        ],
        "FAIL",
        "session-wrapper",
        "A HostProperties wrapper query must not leak negotiated ComID 1 values into ComID 2.",
    )
    for alias in ("getTPerProperties", "readTPerProperties", "fetchTPerProperties", "queryTPerProperties"):
        yield Probe(
            f"{alias} wrapper accepts TPer property response",
            [{"input": {"function": alias}, "output": {"return": {"MaxSessionTimeout": 0, "MinSessionTimeout": 0}}}],
            "PASS",
            "session-wrapper",
            f"{alias} should lower to Session Manager Properties and validate TPer property names.",
        )


def setrange_probes() -> Iterable[Probe]:
    maxranges_eight = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        method_record("Get", "0000080100000000", "LockingInfo", return_values={"MaxRanges": 8}),
    ]
    maxranges_nine = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        method_record("Get", "0000080100000000", "LockingInfo", return_values={"MaxRanges": 9}),
    ]
    for alias, payload in (
        ("setRange", {"rangeId": 9, "RangeStart": 100, "RangeLength": 4, "authAs": ("Admin1", "new")}),
        ("updateRange", {"rangeId": 9, "RangeStart": 100, "authAs": ("Admin1", "new")}),
        ("setRangeStart", {"rangeId": 9, "RangeStart": 100, "authAs": ("Admin1", "new")}),
    ):
        yield Probe(
            f"{alias} Range9 success rejected after MaxRanges eight",
            maxranges_eight + [function_record(alias, [payload], None, True)],
            "FAIL",
            "locking-wrapper",
            f"{alias} must not create or update optional Range9 after LockingInfo.MaxRanges=8 excludes it.",
        )
        yield Probe(
            f"{alias} Range9 success allowed after MaxRanges nine",
            maxranges_nine + [function_record(alias, [payload], None, True)],
            "PASS",
            "locking-wrapper",
            f"{alias} may target Range9 when LockingInfo.MaxRanges=9 supports the optional row.",
        )
    for info_alias in ("readLockingInfo", "fetchLockingInfo", "queryLockingInfo", "loadLockingInfo", "getMaxRanges", "queryRangeSupport"):
        info_eight = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(info_alias, [], {"authAs": ("Admin1", "new")}, {"MaxRanges": 8}),
        ]
        yield Probe(
            f"{info_alias} MaxRanges eight rejects later Range9 setRange",
            info_eight + [function_record("setRange", [], {"rangeId": 9, "RangeStart": 100, "RangeLength": 4, "authAs": ("Admin1", "new")}, True)],
            "FAIL",
            "locking-wrapper",
            f"{info_alias} is a LockingInfo reader and must feed the observed MaxRanges optional-range boundary.",
        )
    yield Probe(
        "queryLockingInfo MaxRanges nine allows later Range9 setRange",
        activated_locking_context()
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record("queryLockingInfo", [], {"authAs": ("Admin1", "new")}, {"MaxRanges": 9}),
            function_record("setRange", [], {"rangeId": 9, "RangeStart": 100, "RangeLength": 4, "authAs": ("Admin1", "new")}, True),
        ],
        "PASS",
        "locking-wrapper",
        "Positive control: the alias-fed MaxRanges boundary must still allow Range9 when MaxRanges=9.",
    )
    yield Probe(
        "fetchLockingInfo rejects empty success payload",
        activated_locking_context()
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record("fetchLockingInfo", [], {"authAs": ("Admin1", "new")}, {}),
        ],
        "FAIL",
        "locking-wrapper",
        "LockingInfo wrapper readers should expose at least one LockingInfo field, not an empty success object.",
    )
    for info_alias, payload in (
        ("getMaxRanges", 8),
        ("getMaxLockingRanges", {"value": 8}),
        ("queryLockingRangeCount", {"MaxRanges": 8}),
        ("getRangeLimit", 8),
    ):
        context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(info_alias, [], {"authAs": ("Admin1", "new")}, payload),
        ]
        yield Probe(
            f"{info_alias} scalar MaxRanges rejects later Range9 setRange",
            context + [function_record("setRange", [], {"rangeId": 9, "RangeStart": 100, "RangeLength": 4, "authAs": ("Admin1", "new")}, True)],
            "FAIL",
            "locking-wrapper",
            f"{info_alias} is a scalar LockingInfo.MaxRanges reader and must constrain optional Range9 support.",
        )
    yield Probe(
        "queryLockingInfo whole-row alias rejects scalar-only MaxRanges",
        activated_locking_context()
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record("queryLockingInfo", [], {"authAs": ("Admin1", "new")}, 8),
        ],
        "FAIL",
        "locking-wrapper",
        "Whole-row LockingInfo readers must not collapse to an unnamed scalar MaxRanges payload.",
    )
    for info_alias, good, stale in (
        ("getAlignmentRequired", True, False),
        ("isAlignmentRequired", False, True),
        ("getLogicalBlockSize", 512, 4096),
        ("queryAlignmentGranularity", 8, 16),
        ("fetchLowestAlignedLBA", 0, 1),
    ):
        context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(info_alias, [], {"authAs": ("Admin1", "new")}, good),
        ]
        yield Probe(
            f"{info_alias} scalar LockingInfo getter rejects stale later value",
            context + [function_record(info_alias, [], {"authAs": ("Admin1", "new")}, stale)],
            "FAIL",
            "locking-wrapper",
            f"{info_alias} should share the tracked LockingInfo geometry cell state.",
        )
    payloads = [
        {"authAs": ("Admin1", "new"), "range": 1, "values": {"start": 144, "length": 8, "readLock": True}},
        {"auth": "Admin1", "band_id": 1, "settings": {"RangeStart": 152, "RangeLength": 8, "WriteLocked": True}},
        {"authAs": ("Admin1", "new"), "lockingRange": 1, "options": {"offset": 160, "size": 8, "writeLockEnabled": True}},
    ]
    for index, payload in enumerate(payloads):
        for shape in ("args1", "kwargs", "params", "request", "call"):
            raw = operation_payload("setRange", payload, key=shape, output={"ok": True})
            start = 144 + index * 8
            current_output = {"RangeStart": start, "RangeLength": 8}
            if index == 0:
                current_output["ReadLocked"] = True
            elif index == 1:
                current_output["WriteLocked"] = True
            context = activated_locking_context() + [raw]
            yield Probe(
                f"setRange {shape} nested payload accepts current state {index}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, current_output)],
                "PASS",
                "locking-wrapper",
                "Wrapper setRange nested payload should update Locking range geometry.",
            )
            yield Probe(
                f"setRange {shape} nested payload rejects stale state {index}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0})],
                "FAIL",
                "locking-wrapper",
                "Stale getRange after successful setRange indicates a parser/state miss.",
            )
    for label, kwargs in (
        ("request values geometry", {"request": {"values": {"geometry": {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}}),
        ("policy request values", {"policy": {"request": {"values": {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}}),
        ("lockingRequest values", {"lockingRequest": {"values": {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}),
        ("lockingRangeRequest values", {"lockingRangeRequest": {"values": {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}),
        ("operation command", {"operation": {"command": {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"rangeId": 1}, "command": {"RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}}}),
    ):
        context = activated_locking_context() + [function_record("setRange", [], kwargs, True)]
        yield Probe(
            f"setRange {label} nested geometry accepts current state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"RangeStart": 222, "RangeLength": 7})],
            "PASS",
            "locking-range-nested-geometry-doc",
            "Nested Locking range geometry envelopes should update RangeStart/RangeLength on the selected row.",
        )
        yield Probe(
            f"setRange {label} nested geometry rejects stale state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 7})],
            "FAIL",
            "locking-range-nested-geometry-doc",
            "Ignoring nested Locking geometry envelopes permits stale RangeStart observations.",
        )
    getrange_domain_context = activated_locking_context() + [
        function_record("setRange", [], {"rangeId": 1, "RangeStart": 222, "RangeLength": 7, "authAs": ("Admin1", "new")}, True),
    ]
    for label, kwargs in (
        ("lockingRequest values", {"lockingRequest": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("rangeRequest values", {"rangeRequest": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("lockingRangeRequest target", {"lockingRangeRequest": {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}}),
        ("operation command", {"operation": {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}}),
    ):
        yield Probe(
            f"getRange {label} nested selector accepts current state",
            getrange_domain_context + [function_record("getRange", [], kwargs, {"RangeStart": 222, "RangeLength": 7})],
            "PASS",
            "locking-range-domain-request-doc",
            "Locking range domain request envelopes should preserve the selected row for GetRange.",
        )
        yield Probe(
            f"getRange {label} nested selector rejects stale state",
            getrange_domain_context + [function_record("getRange", [], kwargs, {"RangeStart": 0, "RangeLength": 7})],
            "FAIL",
            "locking-range-domain-request-doc",
            "Losing a Locking range domain selector permits stale RangeStart observations.",
        )
    getrange_nested_context = activated_locking_context() + [
        function_record("setRange", [], {"rangeId": 1, "RangeStart": 333, "RangeLength": 9, "authAs": ("Admin1", "new")}, True),
    ]
    for label, kwargs in (
        ("request values", {"request": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("policy query target", {"policy": {"query": {"target": {"rangeId": 1}}, "authAs": ("Admin1", "new")}}),
        ("config target", {"config": {"target": {"range": 1}, "authAs": ("Admin1", "new")}}),
    ):
        yield Probe(
            f"getRange {label} nested selector accepts current state",
            getrange_nested_context + [function_record("getRange", [], kwargs, {"RangeStart": 333, "RangeLength": 9})],
            "PASS",
            "locking-range-nested-getter-doc",
            "Nested Locking getRange selector envelopes should select the tracked range row.",
        )
        yield Probe(
            f"getRange {label} nested selector rejects stale state",
            getrange_nested_context + [function_record("getRange", [], kwargs, {"RangeStart": 0, "RangeLength": 9})],
            "FAIL",
            "locking-range-nested-getter-doc",
            "Losing a nested getRange selector permits stale RangeStart observations.",
        )
    def wrap_locking_deep_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        wrapped: dict[str, Any] = payload
        for key in reversed(chain):
            wrapped = {key: wrapped}
        return wrapped

    locking_deep_chains = (
        ("lockingRequest", "rangeRequest", "geometry", "values"),
        ("request", "lockingRangeRequest", "window", "values"),
        ("config", "target", "rangeValues", "geometry"),
        ("policy", "request", "rangeRequest", "values"),
        ("values", "lockingRequest", "rangeValues", "values"),
        ("operationRequest", "lockingRangeRequest", "target", "values"),
    )
    for index, set_chain in enumerate(locking_deep_chains):
        get_chain = locking_deep_chains[-(index + 1)]
        deep_range_context = activated_locking_context() + [
            function_record(
                "setRange",
                [],
                wrap_locking_deep_payload(
                    {
                        "rangeId": 1,
                        "RangeStart": 120,
                        "RangeLength": 8,
                        "ReadLockEnabled": True,
                        "WriteLockEnabled": True,
                        "authAs": ("Admin1", "new"),
                    },
                    set_chain,
                ),
                True,
            )
        ]
        deep_get_payload = wrap_locking_deep_payload({"rangeId": 1, "authAs": ("Admin1", "new")}, get_chain)
        yield Probe(
            f"deep Locking range target envelope {index} accepts current geometry",
            deep_range_context
            + [
                function_record(
                    "getRange",
                    [],
                    deep_get_payload,
                    {"RangeStart": 120, "RangeLength": 8, "ReadLockEnabled": True, "WriteLockEnabled": True},
                )
            ],
            "PASS",
            "locking-range-deep-target-envelope-doc",
            "Deep Locking range target envelopes should unwrap to the canonical selected range before state comparison.",
        )
        yield Probe(
            f"deep Locking range target envelope {index} rejects stale geometry",
            deep_range_context
            + [
                function_record(
                    "getRange",
                    [],
                    deep_get_payload,
                    {"RangeStart": 80, "RangeLength": 8, "ReadLockEnabled": False, "WriteLockEnabled": True},
                )
            ],
            "FAIL",
            "locking-range-deep-target-envelope-doc",
            "If a deep target envelope is treated as a synthetic Band dictionary, stale Locking state can be accepted.",
        )
    for label, function, kwargs, expected in (
        ("lock request values", "lockRange", {"request": {"values": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("lock policy request values", "lockRange", {"policy": {"request": {"values": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}}, True),
        ("lock config target locks", "lockRange", {"config": {"target": {"rangeId": 1}, "locks": {"read": True, "write": True}, "authAs": ("Admin1", "new")}}, True),
        ("lock lockingRequest values", "lockRange", {"lockingRequest": {"values": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("lock rangeRequest values", "lockRange", {"rangeRequest": {"values": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("lock lockingRangeRequest locks", "lockRange", {"lockingRangeRequest": {"locks": {"read": True, "write": True}, "rangeId": 1, "authAs": ("Admin1", "new")}}, True),
        ("lock operation command", "lockRange", {"operation": {"command": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("lock operation target command", "lockRange", {"operation": {"target": {"rangeId": 1}, "command": {"read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("lock operationRequest target command", "lockRange", {"operationRequest": {"target": {"rangeId": 1}, "command": {"read": True, "write": True, "authAs": ("Admin1", "new")}}}, True),
        ("unlock request values", "unlockRange", {"request": {"values": {"rangeId": 1, "read": True, "write": True, "authAs": ("Admin1", "new")}}}, False),
    ):
        prefix = activated_locking_context()
        if not expected:
            prefix = prefix + [function_record("setRange", [], {"rangeId": 1, "ReadLocked": True, "WriteLocked": True, "authAs": ("Admin1", "new")}, True)]
        context = prefix + [function_record(function, [], kwargs, True)]
        yield Probe(
            f"{function} {label} nested lock envelope accepts current state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"ReadLocked": expected, "WriteLocked": expected})],
            "PASS",
            "locking-range-nested-lock-doc",
            "Nested lockRange/unlockRange envelopes should update the selected row's locked state.",
        )
        yield Probe(
            f"{function} {label} nested lock envelope rejects stale state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"ReadLocked": (not expected), "WriteLocked": (not expected)})],
            "FAIL",
            "locking-range-nested-lock-doc",
            "Losing nested lockRange/unlockRange payloads permits stale locked-state observations.",
        )
    range_field_getter_context = activated_locking_context() + [
        function_record("setRange", [], {"rangeId": 1, "ReadLocked": True, "WriteLocked": True, "ReadLockEnabled": True, "WriteLockEnabled": True, "authAs": ("Admin1", "new")}, True),
    ]
    for getter, good_value, stale_value in (
        ("getReadLocked", True, False),
        ("getWriteLockEnabled", True, False),
        ("getWriteLocked", True, False),
        ("getRangeLocks", {"ReadLocked": True, "WriteLocked": True}, {"ReadLocked": False, "WriteLocked": False}),
    ):
        for label, kwargs in (
            ("request values", {"request": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
            ("policy query target", {"policy": {"query": {"target": {"rangeId": 1}}, "authAs": ("Admin1", "new")}}),
            ("config target", {"config": {"target": {"range": 1}, "authAs": ("Admin1", "new")}}),
            ("operation command", {"operation": {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
            ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}}),
            ("operationRequest command", {"operationRequest": {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
            ("command", {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
            ("action", {"action": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
        ):
            tag = "locking-column-operation-envelope-doc" if any(token in label for token in ("operation", "command", "action")) else "locking-column-nested-getter-doc"
            yield Probe(
                f"{getter} {label} nested selector accepts current lock cell",
                range_field_getter_context + [function_record(getter, [], kwargs, good_value)],
                "PASS",
                tag,
                "Nested Locking column getter selectors should select the tracked range row.",
            )
            yield Probe(
                f"{getter} {label} nested selector rejects stale lock cell",
                range_field_getter_context + [function_record(getter, [], kwargs, stale_value)],
                "FAIL",
                tag,
                "Losing a nested Locking column getter selector permits stale lock-state observations.",
            )
    symbolic_payloads = [
        ("Band1", {"values": {"band": "Band1", "authAs": ("Admin1", "new"), "RangeStart": 120, "RangeLength": 8}}),
        ("Locking_Range1", {"values": {"range": "Locking_Range1", "authAs": ("Admin1", "new"), "RangeStart": 128, "RangeLength": 8}}),
    ]
    for label, payload in symbolic_payloads:
        expected_start = 120 if label == "Band1" else 128
        for shape in ("args1", "kwargs", "params", "request", "call"):
            raw = operation_payload("setRange", payload, key=shape, output={"return": True})
            context = activated_locking_context() + [raw]
            yield Probe(
                f"setRange {shape} symbolic {label} updates Range1 geometry",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": expected_start, "RangeLength": 8})],
                "PASS",
                "locking-wrapper",
                "Symbolic setRange selectors should canonicalize to the selected Locking range.",
            )
            yield Probe(
                f"setRange {shape} symbolic {label} rejects stale Range1 geometry",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0})],
                "FAIL",
                "locking-wrapper",
                "Stale geometry after symbolic setRange indicates a noncanonical wrapper target.",
            )
    alias_field_payloads = [
        (
            "rangeSize lockingenabled",
            {"range": 1, "start": 184, "rangeSize": 12, "readLockingEnabled": True, "writeLockingEnabled": True, "authAs": ("Admin1", "new")},
            {"RangeStart": 184, "RangeLength": 12, "ReadLockEnabled": True, "WriteLockEnabled": True},
        ),
        (
            "numLBAs",
            {"range": 1, "startLBA": 196, "numLBAs": 6, "authAs": ("Admin1", "new")},
            {"RangeStart": 196, "RangeLength": 6},
        ),
    ]
    for label, payload, expected_values in alias_field_payloads:
        context = activated_locking_context() + [{"input": {"function": "setRange", "kwargs": payload}, "output": {"return": True}}]
        yield Probe(
            f"setRange {label} aliases update getRange state",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, expected_values)],
            "PASS",
            "locking-wrapper",
            "Common SDK field spellings should canonicalize to official Locking range cells.",
        )
        yield Probe(
            f"setRange {label} aliases reject stale getRange state",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0})],
            "FAIL",
            "locking-wrapper",
            "Stale geometry after aliased setRange indicates a field-name canonicalization miss.",
        )
    for alias in (
        "putRangeGeometry",
        "configureRangeGeometry",
        "defineRange",
        "resizeRange",
        "setLockingRangeGeometry",
        "configureBandGeometry",
        "setLbaRange",
    ):
        context = activated_locking_context() + [
            function_record(alias, [], {"rangeId": 1, "RangeStart": 240, "RangeLength": 8, "authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{alias} geometry alias accepts current getRange state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"RangeStart": 240, "RangeLength": 8})],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to the official Locking range geometry Set path.",
        )
        yield Probe(
            f"{alias} geometry alias rejects stale getRange state",
            context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 8})],
            "FAIL",
            "locking-wrapper",
            f"Stale getRange after {alias} indicates the wrapper mutation was ignored.",
        )
    for alias, expected_start in (
        ("setLockingRange", 204),
        ("setupRange", 208),
        ("setBand", 212),
        ("configureBand", 216),
        ("setBandRange", 220),
        ("updateRange", 228),
        ("modifyRange", 232),
        ("setRangeConfig", 236),
        ("setLockingRangeState", 240),
        ("updateLockingRange", 244),
    ):
        context = activated_locking_context() + [
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "start": expected_start, "length": 4, "authAs": ("Admin1", "new")}}, "output": {"return": True}}
        ]
        yield Probe(
            f"{alias} updates Locking range geometry",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": expected_start, "RangeLength": 4})],
            "PASS",
            "locking-wrapper",
            f"{alias} is an SDK-style spelling for configuring a Locking range row.",
        )
        yield Probe(
            f"{alias} rejects stale Locking range geometry",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0})],
            "FAIL",
            "locking-wrapper",
            f"{alias} must update the same tracked row state as setRange.",
        )
    range_alias_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"rangeId": 1, "start": 224, "length": 6, "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    for alias in (
        "getLockingRange",
        "getBand",
        "getBandRange",
        "getRangeInfo",
        "getRangeState",
        "readRange",
        "fetchRange",
        "queryRange",
        "rangeStatus",
        "getLockingRangeState",
        "readLockingRange",
        "loadRange",
    ):
        yield Probe(
            f"{alias} reads tracked Locking range geometry",
            range_alias_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 224, "RangeLength": 6})],
            "PASS",
            "locking-wrapper",
            f"{alias} is a composite getter alias for the selected Locking range row.",
        )
        yield Probe(
            f"{alias} rejects stale Locking range geometry",
            range_alias_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0})],
            "FAIL",
            "locking-wrapper",
            f"{alias} must compare returned range fields against tracked state.",
        )
    field_context = activated_locking_context() + [
        {"input": {"function": "setRangeStart", "kwargs": {"range": 1, "start": 176, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "setRangeLength", "kwargs": {"range": 1, "length": 12, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "enableReadLock", "kwargs": {"range": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "setReadLocked", "kwargs": {"range": 1, "locked": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "range field helper setters update composite getRange state",
        field_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 176, "RangeLength": 12, "ReadLockEnabled": True, "ReadLocked": True})],
        "PASS",
        "locking-wrapper",
        "Dedicated range field setter helpers should update the same Locking row state as setRange.",
    )
    yield Probe(
        "range field helper setters reject stale getRange state",
        field_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0, "ReadLockEnabled": False, "ReadLocked": False})],
        "FAIL",
        "locking-wrapper",
        "Stale range state means dedicated field helper mutations were ignored.",
    )
    yield Probe(
        "range field helper setters reject omitted non-default getRange lock fields",
        field_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 176, "RangeLength": 12})],
        "FAIL",
        "locking-wrapper",
        "Once getRange exposes an observed range after lock-state mutation, it cannot omit non-default lock fields from the composite state.",
    )
    yield Probe(
        "getRangeStart helper returns current RangeStart",
        field_context + [{"input": {"function": "getRangeStart", "kwargs": {"range": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"RangeStart": 176}}}],
        "PASS",
        "locking-wrapper",
        "Dedicated range field getters should read only the selected Locking column.",
    )
    yield Probe(
        "isReadLocked helper rejects stale unlocked state",
        field_context + [{"input": {"function": "isReadLocked", "kwargs": {"range": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReadLocked": False}}}],
        "FAIL",
        "locking-wrapper",
        "A stale field getter result means column-specific Locking reads were not wired to tracked state.",
    )
    yield Probe(
        "isReadLocked helper accepts named getter result",
        field_context + [{"input": {"function": "isReadLocked", "kwargs": {"range": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"isReadLocked": True}}}],
        "PASS",
        "locking-wrapper",
        "A Boolean helper may return the value under its own getter name.",
    )
    yield Probe(
        "isReadLocked helper rejects pure success envelope",
        field_context + [{"input": {"function": "isReadLocked", "kwargs": {"range": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"success": True}}}],
        "FAIL",
        "locking-wrapper",
        "A pure SDK success envelope does not contain the tracked ReadLocked value.",
    )


def getrange_values_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {"authAs": ("Admin1", "new"), "RangeStart": 88, "RangeLength": 8, "ReadLocked": 1},
            True,
        )
    ]
    payload = {"values": {"range": 1, "authAs": ("Admin1", "new")}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        raw = operation_payload("getRange", payload, key=shape, output={"return": {"RangeStart": 88, "RangeLength": 8, "ReadLocked": 1}})
        yield Probe(
            f"getRange {shape} values envelope accepts current state",
            context + [raw],
            "PASS",
            "locking-wrapper",
            "Wrapper getRange values-envelope selectors should target the selected Locking row.",
        )
        stale = operation_payload("getRange", payload, key=shape, output={"return": {"RangeStart": 0, "RangeLength": 0, "ReadLocked": 0}})
        yield Probe(
            f"getRange {shape} values envelope rejects stale state",
            context + [stale],
            "FAIL",
            "locking-wrapper",
            "Stale getRange values-envelope output indicates BandNone/opaque-dict targeting.",
        )
    for selector_key in ("rangeName", "range_name", "bandName", "band_name"):
        selector_context = activated_locking_context() + [
            {"input": {"function": "setRange", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new"), "RangeStart": 132, "RangeLength": 8}}}, "output": {"return": True}},
        ]
        yield Probe(
            f"getRange values-envelope {selector_key} accepts current geometry",
            selector_context + [{"input": {"function": "getRange", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"RangeStart": 132, "RangeLength": 8}}}],
            "PASS",
            "locking-wrapper",
            f"`{selector_key}` inside a values envelope should select Locking_Range1.",
        )
        yield Probe(
            f"getRange values-envelope {selector_key} rejects stale geometry",
            selector_context + [{"input": {"function": "getRange", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"RangeStart": 0, "RangeLength": 8}}}],
            "FAIL",
            "locking-wrapper",
            f"`{selector_key}` inside a values envelope cannot target BandNone or ignore prior setRange state.",
        )
        boolean_only = operation_payload("getRange", payload, key=shape, output={"return": True})
        yield Probe(
            f"getRange {shape} values envelope rejects Boolean-only result",
            context + [boolean_only],
            "FAIL",
            "locking-wrapper",
            "getRange returns range state values; a literal Boolean wrapper success is not a range payload.",
        )
        if shape == "kwargs":
            yield Probe(
                "getRange values envelope rejects empty current-state result",
                context + [operation_payload("getRange", payload, key=shape, output={"return": {}})],
                "FAIL",
                "locking-wrapper",
                "After Range state is observed, getRange must return at least one range state field rather than an empty success payload.",
            )
            yield Probe(
                "getRange values envelope rejects status-only current-state result",
                context + [operation_payload("getRange", payload, key=shape, output={"return": "SUCCESS"})],
                "FAIL",
                "locking-wrapper",
                "After Range state is observed, getRange success must expose range state fields rather than a status token payload.",
            )
        yield Probe(
            f"getRange {shape} values envelope rejects nested/list Boolean result",
            context + [operation_payload("getRange", payload, key=shape, output={"return": {"Data": True}})],
            "FAIL",
            "locking-wrapper",
            "getRange returns named range state fields; a Boolean hidden under an unrelated payload key is not a range payload.",
        )
    yield Probe(
        "getRange values envelope rejects scalar range payload",
        context + [operation_payload("getRange", payload, key="kwargs", output={"return": 1})],
        "FAIL",
        "locking-wrapper",
        "getRange returns named range state fields; a scalar integer is not a structured range payload.",
    )
    alias_context = activated_locking_context() + [
        function_record(
            "setRange",
            [],
            {"id": 1, "authAs": ("Admin1", "new"), "RangeStart": 96, "RangeLength": 8, "ReadLocked": True},
            True,
        )
    ]
    for selector_key in ("target", "object", "uid", "rangeName", "name", "rangeUid", "range_uid", "bandName", "band_name"):
        yield Probe(
            f"getRange top-level {selector_key} selector accepts current state",
            alias_context
            + [function_record("getRange", [], {selector_key: 1, "authAs": ("Admin1", "new")}, {"RangeStart": 96, "RangeLength": 8, "ReadLocked": True})],
            "PASS",
            "locking-wrapper",
            f"Top-level {selector_key} should select the Locking range row.",
        )
        yield Probe(
            f"getRange top-level {selector_key} selector rejects stale state",
            alias_context
            + [function_record("getRange", [], {selector_key: 1, "authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0, "ReadLocked": False})],
            "FAIL",
            "locking-wrapper",
            f"Stale getRange output indicates top-level {selector_key} selector was ignored.",
        )


def lock_unlock_probes() -> Iterable[Probe]:
    for function, column, good, stale in (
        ("readLock", "ReadLocked", 1, 0),
        ("writeLock", "WriteLocked", 1, 0),
        ("readUnlock", "ReadLocked", 0, 1),
        ("writeUnlock", "WriteLocked", 0, 1),
    ):
        for range_key in ("range", "band_id", "lockingRangeId", "rangeNumber"):
            raw = operation_payload(function, {"authAs": ("Admin1", "new"), range_key: 1, "locked": bool(good)}, key="args1")
            context = activated_locking_context() + [raw]
            yield Probe(
                f"{function} single-dict {range_key} accepts {column}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
                "PASS",
                "locking-wrapper",
                "Explicit lock/unlock wrappers should target the selected range.",
            )
            yield Probe(
                f"{function} single-dict {range_key} rejects stale {column}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
                "FAIL",
                "locking-wrapper",
                "Stale lock cell after lock/unlock is a hidden-score-like false PASS.",
            )
        for range_key in ("id", "object", "target", "uid"):
            raw = operation_payload(function, {"authAs": ("Admin1", "new"), range_key: 1, "locked": bool(good)}, key="kwargs")
            context = activated_locking_context() + [raw]
            yield Probe(
                f"{function} top-level {range_key} accepts {column}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
                "PASS",
                "locking-wrapper",
                f"Top-level {range_key} should select the Locking range for lock/unlock wrappers.",
            )
            yield Probe(
                f"{function} top-level {range_key} rejects stale {column}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
                "FAIL",
                "locking-wrapper",
                f"Stale lock cell indicates top-level {range_key} selector was ignored.",
            )
        raw = operation_payload(function, {"values": {"authAs": ("Admin1", "new"), "range": 1, "locked": bool(good)}}, key="kwargs")
        context = activated_locking_context() + [raw]
        yield Probe(
            f"{function} values envelope accepts {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            "Values-envelope lock/unlock wrappers should target the selected range.",
        )
        yield Probe(
            f"{function} values envelope rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            "Ignoring values-envelope lock/unlock calls creates stale Locking cell false PASSes.",
        )
        symbolic_payload = {"values": {"authAs": ("Admin1", "new"), "range": "Locking_Range1", "locked": bool(good)}}
        for shape in ("args1", "kwargs", "params", "request", "call"):
            raw = operation_payload(function, symbolic_payload, key=shape)
            context = activated_locking_context() + [raw]
            yield Probe(
                f"{function} {shape} symbolic Locking_Range1 rejects stale {column}",
                context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
                "FAIL",
                "locking-wrapper",
                "Symbolic lock/unlock selectors should canonicalize to the selected Locking range.",
            )
    for function, column, good, stale in (
        ("lockReadRange", "ReadLocked", 1, 0),
        ("readLockRange", "ReadLocked", 1, 0),
        ("unlockReadRange", "ReadLocked", 0, 1),
        ("readUnlockRange", "ReadLocked", 0, 1),
        ("lockWriteRange", "WriteLocked", 1, 0),
        ("writeLockRange", "WriteLocked", 1, 0),
        ("unlockWriteRange", "WriteLocked", 0, 1),
        ("writeUnlockRange", "WriteLocked", 0, 1),
        ("lockReadForRange", "ReadLocked", 1, 0),
        ("readLockForRange", "ReadLocked", 1, 0),
        ("unlockReadForRange", "ReadLocked", 0, 1),
        ("readUnlockForRange", "ReadLocked", 0, 1),
        ("lockWriteForRange", "WriteLocked", 1, 0),
        ("writeLockForRange", "WriteLocked", 1, 0),
        ("unlockWriteForRange", "WriteLocked", 0, 1),
        ("writeUnlockForRange", "WriteLocked", 0, 1),
    ):
        context = activated_locking_context() + [
            function_record(function, [1], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{function} ordered range alias accepts {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            "SDK-style lock/read/write/range word-order aliases should target the documented Locking row lock columns.",
        )
        yield Probe(
            f"{function} ordered range alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            "If a range lock alias is parsed as UNKNOWN, stale Locking state can be accepted.",
        )
    for function, getter, column in (
        ("updateReadLockEnabled", "getReadLockEnabled", "ReadLockEnabled"),
        ("putReadLockEnabled", "getReadLockEnabled", "ReadLockEnabled"),
        ("updateWriteLockEnabled", "getWriteLockEnabled", "WriteLockEnabled"),
        ("putWriteLockEnabled", "getWriteLockEnabled", "WriteLockEnabled"),
        ("updateReadLocked", "getReadLocked", "ReadLocked"),
        ("putReadLocked", "getReadLocked", "ReadLocked"),
        ("updateWriteLocked", "getWriteLocked", "WriteLocked"),
        ("putWriteLocked", "getWriteLocked", "WriteLocked"),
    ):
        context = activated_locking_context() + [
            function_record(function, [], {"range": 1, column: True, "authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{function} update/put alias accepts current {column}",
            context + [function_record(getter, [], {"range": 1, "authAs": ("Admin1", "new")}, {column: True})],
            "PASS",
            "locking-wrapper",
            f"{function} is a bounded SDK-style setter for the official Locking.{column} cell.",
        )
        yield Probe(
            f"{function} update/put alias rejects stale {column}",
            context + [function_record(getter, [], {"range": 1, "authAs": ("Admin1", "new")}, {column: False})],
            "FAIL",
            "locking-wrapper",
            f"Stale {column} after {function} indicates the wrapper mutation was ignored.",
        )
    for function, column, good, stale in (
        ("updateRangeStart", "RangeStart", 144, 0),
        ("putRangeStart", "RangeStart", 144, 0),
        ("storeRangeStart", "RangeStart", 144, 0),
        ("saveRangeStart", "RangeStart", 144, 0),
        ("programRangeStart", "RangeStart", 144, 0),
        ("updateRangeLBA", "RangeStart", 144, 0),
        ("putRangeLBA", "RangeStart", 144, 0),
        ("updateStartLBA", "RangeStart", 144, 0),
        ("putStartLBA", "RangeStart", 144, 0),
        ("updateRangeLength", "RangeLength", 12, 0),
        ("putRangeLength", "RangeLength", 12, 0),
        ("storeRangeLength", "RangeLength", 12, 0),
        ("saveRangeLength", "RangeLength", 12, 0),
        ("programRangeLength", "RangeLength", 12, 0),
        ("updateRangeSize", "RangeLength", 12, 0),
        ("putRangeSize", "RangeLength", 12, 0),
        ("storeRangeSize", "RangeLength", 12, 0),
        ("saveRangeSize", "RangeLength", 12, 0),
        ("updateRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("putRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("storeRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("saveRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("configureRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("updateReadLockingEnabled", "ReadLockEnabled", True, False),
        ("putReadLockingEnabled", "ReadLockEnabled", True, False),
        ("updateRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("putRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("storeRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("saveRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("configureRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("updateWriteLockingEnabled", "WriteLockEnabled", True, False),
        ("putWriteLockingEnabled", "WriteLockEnabled", True, False),
        ("updateRangeReadLocked", "ReadLocked", True, False),
        ("putRangeReadLocked", "ReadLocked", True, False),
        ("storeRangeReadLocked", "ReadLocked", True, False),
        ("saveRangeReadLocked", "ReadLocked", True, False),
        ("configureRangeReadLocked", "ReadLocked", True, False),
        ("updateRangeReadLockState", "ReadLocked", True, False),
        ("putRangeReadLockState", "ReadLocked", True, False),
        ("clearReadLocked", "ReadLocked", False, True),
        ("clearRangeReadLocked", "ReadLocked", False, True),
        ("updateRangeWriteLocked", "WriteLocked", True, False),
        ("putRangeWriteLocked", "WriteLocked", True, False),
        ("storeRangeWriteLocked", "WriteLocked", True, False),
        ("saveRangeWriteLocked", "WriteLocked", True, False),
        ("configureRangeWriteLocked", "WriteLocked", True, False),
        ("updateRangeWriteLockState", "WriteLocked", True, False),
        ("putRangeWriteLockState", "WriteLocked", True, False),
        ("clearWriteLocked", "WriteLocked", False, True),
        ("clearRangeWriteLocked", "WriteLocked", False, True),
    ):
        args = [1] if function.lower().startswith("clear") else [1, good]
        context = activated_locking_context() + [
            function_record(function, args, {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{function} range-cell alias accepts current {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            f"{function} is an explicit wrapper setter for the official Locking.{column} cell.",
        )
        yield Probe(
            f"{function} range-cell alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            f"Stale {column} after {function} indicates the wrapper mutation was ignored.",
        )
    range_cell_getter_context = activated_locking_context() + [
        function_record("setRange", [1, 144, 12, True, True, True, True], {"authAs": ("Admin1", "new")}, True),
    ]
    for function, column, good, stale in (
        ("readRangeStart", "RangeStart", 144, 0),
        ("fetchRangeStart", "RangeStart", 144, 0),
        ("queryRangeStart", "RangeStart", 144, 0),
        ("loadRangeStart", "RangeStart", 144, 0),
        ("readRangeLBA", "RangeStart", 144, 0),
        ("fetchRangeLBA", "RangeStart", 144, 0),
        ("queryRangeLBA", "RangeStart", 144, 0),
        ("loadRangeLBA", "RangeStart", 144, 0),
        ("readStartLBA", "RangeStart", 144, 0),
        ("fetchStartLBA", "RangeStart", 144, 0),
        ("queryStartLBA", "RangeStart", 144, 0),
        ("loadStartLBA", "RangeStart", 144, 0),
        ("readRangeLength", "RangeLength", 12, 0),
        ("fetchRangeLength", "RangeLength", 12, 0),
        ("queryRangeLength", "RangeLength", 12, 0),
        ("loadRangeLength", "RangeLength", 12, 0),
        ("readRangeSize", "RangeLength", 12, 0),
        ("fetchRangeSize", "RangeLength", 12, 0),
        ("queryRangeSize", "RangeLength", 12, 0),
        ("loadRangeSize", "RangeLength", 12, 0),
        ("readRangeLen", "RangeLength", 12, 0),
        ("fetchRangeLen", "RangeLength", 12, 0),
        ("queryRangeLen", "RangeLength", 12, 0),
        ("loadRangeLen", "RangeLength", 12, 0),
        ("readReadLockEnabled", "ReadLockEnabled", True, False),
        ("fetchReadLockEnabled", "ReadLockEnabled", True, False),
        ("queryReadLockEnabled", "ReadLockEnabled", True, False),
        ("loadReadLockEnabled", "ReadLockEnabled", True, False),
        ("readRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("fetchRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("queryRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("loadRangeReadLockEnabled", "ReadLockEnabled", True, False),
        ("readWriteLockEnabled", "WriteLockEnabled", True, False),
        ("fetchWriteLockEnabled", "WriteLockEnabled", True, False),
        ("queryWriteLockEnabled", "WriteLockEnabled", True, False),
        ("loadWriteLockEnabled", "WriteLockEnabled", True, False),
        ("readRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("fetchRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("queryRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("loadRangeWriteLockEnabled", "WriteLockEnabled", True, False),
        ("readReadLocked", "ReadLocked", True, False),
        ("fetchReadLocked", "ReadLocked", True, False),
        ("queryReadLocked", "ReadLocked", True, False),
        ("loadReadLocked", "ReadLocked", True, False),
        ("readRangeReadLocked", "ReadLocked", True, False),
        ("fetchRangeReadLocked", "ReadLocked", True, False),
        ("queryRangeReadLocked", "ReadLocked", True, False),
        ("loadRangeReadLocked", "ReadLocked", True, False),
        ("readReadLockState", "ReadLocked", True, False),
        ("fetchReadLockState", "ReadLocked", True, False),
        ("queryReadLockState", "ReadLocked", True, False),
        ("loadReadLockState", "ReadLocked", True, False),
        ("readWriteLocked", "WriteLocked", True, False),
        ("fetchWriteLocked", "WriteLocked", True, False),
        ("queryWriteLocked", "WriteLocked", True, False),
        ("loadWriteLocked", "WriteLocked", True, False),
        ("readRangeWriteLocked", "WriteLocked", True, False),
        ("fetchRangeWriteLocked", "WriteLocked", True, False),
        ("queryRangeWriteLocked", "WriteLocked", True, False),
        ("loadRangeWriteLocked", "WriteLocked", True, False),
        ("readWriteLockState", "WriteLocked", True, False),
        ("fetchWriteLockState", "WriteLocked", True, False),
        ("queryWriteLockState", "WriteLocked", True, False),
        ("loadWriteLockState", "WriteLocked", True, False),
    ):
        yield Probe(
            f"{function} range-cell getter accepts current {column}",
            range_cell_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            f"{function} is an explicit wrapper getter for the official Locking.{column} cell.",
        )
        yield Probe(
            f"{function} range-cell getter rejects stale {column}",
            range_cell_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            f"Stale {column} from {function} indicates the getter was not compared against tracked state.",
        )
    for function, payload_key in (
        ("readReadLocked", "locked"),
        ("fetchReadLocked", "locked"),
        ("queryReadLocked", "locked"),
        ("loadReadLocked", "locked"),
        ("readRangeReadLocked", "locked"),
        ("fetchRangeReadLocked", "locked"),
        ("queryRangeReadLocked", "locked"),
        ("loadRangeReadLocked", "locked"),
        ("readWriteLocked", "locked"),
        ("fetchWriteLocked", "locked"),
        ("queryWriteLocked", "locked"),
        ("loadWriteLocked", "locked"),
        ("readRangeWriteLocked", "locked"),
        ("fetchRangeWriteLocked", "locked"),
        ("queryRangeWriteLocked", "locked"),
        ("loadRangeWriteLocked", "locked"),
        ("readReadLockState", "state"),
        ("fetchReadLockState", "state"),
        ("queryReadLockState", "state"),
        ("loadReadLockState", "state"),
        ("readWriteLockState", "state"),
        ("fetchWriteLockState", "state"),
        ("queryWriteLockState", "state"),
        ("loadWriteLockState", "state"),
    ):
        yield Probe(
            f"{function} bool payload accepts current {payload_key}",
            range_cell_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, {payload_key: True})],
            "PASS",
            "locking-wrapper",
            f"{function} may return a wrapper Boolean under `{payload_key}` for the tracked locked-state cell.",
        )
        yield Probe(
            f"{function} bool payload rejects stale {payload_key}",
            range_cell_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, {payload_key: False})],
            "FAIL",
            "locking-wrapper",
            f"{function} must compare `{payload_key}` Boolean payloads against tracked Locking state.",
        )
    for function, column, good, stale in (
        ("enableReadLockRange", "ReadLockEnabled", 1, 0),
        ("disableReadLockRange", "ReadLockEnabled", 0, 1),
        ("enableWriteLockRange", "WriteLockEnabled", 1, 0),
        ("disableWriteLockRange", "WriteLockEnabled", 0, 1),
        ("enableReadLockForRange", "ReadLockEnabled", 1, 0),
        ("disableReadLockForRange", "ReadLockEnabled", 0, 1),
        ("enableWriteLockForRange", "WriteLockEnabled", 1, 0),
        ("disableWriteLockForRange", "WriteLockEnabled", 0, 1),
        ("setReadLockedForRange", "ReadLocked", 1, 0),
        ("setWriteLockedForRange", "WriteLocked", 1, 0),
    ):
        context = activated_locking_context() + [
            function_record(function, [1], {"authAs": ("Admin1", "new"), "value": bool(good)}, True),
        ]
        yield Probe(
            f"{function} explicit range alias accepts {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            "Enable/disable and explicit locked-for-range helpers should update the matching Locking column.",
        )
        yield Probe(
            f"{function} explicit range alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            "Stale Locking column after an explicit range helper indicates a parser/state miss.",
        )
    for function, column, good, stale in (
        ("setRangeReadLockedState", "ReadLocked", 1, 0),
        ("markReadLocked", "ReadLocked", 1, 0),
        ("setRangeWriteLockedState", "WriteLocked", 1, 0),
        ("markWriteLocked", "WriteLocked", 1, 0),
    ):
        context = activated_locking_context() + [
            function_record(function, [1], {"authAs": ("Admin1", "new"), "locked": bool(good)}, True),
        ]
        yield Probe(
            f"{function} locked-state alias accepts {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: good})],
            "PASS",
            "locking-wrapper",
            f"{function} should update the tracked Locking {column} cell.",
        )
        yield Probe(
            f"{function} locked-state alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "locking-wrapper",
            f"{function} must not leave stale Locking locked-state cells.",
        )
    locked_getter_context = activated_locking_context() + [
        function_record("readLock", [1], {"authAs": ("Admin1", "new")}, True),
        function_record("writeLock", [1], {"authAs": ("Admin1", "new")}, True),
    ]
    for function, column in (
        ("getReadLockedState", "ReadLocked"),
        ("isRangeReadLockSet", "ReadLocked"),
        ("rangeReadLocked", "ReadLocked"),
        ("getWriteLockedState", "WriteLocked"),
        ("isRangeWriteLockSet", "WriteLocked"),
        ("rangeWriteLocked", "WriteLocked"),
    ):
        yield Probe(
            f"{function} locked-state getter accepts true {column}",
            locked_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, True)],
            "PASS",
            "locking-wrapper",
            f"{function} is a boolean getter for the tracked Locking {column} cell.",
        )
        yield Probe(
            f"{function} locked-state getter rejects stale false {column}",
            locked_getter_context + [function_record(function, [1], {"authAs": ("Admin1", "new")}, False)],
            "FAIL",
            "locking-wrapper",
            f"{function} cannot return false after the corresponding lock wrapper succeeded.",
        )
    for setter, getter, good, stale in (
        ("enableReadLockRange", "getReadLockEnabledRange", True, False),
        ("disableReadLockForRange", "isReadLockEnabledForRange", False, True),
        ("enableWriteLockRange", "getWriteLockEnabledRange", True, False),
        ("disableWriteLockForRange", "isWriteLockEnabledForRange", False, True),
        ("lockReadRange", "getReadLockedRange", True, False),
        ("unlockReadForRange", "isReadLockedForRange", False, True),
        ("lockWriteRange", "getWriteLockedRange", True, False),
        ("unlockWriteForRange", "isWriteLockedForRange", False, True),
    ):
        context = activated_locking_context() + [
            function_record(setter, [1], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{getter} ordered getter accepts current Boolean after {setter}",
            context + [function_record(getter, [1], {"authAs": ("Admin1", "new")}, good)],
            "PASS",
            "locking-wrapper",
            "Explicit range getter aliases should compare their Boolean return against tracked Locking state.",
        )
        yield Probe(
            f"{getter} ordered getter rejects stale Boolean after {setter}",
            context + [function_record(getter, [1], {"authAs": ("Admin1", "new")}, stale)],
            "FAIL",
            "locking-wrapper",
            "A getter alias parsed as UNKNOWN or as a generic status wrapper can accept stale Locking booleans.",
        )
    failed_context = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {"authAs": ("Admin1", "new"), "RangeStart": 80, "RangeLength": 8, "WriteLockEnabled": 1, "WriteLocked": 0},
            True,
        )
    ]
    failed_lock = operation_payload(
        "writeLock",
        {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
        key="kwargs",
        output={"return": {"ok": False}},
    )
    yield Probe(
        "Failed writeLock nested ok false preserves unlocked host write",
        failed_context + [failed_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
        "PASS",
        "locking-wrapper",
        "Nested boolean return objects like return:{ok:false} should not apply lock side effects.",
    )
    yield Probe(
        "Failed writeLock nested ok false rejects phantom lock",
        failed_context + [failed_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
        "FAIL",
        "locking-wrapper",
        "Failed wrapper calls must not mutate the Locking range state.",
    )
    failed_status_lock = operation_payload(
        "writeLock",
        {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
        key="kwargs",
        output={"return": {"status": "FAIL"}},
    )
    yield Probe(
        "Failed writeLock nested status FAIL preserves unlocked host write",
        failed_context + [failed_status_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
        "PASS",
        "locking-wrapper",
        "Nested return status fields should be honored before applying mutating wrapper side effects.",
    )
    yield Probe(
        "Failed writeLock nested status FAIL rejects phantom lock",
        failed_context + [failed_status_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
        "FAIL",
        "locking-wrapper",
        "Failed wrapper calls must not mutate the Locking range state.",
    )
    failed_error_lock = operation_payload(
        "writeLock",
        {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
        key="kwargs",
        output={"return": {"error": True}},
    )
    yield Probe(
        "Failed writeLock nested error true preserves unlocked host write",
        failed_context + [failed_error_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
        "PASS",
        "locking-wrapper",
        "Nested return error flags should be honored before applying mutating wrapper side effects.",
    )
    yield Probe(
        "Failed writeLock nested error true rejects phantom lock",
        failed_context + [failed_error_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
        "FAIL",
        "locking-wrapper",
        "Failed wrapper calls must not mutate the Locking range state.",
    )
    failed_passed_lock = operation_payload(
        "writeLock",
        {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
        key="kwargs",
        output={"passed": False},
    )
    yield Probe(
        "Failed writeLock top-level passed false preserves unlocked host write",
        failed_context + [failed_passed_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
        "PASS",
        "locking-wrapper",
        "Top-level passed:false should be treated as a failed mutating wrapper call.",
    )
    yield Probe(
        "Failed writeLock top-level passed false rejects phantom lock",
        failed_context + [failed_passed_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
        "FAIL",
        "locking-wrapper",
        "Failed wrapper calls must not mutate the Locking range state.",
    )
    for result_key in ("isSuccess", "successFlag"):
        failed_nested_success_lock = operation_payload(
            "writeLock",
            {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
            key="kwargs",
            output={"return": {result_key: False}},
        )
        yield Probe(
            f"Failed writeLock nested {result_key} false preserves unlocked host write",
            failed_context + [failed_nested_success_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
            "PASS",
            "locking-wrapper",
            "Nested success aliases should be honored before applying mutating wrapper side effects.",
        )
        yield Probe(
            f"Failed writeLock nested {result_key} false rejects phantom lock",
            failed_context + [failed_nested_success_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
            "FAIL",
            "locking-wrapper",
            "Failed wrapper calls must not mutate the Locking range state.",
        )
    for output in (
        {"return": {"authorized": True, "success": False}},
        {"return": {"allowed": True, "passed": False}},
        {"authorized": True, "success": False},
    ):
        failed_conflict_lock = operation_payload(
            "writeLock",
            {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
            key="kwargs",
            output=output,
        )
        yield Probe(
            f"Failed writeLock conflicting flags {sorted(output)} preserves unlocked host write",
            failed_context + [failed_conflict_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
            "PASS",
            "locking-wrapper",
            "Authorization true only says the call was allowed; success false means the mutation did not happen.",
        )
        yield Probe(
            f"Failed writeLock conflicting flags {sorted(output)} rejects phantom lock",
            failed_context + [failed_conflict_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
            "FAIL",
            "locking-wrapper",
            "A mutating wrapper with authorization true but success false must not update Locking state.",
        )
    for output in ({"return": {"denied": True}}, {"response": {"unauthorized": True}}, {"return": {"authFailed": True}}):
        failed_denied_lock = operation_payload(
            "writeLock",
            {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
            key="kwargs",
            output=output,
        )
        yield Probe(
            f"Denied writeLock {sorted(output)} preserves unlocked host write",
            failed_context + [failed_denied_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
            "PASS",
            "locking-wrapper",
            "Nested denial flags should be honored before applying mutating wrapper side effects.",
        )
        yield Probe(
            f"Denied writeLock {sorted(output)} rejects phantom lock",
            failed_context + [failed_denied_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
            "FAIL",
            "locking-wrapper",
            "Denied wrapper calls must not mutate the Locking range state.",
        )
    for output in ({"return": {"rejected": True}}, {"response": {"forbidden": True}}, {"return": {"accessDenied": True}}):
        failed_rejected_lock = operation_payload(
            "writeLock",
            {"values": {"range": 1, "authAs": ("Admin1", "new"), "locked": True}},
            key="kwargs",
            output=output,
        )
        yield Probe(
            f"Rejected writeLock {sorted(output)} preserves unlocked host write",
            failed_context + [failed_rejected_lock, host_write_status(SUCCESS, lba="80 ~ 87")],
            "PASS",
            "locking-wrapper",
            "Nested rejection flags should be honored before applying mutating wrapper side effects.",
        )
        yield Probe(
            f"Rejected writeLock {sorted(output)} rejects phantom lock",
            failed_context + [failed_rejected_lock, host_write_status(NOT_AUTHORIZED, lba="80 ~ 87")],
            "FAIL",
            "locking-wrapper",
            "Rejected wrapper calls must not mutate the Locking range state.",
        )


def genkey_probes() -> Iterable[Probe]:
    base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {"authAs": ("Admin1", "new"), "RangeStart": 80, "RangeLength": 8, "ReadLockEnabled": 1, "WriteLockEnabled": 1},
            True,
        ),
        host_write("AA", lba="80"),
    ]
    payloads = [
        {"authAs": ("Admin1", "new"), "range": 1},
        {"authAs": ("Admin1", "new"), "rangeName": 1},
        {"authAs": ("Admin1", "new"), "bandName": 1},
        {"authAs": ("Admin1", "new"), "band_name": 1},
        {"auth": "Admin1", "key": "K_AES_256_Range1_Key"},
        {"auth": "Admin1", "range_key": "K_AES_256_Range1_Key"},
        {"authAs": ("Admin1", "new"), "band_id": 1},
        {"authAs": ("Admin1", "new"), "id": 1},
        {"authAs": ("Admin1", "new"), "object": 1},
        {"authAs": ("Admin1", "new"), "target": 1},
        {"authAs": ("Admin1", "new"), "key": 1},
        {"authAs": ("Admin1", "new"), "range_key": 1},
        {"authAs": ("Admin1", "new"), "mek": 1},
        {"authAs": ("Admin1", "new"), "activeKey": 1},
        {"values": {"authAs": ("Admin1", "new"), "range": 1}},
        {"values": {"authAs": ("Admin1", "new"), "rangeName": 1}},
        {"values": {"authAs": ("Admin1", "new"), "bandName": 1}},
        {"values": {"authAs": ("Admin1", "new"), "band_name": 1}},
        {"values": {"auth": "Admin1", "key": "K_AES_256_Range1_Key"}},
        {"values": {"authAs": ("Admin1", "new"), "key": 1}},
        {"values": {"authAs": ("Admin1", "new"), "activeKey": 1}},
        {"values": {"authAs": ("Admin1", "new"), "range": "Locking_Range1"}},
    ]
    for payload in payloads:
        for shape in ("args1", "kwargs", "params", "request", "call"):
            raw = operation_payload("genKey", payload, key=shape)
            yield Probe(
                f"genKey {shape} {sorted(payload)} invalidates old Range1 data",
                base + [raw, host_read("AA", lba="80")],
                "FAIL",
                "media-key-wrapper",
                "Successful Range1 genKey should invalidate prior host data for that range.",
            )
    for alias in ("generateKey", "regenKey", "newKey", "createKey", "makeKey", "refreshKey", "rollKey", "generateRangeKey", "genRangeKey", "newRangeKey", "createRangeKey", "makeRangeKey", "rotateRangeKey", "regenerateRangeKey", "renewRangeKey", "rollRangeKey", "rekeyRange", "rekey", "refreshRangeKey", "generateMEK", "refreshMEK", "rotateMEK"):
        yield Probe(
            f"{alias} rangeId invalidates old Range1 data",
            base + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}}, host_read("AA", lba="80")],
            "FAIL",
            "media-key-wrapper",
            f"{alias} is an SDK-style alias for genKey on the selected range media key.",
        )
    for alias in ("genKey", "generateKey", "genRangeKey", "rotateKey", "rekeyRange"):
        for label, payload in (
            ("policy", {"range": 1, "authAs": ("Admin1", "new")}),
            ("config", {"target": "K_AES_256_Range1_Key", "authAs": ("Admin1", "new")}),
            ("request", {"target": {"range": 1}, "credential": {"auth": "Admin1", "proof": "new"}}),
            ("operation", {"target": {"range": 1}, "command": {"authAs": ("Admin1", "new")}}),
            ("lockingRequest", {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
            ("rangeRequest", {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
            ("keyRequest", {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}),
            ("lockingRangeRequest", {"key": {"rangeId": 1}, "authAs": ("Admin1", "new")}),
        ):
            yield Probe(
                f"{alias} {label} envelope invalidates old Range1 data",
                base + [{"input": {"function": alias, "kwargs": {label: payload}}, "output": {"return": True}}, host_read("AA", lba="80")],
                "FAIL",
                "genkey-policy-envelope-doc",
                "GenKey policy/config/request envelopes must preserve the selected media key and Admin authority before rotating key state.",
            )
        yield Probe(
            f"{alias} wrong wrapper authAs cannot inherit Admin session",
            locking_admin_open()
            + [
                {
                    "input": {"function": alias, "kwargs": {"range_key": "K_AES_256_Range1_Key", "authAs": ("User1", "wrong")}},
                    "output": {"return": True},
                }
            ],
            "FAIL",
            "media-key-wrapper",
            f"{alias} must evaluate explicit authAs in a wrapper-scoped session, not the ambient Admin1 raw session.",
        )
    for alias in ("rotateKey", "regenerateKey"):
        yield Probe(
            f"failed {alias} preserves old Range1 data",
            base + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ok": False}}}, host_read("AA", lba="80")],
            "PASS",
            "media-key-wrapper",
            f"A failed {alias} wrapper must not apply K_AES GenKey side effects.",
        )
    yield Probe(
        "generateKey User authAs lacks Admins for Range1 media key",
        locking_admin_open()
        + [
            set_values("", "User1", {5: 1}),
            set_values("", "C_PIN_User1", {3: "userpin"}),
            {"input": {"function": "generateKey", "kwargs": {"range_key": "K_AES_256_Range1_Key", "authAs": ("User1", "userpin")}}, "output": {"return": True}},
        ],
        "FAIL",
        "media-key-wrapper",
        "Correct User1 credentials still do not satisfy the Admins authority required for K_AES range-key GenKey.",
    )


def getmek_values_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {10: "K_AES_256_Range1_Key"}),
    ]
    payload = {"values": {"range": 1, "authAs": ("Admin1", "new")}}
    good = {"K_AES_256_Range1_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x01"}
    stale = {"K_AES_256_Range2_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x02"}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"getMEK {shape} values envelope accepts Range1 ActiveKey",
            context + [operation_payload("getMEK", payload, key=shape, output={"return": good})],
            "PASS",
            "media-key-wrapper",
            "getMEK values envelopes should target the selected Locking range ActiveKey.",
        )
        yield Probe(
            f"getMEK {shape} values envelope rejects stale Range2 ActiveKey",
            context + [operation_payload("getMEK", payload, key=shape, output={"return": stale})],
            "FAIL",
            "media-key-wrapper",
            "Stale getMEK values-envelope output indicates the range selector was ignored.",
        )
    for label, payload in (
        ("Band1", {"values": {"band": "Band1", "authAs": ("Admin1", "new")}}),
        ("Locking_Range1", {"values": {"range": "Locking_Range1", "authAs": ("Admin1", "new")}}),
        ("rangeName", {"values": {"rangeName": 1, "authAs": ("Admin1", "new")}}),
        ("bandName", {"values": {"bandName": 1, "authAs": ("Admin1", "new")}}),
        ("band_name", {"values": {"band_name": 1, "authAs": ("Admin1", "new")}}),
    ):
        for shape in ("args1", "kwargs", "params", "request", "call"):
            yield Probe(
                f"getMEK {shape} symbolic {label} rejects stale Range2 ActiveKey",
                context + [operation_payload("getMEK", payload, key=shape, output={"return": stale})],
                "FAIL",
                "media-key-wrapper",
                "Symbolic getMEK selectors should canonicalize to the selected Locking range.",
            )
    for label, payload in (
        ("id", {"id": 1, "authAs": ("Admin1", "new")}),
        ("object", {"object": 1, "authAs": ("Admin1", "new")}),
        ("target", {"target": 1, "authAs": ("Admin1", "new")}),
        ("key", {"key": 1, "authAs": ("Admin1", "new")}),
        ("range_key", {"range_key": 1, "authAs": ("Admin1", "new")}),
        ("mek", {"mek": 1, "authAs": ("Admin1", "new")}),
        ("activeKey", {"activeKey": 1, "authAs": ("Admin1", "new")}),
    ):
        for shape in ("args1", "kwargs", "params", "request", "call"):
            yield Probe(
                f"getMEK {shape} {label} selector accepts Range1 ActiveKey",
                context + [operation_payload("getMEK", payload, key=shape, output={"return": good})],
                "PASS",
                "media-key-wrapper",
                f"Top-level getMEK `{label}` should select the Range1 ActiveKey.",
            )
            yield Probe(
                f"getMEK {shape} {label} selector rejects stale Range2 ActiveKey",
                context + [operation_payload("getMEK", payload, key=shape, output={"return": stale})],
                "FAIL",
                "media-key-wrapper",
                f"Top-level getMEK `{label}` should not ignore the selected Range1 ActiveKey.",
            )
    range2_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {10: "K_AES_256_Range1_Key"}),
        set_values("0000080200030002", "Locking_Range2", {10: "K_AES_256_Range2_Key"}),
    ]
    range2_good = {"K_AES_256_Range2_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x02"}
    range2_stale = {"K_AES_256_Range1_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x01"}
    for function_name in ("getMEK", "getActiveKey", "readMEK"):
        for envelope_name, payload in (
            ("policy", {"range": 2, "authAs": ("Admin1", "new")}),
            ("config", {"target": "Locking_Range2", "authAs": ("Admin1", "new")}),
            ("request", {"target": {"range": 2}, "credential": {"auth": "Admin1", "proof": "new"}}),
            ("lockingRequest", {"values": {"rangeId": 2, "authAs": ("Admin1", "new")}}),
            ("rangeRequest", {"values": {"rangeId": 2, "authAs": ("Admin1", "new")}}),
            ("keyRequest", {"target": {"rangeId": 2}, "authAs": ("Admin1", "new")}),
            ("lockingRangeRequest", {"key": {"rangeId": 2}, "authAs": ("Admin1", "new")}),
            ("operation", {"target": {"rangeId": 2}, "command": {"authAs": ("Admin1", "new")}}),
            ("operationRequest", {"target": {"rangeId": 2}, "command": {"authAs": ("Admin1", "new")}}),
        ):
            tag = "getmek-operation-envelope-doc" if "operation" in envelope_name else "getmek-policy-envelope-doc"
            yield Probe(
                f"{function_name} {envelope_name} envelope accepts Range2 ActiveKey",
                range2_context + [{"input": {"function": function_name, "kwargs": {envelope_name: payload}}, "output": {"return": range2_good}}],
                "PASS",
                tag,
                "Nested media-key read wrappers should keep the selected range and Admin credential.",
            )
            yield Probe(
                f"{function_name} {envelope_name} envelope rejects stale Range1 ActiveKey",
                range2_context + [{"input": {"function": function_name, "kwargs": {envelope_name: payload}}, "output": {"return": range2_stale}}],
                "FAIL",
                tag,
                "Stale Range1 ActiveKey output means the Range2 selector was dropped from the wrapper envelope.",
            )


def erase_probes() -> Iterable[Probe]:
    base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {"authAs": ("Admin1", "new"), "RangeStart": 80, "RangeLength": 8, "ReadLockEnabled": 1, "WriteLockEnabled": 1},
            True,
        ),
        host_write("AA", lba="80"),
    ]
    for shape, raw_input in (
        ("values", {"function": "erase", "values": {"range": 1, "authAs": "EraseMaster"}}),
        ("values rangeName", {"function": "erase", "values": {"rangeName": 1, "authAs": "EraseMaster"}}),
        ("values bandName", {"function": "erase", "values": {"bandName": 1, "authAs": "EraseMaster"}}),
        ("call values", {"call": {"function": "erase", "values": {"range": 1, "authAs": "EraseMaster"}}}),
    ):
        yield Probe(
            f"erase {shape} envelope invalidates old Range1 data",
            base + [{"input": raw_input, "output": {"return": True}}, host_read("AA", lba="80")],
            "FAIL",
            "media-key-wrapper",
            "erase values envelopes should target the selected range and invalidate old media data.",
        )
    for function_name in ("erase", "eraseRange"):
        for label, payload in (
            ("policy", {"range": 1, "authAs": "EraseMaster"}),
            ("config", {"target": "Locking_Range1", "authAs": "EraseMaster"}),
            ("request", {"target": {"range": 1}, "credential": {"auth": "EraseMaster"}}),
            ("operation", {"target": {"range": 1}, "command": {"authAs": "EraseMaster"}}),
            ("eraseRequest", {"target": {"rangeId": 1}, "authAs": "EraseMaster"}),
            ("lockingRangeRequest", {"erase": {"rangeId": 1}, "authAs": "EraseMaster"}),
        ):
            yield Probe(
                f"{function_name} {label} envelope invalidates old Range1 data",
                base + [{"input": {"function": function_name, "kwargs": {label: payload}}, "output": {"return": True}}, host_read("AA", lba="80")],
                "FAIL",
                "erase-policy-envelope-doc",
                "Erase policy/config/request envelopes must preserve the selected Locking range before invalidating media data.",
            )
    for label, payload in (
        ("Locking_Range1", {"values": {"range": "Locking_Range1", "authAs": "EraseMaster"}}),
        ("Band1", {"values": {"band": "Band1", "authAs": "EraseMaster"}}),
        ("eraseRange rangeId", {"function": "eraseRange", "kwargs": {"rangeId": 1, "authAs": "EraseMaster"}}),
        ("eraseRange values id", {"function": "eraseRange", "values": {"id": 1, "authAs": "EraseMaster"}}),
    ):
        shapes = ("raw",) if payload.get("function") == "eraseRange" else ("args1", "kwargs", "params", "request", "call")
        for shape in shapes:
            raw = {"input": payload, "output": {"return": True}} if shape == "raw" else operation_payload("erase", payload, key=shape)
            yield Probe(
                f"erase {shape} symbolic {label} invalidates old Range1 data",
                base + [raw, host_read("AA", lba="80")],
                "FAIL",
                "media-key-wrapper",
                "Symbolic erase range selectors should canonicalize to the selected Locking range.",
            )


def datastore_probes() -> Iterable[Probe]:
    base = owned_admin_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    writes = [
        {"auth": "Admin1", "data": "AABB", "offset": 4},
        {"authAs": ("Admin1", "new"), "payload": "CCDD", "byteOffset": 6},
        {"auth": "Admin1", "bytes": [0x11, 0x22], "position": 8},
        {"authAs": ("Admin1", "new"), "values": {"data": "3344", "offset": 10}},
        {"authAs": ("Admin1", "new"), "payload_bytes": "5566", "start_offset": 12},
        {"authAs": ("Admin1", "new"), "value": "7788", "offset": 14},
        {"authAs": ("Admin1", "new"), "dataBytes": "99AA", "offset": 16},
    ]
    for payload in writes:
        for shape in ("args1", "kwargs", "params", "request", "call"):
            raw = operation_payload("writeData", payload, key=shape, output={"success": True})
            payload_values = payload.get("values", {}) if isinstance(payload.get("values"), dict) else {}
            offset = int(payload.get("offset", payload.get("byteOffset", payload.get("position", payload.get("start_offset", payload_values.get("offset", 0))))))
            expected = "AABB" if "data" in payload else "CCDD" if "payload" in payload else "1122" if "bytes" in payload else "5566" if "payload_bytes" in payload else "7788" if "value" in payload else "99AA" if "dataBytes" in payload else "3344"
            context = base + [raw]
            yield Probe(
                f"writeData {shape} sparse payload visible in raw Get {offset}",
                context
                + [
                    method_record(
                        "Get",
                        "0000100100000000",
                        "DataStore",
                        optional={"Where": {"Row": offset}, "CellBlock": [{"startRow": offset}, {"endRow": offset + 1}]},
                        return_values=expected,
                    )
                ],
                "PASS",
                "datastore-wrapper",
                "Wrapper writeData should mutate the shared byte-table state.",
            )
            yield Probe(
                f"writeData {shape} sparse payload rejects stale raw Get {offset}",
                context
                + [
                    method_record(
                        "Get",
                        "0000100100000000",
                        "DataStore",
                        optional={"Where": {"Row": offset}, "CellBlock": [{"startRow": offset}, {"endRow": offset + 1}]},
                        return_values="0000",
                    )
                ],
                "FAIL",
                "datastore-wrapper",
                "Stale raw DataStore bytes after wrapper writeData are a concrete false PASS.",
            )

    for write_fn, read_fn in (
        ("setUserData", "getUserData"),
        ("writeDataStoreBytes", "getDataStoreBytes"),
        ("setDataStoreBytes", "readDataStoreBytes"),
        ("putDataStoreBytes", "getDataStoreBytes"),
        ("saveDataStoreBytes", "fetchDataStoreBytes"),
        ("programDataStore", "readDSPayload"),
        ("programDataStoreBytes", "getDSPayload"),
        ("putDataStorePayload", "fetchDataStorePayload"),
        ("setDataStorePayload", "readDataStorePayload"),
        ("putDSBytes", "fetchDSBytes"),
        ("updateDataStoreBytes", "loadDataStorePayload"),
        ("updateDataStorePayload", "getDataStorePayload"),
        ("updateDSBytes", "loadDSBytes"),
        ("writeDSPayload", "readDSPayload"),
        ("storeDataStorePayload", "fetchDSPayload"),
        ("storeDataStoreBytes", "getDataStoreBytes"),
        ("storeDSPayload", "loadDSPayload"),
        ("saveDataStorePayload", "fetchDataStorePayload"),
        ("saveDSPayload", "loadDSPayload"),
        ("programDSPayload", "readDSPayload"),
        ("programDataStorePayload", "getDataStorePayload"),
        ("programDSBytes", "getDSBytes"),
        ("putDSPayload", "getDSPayload"),
        ("updateDSPayload", "fetchDataStoreBytes"),
        ("setDSBytes", "getDSBytes"),
        ("writeDataBytes", "readDataBytes"),
        ("setDataBytes", "getDataBytes"),
        ("saveUserData", "loadUserData"),
        ("saveDataStore", "fetchUserData"),
        ("saveDS", "loadDS"),
        ("writeDataStorePayload", "getDataStorePayload"),
        ("setDataPayload", "readDataPayload"),
        ("writeUserPayload", "readUserPayload"),
        ("saveUserPayload", "fetchUserPayload"),
        ("storeUserPayload", "loadUserPayload"),
        ("setUserPayload", "getUserPayload"),
        ("writeDataBlock", "readDataBlock"),
        ("storeDataBlock", "fetchDataBlock"),
        ("saveDataBlock", "loadDataBlock"),
        ("setDataBlock", "getDataBlock"),
        ("writeUserDataBlock", "readUserDataBlock"),
        ("storeUserDataBlock", "fetchUserDataBlock"),
        ("writeDataSegment", "readDataSegment"),
        ("storeDataSegment", "fetchDataSegment"),
        ("writeDataRange", "readDataRange"),
        ("storeDataRange", "fetchDataRange"),
        ("writeDataChunk", "readDataChunk"),
        ("storeDataChunk", "fetchDataChunk"),
        ("saveDataChunk", "loadDataChunk"),
        ("setDataChunk", "getDataChunk"),
        ("writeUserDataChunk", "readUserDataChunk"),
        ("storeUserDataChunk", "fetchUserDataChunk"),
        ("writeDataWindow", "readDataWindow"),
        ("storeDataWindow", "fetchDataWindow"),
        ("setDataWindow", "getDataWindow"),
        ("saveDataWindow", "loadDataWindow"),
        ("writeDataSlice", "readDataSlice"),
        ("storeDataSlice", "fetchDataSlice"),
        ("setDataSlice", "getDataSlice"),
        ("writeUserDataSlice", "readUserDataSlice"),
        ("storeUserDataSlice", "fetchUserDataSlice"),
    ):
        context = base + [
            function_record(write_fn, [0, "AABB"], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{write_fn}/{read_fn} DataStore byte alias accepts payload",
            context + [function_record(read_fn, [0, 2], {"authAs": ("Admin1", "new")}, "AABB")],
            "PASS",
            "datastore-wrapper",
            "DataStore byte aliases should share the same sparse byte-table state as writeData/readData.",
        )
        yield Probe(
            f"{write_fn}/{read_fn} DataStore byte alias rejects stale payload",
            context + [function_record(read_fn, [0, 2], {"authAs": ("Admin1", "new")}, "0000")],
            "FAIL",
            "datastore-wrapper",
            "A DataStore byte alias parsed as UNKNOWN can miss stale byte payloads.",
        )
    datastore_payload_alias_context = locking_admin_open() + [
        function_record("writeData", [], {"authAs": ("Admin1", "new"), "offset": 2, "data": "AABBCC"}, True)
    ]
    for read_fn in (
        "fetchDataStore",
        "fetchDS",
        "loadDSBytes",
        "loadDataStoreBytes",
        "readDataStorePayload",
        "loadDataPayload",
        "fetchDataPayload",
        "fetchDataStoreBytes",
        "fetchDataStorePayload",
        "fetchDSBytes",
        "loadDataStorePayload",
        "fetchDSPayload",
        "loadDSPayload",
        "getDSPayload",
        "readDSPayload",
    ):
        yield Probe(
            f"{read_fn} reads DataStore sparse payload window",
            datastore_payload_alias_context + [function_record(read_fn, [], {"authAs": ("Admin1", "new"), "offset": 3, "length": 2}, "BBCC")],
            "PASS",
            "datastore-wrapper",
            f"{read_fn} is a bounded DataStore byte-table read alias.",
        )
        yield Probe(
            f"{read_fn} rejects stale DataStore sparse payload window",
            datastore_payload_alias_context + [function_record(read_fn, [], {"authAs": ("Admin1", "new"), "offset": 3, "length": 2}, "AABB")],
            "FAIL",
            "datastore-wrapper",
            f"{read_fn} must preserve the requested byte offset and length.",
        )

    wrong_auth_payload = {"values": {"authAs": ("Admin1", "wrong"), "data": "AABB", "offset": 4}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"writeData {shape} values envelope rejects wrong authAs",
            base + [operation_payload("writeData", wrong_auth_payload, key=shape, output={"return": True})],
            "FAIL",
            "datastore-wrapper",
            "writeData values-envelope authAs must validate wrapper credentials before mutating DataStore bytes.",
        )

    failed_write_base = base + [
        operation_payload("writeData", {"values": {"authAs": ("Admin1", "new"), "data": "AA", "offset": 0}}, key="kwargs", output={"return": True})
    ]
    for output in (
        {"return": {"authorized": False}},
        {"authorized": False},
        {"return": {"allowed": False}},
        {"return": {"authorized": True, "success": False}},
        {"authorized": True, "success": False},
    ):
        failed_write = operation_payload(
            "writeData",
            {"values": {"authAs": ("Admin1", "new"), "data": "BB", "offset": 0}},
            key="kwargs",
            output=output,
        )
        yield Probe(
            f"Failed writeData {sorted(output)} preserves previous byte",
            failed_write_base
            + [failed_write, operation_payload("readData", {"values": {"authAs": ("Admin1", "new"), "offset": 0, "length": 1}}, key="kwargs", output={"return": "AA"})],
            "PASS",
            "datastore-wrapper",
            "Authorization-style false outputs on mutating wrappers must not update DataStore bytes.",
        )
        yield Probe(
            f"Failed writeData {sorted(output)} rejects phantom byte",
            failed_write_base
            + [failed_write, operation_payload("readData", {"values": {"authAs": ("Admin1", "new"), "offset": 0, "length": 1}}, key="kwargs", output={"return": "BB"})],
            "FAIL",
            "datastore-wrapper",
            "A failed writeData call cannot leave the new byte visible.",
        )

    read_context = base + [
        operation_payload("writeData", {"authAs": ("Admin1", "new"), "values": {"data": "A1B2C3", "offset": 20}}, key="kwargs", output={"return": True})
    ]
    read_payload = {"values": {"authAs": ("Admin1", "new"), "offset": 20, "length": 3}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"readData {shape} values envelope accepts sparse slice",
            read_context + [operation_payload("readData", read_payload, key=shape, output={"return": "A1B2C3"})],
            "PASS",
            "datastore-wrapper",
            "Wrapper readData values-envelope windows should compare against tracked byte-table bytes.",
        )
        yield Probe(
            f"readData {shape} values envelope rejects stale sparse slice",
            read_context + [operation_payload("readData", read_payload, key=shape, output={"return": "000000"})],
            "FAIL",
            "datastore-wrapper",
            "Ignoring readData values-envelope windows lets stale DataStore bytes pass.",
        )
    snake_window_context = base + [
        operation_payload("writeData", {"authAs": ("Admin1", "new"), "payload_bytes": "AABBCCDD", "start_offset": 24}, key="kwargs", output={"return": True})
    ]
    yield Probe(
        "readData start_offset byte_count accepts sparse slice",
        snake_window_context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "start_offset": 25, "byte_count": 2}, key="kwargs", output={"return": "BBCC"})],
        "PASS",
        "datastore-wrapper",
        "Snake-case DataStore offset/window aliases should map to the byte-table window.",
    )
    yield Probe(
        "readData start_offset byte_count rejects stale prefix",
        snake_window_context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "start_offset": 25, "byte_count": 2}, key="kwargs", output={"return": "AABB"})],
        "FAIL",
        "datastore-wrapper",
        "A start_offset read window must not fall back to row zero or full-payload comparison.",
    )
    offset_bytes_context = base + [
        operation_payload("writeDataStore", {"authAs": ("Admin1", "new"), "offsetBytes": 5, "buffer": "AABBCC"}, key="kwargs", output={"return": True})
    ]
    yield Probe(
        "writeDataStore offsetBytes feeds readDataStore sizeBytes slice",
        offset_bytes_context + [operation_payload("readDataStore", {"authAs": ("Admin1", "new"), "offsetBytes": 6, "sizeBytes": 2}, key="kwargs", output={"return": "BBCC"})],
        "PASS",
        "datastore-wrapper",
        "offsetBytes and sizeBytes are SDK byte-window aliases over the official DataStore byte-table offset/length.",
    )
    yield Probe(
        "writeDataStore offsetBytes rejects stale readDataStore sizeBytes slice",
        offset_bytes_context + [operation_payload("readDataStore", {"authAs": ("Admin1", "new"), "offsetBytes": 6, "sizeBytes": 2}, key="kwargs", output={"return": "0000"})],
        "FAIL",
        "datastore-wrapper",
        "Ignoring offsetBytes/sizeBytes leaves stale DataStore byte windows over-accepted or valid windows under-accepted.",
    )
    byte_string_context = base + [
        operation_payload("writeData", {"authAs": ("Admin1", "new"), "byteString": "AABBCCDD", "offset": 30}, key="kwargs", output={"return": True})
    ]
    yield Probe(
        "writeData byteString alias feeds readData slice",
        byte_string_context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "offset": 31, "length": 2}, key="kwargs", output={"return": "BBCC"})],
        "PASS",
        "datastore-wrapper",
        "byteString is a common SDK byte-payload alias and should update the shared DataStore byte state.",
    )
    yield Probe(
        "writeData byteString alias rejects stale readData slice",
        byte_string_context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "offset": 31, "length": 2}, key="kwargs", output={"return": "AABB"})],
        "FAIL",
        "datastore-wrapper",
        "Ignoring byteString leaves stale DataStore read windows over-accepted.",
    )
    for offset_key in ("startByte", "byteIndex", "bytePosition"):
        context = base + [
            operation_payload("writeData", {"authAs": ("Admin1", "new"), offset_key: 4, "data": "AABBCC"}, key="kwargs", output={"return": True})
        ]
        yield Probe(
            f"writeData {offset_key} offset alias feeds readData slice",
            context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "offset": 5, "length": 2}, key="kwargs", output={"return": "BBCC"})],
            "PASS",
            "datastore-wrapper",
            f"{offset_key} is a bounded byte-offset alias for DataStore writes.",
        )
        yield Probe(
            f"writeData {offset_key} offset alias rejects stale readData slice",
            context + [operation_payload("readData", {"authAs": ("Admin1", "new"), "offset": 5, "length": 2}, key="kwargs", output={"return": "AABB"})],
            "FAIL",
            "datastore-wrapper",
            f"Ignoring {offset_key} leaves stale DataStore read windows over-accepted.",
        )
    for label, read_payload in (
        ("byteLength", {"authAs": ("Admin1", "new"), "offset": 25, "byteLength": 2}),
        ("nBytes", {"authAs": ("Admin1", "new"), "offset": 25, "nBytes": 2}),
        ("values byteLength", {"values": {"authAs": ("Admin1", "new"), "offset": 25, "byteLength": 2}}),
        ("bytesToRead", {"authAs": ("Admin1", "new"), "offset": 25, "bytesToRead": 2}),
        ("readLength", {"authAs": ("Admin1", "new"), "offset": 25, "readLength": 2}),
        ("readSize", {"authAs": ("Admin1", "new"), "offset": 25, "readSize": 2}),
        ("windowSize", {"authAs": ("Admin1", "new"), "offset": 25, "windowSize": 2}),
        ("numBytesToRead", {"authAs": ("Admin1", "new"), "offset": 25, "numBytesToRead": 2}),
        ("countBytes", {"authAs": ("Admin1", "new"), "offset": 25, "countBytes": 2}),
    ):
        yield Probe(
            f"readData {label} accepts sparse slice",
            snake_window_context + [operation_payload("readData", read_payload, key="kwargs", output={"return": "BBCC"})],
            "PASS",
            "datastore-wrapper",
            f"`{label}` should be treated as a byte window length alias.",
        )
        yield Probe(
            f"readData {label} rejects stale prefix",
            snake_window_context + [operation_payload("readData", read_payload, key="kwargs", output={"return": "AABB"})],
            "FAIL",
            "datastore-wrapper",
            f"`{label}` must not be ignored when slicing DataStore bytes.",
        )

    nested_window_context = base + [
        operation_payload("writeData", {"authAs": ("Admin1", "new"), "offset": 10, "data": "AABBCCDD"}, key="kwargs", output={"return": True})
    ]
    for label, nested_payload, expected in (
        ("window startByte/readSize", {"authAs": ("Admin1", "new"), "window": {"startByte": 11, "readSize": 2}}, "BBCC"),
        ("values byteIndex/windowSize", {"authAs": ("Admin1", "new"), "values": {"byteIndex": 12, "windowSize": 2}}, "CCDD"),
    ):
        yield Probe(
            f"readData nested {label} accepts sparse slice",
            nested_window_context + [operation_payload("readData", nested_payload, key="kwargs", output={"return": expected})],
            "PASS",
            "datastore-wrapper",
            "Nested DataStore byte-window envelopes should preserve bounded offset/length aliases.",
        )
        yield Probe(
            f"readData nested {label} rejects stale sparse slice",
            nested_window_context + [operation_payload("readData", nested_payload, key="kwargs", output={"return": "AABB"})],
            "FAIL",
            "datastore-wrapper",
            "Ignoring nested DataStore byte-window starts lets stale slices pass.",
        )

    for label, write_payload, read_payload in (
        ("top-level window", {"authAs": ("Admin1", "new"), "window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"window": {"offset": 4, "length": 3}}),
        ("top-level range", {"authAs": ("Admin1", "new"), "range": {"start": 4, "count": 3}, "data": "AABBCC"}, {"range": {"start": 4, "count": 3}}),
        ("top-level slice", {"authAs": ("Admin1", "new"), "slice": {"startOffset": 4, "byteCount": 3}, "payload": "AABBCC"}, {"slice": {"startOffset": 4, "byteCount": 3}}),
        ("request window", {"authAs": ("Admin1", "new"), "request": {"window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}}, {"window": {"offset": 4, "length": 3}}),
        ("policy range", {"authAs": ("Admin1", "new"), "policy": {"range": {"start": 4, "count": 3}, "data": "AABBCC"}}, {"request": {"values": {"window": {"offset": 4, "length": 3}}}}),
        ("config slice", {"authAs": ("Admin1", "new"), "config": {"slice": {"startOffset": 4, "byteCount": 3}, "payload": "AABBCC"}}, {"range": {"start": 4, "count": 3}}),
        ("request values window", {"authAs": ("Admin1", "new"), "request": {"values": {"window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}}}, {"window": {"offset": 4, "length": 3}}),
        ("operation command", {"operation": {"command": {"offset": 4, "length": 3, "bytes": "AABBCC", "authAs": ("Admin1", "new")}}}, {"operation": {"command": {"offset": 4, "length": 3, "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"offset": 4, "length": 3}, "command": {"bytes": "AABBCC", "authAs": ("Admin1", "new")}}}, {"operation": {"target": {"offset": 4, "length": 3}, "command": {"authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"offset": 4, "length": 3}, "command": {"bytes": "AABBCC", "authAs": ("Admin1", "new")}}}, {"operationRequest": {"target": {"offset": 4, "length": 3}, "command": {"authAs": ("Admin1", "new")}}}),
    ):
        context = base + [function_record("writeDataStore", [], write_payload, True)]
        tag = "datastore-nested-window-envelope-doc" if "top-level" not in label else "datastore-wrapper"
        yield Probe(
            f"writeDataStore {label} envelope feeds readDataStore",
            context + [function_record("readDataStore", [], {"authAs": ("Admin1", "new"), **read_payload}, "AABBCC")],
            "PASS",
            tag,
            "Top-level DataStore window/range/slice envelopes should preserve byte offset and length.",
        )
        yield Probe(
            f"writeDataStore {label} envelope rejects stale readDataStore",
            context + [function_record("readDataStore", [], {"authAs": ("Admin1", "new"), **read_payload}, "000000")],
            "FAIL",
            tag,
            "Ignoring top-level DataStore window/range/slice envelopes leaves stale bytes over-accepted.",
        )

    data_first_context = base + [
        {"input": {"function": "writeData", "args": ["AABB", 4], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    yield Probe(
        "writeData data-first positional args visible in raw Get",
        data_first_context
        + [
            method_record(
                "Get",
                "0000100100000000",
                "DataStore",
                optional={"Where": {"Row": 4}, "CellBlock": [{"startRow": 4}, {"endRow": 5}]},
                return_values="AABB",
            )
        ],
        "PASS",
        "datastore-wrapper",
        "When authAs is explicit, writeData positional args may be data and offset.",
    )
    yield Probe(
        "writeData data-first positional args rejects stale raw Get",
        data_first_context
        + [
            method_record(
                "Get",
                "0000100100000000",
                "DataStore",
                optional={"Where": {"Row": 4}, "CellBlock": [{"startRow": 4}, {"endRow": 5}]},
                return_values="0000",
            )
        ],
        "FAIL",
        "datastore-wrapper",
        "A data-first writeData representation must still mutate the shared byte table.",
    )
    offset_first_context = base + [
        function_record("writeData", ["Admin1", "AABBCC"], {"authAs": ("Admin1", "new"), "offset": 8}, True)
    ]
    yield Probe(
        "readData offset-first positional args accepts middle slice",
        offset_first_context + [{"input": {"function": "readData", "args": [9, 2], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": "BBCC"}}],
        "PASS",
        "datastore-wrapper",
        "When authAs is explicit, readData positional args may be offset and byte count.",
    )
    yield Probe(
        "readData offset-first positional args rejects shifted slice",
        offset_first_context + [{"input": {"function": "readData", "args": [9, 2], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
        "FAIL",
        "datastore-wrapper",
        "Offset-first readData must not collapse to a full or prefix byte-table read.",
    )

    access_context = base + [
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        function_record("writeData", ["Admin1", "AABB"], {"authAs": ("Admin1", "new")}, True),
    ]
    for function, target in (
        ("readAccess", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantReadAccess", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantDataRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantUserDataRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantPayloadRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantUserPayloadRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("allowDataRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("allowPayloadRead", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("allowReadAccess", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("setReadAccess", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("setPayloadReadAccess", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("writeAccess", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantWriteAccess", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantDataWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantUserDataWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantPayloadWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantUserPayloadWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("allowDataWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("allowPayloadWrite", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("allowWriteAccess", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("setWriteAccess", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("setPayloadWriteAccess", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
    ):
        payload = {"values": {"user": "User1", "table": "DataStore", "authAs": ("Admin1", "new")}}
        for shape in ("args1", "kwargs", "params", "request", "call"):
            yield Probe(
                f"{function} {shape} values envelope grants User1 DataStore access",
                access_context + [operation_payload(function, payload, key=shape, output={"return": True}), target],
                "PASS",
                "datastore-wrapper",
                "DataStore access wrappers may carry user/table/authAs inside a values envelope.",
            )
    for label, kwargs in (
        ("policy user table", {"policy": {"user": "User1", "table": "DataStore"}, "authAs": ("Admin1", "new")}),
        ("access identity object", {"access": {"identity": "User1", "object": "DataStore"}, "authAs": ("Admin1", "new")}),
        ("permission subject resource", {"permission": {"subject": "User1", "resource": "DataStore"}, "authAs": ("Admin1", "new")}),
        ("request access user table", {"request": {"access": {"user": "User1", "table": "DataStore"}}, "authAs": ("Admin1", "new")}),
        ("operation target command", {"operation": {"target": {"user": "User1", "table": "DataStore"}, "command": {"authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"user": "User1", "table": "DataStore"}, "command": {"authAs": ("Admin1", "new")}}}),
    ):
        granted = access_context + [{"input": {"function": "grantDataRead", "kwargs": kwargs}, "output": {"return": True}}]
        tag = "datastore-access-operation-envelope-doc" if "operation" in label else "datastore-wrapper"
        yield Probe(
            f"grantDataRead {label} envelope authorizes User1 readData",
            granted + [function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")],
            "PASS",
            tag,
            "DataStore read-access wrappers may carry user/table selectors inside structured policy/access/permission envelopes.",
        )
        yield Probe(
            f"grantDataRead {label} envelope rejects stale unauthorized empty read",
            granted + [function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value=[])],
            "FAIL",
            tag,
            "A missed read-access envelope leaves User1 unauthorized and can falsely accept an empty result.",
        )
    for label, kwargs in (
        ("operation target command", {"operation": {"target": {"user": "User1", "table": "DataStore"}, "command": {"authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"user": "User1", "table": "DataStore"}, "command": {"authAs": ("Admin1", "new")}}}),
    ):
        granted = access_context + [
            {"input": {"function": "grantDataWrite", "kwargs": kwargs}, "output": {"return": True}},
            function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True),
        ]
        yield Probe(
            f"grantDataWrite {label} envelope authorizes User1 writeData",
            granted + [function_record("readData", ["Admin1", 0, 2], {"authAs": ("Admin1", "new")}, return_value="CCDD")],
            "PASS",
            "datastore-access-operation-envelope-doc",
            "DataStore write-access operation wrappers must update the Set ACE before a User write can mutate bytes.",
        )
        yield Probe(
            f"grantDataWrite {label} envelope rejects stale bytes",
            granted + [function_record("readData", ["Admin1", 0, 2], {"authAs": ("Admin1", "new")}, return_value="AABB")],
            "FAIL",
            "datastore-access-operation-envelope-doc",
            "A missed write-access operation envelope leaves User writes unauthorized and can falsely preserve stale bytes.",
        )
    for function, mode, target in (
        ("grantDataAccess", "read", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantUserDataAccess", "read", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("allowDataAccess", "read", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("setDataAccess", "read", function_record("readData", ["User1", 0, 2], {"authAs": ("User1", "userpin")}, return_value="AABB")),
        ("grantDataAccess", "write", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("grantUserDataAccess", "write", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("allowDataAccess", "write", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
        ("setDataAccess", "write", function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, True)),
    ):
        payload = {"values": {"user": "User1", "table": "DataStore", "mode": mode, "authAs": ("Admin1", "new")}}
        yield Probe(
            f"{function} mode={mode} grants User1 DataStore access",
            access_context + [operation_payload(function, payload, key="kwargs", output={"return": True}), target],
            "PASS",
            "datastore-wrapper",
            "Generic DataStore access wrappers should use explicit mode/access fields to select Get versus Set ACE personalization.",
        )
    for label, kwargs in (
        ("access identity object", {"access": {"identity": "User1", "object": "DataStore"}, "authAs": ("Admin1", "new")}),
        ("permission subject resource", {"permission": {"subject": "User1", "resource": "DataStore"}, "authAs": ("Admin1", "new")}),
        ("request access user table", {"request": {"access": {"user": "User1", "table": "DataStore"}}, "authAs": ("Admin1", "new")}),
    ):
        for mode_key in ("mode", "operation", "access", "permission"):
            shaped_kwargs = dict(kwargs)
            if "access" in shaped_kwargs:
                shaped_kwargs["access"] = {**shaped_kwargs["access"], mode_key: "write"}
            elif "permission" in shaped_kwargs:
                shaped_kwargs["permission"] = {**shaped_kwargs["permission"], mode_key: "write"}
            else:
                shaped_kwargs["request"] = {"access": {**shaped_kwargs["request"]["access"], mode_key: "write"}}
            granted = access_context + [
                {"input": {"function": "grantDataAccess", "kwargs": shaped_kwargs}, "output": {"return": True}},
                function_record("writeData", ["User1", "EEFF"], {"authAs": ("User1", "userpin")}, True),
            ]
            yield Probe(
                f"grantDataAccess {label} {mode_key}=write envelope mutates bytes",
                granted + [function_record("readData", ["Admin1", 0, 2], {"authAs": ("Admin1", "new")}, return_value="EEFF")],
                "PASS",
                "datastore-wrapper",
                "Generic DataStore access wrappers should select the Set ACE from nested write-mode selectors.",
            )
            yield Probe(
                f"grantDataAccess {label} {mode_key}=write envelope rejects stale bytes",
                granted + [function_record("readData", ["Admin1", 0, 2], {"authAs": ("Admin1", "new")}, return_value="AABB")],
                "FAIL",
                "datastore-wrapper",
                "A missed write-mode selector can falsely leave DataStore bytes unchanged after an accepted User write.",
            )
    write_granted = access_context + [
        operation_payload("writeAccess", {"values": {"user": "User1", "table": "DataStore", "authAs": ("Admin1", "new")}}, key="kwargs", output={"return": True})
    ]
    for empty_payload in ({}, []):
        yield Probe(
            f"writeData rejects empty success payload {type(empty_payload).__name__}",
            write_granted + [function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, empty_payload)],
            "FAIL",
            "datastore-wrapper",
            "TCGstorageAPI writeData is a Boolean mutating wrapper; empty dict/list return payloads must not be promoted to success.",
        )
    for success_payload in ({"success": True}, {"ok": True}, {"authorized": True}):
        yield Probe(
            f"writeData accepts structured success payload {next(iter(success_payload))}",
            write_granted + [function_record("writeData", ["User1", "CCDD"], {"authAs": ("User1", "userpin")}, success_payload)],
            "PASS",
            "datastore-wrapper",
            "A pure structured success envelope is an SDK Boolean return, not a non-empty TCG Set result payload.",
        )


def reset_lockonreset_probes() -> Iterable[Probe]:
    base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "ReadLockEnabled": 1,
                "WriteLockEnabled": 1,
                "ReadLocked": 0,
                "WriteLocked": 0,
                "LockOnReset": [0],
            },
            True,
        )
    ]
    for setter, getter in (
        ("updateLockOnReset", "getLockOnReset"),
        ("putLockOnReset", "readLockOnReset"),
        ("setLockingRangeLockOnReset", "fetchLockOnReset"),
        ("updateRangeLOR", "getRangeLOR"),
        ("putRangeLOR", "readRangeLOR"),
        ("configureLOR", "fetchLOR"),
    ):
        context = activated_locking_context() + [
            function_record(setter, [], {"range": 1, "LockOnReset": [0, 3], "authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{setter}/{getter} aliases accept current LockOnReset list",
            context + [function_record(getter, [], {"range": 1, "authAs": ("Admin1", "new")}, {"LockOnReset": [0, 3]})],
            "PASS",
            "reset-locking-wrapper",
            "LockOnReset update/put/read/fetch/LOR aliases should share the official Locking.LockOnReset column state.",
        )
        yield Probe(
            f"{setter}/{getter} aliases reject stale LockOnReset list",
            context + [function_record(getter, [], {"range": 1, "authAs": ("Admin1", "new")}, {"LockOnReset": [0]})],
            "FAIL",
            "reset-locking-wrapper",
            "A stale LockOnReset list after a successful wrapper Set indicates alias lowering missed the tracked column.",
        )
    reset_payloads = [
        ("powerCycle canonical", {"function": "powerCycle"}),
        ("doPowerCycle alias", {"function": "doPowerCycle"}),
        ("powerCycleDevice alias", {"function": "powerCycleDevice"}),
        ("devicePowerCycle alias", {"function": "devicePowerCycle"}),
        ("powerCycleTPer alias", {"function": "powerCycleTPer"}),
        ("powerCycleReset alias", {"function": "powerCycleReset"}),
        ("doPowerCycleReset alias", {"function": "doPowerCycleReset"}),
        ("resetPowerCycle alias", {"function": "resetPowerCycle"}),
        ("powerCycle call envelope", {"call": {"function": "powerCycle"}}),
        ("powerReset", {"function": "powerReset"}),
        ("coldReset", {"function": "coldReset"}),
        ("reset defaults to PowerCycle", {"function": "reset"}),
        ("command PowerCycle", {"command": "PowerCycle", "args": {}}),
        ("operation PowerCycle", {"operation": "PowerCycle", "args": {}}),
        ("event PowerCycle", {"event": "PowerCycle"}),
        ("resetType PowerCycle", {"resetType": "PowerCycle"}),
    ]
    for label, inp in reset_payloads:
        raw = {"input": inp, "output": {"return": True}}
        context = base + [raw]
        yield Probe(
            f"LockOnReset wrapper {label} blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Power-cycle reset aliases should apply LockOnReset and lock the configured range.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts WRITE_LOCKED host token",
            context + [host_write_status("WRITE_LOCKED", pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Host I/O logs may report a locked write as WRITE_LOCKED; this is the expected failure outcome after LockOnReset.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts READ_LOCKED host token",
            context + [host_read_status("READ_LOCKED", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Host I/O logs may report a locked read as READ_LOCKED; this is the expected failure outcome after LockOnReset.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts generic LOCKED host token",
            context + [host_read_status("LOCKED", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Some host logs collapse locked read/write failures to a generic LOCKED status token.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts access-denied host token",
            context + [host_write_status("ACCESS_DENIED", pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Some host logs spell a locked write as ACCESS_DENIED rather than a TCG method status.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts return-field access-denied token",
            context + [{"input": {"command": "Write", "args": {"LBA": "80 ~ 87", "pattern": "CC"}}, "output": {"return": "ACCESS_DENIED"}}],
            "PASS",
            "reset-locking-wrapper",
            "Host I/O failure tokens may appear in output.return rather than output.status.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} rejects result-field success token on locked read",
            context + [{"input": {"command": "Read", "args": {"LBA": "80 ~ 87"}}, "output": {"result": "SUCCESS"}}],
            "FAIL",
            "reset-locking-wrapper",
            "A locked read cannot be accepted merely because a success token was placed in result instead of status.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} rejects return-field true on locked read",
            context + [{"input": {"command": "Read", "args": {"LBA": "80 ~ 87"}}, "output": {"return": True}}],
            "FAIL",
            "reset-locking-wrapper",
            "A locked read cannot treat Boolean true in output.return as absent read data.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} accepts payload-field write-locked token",
            context + [{"input": {"command": "Write", "args": {"LBA": "80 ~ 87", "pattern": "CC"}}, "output": {"payload": "WRITE_LOCKED"}}],
            "PASS",
            "reset-locking-wrapper",
            "Host I/O failure tokens may appear in generic payload fields rather than status fields.",
        )
        yield Probe(
            f"LockOnReset wrapper {label} rejects stale unlocked host write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            "A missed reset alias leaves the range unlocked and can create a false PASS.",
        )

    hardware_base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "WriteLockEnabled": 1,
                "WriteLocked": 0,
                "LockOnReset": [0, 1],
            },
            True,
        )
    ]
    for alias in ("hardReset", "doHardwareReset", "deviceReset", "resetDevice", "platformReset", "hardwareResetDevice", "resetHardware"):
        context = hardware_base + [{"input": {"function": alias}, "output": {"return": True}}]
        yield Probe(
            f"LockOnReset hardware alias {alias} blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} should lower to hardware reset type 1 when LockOnReset includes it.",
        )
        yield Probe(
            f"LockOnReset hardware alias {alias} rejects stale unlocked host write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"Ignoring {alias} leaves reset-locked ranges writable.",
        )

    generic_hardware_base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "WriteLockEnabled": 1,
                "WriteLocked": 0,
                "LockOnReset": [1],
            },
            True,
        )
    ]
    for label, kwargs in (
        ("direct resetType", {"resetType": "HardwareReset"}),
        ("policy resetType", {"policy": {"resetType": "HardwareReset"}}),
        ("request type", {"request": {"type": "HardwareReset"}}),
        ("target string", {"target": "HardwareReset"}),
        ("operation reset", {"operation": {"reset": "HardwareReset"}}),
    ):
        context = generic_hardware_base + [{"input": {"function": "reset", "kwargs": kwargs}, "output": {"return": True}}]
        yield Probe(
            f"generic reset {label} blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-envelope-type-doc",
            "Generic reset wrappers with explicit HardwareReset payloads should feed reset type 1.",
        )
        yield Probe(
            f"generic reset {label} rejects stale unlocked host write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-envelope-type-doc",
            "Dropping the reset-type envelope leaves HardwareReset-only LockOnReset ranges writable.",
        )

    tper_reset_base = activated_locking_context() + [
        method_record("Get", "", "TPerInfo", return_values={8: True}),
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "WriteLockEnabled": 1,
                "WriteLocked": 0,
                "LockOnReset": [0, 3],
            },
            True,
        ),
    ]
    context = tper_reset_base + [{"input": {"function": "resetTPer"}, "output": {"return": True}}]
    yield Probe(
        "LockOnReset resetTPer alias blocks later host write",
        context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
        "PASS",
        "reset-locking-wrapper",
        "resetTPer should lower to TPer/programmatic reset type 3 when enabled.",
    )
    yield Probe(
        "LockOnReset resetTPer alias rejects stale unlocked host write",
        context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
        "FAIL",
        "reset-locking-wrapper",
        "Ignoring resetTPer leaves reset-locked ranges writable.",
    )

    failed_reset_payloads = [
        ("powerCycle return false", {"input": {"function": "powerCycle"}, "output": {"return": False}}),
        ("powerCycle ok false", {"input": {"function": "powerCycle"}, "output": {"ok": False}}),
        ("powerCycle isOk false", {"input": {"function": "powerCycle"}, "output": {"isOk": False}}),
        ("powerCycle successFlag false", {"input": {"function": "powerCycle"}, "output": {"successFlag": False}}),
        ("powerCycle status FAIL", {"input": {"function": "powerCycle"}, "output": {"status": "FAIL"}}),
        ("command PowerCycle status FAIL", {"input": {"command": "PowerCycle", "args": {}}, "output": {"command": "PowerCycle", "status": "FAIL"}}),
    ]
    for label, raw in failed_reset_payloads:
        context = base + [raw]
        yield Probe(
            f"Failed LockOnReset wrapper {label} preserves unlocked write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "A failed reset event must not apply LockOnReset side effects.",
        )
        yield Probe(
            f"Failed LockOnReset wrapper {label} rejects phantom lock",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            "Failed reset output must not lock ranges as if the reset succeeded.",
        )

    lor_wrapper_base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "ReadLockEnabled": 1,
                "WriteLockEnabled": 1,
                "ReadLocked": 0,
                "WriteLocked": 0,
            },
            True,
        ),
        function_record("setLockOnReset", [1, [0]], {"authAs": ("Admin1", "new")}, True),
    ]
    lor_values_base = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "ReadLockEnabled": 1,
                "WriteLockEnabled": 1,
                "ReadLocked": 0,
                "WriteLocked": 0,
            },
            True,
        ),
        {
            "input": {"function": "setLockOnReset", "kwargs": {"rangeId": 1, "lockOnReset": [0], "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    for label, context in (("positional", lor_wrapper_base), ("rangeId alias", lor_values_base)):
        after_reset = context + [{"input": {"function": "powerCycle"}, "output": {"return": True}}]
        yield Probe(
            f"setLockOnReset {label} blocks later host write",
            after_reset + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Dedicated LockOnReset wrappers should feed the same reset state machine as setRange LockOnReset.",
        )
        yield Probe(
            f"setLockOnReset {label} rejects stale unlocked write",
            after_reset + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            "A missed dedicated LockOnReset wrapper leaves the range unlocked after reset.",
        )
    for selector_key in ("rangeName", "range_name", "bandName", "band_name"):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "WriteLockEnabled": 1,
                    "WriteLocked": 0,
                },
                True,
            ),
            {
                "input": {"function": "setLockOnReset", "kwargs": {"values": {selector_key: 1, "lockOnReset": [0], "authAs": ("Admin1", "new")}}},
                "output": {"return": True},
            },
        ]
        yield Probe(
            f"setLockOnReset values {selector_key} reports reset list",
            context + [{"input": {"function": "getLockOnReset", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"LockOnReset": [0]}}}],
            "PASS",
            "reset-locking-wrapper",
            f"`values.{selector_key}` should select the same Locking range row as rangeId in LockOnReset wrappers.",
        )
        yield Probe(
            f"setLockOnReset values {selector_key} rejects stale reset list",
            context + [{"input": {"function": "getLockOnReset", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"LockOnReset": [3]}}}],
            "FAIL",
            "reset-locking-wrapper",
            f"`values.{selector_key}` cannot fall through to an untracked/default LockOnReset row.",
        )
        after_reset = context + [{"input": {"function": "powerCycle"}, "output": {"return": True}}]
        yield Probe(
            f"setLockOnReset values {selector_key} blocks later host write",
            after_reset + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"`values.{selector_key}` LockOnReset configuration must feed reset-time lock enforcement.",
        )
        yield Probe(
            f"setLockOnReset values {selector_key} rejects stale unlocked write",
            after_reset + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"Ignoring `values.{selector_key}` leaves the selected range unlocked after PowerCycle.",
        )
    for reset_key in ("types", "resetEvents", "reset_on", "resetList"):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "WriteLockEnabled": 1,
                    "WriteLocked": 0,
                },
                True,
            ),
            {"input": {"function": "setLockOnReset", "kwargs": {"rangeId": 1, reset_key: [0], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "powerCycle"}, "output": {"return": True}},
        ]
        yield Probe(
            f"setLockOnReset {reset_key} reset-list alias blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"`{reset_key}` is a bounded reset-type-list alias inside explicit LockOnReset wrappers.",
        )
        yield Probe(
            f"setLockOnReset {reset_key} reset-list alias rejects stale unlocked write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"Ignoring `{reset_key}` leaves the configured range unlocked after a matching reset.",
        )
    for label, kwargs in (
        ("policy resetTypes", {"rangeId": 1, "policy": {"resetTypes": [0]}, "authAs": ("Admin1", "new")}),
        ("config lor", {"rangeId": 1, "config": {"lor": [0]}, "authAs": ("Admin1", "new")}),
        ("values policy resetTypes", {"values": {"rangeId": 1, "policy": {"resetTypes": [0]}, "authAs": ("Admin1", "new")}}),
    ):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "WriteLockEnabled": 1,
                    "WriteLocked": 0,
                },
                True,
            ),
            {"input": {"function": "setLockOnReset", "kwargs": kwargs}, "output": {"return": True}},
            {"input": {"function": "powerCycle"}, "output": {"return": True}},
        ]
        yield Probe(
            f"setLockOnReset {label} envelope blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            "Policy/config LockOnReset envelopes should update the same official reset-type list as direct setters.",
        )
        yield Probe(
            f"setLockOnReset {label} envelope rejects stale unlocked write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            "Ignoring policy/config LockOnReset envelopes leaves the configured range unlocked after PowerCycle.",
        )
    for label, kwargs in (
        ("request values", {"request": {"values": {"rangeId": 1, "LockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
        ("policy request values", {"policy": {"request": {"values": {"rangeId": 1, "lockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}}),
        ("config target reset", {"config": {"target": {"rangeId": 1}, "reset": {"types": [0, 3]}, "authAs": ("Admin1", "new")}}),
        ("lockingRequest values", {"lockingRequest": {"values": {"rangeId": 1, "lockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
        ("lockingRangeRequest values", {"lockingRangeRequest": {"values": {"rangeId": 1, "lockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
        ("operation command", {"operation": {"command": {"rangeId": 1, "LockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"LockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"rangeId": 1}, "command": {"LockOnReset": [0, 3], "authAs": ("Admin1", "new")}}}),
    ):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "WriteLockEnabled": 1,
                    "WriteLocked": 0,
                },
                True,
            ),
            {"input": {"function": "setLockOnReset", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setLockOnReset {label} nested envelope reports reset list",
            context + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": [0, 3]}}}],
            "PASS",
            "lockonreset-nested-envelope-doc",
            "Nested LockOnReset setter envelopes should update the selected row's reset-type list.",
        )
        yield Probe(
            f"setLockOnReset {label} nested envelope rejects stale reset list",
            context + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": [0]}}}],
            "FAIL",
            "lockonreset-nested-envelope-doc",
            "Ignoring nested LockOnReset setter envelopes leaves stale reset lists accepted.",
        )
        after_reset = context + [{"input": {"function": "powerCycle"}, "output": {"return": True}}]
        yield Probe(
            f"setLockOnReset {label} nested envelope blocks later host write",
            after_reset + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "lockonreset-nested-envelope-doc",
            "Nested LockOnReset setters must feed reset-time lock enforcement.",
        )
        yield Probe(
            f"setLockOnReset {label} nested envelope rejects stale unlocked write",
            after_reset + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "lockonreset-nested-envelope-doc",
            "Ignoring nested LockOnReset setters leaves the configured range unlocked after PowerCycle.",
        )
    nested_lor_getter_context = activated_locking_context() + [
        {"input": {"function": "setLockOnReset", "kwargs": {"rangeId": 1, "LockOnReset": [0, 3], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for label, kwargs in (
        ("request values", {"request": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("policy query target", {"policy": {"query": {"target": {"rangeId": 1}}, "authAs": ("Admin1", "new")}}),
        ("config target", {"config": {"target": {"range": 1}, "authAs": ("Admin1", "new")}}),
        ("lockingRequest values", {"lockingRequest": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("rangeRequest values", {"rangeRequest": {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("lockingRangeRequest target", {"lockingRangeRequest": {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}}),
        ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}}),
    ):
        yield Probe(
            f"getLockOnReset {label} nested selector reports reset list",
            nested_lor_getter_context + [{"input": {"function": "getLockOnReset", "kwargs": kwargs}, "output": {"return": {"LockOnReset": [0, 3]}}}],
            "PASS",
            "lockonreset-nested-envelope-doc",
            "Nested LockOnReset getter selectors should select the tracked range row.",
        )
        yield Probe(
            f"getLockOnReset {label} nested selector rejects stale reset list",
            nested_lor_getter_context + [{"input": {"function": "getLockOnReset", "kwargs": kwargs}, "output": {"return": {"LockOnReset": [0]}}}],
            "FAIL",
            "lockonreset-nested-envelope-doc",
            "Losing nested LockOnReset getter selectors permits stale reset-list observations.",
        )
    def wrap_lor_deep_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        wrapped: dict[str, Any] = payload
        for key in reversed(chain):
            wrapped = {key: wrapped}
        return wrapped

    lor_deep_chains = (
        ("lockingRequest", "rangeRequest", "reset", "values"),
        ("request", "lockingRangeRequest", "reset", "types"),
        ("config", "target", "rangeValues", "reset"),
        ("policy", "request", "rangeRequest", "values"),
        ("values", "lockingRequest", "reset", "values"),
        ("operationRequest", "lockingRangeRequest", "target", "values"),
    )
    for index, set_chain in enumerate(lor_deep_chains):
        get_chain = lor_deep_chains[-(index + 1)]
        deep_lor_context = activated_locking_context() + [
            function_record(
                "setLockOnReset",
                [],
                wrap_lor_deep_payload({"rangeId": 1, "LockOnReset": [0, 3], "authAs": ("Admin1", "new")}, set_chain),
                True,
            )
        ]
        deep_get_payload = wrap_lor_deep_payload({"rangeId": 1, "authAs": ("Admin1", "new")}, get_chain)
        yield Probe(
            f"deep LockOnReset envelope {index} reports reset list",
            deep_lor_context + [function_record("getLockOnReset", [], deep_get_payload, {"LockOnReset": [0, 3]})],
            "PASS",
            "lockonreset-deep-envelope-doc",
            "Deep LockOnReset envelopes should unwrap reset/types/target containers before range state comparison.",
        )
        yield Probe(
            f"deep LockOnReset envelope {index} rejects stale reset list",
            deep_lor_context + [function_record("getLockOnReset", [], deep_get_payload, {"LockOnReset": [0]})],
            "FAIL",
            "lockonreset-deep-envelope-doc",
            "Treating deep reset/types/target wrappers as scalar values permits stale LockOnReset observations.",
        )
    for alias in ("setLOR", "setRangeLOR", "setResetTypes", "setRangeResetTypes", "setLockOnResetTypes", "setRangeLockOnResetTypes", "setLockingRangeResetTypes", "configureLockOnReset", "configureRangeLockOnReset"):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "ReadLockEnabled": 1,
                    "WriteLockEnabled": 1,
                    "ReadLocked": 0,
                    "WriteLocked": 0,
                },
                True,
            ),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "resetTypes": [0], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "powerCycle"}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} blocks later host write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} should set LockOnReset reset type 0 for the selected Locking range.",
        )
        yield Probe(
            f"{alias} rejects stale unlocked write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} must feed the reset state machine rather than leaving the range unlocked.",
        )
    for alias in ("enableLockOnReset", "enableRangeLockOnReset", "enableLOR", "enableRangeLOR"):
        context = activated_locking_context() + [
            function_record(
                "setRange",
                [1],
                {
                    "authAs": ("Admin1", "new"),
                    "RangeStart": 80,
                    "RangeLength": 8,
                    "ReadLockEnabled": 1,
                    "WriteLockEnabled": 1,
                    "ReadLocked": 0,
                    "WriteLocked": 0,
                },
                True,
            ),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "powerCycle"}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} enables PowerCycle LockOnReset",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} should default to PowerCycle reset type 0 when no explicit resetTypes list is supplied.",
        )
        yield Probe(
            f"{alias} rejects stale unlocked write",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} must not leave the range unlocked after a matching PowerCycle reset.",
        )
    for alias in ("disableLockOnReset", "disableRangeLockOnReset", "disableLOR", "disableRangeLOR"):
        context = lor_values_base + [
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "powerCycle"}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} clears PowerCycle LockOnReset",
            context + [host_write_status(SUCCESS, pattern="CC", lba="80 ~ 87")],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} should clear the reset-type list for the selected range.",
        )
        yield Probe(
            f"{alias} rejects phantom locked write",
            context + [host_write_status(NOT_AUTHORIZED, pattern="CC", lba="80 ~ 87")],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} must prevent a cleared LockOnReset list from applying reset side effects.",
        )
    clear_lor_context = lor_values_base + [
        {"input": {"function": "clearLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    yield Probe(
        "clearLockOnReset clears reset list",
        clear_lor_context
        + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": []}}}],
        "PASS",
        "reset-locking-wrapper",
        "clearLockOnReset should Set the LockOnReset column to an empty reset-type list.",
    )
    yield Probe(
        "clearLockOnReset rejects stale reset list",
        clear_lor_context
        + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": [0]}}}],
        "FAIL",
        "reset-locking-wrapper",
        "A stale LockOnReset list after clearLockOnReset means the wrapper mutation was ignored.",
    )
    lockonreset_getter_context = activated_locking_context() + [
        function_record(
            "setRange",
            [1],
            {
                "authAs": ("Admin1", "new"),
                "RangeStart": 80,
                "RangeLength": 8,
                "ReadLockEnabled": True,
                "WriteLockEnabled": True,
                "LockOnReset": [0],
            },
        )
    ]
    for alias in (
        "getLockOnReset",
        "getRangeLockOnReset",
        "getLockingRangeLockOnReset",
        "getLOR",
        "getRangeLOR",
        "getResetTypes",
        "getRangeResetTypes",
        "getLockOnResetTypes",
        "getRangeLockOnResetTypes",
        "getLockingRangeResetTypes",
        "readLockOnReset",
        "fetchLockOnReset",
        "queryLockOnReset",
        "loadLockOnReset",
        "readRangeLockOnReset",
        "fetchRangeLockOnReset",
        "queryRangeLockOnReset",
        "loadRangeLockOnReset",
        "readLOR",
        "fetchLOR",
        "queryLOR",
        "loadLOR",
        "readRangeLOR",
        "fetchRangeLOR",
        "queryRangeLOR",
        "loadRangeLOR",
    ):
        yield Probe(
            f"{alias} reports reset list",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": [0]}}}],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} is a bounded getter alias for Locking.LockOnReset.",
        )
        yield Probe(
            f"{alias} rejects stale reset list",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"LockOnReset": [3]}}}],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} must reflect the tracked reset type list.",
        )
        yield Probe(
            f"{alias} rejects Boolean value wrapper",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"value": True}}}],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} returns a reset-type list; a Boolean value wrapper must not coerce to PowerCycle.",
        )
        yield Probe(
            f"{alias} rejects Boolean-only reset list",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} returns the LockOnReset reset-type list, not a literal Boolean success flag.",
        )
        yield Probe(
            f"{alias} accepts direct reset list payload",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": [0]}}],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} may return the Locking.LockOnReset reset-type list directly.",
        )
        yield Probe(
            f"{alias} rejects stale direct reset list payload",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": [3]}}],
            "FAIL",
            "reset-locking-wrapper",
            f"{alias} direct list payload must still match tracked LockOnReset state.",
        )
    for return_key in ("lor", "resetTypes", "types", "resetEvents", "reset_on", "resetList"):
        yield Probe(
            f"getLockOnReset {return_key} return-field alias reports reset list",
            lockonreset_getter_context
            + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: [0]}}}],
            "PASS",
            "reset-locking-wrapper",
            f"`{return_key}` is a bounded return-field alias for Locking.LockOnReset.",
        )
        yield Probe(
            f"getLockOnReset {return_key} return-field alias rejects stale reset list",
            lockonreset_getter_context
            + [{"input": {"function": "getLockOnReset", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: [3]}}}],
            "FAIL",
            "reset-locking-wrapper",
            f"`{return_key}` must reflect the tracked reset type list.",
        )
    for alias in ("isLockOnResetEnabled", "isRangeLockOnResetEnabled", "isLockingRangeLockOnResetEnabled", "lockOnResetEnabled", "rangeLockOnResetEnabled", "hasLockOnReset"):
        yield Probe(
            f"{alias} reports configured state",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "PASS",
            "reset-locking-wrapper",
            f"{alias} is a boolean view of whether the reset type list is non-empty.",
        )
        yield Probe(
            f"{alias} rejects stale disabled state",
            lockonreset_getter_context
            + [{"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
            "FAIL",
            "reset-locking-wrapper",
            f"The boolean LockOnReset getter cannot return false when a reset type is configured.",
        )


def lifecycle_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [host_write("AA", lba="200 ~ 207")]
    payload = {"values": {"cred": "new", "KeepGlobalRangeKey": True}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        raw = operation_payload("revertLockingSP", payload, key=shape, output={"return": True})
        yield Probe(
            f"revertLockingSP {shape} values envelope preserves global range key",
            context + [raw, host_read("Pattern AA", lba="200 ~ 207")],
            "PASS",
            "lifecycle-wrapper",
            "KeepGlobalRangeKey may be nested under a values envelope and must preserve GlobalRange data.",
        )
    for alias_key in ("preserveGlobalRangeKey", "preserveGlobalRange", "keepGlobalKey"):
        yield Probe(
            f"revertLockingSP {alias_key} preserves global range key",
            context + [{"input": {"function": "revertLockingSP", "kwargs": {"cred": "new", alias_key: True}}, "output": {"return": True}}, host_read("Pattern AA", lba="200 ~ 207")],
            "PASS",
            "lifecycle-wrapper",
            f"{alias_key} is an SDK-style alias for the official KeepGlobalRangeKey RevertSP parameter.",
        )
        yield Probe(
            f"revertLockingSP {alias_key} rejects wiped global range data",
            context + [{"input": {"function": "revertLockingSP", "kwargs": {"cred": "new", alias_key: True}}, "output": {"return": True}}, host_read("Pattern 00", lba="200 ~ 207")],
            "FAIL",
            "lifecycle-wrapper",
            f"{alias_key}=True must not be ignored before checking preserved GlobalRange data.",
        )
    yield Probe(
        "targeted revertSP LockingSP preserves global range key",
        context + [{"input": {"function": "revertSP", "args": ["LockingSP", "new"], "kwargs": {"KeepGlobalRangeKey": True}}, "output": {"return": True}}, host_read("Pattern AA", lba="200 ~ 207")],
        "PASS",
        "lifecycle-wrapper",
        "Generic revertSP with an explicit LockingSP target should share revertLockingSP semantics.",
    )
    yield Probe(
        "targeted AdminSP revertSP resets LockingSP activation",
        activated_locking_context()
        + [
            {"input": {"function": "revertSP", "kwargs": {"target": "AdminSP", "psid": "psid"}}, "output": {"return": True}},
            start_session("0000020500000002", "0000000900010001", "new"),
        ],
        "FAIL",
        "lifecycle-wrapper",
        "Generic revertSP with an AdminSP target and PSID credential should share AdminSP RevertSP semantics.",
    )
    for label, payload in (
        ("policy", {"target": "LockingSP", "credential": "new", "KeepGlobalRangeKey": True}),
        ("config", {"sp": "LockingSP", "cred": "new", "keepGlobalRangeKey": True}),
        ("request", {"sp": {"name": "LockingSP"}, "credential": {"proof": "new"}, "options": {"KeepGlobalRangeKey": True}}),
        ("operation", {"target": "LockingSP", "command": {"credential": "new", "KeepGlobalRangeKey": True}}),
        ("operationRequest", {"target": {"name": "LockingSP"}, "command": {"credential": {"proof": "new"}, "KeepGlobalRangeKey": True}}),
    ):
        yield Probe(
            f"revertSP {label} envelope preserves GlobalRange",
            context + [{"input": {"function": "revertSP", "kwargs": {label: payload}}, "output": {"return": True}}, host_read("Pattern AA", lba="200 ~ 207")],
            "PASS",
            "revertsp-policy-envelope-doc",
            "RevertSP policy/config/request envelopes must preserve LockingSP target, credential, and KeepGlobalRangeKey.",
        )
    for label, payload in (
        ("policy", {"target": "AdminSP", "psid": "psid"}),
        ("config", {"sp": "AdminSP", "credential": "psid"}),
        ("request", {"target": {"name": "AdminSP"}, "credential": {"psid": "psid"}}),
        ("revertRequest", {"values": {"target": "AdminSP", "psid": "psid"}}),
        ("revertSpRequest", {"values": {"target": "AdminSP", "psid": "psid"}}),
        ("spRequest", {"values": {"target": "AdminSP", "psid": "psid"}}),
        ("lifecycleRequest", {"values": {"target": "AdminSP", "psid": "psid"}}),
        ("operation", {"target": "AdminSP", "command": {"psid": "psid"}}),
        ("operationRequest", {"target": {"name": "AdminSP"}, "command": {"credential": "psid"}}),
    ):
        yield Probe(
            f"AdminSP revertSP {label} envelope resets LockingSP activation",
            activated_locking_context()
            + [
                {"input": {"function": "revertSP", "kwargs": {label: payload}}, "output": {"return": True}},
                start_session("0000020500000002", "0000000900010001", "new"),
            ],
            "FAIL",
            "revertsp-policy-envelope-doc",
            "AdminSP RevertSP policy/config/request envelopes must preserve target and PSID credential rather than falling through as UNKNOWN.",
        )
    yield Probe(
        "activateLockingSP alias enables LockingSP session",
        owned_admin_context()
        + [
            {"input": {"function": "activateLockingSP", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": True}},
            start_session("0000020500000002", "0000000900010001", "new"),
        ],
        "PASS",
        "lifecycle-wrapper",
        "activateLockingSP should share Activate(LockingSP) lifecycle semantics.",
    )
    for proof, expected in (("new", "PASS"), ("wrong", "FAIL")):
        for function_name in ("activateLockingSP", "activateSP", "activate"):
            for label, payload in (
                ("policy", {"authAs": ("SID", proof)}),
                ("config", {"authority": "SID", "proof": proof}),
                ("request", {"credential": {"auth": "SID", "proof": proof}}),
                ("operation", {"credential": {"auth": "SID", "proof": proof}}),
                ("operation", {"command": {"auth": "SID", "proof": proof}}),
            ):
                yield Probe(
                    f"{function_name} {label} envelope {'enables' if expected == 'PASS' else 'does not enable'} LockingSP with {proof} proof",
                    owned_admin_context()
                    + [
                        {"input": {"function": function_name, "kwargs": {label: payload}}, "output": {"return": True}},
                        start_session("0000020500000002", "0000000900010001", "new"),
                    ],
                    expected,
                    "activate-policy-envelope-doc",
                    "Activate policy/config/request envelopes must preserve SID credentials before mutating LockingSP lifecycle state.",
                )
    for function_name, wrapper, payload_key in (
        ("activateLockingSP", "activateRequest", "authAs"),
        ("activateLockingSP", "spRequest", "authAs"),
        ("takeOwnership", "ownershipRequest", "credential"),
        ("takeOwnership", "credentialRequest", "credential"),
        ("takeOwnership", "operationRequest", "credential"),
    ):
        for proof, expected in (("new", "PASS"), ("wrong", "FAIL")):
            value = ("SID", proof) if payload_key == "authAs" else proof
            yield Probe(
                f"{function_name} {wrapper} {'enables' if expected == 'PASS' else 'does not enable'} LockingSP with {proof} proof",
                owned_admin_context()
                + [
                    {"input": {"function": function_name, "kwargs": {wrapper: {"values": {payload_key: value}}}}, "output": {"return": True}},
                    start_session("0000020500000002", "0000000900010001", "new"),
                ],
                expected,
                "lifecycle-domain-request-envelope-doc",
                "Lifecycle domain request envelopes must validate the SID credential before mutating LockingSP lifecycle state.",
            )
    yield Probe(
        "takeOwnership alias enables LockingSP session",
        owned_admin_context()
        + [
            {"input": {"function": "takeOwnership", "args": ["new"]}, "output": {"return": True}},
            start_session("0000020500000002", "0000000900010001", "new"),
        ],
        "PASS",
        "lifecycle-wrapper",
        "takeOwnership should lower to SID-authorized Activate(LockingSP) and copy SID's PIN to Admin1.",
    )
    for proof, expected in (("new", "PASS"), ("wrong", "FAIL")):
        for label, payload in (
            ("policy", {"pin": proof}),
            ("config", {"credential": proof}),
            ("request", {"credential": {"pin": proof}}),
            ("operation", {"credential": {"proof": proof}}),
            ("operation", {"command": {"credential": proof}}),
        ):
            yield Probe(
                f"takeOwnership {label} envelope {'enables' if expected == 'PASS' else 'does not enable'} LockingSP with {proof} proof",
                owned_admin_context()
                + [
                    {"input": {"function": "takeOwnership", "kwargs": {label: payload}}, "output": {"return": True}},
                    start_session("0000020500000002", "0000000900010001", "new"),
                ],
                expected,
                "takeownership-policy-envelope-doc",
                "takeOwnership policy/config/request envelopes must preserve SID credential before mutating LockingSP lifecycle state.",
            )
    yield Probe(
        "failed takeOwnership does not enable LockingSP session",
        owned_admin_context()
        + [
            {"input": {"function": "takeownership", "args": ["wrong"]}, "output": {"return": False}},
            start_session("0000020500000002", "0000000900010001", "new"),
        ],
        "FAIL",
        "lifecycle-wrapper",
        "A failed takeOwnership wrapper must not activate LockingSP.",
    )
    for alias in ("activateLocking", "enableLocking", "enableLockingSP", "setupLockingSP", "provisionLockingSP", "initializeLockingSP", "initLockingSP"):
        yield Probe(
            f"{alias} alias enables LockingSP session",
            owned_admin_context()
            + [
                {"input": {"function": alias, "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": True}},
                start_session("0000020500000002", "0000000900010001", "new"),
            ],
            "PASS",
            "lifecycle-wrapper",
            f"{alias} should share Activate(LockingSP) lifecycle semantics.",
        )
    yield Probe(
        "failed setupLockingSP does not enable LockingSP session",
        owned_admin_context()
        + [
            {"input": {"function": "setupLockingSP", "kwargs": {"authAs": ("SID", "wrong")}}, "output": {"return": False}},
            start_session("0000020500000002", "0000000900010001", "new"),
        ],
        "FAIL",
        "lifecycle-wrapper",
        "A failed setupLockingSP wrapper must not activate LockingSP.",
    )
    for alias in ("factoryResetDrive", "psidRevert"):
        yield Probe(
            f"{alias} alias resets LockingSP activation",
            activated_locking_context()
            + [
                {"input": {"function": alias, "args": ["psid"]}, "output": {"return": True}},
                start_session("0000020500000002", "0000000900010001", "new"),
            ],
            "FAIL",
            "lifecycle-wrapper",
            f"{alias} should share PSID-authorized AdminSP RevertSP semantics and deactivate LockingSP.",
        )
    yield Probe(
        "startLockingSession alias opens persistent LockingSP session",
        activated_locking_context()
        + [
            {"input": {"function": "startLockingSession", "kwargs": {"user": "Admin1", "password": "new", "write": True}}, "output": {"return": True}},
            set_values("0000080200030001", "Locking", {3: 80, 4: 8}, status=SUCCESS),
        ],
        "PASS",
        "lifecycle-wrapper",
        "startLockingSession should default SPID to LockingSP and recover user/password aliases.",
    )


def random_probes() -> Iterable[Probe]:
    payload = {"values": {"count": 16}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"random {shape} values envelope accepts requested length",
            [operation_payload("random", payload, key=shape, output={"return": bytes(range(16))})],
            "PASS",
            "random-wrapper",
            "Random values envelopes should use the nested Count parameter for output length validation.",
        )
        yield Probe(
            f"random {shape} values envelope rejects wrong length",
            [operation_payload("random", payload, key=shape, output={"return": bytes(range(8))})],
            "FAIL",
            "random-wrapper",
            "Ignoring Random values-envelope Count lets wrong-length payloads pass.",
        )
        yield Probe(
            f"random {shape} values envelope rejects unsupported nested arg",
            [operation_payload("random", {"values": {"foo": 16}}, key=shape, output={"return": bytes(range(16))})],
            "FAIL",
            "random-wrapper",
            "Random should allow values as a wrapper container but still reject unsupported nested parameters.",
        )
    for alias, payload in (("getRandom", {"count": 16}), ("randomBytes", {"length": 16})):
        yield Probe(
            f"{alias} top-level length accepts requested length",
            [operation_payload(alias, payload, key="kwargs", output={"return": bytes(range(16))})],
            "PASS",
            "random-wrapper",
            f"{alias} should share Random Count/length validation.",
        )
        yield Probe(
            f"{alias} top-level length rejects wrong length",
            [operation_payload(alias, payload, key="kwargs", output={"return": bytes(range(8))})],
            "FAIL",
            "random-wrapper",
            f"{alias} must not ignore the requested byte count.",
        )
    for alias in (
        "generateRandom",
        "getRandomBytes",
        "readRandomBytes",
        "fetchRandomBytes",
        "rng",
        "getRNG",
        "generateRandomBytes",
        "rngBytes",
        "readRandom",
        "fetchRandom",
        "randomBuffer",
        "entropy",
        "getEntropy",
        "readEntropy",
        "fetchEntropy",
        "generateEntropy",
        "entropyBytes",
    ):
        yield Probe(
            f"{alias} top-level length accepts requested length",
            [operation_payload(alias, {"count": 2}, key="kwargs", output={"return": bytes([1, 2])})],
            "PASS",
            "random-wrapper",
            f"{alias} should share Random Count validation.",
        )
        yield Probe(
            f"{alias} top-level length rejects wrong length",
            [operation_payload(alias, {"count": 2}, key="kwargs", output={"return": bytes([1])})],
            "FAIL",
            "random-wrapper",
            f"{alias} must not ignore the requested byte count.",
        )
        yield Probe(
            f"{alias} rejects boolean-only random result",
            [operation_payload(alias, {"count": 2}, key="kwargs", output={"return": True})],
            "FAIL",
            "random-wrapper",
            f"{alias} must return random bytes rather than Boolean-only success.",
        )
    random_bytes_repr_16 = "b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f'"
    yield Probe(
        "randomBytes Python bytes repr accepts requested length",
        [operation_payload("randomBytes", {"length": 16}, key="kwargs", output={"return": random_bytes_repr_16})],
        "PASS",
        "random-wrapper",
        "Python bytes repr strings should be measured as byte payloads.",
    )
    yield Probe(
        "randomBytes Python bytes repr rejects wrong length",
        [operation_payload("randomBytes", {"length": 2}, key="kwargs", output={"return": "b'\\x00\\x01\\x02'"})],
        "FAIL",
        "random-wrapper",
        "Python bytes repr strings must still enforce Random Count.",
    )
    yield Probe(
        "randomBytes rejects boolean-only random result",
        [operation_payload("randomBytes", {"length": 2}, key="kwargs", output={"return": True})],
        "FAIL",
        "random-wrapper",
        "Random wrappers must return random bytes rather than Boolean-only success.",
    )
    for scalar in (-1, 2**32):
        yield Probe(
            f"randomBytes rejects scalar non-byte result {scalar}",
            [operation_payload("randomBytes", {"length": 2}, key="kwargs", output={"return": scalar})],
            "FAIL",
            "random-wrapper",
            "Random without BufferOut returns a byte sequence of Count bytes, not a scalar integer payload.",
        )
    for wrapper_key, wrapper_payload in (
        ("policy", {"count": 8}),
        ("config", {"length": 8}),
        ("request", {"random": {"bytes": 8}}),
        ("operation", {"count": 8}),
        ("operation", {"command": {"count": 8}}),
        ("operationRequest", {"command": {"count": 8}}),
        ("command", {"count": 8}),
        ("action", {"count": 8}),
        ("randomRequest", {"values": {"count": 8}}),
        ("rngRequest", {"values": {"bytes": 8}}),
    ):
        family = "random-operation-envelope-doc" if wrapper_key in {"command", "action"} or "command" in wrapper_payload else "random-wrapper"
        yield Probe(
            f"getRandomBytes {wrapper_key} count envelope accepts requested output",
            [operation_payload("getRandomBytes", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": "AABBCCDDEEFF0011"})],
            "PASS",
            family,
            f"getRandomBytes should recover Count from structured {wrapper_key} envelopes.",
        )
        yield Probe(
            f"getRandomBytes {wrapper_key} count envelope rejects wrong output length",
            [operation_payload("getRandomBytes", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": "AABB"})],
            "FAIL",
            family,
            f"getRandomBytes must enforce Count recovered from {wrapper_key}.",
        )
    random_envelope_buffer_out = {"CellBlock": {"Table": "DataStore", "startRow": 4, "endRow": 11}}
    random_buffer_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "old")]
    for wrapper_key, wrapper_payload in (
        ("policy", {"count": 8, "BufferOut": random_envelope_buffer_out}),
        ("config", {"length": 8, "output": random_envelope_buffer_out}),
        ("request", {"random": {"count": 8, "output": random_envelope_buffer_out}}),
        ("operation", {"count": 8, "destination": random_envelope_buffer_out}),
        ("randomRequest", {"random": {"count": 8, "output": random_envelope_buffer_out}}),
        ("operationRequest", {"random": {"count": 8, "destination": random_envelope_buffer_out}}),
    ):
        yield Probe(
            f"getRandomBytes {wrapper_key} BufferOut envelope returns empty result",
            random_buffer_context + [operation_payload("getRandomBytes", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": []})],
            "PASS",
            "random-wrapper",
            f"Random with BufferOut in {wrapper_key} stores generated bytes and returns an empty result.",
        )
        yield Probe(
            f"getRandomBytes {wrapper_key} BufferOut envelope rejects returned bytes",
            random_buffer_context + [operation_payload("getRandomBytes", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": "AABBCCDDEEFF0011"})],
            "FAIL",
            "random-wrapper",
            f"Random must not return generated bytes when BufferOut is supplied through {wrapper_key}.",
        )
    def wrap_random_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        current: dict[str, Any] = payload
        for key in reversed(chain):
            current = {key: current}
        return current

    for chain in (
        ("policy", "request", "random", "values"),
        ("config", "operation", "random", "values"),
        ("request", "randomRequest", "values"),
        ("operationRequest", "random", "request", "values"),
        ("randomRequest", "operation", "rng", "values"),
    ):
        chain_name = "/".join(chain)
        kwargs = wrap_random_payload({"count": 8}, chain)
        yield Probe(
            f"getRandomBytes deep {chain_name} count envelope accepts requested output",
            [operation_payload("getRandomBytes", kwargs, key="kwargs", output={"return": "AABBCCDDEEFF0011"})],
            "PASS",
            "random-deep-envelope-doc",
            "Deep getRandomBytes envelopes should recover Count before output length validation.",
        )
        yield Probe(
            f"getRandomBytes deep {chain_name} count envelope rejects wrong output length",
            [operation_payload("getRandomBytes", kwargs, key="kwargs", output={"return": "AABB"})],
            "FAIL",
            "random-deep-envelope-doc",
            "Deep getRandomBytes envelopes must not fall back to the default Count.",
        )
        buffer_kwargs = wrap_random_payload({"count": 8, "output": random_envelope_buffer_out}, chain)
        yield Probe(
            f"getRandomBytes deep {chain_name} BufferOut envelope returns empty result",
            random_buffer_context + [operation_payload("getRandomBytes", buffer_kwargs, key="kwargs", output={"return": []})],
            "PASS",
            "random-deep-envelope-doc",
            "Deep Random BufferOut envelopes should return an empty result.",
        )
        yield Probe(
            f"getRandomBytes deep {chain_name} BufferOut envelope rejects returned bytes",
            random_buffer_context + [operation_payload("getRandomBytes", buffer_kwargs, key="kwargs", output={"return": "AABBCCDDEEFF0011"})],
            "FAIL",
            "random-deep-envelope-doc",
            "Deep Random BufferOut envelopes must not also return generated bytes.",
        )
    yield Probe(
        "randomBytes BufferOut accepts empty result",
        random_buffer_context + [
            operation_payload(
                "randomBytes",
                {"length": 16, "BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 15}}},
                key="kwargs",
                output={"return": []},
            )
        ],
        "PASS",
        "random-wrapper",
        "Random with BufferOut writes into the referenced buffer and returns an empty result.",
    )
    yield Probe(
        "randomBytes BufferOut rejects returned byte payload",
        random_buffer_context + [
            operation_payload(
                "randomBytes",
                {"length": 16, "BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 15}}},
                key="kwargs",
                output={"return": bytes(range(16))},
            )
        ],
        "FAIL",
        "random-wrapper",
        "A Random wrapper with BufferOut must not also return the generated bytes.",
    )
    yield Probe(
        "randomBytes BufferOut rejects scalar non-empty result",
        random_buffer_context + [
            operation_payload(
                "randomBytes",
                {"length": 16, "BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 15}}},
                key="kwargs",
                output={"return": 1},
            )
        ],
        "FAIL",
        "random-wrapper",
        "Random with BufferOut returns an empty result, not a scalar payload.",
    )
    yield Probe(
        "getRandomBytes output alias accepts empty result",
        random_buffer_context + [
            operation_payload(
                "getRandomBytes",
                {"count": 8, "output": {"CellBlock": {"Table": "DataStore", "startRow": 4, "endRow": 11}}},
                key="kwargs",
                output={"return": []},
            )
        ],
        "PASS",
        "random-wrapper",
        "SDK-style output aliases should lower to Random BufferOut.",
    )


def tpersign_probes() -> Iterable[Probe]:
    payload = {"values": {"data": "AABB", "authAs": "Anybody"}}
    overlong = {"values": {"data": "A" * 300, "authAs": "Anybody"}}
    for shape in ("kwargs", "params", "request", "call"):
        yield Probe(
            f"TPerSign {shape} values envelope accepts host data",
            [operation_payload("tperSign", payload, key=shape, output={"return": b"signed"})],
            "PASS",
            "sign-wrapper",
            "TPerSign values envelopes should recover nested host data payload.",
        )
        yield Probe(
            f"TPerSign {shape} values envelope rejects overlong host data",
            [operation_payload("tperSign", overlong, key=shape, output={"return": b"signed"})],
            "FAIL",
            "sign-wrapper",
            "The TCGstorageAPI 256-byte TPerSign input limit still applies inside values envelopes.",
        )
    yield Probe(
        "TPerSign args1 values envelope rejects missing host data",
        [operation_payload("tperSign", {"values": {"authAs": "Anybody"}}, key="args1", output={"return": b"signed"})],
        "FAIL",
        "sign-wrapper",
        "The wrapper container itself must not count as TPerSign host data.",
    )
    yield Probe(
        "TPerSign rejects boolean-only signature result",
        [operation_payload("tperSign", {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
        "FAIL",
        "sign-wrapper",
        "TPerSign must return signature data rather than Boolean-only success.",
    )
    yield Probe(
        "TPerSign rejects list-wrapped Boolean signature result",
        [operation_payload("tperSign", {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": [True]})],
        "FAIL",
        "sign-wrapper",
        "TPerSign wrapper return lists must be validated as signature payloads, not legacy status tuples.",
    )
    yield Probe(
        "TPerSign rejects empty signature payload",
        [operation_payload("tperSign", {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {}})],
        "FAIL",
        "sign-wrapper",
        "TPerSign wrapper success must expose non-empty signature bytes, not an empty object payload.",
    )
    for alias in ("signData", "tperSignData"):
        yield Probe(
            f"{alias} payload alias accepts host data",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
            "PASS",
            "sign-wrapper",
            f"{alias} should share TPerSign input validation.",
        )
        yield Probe(
            f"{alias} rejects boolean-only signature result",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must return signature data rather than Boolean-only success.",
        )
        yield Probe(
            f"{alias} rejects list-wrapped Boolean signature result",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": [True]})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must return signature bytes rather than a Boolean flag inside a payload list.",
        )
        if alias == "signData":
            yield Probe(
                "signData rejects empty signature payload",
                [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {}})],
                "FAIL",
                "sign-wrapper",
                "signData wrapper success must expose non-empty signature bytes.",
            )
    for alias in ("sign", "signBytes", "signPayload", "createSignature", "generateSignature"):
        yield Probe(
            f"{alias} payload alias accepts host data",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
            "PASS",
            "sign-wrapper",
            f"{alias} should share TPerSign input validation.",
        )
        yield Probe(
            f"{alias} payload alias rejects missing host data",
            [operation_payload(alias, {"authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must still provide host data to TPerSign.",
        )
        yield Probe(
            f"{alias} payload alias rejects overlong host data",
            [operation_payload(alias, {"payload": "AA" * 300, "authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must preserve the TCGstorageAPI 256-byte TPerSign input limit.",
        )
        yield Probe(
            f"{alias} rejects boolean-only signature result",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must return signature data rather than Boolean-only success.",
        )
        yield Probe(
            f"{alias} rejects list-wrapped Boolean signature result",
            [operation_payload(alias, {"payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": [True]})],
            "FAIL",
            "sign-wrapper",
            f"{alias} must return signature bytes rather than a Boolean flag inside a payload list.",
        )
    yield Probe(
        "sign target BufferOut accepts empty result",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "BufferOut": {"Bytes": "0000"}, "authAs": "Anybody"}, key="kwargs", output={"return": []})],
        "PASS",
        "sign-wrapper",
        "When a sign wrapper names a crypto target, it lowers to generic Sign and BufferOut makes the Result empty.",
    )
    yield Probe(
        "sign target BufferOut rejects returned signed bytes",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "BufferOut": {"Bytes": "0000"}, "authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
        "FAIL",
        "sign-wrapper",
        "Generic Sign with BufferOut cannot also return signed bytes.",
    )
    yield Probe(
        "sign target BufferOut rejects scalar non-empty result",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "BufferOut": {"Bytes": "0000"}, "authAs": "Anybody"}, key="kwargs", output={"return": 1})],
        "FAIL",
        "sign-wrapper",
        "Generic Sign with BufferOut stores output bytes and returns an empty result, not a scalar payload.",
    )
    yield Probe(
        "signBytes output target accepts empty result",
        [operation_payload("signBytes", {"object": "C_RSA_2048", "payload": "AABB", "output": {"Bytes": "0000"}, "authAs": "Anybody"}, key="kwargs", output={"return": []})],
        "PASS",
        "sign-wrapper",
        "SDK-style output aliases should lower to generic Sign BufferOut when a target object is explicit.",
    )
    yield Probe(
        "sign target without BufferOut may return signed bytes",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"signed"})],
        "PASS",
        "sign-wrapper",
        "Generic Sign without BufferOut returns signed bytes in-band.",
    )
    yield Probe(
        "sign target without BufferOut rejects boolean-only signature result",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
        "FAIL",
        "sign-wrapper",
        "Generic Sign without BufferOut must return signed bytes rather than Boolean-only success.",
    )
    yield Probe(
        "sign target without BufferOut rejects scalar integer signature result",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": 1})],
        "FAIL",
        "sign-wrapper",
        "Generic Sign without BufferOut returns signed bytes, not a scalar integer payload.",
    )
    yield Probe(
        "sign target without BufferOut rejects empty signature result",
        [operation_payload("sign", {"target": "H_SHA_256", "payload": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": []})],
        "FAIL",
        "sign-wrapper",
        "Generic Sign without BufferOut returns signature bytes in-band rather than an empty BufferOut-style result.",
    )
    for wrapper_key, wrapper_payload in (
        ("operation", {"command": {"payload": "AABB", "authAs": "Anybody"}}),
        ("operationRequest", {"command": {"payload": "AABB", "authAs": "Anybody"}}),
        ("command", {"payload": "AABB", "authAs": "Anybody"}),
        ("action", {"payload": "AABB", "authAs": "Anybody"}),
    ):
        yield Probe(
            f"sign {wrapper_key} envelope accepts signature bytes",
            [operation_payload("sign", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": "signature"})],
            "PASS",
            "sign-operation-envelope-doc",
            "High-level Sign wrappers must preserve payload bytes from operation-style command envelopes.",
        )
        yield Probe(
            f"sign {wrapper_key} envelope rejects boolean signature",
            [operation_payload("sign", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": True})],
            "FAIL",
            "sign-operation-envelope-doc",
            "Sign without BufferOut returns signature bytes, not a Boolean success marker.",
        )


def firmware_attestation_probes() -> Iterable[Probe]:
    payload = {"values": {"nonce": "AABB", "authAs": "Anybody"}}
    for shape in ("kwargs", "params", "request", "call"):
        yield Probe(
            f"FirmwareAttestation {shape} values envelope accepts assessor nonce",
            [operation_payload("firmwareAttestation", payload, key=shape, output={"return": b"attestation"})],
            "PASS",
            "firmware-attestation-wrapper",
            "FirmwareAttestation values envelopes should recover the nested assessor nonce.",
        )
    yield Probe(
        "FirmwareAttestation args1 values envelope rejects missing assessor nonce",
        [operation_payload("firmwareAttestation", {"values": {"authAs": "Anybody"}}, key="args1", output={"return": b"attestation"})],
        "FAIL",
        "firmware-attestation-wrapper",
        "The wrapper container itself must not count as a FirmwareAttestation assessor nonce.",
    )
    yield Probe(
        "FirmwareAttestation nonce alias rejects boolean-only attestation result",
        [operation_payload("firmwareAttestation", {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
        "FAIL",
        "firmware-attestation-wrapper",
        "FirmwareAttestation must return attestation data rather than Boolean-only success.",
    )
    yield Probe(
        "FirmwareAttestation nonce alias rejects nested Boolean attestation result",
        [operation_payload("firmwareAttestation", {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {"Data": True}})],
        "FAIL",
        "firmware-attestation-wrapper",
        "FirmwareAttestation must return attestation bytes rather than a Boolean flag under a byte-data key.",
    )
    yield Probe(
        "FirmwareAttestation nonce alias rejects scalar integer attestation result",
        [operation_payload("firmwareAttestation", {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": 1})],
        "FAIL",
        "firmware-attestation-wrapper",
        "FirmwareAttestation must return attestation bytes rather than a scalar integer payload.",
    )
    yield Probe(
        "FirmwareAttestation nonce alias rejects empty attestation payload",
        [operation_payload("firmwareAttestation", {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {}})],
        "FAIL",
        "firmware-attestation-wrapper",
        "FirmwareAttestation wrapper success must expose non-empty attestation bytes, not an empty object payload.",
    )
    for alias in ("firmwareAttest", "attestFirmware"):
        yield Probe(
            f"{alias} nonce alias accepts assessor nonce",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"attestation"})],
            "PASS",
            "firmware-attestation-wrapper",
            f"{alias} should share FirmwareAttestation nonce validation.",
        )
        yield Probe(
            f"{alias} nonce alias rejects boolean-only attestation result",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
            "FAIL",
            "firmware-attestation-wrapper",
            f"{alias} must return attestation data rather than Boolean-only success.",
        )
        if alias == "getFirmwareQuote":
            yield Probe(
                "getFirmwareQuote nonce alias rejects empty attestation payload",
                [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {}})],
                "FAIL",
                "firmware-attestation-wrapper",
                "Firmware quote wrapper success must expose non-empty attestation bytes.",
            )
        yield Probe(
            f"{alias} nonce alias rejects nested Boolean attestation result",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {"Data": True}})],
            "FAIL",
            "firmware-attestation-wrapper",
            f"{alias} must return attestation bytes rather than a Boolean flag under a byte-data key.",
        )
    for alias in ("getFirmwareAttestation", "readFirmwareAttestation", "fetchFirmwareAttestation", "firmwareQuote", "getFirmwareQuote", "readFirmwareQuote", "fetchFirmwareQuote", "quoteFirmware", "quoteTPer", "attestation", "getAttestation", "readAttestation", "fetchAttestation", "getTPerAttestation", "readTPerAttestation", "fetchTPerAttestation"):
        yield Probe(
            f"{alias} nonce alias accepts assessor nonce",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"attestation"})],
            "PASS",
            "firmware-attestation-wrapper",
            f"{alias} should share FirmwareAttestation nonce validation.",
        )
        yield Probe(
            f"{alias} nonce alias rejects boolean-only attestation result",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": True})],
            "FAIL",
            "firmware-attestation-wrapper",
            f"{alias} must return attestation data rather than Boolean-only success.",
        )
        yield Probe(
            f"{alias} nonce alias rejects nested Boolean attestation result",
            [operation_payload(alias, {"nonce": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": {"Data": True}})],
            "FAIL",
            "firmware-attestation-wrapper",
            f"{alias} must return attestation bytes rather than a Boolean flag under a byte-data key.",
        )
        yield Probe(
            f"{alias} nonce alias rejects missing assessor nonce",
            [operation_payload(alias, {"authAs": "Anybody"}, key="kwargs", output={"return": b"attestation"})],
            "FAIL",
            "firmware-attestation-wrapper",
            f"{alias} must still provide an assessor nonce.",
        )
    for alias in ("firmwareAttestation", "firmwareAttest", "getFirmwareQuote", "quoteFirmware"):
        yield Probe(
            f"{alias} challenge alias accepts assessor nonce",
            [operation_payload(alias, {"challenge": "AABB", "authAs": "Anybody"}, key="kwargs", output={"return": b"attestation"})],
            "PASS",
            "firmware-attestation-wrapper",
            "Challenge is a bounded SDK-style alias for the FirmwareAttestation assessor nonce.",
        )
        yield Probe(
            f"{alias} challenge alias rejects missing nonce",
            [operation_payload(alias, {"authAs": "Anybody"}, key="kwargs", output={"return": b"attestation"})],
            "FAIL",
            "firmware-attestation-wrapper",
            "The challenge alias must not make a missing assessor nonce look present.",
        )
    for wrapper_key, wrapper_payload in (
        ("policy", {"nonce": "AABB"}),
        ("config", {"challenge": "AABB"}),
        ("request", {"attestation": {"nonce": "AABB"}}),
        ("operation", {"input": {"nonce": "AABB"}}),
        ("operation", {"command": {"nonce": "AABB"}}),
        ("operationRequest", {"command": {"nonce": "AABB"}}),
        ("command", {"nonce": "AABB"}),
        ("action", {"nonce": "AABB"}),
        ("attestationRequest", {"values": {"nonce": "AABB"}}),
        ("firmwareRequest", {"quote": {"challenge": "AABB"}}),
        ("quoteRequest", {"input": {"nonce": "AABB"}}),
    ):
        family = "firmware-attestation-operation-envelope-doc" if wrapper_key in {"command", "action"} or "command" in wrapper_payload else "firmware-attestation-wrapper"
        yield Probe(
            f"firmwareAttestation {wrapper_key} envelope accepts assessor nonce",
            [operation_payload("firmwareAttestation", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": b"attestation"})],
            "PASS",
            family,
            f"FirmwareAttestation should recover assessor nonce from structured {wrapper_key} envelopes.",
        )
        yield Probe(
            f"firmwareAttestation {wrapper_key} envelope rejects boolean attestation result",
            [operation_payload("firmwareAttestation", {wrapper_key: wrapper_payload}, key="kwargs", output={"return": True})],
            "FAIL",
            family,
            f"FirmwareAttestation with nonce from {wrapper_key} still returns attestation bytes, not Boolean success.",
        )


def certificate_byte_table_probes() -> Iterable[Probe]:
    for alias in (
        "getAttestationCert",
        "getAttestationCertificate",
        "readTPerAttestationCert",
        "readAttestationCert",
        "fetchAttestationCert",
        "getTPerCert",
    ):
        yield Probe(
            f"{alias} reads TPer attestation certificate byte table",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": "AABB"}}],
            "PASS",
            "certificate-wrapper",
            f"{alias} should share the AdminSP Anybody certificate byte-table Get semantics.",
        )
        yield Probe(
            f"{alias} rejects boolean-only certificate result",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": True}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than Boolean-only success.",
        )
        yield Probe(
            f"{alias} rejects nested Boolean certificate payload",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": {"Data": True}}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than a Boolean flag under a byte-data key.",
        )
        yield Probe(
            f"{alias} rejects scalar integer certificate payload",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": 1}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than a scalar integer payload.",
        )
        if alias == "getAttestationCert":
            yield Probe(
                "getAttestationCert rejects empty certificate payload",
                [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": {}}}],
                "FAIL",
                "certificate-wrapper",
                "Certificate wrapper success must expose non-empty certificate bytes, not an empty object payload.",
            )
    for alias in (
        "getSignCert",
        "getSigningCert",
        "getSignCertificate",
        "getSigningCertificate",
        "getTPerSigningCert",
        "getTPerCertSign",
        "readTPerSignCert",
        "readSignCert",
        "readSignCertificate",
        "readSigningCertificate",
        "fetchSignCert",
        "fetchSignCertificate",
        "fetchSigningCertificate",
    ):
        yield Probe(
            f"{alias} reads TPer signing certificate byte table",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": "AABB"}}],
            "PASS",
            "certificate-wrapper",
            f"{alias} should share the AdminSP certificate byte-table Get semantics.",
        )
        yield Probe(
            f"{alias} rejects boolean-only certificate result",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": True}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than Boolean-only success.",
        )
        yield Probe(
            f"{alias} rejects nested Boolean certificate payload",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": {"Data": True}}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than a Boolean flag under a byte-data key.",
        )
        yield Probe(
            f"{alias} rejects scalar integer certificate payload",
            [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": 1}}],
            "FAIL",
            "certificate-wrapper",
            f"{alias} must return certificate bytes rather than a scalar integer payload.",
        )
        if alias == "getSignCert":
            yield Probe(
                "getSignCert rejects empty certificate payload",
                [{"input": {"function": alias, "kwargs": {}}, "output": {"status": "SUCCESS", "return": {}}}],
                "FAIL",
                "certificate-wrapper",
                "Signing certificate wrapper success must expose non-empty certificate bytes, not an empty object payload.",
            )


def psk_probes() -> Iterable[Probe]:
    context = owned_admin_context() + [start_session("0000020500000001", "0000000900000006", "new")]
    payload = {"values": {"psk": 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "new")}}
    snake_payload = {"values": {"psk": 1, "Enabled": True, "PSK": b"secret", "cipher_suite": "0x1301", "authAs": ("SID", "new")}}
    wrong_payload = {"values": {"psk": 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "wrong")}}
    top_level_payload = {"psk_id": 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "new")}
    secret_payload = {"id": 1, "Enabled": True, "secret": b"secret", "cipherSuite": "0x1301", "authAs": ("SID", "new")}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"setPskEntry {shape} values envelope accepts SID",
            context + [operation_payload("setPskEntry", payload, key=shape, output={"return": True})],
            "PASS",
            "psk-wrapper",
            "setPskEntry values envelopes should recover selector, PSK payload, CipherSuite, and authAs.",
        )
        yield Probe(
            f"setPskEntry {shape} snake-case cipher_suite accepts SID",
            context + [operation_payload("setPskEntry", snake_payload, key=shape, output={"return": True})],
            "PASS",
            "psk-wrapper",
            "cipher_suite is an SDK-style alias for CipherSuite and must satisfy the required PSK field.",
        )
        yield Probe(
            f"setPskEntry {shape} values envelope rejects wrong SID",
            context + [operation_payload("setPskEntry", wrong_payload, key=shape, output={"return": True})],
            "FAIL",
            "psk-wrapper",
            "setPskEntry values envelopes must not bypass wrapper authAs credential checks.",
        )
    yield Probe(
        "setPskEntry top-level psk_id preserves PSK payload",
        context + [operation_payload("setPskEntry", top_level_payload, key="kwargs", output={"return": True})],
        "PASS",
        "psk-wrapper",
        "Top-level psk_id should select the row while exact uppercase PSK remains the payload column.",
    )
    yield Probe(
        "setPskEntry top-level secret maps to PSK payload",
        context + [operation_payload("setPskEntry", secret_payload, key="kwargs", output={"return": True})],
        "PASS",
        "psk-wrapper",
        "Some SDKs name the TLS PSK byte payload secret while id selects the row.",
    )
    psk_state_context = context + [operation_payload("setPskEntry", top_level_payload, key="kwargs", output={"return": True})]
    yield Probe(
        "setPskEntry state visible in getPskEntry",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
        "PASS",
        "psk-wrapper",
        "Successful setPskEntry should make known PSK metadata visible to a later getPskEntry.",
    )
    yield Probe(
        "setPskEntry state rejects stale getPskEntry",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
        "FAIL",
        "psk-wrapper",
        "Tracked PSK metadata must reject stale Enabled values.",
    )
    for label, kwargs in (
        ("setPskEntry policy", {"policy": {"psk": 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "new")}}),
        ("setPskEntry config", {"config": {"psk_id": 1, "enabled": True, "secret": b"secret", "cipher_suite": "0x1301", "authAs": ("SID", "new")}}),
        ("setPskEntry request", {"request": {"target": {"psk": 1}, "state": {"Enabled": True}, "payload": {"PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry request target command", {"request": {"target": {"psk": 1}, "command": {"Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry operation target psk", {"operation": {"target": {"psk": 1}, "psk": {"Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry operation target preSharedKey", {"operation": {"target": {"psk": 1}, "preSharedKey": {"Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry config target action", {"config": {"target": {"psk": 1}, "action": {"Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry pskRequest", {"pskRequest": {"values": {"psk": 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "new")}}}),
        ("setPskEntry tlsPskRequest", {"tlsPskRequest": {"target": {"psk": 1}, "state": {"Enabled": True}, "payload": {"PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
        ("setPskEntry preSharedKeyRequest", {"preSharedKeyRequest": {"target": {"psk": 1}, "state": {"Enabled": True}, "payload": {"PSK": b"secret", "CipherSuite": "0x1301"}, "authAs": ("SID", "new")}}),
    ):
        set_context = context + [{"input": {"function": "setPskEntry", "kwargs": kwargs}, "output": {"return": True}}]
        yield Probe(
            f"{label} envelope updates metadata",
            set_context + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
            "PASS",
            "psk-wrapper",
            "setPskEntry policy/config/request envelopes must preserve selector, PSK payload, CipherSuite, and Enabled metadata.",
        )
        yield Probe(
            f"{label} envelope rejects stale metadata",
            set_context + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
            "FAIL",
            "psk-wrapper",
            "A stale getPskEntry after a policy/config/request setter means the TLS_PSK_Key row mutation was ignored.",
        )
    for label, kwargs in (
        ("getPskEntry policy", {"policy": {"psk": 1, "authAs": ("SID", "new")}}),
        ("getPskEntry config", {"config": {"psk_id": 1, "authAs": ("SID", "new")}}),
        ("getPskEntry request", {"request": {"target": {"psk": 1}, "authAs": ("SID", "new")}}),
        ("getPskEntry operation", {"operation": {"target": {"psk": 1}, "command": {"authAs": ("SID", "new")}}}),
        ("getPskEntry operationRequest", {"operationRequest": {"target": {"psk": 1}, "command": {"authAs": ("SID", "new")}}}),
        ("getPskEntry command", {"command": {"psk": 1, "authAs": ("SID", "new")}}),
        ("getPskEntry action", {"action": {"psk": 1, "authAs": ("SID", "new")}}),
        ("getPskEntry pskRequest", {"pskRequest": {"target": {"psk": 1}, "authAs": ("SID", "new")}}),
        ("getPskEntry tlsPskRequest", {"tlsPskRequest": {"target": {"psk": 1}, "authAs": ("SID", "new")}}),
        ("getPskEntry preSharedKeyRequest", {"preSharedKeyRequest": {"target": {"psk": 1}, "authAs": ("SID", "new")}}),
    ):
        tag = "psk-getter-operation-envelope-doc" if any(token in label for token in ("operation", "command", "action")) else "psk-wrapper"
        yield Probe(
            f"{label} envelope reports current metadata",
            psk_state_context + [{"input": {"function": "getPskEntry", "kwargs": kwargs}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
            "PASS",
            tag,
            "getPskEntry policy/config/request envelopes must recover the selected TLS_PSK_Key row.",
        )
        yield Probe(
            f"{label} envelope rejects stale metadata",
            psk_state_context + [{"input": {"function": "getPskEntry", "kwargs": kwargs}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
            "FAIL",
            tag,
            "A getter envelope that ignores the PSK selector leaves stale metadata accepted.",
        )
    yield Probe(
        "getPskEntry rejects Boolean-only row payload",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": True}}],
        "FAIL",
        "psk-wrapper",
        "TLS_PSK_Key.Get returns PSK metadata cells, not a literal Boolean success flag.",
    )
    yield Probe(
        "getPskEntry rejects list-wrapped Boolean row payload",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": [True]}}],
        "FAIL",
        "psk-wrapper",
        "TLS_PSK_Key.Get returns named PSK metadata cells; list-wrapped Booleans must not collapse to success.",
    )
    yield Probe(
        "getPskEntry rejects empty row payload",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {}}}],
        "FAIL",
        "psk-wrapper",
        "TLS_PSK_Key.Get wrapper success must include at least one PSK metadata cell.",
    )
    yield Probe(
        "getPskEntry rejects status-only row payload",
        psk_state_context
        + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": "SUCCESS"}}],
        "FAIL",
        "psk-wrapper",
        "TLS_PSK_Key.Get wrapper success cannot be represented only by a status token.",
    )
    for setter in (
        "setPSK",
        "configurePSK",
        "configurePskEntry",
        "putPSK",
        "putPskEntry",
        "storePSK",
        "storePskEntry",
        "enablePSK",
        "addPSK",
        "addPskEntry",
        "writePSK",
        "writePskEntry",
        "updatePSK",
        "updatePskEntry",
        "setTLSPSK",
        "updateTLSPSK",
        "putTLSPSK",
        "storeTLSPSK",
        "saveTLSPSK",
        "importTLSPSK",
        "setPreSharedKey",
        "setPreSharedKeyEntry",
        "writePreSharedKey",
        "updatePreSharedKey",
        "putPreSharedKey",
        "storePreSharedKey",
        "savePreSharedKey",
        "importPreSharedKey",
        "restorePreSharedKey",
        "savePSK",
        "savePskEntry",
        "importPSK",
        "importPskEntry",
        "restorePSK",
        "restorePskEntry",
    ):
        setter_context = context + [
            operation_payload(setter, top_level_payload, key="kwargs", output={"return": True}),
        ]
        yield Probe(
            f"{setter} alias updates PSK metadata",
            setter_context
            + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
            "PASS",
            "psk-wrapper",
            f"{setter} should share setPskEntry state mutation.",
        )
        yield Probe(
            f"{setter} alias rejects stale PSK metadata",
            setter_context
            + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
            "FAIL",
            "psk-wrapper",
            f"{setter} must not leave stale PSK metadata accepted.",
        )
    for getter in (
        "getPSK",
        "readPSK",
        "fetchPSK",
        "queryPSK",
        "pskEntry",
        "readPskEntry",
        "fetchPskEntry",
        "queryPskEntry",
        "getTLSPSK",
        "readTLSPSK",
        "fetchTLSPSK",
        "queryTLSPSK",
        "getPreSharedKey",
        "readPreSharedKey",
        "fetchPreSharedKey",
        "queryPreSharedKey",
        "getPreSharedKeyEntry",
        "readPreSharedKeyEntry",
        "fetchPreSharedKeyEntry",
        "queryPreSharedKeyEntry",
    ):
        yield Probe(
            f"{getter} alias reads PSK metadata",
            psk_state_context
            + [{"input": {"function": getter, "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
            "PASS",
            "psk-wrapper",
            f"{getter} should share getPskEntry state comparison.",
        )
        yield Probe(
            f"{getter} alias rejects stale PSK metadata",
            psk_state_context
            + [{"input": {"function": getter, "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
            "FAIL",
            "psk-wrapper",
            f"{getter} must compare against tracked PSK metadata.",
        )
    for return_key, good, stale in (
        ("isEnabled", True, False),
        ("active", True, False),
        ("cipher_suite", "0x1301", "0x1302"),
        ("tlsCipherSuite", "0x1301", "0x1302"),
        ("suite", "0x1301", "0x1302"),
        ("secret", b"secret", b"wrong"),
        ("pskSecret", b"secret", b"wrong"),
        ("pskValue", b"secret", b"wrong"),
        ("preSharedKey", b"secret", b"wrong"),
        ("keyMaterial", b"secret", b"wrong"),
    ):
        yield Probe(
            f"getPskEntry {return_key} return-field alias reads PSK metadata",
            psk_state_context + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {return_key: good}}}],
            "PASS",
            "psk-wrapper",
            f"{return_key} is a bounded return field for TLS_PSK_Key metadata.",
        )
        yield Probe(
            f"getPskEntry {return_key} return-field alias rejects stale PSK metadata",
            psk_state_context + [{"input": {"function": "getPskEntry", "kwargs": {"psk_id": 1, "authAs": ("SID", "new")}}, "output": {"return": {return_key: stale}}}],
            "FAIL",
            "psk-wrapper",
            f"{return_key} must compare against tracked TLS_PSK_Key metadata.",
        )
    for selector_key in ("psk_id", "pskId", "id"):
        yield Probe(
            f"getPskEntry top-level {selector_key} accepts SID",
            context
            + [
                {
                    "input": {"function": "getPskEntry", "kwargs": {selector_key: 1, "authAs": ("SID", "new")}},
                    "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}},
                }
            ],
            "PASS",
            "psk-wrapper",
            f"Top-level {selector_key} should select a TLS_PSK_Key row for getPskEntry.",
        )
    for selector_key in ("uid", "slot", "keyId", "key_id"):
        selector_context = context + [
            {
                "input": {
                    "function": "setPskEntry",
                    "kwargs": {selector_key: 1, "Enabled": True, "PSK": b"secret", "CipherSuite": "0x1301", "authAs": ("SID", "new")},
                },
                "output": {"return": True},
            }
        ]
        yield Probe(
            f"setPskEntry/getPskEntry {selector_key} selector accepts current metadata",
            selector_context + [{"input": {"function": "getPskEntry", "kwargs": {selector_key: 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": True, "CipherSuite": "0x1301"}}}],
            "PASS",
            "psk-wrapper",
            f"{selector_key} should select the same TLS_PSK_Key row for Set and Get wrappers.",
        )
        yield Probe(
            f"setPskEntry/getPskEntry {selector_key} selector rejects stale metadata",
            selector_context + [{"input": {"function": "getPskEntry", "kwargs": {selector_key: 1, "authAs": ("SID", "new")}}, "output": {"return": {"Enabled": False, "CipherSuite": "0x1301"}}}],
            "FAIL",
            "psk-wrapper",
            f"Ignoring {selector_key} would leave stale TLS_PSK_Key metadata accepted.",
        )


def port_probes() -> Iterable[Probe]:
    context = owned_admin_context() + [start_session("0000020500000001", "0000000900000006", "new")]
    payload = {"values": {"port": "Port2", "PortLocked": True, "authAs": ("SID", "new")}}
    get_payload = {"values": {"port": "Port2", "authAs": ("SID", "new")}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        after_set = context + [operation_payload("setPort", payload, key=shape, output={"return": True})]
        yield Probe(
            f"setPort/getPort {shape} values envelope accepts current PortLocked",
            after_set + [operation_payload("getPort", get_payload, key=shape, output={"return": {"PortLocked": True}})],
            "PASS",
            "port-wrapper",
            "setPort values envelopes should update the tracked AdminSP Port row.",
        )
        yield Probe(
            f"setPort/getPort {shape} values envelope rejects stale PortLocked",
            after_set + [operation_payload("getPort", get_payload, key=shape, output={"return": {"PortLocked": False}})],
            "FAIL",
            "port-wrapper",
            "Ignoring setPort state or getPort selectors lets stale PortLocked values pass.",
        )
        yield Probe(
            f"setPort {shape} values envelope rejects stale raw Port Get",
            after_set
            + [
                method_record(
                    "Get",
                    "",
                    "Port2",
                    optional={"CellBlock": [{"startColumn": 3}, {"endColumn": 3}]},
                    return_values={3: False},
                )
            ],
            "FAIL",
            "port-wrapper",
            "Wrapper Port mutations and raw Port table reads must share state.",
        )
    alias_context = context + [
        {"input": {"function": "setPort", "kwargs": {"port_id": "Port2", "PortLocked": True, "authAs": ("SID", "new")}}, "output": {"return": True}}
    ]
    locked_alias_context = context + [
        {"input": {"function": "setPort", "kwargs": {"id": "Port2", "locked": True, "authAs": ("SID", "new")}}, "output": {"return": True}}
    ]
    for selector_key in ("portId", "id", "target", "interface", "interfaceId", "portName", "name"):
        yield Probe(
            f"setPort port_id/getPort {selector_key} accepts current PortLocked",
            alias_context
            + [
                {
                    "input": {"function": "getPort", "kwargs": {selector_key: "Port2", "authAs": ("SID", "new")}},
                    "output": {"return": {"PortLocked": True}},
                }
            ],
            "PASS",
            "port-wrapper",
            "Top-level Port selector aliases should target the same AdminSP Port row.",
        )
        yield Probe(
            f"setPort port_id/getPort {selector_key} rejects stale PortLocked",
            alias_context
            + [
                {
                    "input": {"function": "getPort", "kwargs": {selector_key: "Port2", "authAs": ("SID", "new")}},
                    "output": {"return": {"PortLocked": False}},
                }
            ],
            "FAIL",
            "port-wrapper",
            "A stale PortLocked value means a Port selector alias was ignored.",
        )
    yield Probe(
        "setPort top-level locked updates PortLocked state",
        locked_alias_context
        + [
            {
                "input": {"function": "getPort", "kwargs": {"id": "Port2", "authAs": ("SID", "new")}},
                "output": {"return": {"PortLocked": True}},
            }
        ],
        "PASS",
        "port-wrapper",
        "SDK-style locked should map to the PortLocked column for Port row state.",
    )
    yield Probe(
        "setPort top-level locked rejects stale PortLocked",
        locked_alias_context
        + [
            {
                "input": {"function": "getPort", "kwargs": {"id": "Port2", "authAs": ("SID", "new")}},
                "output": {"return": {"PortLocked": False}},
            }
        ],
        "FAIL",
        "port-wrapper",
        "A stale PortLocked value means the locked alias was not applied to state.",
    )
    yield Probe(
        "getPort rejects scalar-only PortLocked payload",
        locked_alias_context
        + [
            {
                "input": {"function": "getPort", "kwargs": {"id": "Port2", "authAs": ("SID", "new")}},
                "output": {"return": 1},
            }
        ],
        "FAIL",
        "port-wrapper",
        "Port.Get wrappers return named Port cells; scalar Boolean-like values belong to bounded boolean getters.",
    )


def mbr_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [start_session("0000020500000002", "0000000900010001", "new")]
    write_context = context + [
        {"input": {"function": "writeMBR", "kwargs": {"offset": 0, "bytes": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    yield Probe(
        "writeMBR/readMBR preserves byte payload",
        write_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 0, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
        "PASS",
        "mbr-wrapper",
        "MBR byte-table wrapper writes and reads should share sparse byte state.",
    )
    yield Probe(
        "writeMBR/readMBR rejects stale byte payload",
        write_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 0, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
        "FAIL",
        "mbr-wrapper",
        "A stale MBR read means writeMBR or readMBR did not map to the byte table.",
    )
    yield Probe(
        "writeMBR/readMBR rejects Boolean-only byte payload",
        write_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 0, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "mbr-wrapper",
        "A successful MBR byte-table read must return byte data, not only a wrapper success flag.",
    )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"table": "MBR"}, "command": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}}),
        ("operationRequest command", {"operationRequest": {"command": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}}),
        ("command", {"command": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}),
        ("action", {"action": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}),
    ):
        setmbr_context = context + [
            {"input": {"function": "setMBR", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setMBR {label} writes current bytes",
            setmbr_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "PASS",
            "mbr-operation-envelope-doc",
            "setMBR operation-style byte envelopes must mutate the MBR byte table.",
        )
        yield Probe(
            f"setMBR {label} rejects stale bytes",
            setmbr_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
            "FAIL",
            "mbr-operation-envelope-doc",
            "Ignoring setMBR operation-style byte envelopes leaves stale MBR bytes accepted.",
        )
    byte_repr_context = context + [
        {"input": {"function": "writeMBR", "kwargs": {"offset": 4, "bytes": "AABBCC", "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    for label, current_payload, stale_payload in (
        ("hex-string-list", ["AA", "BB", "CC"], ["00", "00", "00"]),
        ("prefixed-hex-string-list", ["0xAA", "0xBB", "0xCC"], ["0x00", "0x00", "0x00"]),
        ("prefixed-hex-string", "0xAABBCC", "0x000000"),
    ):
        yield Probe(
            f"readMBR accepts {label} byte payload",
            byte_repr_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 4, "length": 3, "authAs": ("Admin1", "new")}}, "output": {"return": current_payload}}],
            "PASS",
            "mbr-wrapper",
            f"MBR byte reads may return the same byte window as {label}.",
        )
        yield Probe(
            f"readMBR rejects stale {label} byte payload",
            byte_repr_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 4, "length": 3, "authAs": ("Admin1", "new")}}, "output": {"return": stale_payload}}],
            "FAIL",
            "mbr-wrapper",
            f"MBR byte-return representation must still compare against tracked bytes.",
        )
    for label, write_payload, read_payload in (
        ("window", {"window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"window": {"offset": 4, "length": 3}}),
        ("range", {"range": {"start": 4, "count": 3}, "data": "AABBCC"}, {"range": {"start": 4, "count": 3}}),
        ("slice", {"slice": {"startOffset": 4, "byteCount": 3}, "payload": "AABBCC"}, {"slice": {"startOffset": 4, "byteCount": 3}}),
        ("block", {"block": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"block": {"offset": 4, "length": 3}}),
        ("chunk", {"chunk": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"chunk": {"offset": 4, "length": 3}}),
        ("segment", {"segment": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"segment": {"offset": 4, "length": 3}}),
        ("span", {"span": {"offset": 4, "length": 3}, "bytes": "AABBCC"}, {"span": {"offset": 4, "length": 3}}),
        ("bounds", {"bounds": {"start": 4, "count": 3}, "bytes": "AABBCC"}, {"bounds": {"start": 4, "count": 3}}),
        ("byteRange", {"byteRange": {"start": 4, "count": 3}, "bytes": "AABBCC"}, {"byteRange": {"start": 4, "count": 3}}),
        ("request.window", {"request": {"window": {"offset": 4, "length": 3}}, "bytes": "AABBCC"}, {"request": {"window": {"offset": 4, "length": 3}}}),
        ("request window bytes", {"request": {"window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}}, {"window": {"offset": 4, "length": 3}}),
        ("policy range", {"policy": {"range": {"start": 4, "count": 3}, "data": "AABBCC"}}, {"range": {"start": 4, "count": 3}}),
        ("config slice", {"config": {"slice": {"startOffset": 4, "byteCount": 3}, "payload": "AABBCC"}}, {"request": {"values": {"window": {"offset": 4, "length": 3}}}}),
        ("request values window", {"request": {"values": {"window": {"offset": 4, "length": 3}, "bytes": "AABBCC"}}}, {"window": {"offset": 4, "length": 3}}),
        ("mbrRequest values window", {"mbrRequest": {"values": {"offset": 4, "length": 3, "bytes": "AABBCC"}}}, {"mbrRequest": {"window": {"offset": 4, "length": 3}}}),
        ("mbrShadowRequest byteTableRequest window", {"mbrShadowRequest": {"values": {"offset": 4, "length": 3, "bytes": "AABBCC"}}}, {"byteTableRequest": {"window": {"offset": 4, "length": 3}}}),
        ("operation command", {"operation": {"command": {"offset": 4, "length": 3, "bytes": "AABBCC"}}}, {"operation": {"command": {"offset": 4, "length": 3}}}),
        ("operation target command", {"operation": {"target": {"offset": 4, "length": 3}, "command": {"bytes": "AABBCC"}}}, {"operation": {"target": {"offset": 4, "length": 3}, "command": {}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"offset": 4, "length": 3}, "command": {"bytes": "AABBCC"}}}, {"operationRequest": {"target": {"offset": 4, "length": 3}, "command": {}}}),
    ):
        envelope_context = context + [
            {"input": {"function": "writeMBR", "kwargs": {"authAs": ("Admin1", "new"), **write_payload}}, "output": {"return": True}}
        ]
        tag = "mbr-nested-window-envelope-doc" if " " in label else "mbr-wrapper"
        yield Probe(
            f"writeMBR {label} envelope feeds readMBR",
            envelope_context + [{"input": {"function": "readMBR", "kwargs": {"authAs": ("Admin1", "new"), **read_payload}}, "output": {"return": "AABBCC"}}],
            "PASS",
            tag,
            f"MBR top-level {label} envelopes should preserve byte-table offset and length.",
        )
        yield Probe(
            f"writeMBR {label} envelope rejects stale readMBR",
            envelope_context + [{"input": {"function": "readMBR", "kwargs": {"authAs": ("Admin1", "new"), **read_payload}}, "output": {"return": "000000"}}],
            "FAIL",
            tag,
            f"Ignoring MBR top-level {label} envelopes leaves stale bytes over-accepted.",
        )
    def wrap_mbr_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        current: dict[str, Any] = payload
        for key in reversed(chain):
            current = {key: current}
        return current

    for chain in (
        ("mbrRequest", "window", "values"),
        ("request", "mbrShadowRequest", "slice", "values"),
        ("byteTableRequest", "range", "payload"),
        ("config", "target", "window", "values"),
        ("policy", "request", "slice", "values"),
    ):
        chain_name = "/".join(chain)
        envelope_context = context + [
            {"input": {"function": "writeMBR", "kwargs": wrap_mbr_payload({"offset": 4, "length": 3, "bytes": "AABBCC", "authAs": ("Admin1", "new")}, chain)}, "output": {"return": True}}
        ]
        read_kwargs = wrap_mbr_payload({"offset": 4, "length": 3, "authAs": ("Admin1", "new")}, chain)
        yield Probe(
            f"writeMBR deep {chain_name} envelope feeds readMBR",
            envelope_context + [{"input": {"function": "readMBR", "kwargs": read_kwargs}, "output": {"return": "AABBCC"}}],
            "PASS",
            "mbr-deep-window-envelope-doc",
            "Deep MBR byte-window wrappers must preserve offset, length, payload, and auth.",
        )
        yield Probe(
            f"writeMBR deep {chain_name} envelope rejects stale readMBR",
            envelope_context + [{"input": {"function": "readMBR", "kwargs": read_kwargs}, "output": {"return": "000000"}}],
            "FAIL",
            "mbr-deep-window-envelope-doc",
            "Ignoring deep MBR byte-window wrappers leaves stale bytes over-accepted.",
        )
    mbr_window_context = context + [
        {"input": {"function": "writeMBR", "kwargs": {"offset": 30, "bytes": "AABBCCDD", "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    for length_key in ("bytesToRead", "readLength", "numBytesToRead", "countBytes"):
        yield Probe(
            f"readMBR {length_key} alias returns middle slice",
            mbr_window_context
            + [{"input": {"function": "readMBR", "kwargs": {"offset": 31, length_key: 2, "authAs": ("Admin1", "new")}}, "output": {"return": "BBCC"}}],
            "PASS",
            "mbr-wrapper",
            f"`readMBR` length alias `{length_key}` should use byte-table window semantics.",
        )
        yield Probe(
            f"readMBR {length_key} alias rejects shifted prefix",
            mbr_window_context
            + [{"input": {"function": "readMBR", "kwargs": {"offset": 31, length_key: 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "FAIL",
            "mbr-wrapper",
            f"`readMBR` length alias `{length_key}` should not read from the wrong byte offset.",
        )
    store_context = context + [
        {"input": {"function": "storeMBR", "kwargs": {"offset": 2, "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    yield Probe(
        "storeMBR/readMBR preserves byte payload",
        store_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 2, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
        "PASS",
        "mbr-wrapper",
        "MBR write spelling aliases should update the shared byte-table state.",
    )
    yield Probe(
        "storeMBR/readMBR rejects stale byte payload",
        store_context + [{"input": {"function": "readMBR", "kwargs": {"offset": 2, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
        "FAIL",
        "mbr-wrapper",
        "Ignoring storeMBR leaves stale MBR byte observations over-accepted.",
    )
    for alias in ("setMBR", "storeMBRBytes", "setMBRData", "writeMBRData", "writeMBRShadow", "writeMBRTableBytes", "putMBRTable", "setMBRTable", "storeMBRTable", "writeMBRShadowBytes", "writeMBRShadowPayload", "storeMBRShadow", "storeMBRShadowBytes", "storeMBRShadowPayload", "setMBRShadow", "setMBRShadowBytes", "setMBRShadowPayload", "saveMBRShadow", "saveMBRShadowBytes", "saveMBRShadowPayload", "programMBRShadow", "programMBRShadowBytes", "programMBRShadowPayload", "putMBRShadow", "putMBRShadowBytes", "putMBRShadowPayload", "updateMBRShadow", "updateMBRShadowBytes", "updateMBRShadowPayload"):
        context = activated_locking_context() + [
            start_session("0000020500000002", "0000000900010001", "new"),
            {"input": {"function": alias, "kwargs": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias feeds readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should mutate the shared MBR byte-table state.",
        )
        yield Probe(
            f"{alias} alias rejects stale readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
            "FAIL",
            "mbr-wrapper",
            f"Ignoring {alias} leaves stale MBR bytes over-accepted.",
        )
    for alias in ("writeMbrTable", "updateMBR", "saveMBR", "programMBR", "writeMBRPayload", "setMBRPayload", "putMBRPayload", "storeMBRPayload", "saveMBRPayload", "updateMBRPayload", "programMBRPayload", "putMBRData", "storeMBRData", "saveMBRData", "updateMBRData", "programMBRData", "setMBRTableBytes", "putMBRTableBytes", "storeMBRTableBytes", "saveMBRTable", "saveMBRTableBytes", "updateMBRTable", "updateMBRTableBytes", "programMBRTable", "programMBRTableBytes", "saveMBRBytes", "updateMBRBytes", "programMBRBytes", "writeMBRBlock", "storeMBRBlock", "saveMBRBlock", "setMBRBlock", "putMBRBlock", "updateMBRBlock", "programMBRBlock", "writeMBRSegment", "storeMBRSegment", "putMBRSegment", "saveMBRSegment", "updateMBRSegment", "programMBRSegment", "writeMBRRange", "storeMBRRange", "putMBRRange", "saveMBRRange", "updateMBRRange", "programMBRRange", "writeMBRChunk", "storeMBRChunk", "saveMBRChunk", "setMBRChunk", "putMBRChunk", "updateMBRChunk", "programMBRChunk", "writeMBRWindow", "storeMBRWindow", "setMBRWindow", "saveMBRWindow", "putMBRWindow", "updateMBRWindow", "programMBRWindow", "writeMBRSlice", "storeMBRSlice", "setMBRSlice", "putMBRSlice", "saveMBRSlice", "updateMBRSlice", "programMBRSlice"):
        context = activated_locking_context() + [
            start_session("0000020500000002", "0000000900010001", "new"),
            {"input": {"function": alias, "kwargs": {"offset": 14, "bytes": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias feeds readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 14, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should mutate the shared MBR byte-table state.",
        )
        yield Probe(
            f"{alias} alias rejects stale readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 14, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
            "FAIL",
            "mbr-wrapper",
            f"Ignoring {alias} leaves stale MBR bytes over-accepted.",
        )
    for alias in ("writeMBR", "putMBR", "putMBRBytes"):
        context = activated_locking_context() + [
            start_session("0000020500000002", "0000000900010001", "new"),
            {"input": {"function": alias, "args": ["AABB"], "kwargs": {"offset": 12, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} positional payload feeds readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 12, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} may carry the MBR byte payload as the first positional argument when offset is named.",
        )
        yield Probe(
            f"{alias} positional payload rejects stale readMBR",
            context + [{"input": {"function": "readMBR", "kwargs": {"offset": 12, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} positional payload must mutate the tracked MBR byte-table state.",
        )
    for alias in ("getMBR", "getMBRBytes", "getMBRData", "readMBRBytes", "readMBRData", "readMBRPayload", "readMBRShadow", "readMBRShadowBytes", "readMBRShadowPayload", "readMBRTable", "readMBRTableBytes", "getMBRTable", "getMBRTableBytes", "getMBRPayload", "getMBRShadow", "getMBRShadowBytes", "getMBRShadowPayload", "fetchMBR", "fetchMBRBytes", "fetchMBRData", "fetchMBRPayload", "fetchMBRShadow", "fetchMBRShadowBytes", "fetchMBRShadowPayload", "fetchMBRTable", "fetchMBRTableBytes", "loadMBRBytes", "loadMBRData", "loadMBRPayload", "loadMBRTable", "loadMBRTableBytes", "loadMBRShadow", "loadMBRShadowBytes", "loadMBRShadowPayload", "readMBRBlock", "fetchMBRBlock", "loadMBRBlock", "getMBRBlock", "readMBRSegment", "fetchMBRSegment", "loadMBRSegment", "getMBRSegment", "readMBRRange", "fetchMBRRange", "loadMBRRange", "getMBRRange", "readMBRChunk", "fetchMBRChunk", "loadMBRChunk", "getMBRChunk", "readMBRWindow", "fetchMBRWindow", "loadMBRWindow", "getMBRWindow", "readMBRSlice", "fetchMBRSlice", "loadMBRSlice", "getMBRSlice"):
        context = activated_locking_context() + [
            start_session("0000020500000002", "0000000900010001", "new"),
            {"input": {"function": "writeMBR", "kwargs": {"offset": 10, "bytes": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias reads MBR bytes",
            context + [{"input": {"function": alias, "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "AABB"}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should compare the same MBR byte window as readMBR.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBR bytes",
            context + [{"input": {"function": alias, "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": "0000"}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} cannot ignore tracked MBR bytes.",
        )
        yield Probe(
            f"{alias} alias rejects Boolean-only MBR read",
            context + [{"input": {"function": alias, "kwargs": {"offset": 10, "length": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} is a byte-table read and cannot be satisfied by a literal Boolean wrapper return.",
        )
    control_context = context + [
        {"input": {"function": "setMBRControl", "kwargs": {"MBREnable": True, "MBRDone": False, "authAs": ("Admin1", "new")}}, "output": {"return": True}}
    ]
    yield Probe(
        "setMBRControl updates MBRControl cells",
        control_context + [method_record("Get", "", "MBRControl", return_values={1: True, 2: False, 3: [0]})],
        "PASS",
        "mbr-wrapper",
        "setMBRControl should update Enabled and Done on the MBRControl row.",
    )
    yield Probe(
        "setMBRControl rejects stale MBRControl cells",
        control_context + [method_record("Get", "", "MBRControl", return_values={1: False, 2: True, 3: [0]})],
        "FAIL",
        "mbr-wrapper",
        "Stale MBRControl cells mean compact MBR control wrappers were ignored.",
    )
    yield Probe(
        "setMBRControl rejects empty MBRControl Get result",
        control_context + [method_record("Get", "", "MBRControl", return_values={})],
        "FAIL",
        "mbr-wrapper",
        "MBRControl.Get must return the requested known cells rather than an empty success payload.",
    )
    for label, kwargs in (
        ("request values", {"request": {"values": {"Enabled": True, "Done": False, "DoneOnReset": [0], "authAs": ("Admin1", "new")}}}),
        ("policy request values", {"policy": {"request": {"values": {"MBREnable": True, "MBRDone": False, "DoneOnReset": [0], "authAs": ("Admin1", "new")}}}}),
        ("config mbrcontrol", {"config": {"mbrControl": {"enabled": True, "done": False, "doneOnReset": [0]}, "authAs": ("Admin1", "new")}}),
        ("request target command", {"request": {"target": {"table": "MBRControl"}, "command": {"Enabled": True, "Done": False, "DoneOnReset": [0]}, "authAs": ("Admin1", "new")}}),
        ("operation target control", {"operation": {"target": {"table": "MBRControl"}, "mbrControl": {"Enabled": True, "Done": False, "DoneOnReset": [0]}, "authAs": ("Admin1", "new")}}),
        ("config target action", {"config": {"target": {"table": "MBRControl"}, "action": {"Enabled": True, "Done": False, "DoneOnReset": [0]}, "authAs": ("Admin1", "new")}}),
    ):
        nested_control_context = activated_locking_context() + [
            {"input": {"function": "setMBRControl", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setMBRControl {label} nested envelope updates MBRControl",
            nested_control_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True, "Done": False, "DoneOnReset": [0]}}}],
            "PASS",
            "mbrcontrol-nested-envelope-doc",
            "Nested MBRControl setter envelopes should update Enabled, Done, and DoneOnReset cells.",
        )
        yield Probe(
            f"setMBRControl {label} nested envelope rejects stale MBRControl",
            nested_control_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False, "Done": True, "DoneOnReset": []}}}],
            "FAIL",
            "mbrcontrol-nested-envelope-doc",
            "Ignoring nested MBRControl setter envelopes permits stale control-cell observations.",
        )
    setmbr_context = activated_locking_context() + [
        {"input": {"function": "setMBR", "kwargs": {"enabled": True, "done": False, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        start_session(LOCKING_SP, ADMIN1, "new"),
    ]
    yield Probe(
        "setMBR control-field alias updates MBRControl cells",
        setmbr_context + [method_record("Get", "", "MBRControl", return_values={1: True, 2: False, 3: [0]})],
        "PASS",
        "mbr-wrapper",
        "setMBR with Enabled/Done-style fields should share compact MBRControl Set semantics.",
    )
    yield Probe(
        "setMBR control-field alias rejects stale MBRControl cells",
        setmbr_context + [method_record("Get", "", "MBRControl", return_values={1: False, 2: True, 3: [0]})],
        "FAIL",
        "mbr-wrapper",
        "A control-shaped setMBR call must not be ignored before checking MBRControl cells.",
    )
    yield Probe(
        "setMBRControl direct CellBlock updates MBRControl cells",
        control_context
        + [
            method_record(
                "Get",
                "",
                "MBRControl",
                return_values={1: True, 2: False},
                optional={"CellBlock": [{"startColumn": 1}, {"endColumn": 2}]},
            )
        ],
        "PASS",
        "mbr-wrapper",
        "Optional CellBlock selectors should compare tracked MBRControl cells.",
    )
    yield Probe(
        "setMBRControl direct CellBlock rejects empty MBRControl result",
        control_context
        + [
            method_record(
                "Get",
                "",
                "MBRControl",
                return_values={},
                optional={"CellBlock": [{"startColumn": 1}, {"endColumn": 2}]},
            )
        ],
        "FAIL",
        "mbr-wrapper",
        "A successful CellBlock Get must include the selected MBRControl cells.",
    )
    yield Probe(
        "setMBRControl direct CellBlock rejects stale MBRControl cells",
        control_context
        + [
            method_record(
                "Get",
                "",
                "MBRControl",
                return_values={1: False, 2: False},
                optional={"CellBlock": [{"startColumn": 1}, {"endColumn": 2}]},
            )
        ],
        "FAIL",
        "mbr-wrapper",
        "Optional CellBlock selectors must not erase tracked MBRControl state checks.",
    )


def accesscontrol_probes() -> Iterable[Probe]:
    base = [start_session("0000020500000001")]
    raw = {
        "input": {
            "method": {"name": "GetACL"},
            "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
            "values": {"InvokingID": "0000000B00008402", "MethodID": "Get"},
        },
        "output": {"status_codes": SUCCESS, "return_values": ["0000000800008C04"]},
    }
    stale = {
        "input": {
            "method": {"name": "GetACL"},
            "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
            "values": {"InvokingID": "0000000B00008402", "MethodID": "Get"},
        },
        "output": {"status_codes": SUCCESS, "return_values": []},
    }
    yield Probe(
        "GetACL values dictionary C_PIN_MSID Get returns exact ACL",
        base + [raw],
        "PASS",
        "accesscontrol-wrapper",
        "GetACL InvokingID/MethodID may be encoded under a values dictionary.",
    )
    yield Probe(
        "GetACL values dictionary C_PIN_MSID Get rejects empty ACL",
        base + [stale],
        "FAIL",
        "accesscontrol-wrapper",
        "Values-dictionary GetACL arguments must resolve to the documented AccessControl association.",
    )
    for label, method_node in (
        ("method args list", {"name": "GetACL", "args": ["C_PIN_MSID", "Get"]}),
        ("method required-list args", {"name": "GetACL", "args": {"required": ["C_PIN_MSID", "Get"]}}),
    ):
        yield Probe(
            f"GetACL accepts {label}",
            base
            + [
                {
                    "input": {
                        "method": method_node,
                        "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                    },
                    "output": {"status_codes": SUCCESS, "return_values": ["ACE_00008C04"]},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL positional arguments embedded in the method node must map to InvokingID and MethodID.",
        )
        yield Probe(
            f"GetACL {label} rejects empty ACL",
            base
            + [
                {
                    "input": {
                        "method": method_node,
                        "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                    },
                    "output": {"status_codes": SUCCESS, "return_values": []},
                }
            ],
            "FAIL",
            "accesscontrol-wrapper",
            "The method-node positional InvokingID/MethodID pair identifies C_PIN_MSID.Get and must return the documented ACL.",
        )
    for label, input_payload in (
        ("function positional args", {"function": "getACL", "args": ["C_PIN_MSID", "Get"]}),
        ("function object operation aliases", {"function": "getACL", "object": "C_PIN_MSID", "operation": "Get"}),
        ("function target method aliases", {"function": "getACL", "target": "C_PIN_MSID", "method": "Get"}),
        ("function obj op aliases", {"function": "getACL", "obj": "C_PIN_MSID", "op": "Get"}),
        ("function uid action aliases", {"function": "getACL", "uid": "C_PIN_MSID", "action": "Get"}),
    ):
        yield Probe(
            f"GetACL wrapper accepts {label}",
            base + [{"input": input_payload, "output": {"return": ["ACE_00008C04"]}}],
            "PASS",
            "accesscontrol-wrapper",
            "getACL wrapper calls should map to AccessControl.GetACL with InvokingID and MethodID arguments.",
        )
        yield Probe(
            f"GetACL wrapper {label} rejects empty ACL",
            base + [{"input": input_payload, "output": {"return": []}}],
            "FAIL",
            "accesscontrol-wrapper",
            "The wrapper GetACL argument pair identifies C_PIN_MSID.Get and must return the documented ACL.",
        )
    locking_acl_base = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    locking_acl = ["ACE_0003D001", "ACE_00000003"]
    for label, kwargs in (
        ("association tuple", {"association": ["Locking_Range1", "Get"], "authAs": ("Admin1", "new")}),
        ("association dict", {"association": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}),
        ("aclRequest dict", {"aclRequest": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}),
        ("request dict", {"request": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}),
        ("targetMethod alias", {"target": "Locking_Range1", "targetMethod": "Get", "authAs": ("Admin1", "new")}),
        ("values association dict", {"values": {"association": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}}),
        ("request values association", {"request": {"values": {"association": {"object": "Locking_Range1", "method": "Get"}}, "authAs": ("Admin1", "new")}}),
        ("policy request association", {"policy": {"request": {"association": {"object": "Locking_Range1", "method": "Get"}}, "authAs": ("Admin1", "new")}}),
    ):
        yield Probe(
            f"GetACL wrapper accepts {label}",
            locking_acl_base + [{"input": {"function": "getACL", "kwargs": kwargs}, "output": {"return": locking_acl}}],
            "PASS",
            "accesscontrol-getacl-nested-envelope-doc" if "request" in label else "accesscontrol-wrapper",
            "GetACL queries the AccessControl association keyed by InvokingID and MethodID; SDK wrappers may carry that pair under association/request envelopes.",
        )
        yield Probe(
            f"GetACL wrapper {label} rejects incomplete Locking ACL",
            locking_acl_base + [{"input": {"function": "getACL", "kwargs": kwargs}, "output": {"return": ["ACE_0003D001"]}}],
            "FAIL",
            "accesscontrol-getacl-nested-envelope-doc" if "request" in label else "accesscontrol-wrapper",
            "Known Locking_Range1.Get ACLs must preserve the full ACE uidref list after association/request wrapper lowering.",
        )
    def wrap_getacl_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        current: dict[str, Any] = payload
        for key in reversed(chain):
            current = {key: current}
        return current

    for chain in (
        ("policy", "request", "association", "values"),
        ("config", "target", "association", "values"),
        ("accessControlRequest", "request", "targetMethod", "values"),
        ("request", "aclRequest", "association", "values"),
        ("values", "accessControlRequest", "objectMethod", "values"),
    ):
        chain_name = "/".join(chain)
        kwargs = wrap_getacl_payload({"object": "Locking_Range1", "method": "Get", "authAs": ("Admin1", "new")}, chain)
        yield Probe(
            f"GetACL wrapper accepts deep {chain_name}",
            locking_acl_base + [{"input": {"function": "getACL", "kwargs": kwargs}, "output": {"return": locking_acl}}],
            "PASS",
            "accesscontrol-getacl-deep-envelope-doc",
            "Deep GetACL wrappers must surface the InvokingID/MethodID association before exact ACL comparison.",
        )
        yield Probe(
            f"GetACL wrapper deep {chain_name} rejects incomplete Locking ACL",
            locking_acl_base + [{"input": {"function": "getACL", "kwargs": kwargs}, "output": {"return": ["ACE_0003D001"]}}],
            "FAIL",
            "accesscontrol-getacl-deep-envelope-doc",
            "Deep GetACL wrapper lowering must still reject missing ACE uidrefs.",
        )
    for function_name, args in (
        ("addACE", ["C_PIN_MSID", "Get", "ACE_00000001"]),
        ("removeACE", ["C_PIN_MSID", "Get", "ACE_00000001"]),
        ("deleteMethod", ["C_PIN_MSID", "Get"]),
    ):
        yield Probe(
            f"{function_name} wrapper authorized false is not authorized",
            base + [{"input": {"function": function_name, "args": args}, "output": {"return": {"authorized": False}}}],
            "PASS",
            "accesscontrol-wrapper",
            f"{function_name} mutates AccessControl metadata and an authorized:false wrapper result must be treated as NOT_AUTHORIZED.",
        )
    yield Probe(
        "addACE wrapper uid/action aliases authorized false is not authorized",
        base
        + [
            {
                "input": {"function": "addACE", "kwargs": {"uid": "C_PIN_MSID", "action": "Get", "ACE": "ACE_00000001"}},
                "output": {"return": {"authorized": False}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "addACE uid/action aliases should still map to AccessControl.AddACE and honor authorization failure.",
    )
    for function_name, args, family in (
        ("changePIN", ["SID", "old", "new"], "credential-wrapper"),
        ("setPSKEntry", [1, "AA"], "psk-wrapper"),
    ):
        yield Probe(
            f"{function_name} wrapper authorized false is not authorized",
            base + [{"input": {"function": function_name, "args": args}, "output": {"return": {"authorized": False}}}],
            "PASS",
            family,
            f"{function_name} is a mutating wrapper and authorized:false must be treated as NOT_AUTHORIZED.",
        )
    for method_alias in ("get", "GET", "MethodID_get"):
        alias_raw = {
            "input": {
                "method": {"name": "GetACL"},
                "invoking_id": {"uid": "0000000700000000", "name": "accesscontrol"},
                "values": {"InvokingID": "0000000B00008402", "MethodID": method_alias},
            },
            "output": {"status_codes": SUCCESS, "return_values": ["0000000800008C04"]},
        }
        yield Probe(
            f"GetACL values dictionary canonicalizes MethodID alias {method_alias}",
            base + [alias_raw],
            "PASS",
            "accesscontrol-wrapper",
            "AccessControl MethodID arguments should canonicalize known method names case-insensitively.",
        )
    for label, values in (
        ("object method aliases", {"object": "C_PIN_MSID", "method": "Get"}),
        ("objectId methodId aliases", {"objectId": "C_PIN_MSID", "methodId": "Get"}),
        ("objectUID methodUID aliases", {"objectUID": "C_PIN_MSID", "methodUID": "Get"}),
        ("invoking methodName aliases", {"invoking": "C_PIN_MSID", "methodName": "Get"}),
        ("invokingObject operationId aliases", {"invokingObject": "C_PIN_MSID", "operationId": "Get"}),
        ("invokingObjectUID actionUID aliases", {"invokingObjectUID": "C_PIN_MSID", "actionUID": "Get"}),
        ("target operation aliases", {"target": "C_PIN_MSID", "operation": "Get"}),
        ("obj op aliases", {"obj": "C_PIN_MSID", "op": "Get"}),
        ("uid action aliases", {"uid": "C_PIN_MSID", "action": "Get"}),
        ("single nested args dict", {"args": [{"InvokingID": "C_PIN_MSID", "MethodID": "Get"}]}),
    ):
        yield Probe(
            f"GetACL values dictionary accepts {label}",
            base
            + [
                {
                    "input": {
                        "method": {"name": "GetACL"},
                        "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                        "values": values,
                    },
                    "output": {"status_codes": SUCCESS, "return_values": ["ACE_00008C04"]},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL SDK value dictionaries may name InvokingID/MethodID as object/method or target/operation.",
        )
    for label, required_args in (
        ("required uid action aliases", {"uid": "C_PIN_MSID", "action": "Get"}),
        ("required obj operation aliases", {"obj": "C_PIN_MSID", "operation": "Get"}),
        ("required target op aliases", {"target": "C_PIN_MSID", "op": "Get"}),
        ("required invokingObject actionId aliases", {"invokingObject": "C_PIN_MSID", "actionId": "Get"}),
    ):
        yield Probe(
            f"GetACL accepts {label}",
            base
            + [
                {
                    "input": {
                        "method": {"name": "GetACL"},
                        "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                        "required": required_args,
                    },
                    "output": {"status_codes": SUCCESS, "return_values": ["ACE_00008C04"]},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            "Raw GetACL required dictionaries may use SDK-style InvokingID/MethodID aliases.",
        )
    lower_method_raw = {
        "input": {
            "method": {"name": "getacl"},
            "invoking_id": {"uid": "0000000700000000", "name": "accesscontrol"},
            "values": {"InvokingID": "0000000B00008402", "MethodID": "get"},
        },
        "output": {"status_codes": SUCCESS, "return_values": ["ace_00008c04"]},
    }
    yield Probe(
        "GetACL canonicalizes lowercase method and lowercase ACE return ref",
        base + [lower_method_raw],
        "PASS",
        "accesscontrol-wrapper",
        "Raw method names and returned ACE refs may vary in casing but should resolve to the same documented association.",
    )
    for return_key in ("ACL", "ACE", "values", "acl_uids", "aceUids", "aclRefs", "aceRefs"):
        wrapped_return_raw = {
            "input": {
                "method": {"name": "GetACL"},
                "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                "values": {"InvokingID": "0000000B00008402", "MethodID": "Get"},
            },
            "output": {"status_codes": SUCCESS, "return_values": {return_key: ["0000000800008C04"]}},
        }
        yield Probe(
            f"GetACL accepts {return_key} wrapped ACE uidref return list",
            base + [wrapped_return_raw],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL return uidref lists may be wrapped under descriptive ACL/ACE/value keys.",
        )
    for envelope_key in ("return", "payload", "data", "body"):
        yield Probe(
            f"GetACL accepts nested {envelope_key} ACL return envelope",
            base
            + [
                {
                    "input": {
                        "method": {"name": "GetACL"},
                        "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                        "values": {"InvokingID": "0000000B00008402", "MethodID": "Get"},
                    },
                    "output": {"status_codes": SUCCESS, "return_values": {envelope_key: {"ACL": ["0000000800008C04"]}}},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            "Neutral GetACL return envelopes should unwrap before ACE uidref-list validation.",
        )
    for return_key in ("ACL", "aceUids", "aclRefs", "aceRefs"):
        top_level_return_raw = {
            "input": {
                "method": {"name": "GetACL"},
                "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                "values": {"InvokingID": "0000000B00008402", "MethodID": "Get"},
            },
            "output": {"status_codes": SUCCESS, return_key: ["0000000800008C04"]},
        }
        yield Probe(
            f"GetACL accepts top-level {return_key} ACE uidref return list",
            base + [top_level_return_raw],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL successful ACE uidref lists may be carried as top-level ACL/ACE fields in SDK output envelopes.",
        )
    level0_user_count_eight_context = [level0_opal_v2(0, user_authorities=8)] + activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    yield Probe(
        "GetACL Level0 user count excludes C_PIN_User9 Set association",
        level0_user_count_eight_context
        + [
            {
                "input": {
                    "method": {"name": "GetACL"},
                    "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                    "values": {"InvokingID": "C_PIN_User9", "MethodID": "Set"},
                },
                "output": {"status_codes": SUCCESS, "return_values": ["ACE_0003A809"]},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "Level0 user-authority count bounds the UserN authority/C_PIN association universe.",
    )
    yield Probe(
        "GetACL Level0 user count permits Authority_User9 absence",
        level0_user_count_eight_context
        + [
            {
                "input": {
                    "method": {"name": "GetACL"},
                    "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                    "values": {"InvokingID": "Authority_User9", "MethodID": "Get"},
                },
                "output": {"status_codes": NOT_AUTHORIZED, "return_values": []},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "Objects beyond the observed UserN count should be modeled as absent AccessControl associations.",
    )
    yield Probe(
        "GetACL Level0 user count rejects Authority_User9 success",
        level0_user_count_eight_context
        + [
            {
                "input": {
                    "method": {"name": "GetACL"},
                    "invoking_id": {"uid": "0000000700000000", "name": "AccessControl"},
                    "values": {"InvokingID": "Authority_User9", "MethodID": "Get"},
                },
                "output": {"status_codes": SUCCESS, "return_values": ["ACE_00039000", "ACE_00000003"]},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "Exact UserN ACL synthesis must stop at the observed Level0 user-authority count.",
    )
    dynamic_row_table_uid = "000001AA00000000"
    dynamic_row_uid = "000001AA00000001"
    dynamic_row_ref = {"uid": dynamic_row_uid, "name": "RowAlias"}
    dynamic_row_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        method_record(
            "CreateTable",
            "0000000000000001",
            "ThisSP",
            required={"NewTableName": "DynamicRow", "Kind": 1, "GetSetACL": ["ACE_Anybody"], "Columns": [["Entry", "uid"]], "MinSize": 0},
            optional={"CommonName": "Base"},
            return_values={"UID": dynamic_row_table_uid, "Rows": 0},
        ),
        method_record("CreateRow", dynamic_row_table_uid, "", optional={"Values": [{"1": "row"}]}, return_values=[dynamic_row_uid]),
    ]
    yield Probe(
        "Created row AddACE accepts status plus empty values return",
        dynamic_row_context
        + [
            method_record(
                "AddACE",
                "0000000700000000",
                "AccessControl",
                required={"InvokingID": dynamic_row_ref, "MethodID": "Get"},
                optional={"ACE": "ACE_Admin"},
                return_values={"status": SUCCESS, "values": []},
            )
        ],
        "PASS",
        "accesscontrol-wrapper",
        "Successful AddACE returns an empty list; wrappers may carry it under values next to a status field.",
    )
    for ace_key in ("ACE", "aceRef"):
        context = dynamic_row_context + [
            {
                "input": {"function": "addACE", "values": {"object": dynamic_row_ref, "method": "Get", ace_key: "ACE_Admin"}},
                "output": {"return": []},
            }
        ]
        yield Probe(
            f"Created row wrapper AddACE values {ace_key} updates dynamic ACL",
            context
            + [
                method_record(
                    "GetACL",
                    "0000000700000000",
                    "AccessControl",
                    required={"InvokingID": dynamic_row_uid, "MethodID": "Get"},
                    return_values=["ACE_Anybody", "ACE_Admin"],
                )
            ],
            "PASS",
            "accesscontrol-wrapper",
            "Wrapper AddACE values envelopes must carry the ACE argument into the dynamic AccessControl ACL update.",
        )
        yield Probe(
            f"Created row wrapper AddACE values {ace_key} rejects stale ACL",
            context
            + [
                method_record(
                    "GetACL",
                    "0000000700000000",
                    "AccessControl",
                    required={"InvokingID": dynamic_row_uid, "MethodID": "Get"},
                    return_values=["ACE_Anybody"],
                )
            ],
            "FAIL",
            "accesscontrol-wrapper",
            "A values-envelope ACE reference cannot be ignored when updating dynamic AccessControl ACL state.",
        )
    for label, kwargs in (
        ("policy association aceRef", {"policy": {"association": {"object": dynamic_row_ref, "method": "Get"}, "aceRef": "ACE_Admin"}}),
        ("request accessControlRequest entry", {"request": {"accessControlRequest": {"InvokingID": dynamic_row_ref, "MethodID": "Get"}, "entry": "ACE_Admin"}}),
        ("params target ACE object", {"params": {"target": {"object": dynamic_row_ref, "method": "Get"}, "ACE": {"uid": "0000010800000003", "name": "ACE_Admin"}}}),
    ):
        context = dynamic_row_context + [{"input": {"function": "addACE", "kwargs": kwargs}, "output": {"return": []}}]
        yield Probe(
            f"Created row wrapper AddACE {label} updates dynamic ACL",
            context
            + [
                method_record(
                    "GetACL",
                    "0000000700000000",
                    "AccessControl",
                    required={"InvokingID": dynamic_row_uid, "MethodID": "Get"},
                    return_values=["ACE_Anybody", "ACE_Admin"],
                )
            ],
            "PASS",
            "accesscontrol-wrapper",
            "Nested AddACE policy/request envelopes must carry both the association and ACE argument into dynamic AccessControl ACL state.",
        )
        yield Probe(
            f"Created row wrapper AddACE {label} rejects stale ACL",
            context
            + [
                method_record(
                    "GetACL",
                    "0000000700000000",
                    "AccessControl",
                    required={"InvokingID": dynamic_row_uid, "MethodID": "Get"},
                    return_values=["ACE_Anybody"],
                )
            ],
            "FAIL",
            "accesscontrol-wrapper",
            "After nested AddACE succeeds, later GetACL cannot omit the dynamically added ACE.",
        )
    locking_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "Authority_User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        function_record(
            "setRange",
            [1],
            {"authAs": ("Admin1", "new"), "RangeStart": 80, "RangeLength": 8, "ReadLockEnabled": 1, "WriteLockEnabled": 1, "ReadLocked": 1, "WriteLocked": 1},
            True,
        ),
    ]
    unlock = operation_payload("readUnlock", {"values": {"range": 1, "authAs": ("User1", "userpin"), "locked": False}}, key="kwargs")
    for ace_key, ace_symbol in (("ace", "ACE_0003E001"), ("target", "Ace_0003E001"), ("object", "ace_0003e001")):
        grant = operation_payload(
            "enableRangeAccess",
            {"values": {ace_key: ace_symbol, "user": "User1", "authAs": ("Admin1", "new")}},
            key="kwargs",
        )
        yield Probe(
            f"enableRangeAccess raw ACE symbol via {ace_key} enables User1 readUnlock",
            locking_context + [grant, unlock, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"ReadLocked": 0})],
            "PASS",
            "accesscontrol-wrapper",
            "Raw ACE_0003E001 selectors should update the Range1 read-lock ACE expression.",
        )
    for operation, unlock_fn, column in (("read", "readUnlock", "ReadLocked"), ("write", "writeUnlock", "WriteLocked")):
        grant = operation_payload(
            "enableRangeAccess",
            {"values": {"range": 1, "operation": operation, "user": "User1", "authAs": ("Admin1", "new")}},
            key="kwargs",
        )
        unlock_call = operation_payload(unlock_fn, {"values": {"range": 1, "authAs": ("User1", "userpin"), "locked": False}}, key="kwargs")
        yield Probe(
            f"enableRangeAccess range operation {operation} enables User1 unlock",
            locking_context + [grant, unlock_call, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: 0})],
            "PASS",
            "accesscontrol-wrapper",
            "range+operation access wrappers should update the corresponding Locking Range ACE expression.",
        )
        yield Probe(
            f"enableRangeAccess range operation {operation} rejects stale lock",
            locking_context + [grant, unlock_call, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: 1})],
            "FAIL",
            "accesscontrol-wrapper",
            "Stale lock state after a granted unlock means the range+operation ACE was ignored.",
        )
        grant_access = {
            "input": {"function": "grantAccess", "kwargs": {"range": 1, "operation": operation, "user": "User1", "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        }
        yield Probe(
            f"grantAccess range operation {operation} enables User1 unlock",
            locking_context + [grant_access, unlock_call, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: 0})],
            "PASS",
            "accesscontrol-wrapper",
            "grantAccess with range+operation should update the corresponding Locking Range ACE expression.",
        )
        yield Probe(
            f"grantAccess range operation {operation} rejects stale lock",
            locking_context + [grant_access, unlock_call, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: 1})],
            "FAIL",
            "accesscontrol-wrapper",
            "Stale lock state after grantAccess means the range+operation ACE was ignored.",
        )
        positional_grant_access = {
            "input": {"function": "grantAccess", "args": ["User1", 1, operation], "kwargs": {"authAs": ("Admin1", "new")}},
            "output": {"return": True},
        }
        yield Probe(
            f"grantAccess positional operation {operation} enables User1 unlock",
            locking_context + [positional_grant_access, unlock_call, function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: 0})],
            "PASS",
            "accesscontrol-wrapper",
            "Positional grantAccess(user, range, operation) should not be misparsed as an Authority row Set.",
        )
    yield Probe(
        "User1 readUnlock without ACE grant rejects successful wrapper",
        locking_context + [unlock],
        "FAIL",
        "accesscontrol-wrapper",
        "A User authority should not unlock Range1 until the corresponding ACE expression grants it.",
    )


def authenticate_probes() -> Iterable[Probe]:
    base = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    for shape, raw_input in (
        ("values", {"function": "authenticate", "values": {"authority": "Admin1", "proof": "new"}}),
        ("call values", {"call": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "new"}}}),
    ):
        yield Probe(
            f"Authenticate {shape} envelope accepts correct PIN",
            base + [{"input": raw_input, "output": {"return": True}}],
            "PASS",
            "authenticate-wrapper",
            "Authenticate values envelopes should preserve authority/proof semantics.",
        )
        yield Probe(
            f"Authenticate {shape} envelope rejects status-string result for correct PIN",
            base + [{"input": raw_input, "output": {"return": "SUCCESS"}}],
            "FAIL",
            "authenticate-wrapper",
            "Authenticate success carries an explicit Boolean result, not a repeated SUCCESS status string.",
        )
    for shape, raw_input in (
        ("values", {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}),
        ("call values", {"call": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}}),
    ):
        yield Probe(
            f"Authenticate {shape} envelope rejects wrong true",
            base + [{"input": raw_input, "output": {"return": True}}],
            "FAIL",
            "authenticate-wrapper",
            "Wrong credentials inside values envelopes must not pass as unknown successful calls.",
        )
    yield Probe(
        "Authenticate nested authenticated false is successful false result",
        base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {"return": {"authenticated": False}}}],
        "PASS",
        "authenticate-wrapper",
        "Authenticate false is a method-success boolean result, even when wrapped in a returned object.",
    )
    for result_key in ("matched", "matches", "isVerified", "credentialValid", "pinValid", "authorized"):
        yield Probe(
            f"Authenticate nested {result_key} false is successful false result",
            base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {"return": {result_key: False}}}],
            "PASS",
            "authenticate-wrapper",
            "Authenticate false may be encoded under credential match/verification fields.",
        )
        yield Probe(
            f"Authenticate nested {result_key} true rejects wrong proof",
            base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {"return": {result_key: True}}}],
            "FAIL",
            "authenticate-wrapper",
            "Credential-result aliases must not override the tracked proof truth.",
        )
    yield Probe(
        "Authenticate top-level passed false is successful false result",
        base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {"passed": False}}],
        "PASS",
        "authenticate-wrapper",
        "Authenticate false may be encoded under top-level passed:false.",
    )
    for result_key in ("verified", "isVerified", "matched", "isMatched", "credentialMatched", "pinMatched", "valid", "isValid", "accepted", "authorized"):
        yield Probe(
            f"Authenticate top-level {result_key} accepts correct proof",
            base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "new"}}, "output": {result_key: True}}],
            "PASS",
            "authenticate-wrapper",
            "Top-level credential result fields should be interpreted as the Authenticate Boolean result.",
        )
        yield Probe(
            f"Authenticate top-level {result_key} rejects wrong true",
            base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {result_key: True}}],
            "FAIL",
            "authenticate-wrapper",
            "Top-level credential result fields must not override tracked proof truth.",
        )
        yield Probe(
            f"Authenticate top-level {result_key} accepts wrong false",
            base + [{"input": {"function": "authenticate", "values": {"authority": "Admin1", "proof": "wrong"}}, "output": {result_key: False}}],
            "PASS",
            "authenticate-wrapper",
            "Wrong credentials are represented as method SUCCESS with a false Boolean result.",
        )
    nested_base = activated_locking_context() + [
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
    ]
    for wrapper in ("credential", "auth", "authentication", "verification"):
        for result_key in ("verified", "credentialMatched", "pinMatched", "accepted"):
            yield Probe(
                f"Authenticate nested {wrapper}.{result_key} accepts correct proof",
                nested_base + [{"input": {"function": "authenticate", "values": {"authority": "User1", "proof": "userpin"}}, "output": {"return": {wrapper: {result_key: True}}}}],
                "PASS",
                "authenticate-wrapper",
                "Credential-result envelopes should unwrap before comparing Authenticate's returned Boolean.",
            )
            yield Probe(
                f"Authenticate nested {wrapper}.{result_key} accepts wrong false",
                nested_base + [{"input": {"function": "authenticate", "values": {"authority": "User1", "proof": "wrong"}}, "output": {"return": {wrapper: {result_key: False}}}}],
                "PASS",
                "authenticate-wrapper",
                "Wrong credentials are represented as method SUCCESS with a false Boolean result, even under a credential wrapper.",
            )
            yield Probe(
                f"Authenticate nested {wrapper}.{result_key} rejects wrong true",
                nested_base + [{"input": {"function": "authenticate", "values": {"authority": "User1", "proof": "wrong"}}, "output": {"return": {wrapper: {result_key: True}}}}],
                "FAIL",
                "authenticate-wrapper",
                "Nested credential-result wrappers must not hide a true result for a wrong proof.",
            )
    for envelope in ("credentialRequest", "authRequest", "authenticationRequest", "proofRequest", "pinRequest"):
        yield Probe(
            f"Authenticate {envelope} accepts correct proof",
            nested_base + [{"input": {"function": "authenticate", "kwargs": {envelope: {"values": {"auth": "User1", "proof": "userpin"}}}}, "output": {"return": True}}],
            "PASS",
            "authenticate-domain-request-envelope-doc",
            "Authenticate domain request envelopes must preserve authority and proof before comparing the result Boolean.",
        )
        yield Probe(
            f"Authenticate {envelope} accepts wrong false",
            nested_base + [{"input": {"function": "authenticate", "kwargs": {envelope: {"values": {"auth": "User1", "proof": "wrong"}}}}, "output": {"return": False}}],
            "PASS",
            "authenticate-domain-request-envelope-doc",
            "Wrong credentials are represented as method SUCCESS with a false Boolean result through request envelopes.",
        )
        yield Probe(
            f"Authenticate {envelope} rejects wrong true",
            nested_base + [{"input": {"function": "authenticate", "kwargs": {envelope: {"values": {"auth": "User1", "proof": "wrong"}}}}, "output": {"return": True}}],
            "FAIL",
            "authenticate-domain-request-envelope-doc",
            "Authenticate request envelopes must not hide a true result for a wrong proof.",
        )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"auth": "Admin1", "proof": "new"}}}),
        ("operation target command", {"operation": {"target": {"auth": "Admin1"}, "command": {"proof": "new"}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"auth": "Admin1"}, "command": {"proof": "new"}}}),
    ):
        wrong_kwargs = {
            key: {
                **value,
                "command": {**value.get("command", {}), "proof": "wrong"},
            }
            for key, value in kwargs.items()
        }
        yield Probe(
            f"Authenticate {label} accepts correct proof",
            base + [{"input": {"function": "authenticate", "kwargs": kwargs}, "output": {"return": True}}],
            "PASS",
            "authenticate-operation-envelope-doc",
            "Authenticate operation command envelopes must preserve authority/proof semantics.",
        )
        yield Probe(
            f"Authenticate {label} accepts wrong false",
            base + [{"input": {"function": "authenticate", "kwargs": wrong_kwargs}, "output": {"return": False}}],
            "PASS",
            "authenticate-operation-envelope-doc",
            "Wrong credentials are represented as method SUCCESS with a false Boolean result through operation envelopes.",
        )
        yield Probe(
            f"Authenticate {label} rejects wrong true",
            base + [{"input": {"function": "authenticate", "kwargs": wrong_kwargs}, "output": {"return": True}}],
            "FAIL",
            "authenticate-operation-envelope-doc",
            "Authenticate operation envelopes must not hide a true result for a wrong proof.",
        )
    check_context = activated_locking_context() + [
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
    ]
    check_payload = {"values": {"auth": "User1", "pin": "userpin"}}
    wrong_payload = {"values": {"auth": "User1", "pin": "wrong"}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"checkPIN {shape} values envelope accepts correct PIN",
            check_context + [operation_payload("checkPIN", check_payload, key=shape, output={"return": True})],
            "PASS",
            "authenticate-wrapper",
            "checkPIN values envelopes should preserve authority/PIN semantics.",
        )
        yield Probe(
            f"checkPIN {shape} values envelope rejects status-string result",
            check_context + [operation_payload("checkPIN", check_payload, key=shape, output={"return": "SUCCESS"})],
            "FAIL",
            "authenticate-wrapper",
            "checkPIN lowers to Authenticate and must expose a Boolean result rather than a status string.",
        )
        yield Probe(
            f"checkPIN {shape} values envelope rejects wrong true",
            check_context + [operation_payload("checkPIN", wrong_payload, key=shape, output={"return": True})],
            "FAIL",
            "authenticate-wrapper",
            "Wrong checkPIN values-envelope credentials must not pass.",
        )
        yield Probe(
            f"checkPIN {shape} values envelope rejects false for correct PIN",
            check_context + [operation_payload("checkPIN", check_payload, key=shape, output={"return": False})],
            "FAIL",
            "authenticate-wrapper",
            "Correct checkPIN values-envelope credentials should not be reported as false before lockout.",
        )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"auth": "User1", "pin": "userpin"}}}),
        ("operation target command", {"operation": {"target": {"auth": "User1"}, "command": {"pin": "userpin"}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"auth": "User1"}, "command": {"pin": "userpin"}}}),
    ):
        wrong_kwargs = {
            key: {
                **value,
                "command": {**value.get("command", {}), "pin": "wrong"},
            }
            for key, value in kwargs.items()
        }
        yield Probe(
            f"checkPIN {label} accepts correct PIN",
            check_context + [{"input": {"function": "checkPIN", "kwargs": kwargs}, "output": {"return": True}}],
            "PASS",
            "checkpin-operation-envelope-doc",
            "checkPIN operation command envelopes must preserve authority/PIN semantics.",
        )
        yield Probe(
            f"checkPIN {label} accepts wrong false",
            check_context + [{"input": {"function": "checkPIN", "kwargs": wrong_kwargs}, "output": {"return": False}}],
            "PASS",
            "checkpin-operation-envelope-doc",
            "Wrong checkPIN credentials are represented as method SUCCESS with a false Boolean result through operation envelopes.",
        )
        yield Probe(
            f"checkPIN {label} rejects wrong true",
            check_context + [{"input": {"function": "checkPIN", "kwargs": wrong_kwargs}, "output": {"return": True}}],
            "FAIL",
            "checkpin-operation-envelope-doc",
            "checkPIN operation envelopes must not hide a true result for a wrong PIN.",
        )
    for alias in (
        "verifyPIN",
        "verifyPINCode",
        "verifyPassword",
        "verifyPasscode",
        "checkPINCode",
        "validatePINCode",
        "checkPasscode",
        "validatePasscode",
        "authenticateUser",
        "checkCredential",
        "verifyCredential",
        "validateCredential",
        "checkUserPIN",
        "verifyUserPIN",
        "validateUserPIN",
        "checkUserPassword",
        "verifyUserPassword",
        "validateUserPassword",
        "checkPassphrase",
        "verifyPassphrase",
        "validatePassphrase",
    ):
        yield Probe(
            f"{alias} accepts correct PIN",
            check_context + [{"input": {"function": alias, "kwargs": {"user": "User1", "password": "userpin"}}, "output": {"return": True}}],
            "PASS",
            "authenticate-wrapper",
            f"{alias} is a bounded one-shot credential verification alias for Authenticate/checkPIN.",
        )
        yield Probe(
            f"{alias} rejects wrong PIN success",
            check_context + [{"input": {"function": alias, "kwargs": {"user": "User1", "password": "wrong"}}, "output": {"return": True}}],
            "FAIL",
            "authenticate-wrapper",
            f"{alias} must validate the proof against tracked C_PIN state.",
        )
    yield Probe(
        "checkPIN nested valid false accepts wrong PIN",
        check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"return": {"valid": False}})],
        "PASS",
        "authenticate-wrapper",
        "checkPIN may encode its boolean result under a nested valid field.",
    )
    yield Probe(
        "checkPIN nested valid true accepts correct PIN",
        check_context + [operation_payload("checkPIN", check_payload, key="kwargs", output={"return": {"valid": True}})],
        "PASS",
        "authenticate-wrapper",
        "checkPIN may encode its boolean result under a nested valid field.",
    )
    yield Probe(
        "checkPIN nested valid true rejects wrong PIN",
        check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"return": {"valid": True}})],
        "FAIL",
        "authenticate-wrapper",
        "Nested valid=true must not pass for wrong checkPIN credentials.",
    )
    for result_key in ("matched", "matches", "isVerified", "credentialValid", "pinValid", "authorized"):
        yield Probe(
            f"checkPIN nested {result_key} false accepts wrong PIN",
            check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"return": {result_key: False}})],
            "PASS",
            "authenticate-wrapper",
            "Credential-check wrappers may encode their boolean result under match/verification fields.",
        )
        yield Probe(
            f"checkPIN nested {result_key} true accepts correct PIN",
            check_context + [operation_payload("checkPIN", check_payload, key="kwargs", output={"return": {result_key: True}})],
            "PASS",
            "authenticate-wrapper",
            "Credential-check wrappers may encode their boolean result under match/verification fields.",
        )
        yield Probe(
            f"checkPIN nested {result_key} true rejects wrong PIN",
            check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"return": {result_key: True}})],
            "FAIL",
            "authenticate-wrapper",
            "Credential-check result aliases must not override the tracked PIN truth.",
        )
    yield Probe(
        "checkPIN top-level passed false accepts wrong PIN",
        check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"passed": False})],
        "PASS",
        "authenticate-wrapper",
        "checkPIN false may be encoded under top-level passed:false.",
    )
    yield Probe(
        "checkPIN top-level passed true accepts correct PIN",
        check_context + [operation_payload("checkPIN", check_payload, key="kwargs", output={"passed": True})],
        "PASS",
        "authenticate-wrapper",
        "checkPIN true may be encoded under top-level passed:true.",
    )
    yield Probe(
        "checkPIN top-level passed true rejects wrong PIN",
        check_context + [operation_payload("checkPIN", wrong_payload, key="kwargs", output={"passed": True})],
        "FAIL",
        "authenticate-wrapper",
        "passed:true must not override the tracked PIN truth.",
    )
    datastore_auth_use_context = locking_admin_open() + [
        set_values("", "User1", {5: 1, 15: 1, 16: 0}),
        set_values("", "C_PIN_User1", {3: "userpin", 5: 3}),
        function_record("readAccess", ["User1", 1], {"authAs": ("Admin1", "new")}, True),
        function_record("writeAccess", ["User1", 1], {"authAs": ("Admin1", "new")}, True),
        end_session(),
        function_record("writeData", ["User1", "AABB"], {"authAs": ("User1", "userpin")}, True),
    ]
    yield Probe(
        "writeData authAs consumes User1 Authority Uses before checkPIN",
        datastore_auth_use_context + [function_record("checkPIN", ["User1", "userpin"], return_value=False)],
        "PASS",
        "authenticate-wrapper",
        "Successful wrapper authAs authentication should consume the same Authority.Uses budget as explicit authentication.",
    )
    yield Probe(
        "writeData authAs cannot bypass User1 Authority Limit",
        datastore_auth_use_context + [function_record("checkPIN", ["User1", "userpin"], return_value=True)],
        "FAIL",
        "authenticate-wrapper",
        "After a wrapper operation consumes User1's only allowed use, later checkPIN cannot return true.",
    )
    yield Probe(
        "writeData authAs increments observable User1 Authority Uses",
        datastore_auth_use_context
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            method_record(
                "Get",
                "0000000900030001",
                "Authority",
                SUCCESS,
                required={"Cellblock": [{"startColumn": 16}, {"endColumn": 16}]},
                return_values=[[{"16": 1}]],
            ),
        ],
        "PASS",
        "authenticate-wrapper",
        "Authority.Uses should expose successful implicit authAs authentication on wrapper operations.",
    )
    yield Probe(
        "writeData authAs rejected once Authority Limit already reached",
        locking_admin_open()
        + [
            set_values("", "User1", {5: 1, 15: 1, 16: 1}),
            set_values("", "C_PIN_User1", {3: "userpin", 5: 3}),
            function_record("writeData", ["User1", "AABB"], {"authAs": ("User1", "userpin")}, True),
        ],
        "FAIL",
        "authenticate-wrapper",
        "Wrapper authAs success is impossible once Authority.Uses has reached a nonzero Limit.",
    )
    alias_trylimit_context = activated_locking_context() + [
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin", 5: 1, 7: 1}),
        {"input": {"function": "checkPIN", "kwargs": {"identity": "User1", "passcode": "bad"}}, "output": {"return": False}},
    ]
    yield Probe(
        "checkPIN identity/passcode failure exhausts TryLimit",
        alias_trylimit_context + [{"input": {"function": "checkPIN", "kwargs": {"username": "User1", "secret": "userpin"}}, "output": {"return": False}}],
        "PASS",
        "authenticate-wrapper",
        "identity/passcode and username/secret aliases should feed Authenticate TryLimit state.",
    )
    yield Probe(
        "checkPIN username/secret cannot bypass TryLimit",
        alias_trylimit_context + [{"input": {"function": "checkPIN", "kwargs": {"username": "User1", "secret": "userpin"}}, "output": {"return": True}}],
        "FAIL",
        "authenticate-wrapper",
        "Alias-shaped correct credentials cannot bypass an exhausted TryLimit.",
    )
    for alias in ("validatePIN", "checkPassword", "validatePassword"):
        yield Probe(
            f"{alias} cannot bypass TryLimit",
            alias_trylimit_context + [{"input": {"function": alias, "kwargs": {"username": "User1", "password": "userpin"}}, "output": {"return": True}}],
            "FAIL",
            "authenticate-wrapper",
            f"{alias} should share checkPIN/Authenticate credential and TryLimit semantics.",
        )
    selector_pin_context = locking_admin_open() + [
        set_values("", "User1", {5: 1, 15: 0, 16: 0}),
        set_values("", "C_PIN_User1", {3: "userpin", 5: 10, 7: 0}),
    ]
    for selector_key in ("pinId", "credentialId", "authId", "name"):
        rotated_context = selector_pin_context + [
            {"input": {"function": "changePIN", "kwargs": {selector_key: "User1", "newPin": "rotated", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"changePIN {selector_key} selector updates User1 PIN",
            rotated_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "rotated"}}, "output": {"return": True}}],
            "PASS",
            "authenticate-wrapper",
            f"`{selector_key}` is a bounded credential selector alias for the C_PIN_User1 row.",
        )
        yield Probe(
            f"changePIN {selector_key} selector rejects stale User1 PIN",
            rotated_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "userpin"}}, "output": {"return": True}}],
            "FAIL",
            "authenticate-wrapper",
            f"`{selector_key}` cannot leave the old C_PIN password active after a successful changePIN.",
        )
        yield Probe(
            f"checkPIN {selector_key} selector accepts current User1 PIN",
            selector_pin_context + [{"input": {"function": "checkPIN", "kwargs": {selector_key: "User1", "pin": "userpin"}}, "output": {"return": True}}],
            "PASS",
            "authenticate-wrapper",
            f"`{selector_key}` should authenticate the selected User1 credential.",
        )
        yield Probe(
            f"checkPIN {selector_key} selector rejects wrong User1 PIN",
            selector_pin_context + [{"input": {"function": "checkPIN", "kwargs": {selector_key: "User1", "pin": "bad"}}, "output": {"return": True}}],
            "FAIL",
            "authenticate-wrapper",
            f"`{selector_key}` cannot authenticate with a stale/wrong credential value.",
        )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"auth": "User1", "newPin": "newpin", "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"auth": "User1"}, "command": {"newPin": "newpin", "authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"auth": "User1"}, "command": {"newPin": "newpin", "authAs": ("Admin1", "new")}}}),
    ):
        operation_change_context = locking_admin_open() + [
            set_values("", "User1", {5: 1, 15: 0, 16: 0}),
            set_values("", "C_PIN_User1", {3: "oldpin", 5: 10, 7: 0}),
            {"input": {"function": "changePIN", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"changePIN {label} accepts new PIN",
            operation_change_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "newpin"}}, "output": {"return": True}}],
            "PASS",
            "credential-pin-operation-envelope-doc",
            "changePIN operation command envelopes must update the tracked C_PIN.PIN cell.",
        )
        yield Probe(
            f"changePIN {label} rejects stale old PIN",
            operation_change_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "oldpin"}}, "output": {"return": True}}],
            "FAIL",
            "credential-pin-operation-envelope-doc",
            "Dropping operation target/command fields leaves the old C_PIN credential active.",
        )


def credential_probes() -> Iterable[Probe]:
    context = owned_admin_context() + [
        {
            "input": {"function": "changePIN", "values": {"auth": "SID", "pin": "values-pin", "authAs": ("SID", "new")}},
            "output": {"return": True},
        }
    ]
    yield Probe(
        "changePIN values envelope accepts new credential",
        context + [start_session("0000020500000001", "0000000900000006", "values-pin")],
        "PASS",
        "credential-wrapper",
        "changePIN values envelopes should update the tracked C_PIN credential.",
    )
    yield Probe(
        "changePIN values envelope rejects stale old credential",
        context + [start_session("0000020500000001", "0000000900000006", "new")],
        "FAIL",
        "credential-wrapper",
        "A successful values-envelope PIN change must not leave the prior credential active.",
    )
    cpin_context = owned_admin_context() + [
        {
            "input": {"function": "changePIN", "kwargs": {"cpin": "SID", "newPin": "cpin-pin", "authAs": ("SID", "new")}},
            "output": {"return": True},
        }
    ]
    yield Probe(
        "changePIN cpin alias accepts new credential",
        cpin_context + [start_session("0000020500000001", "0000000900000006", "cpin-pin")],
        "PASS",
        "credential-wrapper",
        "cpin should be treated as a C_PIN selector alias for changePIN.",
    )
    yield Probe(
        "changePIN cpin alias rejects stale old credential",
        cpin_context + [start_session("0000020500000001", "0000000900000006", "new")],
        "FAIL",
        "credential-wrapper",
        "A cpin-selector PIN change must not leave the prior credential active.",
    )
    for alias in (
        "setPIN",
        "updatePIN",
        "putPIN",
        "setPINCode",
        "changePINCode",
        "updatePINCode",
        "putPINCode",
        "changePassword",
        "changePasscode",
        "setPasscode",
        "updatePasscode",
        "putPasscode",
        "setUserPIN",
        "changeUserPIN",
        "updateUserPIN",
        "setUserPINCode",
        "changeUserPINCode",
        "updateUserPINCode",
        "setUserPasscode",
        "changeUserPasscode",
        "updateUserPasscode",
        "setPassword",
        "updatePassword",
        "putPassword",
        "setUserPassword",
        "changeUserPassword",
        "updateUserPassword",
        "putUserPassword",
        "setUserCredential",
        "updateUserCredential",
        "putUserCredential",
        "changeUserCredential",
        "setCredential",
        "updateCredential",
        "putCredential",
        "changeCredential",
    ):
        alias_context = owned_admin_context() + [
            {"input": {"function": alias, "kwargs": {"user": "SID", "password": "next", "authAs": ("SID", "new")}}, "output": {"return": True}}
        ]
        yield Probe(
            f"{alias} updates SID credential",
            alias_context + [start_session("0000020500000001", "0000000900000006", "next")],
            "PASS",
            "credential-wrapper",
            f"{alias} is a high-level C_PIN credential update alias.",
        )
        yield Probe(
            f"{alias} rejects stale SID credential",
            alias_context + [start_session("0000020500000001", "0000000900000006", "new")],
            "FAIL",
            "credential-wrapper",
            f"{alias} must not leave the old SID credential active.",
        )
    for alias in ("setSIDPIN", "changeSIDPIN", "setSIDPasscode", "changeSIDPasscode", "setSIDPassword", "changeSIDPassword"):
        alias_context = owned_admin_context() + [
            {"input": {"function": alias, "kwargs": {"pin": "sid-next", "authAs": ("SID", "new")}}, "output": {"return": True}}
        ]
        yield Probe(
            f"{alias} updates SID credential",
            alias_context + [start_session("0000020500000001", "0000000900000006", "sid-next")],
            "PASS",
            "credential-wrapper",
            f"{alias} has an explicit SID target and should mutate C_PIN_SID.",
        )
        yield Probe(
            f"{alias} rejects stale SID credential",
            alias_context + [start_session("0000020500000001", "0000000900000006", "new")],
            "FAIL",
            "credential-wrapper",
            f"{alias} must not leave the old SID credential active.",
        )
    for alias in ("setAdminPIN", "changeAdminPIN", "setAdminPINCode", "changeAdminPINCode", "setAdminPasscode", "changeAdminPasscode"):
        alias_context = activated_locking_context() + [
            {"input": {"function": alias, "kwargs": {"pin": "admin-next", "authAs": ("Admin1", "new")}}, "output": {"return": True}}
        ]
        yield Probe(
            f"{alias} updates Admin1 credential",
            alias_context + [start_session("0000020500000002", "0000000900010001", "admin-next")],
            "PASS",
            "credential-wrapper",
            f"{alias} has an explicit Admin1 target and should mutate C_PIN_Admin1.",
        )
        yield Probe(
            f"{alias} rejects stale Admin1 credential",
            alias_context + [start_session("0000020500000002", "0000000900010001", "new")],
            "FAIL",
            "credential-wrapper",
            f"{alias} must not leave the old Admin1 credential active.",
        )
    min_context = owned_admin_context() + [
        {
            "input": {"function": "setMinPINLength", "values": {"auth": "SID", "length": 5, "authAs": ("SID", "new")}},
            "output": {"return": True},
        }
    ]
    yield Probe(
        "setMinPINLength values envelope rejects short PIN",
        min_context + [{"input": {"function": "changePIN", "args": ["SID", "1234"], "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": True}}],
        "FAIL",
        "credential-wrapper",
        "setMinPINLength values envelopes should affect later credential policy checks.",
    )
    min_cpin_context = owned_admin_context() + [
        {
            "input": {"function": "setMinPINLength", "kwargs": {"C_PIN": "SID", "length": 5, "authAs": ("SID", "new")}},
            "output": {"return": True},
        }
    ]
    yield Probe(
        "setMinPINLength C_PIN alias rejects short PIN",
        min_cpin_context + [{"input": {"function": "changePIN", "args": ["SID", "1234"], "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": True}}],
        "FAIL",
        "credential-wrapper",
        "C_PIN selector aliases should update credential policy state.",
    )
    minpin_domain_base = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        {"input": {"function": "enableAuthority", "args": ["User1", True], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for envelope in ("credentialRequest", "cpinRequest", "pinRequest", "policyRequest"):
        minpin_payload = {"auth": "User1", "length": 6, "authAs": ("Admin1", "new")}
        minpin_domain_context = minpin_domain_base + [
            {"input": {"function": "setMinPINLength", "kwargs": {envelope: {"values": minpin_payload}}}, "output": {"return": True}},
        ]
        yield Probe(
            f"setMinPINLength {envelope} rejects short User PIN",
            minpin_domain_context + [{"input": {"function": "changePIN", "args": ["User1", "abc"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "credential-policy-envelope-doc",
            "setMinPINLength domain request envelopes must mutate the selected C_PIN minimum length policy.",
        )
        yield Probe(
            f"setMinPINLength {envelope} rejects stale minimum getter",
            minpin_domain_context + [{"input": {"function": "getMinPINLength", "args": ["User1"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"minimumPINLength": 5}}}],
            "FAIL",
            "credential-policy-envelope-doc",
            "setMinPINLength domain request envelopes must update later minimum-length observations.",
        )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"auth": "User1", "length": 6, "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"auth": "User1"}, "command": {"length": 6, "authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"auth": "User1"}, "command": {"length": 6, "authAs": ("Admin1", "new")}}}),
    ):
        minpin_operation_context = minpin_domain_base + [
            {"input": {"function": "setMinPINLength", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setMinPINLength {label} rejects short User PIN",
            minpin_operation_context + [{"input": {"function": "changePIN", "args": ["User1", "abc"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "credential-minpin-operation-envelope-doc",
            "setMinPINLength operation envelopes must mutate the selected C_PIN minimum length policy.",
        )
        yield Probe(
            f"setMinPINLength {label} accepts current minimum getter",
            minpin_operation_context + [{"input": {"function": "getMinPINLength", "args": ["User1"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"minimumPINLength": 6}}}],
            "PASS",
            "credential-minpin-operation-envelope-doc",
            "setMinPINLength operation envelopes should expose the updated C_PIN minimum length through getters.",
        )
        yield Probe(
            f"setMinPINLength {label} rejects stale minimum getter",
            minpin_operation_context + [{"input": {"function": "getMinPINLength", "args": ["User1"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"minimumPINLength": 5}}}],
            "FAIL",
            "credential-minpin-operation-envelope-doc",
            "Dropping operation target/command fields leaves C_PIN._MinPINLength stale.",
        )
    yield Probe(
        "setMinPINLength target without authAs accepts authorized-false failure",
        [
            start_session(ADMIN_SP, write=True),
            {"input": {"function": "setMinPINLength", "args": ["SID", 8]}, "output": {"return": {"authorized": False}}},
        ],
        "PASS",
        "credential-wrapper",
        "The setMinPINLength target C_PIN selector must not be mistaken for wrapper authAs; authorized:false is a failed Set.",
    )
    yield Probe(
        "setMinPINLength target without authAs rejects successful mutation",
        [
            start_session(ADMIN_SP, write=True),
            {"input": {"function": "setMinPINLength", "args": ["SID", 8]}, "output": {"return": True}},
        ],
        "FAIL",
        "credential-wrapper",
        "A target-only setMinPINLength wrapper lacks an authenticating credential and cannot successfully mutate C_PIN policy.",
    )
    trylimit_context = activated_locking_context() + [
        start_session("0000020500000002", "0000000900010001", "new"),
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        {
            "input": {"function": "setTryLimit", "kwargs": {"user": "User1", "tryLimit": 1, "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
        {"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "bad"}}, "output": {"return": False}},
    ]
    yield Probe(
        "setTryLimit user alias exhausts User1 after one failure",
        trylimit_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "userpin"}}, "output": {"return": False}}],
        "PASS",
        "credential-wrapper",
        "setTryLimit should update the C_PIN.TryLimit field used by Authenticate/checkPIN lockout.",
    )
    yield Probe(
        "setTryLimit user alias cannot bypass lockout",
        trylimit_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "userpin"}}, "output": {"return": True}}],
        "FAIL",
        "credential-wrapper",
        "A successful setTryLimit wrapper must make a single failed attempt exhaust TryLimit=1.",
    )
    for label, kwargs in (
        ("policy retryLimit", {"identity": "User1", "policy": {"retryLimit": 1}, "authAs": ("Admin1", "new")}),
        ("limits retryLimit", {"identity": "User1", "limits": {"retryLimit": 1}, "authAs": ("Admin1", "new")}),
        ("security maxRetries", {"identity": "User1", "security": {"maxRetries": 1}, "authAs": ("Admin1", "new")}),
        ("credentialPolicy tryLimit", {"identity": "User1", "credentialPolicy": {"tryLimit": 1}, "authAs": ("Admin1", "new")}),
        ("values policy retryLimit", {"values": {"identity": "User1", "policy": {"retryLimit": 1}, "authAs": ("Admin1", "new")}}),
        ("request limits retryLimit", {"request": {"identity": "User1", "limits": {"retryLimit": 1}}, "authAs": ("Admin1", "new")}),
        ("config attemptLimit", {"identity": "User1", "config": {"attemptLimit": 1}, "authAs": ("Admin1", "new")}),
    ):
        policy_context = activated_locking_context() + [
            start_session("0000020500000002", "0000000900010001", "new"),
            set_values("", "User1", {5: 1}),
            {"input": {"function": "setPIN", "args": ["User1", "userpin"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "setTryLimit", "kwargs": kwargs}, "output": {"return": True}},
            {"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "bad"}}, "output": {"return": False}},
        ]
        yield Probe(
            f"setTryLimit {label} envelope exhausts after one failure",
            policy_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "userpin"}}, "output": {"return": False}}],
            "PASS",
            "credential-wrapper",
            "C_PIN.TryLimit policy envelopes should update the same retry counter used by Authenticate/checkPIN lockout.",
        )
        yield Probe(
            f"setTryLimit {label} envelope rejects lockout bypass",
            policy_context + [{"input": {"function": "checkPIN", "kwargs": {"user": "User1", "pin": "userpin"}}, "output": {"return": True}}],
            "FAIL",
            "credential-wrapper",
            "A policy-envelope TryLimit=1 mutation must make one failed PIN attempt exhaust the credential.",
        )
    deep_counter_context = activated_locking_context() + [
        start_session("0000020500000002", "0000000900010001", "new"),
        set_values("", "User1", {5: 1}),
        {"input": {"function": "setPIN", "args": ["User1", "userpin"], "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {
            "input": {
                "function": "setTryLimit",
                "kwargs": {
                    "request": {
                        "cpinRequest": {
                            "target": {"identity": "User1"},
                            "counter": {"tryLimit": 1},
                            "authAs": ("Admin1", "new"),
                        },
                    },
                },
            },
            "output": {"return": True},
        },
        {
            "input": {
                "function": "checkPIN",
                "kwargs": {
                    "request": {
                        "authRequest": {
                            "target": {"identity": "User1"},
                            "proofRequest": {"pin": "bad"},
                        },
                    },
                },
            },
            "output": {"return": False},
        },
    ]
    deep_good_pin = {
        "input": {
            "function": "checkPIN",
            "kwargs": {
                "operationRequest": {
                    "authenticationRequest": {
                        "target": {"identity": "User1"},
                        "proofRequest": {"pin": "userpin"},
                    },
                },
            },
        },
        "output": {"return": False},
    }
    deep_tries_get = {
        "input": {
            "function": "getPINTries",
            "kwargs": {
                "request": {"cpinRequest": {"target": {"identity": "User1"}, "counter": {}}},
                "authAs": ("Admin1", "new"),
            },
        },
        "output": {"return": {"Tries": 1}},
    }
    yield Probe(
        "deep C_PIN counter envelope locks out after one failed proof",
        deep_counter_context + [deep_good_pin],
        "PASS",
        "cpin-deep-counter-envelope-doc",
        "Deep request/cpinRequest/authRequest envelopes should feed the same C_PIN.TryLimit and Tries state as raw Authenticate.",
    )
    yield Probe(
        "deep C_PIN counter envelope rejects lockout bypass",
        deep_counter_context + [{**deep_good_pin, "output": {"return": True}}],
        "FAIL",
        "cpin-deep-counter-envelope-doc",
        "A wrong proof inside a deep authRequest envelope must increment Tries and exhaust TryLimit=1.",
    )
    yield Probe(
        "deep C_PIN Tries getter reports failed proof count",
        deep_counter_context + [deep_tries_get],
        "PASS",
        "cpin-deep-counter-envelope-doc",
        "Deep getPINTries envelopes should read the C_PIN.Tries value updated by prior failed Authenticate.",
    )
    yield Probe(
        "deep C_PIN Tries getter rejects stale failed proof count",
        deep_counter_context + [{**deep_tries_get, "output": {"return": {"Tries": 0}}}],
        "FAIL",
        "cpin-deep-counter-envelope-doc",
        "Returning stale Tries=0 after one failed proof means the deep Authenticate/Tries state link was lost.",
    )
    get_trylimit_context = activated_locking_context() + [
        start_session("0000020500000002", "0000000900010001", "new"),
        {
            "input": {"function": "setTryLimit", "values": {"identity": "User1", "limit": 1, "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    yield Probe(
        "getTryLimit identity alias reports current limit",
        get_trylimit_context + [{"input": {"function": "getTryLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 1}}}],
        "PASS",
        "credential-wrapper",
        "getTryLimit identity should read the selected C_PIN row rather than an empty object.",
    )
    yield Probe(
        "getTryLimit identity alias rejects stale limit",
        get_trylimit_context + [{"input": {"function": "getTryLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 2}}}],
        "FAIL",
        "credential-wrapper",
        "A stale TryLimit means the getTryLimit selector or setTryLimit mutation was ignored.",
    )
    yield Probe(
        "getTryLimit identity alias rejects Boolean-only limit",
        get_trylimit_context + [{"input": {"function": "getTryLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "credential-wrapper",
        "C_PIN.TryLimit is a uinteger cell, not a literal Boolean success flag.",
    )
    for selector_key in ("pinId", "pin_id", "credentialId", "credential_id", "authId", "name"):
        selector_context = activated_locking_context() + [
            {
                "input": {"function": "setTryLimit", "kwargs": {selector_key: "User1", "tryLimit": 5, "authAs": ("Admin1", "new")}},
                "output": {"return": True},
            },
        ]
        yield Probe(
            f"setTryLimit/getTryLimit {selector_key} selector reports current limit",
            selector_context + [{"input": {"function": "getTryLimit", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 5}}}],
            "PASS",
            "credential-wrapper",
            f"`{selector_key}` is a bounded C_PIN selector alias and must target C_PIN_User1.",
        )
        yield Probe(
            f"setTryLimit/getTryLimit {selector_key} selector rejects stale limit",
            selector_context + [{"input": {"function": "getTryLimit", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 1}}}],
            "FAIL",
            "credential-wrapper",
            f"`{selector_key}` cannot fall back to an untracked/default credential row.",
        )
    for return_key in ("retryLimit", "attemptLimit", "maxAttempts", "pinAttemptLimit"):
        yield Probe(
            f"getTryLimit {return_key} return-field alias reports current limit",
            get_trylimit_context + [{"input": {"function": "getTryLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 1}}}],
            "PASS",
            "credential-wrapper",
            f"`{return_key}` is a bounded C_PIN.TryLimit return-field alias.",
        )
        yield Probe(
            f"getTryLimit {return_key} return-field alias rejects stale limit",
            get_trylimit_context + [{"input": {"function": "getTryLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 2}}}],
            "FAIL",
            "credential-wrapper",
            f"`{return_key}` must compare against the tracked C_PIN.TryLimit value.",
        )
    for alias in ("getRetryLimit", "getUserRetryLimit", "getCredentialRetryLimit", "getMaxRetries", "getUserMaxRetries", "getRetryCountLimit", "getAttemptLimit", "getPINAttemptLimit", "getPinAttemptLimit", "getMaxPINAttempts", "getMaxPinAttempts", "getCredentialAttemptLimit", "getAuthAttemptLimit"):
        yield Probe(
            f"{alias} alias reports current TryLimit",
            get_trylimit_context + [{"input": {"function": alias, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 1}}}],
            "PASS",
            "credential-wrapper",
            f"{alias} should read the same C_PIN.TryLimit cell as getTryLimit.",
        )
        yield Probe(
            f"{alias} alias rejects stale TryLimit",
            get_trylimit_context + [{"input": {"function": alias, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 2}}}],
            "FAIL",
            "credential-wrapper",
            f"{alias} cannot ignore the tracked C_PIN.TryLimit value.",
        )
    get_tries_context = activated_locking_context() + [
        {"input": {"function": "setTries", "kwargs": {"identity": "User1", "Tries": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for alias in ("getUserTries", "getPINAttempts", "getPinAttempts", "getUserAttempts", "getCredentialAttempts", "getRetryCount", "getUserRetryCount"):
        yield Probe(
            f"{alias} alias reports current C_PIN Tries",
            get_tries_context + [{"input": {"function": alias, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 2}}}],
            "PASS",
            "credential-wrapper",
            f"{alias} should read the same bounded C_PIN.Tries column as getTries.",
        )
        yield Probe(
            f"{alias} alias rejects stale C_PIN Tries",
            get_tries_context + [{"input": {"function": alias, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 0}}}],
            "FAIL",
            "credential-wrapper",
            f"{alias} cannot ignore the tracked C_PIN.Tries value.",
        )
    for return_key in ("retryCount", "pinAttempts", "credentialAttempts"):
        yield Probe(
            f"getTries {return_key} return-field alias reports current Tries",
            get_tries_context + [{"input": {"function": "getTries", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 2}}}],
            "PASS",
            "credential-wrapper",
            f"`{return_key}` is a bounded C_PIN.Tries return-field alias.",
        )
        yield Probe(
            f"getTries {return_key} return-field alias rejects stale Tries",
            get_tries_context + [{"input": {"function": "getTries", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 1}}}],
            "FAIL",
            "credential-wrapper",
            f"`{return_key}` must compare against the tracked C_PIN.Tries value.",
        )
    cpin_counter_getter_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        method_record("Set", "0000000B00030001", "C_PIN", optional={"Values": [{"5": 3}, {"6": 1}, {"7": False}]}),
    ]
    for alias, return_key, current, stale in (
        ("getRetryLimit", "TryLimit", 3, 1),
        ("getRetryCount", "Tries", 1, 0),
    ):
        for wrapper_key, wrapper_payload in (
            ("policy", {"auth": "User1", "authAs": ("Admin1", "new")}),
            ("config", {"credentialId": "User1", "authAs": ("Admin1", "new")}),
            ("request", {"credential": {"user": "User1"}, "authAs": ("Admin1", "new")}),
        ):
            yield Probe(
                f"{alias} {wrapper_key} envelope reports current {return_key}",
                cpin_counter_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {return_key: current}}}],
                "PASS",
                "credential-wrapper",
                f"{alias} should recover the selected C_PIN row from a structured {wrapper_key} envelope.",
            )
            yield Probe(
                f"{alias} {wrapper_key} envelope rejects stale {return_key}",
                cpin_counter_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {return_key: stale}}}],
                "FAIL",
                "credential-wrapper",
                f"{alias} must not ignore the credential selector in {wrapper_key}.",
            )
    authority_counter_getter_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "Authority_User1", {15: 2}),
        set_values("", "Authority_User1", {16: 3}),
    ]
    for alias, return_key, current, stale in (
        ("getAuthorityLimit", "Limit", 2, 0),
        ("getAuthorityUses", "Uses", 3, 0),
    ):
        for wrapper_key, wrapper_payload in (
            ("policy", {"identity": "User1", "authAs": ("Admin1", "new")}),
            ("config", {"authorityId": "User1", "authAs": ("Admin1", "new")}),
            ("request", {"target": {"user": "User1"}, "authAs": ("Admin1", "new")}),
            ("operation", {"target": {"identity": "User1"}, "command": {"authAs": ("Admin1", "new")}}),
            ("operationRequest", {"target": {"identity": "User1"}, "command": {"authAs": ("Admin1", "new")}}),
        ):
            tag = "authority-counter-operation-envelope-doc" if wrapper_key in {"operation", "operationRequest"} else "authority-wrapper"
            yield Probe(
                f"{alias} {wrapper_key} envelope reports current {return_key}",
                authority_counter_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {return_key: current}}}],
                "PASS",
                tag,
                f"{alias} should recover the selected Authority row from a structured {wrapper_key} envelope.",
            )
            yield Probe(
                f"{alias} {wrapper_key} envelope rejects stale {return_key}",
                authority_counter_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {return_key: stale}}}],
                "FAIL",
                tag,
                f"{alias} must not ignore the Authority selector in {wrapper_key}.",
            )
    for label, fn, kwargs, getter, current, stale, family in (
        ("TryLimit credentialRequest", "setTryLimit", {"credentialRequest": {"values": {"auth": "User1", "TryLimit": 3, "authAs": ("Admin1", "new")}}}, "getTryLimit", {"TryLimit": 3}, {"TryLimit": 0}, "credential-wrapper"),
        ("TryLimit cpinRequest", "setTryLimit", {"cpinRequest": {"policy": {"user": "User1", "tryLimit": 3}, "authAs": ("Admin1", "new")}}, "getTryLimit", {"TryLimit": 3}, {"TryLimit": 0}, "credential-wrapper"),
        ("TryLimit pinRequest", "setTryLimit", {"pinRequest": {"limits": {"credentialId": "User1", "maxTries": 3}, "authAs": ("Admin1", "new")}}, "getTryLimit", {"TryLimit": 3}, {"TryLimit": 0}, "credential-wrapper"),
        ("Tries limits retryCount", "setTries", {"identity": "User1", "limits": {"retryCount": 2}, "authAs": ("Admin1", "new")}, "getTries", {"Tries": 2}, {"Tries": 0}, "credential-wrapper"),
        ("Tries security pinAttempts", "setTries", {"identity": "User1", "security": {"pinAttempts": 2}, "authAs": ("Admin1", "new")}, "getTries", {"Tries": 2}, {"Tries": 0}, "credential-wrapper"),
        ("Authority Limit policy authLimit", "setAuthLimit", {"identity": "User1", "policy": {"authLimit": 2}, "authAs": ("Admin1", "new")}, "getAuthorityLimit", {"Limit": 2}, {"Limit": 0}, "authority-wrapper"),
        ("Authority Limit limits maxAuthentications", "setAuthLimit", {"identity": "User1", "limits": {"maxAuthentications": 2}, "authAs": ("Admin1", "new")}, "getAuthorityLimit", {"Limit": 2}, {"Limit": 0}, "authority-wrapper"),
        ("Authority Limit authorityRequest", "setAuthLimit", {"authorityRequest": {"values": {"auth": "User1", "Limit": 2, "authAs": ("Admin1", "new")}}}, "getAuthorityLimit", {"Limit": 2}, {"Limit": 0}, "authority-wrapper"),
        ("Authority Limit authRequest", "setAuthLimit", {"authRequest": {"policy": {"identity": "User1", "Limit": 2}, "authAs": ("Admin1", "new")}}, "getAuthorityLimit", {"Limit": 2}, {"Limit": 0}, "authority-wrapper"),
        ("Authority Limit identityRequest", "setAuthLimit", {"identityRequest": {"limits": {"user": "User1", "limit": 2}, "authAs": ("Admin1", "new")}}, "getAuthorityLimit", {"Limit": 2}, {"Limit": 0}, "authority-wrapper"),
        ("Authority Uses policy useCount", "setAuthorityUses", {"identity": "User1", "policy": {"useCount": 2}, "authAs": ("Admin1", "new")}, "getAuthorityUses", {"Uses": 2}, {"Uses": 0}, "authority-wrapper"),
        ("Authority Uses security credentialUses", "setAuthorityUses", {"identity": "User1", "security": {"credentialUses": 2}, "authAs": ("Admin1", "new")}, "getAuthorityUses", {"Uses": 2}, {"Uses": 0}, "authority-wrapper"),
    ):
        counter_context = activated_locking_context() + [{"input": {"function": fn, "kwargs": kwargs}, "output": {"return": True}}]
        yield Probe(
            f"{label} envelope reports current counter",
            counter_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": current}}],
            "PASS",
            family,
            "Structured counter policy envelopes should mutate the same official C_PIN/Authority counter cells as direct setters.",
        )
        yield Probe(
            f"{label} envelope rejects stale counter",
            counter_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": stale}}],
            "FAIL",
            family,
            "A stale counter after a successful policy-envelope setter means the wrapper mutation was ignored.",
        )
    port_envelope_session = [start_session(ADMIN_SP, SID, "new")]
    for wrapper_key, wrapper_payload in (
        ("policy", {"port": "Port2", "locked": True, "authAs": ("SID", "new")}),
        ("config", {"portId": "Port2", "PortLocked": True, "authAs": ("SID", "new")}),
        ("request", {"target": {"port": "Port2"}, "state": {"locked": True}, "authAs": ("SID", "new")}),
        ("request", {"target": {"port": "Port2"}, "command": {"locked": True}, "authAs": ("SID", "new")}),
        ("operation", {"target": {"port": "Port2"}, "portControl": {"locked": True}, "authAs": ("SID", "new")}),
        ("config", {"target": {"port": "Port2"}, "action": {"PortLocked": True}, "authAs": ("SID", "new")}),
        ("portRequest", {"values": {"port": "Port2", "PortLocked": True, "authAs": ("SID", "new")}}),
        ("portRequest", {"target": {"port": "Port2"}, "state": {"locked": True}, "authAs": ("SID", "new")}),
        ("adminRequest", {"port": {"portId": "Port2", "locked": True}, "authAs": ("SID", "new")}),
    ):
        context = port_envelope_session + [{"input": {"function": "setPort", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": True}}]
        yield Probe(
            f"setPort {wrapper_key} envelope updates PortLocked",
            context + [{"input": {"function": "getPort", "kwargs": {"port": "Port2", "authAs": ("SID", "new")}}, "output": {"return": {"PortLocked": True}}}],
            "PASS",
            "port-wrapper",
            f"setPort should flatten {wrapper_key} into the official PortLocked cell.",
        )
        yield Probe(
            f"setPort {wrapper_key} envelope rejects stale PortLocked",
            context + [{"input": {"function": "getPort", "kwargs": {"port": "Port2", "authAs": ("SID", "new")}}, "output": {"return": {"PortLocked": False}}}],
            "FAIL",
            "port-wrapper",
            f"setPort must not ignore PortLocked hidden in {wrapper_key}.",
        )
    port_getter_context = port_envelope_session + [
        {"input": {"function": "setPort", "kwargs": {"port": "Port2", "PortLocked": True, "authAs": ("SID", "new")}}, "output": {"return": True}},
    ]
    for alias, current, stale in (
        ("getPort", {"PortLocked": True}, {"PortLocked": False}),
        ("getPortLocked", True, False),
        ("getPortLocked", {"PortLocked": True}, {"PortLocked": False}),
    ):
        for wrapper_key, wrapper_payload in (
            ("policy", {"port": "Port2", "authAs": ("SID", "new")}),
            ("config", {"portId": "Port2", "authAs": ("SID", "new")}),
            ("request", {"target": {"port": "Port2"}, "authAs": ("SID", "new")}),
            ("operation", {"target": {"port": "Port2"}, "command": {"authAs": ("SID", "new")}}),
            ("operationRequest", {"target": {"port": "Port2"}, "command": {"authAs": ("SID", "new")}}),
            ("command", {"port": "Port2", "authAs": ("SID", "new")}),
            ("action", {"port": "Port2", "authAs": ("SID", "new")}),
            ("portRequest", {"target": {"port": "Port2"}, "authAs": ("SID", "new")}),
            ("adminRequest", {"port": {"portId": "Port2"}, "authAs": ("SID", "new")}),
        ):
            family = "port-operation-envelope-doc" if wrapper_key in {"operation", "operationRequest", "command", "action"} else "port-wrapper"
            yield Probe(
                f"{alias} {wrapper_key} envelope reports current PortLocked",
                port_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": current}}],
                "PASS",
                family,
                f"{alias} should recover the selected Port row from a structured {wrapper_key} envelope.",
            )
            yield Probe(
                f"{alias} {wrapper_key} envelope rejects stale PortLocked",
                port_getter_context + [{"input": {"function": alias, "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": stale}}],
                "FAIL",
                family,
                f"{alias} must not ignore the Port selector in {wrapper_key}.",
            )
    cec_defaults = dict(C_EC_DEFAULT_CURVE_COLUMNS["C_EC_160"])
    wrong_defaults = dict(cec_defaults)
    wrong_defaults[3] = "0"
    row_uid = "0000000D00000160"
    cec_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        method_record(
            "CreateRow",
            "",
            "cec160",
            status=SUCCESS,
            optional={
                "Row": [
                    {"1": "C_EC_160_DocDefault"},
                    {"2": "C_EC_160_DocDefault"},
                    {"8": "11"},
                    {"9": "22"},
                    {"10": "33"},
                    {"11": "SHA_256"},
                    {"12": 0},
                    {"13": "0000000000000000"},
                ]
            },
            return_values=[row_uid],
        ),
    ]

    def cec_get(values: dict[int, Any]) -> dict[str, Any]:
        return method_record(
            "Get",
            row_uid,
            "C_EC_160_DocDefault",
            status=SUCCESS,
            required={"CellBlock": [{"startColumn": 3}, {"endColumn": 7}]},
            return_values=[[{str(column): value} for column, value in sorted(values.items())]],
        )

    yield Probe(
        "C_EC cec160 alias CreateRow accepts documented curve defaults",
        cec_context + [cec_get(cec_defaults)],
        "PASS",
        "credential-wrapper",
        "Short CEC160 aliases should be object names, not fake UID strings.",
    )
    yield Probe(
        "C_EC cec160 alias CreateRow rejects wrong curve defaults",
        cec_context + [cec_get(wrong_defaults)],
        "FAIL",
        "credential-wrapper",
        "A fake-UID parse of CEC160 loses the documented default curve cells.",
    )
    create_row_wrapped = method_record(
        "CreateRow",
        "",
        "C_EC_160Table",
        status=SUCCESS,
        optional={"Row": [{"1": "WrappedRows"}]},
        return_values=[],
    )
    create_row_wrapped["output"]["return_values"] = {"row_uids": [row_uid]}
    yield Probe(
        "CreateRow accepts row_uids wrapped UID-list return",
        owned_admin_context() + [start_session(ADMIN_SP, SID, "new"), create_row_wrapped],
        "PASS",
        "credential-wrapper",
        "CreateRow UID-list returns may be wrapped under row_uids in structured logs.",
    )
    create_row_ace_shorthand = method_record(
        "CreateRow",
        "",
        "C_EC_160Table",
        status=SUCCESS,
        optional={"Row": [{"1": "WrappedRows"}]},
        return_values=[1],
    )
    yield Probe(
        "C_EC CreateRow rejects ACE-shorthand UID-list return",
        owned_admin_context() + [start_session(ADMIN_SP, SID, "new"), create_row_ace_shorthand],
        "FAIL",
        "credential-wrapper",
        "C_EC CreateRow must return the created C_EC row UID, not a bare integer ACE shorthand.",
    )


def authority_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        {
            "input": {"function": "enableAuthority", "values": {"auth": "User1", "enable": False, "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    setauthority_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        {
            "input": {"function": "setAuthority", "kwargs": {"user": "User1", "values": {"Enabled": False}, "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    disableauthority_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
        {
            "input": {"function": "disableAuthority", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    enabled_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        {
            "input": {"function": "enableAuthority", "args": ["User1", True], "kwargs": {"authAs": ("Admin1", "new")}},
            "output": {"return": True},
        },
    ]
    activate_contexts = {
        alias: activated_locking_context()
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            set_values("", "User1", {5: 0}),
            function_record(alias, ["User1"], {"authAs": ("Admin1", "new")}, True),
        ]
        for alias in ("activateAuthority", "activateUser")
    }
    deactivate_contexts = {
        alias: activated_locking_context()
        + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            set_values("", "User1", {5: 1}),
            function_record(alias, ["User1"], {"authAs": ("Admin1", "new")}, True),
        ]
        for alias in ("deactivateAuthority", "deactivateUser")
    }
    yield Probe(
        "enableAuthority values envelope disables User1",
        context + [function_record("checkPIN", ["User1", "userpin"], return_value=True)],
        "FAIL",
        "authority-wrapper",
        "enableAuthority values envelopes should update Authority.Enabled state.",
    )
    payload = {"values": {"auth": "User1", "authAs": ("Admin1", "new")}}
    for shape in ("args1", "kwargs", "params", "request", "call"):
        yield Probe(
            f"getAuthority {shape} values envelope returns disabled state",
            context + [operation_payload("getAuthority", payload, key=shape, output={"return": False})],
            "PASS",
            "authority-wrapper",
            "getAuthority values envelopes should target the selected Authority row.",
        )
        yield Probe(
            f"getAuthority {shape} values envelope rejects stale enabled state",
            context + [operation_payload("getAuthority", payload, key=shape, output={"return": True})],
            "FAIL",
            "authority-wrapper",
            "Stale getAuthority values-envelope output indicates the Authority selector was ignored.",
        )
    yield Probe(
        "setAuthority values envelope disables User1",
        setauthority_context + [function_record("getAuthority", ["User1"], {"obj": "Authority_User1", "authAs": ("Admin1", "new")}, False)],
        "PASS",
        "authority-wrapper",
        "setAuthority is an SDK alias for setting Authority.Enabled and must update tracked authority state.",
    )
    yield Probe(
        "setAuthority values envelope rejects stale enabled state",
        setauthority_context + [function_record("getAuthority", ["User1"], {"obj": "Authority_User1", "authAs": ("Admin1", "new")}, True)],
        "FAIL",
        "authority-wrapper",
        "A setAuthority values envelope must not be ignored when tracking Authority.Enabled.",
    )
    yield Probe(
        "isUserEnabled reflects enabled authority",
        enabled_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "PASS",
        "authority-wrapper",
        "isUserEnabled is a direct Boolean getter alias for Authority.Enabled.",
    )
    yield Probe(
        "isUserEnabled rejects stale disabled value",
        enabled_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
        "FAIL",
        "authority-wrapper",
        "isUserEnabled cannot report false after User1 was enabled.",
    )
    yield Probe(
        "isUserEnabled rejects status-only Boolean payload",
        enabled_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"status": "SUCCESS", "return": "SUCCESS"}}],
        "FAIL",
        "authority-wrapper",
        "A Boolean Authority.Enabled getter must return the actual Boolean value, not only a repeated SUCCESS status token.",
    )
    for alias, activate_context in activate_contexts.items():
        yield Probe(
            f"{alias} enables User1",
            activate_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "PASS",
            "authority-wrapper",
            f"{alias} is a bounded high-level spelling for Authority.Enabled=true.",
        )
        yield Probe(
            f"{alias} rejects stale disabled state",
            activate_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
            "FAIL",
            "authority-wrapper",
            f"{alias} must not leave Authority.Enabled false after a successful wrapper call.",
        )
    for alias, deactivate_context in deactivate_contexts.items():
        yield Probe(
            f"{alias} disables User1",
            deactivate_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
            "PASS",
            "authority-wrapper",
            f"{alias} is a bounded high-level spelling for Authority.Enabled=false.",
        )
        yield Probe(
            f"{alias} rejects stale enabled state",
            deactivate_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "authority-wrapper",
            f"{alias} must not leave Authority.Enabled true after a successful wrapper call.",
        )
    for label, return_value in (
        ("Enabled object", {"Enabled": True}),
        ("enabled object", {"enabled": True}),
        ("isEnabled object", {"isEnabled": True}),
        ("AuthorityEnabled object", {"AuthorityEnabled": True}),
        ("UserEnabled object", {"UserEnabled": True}),
        ("enabledFlag object", {"enabledFlag": True}),
        ("Disabled inverse object", {"Disabled": False}),
        ("AuthorityDisabled inverse object", {"AuthorityDisabled": False}),
    ):
        yield Probe(
            f"getAuthority {label} reflects enabled authority",
            enabled_context + [function_record("getAuthority", ["User1"], {"obj": "Authority_User1", "authAs": ("Admin1", "new")}, return_value)],
            "PASS",
            "authority-wrapper",
            "getAuthority may return a structured Authority.Enabled object instead of a bare boolean.",
        )
    yield Probe(
        "getAuthority Enabled object rejects stale disabled value",
        enabled_context + [function_record("getAuthority", ["User1"], {"obj": "Authority_User1", "authAs": ("Admin1", "new")}, {"Enabled": False})],
        "FAIL",
        "authority-wrapper",
        "Structured getAuthority Enabled fields must still match the tracked Authority.Enabled state.",
    )
    yield Probe(
        "isUserEnabled structured object reflects enabled authority",
        enabled_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"isEnabled": True}}}],
        "PASS",
        "authority-wrapper",
        "isUserEnabled may return an object-shaped boolean result.",
    )
    for getter in ("userEnabled", "getAuthorityEnabled", "isAuthorityEnabled", "authorityEnabled", "getUserState"):
        yield Probe(
            f"{getter} alias reflects enabled authority",
            enabled_context + [function_record(getter, ["User1"], {"authAs": ("Admin1", "new")}, True)],
            "PASS",
            "authority-wrapper",
            f"{getter} should lower to an Authority.Enabled Get.",
        )
        yield Probe(
            f"{getter} alias rejects stale disabled value",
            enabled_context + [function_record(getter, ["User1"], {"authAs": ("Admin1", "new")}, False)],
            "FAIL",
            "authority-wrapper",
            f"{getter} must compare against tracked Authority.Enabled state.",
        )
    authority_enabled_base = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "User1", {5: 1}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
    ]
    for setter in ("setAuthorityEnabled", "setAuthorityState", "setUserEnable", "setUserState"):
        setter_context = authority_enabled_base + [
            function_record(setter, ["User1"], {"authAs": ("Admin1", "new"), "value": False}, True),
        ]
        yield Probe(
            f"{setter} alias disables authority",
            setter_context + [function_record("isUserEnabled", ["User1"], {"authAs": ("Admin1", "new")}, False)],
            "PASS",
            "authority-wrapper",
            f"{setter} should mutate Authority.Enabled through the wrapper state path.",
        )
        yield Probe(
            f"{setter} alias rejects stale enabled authority",
            setter_context + [function_record("isUserEnabled", ["User1"], {"authAs": ("Admin1", "new")}, True)],
            "FAIL",
            "authority-wrapper",
            f"{setter} must not leave Authority.Enabled at the old value.",
        )
    authority_disabled_base = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "User1", {5: 0}),
        set_values("", "C_PIN_User1", {3: "userpin"}),
    ]
    enable_default_context = authority_disabled_base + [
        function_record("enableAuthority", ["User1"], {"authAs": ("Admin1", "new")}, True),
    ]
    yield Probe(
        "enableAuthority default true enables authority",
        enable_default_context + [function_record("isUserEnabled", ["User1"], {"authAs": ("Admin1", "new")}, True)],
        "PASS",
        "authority-wrapper",
        "enableAuthority without an explicit Boolean should default to Authority.Enabled=true.",
    )
    yield Probe(
        "enableAuthority default true rejects stale disabled authority",
        enable_default_context + [function_record("isUserEnabled", ["User1"], {"authAs": ("Admin1", "new")}, False)],
        "FAIL",
        "authority-wrapper",
        "enableAuthority must not leave Authority.Enabled false when it succeeds.",
    )
    authority_request_base = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("", "C_PIN_User1", {3: "userpin"}),
    ]
    for function_name, enabled, expected in (
        ("enableAuthority", True, True),
        ("disableAuthority", False, False),
        ("setAuthorityEnabled", True, True),
        ("setUserEnabled", False, False),
    ):
        for envelope in ("authorityRequest", "authRequest", "identityRequest", "userRequest", "policyRequest"):
            payload = {"authority": "User1", "enabled": enabled, "authAs": ("Admin1", "new")}
            authority_request_context = authority_request_base + [
                {"input": {"function": function_name, "kwargs": {envelope: {"values": payload}}}, "output": {"return": True}},
            ]
            yield Probe(
                f"{function_name} {envelope} updates authority state",
                authority_request_context + [{"input": {"function": "authenticate", "values": {"authority": "User1", "proof": "userpin"}}, "output": {"return": expected}}],
                "PASS",
                "authority-enabled-envelope-doc",
                "Authority state request envelopes must preserve authority selector and Enabled value.",
            )
            yield Probe(
                f"{function_name} {envelope} rejects stale authority state",
                authority_request_context + [{"input": {"function": "authenticate", "values": {"authority": "User1", "proof": "userpin"}}, "output": {"return": not expected}}],
                "FAIL",
                "authority-enabled-envelope-doc",
                "Authority state request envelopes must update later Authenticate results.",
            )
    authority_getter_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("enableAuthority", ["User1", True], {"authAs": ("Admin1", "new")}, True),
    ]
    for function_name in ("getAuthority", "isUserEnabled", "getUserEnabled"):
        for envelope in ("authorityRequest", "authRequest", "identityRequest", "userRequest", "policyRequest", "queryRequest"):
            payload = {"authority": "User1", "authAs": ("Admin1", "new")}
            getter = {"input": {"function": function_name, "kwargs": {envelope: {"values": payload}}}}
            yield Probe(
                f"{function_name} {envelope} returns selected authority state",
                authority_getter_context + [getter | {"output": {"return": True}}],
                "PASS",
                "authority-getter-envelope-doc",
                "Authority getter request envelopes must preserve the selected authority.",
            )
            yield Probe(
                f"{function_name} {envelope} rejects stale selected authority state",
                authority_getter_context + [getter | {"output": {"return": False}}],
                "FAIL",
                "authority-getter-envelope-doc",
                "Authority getter request envelopes must not fall back to the wrong authority.",
            )
    def wrap_authority_getter_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        current: dict[str, Any] = payload
        for key in reversed(chain):
            current = {key: current}
        return current

    for function_name in ("getAuthority", "isUserEnabled", "getUserEnabled"):
        for chain in (
            ("authRequest", "identityRequest", "userRequest", "values"),
            ("request", "authorityRequest", "queryRequest", "values"),
            ("config", "policyRequest", "query", "selector"),
        ):
            kwargs = wrap_authority_getter_payload({"authority": "User1", "authAs": ("Admin1", "new")}, chain)
            getter = {"input": {"function": function_name, "kwargs": kwargs}}
            chain_name = "/".join(chain)
            yield Probe(
                f"{function_name} deep {chain_name} returns selected authority state",
                authority_getter_context + [getter | {"output": {"return": True}}],
                "PASS",
                "authority-getter-deep-envelope-doc",
                "Deep Authority getter request envelopes must preserve the selected authority.",
            )
            yield Probe(
                f"{function_name} deep {chain_name} rejects stale selected authority state",
                authority_getter_context + [getter | {"output": {"return": False}}],
                "FAIL",
                "authority-getter-deep-envelope-doc",
                "Deep Authority getter request envelopes must not fall back to the wrong authority.",
            )
    authority_operation_disabled_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("enableAuthority", ["User1", False], {"authAs": ("Admin1", "new")}, True),
    ]
    for function_name in ("getAuthority", "isUserEnabled", "getUserEnabled", "getAuthorityEnabled"):
        for label, kwargs in (
            ("operation", {"operation": {"target": {"identity": "User1"}, "command": {"authAs": ("Admin1", "new")}}}),
            ("operationRequest", {"operationRequest": {"target": {"identity": "User1"}, "command": {"authAs": ("Admin1", "new")}}}),
            ("command", {"command": {"identity": "User1", "authAs": ("Admin1", "new")}}),
            ("action", {"action": {"identity": "User1", "authAs": ("Admin1", "new")}}),
        ):
            yield Probe(
                f"{function_name} {label} envelope returns disabled authority state",
                authority_operation_disabled_context + [function_record(function_name, [], kwargs, False)],
                "PASS",
                "authority-enabled-operation-envelope-doc",
                "Authority.Enabled getter operation envelopes must preserve the selected Authority row.",
            )
            yield Probe(
                f"{function_name} {label} envelope rejects stale enabled authority state",
                authority_operation_disabled_context + [function_record(function_name, [], kwargs, True)],
                "FAIL",
                "authority-enabled-operation-envelope-doc",
                "Authority.Enabled getter operation envelopes must not fall back to an untracked/default authority.",
            )
    disabled_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("disableAuthority", [], {"auth": "User1", "authAs": ("Admin1", "new")}, True),
    ]
    yield Probe(
        "isUserEnabled raw false reflects disabled authority",
        disabled_context + [{"input": {"function": "isUserEnabled", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
        "PASS",
        "authority-wrapper",
        "Raw false is a successful Boolean getter result when Authority.Enabled is false.",
    )
    for selector_key in ("user", "uid", "identity", "username"):
        yield Probe(
            f"getAuthority kwargs {selector_key} returns disabled state",
            setauthority_context
            + [
                {
                    "input": {"function": "getAuthority", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}},
                    "output": {"return": False},
                }
            ],
            "PASS",
            "authority-wrapper",
            f"getAuthority top-level {selector_key} aliases should select the Authority row.",
        )
        yield Probe(
            f"getAuthority kwargs {selector_key} rejects stale enabled state",
            setauthority_context
            + [
                {
                    "input": {"function": "getAuthority", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}},
                    "output": {"return": True},
                }
            ],
            "FAIL",
            "authority-wrapper",
            f"Stale getAuthority output indicates the top-level {selector_key} selector was ignored.",
        )
    yield Probe(
        "disableAuthority identity disables User1",
        disableauthority_context + [function_record("checkPIN", ["User1", "userpin"], return_value=True)],
        "FAIL",
        "authority-wrapper",
        "disableAuthority is an SDK alias for setting Authority.Enabled false.",
    )
    yield Probe(
        "disableAuthority identity rejects stale getAuthority",
        disableauthority_context
        + [
            {
                "input": {"function": "getAuthority", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}},
                "output": {"return": True},
            }
        ],
        "FAIL",
        "authority-wrapper",
        "Stale getAuthority output indicates the identity selector or disable alias was ignored.",
    )


def session_probes() -> Iterable[Probe]:
    base = owned_admin_context() + [
        {"input": {"function": "startSession", "args": ["AdminSP", "SID", "new"], "kwargs": {"write": True}}, "output": {"return": True}}
    ]
    aliases = ("endSession", "closeSession", "stopSession", "terminateSession", "abortSession", "finishSession", "logout", "logOut", "stopSP", "terminateSP", "disconnectSP")
    for alias in aliases:
        for output in ({"return": True}, {"ok": True}, {"statusCode": 0}):
            raw = {"input": {"function": alias}, "output": output}
            yield Probe(
                f"{alias} {sorted(output)} closes persistent session",
                base + [raw, set_values("0000000B00000001", "C_PIN", {3: "after-close"}, status=SUCCESS)],
                "FAIL",
                "session-wrapper",
            "Successful explicit session termination should close the persistent session.",
        )
    values_session = owned_admin_context() + [
        {
            "input": {"function": "startSession", "values": {"SPID": "0000020500000001", "auth": "SID", "proof": "new", "write": True}},
            "output": {"return": True},
        }
    ]
    yield Probe(
        "startSession values envelope opens persistent session",
        values_session + [set_values("0000000B00000001", "C_PIN", {3: "after-values-session"}, status=SUCCESS)],
        "PASS",
        "session-wrapper",
        "Session wrapper values envelopes should establish the persistent authenticated session.",
    )
    for label, payload in (
        ("policy", {"SPID": ADMIN_SP, "auth": "SID", "proof": "new", "write": True}),
        ("config", {"sp": ADMIN_SP, "identity": "SID", "password": "new", "readWrite": True}),
        ("request", {"session": {"sp": ADMIN_SP}, "credential": {"user": "SID", "proof": "new"}, "write": True}),
    ):
        context = owned_admin_context() + [{"input": {"function": "startSession", "kwargs": {label: payload}}, "output": {"return": True}}]
        yield Probe(
            f"startSession {label} envelope opens persistent session",
            context + [set_values("0000000B00000001", "C_PIN", {3: f"after-{label}-session"}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            "Session policy/config/request envelopes must recover SPID, authority, proof, and Write.",
        )
    yield Probe(
        "startSession values envelope rejects unauthenticated stale status",
        values_session + [set_values("0000000B00000001", "C_PIN", {3: "after-values-session"}, status=NOT_AUTHORIZED)],
        "FAIL",
        "session-wrapper",
        "A successful values-envelope startSession cannot be ignored before later mutating methods.",
    )
    for label, payload in (
        ("values user password readWrite", {"function": "startSession", "values": {"sp": "AdminSP", "user": "SID", "password": "new", "readWrite": True}}),
        ("values identity secret writable", {"function": "openSP", "values": {"sp": "AdminSP", "identity": "SID", "secret": "new", "writable": True}}),
    ):
        context = owned_admin_context() + [{"input": payload, "output": {"return": True}}]
        yield Probe(
            f"startSession {label} opens persistent session",
            context + [set_values("0000000B00000001", "C_PIN", {3: "ssn-ok"}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            "Session wrapper values envelopes should recover authority/challenge aliases before opening the persistent session.",
        )
    for alias in ("protocolReset", "comIdReset", "resetComID", "resetComId", "resetProtocolStack"):
        other_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 1}),
            {"input": {"function": alias, "kwargs": {"comid": 2}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} other ComID preserves open session",
            other_comid + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-preserved"}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            f"{alias} should share ProtocolStackReset ComID-scoped session preservation.",
        )
        same_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 1}),
            {"input": {"function": alias, "kwargs": {"comid": 1}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} same ComID aborts open session",
            same_comid + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-aborted"}, status=SUCCESS)],
            "FAIL",
            "session-wrapper",
            f"{alias} should share ProtocolStackReset ComID-scoped session abort semantics.",
        )
        yield Probe(
            f"startSession {label} rejects ignored-session status",
            context + [set_values("0000000B00000001", "C_PIN", {3: "ssn-no"}, status=NOT_AUTHORIZED)],
            "FAIL",
            "session-wrapper",
            "A successful aliased startSession values envelope cannot be ignored before later mutating methods.",
        )
    for label, payload in (
        (
            "operationRequest session values",
            {
                "operationRequest": {
                    "session": {
                        "values": {
                            "SPID": "AdminSP",
                            "HostSigningAuthority": "SID",
                            "HostChallenge": "new",
                            "Write": True,
                        },
                    },
                },
            },
        ),
        (
            "startupRequest session values",
            {
                "startupRequest": {
                    "session": {
                        "values": {
                            "SPID": "AdminSP",
                            "HostSigningAuthority": "SID",
                            "HostChallenge": "new",
                            "Write": True,
                        },
                    },
                },
            },
        ),
        (
            "operationRequest session target credential options",
            {
                "operationRequest": {
                    "session": {"target": {"SPID": "AdminSP"}},
                    "credential": {"HostSigningAuthority": "SID", "HostChallenge": "new"},
                    "options": {"Write": True},
                },
            },
        ),
        (
            "startupRequest request target auth proof settings",
            {
                "startupRequest": {
                    "request": {"target": {"sp": "AdminSP"}, "auth": {"identity": "SID"}, "proof": {"password": "new"}},
                    "settings": {"readWrite": True},
                },
            },
        ),
        (
            "config session start values",
            {
                "config": {
                    "session": {
                        "start": {
                            "values": {
                                "sp": "AdminSP",
                                "identity": "SID",
                                "secret": "new",
                                "writable": True,
                            },
                        },
                    },
                },
            },
        ),
    ):
        context = owned_admin_context() + [
            {
                "input": {"function": "startSession", **payload},
                "output": {"return": True},
            },
        ]
        yield Probe(
            f"startSession {label} opens persistent session",
            context + [set_values("0000000B00000001", "C_PIN", {3: "pin2"}, status=SUCCESS)],
            "PASS",
            "startsession-deep-envelope-doc",
            "Deep operation/startup request envelopes must recover SPID, authority, proof, and Write.",
        )
        yield Probe(
            f"startSession {label} rejects ignored session",
            context + [set_values("0000000B00000001", "C_PIN", {3: "pin2"}, status=NOT_AUTHORIZED)],
            "FAIL",
            "startsession-deep-envelope-doc",
            "A successful deep startSession envelope cannot be ignored before later mutating methods.",
        )
    for wrapper in ("resetRequest", "protocolResetRequest", "comIdRequest", "sessionRequest"):
        payload = {wrapper: {"values": {"type": "ProtocolStackReset", "ComID": 1}}}
        other_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 2}),
            {"input": {"function": "protocolReset", "kwargs": payload}, "output": {"return": True}},
        ]
        yield Probe(
            f"protocolReset {wrapper} other ComID preserves open session",
            other_comid + [set_values("0000000B00000001", "C_PIN", {3: f"{wrapper}-preserved"}, status=SUCCESS)],
            "PASS",
            "protocol-reset-domain-request-envelope-doc",
            f"{wrapper} must preserve ProtocolStackReset ComID so unrelated ComID sessions remain open.",
        )
        same_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 1}),
            {"input": {"function": "protocolReset", "kwargs": payload}, "output": {"return": True}},
        ]
        yield Probe(
            f"protocolReset {wrapper} same ComID aborts open session",
            same_comid + [set_values("0000000B00000001", "C_PIN", {3: f"{wrapper}-aborted"}, status=SUCCESS)],
            "FAIL",
            "protocol-reset-domain-request-envelope-doc",
            f"{wrapper} must preserve ProtocolStackReset ComID so same-ComID sessions are aborted.",
        )
    for label, payload in (
        ("operation command", {"operation": {"command": {"type": "ProtocolStackReset", "ComID": 1}}}),
        ("operation target command", {"operation": {"target": {"ComID": 1}, "command": {"type": "ProtocolStackReset"}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"ComID": 1}, "command": {"type": "ProtocolStackReset"}}}),
    ):
        other_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 2}),
            {"input": {"function": "protocolReset", "kwargs": payload}, "output": {"return": True}},
        ]
        yield Probe(
            f"protocolReset {label} other ComID preserves open session",
            other_comid + [set_values("0000000B00000001", "C_PIN", {3: "preserved"}, status=SUCCESS)],
            "PASS",
            "protocol-reset-domain-request-envelope-doc",
            f"{label} must preserve ProtocolStackReset ComID so unrelated ComID sessions remain open.",
        )
        same_comid = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new", extra_optional={"ComID": 1}),
            {"input": {"function": "protocolReset", "kwargs": payload}, "output": {"return": True}},
        ]
        yield Probe(
            f"protocolReset {label} same ComID aborts open session",
            same_comid + [set_values("0000000B00000001", "C_PIN", {3: "aborted"}, status=SUCCESS)],
            "FAIL",
            "protocol-reset-domain-request-envelope-doc",
            f"{label} must preserve ProtocolStackReset ComID so same-ComID sessions are aborted.",
        )
    for alias in ("startAdminSP", "openAdminSP", "beginAdminSession", "createAdminSession"):
        context = owned_admin_context() + [{"input": {"function": alias, "kwargs": {"authAs": ("SID", "new"), "write": True}}, "output": {"return": True}}]
        yield Probe(
            f"{alias} opens AdminSP persistent session",
            context + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-ok"}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            f"{alias} should infer AdminSP while preserving SID authentication.",
        )
        yield Probe(
            f"{alias} rejects ignored AdminSP session",
            context + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-no"}, status=NOT_AUTHORIZED)],
            "FAIL",
            "session-wrapper",
            f"A successful {alias} call cannot be ignored before later AdminSP writes.",
        )
    for alias in ("beginSession", "startSPSession", "openSPSession", "beginSPSession", "createSession", "connectSession"):
        context = owned_admin_context() + [{"input": {"function": alias, "kwargs": {"sp": "AdminSP", "authAs": ("SID", "new"), "write": True}}, "output": {"return": True}}]
        yield Probe(
            f"{alias} opens explicit AdminSP persistent session",
            context + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-ok"}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            f"{alias} should lower to StartSession when an explicit SP is supplied.",
        )
        yield Probe(
            f"{alias} rejects ignored explicit AdminSP session",
            context + [set_values("0000000B00000001", "C_PIN", {3: f"{alias}-no"}, status=NOT_AUTHORIZED)],
            "FAIL",
            "session-wrapper",
            f"A successful {alias} call cannot be ignored before later AdminSP writes.",
        )
    for alias in ("startLockingSP", "openLockingSP", "beginLockingSession"):
        context = activated_locking_context() + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "write": True}}, "output": {"return": True}}]
        yield Probe(
            f"{alias} opens LockingSP persistent session",
            context + [set_values(LOCKING_RANGE1, "Locking_Range1", {3: 96}, status=SUCCESS)],
            "PASS",
            "session-wrapper",
            f"{alias} should infer LockingSP while preserving Admin1 authentication.",
        )
        yield Probe(
            f"{alias} rejects ignored LockingSP session",
            context + [set_values(LOCKING_RANGE1, "Locking_Range1", {3: 96}, status=NOT_AUTHORIZED)],
            "FAIL",
            "session-wrapper",
            f"A successful {alias} call cannot be ignored before later LockingSP writes.",
        )
    sync_context = owned_admin_context() + [{"input": {"function": "startSession", "args": ["AdminSP", "SID", "new"], "kwargs": {"write": True}}, "output": {"return": True}}]
    yield Probe(
        "sessionSync wrapper requires open session",
        owned_admin_context() + [{"input": {"function": "sessionSync"}, "output": {"return": True}}],
        "FAIL",
        "session-wrapper",
        "sessionSync should lower to SyncSession and require an existing session.",
    )
    yield Probe(
        "sessionSync wrapper preserves persistent session",
        sync_context + [{"input": {"function": "sessionSync"}, "output": {"return": True}}, set_values("0000000B00000001", "C_PIN", {3: "after-sync"}, status=SUCCESS)],
        "PASS",
        "session-wrapper",
        "sessionSync should not close the persistent session.",
    )
    for label, payload in (
        ("kwargs readOnly", {"function": "startSession", "kwargs": {"sp": "AdminSP", "user": "SID", "password": "new", "readOnly": True}}),
        ("values readonly", {"function": "openSP", "values": {"sp": "AdminSP", "identity": "SID", "secret": "new", "readonly": True}}),
    ):
        context = owned_admin_context() + [{"input": payload, "output": {"return": True}}]
        yield Probe(
            f"startSession {label} opens read-only session",
            context + [set_values("0000000B00000001", "C_PIN", {3: "ssn-readonly"}, status=NOT_AUTHORIZED)],
            "PASS",
            "session-wrapper",
            "readOnly/readonly=true is an inverse alias for official StartSession Write=false.",
        )
        yield Probe(
            f"startSession {label} rejects writable mutation",
            context + [set_values("0000000B00000001", "C_PIN", {3: "ssn-readonly"}, status=SUCCESS)],
            "FAIL",
            "session-wrapper",
            "A read-only wrapper session cannot authorize a later Set mutation.",
        )
    yield Probe(
        "Raw StartSession accepts TPerSessionID response alias",
        activated_locking_context()
        + [
            {
                "input": {
                    "method": {"name": "StartSession", "args": {"required": {"SPID": LOCKING_SP, "Write": 1, "HostSessionID": "7"}, "optional": {}}},
                    "invoking_id": {"uid": "00000000000000FF", "name": "Session Manager UID"},
                },
                "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "TPerSessionID": "1"}},
            }
        ],
        "PASS",
        "session-wrapper",
        "Some wrappers name the returned SP session identifier TPerSessionID; it is the SPSessionID echo payload.",
    )
    sync_session_alias_context = [
        {
            "input": {
                "method": {"name": "StartSession", "args": {"required": {"SPID": ADMIN_SP, "Write": 1, "HostSessionID": "7"}, "optional": {}}},
                "invoking_id": {"uid": "00000000000000FF", "name": "Session Manager UID"},
            },
            "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "TPerSessionID": "9"}},
        }
    ]
    yield Probe(
        "SyncSession accepts TPerSessionID-tracked SPSessionID",
        sync_session_alias_context
        + [
            {
                "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", "SPSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "SPSessionID": "9"}},
            }
        ],
        "PASS",
        "session-wrapper",
        "A StartSession response may name the SP session id TPerSessionID; later SyncSession must match that tracked id.",
    )
    yield Probe(
        "SyncSession rejects empty successful return identifiers",
        sync_session_alias_context
        + [
            {
                "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", "SPSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": []},
            }
        ],
        "FAIL",
        "session-wrapper",
        "Raw SyncSession success returns HostSessionID and SPSessionID rather than an empty result.",
    )
    yield Probe(
        "SyncSession rejects mismatched TPerSessionID-tracked SPSessionID",
        sync_session_alias_context
        + [
            {
                "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", "SPSessionID": "8"}},
                "output": {"status_codes": SUCCESS, "return_values": []},
            }
        ],
        "FAIL",
        "session-wrapper",
        "When SyncSession supplies an SPSessionID it must match the id returned by the preceding StartSession exchange.",
    )
    for sp_id_key in ("TPerSessionID", "tperSessionID", "TPerSID"):
        yield Probe(
            f"SyncSession accepts matching {sp_id_key} alias",
            sync_session_alias_context
            + [
                {
                    "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", sp_id_key: "9"}},
                    "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "SPSessionID": "9"}},
                }
            ],
            "PASS",
            "session-wrapper",
            f"{sp_id_key} is an alias for the TPer/SP session identifier and must match the StartSession response.",
        )
        yield Probe(
            f"SyncSession rejects mismatched {sp_id_key} alias",
            sync_session_alias_context
            + [
                {
                    "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", sp_id_key: "8"}},
                    "output": {"status_codes": SUCCESS, "return_values": []},
                }
            ],
            "FAIL",
            "session-wrapper",
            f"{sp_id_key} must be validated as the same SP session identifier as SPSessionID.",
        )
    host_alias_context = [
        {
            "input": {
                "method": {"name": "StartSession", "args": {"required": {"SPID": ADMIN_SP, "Write": 1, "HostSID": "7"}, "optional": {}}},
                "invoking_id": {"uid": "00000000000000FF", "name": "Session Manager UID"},
            },
            "output": {"status_codes": SUCCESS, "return_values": {"HostSID": "7", "SPSessionID": "9"}},
        }
    ]
    yield Probe(
        "StartSession rejects mismatched HostSID echo alias",
        [
            {
                "input": {
                    "method": {"name": "StartSession", "args": {"required": {"SPID": ADMIN_SP, "Write": 1, "HostSID": "7"}, "optional": {}}},
                    "invoking_id": {"uid": "00000000000000FF", "name": "Session Manager UID"},
                },
                "output": {"status_codes": SUCCESS, "return_values": {"HostSID": "8", "SPSessionID": "9"}},
            }
        ],
        "FAIL",
        "session-wrapper",
        "HostSID is a HostSessionID alias and a successful StartSession response must echo the requested value.",
    )
    yield Probe(
        "SyncSession rejects mismatched HostSID-tracked host id",
        host_alias_context
        + [
            {
                "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSID": "8", "SPSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": []},
            }
        ],
        "FAIL",
        "session-wrapper",
        "SyncSession must validate HostSID as the same host session identifier as HostSessionID.",
    )
    for label, sync_input in (
        ("syncSession kwargs", {"function": "syncSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}),
        ("syncSession positional", {"function": "syncSession", "args": [7, 8]}),
        ("resyncSession kwargs", {"function": "resyncSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}),
        ("refreshSession kwargs", {"function": "refreshSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}),
    ):
        yield Probe(
            f"{label} rejects mismatched identifiers",
            host_alias_context + [{"input": sync_input, "output": {"return": True}}],
            "FAIL",
            "session-wrapper",
            "High-level sync-session wrappers must carry supplied Host/SP session identifiers into SyncSession validation.",
        )
    for function_name in ("syncSession", "endSession", "startTrustedSession", "startTlsSession"):
        for label, payload in (
            ("policy", {"HostSessionID": "7", "SPSessionID": "9"}),
            ("config", {"HostSID": "7", "TPerSessionID": "9"}),
            ("request", {"session": {"HostSessionID": "7", "SPSessionID": "9"}}),
            ("syncSessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "9"}}),
            ("sessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "9"}}),
            ("spSessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "9"}}),
        ):
            yield Probe(
                f"{function_name} {label} envelope accepts matching identifiers",
                host_alias_context + [{"input": {"function": function_name, "kwargs": {label: payload}}, "output": {"return": True}}],
                "PASS",
                "session-id-envelope-doc",
                "Session-control policy/config/request envelopes must preserve HostSessionID and SPSessionID aliases.",
            )
        for label, payload in (
            ("policy", {"HostSessionID": "7", "SPSessionID": "8"}),
            ("config", {"HostSID": "7", "TPerSessionID": "8"}),
            ("request", {"session": {"HostSessionID": "7", "SPSessionID": "8"}}),
            ("syncSessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "8"}}),
            ("sessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "8"}}),
            ("spSessionRequest", {"values": {"HostSessionID": "7", "SPSessionID": "8"}}),
        ):
            yield Probe(
                f"{function_name} {label} envelope rejects mismatched identifiers",
                host_alias_context + [{"input": {"function": function_name, "kwargs": {label: payload}}, "output": {"return": True}}],
                "FAIL",
                "session-id-envelope-doc",
                "Hidden session identifiers must reach the same validation path as direct Session Manager calls.",
            )
    for function_name in ("startTrustedSession", "startTlsSession"):
        yield Probe(
            f"{function_name} wrapper accepts matching identifiers",
            host_alias_context + [{"input": {"function": function_name, "kwargs": {"HostSessionID": "7", "SPSessionID": "9"}}, "output": {"return": True}}],
            "PASS",
            "session-wrapper",
            f"High-level {function_name} wrappers should map to the corresponding session-control method.",
        )
        yield Probe(
            f"{function_name} wrapper rejects mismatched identifiers",
            host_alias_context + [{"input": {"function": function_name, "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}, "output": {"return": True}}],
            "FAIL",
            "session-wrapper",
            f"High-level {function_name} wrappers must validate supplied Host/SP session identifiers.",
        )
    for function_name in ("beginTrusted", "trustedStart", "openTrustedSession", "beginTLS", "tlsStart", "openTlsSession"):
        yield Probe(
            f"{function_name} wrapper accepts matching identifiers",
            host_alias_context + [{"input": {"function": function_name, "kwargs": {"HostSessionID": "7", "SPSessionID": "9"}}, "output": {"return": True}}],
            "PASS",
            "session-wrapper",
            f"High-level {function_name} should map to the corresponding trusted/TLS session-control method.",
        )
        yield Probe(
            f"{function_name} wrapper rejects mismatched identifiers",
            host_alias_context + [{"input": {"function": function_name, "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}, "output": {"return": True}}],
            "FAIL",
            "session-wrapper",
            f"High-level {function_name} must validate supplied Host/SP session identifiers.",
        )
    for label, start_input, start_output in (
        (
            "startSession positional HostSessionID",
            {"function": "startSession", "args": [ADMIN_SP, "Anybody", None, True, 7]},
            {"return": {"HostSessionID": "8", "SPSessionID": "9"}},
        ),
        (
            "startSession HostSID alias",
            {"function": "startSession", "kwargs": {"SPID": ADMIN_SP, "Write": 1, "HostSID": "7"}},
            {"return": {"HostSID": "8", "SPSessionID": "9"}},
        ),
    ):
        yield Probe(
            f"{label} rejects mismatched echo",
            [{"input": start_input, "output": start_output}],
            "FAIL",
            "session-wrapper",
            "High-level StartSession wrappers must echo requested HostSessionID aliases on success.",
        )
    for wrapper in ("startSessionRequest", "sessionRequest", "spSessionRequest", "securityProviderRequest"):
        payload = {
            wrapper: {
                "values": {
                    "SPID": ADMIN_SP,
                    "Write": 1,
                    "HostSessionID": "7",
                    "HostSigningAuthority": SID,
                    "HostChallenge": "new",
                }
            }
        }
        yield Probe(
            f"StartSession {wrapper} preserves requested HostSessionID echo",
            [{"input": {"function": "startSession", "kwargs": payload}, "output": {"return": {"required": {"HostSessionID": "7", "SPSessionID": "1"}, "optional": {}}}}],
            "PASS",
            "startsession-domain-request-envelope-doc",
            f"{wrapper} must preserve SPID, Write, authority, challenge, and HostSessionID before lowering to StartSession.",
        )
        yield Probe(
            f"StartSession {wrapper} rejects mismatched HostSessionID echo",
            [{"input": {"function": "startSession", "kwargs": payload}, "output": {"return": {"required": {"HostSessionID": "8", "SPSessionID": "1"}, "optional": {}}}}],
            "FAIL",
            "startsession-domain-request-envelope-doc",
            f"{wrapper} must preserve requested HostSessionID so a mismatched StartSession response is rejected.",
        )
    yield Probe(
        "EndSession explicit Session Manager target accepts matching identifiers",
        host_alias_context
        + [
            {
                "input": {"method": {"name": "EndSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSID": "7", "TPerSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": []},
            }
        ],
        "PASS",
        "session-wrapper",
        "EndSession is treated consistently with CloseSession when it targets the Session Manager and identifiers match.",
    )
    yield Probe(
        "Raw EndSession rejects list-wrapped Boolean result payload",
        host_alias_context
        + [
            {
                "input": {"method": {"name": "EndSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSID": "7", "TPerSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": [True]},
            }
        ],
        "FAIL",
        "session-wrapper",
        "Raw EndSession closes the session with an empty result, not a Boolean payload list.",
    )
    yield Probe(
        "EndSession explicit Session Manager target rejects mismatched identifiers",
        host_alias_context
        + [
            {
                "input": {"method": {"name": "EndSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSID": "7", "TPerSessionID": "8"}},
                "output": {"status_codes": SUCCESS, "return_values": []},
            }
        ],
        "FAIL",
        "session-wrapper",
        "EndSession must validate supplied Host/SP session identifiers before closing the open session.",
    )
    yield Probe(
        "disconnectSession wrapper accepts matching identifiers",
        host_alias_context + [{"input": {"function": "disconnectSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "9"}}, "output": {"return": True}}],
        "PASS",
        "session-wrapper",
        "disconnectSession should lower to EndSession and validate matching tracked identifiers.",
    )
    yield Probe(
        "disconnectSession wrapper rejects mismatched identifiers",
        host_alias_context + [{"input": {"function": "disconnectSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}, "output": {"return": True}}],
        "FAIL",
        "session-wrapper",
        "disconnectSession must carry Host/SP identifiers into EndSession validation.",
    )
    for label, close_input in (
        ("endSession kwargs", {"function": "endSession", "kwargs": {"HostSessionID": "7", "SPSessionID": "8"}}),
        ("closeSession positional", {"function": "closeSession", "args": [7, 8]}),
        ("endSession alias kwargs", {"function": "endSession", "kwargs": {"HostSID": "7", "TPerSessionID": "8"}}),
    ):
        yield Probe(
            f"Mismatched {label} wrapper does not close tracked session",
            host_alias_context
            + [
                {"input": close_input, "output": {"return": True}},
                {
                    "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSID": "7", "SPSessionID": "9"}},
                    "output": {"status_codes": SUCCESS, "return_values": {"HostSID": "7", "SPSessionID": "9"}},
                },
            ],
            "PASS",
            "session-wrapper",
            "High-level close-session wrappers must carry supplied Host/SP/TPer session identifiers into the same validation path as raw EndSession.",
        )
    end_session_wrong_id_context = [
        {
            "input": {
                "method": {"name": "StartSession", "args": {"required": {"SPID": ADMIN_SP, "Write": 1, "HostSessionID": "7"}, "optional": {}}},
                "invoking_id": {"uid": "00000000000000FF", "name": "Session Manager UID"},
            },
            "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "SPSessionID": "9"}},
        },
        {
            "input": {"method": {"name": "EndSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", "SPSessionID": "8"}},
            "output": {"status_codes": SUCCESS, "return_values": []},
        },
    ]
    yield Probe(
        "Mismatched EndSession context does not close tracked session",
        end_session_wrong_id_context
        + [
            {
                "input": {"method": {"name": "SyncSession"}, "invoking_id": {"uid": "00000000000000FF"}, "required": {"HostSessionID": "7", "SPSessionID": "9"}},
                "output": {"status_codes": SUCCESS, "return_values": {"HostSessionID": "7", "SPSessionID": "9"}},
            }
        ],
        "PASS",
        "session-wrapper",
        "A context EndSession whose supplied session id does not match the tracked open session must not close that session.",
    )


def wrapper_alias_probe_batch() -> Iterable[Probe]:
    datastore_alias_context = locking_admin_open() + [
        {"input": {"function": "putData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 2, "data": "AABBCC"}}, "output": {"return": True}},
    ]
    yield Probe(
        "putData/getData aliases preserve sparse byte window",
        datastore_alias_context + [{"input": {"function": "getData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 3, "length": 2}}, "output": {"return": "BBCC"}}],
        "PASS",
        "datastore-wrapper",
        "DataStore spelling aliases must share the same byte-table state as writeData/readData.",
    )
    yield Probe(
        "putData/getData aliases reject shifted byte window",
        datastore_alias_context + [{"input": {"function": "getData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 3, "length": 2}}, "output": {"return": "AABB"}}],
        "FAIL",
        "datastore-wrapper",
        "Ignoring getData length/offset aliases permits stale shifted payloads.",
    )
    for alias in ("readData", "readDatastore", "getData"):
        yield Probe(
            f"{alias} rejects Boolean-only DataStore read",
            locking_admin_open() + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 0, "length": 2}}, "output": {"return": True}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a DataStore byte-table read and cannot be satisfied by a literal Boolean wrapper return.",
        )
        yield Probe(
            f"{alias} rejects nested Boolean DataStore read",
            locking_admin_open() + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 0, "length": 2}}, "output": {"return": {"Data": True}}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a DataStore byte-table read and cannot be satisfied by a Boolean flag under a byte-data key.",
        )
        yield Probe(
            f"{alias} rejects list-wrapped Boolean DataStore read",
            locking_admin_open() + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 0, "length": 2}}, "output": {"return": [True]}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a DataStore byte-table read and cannot be satisfied by a Boolean flag inside a payload list.",
        )
    byte_repr_context = locking_admin_open() + [
        {"input": {"function": "writeDataStore", "kwargs": {"authAs": ("Admin1", "new"), "offset": 4, "bytes": "AABBCC"}}, "output": {"return": True}},
    ]
    for label, current_payload, stale_payload in (
        ("hex-string-list", ["AA", "BB", "CC"], ["00", "00", "00"]),
        ("prefixed-hex-string-list", ["0xAA", "0xBB", "0xCC"], ["0x00", "0x00", "0x00"]),
        ("prefixed-hex-string", "0xAABBCC", "0x000000"),
    ):
        yield Probe(
            f"readDataStore accepts {label} byte payload",
            byte_repr_context + [{"input": {"function": "readDataStore", "kwargs": {"authAs": ("Admin1", "new"), "offset": 4, "length": 3}}, "output": {"return": current_payload}}],
            "PASS",
            "datastore-wrapper",
            f"DataStore byte reads may return the same byte window as {label}.",
        )
        yield Probe(
            f"readDataStore rejects stale {label} byte payload",
            byte_repr_context + [{"input": {"function": "readDataStore", "kwargs": {"authAs": ("Admin1", "new"), "offset": 4, "length": 3}}, "output": {"return": stale_payload}}],
            "FAIL",
            "datastore-wrapper",
            f"DataStore byte-return representation must still compare against tracked bytes.",
        )
    datastore_write_alias_context = locking_admin_open() + [
        {"input": {"function": "storeData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 4, "data": "AABB"}} , "output": {"return": True}},
    ]
    yield Probe(
        "storeData alias feeds raw DataStore Get",
        datastore_write_alias_context
        + [method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 4}, {"endRow": 5}]}, return_values="AABB")],
        "PASS",
        "datastore-wrapper",
        "DataStore write spelling aliases should mutate the same byte-table state.",
    )
    yield Probe(
        "storeData alias rejects stale raw DataStore Get",
        datastore_write_alias_context
        + [method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 4}, {"endRow": 5}]}, return_values="0000")],
        "FAIL",
        "datastore-wrapper",
        "Ignoring storeData leaves stale byte-table observations over-accepted.",
    )
    for alias in (
        "storeBytes",
        "setBytes",
        "writeDS",
        "writeDataStoreBytes",
        "putDataStore",
        "setDataStore",
        "updateDataStore",
        "storeDataStore",
        "writeUserData",
        "writeUserDataStore",
        "setUserDataStore",
        "putUserDataStore",
        "storeUserDataStore",
        "saveUserDataStore",
        "putUserData",
        "writeDSBytes",
        "storeDS",
    ):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "bytes": "AABB"}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias feeds readData",
            context + [{"input": {"function": "readData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": "AABB"}}],
            "PASS",
            "datastore-wrapper",
            f"{alias} should mutate the shared DataStore byte-table state.",
        )
        yield Probe(
            f"{alias} alias rejects stale readData",
            context + [{"input": {"function": "readData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": "0000"}}],
            "FAIL",
            "datastore-wrapper",
            f"Ignoring {alias} leaves stale DataStore bytes over-accepted.",
        )
    for alias in (
        "getBytes",
        "readBytes",
        "readDS",
        "fetchData",
        "loadData",
        "readDataStoreBytes",
        "getDataStore",
        "loadDataStore",
        "readUserData",
        "readUserDataStore",
        "getUserDataStore",
        "fetchUserDataStore",
        "loadUserDataStore",
        "getUserData",
        "readDSBytes",
        "loadDS",
    ):
        context = locking_admin_open() + [
            {"input": {"function": "writeData", "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "bytes": "AABB"}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias reads DataStore bytes",
            context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": "AABB"}}],
            "PASS",
            "datastore-wrapper",
            f"{alias} should compare the same DataStore byte window as readData.",
        )
        yield Probe(
            f"{alias} alias rejects stale read bytes",
            context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": "0000"}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} cannot ignore tracked DataStore bytes.",
        )
        yield Probe(
            f"{alias} alias rejects Boolean-only DataStore read",
            context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": True}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a byte-table read and cannot be satisfied by a literal Boolean wrapper return.",
        )
        yield Probe(
            f"{alias} alias rejects nested Boolean DataStore read",
            context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": {"Data": True}}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a byte-table read and cannot be satisfied by a Boolean flag under a byte-data key.",
        )
        yield Probe(
            f"{alias} alias rejects list-wrapped Boolean DataStore read",
            context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "offset": 10, "length": 2}}, "output": {"return": [True]}}],
            "FAIL",
            "datastore-wrapper",
            f"{alias} is a byte-table read and cannot be satisfied by a Boolean flag inside a payload list.",
        )

    yield Probe(
        "getLockingInfo rejects Boolean-only geometry",
        locking_admin_open() + [function_record("getLockingInfo", [], {}, True)],
        "FAIL",
        "locking-wrapper",
        "LockingInfo Get returns geometry/read-only fields, not a literal Boolean success flag.",
    )
    yield Probe(
        "getLockingInfo rejects nested Boolean geometry payload",
        locking_admin_open() + [function_record("getLockingInfo", [], {}, {"Data": True})],
        "FAIL",
        "locking-wrapper",
        "LockingInfo Get returns named geometry/read-only fields, not a Boolean hidden under an unrelated payload key.",
    )

    locking_alias_context = activated_locking_context() + [
        {"input": {"function": "configureRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 40, "length": 4, "readLockEnabled": True, "writeLockEnabled": True}}, "output": {"return": True}},
        {"input": {"function": "lockRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
    ]
    yield Probe(
        "configureRange/lockRange aliases block host write",
        locking_alias_context + [host_write_status(NOT_AUTHORIZED, "AA", "41 ~ 41")],
        "PASS",
        "locking-wrapper",
        "Locking range wrapper aliases should update RangeStart/RangeLength and ReadLocked/WriteLocked state.",
    )
    yield Probe(
        "configureRange/lockRange aliases reject host write success",
        locking_alias_context + [host_write_status(SUCCESS, "AA", "41 ~ 41")],
        "FAIL",
        "locking-wrapper",
        "A locked configured range must not allow a successful host write inside its LBA window.",
    )
    failed_lock_range_context = activated_locking_context() + [
        {"input": {"function": "configureRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 40, "length": 4, "writeLockEnabled": True}}, "output": {"return": True}},
        {"input": {"function": "lockRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"ok": False}}},
    ]
    yield Probe(
        "failed lockRange preserves unlocked host write",
        failed_lock_range_context + [host_write_status(SUCCESS, "AA", "41 ~ 41")],
        "PASS",
        "locking-wrapper",
        "Failure-shaped range-lock wrappers should not mutate WriteLocked state.",
    )
    yield Probe(
        "failed lockRange rejects phantom host-write denial",
        failed_lock_range_context + [host_write_status(NOT_AUTHORIZED, "AA", "41 ~ 41")],
        "FAIL",
        "locking-wrapper",
        "A failed lockRange wrapper cannot be applied as a successful Locking.Set.",
    )
    failed_configure_range_context = activated_locking_context() + [
        {"input": {"function": "configureRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 40, "length": 4, "writeLockEnabled": True, "writeLocked": True}}, "output": {"return": {"ok": False}}},
    ]
    yield Probe(
        "failed configureRange preserves host write",
        failed_configure_range_context + [host_write_status(SUCCESS, "AA", "40 ~ 40")],
        "PASS",
        "locking-wrapper",
        "Failure-shaped configureRange wrappers should not mutate geometry or lock-cell state.",
    )
    yield Probe(
        "failed configureRange rejects phantom host-write denial",
        failed_configure_range_context + [host_write_status(NOT_AUTHORIZED, "AA", "40 ~ 40")],
        "FAIL",
        "locking-wrapper",
        "A failed configureRange wrapper cannot be applied as a successful Locking.Set.",
    )
    for alias in (
        "configureLockingRange",
        "configRange",
        "setRangeGeometry",
        "updateRangeGeometry",
        "setRangeAttributes",
        "updateRangeAttributes",
        "setRangeWindow",
        "setBandConfig",
        "updateBandConfig",
        "setLockingBand",
        "updateLockingBand",
        "configureLockingBand",
        "setBandGeometry",
        "updateBandGeometry",
        "setBandAttributes",
        "updateBandAttributes",
        "setBandWindow",
    ):
        alias_context = activated_locking_context() + [
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 222, "length": 6, "readLockEnabled": True, "writeLockEnabled": True}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates range geometry",
            alias_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 222, "RangeLength": 6, "ReadLockEnabled": True, "WriteLockEnabled": True})],
            "PASS",
            "locking-wrapper",
            f"{alias} is a bounded Locking Range/Band configuration alias and should mutate tracked geometry.",
        )
        yield Probe(
            f"{alias} alias rejects stale range geometry",
            alias_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {"RangeStart": 0, "RangeLength": 0, "ReadLockEnabled": False, "WriteLockEnabled": False})],
            "FAIL",
            "locking-wrapper",
            f"Ignoring {alias} leaves stale Locking range state over-accepted.",
        )
    range_alias_get_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 222, "length": 6, "readLockEnabled": True, "writeLockEnabled": True}}, "output": {"return": True}},
    ]
    for alias in (
        "queryLockingRange",
        "fetchLockingRange",
        "readRangeConfig",
        "fetchRangeConfig",
        "readBand",
        "fetchBand",
        "queryBand",
        "getBandConfig",
        "readBandConfig",
        "fetchBandConfig",
        "getRangeGeometry",
        "readRangeGeometry",
        "getBandGeometry",
        "readBandGeometry",
        "getRangeAttributes",
        "getBandAttributes",
    ):
        yield Probe(
            f"{alias} alias reads range geometry",
            range_alias_get_context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"RangeStart": 222, "RangeLength": 6, "ReadLockEnabled": True, "WriteLockEnabled": True}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should compare the same Locking range state as getRange.",
        )
        yield Probe(
            f"{alias} alias rejects stale range geometry",
            range_alias_get_context + [{"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"RangeStart": 0, "RangeLength": 0, "ReadLockEnabled": False, "WriteLockEnabled": False}}}],
            "FAIL",
            "locking-wrapper",
            f"{alias} cannot ignore tracked Locking range state.",
        )
    set_write_lock_enabled_context = activated_locking_context() + [
        {"input": {"function": "setRangeStart", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 40}}, "output": {"return": True}},
        {"input": {"function": "setRangeLength", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 4}}, "output": {"return": True}},
        {"input": {"function": "setWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
        {"input": {"function": "setWriteLocked", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
    ]
    yield Probe(
        "setWriteLockEnabled alias blocks host write",
        set_write_lock_enabled_context + [host_write_status(NOT_AUTHORIZED, "AA", "40 ~ 40")],
        "PASS",
        "locking-wrapper",
        "Direct WriteLockEnabled setter aliases should update the same Locking state as enableWriteLock.",
    )
    yield Probe(
        "setWriteLockEnabled alias rejects host write success",
        set_write_lock_enabled_context + [host_write_status(SUCCESS, "AA", "40 ~ 40")],
        "FAIL",
        "locking-wrapper",
        "A range with WriteLockEnabled and WriteLocked true cannot allow host writes.",
    )
    bool_value_getter_context = activated_locking_context() + [
        {"input": {"function": "setWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
        {"input": {"function": "setReadLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": False}}, "output": {"return": True}},
    ]
    for getter, expected_value, stale_value in (
        ("getWriteLockEnabled", True, False),
        ("isWriteLockEnabled", True, False),
        ("isWriteLockingEnabled", True, False),
        ("writeLockEnabled", True, False),
        ("writeLockingEnabled", True, False),
        ("getRangeWriteLockEnabled", True, False),
        ("isRangeWriteLockEnabled", True, False),
        ("getRangeWriteLockingEnabled", True, False),
        ("isRangeWriteLockingEnabled", True, False),
        ("getReadLockEnabled", False, True),
        ("isReadLockEnabled", False, True),
        ("isReadLockingEnabled", False, True),
        ("readLockEnabled", False, True),
        ("readLockingEnabled", False, True),
        ("getRangeReadLockEnabled", False, True),
        ("isRangeReadLockEnabled", False, True),
        ("getRangeReadLockingEnabled", False, True),
        ("isRangeReadLockingEnabled", False, True),
    ):
        yield Probe(
            f"{getter} value-field return matches tracked boolean",
            bool_value_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"value": expected_value}}}],
            "PASS",
            "locking-wrapper",
            "`value` is a common single-result wrapper field and must be compared against the tracked Locking boolean cell.",
        )
        yield Probe(
            f"{getter} value-field rejects stale boolean",
            bool_value_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"value": stale_value}}}],
            "FAIL",
            "locking-wrapper",
            "`value` return fields cannot bypass tracked Locking boolean state.",
        )
    bool_locked_getter_context = activated_locking_context() + [
        {"input": {"function": "setReadLocked", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
        {"input": {"function": "setWriteLocked", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": False}}, "output": {"return": True}},
    ]
    for getter, expected_value, stale_value in (
        ("getReadLocked", True, False),
        ("getReadLock", True, False),
        ("isReadLocked", True, False),
        ("readLocked", True, False),
        ("getRangeReadLocked", True, False),
        ("isRangeReadLocked", True, False),
        ("isReadLockSet", True, False),
        ("getReadLockState", True, False),
        ("getRangeReadLockState", True, False),
        ("readLockState", True, False),
        ("rangeReadLockState", True, False),
        ("getWriteLocked", False, True),
        ("getWriteLock", False, True),
        ("isWriteLocked", False, True),
        ("writeLocked", False, True),
        ("getRangeWriteLocked", False, True),
        ("isRangeWriteLocked", False, True),
        ("isWriteLockSet", False, True),
        ("getWriteLockState", False, True),
        ("getRangeWriteLockState", False, True),
        ("writeLockState", False, True),
        ("rangeWriteLockState", False, True),
    ):
        yield Probe(
            f"{getter} locked-field return matches tracked boolean",
            bool_locked_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"locked": expected_value}}}],
            "PASS",
            "locking-wrapper",
            "`locked` is a common single-result wrapper field for Locking locked-state getters.",
        )
        yield Probe(
            f"{getter} isLocked-field rejects stale boolean",
            bool_locked_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"isLocked": stale_value}}}],
            "FAIL",
            "locking-wrapper",
            "`isLocked` return fields cannot bypass tracked Locking locked-state cells.",
        )
    for selector_key in ("rangeName", "range_name", "bandName", "band_name"):
        context = activated_locking_context() + [
            {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 84, "length": 4, "readLockEnabled": True, "readLocked": False}}, "output": {"return": True}},
            {"input": {"function": "readLock", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": True}},
        ]
        yield Probe(
            f"readLock values {selector_key} getter reports tracked lock",
            context + [{"input": {"function": "getReadLocked", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"locked": True}}}],
            "PASS",
            "locking-wrapper",
            f"`values.{selector_key}` should select Range1 for both lock mutation and lock-state getter wrappers.",
        )
        yield Probe(
            f"readLock values {selector_key} getter rejects stale lock",
            context + [{"input": {"function": "getReadLocked", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"locked": False}}}],
            "FAIL",
            "locking-wrapper",
            f"`values.{selector_key}` cannot bypass the tracked ReadLocked cell.",
        )
        yield Probe(
            f"getRangeLocks values {selector_key} reports tracked locks",
            context + [{"input": {"function": "getRangeLocks", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"ReadLocked": True, "WriteLocked": False}}}],
            "PASS",
            "locking-wrapper",
            f"`values.{selector_key}` should select Range1 for composite lock-state getters.",
        )
        yield Probe(
            f"getRangeLocks values {selector_key} rejects stale locks",
            context + [{"input": {"function": "getRangeLocks", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"ReadLocked": False, "WriteLocked": False}}}],
            "FAIL",
            "locking-wrapper",
            f"`values.{selector_key}` cannot bypass tracked composite lock-state cells.",
        )
    advanced_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "AdvKeyMode": 1, "GeneralStatus": 0}}, "output": {"return": True}},
    ]
    for selector_key in ("rangeName", "range_name", "bandName", "band_name"):
        yield Probe(
            f"getAdvKeyMode values {selector_key} reports tracked mode",
            advanced_context + [{"input": {"function": "getAdvKeyMode", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"advancedKeyMode": 1}}}],
            "PASS",
            "locking-wrapper",
            f"`values.{selector_key}` should select Range1 for advanced Locking column getters.",
        )
        yield Probe(
            f"getAdvKeyMode values {selector_key} rejects stale mode",
            advanced_context + [{"input": {"function": "getAdvKeyMode", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"advancedKeyMode": 0}}}],
            "FAIL",
            "locking-wrapper",
            f"`values.{selector_key}` cannot bypass the tracked AdvKeyMode cell.",
        )
        yield Probe(
            f"getGeneralStatus values {selector_key} reports tracked status",
            advanced_context + [{"input": {"function": "getGeneralStatus", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"rangeStatus": 0}}}],
            "PASS",
            "locking-wrapper",
            f"`values.{selector_key}` should select Range1 for advanced Locking status getters.",
        )
        yield Probe(
            f"getGeneralStatus values {selector_key} rejects stale status",
            advanced_context + [{"input": {"function": "getGeneralStatus", "kwargs": {"values": {selector_key: 1, "authAs": ("Admin1", "new")}}}, "output": {"return": {"rangeStatus": 1}}}],
            "FAIL",
            "locking-wrapper",
            f"`values.{selector_key}` cannot bypass the tracked GeneralStatus cell.",
        )
    numeric_value_getter_context = activated_locking_context() + [
        {"input": {"function": "setRangeStart", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 123}}, "output": {"return": True}},
        {"input": {"function": "setRangeLength", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 7}}, "output": {"return": True}},
    ]
    for getter, expected_value, stale_value in (
        ("getRangeStart", 123, 122),
        ("getRangeLBA", 123, 122),
        ("getRangeStartLBA", 123, 122),
        ("getStartLBA", 123, 122),
        ("getRangeLength", 7, 8),
        ("getRangeSize", 7, 8),
        ("getRangeLen", 7, 8),
    ):
        yield Probe(
            f"{getter} raw scalar return matches tracked numeric cell",
            numeric_value_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": expected_value}}],
            "PASS",
            "locking-wrapper",
            "Single-cell numeric wrapper getters may return the scalar value directly.",
        )
        yield Probe(
            f"{getter} value-field rejects stale numeric cell",
            numeric_value_getter_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"value": stale_value}}}],
            "FAIL",
            "locking-wrapper",
            "Single-cell numeric wrapper getters must still compare against tracked Locking state.",
        )
    for setter, column, expected_value, stale_value in (
        ("setRangeLBA", "RangeStart", 77, 0),
        ("setRangeStartLBA", "RangeStart", 77, 0),
        ("setStartLBA", "RangeStart", 77, 0),
        ("setRangeSize", "RangeLength", 9, 0),
        ("setRangeLen", "RangeLength", 9, 0),
    ):
        setter_context = activated_locking_context() + [
            {"input": {"function": setter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": expected_value}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates {column}",
            setter_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: expected_value})],
            "PASS",
            "locking-wrapper",
            f"{setter} is a bounded numeric setter alias for Locking.{column}.",
        )
        yield Probe(
            f"{setter} alias rejects stale {column}",
            setter_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: stale_value})],
            "FAIL",
            "locking-wrapper",
            f"{setter} must mutate tracked Locking.{column}.",
        )
    for setter, column, expected_value in (
        ("enableRangeReadLock", "ReadLockEnabled", True),
        ("enableRangeReadLocking", "ReadLockEnabled", True),
        ("disableRangeReadLock", "ReadLockEnabled", False),
        ("disableRangeReadLocking", "ReadLockEnabled", False),
        ("setRangeReadLockEnabled", "ReadLockEnabled", True),
        ("setRangeReadLockingEnabled", "ReadLockEnabled", True),
        ("enableRangeWriteLock", "WriteLockEnabled", True),
        ("enableRangeWriteLocking", "WriteLockEnabled", True),
        ("disableRangeWriteLock", "WriteLockEnabled", False),
        ("disableRangeWriteLocking", "WriteLockEnabled", False),
        ("setRangeWriteLockEnabled", "WriteLockEnabled", True),
        ("setRangeWriteLockingEnabled", "WriteLockEnabled", True),
        ("lockRangeRead", "ReadLocked", True),
        ("unlockRangeRead", "ReadLocked", False),
        ("setRangeReadLock", "ReadLocked", True),
        ("setReadLockState", "ReadLocked", True),
        ("setRangeReadLockState", "ReadLocked", True),
        ("lockRangeWrite", "WriteLocked", True),
        ("unlockRangeWrite", "WriteLocked", False),
        ("setRangeWriteLock", "WriteLocked", True),
        ("setWriteLockState", "WriteLocked", True),
        ("setRangeWriteLockState", "WriteLocked", True),
    ):
        setter_context = activated_locking_context() + [
            {"input": {"function": setter, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": expected_value}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates {column}",
            setter_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: expected_value})],
            "PASS",
            "locking-wrapper",
            f"{setter} is a bounded setter alias for Locking.{column}.",
        )
        yield Probe(
            f"{setter} alias rejects stale {column}",
            setter_context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: (not expected_value)})],
            "FAIL",
            "locking-wrapper",
            f"{setter} must mutate tracked Locking.{column}; stale observations are invalid.",
        )
    set_write_lock_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 80, "length": 4, "writeLockEnabled": True}}, "output": {"return": True}},
        {"input": {"function": "setWriteLock", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
    ]
    yield Probe(
        "setWriteLock alias blocks host write",
        set_write_lock_context + [host_write_status(NOT_AUTHORIZED, "AA", "80 ~ 80")],
        "PASS",
        "locking-wrapper",
        "Direct WriteLocked setter aliases should update the same Locking state as writeLock.",
    )
    yield Probe(
        "setWriteLock alias rejects host write success",
        set_write_lock_context + [host_write_status(SUCCESS, "AA", "80 ~ 80")],
        "FAIL",
        "locking-wrapper",
        "A range with WriteLockEnabled and WriteLocked true cannot allow host writes.",
    )
    lock_read_alias_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 84, "length": 4, "readLockEnabled": True}}, "output": {"return": True}},
        {"input": {"function": "lockRead", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
    ]
    yield Probe(
        "lockRead alias blocks host read",
        lock_read_alias_context + [host_read_status(NOT_AUTHORIZED, "84 ~ 84")],
        "PASS",
        "locking-wrapper",
        "lockRead should share readLock's ReadLocked state transition.",
    )
    yield Probe(
        "lockRead alias rejects host read success",
        lock_read_alias_context + [host_read_status(SUCCESS, "84 ~ 84")],
        "FAIL",
        "locking-wrapper",
        "A range with ReadLockEnabled and ReadLocked true cannot allow host reads.",
    )
    lock_write_alias_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 88, "length": 4, "writeLockEnabled": True}}, "output": {"return": True}},
        {"input": {"function": "lockWrite", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
    ]
    yield Probe(
        "lockWrite alias blocks host write",
        lock_write_alias_context + [host_write_status(NOT_AUTHORIZED, "AA", "88 ~ 88")],
        "PASS",
        "locking-wrapper",
        "lockWrite should share writeLock's WriteLocked state transition.",
    )
    yield Probe(
        "lockWrite alias rejects host write success",
        lock_write_alias_context + [host_write_status(SUCCESS, "AA", "88 ~ 88")],
        "FAIL",
        "locking-wrapper",
        "A range with WriteLockEnabled and WriteLocked true cannot allow host writes.",
    )
    unlock_read_alias_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 92, "length": 4, "readLockEnabled": True, "readLocked": True}}, "output": {"return": True}},
        {"input": {"function": "unlockRead", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
    ]
    yield Probe(
        "unlockRead alias permits host read",
        unlock_read_alias_context + [host_read_status(SUCCESS, "92 ~ 92")],
        "PASS",
        "locking-wrapper",
        "unlockRead should share readUnlock's ReadLocked clearing transition.",
    )
    yield Probe(
        "unlockRead alias rejects stale host read denial",
        unlock_read_alias_context + [host_read_status(NOT_AUTHORIZED, "92 ~ 92")],
        "FAIL",
        "locking-wrapper",
        "A successful unlockRead wrapper must clear the stored ReadLocked cell.",
    )
    unlock_write_alias_context = activated_locking_context() + [
        {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 96, "length": 4, "writeLockEnabled": True, "writeLocked": True}}, "output": {"return": True}},
        {"input": {"function": "unlockWrite", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
    ]
    yield Probe(
        "unlockWrite alias permits host write",
        unlock_write_alias_context + [host_write_status(SUCCESS, "AA", "96 ~ 96")],
        "PASS",
        "locking-wrapper",
        "unlockWrite should share writeUnlock's WriteLocked clearing transition.",
    )
    yield Probe(
        "unlockWrite alias rejects stale host write denial",
        unlock_write_alias_context + [host_write_status(NOT_AUTHORIZED, "AA", "96 ~ 96")],
        "FAIL",
        "locking-wrapper",
        "A successful unlockWrite wrapper must clear the stored WriteLocked cell.",
    )
    for alias, column, expected_value, base_values in (
        ("enableReadLocking", "ReadLockEnabled", True, {"readLockEnabled": False}),
        ("disableReadLocking", "ReadLockEnabled", False, {"readLockEnabled": True}),
        ("enableWriteLocking", "WriteLockEnabled", True, {"writeLockEnabled": False}),
        ("disableWriteLocking", "WriteLockEnabled", False, {"writeLockEnabled": True}),
        ("setReadLockingEnabled", "ReadLockEnabled", True, {"readLockEnabled": False}),
        ("setWriteLockingEnabled", "WriteLockEnabled", True, {"writeLockEnabled": False}),
    ):
        context = activated_locking_context() + [
            {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 100, "length": 4, **base_values}}, "output": {"return": True}},
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "enabled": expected_value}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: expected_value})],
            "PASS",
            "locking-wrapper",
            f"{alias} should update Locking.{column}.",
        )
        yield Probe(
            f"{alias} alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: not expected_value})],
            "FAIL",
            "locking-wrapper",
            f"A later getRange cannot ignore {alias}.",
        )
    for alias, column, expected_value, base_values in (
        ("lockForRead", "ReadLocked", True, {"readLockEnabled": True, "readLocked": False}),
        ("lockRangeForRead", "ReadLocked", True, {"readLockEnabled": True, "readLocked": False}),
        ("setReadLockForRange", "ReadLocked", True, {"readLockEnabled": True, "readLocked": False}),
        ("unlockForRead", "ReadLocked", False, {"readLockEnabled": True, "readLocked": True}),
        ("unlockRangeForRead", "ReadLocked", False, {"readLockEnabled": True, "readLocked": True}),
        ("clearReadLockForRange", "ReadLocked", False, {"readLockEnabled": True, "readLocked": True}),
        ("clearRangeReadLock", "ReadLocked", False, {"readLockEnabled": True, "readLocked": True}),
        ("lockForWrite", "WriteLocked", True, {"writeLockEnabled": True, "writeLocked": False}),
        ("lockRangeForWrite", "WriteLocked", True, {"writeLockEnabled": True, "writeLocked": False}),
        ("setWriteLockForRange", "WriteLocked", True, {"writeLockEnabled": True, "writeLocked": False}),
        ("unlockForWrite", "WriteLocked", False, {"writeLockEnabled": True, "writeLocked": True}),
        ("unlockRangeForWrite", "WriteLocked", False, {"writeLockEnabled": True, "writeLocked": True}),
        ("clearWriteLockForRange", "WriteLocked", False, {"writeLockEnabled": True, "writeLocked": True}),
        ("clearRangeWriteLock", "WriteLocked", False, {"writeLockEnabled": True, "writeLocked": True}),
    ):
        context = activated_locking_context() + [
            {"input": {"function": "setRange", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "start": 104, "length": 4, **base_values}}, "output": {"return": True}},
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: expected_value})],
            "PASS",
            "locking-wrapper",
            f"{alias} should update Locking.{column}.",
        )
        yield Probe(
            f"{alias} alias rejects stale {column}",
            context + [function_record("getRange", [1], {"authAs": ("Admin1", "new")}, {column: not expected_value})],
            "FAIL",
            "locking-wrapper",
            f"A later getRange cannot ignore {alias}.",
        )
    failed_set_write_lock_enabled_context = activated_locking_context() + [
        {"input": {"function": "setRangeStart", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 40}}, "output": {"return": True}},
        {"input": {"function": "setRangeLength", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": 4}}, "output": {"return": True}},
        {"input": {"function": "setWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": {"ok": False}}},
        {"input": {"function": "setWriteLocked", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1, "value": True}}, "output": {"return": True}},
    ]
    yield Probe(
        "failed setWriteLockEnabled preserves host write",
        failed_set_write_lock_enabled_context + [host_write_status(SUCCESS, "AA", "40 ~ 40")],
        "PASS",
        "locking-wrapper",
        "Failure-shaped setWriteLockEnabled wrappers should not enable write-lock enforcement.",
    )
    yield Probe(
        "failed setWriteLockEnabled rejects phantom denial",
        failed_set_write_lock_enabled_context + [host_write_status(NOT_AUTHORIZED, "AA", "40 ~ 40")],
        "FAIL",
        "locking-wrapper",
        "A failed setWriteLockEnabled wrapper cannot be applied as a successful Locking.Set.",
    )
    yield Probe(
        "getWriteLockEnabled alias reports enabled state",
        set_write_lock_enabled_context
        + [{"input": {"function": "getWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": True}}],
        "PASS",
        "locking-wrapper",
        "Direct WriteLockEnabled getter aliases should read the tracked Locking column.",
    )
    yield Probe(
        "getWriteLockEnabled alias rejects stale disabled state",
        set_write_lock_enabled_context
        + [{"input": {"function": "getWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": False}}],
        "FAIL",
        "locking-wrapper",
        "The getter alias cannot return false after WriteLockEnabled was set true.",
    )
    yield Probe(
        "getWriteLockEnabled rejects status-only Boolean payload",
        set_write_lock_enabled_context
        + [{"input": {"function": "getWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"status": "SUCCESS", "return": "SUCCESS"}}],
        "FAIL",
        "locking-wrapper",
        "A Locking boolean getter must expose the tracked Boolean column, not a bare method status token.",
    )
    yield Probe(
        "getWriteLockEnabled object return reports enabled state",
        set_write_lock_enabled_context
        + [{"input": {"function": "getWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"WriteLockEnabled": True}}}],
        "PASS",
        "locking-wrapper",
        "A direct locking boolean getter may return a one-field object named after the official column.",
    )
    yield Probe(
        "getWriteLockEnabled object return rejects stale disabled state",
        set_write_lock_enabled_context
        + [{"input": {"function": "getWriteLockEnabled", "kwargs": {"authAs": ("Admin1", "new"), "rangeId": 1}}, "output": {"return": {"WriteLockEnabled": False}}}],
        "FAIL",
        "locking-wrapper",
        "A one-field WriteLockEnabled object must still match tracked state.",
    )

    pin_limit_context = locking_admin_open() + [
        {"input": {"function": "setPINLimit", "kwargs": {"user": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "checkPIN", "kwargs": {"identity": "User1", "passcode": "bad"}}, "output": {"return": False}},
    ]
    yield Probe(
        "setPINLimit alias exhausts checkPIN",
        pin_limit_context + [{"input": {"function": "checkPIN", "kwargs": {"identity": "User1", "passcode": "userpin"}}, "output": {"return": False}}],
        "PASS",
        "credential-wrapper",
        "setPINLimit is a C_PIN.TryLimit alias and should feed TryLimit lockout.",
    )
    yield Probe(
        "getTryLimit pinLimit alias reports current limit",
        locking_admin_open()
        + [
            {"input": {"function": "setPINLimit", "kwargs": {"user": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "getTryLimit", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"pinLimit": 1}}},
        ],
        "PASS",
        "credential-wrapper",
        "C_PIN.TryLimit wrapper getters may return SDK-style pinLimit fields.",
    )
    for getter in ("getPINTryLimit", "getPINRetryLimit", "getUserTryLimit", "getCredentialTryLimit"):
        getter_context = locking_admin_open() + [
            {"input": {"function": "setTryLimit", "kwargs": {"user": "User1", "value": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{getter} alias reports current TryLimit",
            getter_context + [{"input": {"function": getter, "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 2}}}],
            "PASS",
            "credential-wrapper",
            f"{getter} should read the bounded C_PIN.TryLimit column.",
        )
        yield Probe(
            f"{getter} alias rejects stale TryLimit",
            getter_context + [{"input": {"function": getter, "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 3}}}],
            "FAIL",
            "credential-wrapper",
            f"{getter} must compare against tracked C_PIN.TryLimit state.",
        )
    pin_tries_context = locking_admin_open() + [
        {"input": {"function": "setPINTries", "kwargs": {"user": "User1", "tries": 0, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "setPINTries getTries reports zero",
        pin_tries_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 0}}}],
        "PASS",
        "credential-wrapper",
        "setPINTries should update the same C_PIN.Tries column as setTries.",
    )
    yield Probe(
        "setPINTries getTries pinTries alias reports zero",
        pin_tries_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"pinTries": 0}}}],
        "PASS",
        "credential-wrapper",
        "C_PIN.Tries wrapper getters may return SDK-style pinTries fields.",
    )
    yield Probe(
        "setPINTries getTries rejects Boolean-only Tries",
        pin_tries_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "credential-wrapper",
        "C_PIN.Tries is a uinteger cell, not a literal Boolean success flag.",
    )
    for setter, getter, value_key, column, expected, stale in (
        ("setPINTries", "getTries", "tries", "Tries", 0, 1),
        ("setPINTryLimit", "getTryLimit", "tryLimit", "TryLimit", 2, 3),
    ):
        operation_context = locking_admin_open() + [
            {
                "input": {
                    "function": setter,
                    "kwargs": {
                        "operation": {
                            "target": {"user": "User1"},
                            "command": {value_key: expected, "authAs": ("Admin1", "new")},
                        }
                    },
                },
                "output": {"return": True},
            },
        ]
        operation_get = {"operation": {"target": {"user": "User1"}, "command": {"authAs": ("Admin1", "new")}}}
        yield Probe(
            f"{setter}/{getter} operation target command reports current counter",
            operation_context + [{"input": {"function": getter, "kwargs": operation_get}, "output": {"return": {column: expected}}}],
            "PASS",
            "credential-counter-operation-envelope-doc",
            "C_PIN counter getters must preserve operation target selectors and command auth.",
        )
        yield Probe(
            f"{setter}/{getter} operation target command rejects stale counter",
            operation_context + [{"input": {"function": getter, "kwargs": operation_get}, "output": {"return": {column: stale}}}],
            "FAIL",
            "credential-counter-operation-envelope-doc",
            "Dropping operation target selectors lets stale C_PIN counter observations pass.",
        )
    for setter in (
        "setPINTryLimit",
        "setPINRetryLimit",
        "setUserTryLimit",
        "setCredentialTryLimit",
        "setRetryLimit",
        "setUserRetryLimit",
        "setPasswordRetryLimit",
        "setCredentialRetryLimit",
        "setMaxRetries",
        "setUserMaxRetries",
    ):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "value": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates TryLimit",
            setter_context + [{"input": {"function": "getTryLimit", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 2}}}],
            "PASS",
            "credential-wrapper",
            f"{setter} should mutate the bounded C_PIN.TryLimit column.",
        )
        yield Probe(
            f"{setter} alias rejects stale TryLimit",
            setter_context + [{"input": {"function": "getTryLimit", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 3}}}],
            "FAIL",
            "credential-wrapper",
            f"{setter} must not leave a stale C_PIN.TryLimit value.",
        )
    for setter in ("updateTryLimit", "putTryLimit"):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "value": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates TryLimit",
            setter_context + [{"input": {"function": "getTryLimit", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 2}}}],
            "PASS",
            "credential-wrapper",
            f"{setter} should share C_PIN.TryLimit Set semantics.",
        )
        yield Probe(
            f"{setter} alias rejects stale TryLimit",
            setter_context + [{"input": {"function": "getTryLimit", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"TryLimit": 3}}}],
            "FAIL",
            "credential-wrapper",
            f"{setter} must not leave a stale C_PIN.TryLimit value.",
        )
    for setter in ("setUserRetries", "setCredentialTries"):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "value": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates Tries",
            setter_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 1}}}],
            "PASS",
            "credential-wrapper",
            f"{setter} should mutate the bounded C_PIN.Tries column.",
        )
        yield Probe(
            f"{setter} alias rejects stale Tries",
            setter_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 2}}}],
            "FAIL",
            "credential-wrapper",
            f"{setter} must not leave a stale C_PIN.Tries value.",
        )
    for setter in ("updateTries", "putTries"):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "value": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates Tries",
            setter_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 1}}}],
            "PASS",
            "credential-wrapper",
            f"{setter} should share C_PIN.Tries Set semantics.",
        )
        yield Probe(
            f"{setter} alias rejects stale Tries",
            setter_context + [{"input": {"function": "getTries", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 2}}}],
            "FAIL",
            "credential-wrapper",
            f"{setter} must not leave a stale C_PIN.Tries value.",
        )
    for getter in ("getUserRetries", "getCredentialTries"):
        getter_context = locking_admin_open() + [
            {"input": {"function": "setPINTries", "kwargs": {"user": "User1", "value": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{getter} alias reports current Tries",
            getter_context + [{"input": {"function": getter, "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 1}}}],
            "PASS",
            "credential-wrapper",
            f"{getter} should read the bounded C_PIN.Tries column.",
        )
        yield Probe(
            f"{getter} alias rejects stale Tries",
            getter_context + [{"input": {"function": getter, "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Tries": 2}}}],
            "FAIL",
            "credential-wrapper",
            f"{getter} must compare against tracked C_PIN.Tries state.",
        )

    authority_limit_context = locking_admin_open() + [
        {"input": {"function": "setAuthorityLimit", "kwargs": {"authority": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        set_values("", "C_PIN_User1", {3: "userpin", 5: 3}),
        {"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}},
    ]
    yield Probe(
        "setAuthorityLimit alias blocks second checkPIN",
        authority_limit_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": False}}],
        "PASS",
        "authority-wrapper",
        "Authority.Limit wrapper aliases should feed the existing authority-use counter.",
    )
    yield Probe(
        "setAuthorityLimit alias rejects second checkPIN success",
        authority_limit_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}}],
        "FAIL",
        "authority-wrapper",
        "Ignoring Authority.Limit aliases would permit authentication after the configured use limit is consumed.",
    )
    yield Probe(
        "getAuthorityLimit authorityLimit alias reports current limit",
        locking_admin_open()
        + [
            {"input": {"function": "setAuthorityLimit", "kwargs": {"authority": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "getAuthorityLimit", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"authorityLimit": 1}}},
        ],
        "PASS",
        "authority-wrapper",
        "Authority.Limit wrapper getters may return SDK-style authorityLimit fields.",
    )
    authority_limit_return_context = locking_admin_open() + [
        {"input": {"function": "setAuthLimit", "kwargs": {"identity": "User1", "limit": 3, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for return_key in ("authLimit", "useLimit", "maxUses", "maxAuthentications", "maxAuths", "authenticationLimit", "authUseLimit", "userUseLimit", "credentialLimit", "credentialUseLimit"):
        yield Probe(
            f"getAuthorityLimit {return_key} return-field alias reports current limit",
            authority_limit_return_context + [{"input": {"function": "getAuthorityLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 3}}}],
            "PASS",
            "authority-wrapper",
            f"{return_key} is a bounded SDK-style return field for the official Authority.Limit cell.",
        )
        yield Probe(
            f"getAuthorityLimit {return_key} return-field alias rejects stale limit",
            authority_limit_return_context + [{"input": {"function": "getAuthorityLimit", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 1}}}],
            "FAIL",
            "authority-wrapper",
            f"{return_key} must compare against the tracked Authority.Limit cell.",
        )
    yield Probe(
        "getAuthorityLimit rejects Boolean-only Limit",
        locking_admin_open()
        + [
            {"input": {"function": "setAuthorityLimit", "kwargs": {"authority": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "getAuthorityLimit", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ],
        "FAIL",
        "authority-wrapper",
        "Authority.Limit is a uinteger cell, not a literal Boolean success flag.",
    )
    user_limit_context = locking_admin_open() + [
        {"input": {"function": "setUserLimit", "kwargs": {"user": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        set_values("", "C_PIN_User1", {3: "userpin", 5: 3}),
        {"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}},
    ]
    yield Probe(
        "setUserLimit alias blocks second checkPIN",
        user_limit_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": False}}],
        "PASS",
        "authority-wrapper",
        "setUserLimit should update the same Authority.Limit column as setAuthorityLimit.",
    )
    yield Probe(
        "setUserLimit alias rejects second checkPIN success",
        user_limit_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}}],
        "FAIL",
        "authority-wrapper",
        "Ignoring setUserLimit would permit authentication after the configured use limit is consumed.",
    )
    for setter in ("setAuthLimit", "setMaxAuthentications", "setUserMaxAuthentications", "setAuthorityUseLimit", "setUserUseLimit"):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "limit": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            set_values("", "C_PIN_User1", {3: "userpin", 5: 3}),
            {"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias blocks second checkPIN",
            setter_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": False}}],
            "PASS",
            "authority-wrapper",
            f"{setter} should update the bounded Authority.Limit column.",
        )
        yield Probe(
            f"{setter} alias rejects second checkPIN success",
            setter_context + [{"input": {"function": "checkPIN", "args": ["User1", "userpin"]}, "output": {"return": True}}],
            "FAIL",
            "authority-wrapper",
            f"Ignoring {setter} would permit authentication after the configured use limit is consumed.",
        )
    authority_limit_alias_context = locking_admin_open() + [
        {"input": {"function": "setAuthLimit", "kwargs": {"identity": "User1", "limit": 3, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for getter in ("getAuthLimit", "getMaxAuthentications", "getUserMaxAuthentications", "getAuthorityUseLimit", "getUserUseLimit"):
        yield Probe(
            f"{getter} alias reports current Authority Limit",
            authority_limit_alias_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Limit": 3}}}],
            "PASS",
            "authority-wrapper",
            f"{getter} should read the bounded Authority.Limit column.",
        )
        yield Probe(
            f"{getter} alias rejects stale Authority Limit",
            authority_limit_alias_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Limit": 1}}}],
            "FAIL",
            "authority-wrapper",
            f"{getter} cannot ignore the tracked Authority.Limit value.",
        )
    authority_uses_alias_context = locking_admin_open() + [
        {"input": {"function": "setUserUses", "kwargs": {"identity": "User1", "uses": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for getter in ("getAuthorityUseCount", "getUserUseCount", "getAuthUses", "getAuthenticationUses", "getUserAuthenticationUses", "getUseCount", "getAuthUseCount", "getCredentialUseCount", "getCredentialUses"):
        yield Probe(
            f"{getter} alias reports current Authority Uses",
            authority_uses_alias_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 2}}}],
            "PASS",
            "authority-wrapper",
            f"{getter} should read the bounded Authority.Uses column.",
        )
        yield Probe(
            f"{getter} alias rejects stale Authority Uses",
            authority_uses_alias_context + [{"input": {"function": getter, "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 0}}}],
            "FAIL",
            "authority-wrapper",
            f"{getter} cannot ignore the tracked Authority.Uses value.",
        )
    failed_authority_uses_context = locking_admin_open() + [
        set_values("", "User1", {16: 0}),
        {"input": {"function": "setAuthorityUses", "kwargs": {"authority": "User1", "uses": 7, "authAs": ("Admin1", "new")}}, "output": {"return": {"ok": False}}},
    ]
    yield Probe(
        "failed setAuthorityUses preserves prior Uses",
        failed_authority_uses_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 0}}}],
        "PASS",
        "authority-wrapper",
        "Failure-shaped Authority counter setters should not mutate Authority.Uses.",
    )
    yield Probe(
        "setAuthorityUses getAuthorityUses authorityUses alias reports current uses",
        locking_admin_open()
        + [
            {"input": {"function": "setAuthorityUses", "kwargs": {"authority": "User1", "uses": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "getAuthorityUses", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"authorityUses": 2}}},
        ],
        "PASS",
        "authority-wrapper",
        "Authority.Uses wrapper getters may return SDK-style authorityUses fields.",
    )
    for return_key in ("useCount", "authUseCount", "credentialUseCount", "credentialUses"):
        yield Probe(
            f"getAuthorityUses {return_key} return-field alias reports current uses",
            authority_uses_alias_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 2}}}],
            "PASS",
            "authority-wrapper",
            f"`{return_key}` is a bounded Authority.Uses return-field alias.",
        )
        yield Probe(
            f"getAuthorityUses {return_key} return-field alias rejects stale uses",
            authority_uses_alias_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"identity": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {return_key: 1}}}],
            "FAIL",
            "authority-wrapper",
            f"`{return_key}` must compare against tracked Authority.Uses.",
        )
    for setter in ("updateUses", "putUses", "updateUserUses", "putUserUses"):
        setter_context = locking_admin_open() + [
            {"input": {"function": setter, "kwargs": {"user": "User1", "value": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{setter} alias updates Authority Uses",
            setter_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 2}}}],
            "PASS",
            "authority-wrapper",
            f"{setter} should share Authority.Uses Set semantics.",
        )
        yield Probe(
            f"{setter} alias rejects stale Authority Uses",
            setter_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"user": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 3}}}],
            "FAIL",
            "authority-wrapper",
            f"{setter} must not leave a stale Authority.Uses value.",
        )
    for selector_key in ("authId", "auth_id", "authorityId", "authority_id", "userId", "user_id", "name"):
        selector_context = locking_admin_open() + [
            {
                "input": {"function": "setAuthorityUses", "kwargs": {selector_key: "User1", "uses": 4, "authAs": ("Admin1", "new")}},
                "output": {"return": True},
            },
        ]
        yield Probe(
            f"setAuthorityUses/getAuthorityUses {selector_key} selector reports current uses",
            selector_context + [{"input": {"function": "getAuthorityUses", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 4}}}],
            "PASS",
            "authority-wrapper",
            f"`{selector_key}` is a bounded Authority selector alias and must target User1.",
        )
        yield Probe(
            f"setAuthorityUses/getAuthorityUses {selector_key} selector rejects stale uses",
            selector_context + [{"input": {"function": "getAuthorityUses", "kwargs": {selector_key: "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 1}}}],
            "FAIL",
            "authority-wrapper",
            f"`{selector_key}` cannot fall back to an untracked/default authority row.",
        )
    yield Probe(
        "getAuthorityUses rejects Boolean-only Uses",
        locking_admin_open()
        + [
            {"input": {"function": "setAuthorityUses", "kwargs": {"authority": "User1", "uses": 2, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": "getAuthorityUses", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ],
        "FAIL",
        "authority-wrapper",
        "Authority.Uses is a uinteger cell, not a literal Boolean success flag.",
    )
    yield Probe(
        "failed setAuthorityUses rejects phantom Uses update",
        failed_authority_uses_context + [{"input": {"function": "getAuthorityUses", "kwargs": {"authority": "User1", "authAs": ("Admin1", "new")}}, "output": {"return": {"Uses": 7}}}],
        "FAIL",
        "authority-wrapper",
        "A failed setAuthorityUses wrapper cannot be applied as if the official Set succeeded.",
    )

    mbr_alias_context = locking_admin_open() + [
        {"input": {"function": "enableMBR", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "disableMBR", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "enableMBR/disableMBR aliases update getMBRControl",
        mbr_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
        "PASS",
        "mbr-wrapper",
        "MBR helper aliases should update and observe MBRControl.Enabled.",
    )
    yield Probe(
        "disableMBR alias rejects stale enabled observation",
        mbr_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
        "FAIL",
        "mbr-wrapper",
        "A getMBRControl helper response cannot ignore a prior disableMBR call.",
    )
    yield Probe(
        "getMBRControl rejects list-wrapped Boolean payload",
        mbr_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": [True]}}],
        "FAIL",
        "mbr-wrapper",
        "MBRControl.Get returns table cells; a list-wrapped Boolean must not erase tracked Enabled state.",
    )
    failed_enable_mbr_context = locking_admin_open() + [
        {"input": {"function": "enableMBR", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"ok": False}}},
    ]
    yield Probe(
        "failed enableMBR preserves disabled MBRControl",
        failed_enable_mbr_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
        "PASS",
        "mbr-wrapper",
        "Failure-shaped MBRControl wrappers should not mutate MBRControl.Enabled.",
    )
    yield Probe(
        "failed enableMBR rejects empty getMBRControl wrapper payload",
        failed_enable_mbr_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {}}}],
        "FAIL",
        "mbr-wrapper",
        "TCGstorageAPI getMBRControl is a structured getter and should return MBRControl cells even when a prior mutation failed.",
    )
    yield Probe(
        "failed enableMBR rejects phantom enabled MBRControl",
        failed_enable_mbr_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
        "FAIL",
        "mbr-wrapper",
        "A failed enableMBR wrapper cannot be applied as a successful MBRControl Set.",
    )
    mbr_enabled_alias_context = locking_admin_open() + [
        {"input": {"function": "setMBREnabled", "kwargs": {"enabled": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "setMBREnabled alias updates MBRControl",
        mbr_enabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
        "PASS",
        "mbr-wrapper",
        "setMBREnabled should update MBRControl.Enabled.",
    )
    yield Probe(
        "getMBRControl MBREnable alias reports enabled state",
        mbr_enabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"MBREnable": True}}}],
        "PASS",
        "mbr-wrapper",
        "MBRControl.Enabled may be returned through SDK-style MBREnable spelling.",
    )
    yield Probe(
        "setMBREnabled alias rejects stale disabled state",
        mbr_enabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
        "FAIL",
        "mbr-wrapper",
        "A getMBRControl helper response cannot ignore setMBREnabled.",
    )
    yield Probe(
        "getMBRControl MBREnable alias rejects stale disabled state",
        mbr_enabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"MBREnable": False}}}],
        "FAIL",
        "mbr-wrapper",
        "MBREnable object returns must match tracked MBRControl.Enabled.",
    )
    for getter in ("getMBREnabled", "isMBREnabled"):
        yield Probe(
            f"{getter} alias reports enabled state",
            mbr_enabled_alias_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
            "PASS",
            "mbr-wrapper",
            f"{getter} is a bounded getter for MBRControl.Enabled.",
        )
        yield Probe(
            f"{getter} alias rejects stale disabled state",
            mbr_enabled_alias_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
            "FAIL",
            "mbr-wrapper",
            f"{getter} must compare against tracked MBRControl.Enabled.",
        )
    mbr_done_alias_context = locking_admin_open() + [
        {"input": {"function": "setDoneMBR", "kwargs": {"done": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "setDoneMBR alias updates MBRDone",
        mbr_done_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": True}}}],
        "PASS",
        "mbr-wrapper",
        "setDoneMBR should update MBRControl.Done.",
    )
    yield Probe(
        "getMBRControl MBRDone alias reports done state",
        mbr_done_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"MBRDone": True}}}],
        "PASS",
        "mbr-wrapper",
        "MBRControl.Done may be returned through SDK-style MBRDone spelling.",
    )
    yield Probe(
        "setDoneMBR alias rejects stale not-done state",
        mbr_done_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": False}}}],
        "FAIL",
        "mbr-wrapper",
        "A getMBRControl helper response cannot ignore setDoneMBR.",
    )
    for alias in ("completeMBR", "finishMBR"):
        complete_mbr_context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias marks MBR complete",
            complete_mbr_context + [{"input": {"function": "getMBRComplete", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": True}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} is a bounded alias for setting MBRControl.Done true.",
        )
        yield Probe(
            f"{alias} alias rejects stale incomplete state",
            complete_mbr_context + [{"input": {"function": "getMBRComplete", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": False}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must update tracked MBRControl.Done.",
        )
    mbr_done_flag_context = locking_admin_open() + [
        {"input": {"function": "setMBRDoneFlag", "kwargs": {"done": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for getter in ("getMBRDone", "isMBRDone", "getMBRDoneFlag", "getMBRComplete", "isMBRComplete"):
        yield Probe(
            f"{getter} alias reports done state",
            mbr_done_flag_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": True}}}],
            "PASS",
            "mbr-wrapper",
            f"{getter} is a bounded getter for MBRControl.Done.",
        )
        yield Probe(
            f"{getter} alias rejects stale not-done state",
            mbr_done_flag_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": False}}}],
            "FAIL",
            "mbr-wrapper",
            f"{getter} must compare against tracked MBRControl.Done.",
        )
    for alias in ("clearMBRDone", "resetMBRDone", "unmarkMBRDone", "setMBRNotDone", "clearMBRComplete", "resetMBRComplete"):
        clear_done_context = locking_admin_open() + [
            {"input": {"function": "markMBRDone", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
            {"input": {"function": alias, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias clears MBRDone",
            clear_done_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": False}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should clear MBRControl.Done.",
        )
        yield Probe(
            f"{alias} alias rejects stale done state",
            clear_done_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": True}}}],
            "FAIL",
            "mbr-wrapper",
            f"A getMBRControl helper response cannot ignore {alias}.",
        )
    mbr_disabled_alias_context = locking_admin_open() + [
        {"input": {"function": "enableMBR", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "setMBRDisabled", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "setMBRDisabled alias clears MBRControl Enabled",
        mbr_disabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
        "PASS",
        "mbr-wrapper",
        "setMBRDisabled should clear MBRControl.Enabled.",
    )
    yield Probe(
        "setMBRDisabled alias rejects stale enabled state",
        mbr_disabled_alias_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
        "FAIL",
        "mbr-wrapper",
        "A getMBRControl helper response cannot ignore setMBRDisabled.",
    )
    clear_enabled_context = locking_admin_open() + [
        {"input": {"function": "setMBREnabled", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "clearMBREnabled", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "clearMBREnabled alias clears MBRControl Enabled",
        clear_enabled_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
        "PASS",
        "mbr-wrapper",
        "clearMBREnabled should clear MBRControl.Enabled.",
    )
    yield Probe(
        "clearMBREnabled alias rejects stale enabled state",
        clear_enabled_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
        "FAIL",
        "mbr-wrapper",
        "A getMBRControl helper response cannot ignore clearMBREnabled.",
    )
    for alias in (
        "putMBRControl",
        "storeMBRControl",
        "saveMBRControl",
        "writeMBRControl",
        "programMBRControl",
        "setMBRState",
        "updateMBRState",
        "putMBRState",
        "configureMBRStatus",
    ):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates whole MBRControl state",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True, "Done": True, "DoneOnReset": [1]}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should lower to MBRControl.Set for explicit control/status/state payloads.",
        )
        yield Probe(
            f"{alias} alias rejects stale whole MBRControl state",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False, "Done": False, "DoneOnReset": [0]}}}],
            "FAIL",
            "mbr-wrapper",
            f"A later MBRControl observation cannot ignore successful {alias}.",
        )
    for alias in ("updateMBREnabled", "putMBREnabled", "storeMBREnable", "saveMBREnable"):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"enabled": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates MBRControl.Enabled",
            context + [{"input": {"function": "queryMBREnabled", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should share MBRControl.Enabled Set semantics.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl.Enabled",
            context + [{"input": {"function": "queryMBREnabled", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must mutate the tracked MBRControl.Enabled cell.",
        )
    for alias in ("updateMBRDone", "putMBRDone", "storeMBRDoneFlag", "saveMBRComplete"):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"done": True, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates MBRControl.Done",
            context + [{"input": {"function": "queryMBRDoneFlag", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": True}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should share MBRControl.Done Set semantics.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl.Done",
            context + [{"input": {"function": "queryMBRDoneFlag", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Done": False}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must mutate the tracked MBRControl.Done cell.",
        )
    for alias in ("updateMBRDoneOnReset", "putDoneOnReset", "storeMBRDOR", "saveMBRResetTypes"):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"DoneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates MBRControl.DoneOnReset",
            context + [{"input": {"function": "queryMBRResetTypes", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [1]}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should share MBRControl.DoneOnReset Set semantics.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl.DoneOnReset",
            context + [{"input": {"function": "queryMBRResetTypes", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [0]}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must mutate the tracked MBRControl.DoneOnReset cell.",
        )
    dor_list_context = locking_admin_open() + [
        {"input": {"function": "setMBRControl", "kwargs": {"DoneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for getter in ("queryMBRDoneOnReset", "loadMBRDoneOnReset", "readDoneOnReset", "fetchDoneOnReset", "queryMBRDOR", "fetchMBRResetTypes"):
        yield Probe(
            f"{getter} alias accepts current DoneOnReset list payload",
            dor_list_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": [1]}}],
            "PASS",
            "mbr-wrapper",
            f"{getter} is a scalar wrapper for the MBRControl.DoneOnReset reset_types cell.",
        )
        yield Probe(
            f"{getter} alias rejects stale DoneOnReset list payload",
            dor_list_context + [{"input": {"function": getter, "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": [0]}}],
            "FAIL",
            "mbr-wrapper",
            f"{getter} list payload must still match tracked MBRControl.DoneOnReset state.",
        )

    active_key_alias_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {10: "K_AES_256_Range1_Key"}),
    ]
    yield Probe(
        "getActiveKey alias reflects known ActiveKey UID",
        active_key_alias_context
        + [
            function_record(
                "getActiveKey",
                [1, "Admin1"],
                {"authAs": ("Admin1", "new")},
                {"K_AES_256_Range1_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x01"},
            )
        ],
        "PASS",
        "media-key-wrapper",
        "getActiveKey should share getMEK's ActiveKey UID comparison.",
    )
    yield Probe(
        "getActiveKey alias rejects Boolean-only ActiveKey",
        active_key_alias_context
        + [function_record("getActiveKey", [1, "Admin1"], {"authAs": ("Admin1", "new")}, True)],
        "FAIL",
        "media-key-wrapper",
        "getActiveKey returns an ActiveKey uidref, not a literal Boolean success flag.",
    )
    for alias in (
        "getRangeKey",
        "getMediaKey",
        "readMEK",
        "activeKey",
        "getActiveMediaKey",
        "getLockingKey",
        "readRangeKey",
        "getMediaEncryptionKey",
        "getCurrentKey",
        "getRangeCurrentKey",
        "getRangeMediaEncryptionKey",
        "getEncryptionKey",
        "getRangeEncryptionKey",
        "getActiveMEK",
        "getCurrentMEK",
    ):
        yield Probe(
            f"{alias} alias reflects known ActiveKey UID",
            active_key_alias_context
            + [
                function_record(
                    alias,
                    [1, "Admin1"],
                    {"authAs": ("Admin1", "new")},
                    {"K_AES_256_Range1_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x01"},
                )
            ],
            "PASS",
            "media-key-wrapper",
            f"{alias} should share getMEK's ActiveKey UID comparison.",
        )
        yield Probe(
            f"{alias} alias accepts ActiveKey object symbol",
            active_key_alias_context
            + [
                function_record(
                    alias,
                    [1, "Admin1"],
                    {"authAs": ("Admin1", "new")},
                    {"ActiveKey": "K_AES_256_Range1_Key"},
                )
            ],
            "PASS",
            "media-key-wrapper",
            f"{alias} may expose the active key uidref as its canonical object symbol.",
        )
        yield Probe(
            f"{alias} alias rejects wrong ActiveKey UID",
            active_key_alias_context
            + [
                function_record(
                    alias,
                    [1, "Admin1"],
                    {"authAs": ("Admin1", "new")},
                    {"K_AES_256_Range2_Key_UID": b"\x00\x00\x08\x06\x00\x03\x00\x02"},
                )
            ],
            "FAIL",
            "media-key-wrapper",
            f"{alias} must not accept a stale/wrong ActiveKey UID.",
        )
        yield Probe(
            f"{alias} alias rejects wrong ActiveKey object symbol",
            active_key_alias_context
            + [
                function_record(
                    alias,
                    [1, "Admin1"],
                    {"authAs": ("Admin1", "new")},
                    {"ActiveKey": "K_AES_256_Range2_Key"},
                )
            ],
            "FAIL",
            "media-key-wrapper",
            f"{alias} object-symbol returns must still match the tracked ActiveKey uidref.",
        )
        yield Probe(
            f"{alias} alias rejects Boolean-only ActiveKey",
            active_key_alias_context + [function_record(alias, [1, "Admin1"], {"authAs": ("Admin1", "new")}, True)],
            "FAIL",
            "media-key-wrapper",
            f"{alias} returns an ActiveKey uidref, not a literal Boolean success flag.",
        )

    reencrypt_alias_context = locking_admin_open() + [
        method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
        {"input": {"function": "startReEncrypt", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "startReEncrypt alias moves state to pending",
        reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
        "PASS",
        "locking-wrapper",
        "ReEncrypt helper aliases should update Locking.ReEncryptRequest and observed ReEncryptState.",
    )
    yield Probe(
        "startReEncrypt alias rejects stale idle",
        reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
        "FAIL",
        "locking-wrapper",
        "Ignoring startReEncrypt would leave stale ReEncryptState accepted.",
    )
    for label, wrapper_key, wrapper_payload in (
        ("policy", "policy", {"rangeId": 1, "authAs": ("Admin1", "new")}),
        ("config", "config", {"range": 1, "authAs": ("Admin1", "new")}),
        ("request", "request", {"reencrypt": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
        ("request values", "request", {"values": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
        ("query", "query", {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}),
        ("policy query target", "policy", {"query": {"target": {"rangeId": 1}}, "authAs": ("Admin1", "new")}),
        ("operation command", "operation", {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
        ("operation target command", "operation", {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}),
        ("operationRequest target command", "operationRequest", {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}),
    ):
        tag = "reencrypt-operation-envelope-doc" if "operation" in label else "reencrypt-nested-envelope-doc" if " " in label else "locking-wrapper"
        yield Probe(
            f"getReEncryptStatus {label} envelope reads pending state",
            reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            tag,
            f"getReEncryptStatus should read its range selector from a structured {label} envelope.",
        )
        yield Probe(
            f"getReEncryptStatus {label} envelope rejects stale idle",
            reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            tag,
            f"getReEncryptStatus must not ignore a structured {label} range selector after START_req.",
        )
    for selector_key in ("rangeName", "range_name", "bandName", "band_name"):
        selector_context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
            {"input": {"function": "startReEncrypt", "values": {selector_key: 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"startReEncrypt values {selector_key} moves state to pending",
            selector_context + [{"input": {"function": "getReEncryptStatus", "values": {selector_key: 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"`{selector_key}` values selector should target Locking_Range1 for ReEncrypt state.",
        )
        yield Probe(
            f"startReEncrypt values {selector_key} rejects stale idle",
            selector_context + [{"input": {"function": "getReEncryptStatus", "values": {selector_key: 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            f"`{selector_key}` values selector cannot target BandNone or ignore START_req.",
        )
    for request_alias in ("updateReEncryptRequest", "putReEncryptRequest"):
        request_context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
            {"input": {"function": request_alias, "kwargs": {"rangeId": 1, "request": "START", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{request_alias} alias moves state to pending",
            request_context + [{"input": {"function": "readReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"{request_alias} should lower to a START_req ReEncryptRequest Set.",
        )
        yield Probe(
            f"{request_alias} alias rejects stale idle",
            request_context + [{"input": {"function": "readReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            f"{request_alias} cannot be accepted without mutating tracked ReEncryptState.",
        )
    for label, kwargs in (
        ("request values", {"request": {"values": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}}),
        ("policy request values", {"policy": {"request": {"values": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}}}),
        ("config target request", {"config": {"target": {"range": 1}, "request": {"value": "START_req"}, "authAs": ("Admin1", "new")}}),
        ("request target command", {"request": {"target": {"rangeId": 1}, "command": {"ReEncryptRequest": "START_req"}, "authAs": ("Admin1", "new")}}),
        ("operation target reencrypt", {"operation": {"target": {"rangeId": 1}, "reencrypt": {"request": "START_req"}, "authAs": ("Admin1", "new")}}),
        ("config target action", {"config": {"target": {"range": 1}, "action": "START_req", "authAs": ("Admin1", "new")}}),
        ("lockingRequest values", {"lockingRequest": {"values": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}}),
        ("rangeRequest values", {"rangeRequest": {"values": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}}),
        ("reencryptRequest values", {"reencryptRequest": {"values": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}}),
    ):
        request_context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
            {"input": {"function": "setReEncryptRequest", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setReEncryptRequest {label} moves state to pending",
            request_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "reencrypt-nested-envelope-doc",
            "Nested ReEncrypt request wrappers must preserve both the range selector and START_req value.",
        )
        yield Probe(
            f"setReEncryptRequest {label} rejects stale idle",
            request_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "reencrypt-nested-envelope-doc",
            "Ignoring a nested ReEncrypt request wrapper leaves stale IDLE state accepted.",
        )
    def wrap_reencrypt_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        current: dict[str, Any] = payload
        for key in reversed(chain):
            current = {key: current}
        return current

    reencrypt_deep_chains = (
        ("policy", "request", "values"),
        ("config", "target", "request"),
        ("lockingRequest", "rangeRequest", "reencryptRequest", "values"),
        ("request", "lockingRequest", "rangeRequest", "values"),
        ("policy", "query", "target", "request"),
    )
    for chain in reencrypt_deep_chains:
        chain_name = "/".join(chain)
        request_context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
            {"input": {"function": "setReEncryptRequest", "kwargs": wrap_reencrypt_payload({"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}, chain)}, "output": {"return": True}},
        ]
        yield Probe(
            f"setReEncryptRequest deep {chain_name} moves state to pending",
            request_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "reencrypt-deep-envelope-doc",
            "Deep ReEncrypt request wrappers must preserve both range selector and START_req value.",
        )
        yield Probe(
            f"setReEncryptRequest deep {chain_name} rejects stale idle",
            request_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "reencrypt-deep-envelope-doc",
            "Ignoring deep ReEncrypt request wrappers leaves stale IDLE state accepted.",
        )
    reencrypt_deep_getter_context = locking_admin_open() + [
        method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
        {"input": {"function": "setReEncryptRequest", "kwargs": {"rangeId": 1, "ReEncryptRequest": "START_req", "authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    for chain in reencrypt_deep_chains:
        chain_name = "/".join(chain)
        kwargs = wrap_reencrypt_payload({"rangeId": 1, "authAs": ("Admin1", "new")}, chain)
        yield Probe(
            f"getReEncryptStatus deep {chain_name} reads pending state",
            reencrypt_deep_getter_context + [{"input": {"function": "getReEncryptStatus", "kwargs": kwargs}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "reencrypt-deep-envelope-doc",
            "Deep ReEncrypt getter wrappers must preserve the range selector.",
        )
        yield Probe(
            f"getReEncryptStatus deep {chain_name} rejects stale idle",
            reencrypt_deep_getter_context + [{"input": {"function": "getReEncryptStatus", "kwargs": kwargs}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "reencrypt-deep-envelope-doc",
            "Ignoring deep ReEncrypt getter wrappers leaves stale IDLE accepted.",
        )
    for status_alias in (
        "getReEncryptState",
        "readReEncryptState",
        "fetchReEncryptState",
        "queryReEncryptState",
        "reEncryptStatus",
        "getReEncryptStatus",
        "readReEncryptStatus",
        "fetchReEncryptStatus",
        "queryReEncryptStatus",
        "getReEncryptionStatus",
        "readReEncryptionStatus",
        "fetchReEncryptionStatus",
        "queryReEncryptionStatus",
        "getReEncryptionState",
        "readReEncryptionState",
        "fetchReEncryptionState",
        "queryReEncryptionState",
    ):
        yield Probe(
            f"{status_alias} alias reads pending ReEncryptState",
            reencrypt_alias_context + [{"input": {"function": status_alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"{status_alias} should lower to Locking.ReEncryptState Get.",
        )
        yield Probe(
            f"{status_alias} alias accepts generic pending state field",
            reencrypt_alias_context + [{"input": {"function": status_alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"state": 2}}}],
            "PASS",
            "locking-wrapper",
            f"{status_alias} may expose the single ReEncryptState cell as a generic state field.",
        )
        yield Probe(
            f"{status_alias} alias accepts generic pending status field",
            reencrypt_alias_context + [{"input": {"function": status_alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"status": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"{status_alias} may expose the single ReEncryptState cell as a generic status field.",
        )
        yield Probe(
            f"{status_alias} alias rejects stale idle ReEncryptState",
            reencrypt_alias_context + [{"input": {"function": status_alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            f"{status_alias} must compare against the tracked ReEncryptState.",
        )
        yield Probe(
            f"{status_alias} alias rejects generic idle status field",
            reencrypt_alias_context + [{"input": {"function": status_alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"status": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            f"{status_alias} generic status returns must still compare against the tracked ReEncryptState.",
        )
    yield Probe(
        "isReEncrypting alias returns true while pending",
        reencrypt_alias_context + [{"input": {"function": "isReEncrypting", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "PASS",
        "locking-wrapper",
        "isReEncrypting should report true after START_req moves ReEncryptState to PENDING.",
    )
    yield Probe(
        "isReEncrypting alias rejects false while pending",
        reencrypt_alias_context + [{"input": {"function": "isReEncrypting", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
        "FAIL",
        "locking-wrapper",
        "isReEncrypting cannot report false while ReEncryptState is PENDING.",
    )
    idle_reencrypt_alias_context = locking_admin_open() + [
        method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
    ]
    yield Probe(
        "isReEncrypting alias returns false while idle",
        idle_reencrypt_alias_context + [{"input": {"function": "isReEncrypting", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"reEncrypting": False}}}],
        "PASS",
        "locking-wrapper",
        "isReEncrypting should report false while ReEncryptState is IDLE.",
    )
    yield Probe(
        "isReEncrypting raw false while idle",
        idle_reencrypt_alias_context + [{"input": {"function": "isReEncrypting", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
        "PASS",
        "locking-wrapper",
        "Raw false is a successful Boolean getter result when ReEncryptState is IDLE.",
    )
    locking_column_getter_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {11: "K_AES_256_Range1_Key", 14: 1, 15: 0, 16: 1, 17: 12345, 18: 1, 19: 0}),
    ]
    for alias, column_name, good, stale in (
        ("getNextKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getPendingKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getReEncryptKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getReEncryptionKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getNewKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getNewMEK", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getNextMEK", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getPendingMEK", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangeNextKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangePendingKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangeNewKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangePendingMEK", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangeNewMEK", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangeReEncryptKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getRangeReEncryptionKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
        ("getAdvKeyMode", "AdvKeyMode", 1, 2),
        ("getAdvancedKeyMode", "AdvKeyMode", 1, 2),
        ("getVerifyMode", "VerifyMode", 0, 1),
        ("getContOnReset", "ContOnReset", 1, 0),
        ("getContinueOnReset", "ContOnReset", 1, 0),
        ("getReEncryptContOnReset", "ContOnReset", 1, 0),
        ("getReEncryptContinueOnReset", "ContOnReset", 1, 0),
        ("isContOnReset", "ContOnReset", 1, 0),
        ("isContinueOnReset", "ContOnReset", 1, 0),
        ("getLastReEncryptLBA", "LastReEncryptLBA", 12345, 999),
        ("getLastReEncryptionLBA", "LastReEncryptLBA", 12345, 999),
        ("getLastReEncLBA", "LastReEncryptLBA", 12345, 999),
        ("getReEncryptLBA", "LastReEncryptLBA", 12345, 999),
        ("getReEncryptionLBA", "LastReEncryptLBA", 12345, 999),
        ("getLastReEncryptStatus", "LastReEncStat", 1, 0),
        ("getLastReEncryptionStatus", "LastReEncStat", 1, 0),
        ("getLastReEncStat", "LastReEncStat", 1, 0),
        ("getLastReEncryptStat", "LastReEncStat", 1, 0),
        ("getGeneralStatus", "GeneralStatus", 0, 1),
        ("getLockingRangeStatus", "GeneralStatus", 0, 1),
    ):
        yield Probe(
            f"{alias} alias reads tracked {column_name}",
            locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {column_name: good})],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to a bounded Locking.{column_name} Get.",
        )
        yield Probe(
            f"{alias} alias rejects stale {column_name}",
            locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {column_name: stale})],
            "FAIL",
            "locking-wrapper",
            f"{alias} must compare returned {column_name} against tracked state.",
        )
        if column_name in {"AdvKeyMode", "LastReEncStat"}:
            yield Probe(
                f"{alias} alias rejects Boolean-only {column_name}",
                locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, True)],
                "FAIL",
                "locking-wrapper",
                f"{alias} returns a typed Locking.{column_name} value, not a literal Boolean success flag.",
            )
        if column_name == "NextKey":
            yield Probe(
                f"{alias} alias rejects Boolean-only NextKey",
                locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, True)],
                "FAIL",
                "media-key-wrapper",
                f"{alias} returns a NextKey uidref, not a literal Boolean success flag.",
            )
    for alias, column_name, good, stale in (
        ("getAdvKeyMode", "AdvKeyMode", 1, 2),
        ("getLastReEncryptLBA", "LastReEncryptLBA", 12345, 999),
        ("getLastReEncryptStatus", "LastReEncStat", 1, 0),
        ("getGeneralStatus", "GeneralStatus", 0, 1),
        ("getNextKey", "NextKey", "K_AES_256_Range1_Key", "K_AES_256_Range2_Key"),
    ):
        for wrapper_key, wrapper_payload in (
            ("policy", {"rangeId": 1, "authAs": ("Admin1", "new")}),
            ("config", {"range": 1, "authAs": ("Admin1", "new")}),
            ("request", {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}),
            ("query", {"target": {"rangeId": 1}, "authAs": ("Admin1", "new")}),
            ("operation", {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
            ("operation", {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}),
            ("operationRequest", {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}),
        ):
            tag = "locking-column-operation-envelope-doc" if wrapper_key in {"operation", "operationRequest"} else "locking-wrapper"
            yield Probe(
                f"{alias} {wrapper_key} envelope reads tracked {column_name}",
                locking_column_getter_context + [function_record(alias, [], {wrapper_key: wrapper_payload}, {column_name: good})],
                "PASS",
                tag,
                f"{alias} should read the range selector from a structured {wrapper_key} envelope.",
            )
            yield Probe(
                f"{alias} {wrapper_key} envelope rejects stale {column_name}",
                locking_column_getter_context + [function_record(alias, [], {wrapper_key: wrapper_payload}, {column_name: stale})],
                "FAIL",
                tag,
                f"{alias} must not ignore a structured {wrapper_key} range selector.",
            )
    for alias, return_key, good, stale, column_name in (
        ("getAdvKeyMode", "advancedKeyMode", 1, 2, "AdvKeyMode"),
        ("getAdvKeyMode", "adv_key_mode", 1, 2, "AdvKeyMode"),
        ("getVerifyMode", "verify_mode", 0, 1, "VerifyMode"),
        ("getVerifyMode", "verificationMode", 0, 1, "VerifyMode"),
        ("getContOnReset", "continueOnReset", 1, 0, "ContOnReset"),
        ("getContOnReset", "cont_on_reset", 1, 0, "ContOnReset"),
        ("getContOnReset", "resetContinue", 1, 0, "ContOnReset"),
        ("getLastReEncryptLBA", "lastReEncryptionLBA", 12345, 999, "LastReEncryptLBA"),
        ("getLastReEncryptLBA", "reEncryptLBA", 12345, 999, "LastReEncryptLBA"),
        ("getLastReEncryptStatus", "lastReEncryptStatus", 1, 0, "LastReEncStat"),
        ("getLastReEncryptStatus", "lastReEncryptionStatus", 1, 0, "LastReEncStat"),
        ("getGeneralStatus", "rangeStatus", 0, 1, "GeneralStatus"),
        ("getGeneralStatus", "lockingRangeStatus", 0, 1, "GeneralStatus"),
    ):
        yield Probe(
            f"{alias} {return_key} return-field alias reads tracked {column_name}",
            locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {return_key: good})],
            "PASS",
            "locking-wrapper",
            f"{return_key} is a bounded return field for Locking.{column_name}.",
        )
        yield Probe(
            f"{alias} {return_key} return-field alias rejects stale {column_name}",
            locking_column_getter_context + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {return_key: stale})],
            "FAIL",
            "locking-wrapper",
            f"{return_key} must compare against the tracked Locking.{column_name} cell.",
        )
    next_key_uid_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {11: "K_AES_256_Range1_Key"}),
    ]
    yield Probe(
        "getNextKey alias accepts key UID return",
        next_key_uid_context + [function_record("getNextKey", [1], {"authAs": ("Admin1", "new")}, {"NextKey": b"\x00\x00\x08\x06\x00\x03\x00\x01"})],
        "PASS",
        "media-key-wrapper",
        "getNextKey may expose Locking.NextKey as a key UID reference.",
    )
    yield Probe(
        "getNextKey alias accepts key UID bytes repr return",
        next_key_uid_context
        + [function_record("getNextKey", [1], {"authAs": ("Admin1", "new")}, {"K_AES_256_Range1_Key_UID": "b'\\x00\\x00\\x08\\x06\\x00\\x03\\x00\\x01'"})],
        "PASS",
        "media-key-wrapper",
        "getNextKey may expose Locking.NextKey as a named UID bytes repr field.",
    )
    yield Probe(
        "getNextKey alias rejects stale key UID bytes repr return",
        next_key_uid_context
        + [function_record("getNextKey", [1], {"authAs": ("Admin1", "new")}, {"K_AES_256_Range2_Key_UID": "b'\\x00\\x00\\x08\\x06\\x00\\x03\\x00\\x02'"})],
        "FAIL",
        "media-key-wrapper",
        "getNextKey UID representations must still match tracked Locking.NextKey.",
    )
    for alias in (
        "getNextMEK",
        "getPendingMEK",
        "getNewMEK",
        "getReEncryptionKey",
        "getRangePendingKey",
        "getRangeNewKey",
        "getRangePendingMEK",
        "getRangeNewMEK",
        "getRangeReEncryptKey",
        "getRangeReEncryptionKey",
    ):
        yield Probe(
            f"{alias} alias accepts key UID bytes repr return",
            next_key_uid_context
            + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {"K_AES_256_Range1_Key_UID": "b'\\x00\\x00\\x08\\x06\\x00\\x03\\x00\\x01'"})],
            "PASS",
            "media-key-wrapper",
            f"{alias} may expose Locking.NextKey as a named UID bytes repr field.",
        )
        yield Probe(
            f"{alias} alias rejects stale key UID bytes repr return",
            next_key_uid_context
            + [function_record(alias, [1], {"authAs": ("Admin1", "new")}, {"K_AES_256_Range2_Key_UID": "b'\\x00\\x00\\x08\\x06\\x00\\x03\\x00\\x02'"})],
            "FAIL",
            "media-key-wrapper",
            f"{alias} UID representations must still match tracked Locking.NextKey.",
        )
    for alias in ("beginReEncrypt", "beginReEncryption", "reEncryptRange", "startReEncryption", "requestReEncrypt", "triggerReEncrypt", "reEncrypt"):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias moves state to pending",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to a START_req ReEncryptRequest.",
        )
        yield Probe(
            f"{alias} alias rejects stale idle",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring the START_req wrapper would leave stale ReEncryptState accepted.",
        )
    for alias in ("pauseReEncrypt", "pauseReEncryption"):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "ACTIVE"}]]),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias moves active state to paused",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PAUSED"}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to a PAUSE_req ReEncryptRequest.",
        )
        yield Probe(
            f"{alias} alias rejects stale active state",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "ACTIVE"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring the PAUSE_req wrapper would leave stale ReEncryptState accepted.",
        )
    for alias in ("resumeReEncrypt", "resumeReEncryption", "continueReEncrypt", "continueReEncryption"):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "PAUSED"}]]),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias moves paused state to pending",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to a CONT_req ReEncryptRequest.",
        )
        yield Probe(
            f"{alias} alias rejects stale paused state",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PAUSED"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring the CONT_req wrapper would leave stale ReEncryptState accepted.",
        )
    for alias in ("advanceKey", "advKey", "advanceReEncryptKey", "commitReEncryptKey"):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "PAUSED"}]]),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias advances paused state to idle",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to an ADVKEY_req ReEncryptRequest.",
        )
        yield Probe(
            f"{alias} alias rejects stale paused state",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PAUSED"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring the ADVKEY_req wrapper would leave stale ReEncryptState accepted.",
        )
    for alias in ("retIdle", "returnIdle", "returnToIdle", "returnReEncryptIdle", "returnReEncryptionIdle", "stopReEncrypt", "cancelReEncrypt"):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "PAUSED"}]]),
            {"input": {"function": alias, "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias returns paused state to idle",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "PASS",
            "locking-wrapper",
            f"{alias} should lower to a RETIDLE_req ReEncryptRequest.",
        )
        yield Probe(
            f"{alias} alias rejects stale paused state",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PAUSED"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring the RETIDLE_req wrapper would leave stale ReEncryptState accepted.",
        )
    for label, kwargs in (
        ("operation command", {"operation": {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"rangeId": 1}, "command": {"authAs": ("Admin1", "new")}}}),
        ("operationRequest command", {"operationRequest": {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}}),
        ("command", {"command": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
        ("action", {"action": {"rangeId": 1, "authAs": ("Admin1", "new")}}),
    ):
        context = locking_admin_open() + [
            method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "PAUSED"}]]),
            {"input": {"function": "returnReEncryptIdle", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"returnReEncryptIdle {label} returns paused state to idle",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": kwargs}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "PASS",
            "reencrypt-operation-envelope-doc",
            "returnReEncryptIdle operation envelopes must lower to RETIDLE_req on the selected range.",
        )
        yield Probe(
            f"returnReEncryptIdle {label} rejects stale paused state",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": kwargs}, "output": {"return": {"ReEncryptState": "PAUSED"}}}],
            "FAIL",
            "reencrypt-operation-envelope-doc",
            "Ignoring the returnReEncryptIdle operation envelope leaves stale ReEncryptState accepted.",
        )
    for label, kwargs in (
        ("policy", {"policy": {"rangeId": 1, "request": "START_req"}, "authAs": ("Admin1", "new")}),
        ("config", {"config": {"band": 1, "reencryptRequest": "START_req"}, "authAs": ("Admin1", "new")}),
        ("request", {"request": {"reencrypt": {"range": 1, "request": "START_req"}}, "authAs": ("Admin1", "new")}),
    ):
        context = locking_admin_open() + [
            {"input": {"function": "setReEncryptRequest", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setReEncryptRequest {label} envelope moves state to pending",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
            "PASS",
            "locking-wrapper",
            "ReEncrypt request wrappers may carry range/request selectors inside policy/config/request envelopes.",
        )
        yield Probe(
            f"setReEncryptRequest {label} envelope rejects stale idle",
            context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
            "FAIL",
            "locking-wrapper",
            "Ignoring a ReEncrypt request envelope leaves stale IDLE state accepted.",
        )
    failed_reencrypt_alias_context = locking_admin_open() + [
        method_record("Get", "0000080200030001", "Locking", return_values=[[{"12": "IDLE"}]]),
        {"input": {"function": "startReEncrypt", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ok": False}}},
    ]
    yield Probe(
        "failed startReEncrypt preserves idle state",
        failed_reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "IDLE"}}}],
        "PASS",
        "locking-wrapper",
        "Failure-shaped ReEncrypt request wrappers should not mutate ReEncrypt state.",
    )
    yield Probe(
        "failed startReEncrypt rejects phantom pending state",
        failed_reencrypt_alias_context + [{"input": {"function": "getReEncryptStatus", "kwargs": {"rangeId": 1, "authAs": ("Admin1", "new")}}, "output": {"return": {"ReEncryptState": "PENDING"}}}],
        "FAIL",
        "locking-wrapper",
            "A failed startReEncrypt wrapper cannot be applied as a successful START_req Set.",
    )

    for alias in (
        "setMBRDoneOnReset",
        "setDoneOnReset",
        "setMBRDOR",
        "setMBRResetDone",
        "markMBRDoneOnReset",
        "setMBRDoneAfterReset",
        "setMBRDoneOnResetTypes",
        "setMBRResetTypes",
    ):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"doneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates MBRControl DoneOnReset",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [1]}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should update MBRControl.DoneOnReset.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl DoneOnReset",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [0]}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must not be ignored before a later MBRControl getter.",
        )
    clear_dor_context = locking_admin_open() + [
        {"input": {"function": "setMBRDoneOnReset", "kwargs": {"doneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        {"input": {"function": "clearMBRDoneOnReset", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "clearMBRDoneOnReset alias clears MBRControl DoneOnReset",
        clear_dor_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": []}}}],
        "PASS",
        "mbr-wrapper",
        "clearMBRDoneOnReset should clear MBRControl.DoneOnReset.",
    )
    yield Probe(
        "clearMBRDoneOnReset alias rejects stale MBRControl DoneOnReset",
        clear_dor_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [1]}}}],
        "FAIL",
        "mbr-wrapper",
        "clearMBRDoneOnReset must not be ignored before a later MBRControl getter.",
    )
    for alias in ("configureMBRControl", "updateMBRControl"):
        context = locking_admin_open() + [
            {"input": {"function": alias, "kwargs": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias updates MBRControl composite cells",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True, "Done": True, "DoneOnReset": [1]}}}],
            "PASS",
            "mbr-wrapper",
            f"{alias} should share compact MBRControl Set semantics.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl composite cells",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False, "Done": False, "DoneOnReset": [0]}}}],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must update all supplied MBRControl cells.",
        )
    for label, kwargs in (
        ("policy", {"policy": {"Enabled": True, "Done": True, "DoneOnReset": [1]}, "authAs": ("Admin1", "new")}),
        ("config", {"config": {"enabled": True, "done": True, "doneOnReset": [1]}, "authAs": ("Admin1", "new")}),
        ("state", {"state": {"MBREnable": True, "MBRDone": True, "MBRDoneOnReset": [1]}, "authAs": ("Admin1", "new")}),
        ("control", {"control": {"Enabled": True, "Done": True, "DoneOnReset": [1]}, "authAs": ("Admin1", "new")}),
        ("setMBR operation command", {"operation": {"command": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}}),
        ("setMBR operation target command", {"operation": {"target": {"table": "MBRControl"}, "command": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}}),
        ("setMBR operationRequest command", {"operationRequest": {"command": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}}),
        ("setMBR command", {"command": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}),
        ("setMBR action", {"action": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}),
        ("request policy", {"request": {"policy": {"enabled": True, "done": True, "resetTypes": [1]}}, "authAs": ("Admin1", "new")}),
        ("mbrControlRequest", {"mbrControlRequest": {"values": {"Enabled": True, "Done": True, "DoneOnReset": [1], "authAs": ("Admin1", "new")}}}),
        ("mbrRequest", {"mbrRequest": {"control": {"enabled": True, "done": True, "doneOnReset": [1]}, "authAs": ("Admin1", "new")}}),
        ("bootRequest", {"bootRequest": {"state": {"MBREnable": True, "MBRDone": True, "MBRDoneOnReset": [1]}, "authAs": ("Admin1", "new")}}),
    ):
        context = locking_admin_open() + [
            {"input": {"function": "setMBR" if label.startswith("setMBR ") else "setMBRControl", "kwargs": kwargs}, "output": {"return": True}},
        ]
        tag = "mbr-operation-envelope-doc" if label.startswith("setMBR ") else "mbr-wrapper"
        yield Probe(
            f"setMBRControl {label} envelope updates cells",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": True, "Done": True, "DoneOnReset": [1]}}}],
            "PASS",
            tag,
            "MBRControl wrappers may carry official cells inside bounded policy/config/state/control envelopes.",
        )
        yield Probe(
            f"setMBRControl {label} envelope rejects stale cells",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"Enabled": False, "Done": False, "DoneOnReset": [0]}}}],
            "FAIL",
            tag,
            "Ignoring the MBRControl envelope leaves stale Enabled/Done/DoneOnReset state accepted.",
        )
    for label, kwargs in (
        ("policy resetTypes", {"policy": {"resetTypes": [1]}, "authAs": ("Admin1", "new")}),
        ("config DOR", {"config": {"DOR": [1]}, "authAs": ("Admin1", "new")}),
        ("request reset", {"request": {"reset": {"doneOnReset": [1]}}, "authAs": ("Admin1", "new")}),
    ):
        context = locking_admin_open() + [
            {"input": {"function": "setMBRDoneOnReset", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setMBRDoneOnReset {label} envelope updates reset list",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [1]}}}],
            "PASS",
            "mbr-wrapper",
            "Dedicated MBR DoneOnReset wrappers may carry the reset-type list inside policy/config/request envelopes.",
        )
        yield Probe(
            f"setMBRDoneOnReset {label} envelope rejects stale reset list",
            context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {"DoneOnReset": [0]}}}],
            "FAIL",
            "mbr-wrapper",
            "A missed DoneOnReset envelope cannot leave the default reset list observable.",
        )
    mbr_done_on_reset_getter_context = locking_admin_open() + [
        set_values("", "MBRControl", {3: [0]}),
    ]
    for alias in ("getMBRDoneOnReset", "readMBRDoneOnReset", "fetchMBRDoneOnReset", "getDoneOnReset", "getMBRDOR", "readMBRDOR", "fetchMBRDOR", "getMBRResetTypes", "isMBRDoneOnReset"):
        yield Probe(
            f"{alias} alias reads MBRControl DoneOnReset",
            mbr_done_on_reset_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {"DoneOnReset": [0]})],
            "PASS",
            "mbr-wrapper",
            f"{alias} should lower to a bounded MBRControl.DoneOnReset Get.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl DoneOnReset",
            mbr_done_on_reset_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {"DoneOnReset": []})],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must compare against tracked MBRControl.DoneOnReset.",
        )
        yield Probe(
            f"{alias} alias rejects Boolean-only DoneOnReset",
            mbr_done_on_reset_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, True)],
            "FAIL",
            "mbr-wrapper",
            f"{alias} returns a DoneOnReset reset-type list, not a literal Boolean success flag.",
        )
        yield Probe(
            f"{alias} alias rejects list-wrapped Boolean DoneOnReset",
            mbr_done_on_reset_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, [True])],
            "FAIL",
            "mbr-wrapper",
            f"{alias} returns a reset-type list; Boolean elements must not be coerced to reset type 0.",
        )
    for return_key in ("resetTypes", "types", "resetEvents", "reset_on", "resetList"):
        yield Probe(
            f"getMBRControl {return_key} return-field alias reports DoneOnReset",
            mbr_done_on_reset_getter_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {return_key: [0]}}}],
            "PASS",
            "mbr-wrapper",
            f"`{return_key}` is a bounded MBRControl.DoneOnReset return-field alias.",
        )
        yield Probe(
            f"getMBRControl {return_key} return-field alias rejects stale DoneOnReset",
            mbr_done_on_reset_getter_context + [{"input": {"function": "getMBRControl", "kwargs": {"authAs": ("Admin1", "new")}}, "output": {"return": {return_key: [3]}}}],
            "FAIL",
            "mbr-wrapper",
            f"`{return_key}` must compare against tracked MBRControl.DoneOnReset.",
        )
    mbr_control_getter_context = locking_admin_open() + [
        set_values("", "MBRControl", {1: True, 2: True, 3: [1]}),
    ]
    for alias in ("readMBRControl", "fetchMBRControl", "queryMBRControl"):
        yield Probe(
            f"{alias} alias reads MBRControl composite state",
            mbr_control_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {"Enabled": True, "Done": True, "DoneOnReset": [1]})],
            "PASS",
            "mbr-wrapper",
            f"{alias} should lower to MBRControl.Get and compare known cells.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl composite state",
            mbr_control_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {"Enabled": False, "Done": False, "DoneOnReset": [0]})],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must compare against tracked MBRControl state.",
        )
    for alias, column, current, stale in (
        ("readMBREnabled", "Enabled", True, False),
        ("fetchMBREnabled", "Enabled", True, False),
        ("readMBRDone", "Done", True, False),
        ("fetchMBRDone", "Done", True, False),
        ("readMBRComplete", "Done", True, False),
        ("fetchMBRComplete", "Done", True, False),
    ):
        yield Probe(
            f"{alias} alias reads MBRControl {column}",
            mbr_control_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {column: current})],
            "PASS",
            "mbr-wrapper",
            f"{alias} should lower to the bounded MBRControl.{column} Get.",
        )
        yield Probe(
            f"{alias} alias rejects stale MBRControl {column}",
            mbr_control_getter_context + [function_record(alias, [], {"authAs": ("Admin1", "new")}, {column: stale})],
            "FAIL",
            "mbr-wrapper",
            f"{alias} must compare against tracked MBRControl.{column}.",
        )

    data_removal_alias_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        {"input": {"function": "setDataRemovalMechanism", "kwargs": {"mechanism": 2, "authAs": ("SID", "new")}}, "output": {"return": True}},
    ]
    yield Probe(
        "setDataRemovalMechanism alias feeds later get",
        data_removal_alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 2}}}],
        "PASS",
        "data-removal-wrapper",
        "DataRemovalMechanism helper aliases should update and observe ActiveDataRemovalMechanism.",
    )
    yield Probe(
        "setDataRemovalMechanism alias rejects stale mechanism",
        data_removal_alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 1}}}],
        "FAIL",
        "data-removal-wrapper",
        "Ignoring the helper Set would permit a stale ActiveDataRemovalMechanism observation.",
    )
    yield Probe(
        "getDataRemovalMechanism alias accepts mechanism field",
        data_removal_alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"mechanism": 2}}}],
        "PASS",
        "data-removal-wrapper",
        "mechanism is a bounded SDK-style alias for ActiveDataRemovalMechanism.",
    )
    yield Probe(
        "getDataRemovalMechanism alias rejects stale mechanism field",
        data_removal_alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"mechanism": 1}}}],
        "FAIL",
        "data-removal-wrapper",
        "mechanism must still compare against tracked ActiveDataRemovalMechanism.",
    )
    for alias, return_key in (
        ("getDataRemovalMechanism", "activeMechanism"),
        ("getDataRemovalMechanism", "removalMechanism"),
        ("getDataRemovalMode", "dataRemovalMode"),
        ("getDataRemovalMethod", "dataRemovalMethod"),
        ("fetchDataRemoval", "selectedMechanism"),
        ("fetchDataRemoval", "currentMechanism"),
        ("getDataRemovalMode", "mode"),
        ("getDataRemovalMethod", "method"),
    ):
        yield Probe(
            f"{alias} {return_key} return-field alias accepts current mechanism",
            data_removal_alias_context + [{"input": {"function": alias, "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {return_key: 2}}}],
            "PASS",
            "data-removal-wrapper",
            f"{return_key} is a bounded return field for DataRemovalMechanism.ActiveDataRemovalMechanism.",
        )
        yield Probe(
            f"{alias} {return_key} return-field alias rejects stale mechanism",
            data_removal_alias_context + [{"input": {"function": alias, "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {return_key: 1}}}],
            "FAIL",
            "data-removal-wrapper",
            f"{return_key} must compare against tracked ActiveDataRemovalMechanism.",
        )
    yield Probe(
        "getDataRemovalMechanism alias rejects Boolean-only mechanism",
        data_removal_alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": True}}],
        "FAIL",
        "data-removal-wrapper",
        "DataRemovalMechanism Get returns a mechanism enum cell, not a literal Boolean success flag.",
    )
    for alias in (
        "eraseData",
        "dataErase",
        "startDataErase",
        "beginDataErase",
        "setDataRemoval",
        "setActiveDataRemovalMechanism",
        "selectDataRemovalMechanism",
        "chooseDataRemovalMechanism",
        "updateDataRemovalMechanism",
        "putDataRemovalMechanism",
        "configureDataRemoval",
        "configureDataRemovalMechanism",
        "setDataRemovalMode",
        "setDataRemovalMethod",
        "startDataRemovalOperation",
        "beginDataRemoval",
        "sanitizeData",
        "secureEraseData",
    ):
        alias_context = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            {"input": {"function": alias, "kwargs": {"mechanism": 2, "authAs": ("SID", "new")}}, "output": {"return": True}},
        ]
        yield Probe(
            f"{alias} alias feeds later get",
            alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 2}}}],
            "PASS",
            "data-removal-wrapper",
            f"{alias} should update DataRemovalMechanism.ActiveDataRemovalMechanism.",
        )
        yield Probe(
            f"{alias} alias rejects stale mechanism",
            alias_context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 1}}}],
            "FAIL",
            "data-removal-wrapper",
            f"{alias} must not be ignored before a later DataRemovalMechanism Get.",
        )
    for label, kwargs in (
        ("policy", {"policy": {"mechanism": 2}, "authAs": ("SID", "new")}),
        ("config", {"config": {"ActiveDataRemovalMechanism": 2}, "authAs": ("SID", "new")}),
        ("request", {"request": {"dataRemoval": {"mechanism": 2}}, "authAs": ("SID", "new")}),
        ("request values", {"request": {"values": {"ActiveDataRemovalMechanism": 2, "authAs": ("SID", "new")}}}),
        ("policy request values", {"policy": {"request": {"values": {"mechanism": 2, "authAs": ("SID", "new")}}}}),
        ("request activeDataRemoval", {"request": {"activeDataRemoval": {"mechanism": 2}}, "authAs": ("SID", "new")}),
        ("request target command", {"request": {"target": {"table": "DataRemovalMechanism"}, "command": {"ActiveDataRemovalMechanism": 2}, "authAs": ("SID", "new")}}),
        ("operation target removal", {"operation": {"target": {"table": "DataRemovalMechanism"}, "dataRemoval": {"mechanism": 2}, "authAs": ("SID", "new")}}),
        ("config target action", {"config": {"target": {"table": "DataRemovalMechanism"}, "action": 2, "authAs": ("SID", "new")}}),
        ("policy operation active", {"policy": {"operation": {"activeDataRemoval": {"mechanism": 2}}, "authAs": ("SID", "new")}}),
        ("dataRemovalRequest values", {"dataRemovalRequest": {"values": {"mechanism": 2, "authAs": ("SID", "new")}}}),
        ("removalRequest values", {"removalRequest": {"values": {"mechanism": 2, "authAs": ("SID", "new")}}}),
        ("adminRequest values", {"adminRequest": {"values": {"mechanism": 2, "authAs": ("SID", "new")}}}),
    ):
        context = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            {"input": {"function": "setDataRemovalMechanism", "kwargs": kwargs}, "output": {"return": True}},
        ]
        yield Probe(
            f"setDataRemovalMechanism {label} envelope feeds later get",
            context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 2}}}],
            "PASS",
            "data-removal-nested-envelope-doc" if " " in label else "data-removal-wrapper",
            "DataRemovalMechanism setters may carry the active mechanism inside policy/config/request envelopes.",
        )
        yield Probe(
            f"setDataRemovalMechanism {label} envelope rejects stale get",
            context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": {"authAs": ("SID", "new")}}, "output": {"return": {"ActiveDataRemovalMechanism": 1}}}],
            "FAIL",
            "data-removal-nested-envelope-doc" if " " in label else "data-removal-wrapper",
            "Ignoring a DataRemovalMechanism envelope permits stale active mechanism observations.",
        )
    data_removal_operation_set = {"operation": {"target": {"table": "DataRemovalMechanism"}, "command": {"ActiveDataRemovalMechanism": 2, "authAs": ("SID", "new")}}}
    for label, get_kwargs in (
        ("operation", {"operation": {"target": {"table": "DataRemovalMechanism"}, "command": {"authAs": ("SID", "new")}}}),
        ("operationRequest", {"operationRequest": {"target": {"table": "DataRemovalMechanism"}, "command": {"authAs": ("SID", "new")}}}),
        ("command", {"command": {"authAs": ("SID", "new")}}),
        ("action", {"action": {"authAs": ("SID", "new")}}),
    ):
        context = owned_admin_context() + [
            {"input": {"function": "setDataRemovalMechanism", "kwargs": data_removal_operation_set}, "output": {"return": True}},
        ]
        yield Probe(
            f"getDataRemovalMechanism {label} envelope reports current mechanism",
            context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": get_kwargs}, "output": {"return": {"ActiveDataRemovalMechanism": 2}}}],
            "PASS",
            "data-removal-operation-envelope-doc",
            "DataRemovalMechanism operation-style getters must preserve wrapper auth and must not treat target.table as a CellBlock Table component.",
        )
        yield Probe(
            f"getDataRemovalMechanism {label} envelope rejects stale mechanism",
            context + [{"input": {"function": "getDataRemovalMechanism", "kwargs": get_kwargs}, "output": {"return": {"ActiveDataRemovalMechanism": 1}}}],
            "FAIL",
            "data-removal-operation-envelope-doc",
            "Operation-style DataRemovalMechanism getters must compare against tracked ActiveDataRemovalMechanism state.",
        )
    official_data_removal_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        set_values("", "DataRemovalMechanism", {1: 2}),
    ]
    for alias in (
        "getActiveDataRemovalMechanism",
        "readDataRemovalMechanism",
        "fetchDataRemovalMechanism",
        "queryDataRemovalMechanism",
        "loadDataRemovalMechanism",
        "readActiveDataRemovalMechanism",
        "fetchActiveDataRemovalMechanism",
        "queryActiveDataRemovalMechanism",
        "loadActiveDataRemovalMechanism",
        "getDataRemovalMode",
        "getDataRemovalMethod",
        "getDataRemoval",
        "readDataRemoval",
        "fetchDataRemoval",
        "isDataRemovalActive",
    ):
        yield Probe(
            f"{alias} alias reads ActiveDataRemovalMechanism",
            official_data_removal_context + [function_record(alias, [], {"authAs": ("SID", "new")}, {"ActiveDataRemovalMechanism": 2})],
            "PASS",
            "data-removal-wrapper",
            f"{alias} should lower to a bounded DataRemovalMechanism Get.",
        )
        yield Probe(
            f"{alias} alias rejects stale ActiveDataRemovalMechanism",
            official_data_removal_context + [function_record(alias, [], {"authAs": ("SID", "new")}, {"ActiveDataRemovalMechanism": 1})],
            "FAIL",
            "data-removal-wrapper",
            f"{alias} must compare against tracked ActiveDataRemovalMechanism state.",
        )
        yield Probe(
            f"{alias} alias accepts scalar ActiveDataRemovalMechanism",
            official_data_removal_context + [function_record(alias, [], {"authAs": ("SID", "new")}, 2)],
            "PASS",
            "data-removal-wrapper",
            f"{alias} may expose the single ActiveDataRemovalMechanism cell as a scalar enum.",
        )
        yield Probe(
            f"{alias} alias rejects stale scalar ActiveDataRemovalMechanism",
            official_data_removal_context + [function_record(alias, [], {"authAs": ("SID", "new")}, 1)],
            "FAIL",
            "data-removal-wrapper",
            f"{alias} scalar enum payload must still match tracked ActiveDataRemovalMechanism state.",
        )
        yield Probe(
            f"{alias} alias rejects Boolean-only ActiveDataRemovalMechanism",
            official_data_removal_context + [function_record(alias, [], {"authAs": ("SID", "new")}, True)],
            "FAIL",
            "data-removal-wrapper",
            f"{alias} returns the mechanism enum cell, not a literal Boolean success flag.",
        )
    range_locks_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000080200030001", "Locking", {7: False, 8: True}),
    ]
    yield Probe(
        "getRangeLocks alias reads tracked locks",
        range_locks_context + [function_record("getRangeLocks", [1], {"authAs": ("Admin1", "new")}, {"ReadLocked": False, "WriteLocked": True})],
        "PASS",
        "locking-wrapper",
        "getRangeLocks should lower to a composite ReadLocked/WriteLocked Get.",
    )
    yield Probe(
        "getRangeLocks alias rejects stale locks",
        range_locks_context + [function_record("getRangeLocks", [1], {"authAs": ("Admin1", "new")}, {"ReadLocked": True, "WriteLocked": False})],
        "FAIL",
        "locking-wrapper",
        "getRangeLocks must compare both lock cells against tracked state.",
    )
    getacl_required_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
    ]
    yield Probe(
        "getACL required envelope resolves association",
        getacl_required_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["ACE_00000003", "ACE_0003D001"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "getACL required-envelope arguments should resolve to InvokingID/MethodID before exact ACL comparison.",
    )
    yield Probe(
        "getACL required envelope rejects incomplete ACL",
        getacl_required_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["ACE_0003D001"]}},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "getACL exact ACL comparison must not accept missing default ACE refs.",
    )
    yield Probe(
        "getACL accepts full UID ACE refs",
        getacl_required_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "GetACL ACE uidrefs may be returned as full 8-byte UID hex values.",
    )
    yield Probe(
        "getACL accepts bytes-repr ACE refs",
        getacl_required_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03'", "b'\\x00\\x00\\x00\\x00\\x00\\x03\\xd0\\x01'"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "GetACL ACE uidrefs may be returned as Python bytes repr strings.",
    )
    yield Probe(
        "getACL full UID ACE refs reject incomplete ACL",
        getacl_required_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["000000000003D001"]}},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "Full UID ACE refs must still preserve exact ACL membership.",
    )
    for alias in (
        "readACL",
        "fetchACL",
        "queryACL",
        "listACL",
        "getObjectACL",
        "getMethodACL",
        "getAssociationACL",
        "readAssociationACL",
        "fetchAssociationACL",
        "queryAssociationACL",
        "listAssociationACL",
        "getAccessControlList",
        "readAccessControlList",
        "fetchAccessControlList",
        "queryAccessControlList",
        "listAccessControlList",
        "getACEList",
        "readACEList",
        "queryACEList",
        "loadACEList",
        "getAclEntries",
        "readAclEntries",
        "readAceEntries",
        "queryAclEntries",
        "queryAceEntries",
        "loadAclEntries",
        "loadAceEntries",
        "fetchAclEntries",
        "fetchAceEntries",
        "fetchAceList",
        "readObjectACL",
        "fetchObjectACL",
        "queryObjectACL",
        "readMethodACL",
        "fetchMethodACL",
        "queryMethodACL",
        "getACLForObject",
        "readACLForObject",
        "fetchACLForObject",
        "queryACLForObject",
        "loadACLForObject",
        "getACLForMethod",
        "readACLForMethod",
        "fetchACLForMethod",
        "queryACLForMethod",
        "loadACLForMethod",
        "getObjectMethodACL",
        "readObjectMethodACL",
        "fetchObjectMethodACL",
        "queryObjectMethodACL",
        "loadObjectMethodACL",
        "getMethodAccessControl",
        "readMethodAccessControl",
        "fetchMethodAccessControl",
        "queryMethodAccessControl",
        "loadMethodAccessControl",
        "getObjectAccessControl",
        "readObjectAccessControl",
        "fetchObjectAccessControl",
        "queryObjectAccessControl",
        "loadObjectAccessControl",
        "getAssociationAccessControl",
        "readAssociationAccessControl",
        "fetchAssociationAccessControl",
        "queryAssociationAccessControl",
        "loadAssociationAccessControl",
        "getAccessControlForObject",
        "readAccessControlForObject",
        "fetchAccessControlForObject",
        "queryAccessControlForObject",
        "loadAccessControlForObject",
        "getAccessControlForMethod",
        "readAccessControlForMethod",
        "fetchAccessControlForMethod",
        "queryAccessControlForMethod",
        "loadAccessControlForMethod",
        "listACEs",
        "listAceEntries",
    ):
        yield Probe(
            f"{alias} alias resolves GetACL association",
            getacl_required_context
            + [
                {
                    "input": {"function": alias, "args": ["Locking_Range1", "Get"], "kwargs": {"authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["ACE_00000003", "ACE_0003D001"]}},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            f"{alias} is a narrow ACL-list reader and should share GetACL association semantics.",
        )
        yield Probe(
            f"{alias} alias rejects incomplete exact ACL",
            getacl_required_context
            + [
                {
                    "input": {"function": alias, "args": ["Locking_Range1", "Get"], "kwargs": {"authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["ACE_0003D001"]}},
                }
            ],
            "FAIL",
            "accesscontrol-wrapper",
            f"{alias} must not fall through as UNKNOWN or skip GetACL exact ACL membership.",
        )
    acl_mutation_uid_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record(
            "addACE",
            [],
            {"required": {"object": "Locking_Range1", "method": "Get"}, "ace": "0000000000039000", "authAs": ("Admin1", "new")},
            True,
        ),
    ]
    yield Probe(
        "addACE full UID updates later getACL",
        acl_mutation_uid_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "AddACE ACE arguments may be full 8-byte UID hex values and must affect subsequent GetACL state.",
    )
    yield Probe(
        "addACE full UID rejects stale later getACL",
        acl_mutation_uid_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "After AddACE succeeds, later GetACL cannot omit the dynamically added ACE.",
    )
    for alias in (
        "appendACE",
        "appendAclEntry",
        "addAclEntry",
        "grantACE",
        "grantAcl",
        "addAccessControlEntry",
        "appendAccessControlEntry",
        "grantAccessControlEntry",
        "addACEToACL",
        "appendACEToACL",
        "grantACEToACL",
        "addAccessControlACE",
        "addACLForObject",
        "appendACLForObject",
        "grantACLForObject",
        "addACEForObject",
        "appendACEForObject",
        "grantACEForObject",
        "addACLForMethod",
        "appendACLForMethod",
        "grantACLForMethod",
        "addACEForMethod",
        "appendACEForMethod",
        "grantACEForMethod",
        "addObjectMethodACE",
        "appendObjectMethodACE",
        "grantObjectMethodACE",
        "addObjectAccessControlEntry",
        "grantObjectAccessControlEntry",
        "appendObjectAccessControlEntry",
        "addMethodAccessControlEntry",
        "grantMethodAccessControlEntry",
        "appendMethodAccessControlEntry",
    ):
        alias_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(alias, ["Locking_Range1", "Get", "0000000000039000"], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{alias} alias updates later getACL",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            f"{alias} should share AddACE mutation semantics.",
        )
        yield Probe(
            f"{alias} alias rejects stale later getACL",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "FAIL",
            "accesscontrol-wrapper",
            f"{alias} must not fall through as UNKNOWN or lose AddACE side effects.",
        )
    acl_mutation_bytes_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record(
            "addACE",
            [],
            {"required": {"object": "Locking_Range1", "method": "Get"}, "ace": "b'\\x00\\x00\\x00\\x00\\x00\\x03\\x90\\x00'", "authAs": ("Admin1", "new")},
            True,
        ),
    ]
    yield Probe(
        "addACE bytes-repr updates later getACL",
        acl_mutation_bytes_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "AddACE ACE arguments may be Python bytes repr strings and must affect subsequent GetACL state.",
    )
    setacl_replacement_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record(
            "setACL",
            [],
            {
                "required": {"object": "Locking_Range1", "method": "Get"},
                "ACL": ["0000000000000003", "0000000000039000"],
                "authAs": ("Admin1", "new"),
            },
            True,
        ),
    ]
    yield Probe(
        "setACL replaces later getACL",
        setacl_replacement_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "0000000000039000"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "SetACL is a full AccessControl ACL replacement and later GetACL must reflect the new ACE list.",
    )
    yield Probe(
        "setACL rejects pre-replacement getACL",
        setacl_replacement_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "After SetACL succeeds, later GetACL cannot report the old documented ACL.",
    )
    nested_setacl_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record(
            "setACL",
            [],
            {
                "policy": {
                    "request": {
                        "values": {
                            "object": "Locking_Range1",
                            "method": "Get",
                            "acl": ["000000000003D001"],
                            "authAs": ("Admin1", "new"),
                        }
                    }
                }
            },
            True,
        ),
    ]
    yield Probe(
        "setACL policy request values replaces later getACL",
        nested_setacl_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["000000000003D001"]}},
            }
        ],
        "PASS",
        "accesscontrol-nested-mutation-doc",
        "Nested SetACL policy/request/value envelopes must preserve object, method, and ACL replacement list.",
    )
    yield Probe(
        "setACL policy request values rejects old later getACL",
        nested_setacl_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
            }
        ],
        "FAIL",
        "accesscontrol-nested-mutation-doc",
        "After nested SetACL succeeds, later GetACL cannot retain the old documented ACL.",
    )
    for alias in (
        "replaceACL",
        "updateACL",
        "setAccessControlList",
        "replaceAccessControlList",
        "setObjectACL",
        "setAssociationACL",
        "replaceAccessControlACL",
        "updateAccessControlACL",
        "putAccessControlList",
        "updateAccessControlList",
        "replaceObjectACL",
        "updateObjectACL",
        "replaceMethodACL",
        "updateMethodACL",
        "setACLForObject",
        "replaceACLForObject",
        "updateACLForObject",
        "putACLForObject",
        "setACLForMethod",
        "replaceACLForMethod",
        "updateACLForMethod",
        "putACLForMethod",
        "setObjectMethodACL",
        "replaceObjectMethodACL",
        "updateObjectMethodACL",
        "putObjectMethodACL",
        "setObjectAccessControl",
        "replaceObjectAccessControl",
        "updateObjectAccessControl",
        "putObjectAccessControl",
        "setMethodAccessControl",
        "replaceMethodAccessControl",
        "updateMethodAccessControl",
        "putMethodAccessControl",
    ):
        alias_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(alias, ["Locking_Range1", "Get", ["0000000000000003", "0000000000039000"]], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{alias} alias replaces later getACL",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "0000000000039000"]}},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            f"{alias} should share SetACL replacement semantics.",
        )
        yield Probe(
            f"{alias} alias rejects old later getACL",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "FAIL",
            "accesscontrol-wrapper",
            f"{alias} must not fall through as UNKNOWN or lose SetACL replacement side effects.",
        )
    for alias in (
        "deleteACE",
        "deleteAclEntry",
        "dropACE",
        "revokeACE",
        "revokeAcl",
        "removeAccessControlEntry",
        "deleteAccessControlEntry",
        "revokeAccessControlEntry",
        "removeACEFromACL",
        "deleteACEFromACL",
        "revokeACEFromACL",
        "removeAccessControlACE",
        "removeACLForObject",
        "deleteACLForObject",
        "revokeACLForObject",
        "removeACEForObject",
        "deleteACEForObject",
        "revokeACEForObject",
        "removeACLForMethod",
        "deleteACLForMethod",
        "revokeACLForMethod",
        "removeACEForMethod",
        "deleteACEForMethod",
        "revokeACEForMethod",
        "removeObjectMethodACE",
        "deleteObjectMethodACE",
        "revokeObjectMethodACE",
        "removeObjectAccessControlEntry",
        "revokeObjectAccessControlEntry",
        "deleteObjectAccessControlEntry",
        "removeMethodAccessControlEntry",
        "revokeMethodAccessControlEntry",
        "deleteMethodAccessControlEntry",
    ):
        alias_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record("addACE", [], {"required": {"object": "Locking_Range1", "method": "Get"}, "ace": "0000000000039000", "authAs": ("Admin1", "new")}, True),
            function_record(alias, ["Locking_Range1", "Get", "0000000000039000"], {"authAs": ("Admin1", "new")}, True),
        ]
        yield Probe(
            f"{alias} alias removes ACE from later getACL",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "PASS",
            "accesscontrol-wrapper",
            f"{alias} should share RemoveACE mutation semantics.",
        )
        yield Probe(
            f"{alias} alias rejects retained removed ACE",
            alias_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
                }
            ],
            "FAIL",
            "accesscontrol-wrapper",
            f"{alias} must not fall through as UNKNOWN or retain the removed ACE.",
        )
    nested_removeace_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record(
            "addACE",
            [],
            {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")},
            True,
        ),
        function_record(
            "removeACE",
            [],
            {
                "policy": {
                    "request": {
                        "values": {
                            "object": "Locking_Range1",
                            "method": "Get",
                            "ace": "0000000000039000",
                            "authAs": ("Admin1", "new"),
                        }
                    }
                }
            },
            True,
        ),
    ]
    yield Probe(
        "removeACE policy request values removes ACE from later getACL",
        nested_removeace_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
            }
        ],
        "PASS",
        "accesscontrol-nested-mutation-doc",
        "Nested RemoveACE policy/request/value envelopes must preserve object, method, and ACE argument.",
    )
    yield Probe(
        "removeACE policy request values rejects retained removed ACE",
        nested_removeace_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
            }
        ],
        "FAIL",
        "accesscontrol-nested-mutation-doc",
        "After nested RemoveACE succeeds, later GetACL cannot retain the removed ACE.",
    )
    for label, payload in (
        ("operation command", {"operation": {"command": {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")}}}),
        ("operation target command", {"operation": {"target": {"object": "Locking_Range1", "method": "Get"}, "command": {"ace": "0000000000039000", "authAs": ("Admin1", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"object": "Locking_Range1", "method": "Get"}, "command": {"ace": "0000000000039000", "authAs": ("Admin1", "new")}}}),
    ):
        remove_operation_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(
                "addACE",
                [],
                {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")},
                True,
            ),
            function_record("removeACE", [], payload, True),
        ]
        yield Probe(
            f"removeACE {label} removes ACE from later getACL",
            remove_operation_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "PASS",
            "accesscontrol-nested-mutation-doc",
            "RemoveACE operation envelopes must preserve object, method, and ACE arguments.",
        )
        yield Probe(
            f"removeACE {label} rejects retained removed ACE",
            remove_operation_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
                }
            ],
            "FAIL",
            "accesscontrol-nested-mutation-doc",
            "After operation-envelope RemoveACE succeeds, later GetACL cannot retain the removed ACE.",
        )
    for payload_key in ("accessControlRequest", "ACLRequest"):
        add_request_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(
                "addACE",
                [],
                {payload_key: {"values": {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")}}},
                True,
            ),
        ]
        yield Probe(
            f"addACE {payload_key} values adds ACE to later getACL",
            add_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
                }
            ],
            "PASS",
            "accesscontrol-request-values-mutation-doc",
            f"{payload_key}.values AddACE envelopes must preserve object, method, and ACE.",
        )
        yield Probe(
            f"addACE {payload_key} values rejects stale getACL",
            add_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "FAIL",
            "accesscontrol-request-values-mutation-doc",
            f"After {payload_key}.values AddACE succeeds, later GetACL cannot omit the added ACE.",
        )
        set_request_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(
                "setACL",
                [],
                {payload_key: {"values": {"object": "Locking_Range1", "method": "Get", "acl": ["0000000000039000"], "authAs": ("Admin1", "new")}}},
                True,
            ),
        ]
        yield Probe(
            f"setACL {payload_key} values replaces later getACL",
            set_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000039000"]}},
                }
            ],
            "PASS",
            "accesscontrol-request-values-mutation-doc",
            f"{payload_key}.values SetACL envelopes must preserve the replacement ACL list.",
        )
        yield Probe(
            f"setACL {payload_key} values rejects stale getACL",
            set_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "FAIL",
            "accesscontrol-request-values-mutation-doc",
            f"After {payload_key}.values SetACL succeeds, later GetACL cannot retain the old ACL.",
        )
        remove_request_context = activated_locking_context() + [
            start_session(LOCKING_SP, ADMIN1, "new"),
            function_record(
                "addACE",
                [],
                {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")},
                True,
            ),
            function_record(
                "removeACE",
                [],
                {payload_key: {"values": {"object": "Locking_Range1", "method": "Get", "ace": "0000000000039000", "authAs": ("Admin1", "new")}}},
                True,
            ),
        ]
        yield Probe(
            f"removeACE {payload_key} values removes ACE from later getACL",
            remove_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001"]}},
                }
            ],
            "PASS",
            "accesscontrol-request-values-mutation-doc",
            f"{payload_key}.values RemoveACE envelopes must preserve the removed ACE.",
        )
        yield Probe(
            f"removeACE {payload_key} values rejects retained removed ACE",
            remove_request_context
            + [
                {
                    "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                    "output": {"return": {"ACL": ["0000000000000003", "000000000003D001", "0000000000039000"]}},
                }
            ],
            "FAIL",
            "accesscontrol-request-values-mutation-doc",
            f"After {payload_key}.values RemoveACE succeeds, later GetACL cannot retain the removed ACE.",
        )
    setacl_positional_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("setACL", ["Locking_Range1", "Get", ["0000000000000003", "0000000000039000"]], {"authAs": ("Admin1", "new")}, True),
    ]
    yield Probe(
        "setACL positional full UID replaces later getACL",
        setacl_positional_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003", "0000000000039000"]}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "SetACL positional wrappers should parse InvokingID, MethodID, and ACL list in official argument order.",
    )
    setacl_empty_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("setACL", [], {"required": {"object": "Locking_Range1", "method": "Get"}, "ACL": [], "authAs": ("Admin1", "new")}, True),
    ]
    yield Probe(
        "setACL empty ACL replaces later getACL",
        setacl_empty_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": []}},
            }
        ],
        "PASS",
        "accesscontrol-wrapper",
        "SetACL can replace an AccessControl ACL with an empty ACE list.",
    )
    yield Probe(
        "setACL empty ACL rejects stale default ACE",
        setacl_empty_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": {"ACL": ["0000000000000003"]}},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "After SetACL replaces the ACL with empty, later GetACL cannot retain default ACE entries.",
    )
    yield Probe(
        "setACL empty ACL rejects boolean ACL payload",
        setacl_empty_context
        + [
            {
                "input": {"function": "getACL", "kwargs": {"required": {"object": "Locking_Range1", "method": "Get"}, "authAs": ("Admin1", "new")}},
                "output": {"return": [True]},
            }
        ],
        "FAIL",
        "accesscontrol-wrapper",
        "An empty GetACL result is an empty ACE uidref list; a Boolean list element must not collapse to an empty ACL.",
    )
    def wrap_datastore_deep_payload(payload: dict[str, Any], chain: tuple[str, ...]) -> dict[str, Any]:
        wrapped: dict[str, Any] = payload
        for key in reversed(chain):
            wrapped = {key: wrapped}
        return wrapped

    datastore_deep_chains = (
        ("dataStoreRequest", "byteTableRequest", "window", "values"),
        ("request", "dataStoreRequest", "range", "payload"),
        ("config", "target", "byteWindow", "values"),
        ("policy", "request", "slice", "values"),
        ("values", "dataStoreRequest", "payload", "values"),
        ("operationRequest", "dataRequest", "window", "payload"),
    )
    for index, write_chain in enumerate(datastore_deep_chains):
        read_chain = datastore_deep_chains[-(index + 1)]
        deep_datastore_context = activated_locking_context() + [
            function_record(
                "writeData",
                [],
                wrap_datastore_deep_payload({"user": "Admin1", "bytes": "AABBCCDD", "offset": 2, "authAs": ("Admin1", "new")}, write_chain),
                True,
            )
        ]
        read_payload = wrap_datastore_deep_payload({"user": "Admin1", "offset": 2, "length": 4, "authAs": ("Admin1", "new")}, read_chain)
        yield Probe(
            f"deep DataStore window envelope {index} reads current bytes",
            deep_datastore_context + [function_record("readData", [], read_payload, "AABBCCDD")],
            "PASS",
            "datastore-deep-window-envelope-doc",
            "Deep DataStore byte-window wrappers should preserve offset, length, payload, and auth.",
        )
        yield Probe(
            f"deep DataStore window envelope {index} rejects stale bytes",
            deep_datastore_context + [function_record("readData", [], read_payload, "0000AABB")],
            "FAIL",
            "datastore-deep-window-envelope-doc",
            "After a deep DataStore write wrapper succeeds, a later deep read wrapper cannot return stale bytes.",
        )
    cpin_getter_alias_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000000B00030001", "C_PIN", {6: 1}),
    ]
    yield Probe(
        "getPINTries alias reads tracked Tries",
        cpin_getter_alias_context + [function_record("getPINTries", ["User1"], {"authAs": ("Admin1", "new")}, {"pinTries": 1})],
        "PASS",
        "credential-wrapper",
        "getPINTries should lower to C_PIN.Tries.",
    )
    yield Probe(
        "getPINTries alias rejects stale Tries",
        cpin_getter_alias_context + [function_record("getPINTries", ["User1"], {"authAs": ("Admin1", "new")}, {"pinTries": 0})],
        "FAIL",
        "credential-wrapper",
        "getPINTries must compare against tracked C_PIN.Tries.",
    )
    cpin_min_pin_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        function_record("setMinPINLength", ["User1", 6], {"authAs": ("Admin1", "new")}, True),
    ]
    yield Probe(
        "getMinPINLength alias reads tracked minimum",
        cpin_min_pin_context + [function_record("getMinPINLength", ["User1"], {"authAs": ("Admin1", "new")}, {"minimumPINLength": 6})],
        "PASS",
        "credential-wrapper",
        "getMinPINLength should lower to the tracked C_PIN minimum PIN length policy.",
    )
    yield Probe(
        "getMinPINLength alias rejects stale minimum",
        cpin_min_pin_context + [function_record("getMinPINLength", ["User1"], {"authAs": ("Admin1", "new")}, {"minimumPINLength": 5})],
        "FAIL",
        "credential-wrapper",
        "getMinPINLength must compare against tracked C_PIN minimum PIN length policy.",
    )
    authority_getter_alias_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        set_values("0000000900030001", "Authority", {15: 3, 16: 1}),
    ]
    yield Probe(
        "getUserLimit alias reads tracked Limit",
        authority_getter_alias_context + [function_record("getUserLimit", ["User1"], {"authAs": ("Admin1", "new")}, {"userLimit": 3})],
        "PASS",
        "authority-wrapper",
        "getUserLimit should lower to Authority.Limit.",
    )
    yield Probe(
        "getUserUses alias reads tracked Uses",
        authority_getter_alias_context + [function_record("getUserUses", ["User1"], {"authAs": ("Admin1", "new")}, {"userUses": 1})],
        "PASS",
        "authority-wrapper",
        "getUserUses should lower to Authority.Uses.",
    )
    yield Probe(
        "getUserUses alias rejects stale Uses",
        authority_getter_alias_context + [function_record("getUserUses", ["User1"], {"authAs": ("Admin1", "new")}, {"userUses": 0})],
        "FAIL",
        "authority-wrapper",
        "getUserUses must compare against tracked Authority.Uses.",
    )
    port_locked_alias_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        function_record("setPort", [], {"port": "Port2", "PortLocked": True, "authAs": ("SID", "new")}, True),
    ]
    yield Probe(
        "getPort locked field alias reads PortLocked",
        port_locked_alias_context + [function_record("getPort", ["Port2"], {"authAs": ("SID", "new")}, {"locked": True})],
        "PASS",
        "port-wrapper",
        "locked should be treated as a bounded return alias for PortLocked.",
    )
    for return_key in ("portLock", "lockState", "portLockState", "portState"):
        yield Probe(
            f"getPortLocked {return_key} return-field alias reads PortLocked",
            port_locked_alias_context + [function_record("getPortLocked", ["Port2"], {"authAs": ("SID", "new")}, {return_key: True})],
            "PASS",
            "port-wrapper",
            f"{return_key} is a bounded return field for Port.PortLocked.",
        )
        yield Probe(
            f"getPortLocked {return_key} return-field alias rejects stale PortLocked",
            port_locked_alias_context + [function_record("getPortLocked", ["Port2"], {"authAs": ("SID", "new")}, {return_key: False})],
            "FAIL",
            "port-wrapper",
            f"{return_key} must compare against tracked Port.PortLocked.",
        )
    yield Probe(
        "getPort rejects Boolean-only Port row",
        port_locked_alias_context + [function_record("getPort", ["Port2"], {"authAs": ("SID", "new")}, True)],
        "FAIL",
        "port-wrapper",
        "getPort returns Port row state, not a literal Boolean success flag.",
    )
    yield Probe(
        "getPort rejects status-only Port row",
        port_locked_alias_context + [{"input": {"function": "getPort", "args": ["Port2"], "kwargs": {"authAs": ("SID", "new")}}, "output": {"status": "SUCCESS", "return": "SUCCESS"}}],
        "FAIL",
        "port-wrapper",
        "getPort must return Port row data; a bare SUCCESS token is only call status.",
    )
    for getter in ("readPort", "fetchPort"):
        yield Probe(
            f"{getter} alias reads Port row",
            port_locked_alias_context + [function_record(getter, ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": True})],
            "PASS",
            "port-wrapper",
            f"{getter} should lower to a Port table Get and observe tracked PortLocked state.",
        )
        yield Probe(
            f"{getter} alias rejects stale Port row",
            port_locked_alias_context + [function_record(getter, ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": False})],
            "FAIL",
            "port-wrapper",
            f"{getter} must not ignore tracked PortLocked state.",
        )
        yield Probe(
            f"{getter} rejects Boolean-only Port row",
            port_locked_alias_context + [function_record(getter, ["Port2"], {"authAs": ("SID", "new")}, True)],
            "FAIL",
            "port-wrapper",
            f"{getter} returns Port row data, not a literal Boolean success flag.",
        )
    yield Probe(
        "isPortLocked alias reads PortLocked",
        port_locked_alias_context + [function_record("isPortLocked", ["Port2"], {"authAs": ("SID", "new")}, {"isLocked": True})],
        "PASS",
        "port-wrapper",
        "isPortLocked should lower to Port.PortLocked Get.",
    )
    yield Probe(
        "isPortLocked alias rejects stale PortLocked",
        port_locked_alias_context + [function_record("isPortLocked", ["Port2"], {"authAs": ("SID", "new")}, {"isLocked": False})],
        "FAIL",
        "port-wrapper",
        "isPortLocked must compare against tracked PortLocked state.",
    )
    yield Probe(
        "isPortLocked rejects status-only Boolean payload",
        port_locked_alias_context + [{"input": {"function": "isPortLocked", "args": ["Port2"], "kwargs": {"authAs": ("SID", "new")}}, "output": {"status": "SUCCESS", "return": "SUCCESS"}}],
        "FAIL",
        "port-wrapper",
        "A PortLocked Boolean getter must return the actual Boolean value, not only a repeated SUCCESS status token.",
    )
    for getter in ("getPortLock", "isPortLock", "portLocked", "readPortLock", "getInterfaceLock"):
        yield Probe(
            f"{getter} alias reads PortLocked",
            port_locked_alias_context + [function_record(getter, ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": True})],
            "PASS",
            "port-wrapper",
            f"{getter} should lower to Port.PortLocked Get.",
        )
        yield Probe(
            f"{getter} alias rejects stale PortLocked",
            port_locked_alias_context + [function_record(getter, ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": False})],
            "FAIL",
            "port-wrapper",
            f"{getter} must compare against tracked PortLocked state.",
        )
    for setter, expected_locked in (
        ("lockPort", True),
        ("unlockPort", False),
        ("lockInterface", True),
        ("unlockInterface", False),
        ("lockPortAccess", True),
        ("unlockPortAccess", False),
        ("enablePortLock", True),
        ("disablePortLock", False),
        ("setPortLocked", True),
        ("setPortState", True),
        ("setPortLock", True),
        ("updatePortLocked", True),
        ("putPortLocked", True),
        ("updatePortLock", True),
        ("putPortLock", True),
        ("updatePortState", True),
    ):
        setter_context = owned_admin_context() + [
            start_session(ADMIN_SP, SID, "new"),
            function_record(setter, ["Port2"], {"authAs": ("SID", "new"), "value": expected_locked}, True),
        ]
        yield Probe(
            f"{setter} alias updates PortLocked state",
            setter_context + [function_record("getPort", ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": expected_locked})],
            "PASS",
            "port-wrapper",
            f"{setter} should mutate the bounded Port.PortLocked column.",
        )
        yield Probe(
            f"{setter} alias rejects stale PortLocked",
            setter_context + [function_record("getPort", ["Port2"], {"authAs": ("SID", "new")}, {"PortLocked": not expected_locked})],
            "FAIL",
            "port-wrapper",
            f"{setter} must not leave a stale PortLocked value.",
        )
    port_unlocked_alias_context = owned_admin_context() + [
        start_session(ADMIN_SP, SID, "new"),
        function_record("setPort", [], {"port": "Port2", "PortLocked": False, "authAs": ("SID", "new")}, True),
    ]
    yield Probe(
        "isPortLocked raw false reads unlocked PortLocked",
        port_unlocked_alias_context + [function_record("isPortLocked", ["Port2"], {"authAs": ("SID", "new")}, False)],
        "PASS",
        "port-wrapper",
        "Raw false is a successful Boolean getter result when PortLocked is false.",
    )

    log_wrapper_context = locking_admin_open()
    yield Probe(
        "addLog wrapper boolean success",
        log_wrapper_context + [{"input": {"function": "addLog", "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "PASS",
        "log-wrapper",
        "addLog lowers to Log.AddLog while accepting SDK-style boolean success.",
    )
    yield Probe(
        "addLog wrapper rejects missing data success",
        log_wrapper_context + [{"input": {"function": "addLog", "kwargs": {"log": "Log1", "name": "Entry1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "log-wrapper",
        "Wrapper lowering must not synthesize a missing AddLog Data parameter.",
    )
    yield Probe(
        "addLog wrapper rejects non-empty success result",
        log_wrapper_context + [{"input": {"function": "addLog", "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": ["unexpected"]}}],
        "FAIL",
        "log-wrapper",
        "AddLog wrappers may expose Boolean success, but the backing method result is empty.",
    )
    yield Probe(
        "putLog wrapper boolean success",
        log_wrapper_context + [{"input": {"function": "putLog", "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "PASS",
        "log-wrapper",
        "putLog lowers to Log.AddLog while accepting SDK-style boolean success.",
    )
    yield Probe(
        "putLog wrapper rejects non-empty success result",
        log_wrapper_context + [{"input": {"function": "putLog", "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": ["unexpected"]}}],
        "FAIL",
        "log-wrapper",
        "putLog is an AddLog wrapper and the backing method result is empty.",
    )
    yield Probe(
        "putLog wrapper rejects missing data success",
        log_wrapper_context + [{"input": {"function": "putLog", "kwargs": {"log": "Log1", "name": "Entry1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "log-wrapper",
        "putLog must not synthesize a missing AddLog Data parameter.",
    )
    yield Probe(
        "createLog wrapper accepts three field result",
        log_wrapper_context + [{"input": {"function": "createLog", "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}],
        "PASS",
        "log-wrapper",
        "createLog lowers to LogList.CreateLog and successful responses carry three result fields.",
    )
    yield Probe(
        "createLog wrapper rejects boolean success",
        log_wrapper_context + [{"input": {"function": "createLog", "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "FAIL",
        "log-wrapper",
        "CreateLog successful responses carry three result fields, not a Boolean-only wrapper result.",
    )
    yield Probe(
        "createLog wrapper rejects generic false failure",
        log_wrapper_context + [{"input": {"function": "createLog", "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": False}}],
        "FAIL",
        "log-wrapper",
        "Valid CreateLog may return SUCCESS with three fields or documented insufficient-space/rows statuses, not generic Boolean false failure.",
    )
    yield Probe(
        "createLog wrapper rejects extra result field",
        log_wrapper_context + [{"input": {"function": "createLog", "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": ["LogListUID", "LogTableUID", 8, "extra"]}}],
        "FAIL",
        "log-wrapper",
        "CreateLog successful responses have exactly three fields.",
    )
    log_add_request = {"addLogRequest": {"values": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}}
    log_create_request = {"createLogRequest": {"values": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}}
    log_clear_request = {"clearLogRequest": {"values": {"log": "Log1", "authAs": ("Admin1", "new")}}}
    for name, trajectory, expected, why in (
        (
            "AddLog request envelope preserves required payload",
            log_wrapper_context + [{"input": {"function": "addLog", "kwargs": log_add_request}, "output": {"return": True}}],
            "PASS",
            "AddLog request wrappers must preserve LogEntryName and Data before lowering.",
        ),
        (
            "AddLog request envelope rejects missing Data",
            log_wrapper_context + [{"input": {"function": "addLog", "kwargs": {"addLogRequest": {"values": {"log": "Log1", "name": "Entry1", "authAs": ("Admin1", "new")}}}}, "output": {"return": True}}],
            "FAIL",
            "AddLog request wrappers must not synthesize the required Data parameter.",
        ),
        (
            "AddLog request envelope rejects non-empty success",
            log_wrapper_context + [{"input": {"function": "addLog", "kwargs": log_add_request}, "output": {"return": ["unexpected"]}}],
            "FAIL",
            "AddLog request wrappers may expose Boolean success but not arbitrary non-empty result values.",
        ),
        (
            "CreateLog request envelope preserves three-field result shape",
            log_wrapper_context + [{"input": {"function": "createLog", "kwargs": log_create_request}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}],
            "PASS",
            "CreateLog request wrappers must preserve MinSize and the three-field success result.",
        ),
        (
            "CreateLog request envelope rejects missing MinSize",
            log_wrapper_context + [{"input": {"function": "createLog", "kwargs": {"createLogRequest": {"values": {"name": "MyLog", "highSecurity": False, "authAs": ("Admin1", "new")}}}}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}],
            "FAIL",
            "CreateLog request wrappers must not synthesize the required MinSize parameter.",
        ),
        (
            "CreateLog request envelope rejects Boolean success",
            log_wrapper_context + [{"input": {"function": "createLog", "kwargs": log_create_request}, "output": {"return": True}}],
            "FAIL",
            "CreateLog request wrappers must keep the official three-field success shape.",
        ),
        (
            "ClearLog request envelope accepts Boolean wrapper success",
            log_wrapper_context + [{"input": {"function": "clearLog", "kwargs": log_clear_request}, "output": {"return": True}}],
            "PASS",
            "ClearLog request wrappers lower to an empty-result method while accepting SDK Boolean success.",
        ),
        (
            "ClearLog request envelope rejects non-empty success",
            log_wrapper_context + [{"input": {"function": "clearLog", "kwargs": log_clear_request}, "output": {"return": ["unexpected"]}}],
            "FAIL",
            "ClearLog request wrappers must not accept arbitrary non-empty success payloads.",
        ),
    ):
        yield Probe(name, trajectory, expected, "log-domain-request-envelope-doc", why)
    for label, add_kwargs, create_kwargs, clear_kwargs in (
        (
            "operation",
            {"operation": {"target": {"log": "Log1"}, "command": {"name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}},
            {"operation": {"command": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}},
            {"operation": {"target": {"log": "Log1"}, "command": {"authAs": ("Admin1", "new")}}},
        ),
        (
            "operationRequest",
            {"operationRequest": {"target": {"log": "Log1"}, "command": {"name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}},
            {"operationRequest": {"command": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}},
            {"operationRequest": {"target": {"log": "Log1"}, "command": {"authAs": ("Admin1", "new")}}},
        ),
        (
            "command",
            {"command": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}},
            {"command": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}},
            {"command": {"log": "Log1", "authAs": ("Admin1", "new")}},
        ),
        (
            "action",
            {"action": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}},
            {"action": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}},
            {"action": {"log": "Log1", "authAs": ("Admin1", "new")}},
        ),
    ):
        for name, trajectory, expected, why in (
            (f"AddLog {label} envelope preserves required payload", log_wrapper_context + [{"input": {"function": "addLog", "kwargs": add_kwargs}, "output": {"return": True}}], "PASS", "AddLog operation wrappers must preserve LogEntryName and Data before lowering."),
            (f"AddLog {label} envelope rejects non-empty success", log_wrapper_context + [{"input": {"function": "addLog", "kwargs": add_kwargs}, "output": {"return": ["unexpected"]}}], "FAIL", "AddLog operation wrappers may expose Boolean success but not arbitrary non-empty result values."),
            (f"CreateLog {label} envelope preserves three-field result shape", log_wrapper_context + [{"input": {"function": "createLog", "kwargs": create_kwargs}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}], "PASS", "CreateLog operation wrappers must preserve MinSize and the three-field success result."),
            (f"CreateLog {label} envelope rejects Boolean success", log_wrapper_context + [{"input": {"function": "createLog", "kwargs": create_kwargs}, "output": {"return": True}}], "FAIL", "CreateLog operation wrappers must keep the official three-field success shape."),
            (f"ClearLog {label} envelope accepts Boolean wrapper success", log_wrapper_context + [{"input": {"function": "clearLog", "kwargs": clear_kwargs}, "output": {"return": True}}], "PASS", "ClearLog operation wrappers lower to an empty-result method while accepting SDK Boolean success."),
            (f"ClearLog {label} envelope rejects non-empty success", log_wrapper_context + [{"input": {"function": "clearLog", "kwargs": clear_kwargs}, "output": {"return": ["unexpected"]}}], "FAIL", "ClearLog operation wrappers must not accept arbitrary non-empty success payloads."),
        ):
            yield Probe(name, trajectory, expected, "log-operation-envelope-doc", why)
    for alias in ("newLog", "makeLog", "createLogTable", "newLogTable", "allocateLog"):
        yield Probe(
            f"{alias} wrapper accepts three field result",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}],
            "PASS",
            "log-wrapper",
            f"{alias} should lower to LogList.CreateLog and keep the three-field result shape.",
        )
        yield Probe(
            f"{alias} wrapper rejects missing MinSize",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"name": "MyLog", "highSecurity": False, "authAs": ("Admin1", "new")}}, "output": {"return": ["LogListUID", "LogTableUID", 8]}}],
            "FAIL",
            "log-wrapper",
            f"{alias} must preserve the CreateLog MinSize requirement.",
        )
        yield Probe(
            f"{alias} wrapper rejects boolean success",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "log-wrapper",
            f"{alias} should preserve the three-field CreateLog result shape.",
        )
        yield Probe(
            f"{alias} wrapper rejects extra result field",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"name": "MyLog", "highSecurity": False, "minSize": 8, "authAs": ("Admin1", "new")}}, "output": {"return": ["LogListUID", "LogTableUID", 8, "extra"]}}],
            "FAIL",
            "log-wrapper",
            f"{alias} successful responses have exactly three fields.",
        )
    yield Probe(
        "clearLog wrapper boolean success",
        log_wrapper_context + [{"input": {"function": "clearLog", "kwargs": {"log": "Log1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
        "PASS",
        "log-wrapper",
        "clearLog lowers to Log.ClearLog while accepting SDK-style boolean success.",
    )
    for alias in ("clearLog", "truncateLog", "flushLog", "syncLog"):
        yield Probe(
            f"{alias} wrapper rejects non-empty success result",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"log": "Log1", "authAs": ("Admin1", "new")}}, "output": {"return": ["unexpected"]}}],
            "FAIL",
            "log-wrapper",
            f"{alias} wrappers may expose Boolean success, but the backing method result is empty.",
        )
    for alias in ("appendLog", "writeLog", "putLogEntry", "addLogEntry", "appendLogEntry", "writeLogEntry", "storeLogEntry", "createLogEntry"):
        yield Probe(
            f"{alias} wrapper boolean success",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "PASS",
            "log-wrapper",
            f"{alias} should lower to Log.AddLog and preserve AddLog parameter validation.",
        )
        yield Probe(
            f"{alias} wrapper rejects missing data success",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"log": "Log1", "name": "Entry1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "FAIL",
            "log-wrapper",
            f"{alias} must not synthesize the required AddLog Data parameter.",
        )
        yield Probe(
            f"{alias} wrapper rejects non-empty success result",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"log": "Log1", "name": "Entry1", "data": "AABB", "authAs": ("Admin1", "new")}}, "output": {"return": ["unexpected"]}}],
            "FAIL",
            "log-wrapper",
            f"{alias} may expose Boolean success, but the backing AddLog method result is empty.",
        )
    for alias in ("eraseLog", "resetLog", "clearLogEntries"):
        yield Probe(
            f"{alias} wrapper boolean success",
            log_wrapper_context + [{"input": {"function": alias, "kwargs": {"log": "Log1", "authAs": ("Admin1", "new")}}, "output": {"return": True}}],
            "PASS",
            "log-wrapper",
            f"{alias} should lower to Log.ClearLog with the selected log object.",
        )

    crypto_wrapper_context = locking_admin_open()
    crypto_stream_context = crypto_wrapper_context + [
        {"input": {"function": "hashInit", "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}},
    ]
    yield Probe(
        "hashInit/hash wrappers share stream state",
        crypto_stream_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
        "PASS",
        "crypto-wrapper",
        "Hash wrapper aliases should lower to H_SHA_* stream methods and preserve open stream state.",
    )
    yield Probe(
        "hash wrapper rejects boolean-only digest result",
        crypto_stream_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": True}}],
        "FAIL",
        "crypto-wrapper",
        "Hash must return digest bytes rather than Boolean-only success.",
    )
    yield Probe(
        "hash wrapper rejects missing init",
        crypto_wrapper_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
        "FAIL",
        "crypto-wrapper",
        "Hash requires an open HashInit stream through both raw and wrapper forms.",
    )
    crypto_buffer_out = {"table": "DataStore", "row": 0, "offset": 0, "length": 2}
    for wrapper_key, wrapper_payload in (
        ("policy", {"data": "AABB", "BufferOut": crypto_buffer_out, "authAs": "Anybody"}),
        ("config", {"input": "AABB", "output": crypto_buffer_out, "authAs": "Anybody"}),
        ("request", {"crypto": {"payload": "AABB", "bufferOut": crypto_buffer_out}, "authAs": "Anybody"}),
        ("operation", {"input": {"bytes": "AABB"}, "destination": crypto_buffer_out, "authAs": "Anybody"}),
        ("cryptoRequest", {"values": {"data": "AABB", "BufferOut": crypto_buffer_out, "authAs": "Anybody"}}),
        ("cipherRequest", {"values": {"input": "AABB", "output": crypto_buffer_out, "authAs": "Anybody"}}),
        ("operationRequest", {"crypto": {"payload": "AABB", "bufferOut": crypto_buffer_out}, "authAs": "Anybody"}),
        ("hashRequest", {"values": {"data": "AABB", "BufferOut": crypto_buffer_out, "authAs": "Anybody"}}),
    ):
        yield Probe(
            f"encrypt {wrapper_key} BufferOut envelope returns empty result",
            crypto_wrapper_context
            + [
                {"input": {"function": "encryptInit", "kwargs": {"target": "AES256", "authAs": "Anybody"}}, "output": {"return": []}},
                {"input": {"function": "encrypt", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": []}},
            ],
            "PASS",
            "crypto-wrapper",
            f"encrypt with BufferOut in a structured {wrapper_key} envelope stores bytes and returns an empty result.",
        )
        yield Probe(
            f"encrypt {wrapper_key} BufferOut envelope rejects returned bytes",
            crypto_wrapper_context
            + [
                {"input": {"function": "encryptInit", "kwargs": {"target": "AES256", "authAs": "Anybody"}}, "output": {"return": []}},
                {"input": {"function": "encrypt", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": "AABB"}},
            ],
            "FAIL",
            "crypto-wrapper",
            f"encrypt must not return byte payload when BufferOut is supplied through {wrapper_key}.",
        )
        yield Probe(
            f"hashInit {wrapper_key} BufferOut makes hash return empty result",
            crypto_wrapper_context
            + [
                {"input": {"function": "hashInit", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": []}},
                {"input": {"function": "hash", "kwargs": {"data": "AABB", "authAs": "Anybody"}}, "output": {"return": []}},
            ],
            "PASS",
            "crypto-wrapper",
            f"hashInit with BufferOut in {wrapper_key} stores the later Hash output and makes Hash return empty.",
        )
        yield Probe(
            f"hashInit {wrapper_key} BufferOut rejects hash byte return",
            crypto_wrapper_context
            + [
                {"input": {"function": "hashInit", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": []}},
                {"input": {"function": "hash", "kwargs": {"data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}},
            ],
            "FAIL",
            "crypto-wrapper",
            f"Hash must not return byte payload after BufferOut was supplied through {wrapper_key} at HashInit.",
        )
    hash_operation_context = crypto_wrapper_context + [
        {"input": {"function": "hashInit", "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}},
    ]
    for wrapper_key, wrapper_payload in (
        ("operation", {"command": {"data": "AABB", "authAs": "Anybody"}}),
        ("operationRequest", {"command": {"data": "AABB", "authAs": "Anybody"}}),
        ("command", {"data": "AABB", "authAs": "Anybody"}),
        ("action", {"data": "AABB", "authAs": "Anybody"}),
    ):
        yield Probe(
            f"hash {wrapper_key} command envelope accepts initialized hash",
            hash_operation_context + [{"input": {"function": "hash", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-operation-envelope-doc",
            "Hash operation-style command envelopes must preserve digest input bytes.",
        )
        yield Probe(
            f"hash {wrapper_key} command envelope rejects boolean digest",
            hash_operation_context + [{"input": {"function": "hash", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": True}}],
            "FAIL",
            "crypto-operation-envelope-doc",
            "Hash operation-style command envelopes must still return digest bytes, not Boolean success.",
        )
    for init_alias in ("initHash", "hashBegin", "hashStart", "beginDigest", "digestInit", "digestStart", "sha256Init", "startDigest"):
        alias_stream_context = crypto_wrapper_context + [
            {"input": {"function": init_alias, "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}},
        ]
        yield Probe(
            f"{init_alias}/hash wrappers share stream state",
            alias_stream_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{init_alias} should lower to HashInit and open the same H_SHA_* stream.",
        )
    for update_alias in ("updateHash", "computeHash", "digest", "hashBytes", "updateDigest", "digestUpdate", "sha256Update", "hashBuffer", "processHash", "processDigest"):
        yield Probe(
            f"hashInit/{update_alias} wrappers share stream state",
            crypto_stream_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{update_alias} should lower to Hash and require an open hash stream.",
        )
        yield Probe(
            f"hashInit/{update_alias} rejects boolean-only digest result",
            crypto_stream_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": True}}],
            "FAIL",
            "crypto-wrapper",
            f"{update_alias} must return digest bytes rather than Boolean-only success.",
        )
        yield Probe(
            f"{update_alias} wrapper rejects missing init",
            crypto_wrapper_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "FAIL",
            "crypto-wrapper",
            f"{update_alias} must preserve the official HashInit-before-Hash stream precondition.",
        )
    for final_alias in ("finalHash", "hashFinish", "completeHash", "finalizeHash", "finalDigest", "finishDigest", "digestFinal", "completeDigest", "sha256Final"):
        yield Probe(
            f"hashInit/{final_alias} wrapper accepts finalize",
            crypto_stream_context + [{"input": {"function": final_alias, "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{final_alias} should lower to HashFinalize for the open hash stream.",
        )
    for hmac_init_alias in ("initHMAC", "hmacStart", "beginHMAC", "initMAC", "macInit", "startMAC"):
        yield Probe(
            f"{hmac_init_alias} wrapper accepts HMACInit",
            crypto_wrapper_context + [{"input": {"function": hmac_init_alias, "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}}],
            "PASS",
            "crypto-wrapper",
            f"{hmac_init_alias} should lower to HMACInit on an H_SHA_* object.",
        )
    hmac_stream_context = crypto_wrapper_context + [
        {"input": {"function": "hmacInit", "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}},
    ]
    for hmac_init_alias in ("beginMAC", "macStart", "hmacBegin", "sha256HmacInit"):
        alias_stream_context = crypto_wrapper_context + [
            {"input": {"function": hmac_init_alias, "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}},
        ]
        yield Probe(
            f"{hmac_init_alias}/hmac wrappers share stream state",
            alias_stream_context + [{"input": {"function": "hmac", "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{hmac_init_alias} should lower to HMACInit and open the same HMAC stream.",
        )
    for hmac_update_alias in ("updateHMAC", "computeHMAC", "hmacBytes", "macUpdate", "updateMAC", "processMAC", "processHMAC", "hmacDigest", "digestHMAC", "macDigest"):
        yield Probe(
            f"hmacInit/{hmac_update_alias} wrappers share stream state",
            hmac_stream_context + [{"input": {"function": hmac_update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{hmac_update_alias} should lower to HMAC and require an open HMACInit stream.",
        )
        if hmac_update_alias == "updateHMAC":
            yield Probe(
                "hmacInit/updateHMAC rejects empty MAC result without BufferOut",
                hmac_stream_context + [{"input": {"function": hmac_update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": {}}}],
                "FAIL",
                "crypto-wrapper",
                "HMAC without BufferOut returns a non-empty MAC byte payload, not an empty result.",
            )
        yield Probe(
            f"{hmac_update_alias} wrapper rejects missing HMACInit stream",
            crypto_wrapper_context + [{"input": {"function": hmac_update_alias, "kwargs": {"algorithm": "sha256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "FAIL",
            "crypto-wrapper",
            f"{hmac_update_alias} must preserve the official HMACInit-before-HMAC precondition.",
        )
    for hmac_final_alias in ("finalHMAC", "finalizeHMAC", "hmacFinish", "completeHMAC", "finishMAC", "finalMAC", "macFinal", "completeMAC", "finalizeMAC"):
        yield Probe(
            f"hmacInit/{hmac_final_alias} wrappers finalize stream",
            hmac_stream_context + [{"input": {"function": hmac_final_alias, "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
            "PASS",
            "crypto-wrapper",
            f"{hmac_final_alias} should lower to HMACFinalize for the open HMAC stream.",
        )
    for stream_name, init_name, update_name, init_aliases, update_aliases, final_aliases in (
        (
            "Encrypt",
            "encryptInit",
            "encrypt",
            ("initEncrypt", "beginEncrypt", "encryptBegin", "beginEncryption", "encryptStart", "aesEncryptInit", "initEncryption", "startEncryption"),
            ("updateEncrypt", "encryptUpdate", "updateEncryption", "encryptBytes", "encryptBuffer", "processEncrypt", "processEncryption", "doEncrypt"),
            ("finalEncrypt", "finalizeEncrypt", "finalEncryption", "finishEncryption", "encryptFinish", "completeEncrypt", "completeEncryption"),
        ),
        (
            "Decrypt",
            "decryptInit",
            "decrypt",
            ("initDecrypt", "beginDecrypt", "decryptBegin", "beginDecryption", "decryptStart", "aesDecryptInit", "initDecryption", "startDecryption"),
            ("updateDecrypt", "decryptUpdate", "updateDecryption", "decryptBytes", "decryptBuffer", "processDecrypt", "processDecryption", "doDecrypt"),
            ("finalDecrypt", "finalizeDecrypt", "finalDecryption", "finishDecryption", "decryptFinish", "completeDecrypt", "completeDecryption"),
        ),
    ):
        stream_context = crypto_wrapper_context + [
            {"input": {"function": init_name, "kwargs": {"algorithm": "aes256", "authAs": "Anybody"}}, "output": {"return": []}},
        ]
        for init_alias in init_aliases:
            alias_stream_context = crypto_wrapper_context + [
                {"input": {"function": init_alias, "kwargs": {"algorithm": "aes256", "authAs": "Anybody"}}, "output": {"return": []}},
            ]
            yield Probe(
                f"{init_alias}/{update_name} wrappers share stream state",
                alias_stream_context + [{"input": {"function": update_name, "kwargs": {"algorithm": "aes256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
                "PASS",
                "crypto-wrapper",
                f"{init_alias} should lower to {stream_name}Init and open the same C_AES stream.",
            )
            yield Probe(
                f"{init_alias}/{update_name} rejects empty byte result without BufferOut",
                alias_stream_context + [{"input": {"function": update_name, "kwargs": {"algorithm": "aes256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": []}}],
                "FAIL",
                "crypto-wrapper",
                f"{stream_name} without BufferOut returns transformed bytes in-band, not an empty BufferOut-style result.",
            )
        for update_alias in update_aliases:
            yield Probe(
                f"{init_name}/{update_alias} wrappers share stream state",
                stream_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "aes256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
                "PASS",
                "crypto-wrapper",
                f"{update_alias} should lower to {stream_name} and require an open {stream_name}Init stream.",
            )
            yield Probe(
                f"{update_alias} wrapper rejects missing {stream_name}Init stream",
                crypto_wrapper_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "aes256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
                "FAIL",
                "crypto-wrapper",
                f"{update_alias} must preserve the official {stream_name}Init-before-{stream_name} precondition.",
            )
            yield Probe(
                f"{init_name}/{update_alias} rejects empty byte result without BufferOut",
                stream_context + [{"input": {"function": update_alias, "kwargs": {"algorithm": "aes256", "data": "AABB", "authAs": "Anybody"}}, "output": {"return": {}}}],
                "FAIL",
                "crypto-wrapper",
                f"{update_alias} without BufferOut returns transformed bytes in-band, not an empty BufferOut-style result.",
            )
        for final_alias in final_aliases:
            yield Probe(
                f"{init_name}/{final_alias} wrappers finalize stream",
                stream_context + [{"input": {"function": final_alias, "kwargs": {"algorithm": "aes256", "authAs": "Anybody"}}, "output": {"return": "AABB"}}],
                "PASS",
                "crypto-wrapper",
                f"{final_alias} should lower to {stream_name}Finalize for the open C_AES stream.",
            )
    yield Probe(
        "HashInit rejects C_AES object",
        crypto_wrapper_context + [method_record("HashInit", "C_AES_256", "C_AES_256", status=SUCCESS)],
        "FAIL",
        "crypto-wrapper",
        "Hash/HMAC stream methods are defined on H_SHA_* objects, not symmetric credential rows.",
    )
    sign_wrapper_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    for sign_alias in ("makeSignature", "signatureCreate", "signatureGenerate", "signMessage", "signDigest", "tpersignPayload", "makeTPerSignature", "createTPerSignature", "generateTPerSignature"):
        yield Probe(
            f"{sign_alias} wrapper accepts signature byte payload",
            sign_wrapper_context + [{"input": {"function": sign_alias, "kwargs": {"payload": "AABB", "authAs": "Anybody"}}, "output": {"return": "signature"}}],
            "PASS",
            "sign-wrapper",
            f"{sign_alias} should lower to Sign and return signature bytes in-band.",
        )
        yield Probe(
            f"{sign_alias} wrapper rejects boolean signature payload",
            sign_wrapper_context + [{"input": {"function": sign_alias, "kwargs": {"payload": "AABB", "authAs": "Anybody"}}, "output": {"return": True}}],
            "FAIL",
            "sign-wrapper",
            f"{sign_alias} must preserve the official Sign byte-payload result shape.",
        )
    sign_buffer_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "old")]
    sign_buffer_out = {"table": "DataStore", "row": 0, "offset": 0, "length": 2}
    for wrapper_key, wrapper_payload in (
        ("policy", {"target": "C_RSA_2048", "data": "AABB", "BufferOut": sign_buffer_out, "authAs": ("SID", "old")}),
        ("config", {"target": "C_RSA_2048", "input": "AABB", "output": sign_buffer_out, "authAs": ("SID", "old")}),
        ("request", {"sign": {"target": "C_RSA_2048", "payload": "AABB", "bufferOut": sign_buffer_out}, "authAs": ("SID", "old")}),
        ("operation", {"target": "C_RSA_2048", "input": {"bytes": "AABB"}, "destination": sign_buffer_out, "authAs": ("SID", "old")}),
        ("signRequest", {"values": {"target": "C_RSA_2048", "data": "AABB", "BufferOut": sign_buffer_out, "authAs": ("SID", "old")}}),
        ("signatureRequest", {"values": {"target": "C_RSA_2048", "payload": "AABB", "bufferOut": sign_buffer_out, "authAs": ("SID", "old")}}),
        ("operationRequest", {"sign": {"target": "C_RSA_2048", "payload": "AABB", "bufferOut": sign_buffer_out}, "authAs": ("SID", "old")}),
    ):
        yield Probe(
            f"signPayload {wrapper_key} BufferOut envelope returns empty result",
            sign_buffer_context + [{"input": {"function": "signPayload", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": []}}],
            "PASS",
            "sign-wrapper",
            f"Sign with BufferOut in a structured {wrapper_key} envelope stores the signature and returns an empty result.",
        )
        yield Probe(
            f"signPayload {wrapper_key} BufferOut envelope rejects returned bytes",
            sign_buffer_context + [{"input": {"function": "signPayload", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"return": "AABB"}}],
            "FAIL",
            "sign-wrapper",
            f"Sign must not return byte payload when BufferOut is supplied through {wrapper_key}.",
        )
    yield Probe(
        "verifyData wrapper requires boolean",
        crypto_wrapper_context + [{"input": {"function": "verifyData", "kwargs": {"algorithm": "sha256", "proof": "AABB", "authAs": "Anybody"}}, "output": {"return": "verified"}}],
        "FAIL",
        "crypto-wrapper",
        "Verify wrapper aliases must preserve the official Boolean result shape.",
    )
    for verify_alias in ("verify", "checkSignature", "validateSignature", "verifyProof", "checkProof", "validateProof", "checkHash", "validateHash", "verifyDigest", "checkDigest", "validateDigest", "verifyMAC", "checkMAC", "validateMAC"):
        yield Probe(
            f"{verify_alias} wrapper accepts boolean Verify result",
            crypto_wrapper_context + [{"input": {"function": verify_alias, "kwargs": {"algorithm": "sha256", "proof": "AABB", "authAs": "Anybody"}}, "output": {"return": True}}],
            "PASS",
            "crypto-wrapper",
            f"{verify_alias} should lower to Verify and preserve the Boolean result shape.",
        )
        yield Probe(
            f"{verify_alias} wrapper rejects non-boolean Verify result",
            crypto_wrapper_context + [{"input": {"function": verify_alias, "kwargs": {"algorithm": "sha256", "proof": "AABB", "authAs": "Anybody"}}, "output": {"return": "verified"}}],
            "FAIL",
            "crypto-wrapper",
            f"{verify_alias} must preserve the official Boolean Verify result shape.",
        )
        yield Probe(
            f"{verify_alias} wrapper rejects status-string Verify result",
            crypto_wrapper_context + [{"input": {"function": verify_alias, "kwargs": {"algorithm": "sha256", "proof": "AABB", "authAs": "Anybody"}}, "output": {"return": "SUCCESS"}}],
            "FAIL",
            "crypto-wrapper",
            f"{verify_alias} must return a Boolean verification result rather than a SUCCESS status string.",
        )

    package_wrapper_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    yield Probe(
        "getPackage wrapper accepts credential purpose",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
        "PASS",
        "package-wrapper",
        "getPackage should lower to C_PIN.GetPackage and preserve the required Purpose parameter.",
    )
    yield Probe(
        "getPackage wrapper rejects boolean package payload",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": True}}],
        "FAIL",
        "package-wrapper",
        "GetPackage returns credential package bytes, not a wrapper Boolean success marker.",
    )
    yield Probe(
        "getPackage wrapper rejects list-wrapped boolean package payload",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": [True]}}],
        "FAIL",
        "package-wrapper",
        "GetPackage wrapper return lists carry package payload bytes and must not collapse a Boolean status marker.",
    )
    yield Probe(
        "getPackage wrapper rejects empty object package payload",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": {}}}],
        "FAIL",
        "package-wrapper",
        "GetPackage success must expose non-empty package bytes, not an empty object payload.",
    )
    yield Probe(
        "getPackage wrapper rejects scalar status package payload",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": "SUCCESS"}}],
        "FAIL",
        "package-wrapper",
        "GetPackage success must expose package material rather than a status string.",
    )
    yield Probe(
        "getPackage wrapper rejects missing purpose",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
        "FAIL",
        "package-wrapper",
        "Wrapper lowering must not synthesize the required GetPackage Purpose parameter.",
    )
    yield Probe(
        "getPackage wrapper rejects empty purpose",
        package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": {"auth": "SID", "purpose": "", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
        "FAIL",
        "package-wrapper",
        "GetPackage Purpose must be present and non-empty.",
    )
    yield Probe(
        "setPackage wrapper accepts empty result",
        package_wrapper_context + [{"input": {"function": "setPackage", "kwargs": {"auth": "SID", "value": "pkg", "authAs": ("SID", "new")}}, "output": {"return": []}}],
        "PASS",
        "package-wrapper",
        "setPackage should lower to credential SetPackage and keep the empty raw success result shape.",
    )
    yield Probe(
        "setPackage wrapper rejects empty value",
        package_wrapper_context + [{"input": {"function": "setPackage", "kwargs": {"auth": "SID", "value": [], "authAs": ("SID", "new")}}, "output": {"return": []}}],
        "FAIL",
        "package-wrapper",
        "SetPackage Value must carry non-empty package material.",
    )
    for label, kwargs in (
        ("getPackage policy", {"policy": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}),
        ("getPackage config", {"config": {"credential": "SID", "Purpose": "backup", "authAs": ("SID", "new")}}),
        ("getPackage request target", {"request": {"target": {"auth": "SID"}, "purpose": "backup", "authAs": ("SID", "new")}}),
        ("getPackage request target command", {"request": {"target": {"auth": "SID"}, "command": {"Purpose": "backup"}, "authAs": ("SID", "new")}}),
        ("getPackage operation target package", {"operation": {"target": {"auth": "SID"}, "package": {"Purpose": "backup"}, "authAs": ("SID", "new")}}),
        ("getPackage packageRequest", {"packageRequest": {"values": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}}),
        ("getPackage credentialPackageRequest", {"credentialPackageRequest": {"package": {"auth": "SID", "purpose": "backup"}, "authAs": ("SID", "new")}}),
        ("getPackage keyPackageRequest", {"keyPackageRequest": {"target": {"auth": "SID"}, "purpose": "backup", "authAs": ("SID", "new")}}),
    ):
        yield Probe(
            f"{label} envelope preserves Purpose",
            package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": kwargs}, "output": {"return": "pkg"}}],
            "PASS",
            "package-wrapper",
            "GetPackage policy/config/request envelopes must preserve credential target and Purpose.",
        )
        yield Probe(
            f"{label} envelope rejects boolean package payload",
            package_wrapper_context + [{"input": {"function": "getPackage", "kwargs": kwargs}, "output": {"return": True}}],
            "FAIL",
            "package-wrapper",
            "GetPackage envelope lowering must still require package material rather than a Boolean marker.",
        )
    for label, kwargs in (
        ("setPackage policy", {"policy": {"auth": "SID", "value": "pkg", "authAs": ("SID", "new")}}),
        ("setPackage request", {"request": {"credential": "SID", "package": "pkg", "authAs": ("SID", "new")}}),
        ("setPackage request target command", {"request": {"target": {"auth": "SID"}, "command": {"Value": "pkg"}, "authAs": ("SID", "new")}}),
        ("setPackage operation target package", {"operation": {"target": {"auth": "SID"}, "package": {"Value": "pkg"}, "authAs": ("SID", "new")}}),
        ("setPackage packageRequest", {"packageRequest": {"values": {"auth": "SID", "value": "pkg", "authAs": ("SID", "new")}}}),
        ("setPackage credentialPackageRequest", {"credentialPackageRequest": {"credential": "SID", "package": "pkg", "authAs": ("SID", "new")}}),
    ):
        yield Probe(
            f"{label} envelope preserves Value",
            package_wrapper_context + [{"input": {"function": "setPackage", "kwargs": kwargs}, "output": {"return": []}}],
            "PASS",
            "package-wrapper",
            "SetPackage policy/request envelopes must preserve credential target and package Value.",
        )
    for label, kwargs in (
        ("setPackage policy empty", {"policy": {"auth": "SID", "value": [], "authAs": ("SID", "new")}}),
        ("setPackage request empty", {"request": {"credential": "SID", "package": [], "authAs": ("SID", "new")}}),
        ("setPackage packageRequest empty", {"packageRequest": {"values": {"auth": "SID", "value": [], "authAs": ("SID", "new")}}}),
        ("setPackage credentialPackageRequest empty", {"credentialPackageRequest": {"credential": "SID", "package": [], "authAs": ("SID", "new")}}),
    ):
        yield Probe(
            f"{label} envelope rejects empty Value",
            package_wrapper_context + [{"input": {"function": "setPackage", "kwargs": kwargs}, "output": {"return": []}}],
            "FAIL",
            "package-wrapper",
            "SetPackage envelope lowering must preserve empty package material so it remains invalid.",
        )
    yield Probe(
        "exportKeyPackage alias accepts credential purpose",
        package_wrapper_context + [{"input": {"function": "exportKeyPackage", "args": ["SID"], "kwargs": {"Purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": {"Result": "pkg"}}}],
        "PASS",
        "package-wrapper",
        "Package-suffixed export aliases should lower to GetPackage instead of UNKNOWN.",
    )
    for alias in (
        "backupPackage",
        "readPackage",
        "backupCredential",
        "backupKeyPackage",
        "readKeyPackage",
        "getKeyPackage",
        "dumpKeyPackage",
        "exportCredential",
        "exportCredentialPackage",
        "backupCredentialPackage",
        "readCredentialPackage",
        "getCredentialBackup",
        "readCredentialBackup",
        "fetchCredentialBackup",
        "dumpCredentialPackage",
        "exportCredentialBackup",
        "backupPIN",
        "backupPINPackage",
        "exportPIN",
        "exportPINPackage",
        "getPINPackage",
        "readKeyBackup",
        "exportKeyBackup",
        "getWrappedKey",
        "exportWrappedKey",
        "getWrappedPackage",
    ):
        yield Probe(
            f"{alias} alias accepts credential purpose",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
            "PASS",
            "package-wrapper",
            f"{alias} should lower to GetPackage and preserve the required Purpose parameter.",
        )
        yield Probe(
            f"{alias} alias rejects missing purpose",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"auth": "SID", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
            "FAIL",
            "package-wrapper",
            f"{alias} must not synthesize the required GetPackage Purpose parameter.",
        )
        yield Probe(
            f"{alias} alias rejects empty object package payload",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"auth": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": {}}}],
            "FAIL",
            "package-wrapper",
            f"{alias} success must expose non-empty package material, not an empty object payload.",
        )
        yield Probe(
            f"{alias} credential alias accepts purpose",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"credential": "SID", "purpose": "backup", "authAs": ("SID", "new")}}, "output": {"return": "pkg"}}],
            "PASS",
            "package-wrapper",
            f"{alias} should treat credential as the target C_PIN row for GetPackage.",
        )
    yield Probe(
        "importKeyPackage alias accepts wrapper boolean success",
        package_wrapper_context + [{"input": {"function": "importKeyPackage", "args": ["SID"], "kwargs": {"Value": "pkg", "authAs": ("SID", "new")}}, "output": {"return": True}}],
        "PASS",
        "package-wrapper",
        "Package-suffixed import aliases should lower to SetPackage and may expose SDK-style boolean success.",
    )
    for alias in (
        "restorePackage",
        "loadPackage",
        "writePackage",
        "restoreCredential",
        "restoreKeyPackage",
        "loadKeyPackage",
        "writeKeyPackage",
        "setKeyPackage",
        "restoreCredentialPackage",
        "loadCredentialPackage",
        "writeCredentialPackage",
        "setCredentialBackup",
        "importCredential",
        "restoreCredentialBackup",
        "importCredentialBackup",
        "restorePIN",
        "restorePINPackage",
        "importPIN",
        "importPINPackage",
        "setPINPackage",
        "writeKeyBackup",
        "importKeyBackup",
        "setWrappedKey",
        "importWrappedKey",
        "setWrappedPackage",
    ):
        yield Probe(
            f"{alias} alias accepts empty result",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"auth": "SID", "value": "pkg", "authAs": ("SID", "new")}}, "output": {"return": []}}],
            "PASS",
            "package-wrapper",
            f"{alias} should lower to SetPackage and preserve the required Value parameter.",
        )
        yield Probe(
            f"{alias} alias rejects empty value",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"auth": "SID", "value": [], "authAs": ("SID", "new")}}, "output": {"return": []}}],
            "FAIL",
            "package-wrapper",
            f"{alias} must preserve the SetPackage non-empty Value requirement.",
        )
        yield Probe(
            f"{alias} credential package aliases accept boolean success",
            package_wrapper_context + [{"input": {"function": alias, "kwargs": {"credential": "SID", "package": "pkg", "authAs": ("SID", "new")}}, "output": {"return": True}}],
            "PASS",
            "package-wrapper",
            f"{alias} should treat credential as the target C_PIN row and package as SetPackage Value.",
        )
    yield Probe(
        "raw SetPackage rejects scalar true result",
        package_wrapper_context + [method_record("SetPackage", C_PIN_SID, "C_PIN_SID", SUCCESS, required={"Value": "pkg"}, return_values=True)],
        "FAIL",
        "package-wrapper",
        "The raw SetPackage method returns an empty list, not a scalar Boolean.",
    )

    table_wrapper_context = locking_admin_open()
    yield Probe(
        "createTable wrapper accepts valid object table",
        table_wrapper_context
        + [
            {
                "input": {"function": "createTable", "kwargs": {"name": "T", "kind": "Object", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "minSize": 1, "authAs": ("Admin1", "new")}},
                "output": {"return": ["0000010000000001", 1]},
            }
        ],
        "PASS",
        "table-wrapper",
        "createTable should lower to ThisSP.CreateTable and preserve required table parameters.",
    )
    yield Probe(
        "createTable wrapper rejects generic false failure",
        table_wrapper_context
        + [
            {
                "input": {"function": "createTable", "kwargs": {"name": "T", "kind": "Object", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "minSize": 1, "authAs": ("Admin1", "new")}},
                "output": {"return": False},
            }
        ],
        "FAIL",
        "table-wrapper",
        "Valid CreateTable may return SUCCESS with UID/Rows or documented insufficient-space/rows statuses, not a generic Boolean false failure.",
    )
    yield Probe(
        "createTable wrapper rejects missing MinSize",
        table_wrapper_context
        + [
            {
                "input": {"function": "createTable", "kwargs": {"name": "T", "kind": "Object", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "authAs": ("Admin1", "new")}},
                "output": {"return": ["0000010000000001", 1]},
            }
        ],
        "FAIL",
        "table-wrapper",
        "Wrapper lowering must not synthesize the required CreateTable MinSize parameter.",
    )
    table_lifecycle_values = {
        "NewTableName": "DynamicRow",
        "Kind": 1,
        "GetSetACL": ["ACE_Anybody"],
        "Columns": [["Entry", "uid"]],
        "MinSize": 0,
        "CommonName": "Base",
        "authAs": ("SID", "new"),
    }
    for envelope in ("createTableRequest", "tableRequest", "schemaRequest"):
        yield Probe(
            f"createTable {envelope} preserves zero MinSize",
            table_wrapper_context
            + [
                {
                    "input": {"function": "createTable", "kwargs": {envelope: {"values": table_lifecycle_values}}},
                    "output": {"return": {"UID": "000001AA00000000", "Rows": 0}},
                }
            ],
            "PASS",
            "table-lifecycle-domain-request-envelope-doc",
            "CreateTable domain request envelopes must preserve nested table parameters, including a zero MinSize.",
        )
    for label, payload in (
        ("operation command", {"operation": {"command": table_lifecycle_values}}),
        ("operationRequest command", {"operationRequest": {"command": table_lifecycle_values}}),
    ):
        yield Probe(
            f"createTable {label} preserves zero MinSize",
            table_wrapper_context
            + [
                {
                    "input": {"function": "createTable", "kwargs": payload},
                    "output": {"return": {"UID": "000001AA00000000", "Rows": 0}},
                }
            ],
            "PASS",
            "table-lifecycle-domain-request-envelope-doc",
            "CreateTable operation envelopes must preserve nested table parameters, including a zero MinSize.",
        )
    missing_table_lifecycle_min = dict(table_lifecycle_values)
    missing_table_lifecycle_min.pop("MinSize")
    yield Probe(
        "createTable request envelope rejects missing MinSize",
        table_wrapper_context
        + [
            {
                "input": {"function": "createTable", "kwargs": {"createTableRequest": {"values": missing_table_lifecycle_min}}},
                "output": {"return": {"UID": "000001AA00000000", "Rows": 0}},
            }
        ],
        "FAIL",
        "table-lifecycle-domain-request-envelope-doc",
        "CreateTable request wrappers must not synthesize the required MinSize field.",
    )
    yield Probe(
        "createTable request envelope rejects boolean success",
        table_wrapper_context
        + [
            {
                "input": {"function": "createTable", "kwargs": {"tableRequest": {"values": table_lifecycle_values}}},
                "output": {"return": True},
            }
        ],
        "FAIL",
        "table-lifecycle-domain-request-envelope-doc",
        "A valid CreateTable request returns a created table descriptor, not a scalar Boolean.",
    )
    dynamic_table_context = table_wrapper_context + [
        method_record(
            "CreateTable",
            "0000000000000001",
            "ThisSP",
            "SUCCESS",
            required={"NewTableName": "DynamicRow", "Kind": 1, "GetSetACL": ["ACE_Anybody"], "Columns": [["Entry", "uid"]], "MinSize": 0},
            optional={"CommonName": "Base"},
            return_values={"UID": "000001AA00000000", "Rows": 0},
        )
    ]
    row_lifecycle_values = {"table": "000001AA00000000", "Values": [{"1": "row"}], "authAs": ("SID", "new")}
    for envelope in ("createRowRequest", "rowRequest", "tableRequest"):
        yield Probe(
            f"createRow {envelope} preserves dynamic table values",
            dynamic_table_context
            + [
                {
                    "input": {"function": "createRow", "kwargs": {envelope: {"values": row_lifecycle_values}}},
                    "output": {"return": ["000001AA00000001"]},
                }
            ],
            "PASS",
            "table-lifecycle-domain-request-envelope-doc",
            "CreateRow domain request envelopes must preserve the target table and Values payload.",
        )
    for label, payload in (
        ("operation target command", {"operation": {"target": {"table": "000001AA00000000"}, "command": {"Values": [{"1": "row"}], "authAs": ("SID", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"table": "000001AA00000000"}, "command": {"Values": [{"1": "row"}], "authAs": ("SID", "new")}}}),
    ):
        yield Probe(
            f"createRow {label} preserves dynamic table values",
            dynamic_table_context
            + [
                {
                    "input": {"function": "createRow", "kwargs": payload},
                    "output": {"return": ["000001AA00000001"]},
                }
            ],
            "PASS",
            "table-lifecycle-domain-request-envelope-doc",
            "CreateRow operation envelopes must preserve the target table and Values payload.",
        )
    yield Probe(
        "createRow request envelope rejects boolean success",
        dynamic_table_context
        + [
            {
                "input": {"function": "createRow", "kwargs": {"createRowRequest": {"values": row_lifecycle_values}}},
                "output": {"return": True},
            }
        ],
        "FAIL",
        "table-lifecycle-domain-request-envelope-doc",
        "CreateRow success returns the created row UID list, not a scalar Boolean.",
    )
    delete_query_context = table_wrapper_context + [
        method_record(
            "CreateTable",
            "0000000000000001",
            "ThisSP",
            "SUCCESS",
            required={"NewTableName": "Audit", "Kind": 1, "GetSetACL": [], "Columns": [["Entry", "uid"]], "MinSize": 0},
            return_values={"UID": "0000010000000001", "Rows": 0},
        ),
        method_record("CreateRow", "0000010000000001", "", "SUCCESS", optional={"Values": [{"1": "row"}]}, return_values=["0000010100000001"]),
    ]
    delete_row_values = {"table": "0000010000000001", "Rows": ["0000010100000001"], "authAs": ("SID", "new")}
    for envelope in ("deleteRowRequest", "rowRequest", "tableRequest"):
        yield Probe(
            f"deleteRow {envelope} preserves table and row UID",
            delete_query_context
            + [
                {
                    "input": {"function": "deleteRow", "kwargs": {envelope: {"values": delete_row_values}}},
                    "output": {"return": []},
                }
            ],
            "PASS",
            "table-lifecycle-delete-query-envelope-doc",
            "DeleteRow domain request envelopes must preserve target table and row UID arguments.",
        )
    for label, payload in (
        ("operation target command", {"operation": {"target": {"table": "0000010000000001"}, "command": {"Rows": ["0000010100000001"], "authAs": ("SID", "new")}}}),
        ("operationRequest target command", {"operationRequest": {"target": {"table": "0000010000000001"}, "command": {"Rows": ["0000010100000001"], "authAs": ("SID", "new")}}}),
    ):
        yield Probe(
            f"deleteRow {label} preserves table and row UID",
            delete_query_context
            + [
                {
                    "input": {"function": "deleteRow", "kwargs": payload},
                    "output": {"return": []},
                }
            ],
            "PASS",
            "table-lifecycle-delete-query-envelope-doc",
            "DeleteRow operation envelopes must preserve target table and row UID arguments.",
        )
    yield Probe(
        "deleteRow request envelope rejects missing row UID",
        delete_query_context
        + [
            {
                "input": {"function": "deleteRow", "kwargs": {"deleteRowRequest": {"values": {"table": "0000010000000001", "authAs": ("SID", "new")}}}},
                "output": {"return": []},
            }
        ],
        "FAIL",
        "table-lifecycle-delete-query-envelope-doc",
        "DeleteRow request wrappers must not synthesize the required row UID argument.",
    )
    delete_table_context = table_wrapper_context + [
        method_record(
            "CreateTable",
            "0000000000000001",
            "ThisSP",
            "SUCCESS",
            required={"NewTableName": "Audit", "Kind": 1, "GetSetACL": [], "Columns": [], "MinSize": 0},
            return_values={"UID": "0000016300000000", "Rows": 0},
        )
    ]
    for envelope in ("deleteTableRequest", "tableRequest"):
        yield Probe(
            f"deleteTable {envelope} preserves table UID",
            delete_table_context
            + [
                {
                    "input": {"function": "deleteTable", "kwargs": {envelope: {"values": {"table": "0000016300000000", "authAs": ("SID", "new")}}}},
                    "output": {"return": []},
                }
            ],
            "PASS",
            "table-lifecycle-delete-query-envelope-doc",
            "DeleteTable domain request envelopes must preserve the created table UID target.",
        )
    for label, kwargs in (
        ("operation", {"operation": {"target": {"table": "0000016300000000"}, "command": {"authAs": ("SID", "new")}}}),
        ("operationRequest", {"operationRequest": {"target": {"table": "0000016300000000"}, "command": {"authAs": ("SID", "new")}}}),
        ("command", {"command": {"table": "0000016300000000", "authAs": ("SID", "new")}}),
        ("action", {"action": {"table": "0000016300000000", "authAs": ("SID", "new")}}),
    ):
        delete_context = delete_table_context + [{"input": {"function": "deleteTable", "kwargs": kwargs}, "output": {"return": []}}]
        yield Probe(
            f"deleteTable {label} envelope preserves table UID",
            delete_context,
            "PASS",
            "table-delete-operation-envelope-doc",
            "DeleteTable operation envelopes must preserve the created table UID target and authenticator.",
        )
        yield Probe(
            f"deleteTable {label} envelope removes created table state",
            delete_context + [method_record("Get", "0000016300000000", "Audit", "SUCCESS", return_values={"A": 1})],
            "FAIL",
            "table-delete-operation-envelope-doc",
            "After a created table is deleted, later Get on that table must not remain successful.",
        )
    for envelope in ("tableQueryRequest", "freeRowsRequest", "tableRequest"):
        yield Probe(
            f"tableQuery {envelope} preserves table selector",
            table_wrapper_context
            + [
                {
                    "input": {"function": "tableQuery", "kwargs": {envelope: {"values": {"table": "C_PIN", "authAs": "Anybody"}}}},
                    "output": {"return": [4]},
                }
            ],
            "PASS",
            "table-lifecycle-delete-query-envelope-doc",
            "Table query request envelopes must preserve the target table selector.",
        )
        yield Probe(
            f"tableQuery {envelope} rejects boolean success",
            table_wrapper_context
            + [
                {
                    "input": {"function": "tableQuery", "kwargs": {envelope: {"values": {"table": "C_PIN", "authAs": "Anybody"}}}},
                    "output": {"return": True},
                }
            ],
            "FAIL",
            "table-lifecycle-delete-query-envelope-doc",
            "Table query wrappers return free-row counts, not scalar Boolean success.",
        )
    yield Probe(
        "getNext request envelope preserves table and count",
        table_wrapper_context + [{"input": {"function": "getNext", "kwargs": {"nextRequest": {"values": {"table": "C_PIN", "Count": 2, "authAs": "Anybody"}}}}, "output": {"return": ["0000000B00010001"]}}],
        "PASS",
        "table-lifecycle-delete-query-envelope-doc",
        "Next request envelopes must preserve table selector and Count.",
    )
    yield Probe(
        "getNext request envelope rejects boolean UID list",
        table_wrapper_context + [{"input": {"function": "getNext", "kwargs": {"tableRequest": {"values": {"table": "C_PIN", "Count": 2, "authAs": "Anybody"}}}}, "output": {"return": [True]}}],
        "FAIL",
        "table-lifecycle-delete-query-envelope-doc",
        "Next request envelopes preserve UID-list result validation.",
    )
    yield Probe(
        "getFreeSpace request envelope accepts two-field result",
        table_wrapper_context + [{"input": {"function": "getFreeSpace", "kwargs": {"freeSpaceRequest": {"values": {"authAs": "Anybody"}}}}, "output": {"return": {"FreeSpace": 1024, "TableRows": []}}}],
        "PASS",
        "table-lifecycle-delete-query-envelope-doc",
        "GetFreeSpace request envelopes preserve ThisSP free-space result shape.",
    )
    yield Probe(
        "getFreeSpace request envelope rejects boolean result",
        table_wrapper_context + [{"input": {"function": "getFreeSpace", "kwargs": {"spRequest": {"values": {"authAs": "Anybody"}}}}, "output": {"return": True}}],
        "FAIL",
        "table-lifecycle-delete-query-envelope-doc",
        "GetFreeSpace request envelopes must still reject scalar Boolean success.",
    )
    for alias in ("makeTable", "allocateTable"):
        yield Probe(
            f"{alias} wrapper accepts valid object table",
            table_wrapper_context
            + [
                {
                    "input": {"function": alias, "kwargs": {"name": "T", "kind": "Object", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "minSize": 1, "authAs": ("Admin1", "new")}},
                    "output": {"return": ["0000010000000001", 1]},
                }
            ],
            "PASS",
            "table-wrapper",
            f"{alias} should lower to ThisSP.CreateTable and preserve required table parameters.",
        )
    yield Probe(
        "newObjectTable wrapper supplies object kind",
        table_wrapper_context
        + [
            {
                "input": {"function": "newObjectTable", "kwargs": {"name": "T", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "minSize": 1, "authAs": ("Admin1", "new")}},
                "output": {"return": ["0000010000000001", 1]},
            }
        ],
        "PASS",
        "table-wrapper",
        "newObjectTable may infer Object kind while preserving the other CreateTable requirements.",
    )
    yield Probe(
        "newObjectTable wrapper rejects missing MinSize",
        table_wrapper_context
        + [
            {
                "input": {"function": "newObjectTable", "kwargs": {"name": "T", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "authAs": ("Admin1", "new")}},
                "output": {"return": ["0000010000000001", 1]},
            }
        ],
        "FAIL",
        "table-wrapper",
        "newObjectTable must still preserve the CreateTable MinSize requirement.",
    )
    yield Probe(
        "getNext wrapper accepts table UID list",
        table_wrapper_context + [{"input": {"function": "getNext", "args": ["C_PIN"], "kwargs": {"Count": 2}}, "output": {"return": ["0000000B00010001"]}}],
        "PASS",
        "table-wrapper",
        "getNext should lower to the table Next method.",
    )
    yield Probe(
        "getNext wrapper rejects Boolean UID list payload",
        table_wrapper_context + [{"input": {"function": "getNext", "args": ["C_PIN"], "kwargs": {"Count": 2}}, "output": {"return": [True]}}],
        "FAIL",
        "table-wrapper",
        "Next returns UID column values, so wrapper return lists must be preserved and validated as UID refs.",
    )
    yield Probe(
        "getNext wrapper rejects ACE shorthand row payload for C_PIN",
        table_wrapper_context + [{"input": {"function": "getNext", "args": ["C_PIN"], "kwargs": {"Count": 2}}, "output": {"return": [1]}}],
        "FAIL",
        "table-wrapper",
        "Next over C_PIN returns C_PIN row UIDs; bare integers must not be accepted as ACE shorthand refs.",
    )
    for alias in ("nextRows", "listNext", "nextUIDs", "getNextUIDs", "readNext", "fetchNext", "enumerateNext", "listRows", "scanNext", "fetchRows", "readRows", "enumerateRows", "listUIDs", "scanRows"):
        yield Probe(
            f"{alias} wrapper accepts table UID list",
            table_wrapper_context + [{"input": {"function": alias, "args": ["C_PIN"], "kwargs": {"Count": 2}}, "output": {"return": ["0000000B00010001"]}}],
            "PASS",
            "table-wrapper",
            f"{alias} should lower to the table Next method.",
        )
        yield Probe(
            f"{alias} wrapper rejects Boolean UID list payload",
            table_wrapper_context + [{"input": {"function": alias, "args": ["C_PIN"], "kwargs": {"Count": 2}}, "output": {"return": [True]}}],
            "FAIL",
            "table-wrapper",
            f"{alias} must preserve Next UID-list result validation.",
        )
    yield Probe(
        "getFreeSpace wrapper accepts two field result",
        table_wrapper_context + [{"input": {"function": "getFreeSpace"}, "output": {"return": {"FreeSpace": 1024, "TableRows": []}}}],
        "PASS",
        "table-wrapper",
        "getFreeSpace should lower to ThisSP.GetFreeSpace and keep the two-field result shape.",
    )
    for alias in ("getFreeSpace", "freeSpace", "queryFreeSpace", "getAvailableSpace", "availableSpace", "remainingSpace", "freeSpaceBytes", "availableBytes", "getAvailableBytes", "queryAvailableSpace", "spaceAvailable", "getRemainingSpace", "remainingBytes", "freeBytes", "getFreeBytes", "spaceFree", "availableStorage", "getAvailableStorage"):
        yield Probe(
            f"{alias} wrapper rejects boolean success",
            table_wrapper_context + [{"input": {"function": alias}, "output": {"return": True}}],
            "FAIL",
            "table-wrapper",
            f"{alias} must preserve the two-field GetFreeSpace result shape.",
        )
    for alias in ("queryFreeSpace", "getAvailableSpace", "availableSpace", "remainingSpace", "freeSpaceBytes", "availableBytes", "getAvailableBytes", "queryAvailableSpace", "spaceAvailable", "getRemainingSpace", "remainingBytes", "freeBytes", "getFreeBytes", "spaceFree", "availableStorage", "getAvailableStorage"):
        yield Probe(
            f"{alias} wrapper accepts two field result",
            table_wrapper_context + [{"input": {"function": alias}, "output": {"return": {"FreeSpace": 1024, "TableRows": []}}}],
            "PASS",
            "table-wrapper",
            f"{alias} should lower to ThisSP.GetFreeSpace and keep the two-field result shape.",
        )
    yield Probe(
        "createRow wrapper accepts Locking range row",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": ["0000080200030002"]}}],
        "PASS",
        "table-wrapper",
        "createRow should lower to LockingTable.CreateRow and preserve RangeStart/RangeLength.",
    )
    yield Probe(
        "createRow wrapper rejects boolean created-row result",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": True}}],
        "FAIL",
        "table-wrapper",
        "Locking CreateRow success returns the created row UID list rather than a Boolean success marker.",
    )
    yield Probe(
        "createRow wrapper rejects empty created-row result",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": []}}],
        "FAIL",
        "table-wrapper",
        "Locking CreateRow creates one row, so the success result cannot be an empty UID list.",
    )
    yield Probe(
        "createRow wrapper rejects non-locking created-row UID",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": ["0000DEAD0000BEEF"]}}],
        "FAIL",
        "table-wrapper",
        "Locking CreateRow must return a Locking range row UID, not an unrelated UID-shaped value.",
    )
    yield Probe(
        "createRow wrapper rejects status-string created-row payload",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": "FAIL"}}],
        "FAIL",
        "table-wrapper",
        "A status string is not an object UID and cannot satisfy Locking CreateRow's created-row UID result.",
    )
    yield Probe(
        "createRow wrapper rejects missing range values",
        table_wrapper_context + [{"input": {"function": "createRow", "args": ["Locking", {}]}, "output": {"return": ["0000080200030002"]}}],
        "FAIL",
        "table-wrapper",
        "Locking CreateRow still requires RangeStart and RangeLength after wrapper lowering.",
    )
    for alias in ("insertRow", "addRow", "appendRow", "createTableRow", "newTableRow", "makeRow", "allocateRow", "createObjectRow", "insertTableRow", "appendTableRow", "addTableRow"):
        yield Probe(
            f"{alias} wrapper accepts Locking range row",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking", {"RangeStart": 100, "RangeLength": 8}]}, "output": {"return": ["0000080200030002"]}}],
            "PASS",
            "table-wrapper",
            f"{alias} should lower to table CreateRow and preserve RangeStart/RangeLength.",
        )
        yield Probe(
            f"{alias} wrapper rejects missing range values",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking", {}]}, "output": {"return": ["0000080200030002"]}}],
            "FAIL",
            "table-wrapper",
            f"{alias} must preserve Locking CreateRow RangeStart/RangeLength requirements.",
        )
    yield Probe(
        "deleteRow wrapper accepts Locking range row",
        table_wrapper_context + [{"input": {"function": "deleteRow", "args": ["Locking", "0000080200030002"]}, "output": {"return": []}}],
        "PASS",
        "table-wrapper",
        "deleteRow should lower to LockingTable.DeleteRow and preserve row UID arguments.",
    )
    yield Probe(
        "deleteRow wrapper rejects missing row UID",
        table_wrapper_context + [{"input": {"function": "deleteRow", "args": ["Locking"]}, "output": {"return": []}}],
        "FAIL",
        "table-wrapper",
        "DeleteRow still requires row UID arguments after wrapper lowering.",
    )
    for alias in ("deleteTableRow", "removeTableRow", "dropRow", "deleteObjectRow", "removeObjectRow", "destroyTableRow", "eraseRow", "deleteRows", "removeRows"):
        yield Probe(
            f"{alias} wrapper accepts Locking range row",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking", "0000080200030002"]}, "output": {"return": []}}],
            "PASS",
            "table-wrapper",
            f"{alias} should lower to table DeleteRow and preserve row UID arguments.",
        )
        yield Probe(
            f"{alias} wrapper rejects missing row UID",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking"]}, "output": {"return": []}}],
            "FAIL",
            "table-wrapper",
            f"{alias} must preserve the DeleteRow row UID requirement.",
        )
    yield Probe(
        "tableQuery wrapper accepts free row count",
        table_wrapper_context + [{"input": {"function": "tableQuery", "args": ["Locking"]}, "output": {"return": [4]}}],
        "PASS",
        "table-wrapper",
        "tableQuery should lower to table GetFreeRows and preserve the one-field result shape.",
    )
    for alias in ("getFreeRows", "freeRows", "tableQuery", "queryTable", "queryFreeRows", "availableRows", "getAvailableRows", "remainingRows", "freeRowCount", "availableRowCount", "getRemainingRows"):
        yield Probe(
            f"{alias} wrapper rejects boolean success",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking"]}, "output": {"return": True}}],
            "FAIL",
            "table-wrapper",
            f"{alias} must preserve the one-field GetFreeRows result shape.",
        )
        yield Probe(
            f"{alias} wrapper rejects extra result field",
            table_wrapper_context + [{"input": {"function": alias, "args": ["Locking"]}, "output": {"return": [4, "extra"]}}],
            "FAIL",
            "table-wrapper",
            f"{alias} successful responses have exactly one FreeRows field.",
        )
    yield Probe(
        "queryTable wrapper rejects byte table target",
        table_wrapper_context + [{"input": {"function": "queryTable", "args": ["DataStore"]}, "output": {"return": [4]}}],
        "FAIL",
        "table-wrapper",
        "GetFreeRows is defined for object tables, not byte tables.",
    )
    yield Probe(
        "deleteRange wrapper accepts optional Locking range object",
        table_wrapper_context + [{"input": {"function": "deleteRange", "args": [2]}, "output": {"return": []}}],
        "PASS",
        "table-wrapper",
        "deleteRange should lower to direct Locking range Delete.",
    )
    yield Probe(
        "deleteObject wrapper rejects GlobalRange delete success",
        table_wrapper_context + [{"input": {"function": "deleteObject", "args": ["Locking_GlobalRange"]}, "output": {"return": []}}],
        "FAIL",
        "table-wrapper",
        "Direct Delete is modeled only for deletable non-global Locking range rows.",
    )
    delete_table_wrapper_context = table_wrapper_context + [
        {
            "input": {"function": "createTable", "kwargs": {"name": "DelT", "kind": "Object", "acl": ["ACE_00000001"], "columns": [{"Name": "A", "Type": "uinteger"}], "minSize": 1, "authAs": ("Admin1", "new")}},
            "output": {"return": ["0000016300000000", 1]},
        }
    ]
    yield Probe(
        "deleteTable wrapper accepts created table UID",
        delete_table_wrapper_context + [{"input": {"function": "deleteTable", "args": ["0000016300000000"]}, "output": {"return": []}}],
        "PASS",
        "table-wrapper",
        "deleteTable should alias a created table UID to its Table descriptor Delete object.",
    )
    yield Probe(
        "deleteTable wrapper rejects non-empty success return",
        delete_table_wrapper_context + [{"input": {"function": "deleteTable", "args": ["0000016300000000"]}, "output": {"return": ["unexpected"]}}],
        "FAIL",
        "table-wrapper",
        "Successful table descriptor Delete returns an empty list.",
    )

    xor_wrapper_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        method_record("Set", "0000100100000000", "DataStore", optional={"Bytes": "0F0F"}),
    ]
    yield Probe(
        "xor wrapper returns direct XOR result",
        xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {"PatternInput": "DataStore", "Input": {"Data": "F00F"}}}, "output": {"status": "SUCCESS", "return_values": "FF00"}}],
        "PASS",
        "xor-wrapper",
        "xor should lower to ThisSP.XOR and compare direct byte results against the known pattern input.",
    )
    for alias in ("xorBytes", "xorDataBytes", "oneTimePadXor", "otpXor"):
        yield Probe(
            f"{alias} wrapper returns direct XOR result",
            xor_wrapper_context + [{"input": {"function": alias, "kwargs": {"PatternInput": "DataStore", "Input": {"Data": "F00F"}}}, "output": {"status": "SUCCESS", "return_values": "FF00"}}],
            "PASS",
            "xor-wrapper",
            f"{alias} should lower to ThisSP.XOR and compare direct byte results against the known pattern input.",
        )
        yield Probe(
            f"{alias} wrapper rejects stale XOR result",
            xor_wrapper_context + [{"input": {"function": alias, "kwargs": {"PatternInput": "DataStore", "Input": {"Data": "F00F"}}}, "output": {"status": "SUCCESS", "return_values": "0F0F"}}],
            "FAIL",
            "xor-wrapper",
            f"{alias} must preserve XOR byte-result comparison.",
        )
    xor_domain_values = {"PatternInput": "DataStore", "Input": {"Data": "F00F"}, "authAs": ("Admin1", "new")}
    for envelope in ("xorRequest", "cryptoRequest", "byteTableRequest", "operationRequest"):
        yield Probe(
            f"xor {envelope} returns direct XOR result",
            xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {envelope: {"values": xor_domain_values}}}, "output": {"status": "SUCCESS", "return_values": "FF00"}}],
            "PASS",
            "xor-domain-request-envelope-doc",
            "XOR domain request envelopes must preserve PatternInput and Input bytes.",
        )
        yield Probe(
            f"xor {envelope} rejects stale XOR result",
            xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {envelope: {"values": xor_domain_values}}}, "output": {"status": "SUCCESS", "return_values": "0F0F"}}],
            "FAIL",
            "xor-domain-request-envelope-doc",
            "XOR domain request envelopes must preserve byte-result comparison.",
        )
    for wrapper_key, wrapper_payload in (
        ("operation", {"command": xor_domain_values}),
        ("operationRequest", {"command": xor_domain_values}),
        ("command", xor_domain_values),
        ("action", xor_domain_values),
    ):
        yield Probe(
            f"xor {wrapper_key} command envelope returns direct XOR result",
            xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"status": "SUCCESS", "return_values": "FF00"}}],
            "PASS",
            "xor-operation-envelope-doc",
            "XOR operation-style command envelopes must preserve PatternInput and Input bytes.",
        )
        yield Probe(
            f"xor {wrapper_key} command envelope rejects stale XOR result",
            xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {wrapper_key: wrapper_payload}}, "output": {"status": "SUCCESS", "return_values": "0F0F"}}],
            "FAIL",
            "xor-operation-envelope-doc",
            "XOR operation-style command envelopes must preserve byte-result comparison.",
        )
    xor_domain_bufferout_values = {
        "PatternInput": "DataStore",
        "Input": {"Data": "F00F"},
        "BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 1}},
        "authAs": ("Admin1", "new"),
    }
    for envelope in ("xorRequest", "byteTableRequest"):
        yield Probe(
            f"xor {envelope} BufferOut mutates DataStore bytes",
            xor_wrapper_context
            + [
                {"input": {"function": "xor", "kwargs": {envelope: {"values": xor_domain_bufferout_values}}}, "output": {"status": "SUCCESS", "return_values": []}},
                method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 0}, {"endRow": 1}]}, return_values="FF00"),
            ],
            "PASS",
            "xor-domain-request-envelope-doc",
            "XOR BufferOut request envelopes must preserve output cellblock mutation.",
        )
        yield Probe(
            f"xor {envelope} BufferOut rejects boolean result",
            xor_wrapper_context + [{"input": {"function": "xor", "kwargs": {envelope: {"values": xor_domain_bufferout_values}}}, "output": {"status": "SUCCESS", "return_values": True}}],
            "FAIL",
            "xor-domain-request-envelope-doc",
            "XOR with BufferOut returns an empty result list, not a Boolean marker.",
        )
    xor_bufferout_context = xor_wrapper_context + [
        method_record(
            "XOR",
            "0000000000000001",
            "ThisSP",
            required={"PatternInput": "DataStore", "Input": {"Data": "F00F"}},
            optional={"BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 1}}},
            return_values=[],
        )
    ]
    yield Probe(
        "XOR BufferOut mutates DataStore bytes",
        xor_bufferout_context + [method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 0}, {"endRow": 1}]}, return_values="FF00")],
        "PASS",
        "xor-wrapper",
        "A successful XOR with BufferOut stores the XOR result in the referenced byte table.",
    )
    yield Probe(
        "XOR BufferOut rejects stale DataStore bytes",
        xor_bufferout_context + [method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 0}, {"endRow": 1}]}, return_values="0F0F")],
        "FAIL",
        "xor-wrapper",
        "The referenced BufferOut bytes cannot remain at their pre-XOR value.",
    )
    xor_cellblock_context = activated_locking_context() + [
        start_session(LOCKING_SP, ADMIN1, "new"),
        method_record("Set", "0000100100000000", "DataStore", optional={"Bytes": "F00F"}),
        method_record("Set", "0000080400000000", "MBR", optional={"Bytes": "0F0F"}),
    ]
    yield Probe(
        "XOR accepts DataStore cellblock as input bytes",
        xor_cellblock_context
        + [
            method_record(
                "XOR",
                "0000000000000001",
                "ThisSP",
                required={"PatternInput": "MBR", "Input": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 1}}},
                return_values="FF00",
            )
        ],
        "PASS",
        "xor-wrapper",
        "XOR Input may be a byte-table cellblock; the known DataStore bytes are XORed against PatternInput.",
    )
    xor_cellblock_bufferout_context = xor_cellblock_context + [
        method_record(
            "XOR",
            "0000000000000001",
            "ThisSP",
            required={"PatternInput": "MBR", "Input": {"CellBlock": {"Table": "DataStore", "startRow": 0, "endRow": 1}}},
            optional={"BufferOut": {"CellBlock": {"Table": "DataStore", "startRow": 2, "endRow": 3}}},
            return_values=[],
        )
    ]
    yield Probe(
        "XOR cellblock input BufferOut mutates destination bytes",
        xor_cellblock_bufferout_context + [method_record("Get", "0000100100000000", "DataStore", required={"Cellblock": [{"startRow": 2}, {"endRow": 3}]}, return_values="FF00")],
        "PASS",
        "xor-wrapper",
        "XOR with cellblock Input and BufferOut stores the computed result in the destination byte-table cellblock.",
    )


def raw_empty_result_probes() -> Iterable[Probe]:
    raw_admin_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    raw_locking_context = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    yield Probe(
        "raw Set MBRControl rejects Boolean empty result",
        raw_admin_context
        + [
            method_record(
                "Set",
                "0000080300000001",
                "MBRControl",
                optional={"Values": [{"1": True}]},
                return_values=True,
            )
        ],
        "FAIL",
        "raw-empty-result",
        "Raw Core Set returns an empty list; Boolean success is only a high-level wrapper convention.",
    )
    yield Probe(
        "raw Set Locking rejects Boolean empty result",
        raw_locking_context
        + [
            method_record(
                "Set",
                LOCKING_RANGE1,
                "Locking",
                optional={"Values": [{"7": True}]},
                return_values=True,
            )
        ],
        "FAIL",
        "raw-empty-result",
        "Raw Core Set cannot satisfy its empty result shape with a literal Boolean.",
    )
    yield Probe(
        "raw K_AES GenKey rejects Boolean empty result",
        raw_locking_context + [method_record("GenKey", "0000080600030001", "K_AES_256", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw Opal GenKey success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw Locking Delete rejects Boolean empty result",
        raw_locking_context + [method_record("Delete", LOCKING_RANGE1, "Locking", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw Delete success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw Activate rejects Boolean empty result",
        raw_admin_context + [method_record("Activate", LOCKING_SP, "LockingSP", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw Activate success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw RevertSP rejects Boolean empty result",
        raw_locking_context + [method_record("RevertSP", LOCKING_SP, "LockingSP", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw RevertSP success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw AddLog rejects Boolean empty result",
        raw_admin_context
        + [
            method_record(
                "AddLog",
                "0000000A00000001",
                "Log",
                required={"LogEntryName": "x", "Data": "AA"},
                return_values=True,
            )
        ],
        "FAIL",
        "raw-empty-result",
        "Raw AddLog success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw ClearLog rejects Boolean empty result",
        raw_admin_context + [method_record("ClearLog", "0000000A00000001", "Log", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw ClearLog success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw FlushLog rejects Boolean empty result",
        raw_admin_context + [method_record("FlushLog", "0000000A00000001", "Log", return_values=True)],
        "FAIL",
        "raw-empty-result",
        "Raw FlushLog success returns an empty list, not a Boolean wrapper flag.",
    )
    yield Probe(
        "raw SetACL rejects Boolean empty result",
        raw_locking_context
        + [
            method_record(
                "SetACL",
                "0000000700000000",
                "AccessControl",
                required={"InvokingID": "Locking_Range1", "MethodID": "Get", "ACL": ["ACE_00000003"]},
                return_values=True,
            )
        ],
        "FAIL",
        "raw-empty-result",
        "Raw SetACL success returns an empty list, not a Boolean wrapper flag.",
    )
    for method, symbol in (
        ("HashInit", "H_SHA_256"),
        ("HMACInit", "H_SHA_256"),
        ("EncryptInit", "K_AES_256"),
        ("DecryptInit", "K_AES_256"),
    ):
        yield Probe(
            f"raw {method} rejects Boolean empty result",
            raw_admin_context + [method_record(method, "0000080600030001", symbol, return_values=True)],
            "FAIL",
            "raw-empty-result",
            f"Raw {method} success returns an empty list, not a Boolean wrapper flag.",
        )
    yield Probe(
        "wrapper setRange Boolean success remains accepted",
        raw_locking_context + [function_record("setRange", [1], {"authAs": ("Admin1", "new"), "RangeStart": 120, "RangeLength": 8}, True)],
        "PASS",
        "raw-empty-result",
        "High-level wrappers may expose Boolean success while the lowered method is empty-list typed.",
    )
    yield Probe(
        "wrapper rollKey Boolean success remains accepted",
        raw_locking_context + [function_record("rollKey", [], {"range_key": "K_AES_256_Range1_Key", "authAs": ("Admin1", "new")}, True)],
        "PASS",
        "raw-empty-result",
        "High-level GenKey wrappers may expose Boolean success while raw GenKey remains empty-list typed.",
    )
    yield Probe(
        "wrapper activateLockingSP Boolean success remains accepted",
        raw_admin_context + [function_record("activateLockingSP", [], {"authAs": ("SID", "new")}, True)],
        "PASS",
        "raw-empty-result",
        "High-level Activate wrappers may expose Boolean success while raw Activate remains empty-list typed.",
    )
    yield Probe(
        "wrapper addLog Boolean success remains accepted",
        raw_admin_context + [function_record("addLog", [], {"log": "Log", "LogEntryName": "x", "Data": "AA", "authAs": ("SID", "new")}, True)],
        "PASS",
        "raw-empty-result",
        "High-level AddLog wrappers may expose Boolean success while raw AddLog remains empty-list typed.",
    )
    yield Probe(
        "wrapper clearLog Boolean success remains accepted",
        raw_admin_context + [function_record("clearLog", [], {"log": "Log", "authAs": ("SID", "new")}, True)],
        "PASS",
        "raw-empty-result",
        "High-level ClearLog wrappers may expose Boolean success while raw ClearLog remains empty-list typed.",
    )


def table_query_shape_probes() -> Iterable[Probe]:
    table_context = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    admin_context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    for bad_payload in ({"ok": True}, {"return": True}, ["extra"], [True], {"value": True}):
        yield Probe(
            f"GetFreeRows rejects non-uinteger payload {bad_payload!r}",
            table_context + [method_record("GetFreeRows", "0000000100000008", "LockingTable", return_values=bad_payload)],
            "FAIL",
            "table-query-shape",
            "GetFreeRows returns one non-Boolean uinteger value, not an arbitrary one-field payload.",
        )
    for good_payload in ([4], {"FreeRows": 4}, {"return": [4]}, {"Rows": 4}):
        yield Probe(
            f"GetFreeRows accepts uinteger payload {good_payload!r}",
            table_context + [method_record("GetFreeRows", "0000000100000008", "LockingTable", return_values=good_payload)],
            "PASS",
            "table-query-shape",
            "GetFreeRows may be represented as a one-element result list or a named FreeRows/Rows uinteger field.",
        )
    for good_payload in ([1024, 8], {"FreeSpace": 1024, "TableRows": 8}, {"return": [1024, 8]}):
        yield Probe(
            f"GetFreeSpace accepts uinteger pair {good_payload!r}",
            admin_context + [method_record("GetFreeSpace", "0000000000000001", "ThisSP", return_values=good_payload)],
            "PASS",
            "table-query-shape",
            "GetFreeSpace returns two uinteger values: FreeSpace and TableRows.",
        )
    for bad_payload in (["x", "y"], [True, 8], {"ok": True, "other": 1}):
        yield Probe(
            f"GetFreeSpace rejects non-uinteger pair {bad_payload!r}",
            admin_context + [method_record("GetFreeSpace", "0000000000000001", "ThisSP", return_values=bad_payload)],
            "FAIL",
            "table-query-shape",
            "GetFreeSpace result shape requires two non-Boolean uinteger values.",
        )


def sign_payload_shape_probes() -> Iterable[Probe]:
    context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    for bad_payload in ({"ok": True}, {"return": True}, [True], {"Data": True}, 1):
        yield Probe(
            f"Sign rejects nested Boolean payload {bad_payload!r}",
            context + [method_record("Sign", "", "C_RSA_2048", required={"Input": {"Data": "AA"}}, return_values=bad_payload)],
            "FAIL",
            "sign-payload-shape",
            "Sign without BufferOut returns signature bytes, not a Boolean flag or scalar integer payload.",
        )
    for good_payload in ("AABB", {"Data": "AABB"}, ["AABB"]):
        yield Probe(
            f"Sign accepts byte payload {good_payload!r}",
            context + [method_record("Sign", "", "C_RSA_2048", required={"Input": {"Data": "AA"}}, return_values=good_payload)],
            "PASS",
            "sign-payload-shape",
            "Sign without BufferOut may return signature bytes directly or under a byte-data payload wrapper.",
        )


def crypto_stream_payload_shape_probes() -> Iterable[Probe]:
    context = owned_admin_context() + [start_session(ADMIN_SP, SID, "new")]
    hash_context = context + [method_record("HashInit", "0000000900000006", "H_SHA_256", return_values=[])]
    for bad_payload in ({"ok": True}, {"return": True}, [True], {"Data": True}, 1):
        yield Probe(
            f"Hash rejects nested Boolean payload {bad_payload!r}",
            hash_context + [method_record("Hash", "0000000900000006", "H_SHA_256", required={"Data": "AA"}, return_values=bad_payload)],
            "FAIL",
            "crypto-stream-payload-shape",
            "Hash without BufferOut returns digest bytes, not a Boolean flag or scalar integer payload.",
        )
    yield Probe(
        "Hash rejects empty digest result without BufferOut",
        hash_context + [method_record("Hash", "0000000900000006", "H_SHA_256", required={"Data": "AA"}, return_values={})],
        "FAIL",
        "crypto-stream-payload-shape",
        "Hash without BufferOut returns a non-empty digest byte payload; empty results are reserved for BufferOut-style flows.",
    )
    for good_payload in ("AABB", {"Data": "AABB"}, ["AABB"]):
        yield Probe(
            f"Hash accepts byte payload {good_payload!r}",
            hash_context + [method_record("Hash", "0000000900000006", "H_SHA_256", required={"Data": "AA"}, return_values=good_payload)],
            "PASS",
            "crypto-stream-payload-shape",
            "Hash digest bytes may be represented directly or under a byte-data payload wrapper.",
        )
    wrapper_context = context + [{"input": {"function": "hashInit", "kwargs": {"algorithm": "sha256", "authAs": "Anybody"}}, "output": {"return": []}}]
    yield Probe(
        "hash wrapper rejects list-wrapped Boolean digest payload",
        wrapper_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AA", "authAs": "Anybody"}}, "output": {"return": [True]}}],
        "FAIL",
        "crypto-stream-payload-shape",
        "Wrapper return lists for crypto stream byte outputs must be treated as payload lists, not legacy status tuples.",
    )
    yield Probe(
        "hash wrapper accepts list-wrapped byte digest payload",
        wrapper_context + [{"input": {"function": "hash", "kwargs": {"algorithm": "sha256", "data": "AA", "authAs": "Anybody"}}, "output": {"return": ["AABB"]}}],
        "PASS",
        "crypto-stream-payload-shape",
        "A one-element wrapper return list may carry byte digest data.",
    )


def locking_range_lock_envelope_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    cases = (
        ("setReadLockEnabled", {"state": {"enabled": True}}, "getReadLockEnabled", True, False),
        ("setWriteLockEnabled", {"state": {"enabled": True}}, "getWriteLockEnabled", True, False),
        ("setReadLocked", {"state": {"locked": True}}, "getReadLocked", True, False),
        ("setWriteLocked", {"state": {"locked": True}}, "getWriteLocked", True, False),
        ("configureRangeReadLock", {"locks": {"read": True}}, "getReadLockEnabled", True, False),
        ("configureRangeWriteLock", {"locks": {"write": True}}, "getWriteLockEnabled", True, False),
    )
    for setter, payload, getter, current, stale in cases:
        mutation = function_record(setter, [], {"rangeId": 1, "authAs": ("Admin1", "new"), **payload}, True)
        yield Probe(
            f"{setter} envelope accepts current {getter}",
            context + [mutation, function_record(getter, [], {"rangeId": 1, "authAs": ("Admin1", "new")}, current)],
            "PASS",
            "locking-range-lock-envelope-doc",
            "SDK-style state/locks envelopes should lower to the same Locking range lock columns as direct Set values.",
        )
        yield Probe(
            f"{setter} envelope rejects stale {getter}",
            context + [mutation, function_record(getter, [], {"rangeId": 1, "authAs": ("Admin1", "new")}, stale)],
            "FAIL",
            "locking-range-lock-envelope-doc",
            "A stale lock-field getter after a successful envelope setter indicates the wrapper payload was ignored.",
        )
    output_cases = (
        ("setReadLockEnabled", {"enabled": True}, "getReadLockEnabled", {"locks": {"read": True}}, {"locks": {"read": False}}),
        ("setWriteLockEnabled", {"enabled": True}, "getWriteLockEnabled", {"locks": {"write": True}}, {"locks": {"write": False}}),
        ("setReadLocked", {"locked": True}, "getReadLocked", {"lockState": {"read": True}}, {"lockState": {"read": False}}),
        ("setWriteLocked", {"locked": True}, "getWriteLocked", {"lockState": {"write": True}}, {"lockState": {"write": False}}),
    )
    for setter, setter_payload, getter, current, stale in output_cases:
        mutation = function_record(setter, [], {"rangeId": 1, "authAs": ("Admin1", "new"), **setter_payload}, True)
        yield Probe(
            f"{getter} accepts current directional output envelope",
            context + [mutation, function_record(getter, [], {"rangeId": 1, "authAs": ("Admin1", "new")}, current)],
            "PASS",
            "locking-range-lock-envelope-doc",
            "Directional locks/lockState output envelopes should compare against the tracked Locking range Boolean cell.",
        )
        yield Probe(
            f"{getter} rejects stale directional output envelope",
            context + [mutation, function_record(getter, [], {"rangeId": 1, "authAs": ("Admin1", "new")}, stale)],
            "FAIL",
            "locking-range-lock-envelope-doc",
            "A stale directional output envelope must not satisfy the tracked Locking range Boolean cell.",
        )
    composite_context = context + [
        function_record("setReadLockEnabled", [], {"rangeId": 1, "authAs": ("Admin1", "new"), "state": {"enabled": True}}, True),
        function_record("setReadLocked", [], {"rangeId": 1, "authAs": ("Admin1", "new"), "state": {"locked": True}}, True),
    ]
    yield Probe(
        "getRange accepts current directional locks envelope",
        composite_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"rangeInfo": {"locks": {"read": True}}})],
        "PASS",
        "locking-range-lock-envelope-doc",
        "Composite getRange should recognize directional lock envelopes as the tracked ReadLocked cell.",
    )
    yield Probe(
        "getRange rejects stale directional locks envelope",
        composite_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"rangeInfo": {"locks": {"read": False}}})],
        "FAIL",
        "locking-range-lock-envelope-doc",
        "Composite getRange must compare directional lock envelope values, not merely require a lock-state field to exist.",
    )
    geometry_context = context + [
        function_record("configureRangeGeometry", [], {"rangeId": 1, "authAs": ("Admin1", "new"), "RangeStart": 240, "RangeLength": 8}, True),
    ]
    yield Probe(
        "getRange accepts lba/blocks window envelope",
        geometry_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"window": {"lba": 240, "blocks": 8}})],
        "PASS",
        "locking-range-lock-envelope-doc",
        "Composite getRange window envelopes may spell RangeStart/RangeLength as lba/blocks.",
    )
    yield Probe(
        "getRange rejects stale lba/blocks window envelope",
        geometry_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"window": {"lba": 241, "blocks": 8}})],
        "FAIL",
        "locking-range-lock-envelope-doc",
        "Composite getRange must compare lba/blocks window values against the tracked RangeStart/RangeLength cells.",
    )
    yield Probe(
        "getRange accepts sector/sectors window envelope",
        geometry_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"window": {"sector": 240, "sectors": 8}})],
        "PASS",
        "locking-range-lock-envelope-doc",
        "Composite getRange window envelopes may spell RangeStart/RangeLength as sector/sectors.",
    )
    yield Probe(
        "getRange rejects stale sector/sectors window envelope",
        geometry_context + [function_record("getRange", [], {"rangeId": 1, "authAs": ("Admin1", "new")}, {"window": {"sector": 241, "sectors": 8}})],
        "FAIL",
        "locking-range-lock-envelope-doc",
        "Composite getRange must compare sector/sectors values against the tracked RangeStart/RangeLength cells.",
    )


def accesscontrol_acl_result_alias_probes() -> Iterable[Probe]:
    context = activated_locking_context() + [start_session(LOCKING_SP, ADMIN1, "new")]
    expected_acl = ["ACE_0003D001", "ACE_00000003"]
    for key in (
        "accessControlList",
        "aceEntries",
        "entries",
        "aclEntries",
        "ACLEntries",
        "acl_entries",
        "aceList",
        "ACEList",
        "ace_list",
        "accessList",
        "accessEntries",
        "access_list",
        "access_entries",
    ):
        yield Probe(
            f"GetACL accepts {key} result wrapper",
            context + [function_record("getACL", [], {"object": "Locking_Range1", "method": "Get", "authAs": ("Admin1", "new")}, {key: expected_acl})],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL returns an ACE uidref list; SDK wrappers may name the list with explicit ACL/ACE/access-list wrapper keys.",
        )
    for label, payload in (
        ("uid object list", [{"uid": "ACE_0003D001"}, {"uid": "ACE_00000003"}]),
        ("rows uid object list", {"rows": [{"uid": "ACE_0003D001"}, {"uid": "ACE_00000003"}]}),
        ("entries object list", {"entries": [{"object": "ACE_0003D001"}, {"object": "ACE_00000003"}]}),
        ("acl ref object list", {"acl": [{"ref": "ACE_0003D001"}, {"ref": "ACE_00000003"}]}),
    ):
        yield Probe(
            f"GetACL accepts {label}",
            context + [function_record("getACL", [], {"object": "Locking_Range1", "method": "Get", "authAs": ("Admin1", "new")}, payload)],
            "PASS",
            "accesscontrol-wrapper",
            "GetACL ACE uidrefs may be wrapped as per-entry objects as long as exact refs are preserved.",
        )
    yield Probe(
        "GetACL rejects incomplete accessControlList wrapper",
        context + [function_record("getACL", [], {"object": "Locking_Range1", "method": "Get", "authAs": ("Admin1", "new")}, {"accessControlList": ["ACE_0003D001"]})],
        "FAIL",
        "accesscontrol-wrapper",
        "Known GetACL associations with exact ACLs must reject incomplete ACE uidref lists even when wrapped.",
    )



def all_probes() -> list[Probe]:
    probes: list[Probe] = []
    for generator in (properties_wrapper_probes, setrange_probes, getrange_values_probes, lock_unlock_probes, genkey_probes, getmek_values_probes, erase_probes, datastore_probes, reset_lockonreset_probes, lifecycle_probes, random_probes, tpersign_probes, firmware_attestation_probes, certificate_byte_table_probes, psk_probes, port_probes, mbr_probes, accesscontrol_probes, authenticate_probes, credential_probes, authority_probes, session_probes, wrapper_alias_probe_batch, raw_empty_result_probes, table_query_shape_probes, sign_payload_shape_probes, crypto_stream_payload_shape_probes, locking_range_lock_envelope_probes, accesscontrol_acl_result_alias_probes):
        probes.extend(generator())
    return probes


def run_pass(pass_index: int, queue: Path) -> dict[str, Any]:
    started = time.time()
    probes = all_probes()
    mismatches = 0
    by_family: dict[str, int] = {}
    for probe in probes:
        got = predict_trajectory(probe.trajectory)
        by_family[probe.family] = by_family.get(probe.family, 0) + 1
        if got != probe.expected:
            mismatches += 1
            append_jsonl(
                queue,
                {
                    "found_at": now_iso(),
                    "pass_index": pass_index,
                    "name": probe.name,
                    "family": probe.family,
                    "expected": probe.expected,
                    "got": got,
                    "why": probe.why,
                    "trajectory": probe.trajectory,
                    "last_events": [compact_event(raw) for raw in probe.trajectory[-4:]],
                },
            )
    return {
        "pass_index": pass_index,
        "finished_at": now_iso(),
        "seconds": round(time.time() - started, 2),
        "probes": len(probes),
        "mismatches": mismatches,
        "by_family": dict(sorted(by_family.items())),
    }


def write_status(path: Path, record: dict[str, Any], queue: Path) -> None:
    lines = [
        "# Score Probe Loop Status",
        "",
        f"- updated: {record['finished_at']}",
        f"- pass: {record['pass_index']}",
        f"- probes: {record['probes']}",
        f"- mismatches_this_pass: {record['mismatches']}",
        f"- queue: `{queue}`",
        "",
        "## Families",
        "",
        "```json",
        json.dumps(record["by_family"], indent=2, sort_keys=True),
        "```",
        "",
        "No code edits, server sync, or submission are performed by this loop.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1, help="Number of passes. Use 0 for endless.")
    parser.add_argument("--sleep", type=int, default=120, help="Seconds between passes.")
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--history", type=Path, default=DEFAULT_HISTORY)
    parser.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    args = parser.parse_args()

    pass_index = 0
    while args.iterations == 0 or pass_index < args.iterations:
        pass_index += 1
        record = run_pass(pass_index, args.queue)
        append_jsonl(args.history, record)
        write_status(args.status, record, args.queue)
        if args.iterations != 0 and pass_index >= args.iterations:
            break
        time.sleep(args.sleep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
