"""Trajectory judging and public solver wrapper."""

from __future__ import annotations

import ast
import copy
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *
from .expectations import *
from .transitions import *


def compare_expected_actual(expected: ExpectedResponse, target: Event) -> str:
    if target.kind == "host_io" and target.method == "Read":
        if expected.forbid_read_result_presence and target.read_result is not None:
            return "FAIL"
        if expected.forbidden_read_result is not None and target.read_result == expected.forbidden_read_result:
            return "FAIL"
        if expected.expected_zero_read_result:
            return "PASS" if _read_result_is_all_zeroes(target.read_result) else "FAIL"
        if expected.expected_read_result is not None:
            return "PASS" if target.read_result == expected.expected_read_result else "FAIL"
        if expected.expected_read_byte_positions:
            if target.read_result is None or len(target.read_result) % 2:
                return "FAIL"
            actual_bytes = [target.read_result[index : index + 2].upper() for index in range(0, len(target.read_result), 2)]
            for offset, expected_byte in expected.expected_read_byte_positions.items():
                if offset < 0 or offset >= len(actual_bytes) or actual_bytes[offset] != expected_byte.upper():
                    return "FAIL"

    actual = target.status
    if actual in expected.forbidden_statuses:
        return "FAIL"
    if actual in expected.allowed_statuses:
        actual_success_like = actual in {SUCCESS, None, "PASS"}
        actual_return_bool = _return_bool(target.raw, credential_aliases=target.method == "Authenticate") if actual == SUCCESS else None
        if expected.expected_return_bool is not None and actual_return_bool is None and target.method == "Get":
            actual_return_bool = _locking_single_cell_return_bool(target)
        if expected.require_return_bool and actual_success_like and actual_return_bool is None:
            return "FAIL"
        if expected.forbid_return_bool_literal and actual_success_like and isinstance(_output_return_values(target.raw), bool):
            return "FAIL"
        if expected.forbid_return_bool_payload and actual_success_like and _return_payload_contains_bool(_output_return_values(target.raw)):
            return "FAIL"
        if expected.forbid_return_status_bool_payload and actual_success_like and _return_payload_contains_status_bool(_output_return_values(target.raw)):
            return "FAIL"
        if expected.forbid_bare_status_return_payload and actual_success_like and _return_payload_is_bare_status_bool(_output_return_values(target.raw)):
            return "FAIL"
        if expected.expected_return_bool is not None and actual_success_like and _return_payload_is_bare_status_bool(_output_return_values(target.raw)):
            return "FAIL"
        if (
            expected.expected_return_bool is not None
            and actual_success_like
            and target.method == "Get"
            and _return_payload_is_pure_status_bool_envelope(_output_return_values(target.raw))
        ):
            return "FAIL"
        if expected.require_return_byte_payload and actual_success_like:
            returned_payload = _output_return_values(target.raw)
            if returned_payload not in (None, [], (), {}) and not _return_payload_is_byte_like(returned_payload):
                return "FAIL"
        if expected.expected_return_bool is not None and actual_return_bool != expected.expected_return_bool:
            return "FAIL"
        if expected.forbidden_return_bool is not None and actual_return_bool is not None and actual_return_bool == expected.forbidden_return_bool:
            return "FAIL"
        if actual_success_like and expected.expected_return_length is not None:
            returned_payload = _output_return_values(target.raw)
            wrapper_success_payload = _high_level_bool_wrapper_success_payload(target.raw, returned_payload)
            if (
                expected.expected_return_length == 0
                and not _return_payload_is_empty(returned_payload)
                and not (isinstance(returned_payload, bool) and not expected.forbid_return_bool_literal)
                and not wrapper_success_payload
            ):
                return "FAIL"
            actual_length = _return_payload_length(returned_payload)
            if actual_length is None and expected.expected_return_length > 0 and returned_payload not in (None, [], (), {}) and not wrapper_success_payload:
                return "FAIL"
            if actual_length is not None and actual_length != expected.expected_return_length and not wrapper_success_payload:
                return "FAIL"
        if actual_success_like and expected.expected_return_uinteger_count is not None:
            if not _return_is_uinteger_sequence(_output_return_values(target.raw), expected.expected_return_uinteger_count):
                return "FAIL"
        if actual_success_like and expected.expected_return_min_length is not None:
            actual_length = _return_payload_length(_output_return_values(target.raw))
            if actual_length is None or actual_length < expected.expected_return_min_length:
                return "FAIL"
        if actual_success_like and expected.expected_return_uid_list:
            if not _return_is_uid_list(_output_return_values(target.raw)):
                return "FAIL"
        if actual_success_like and expected.require_non_empty_return_payload:
            returned_payload = _output_return_values(target.raw)
            if returned_payload in (None, [], (), {}):
                return "FAIL"
            if isinstance(returned_payload, str) and _normalize_status(returned_payload) in {
                SUCCESS,
                NOT_AUTHORIZED,
                INVALID_PARAMETER,
                INSUFFICIENT_SPACE,
                INSUFFICIENT_ROWS,
                FAIL,
                "PASS",
            }:
                return "FAIL"
        if actual_success_like and expected.expected_return_uid_list_length is not None:
            actual_uid_list_length = _return_uid_list_length(_output_return_values(target.raw))
            if actual_uid_list_length != expected.expected_return_uid_list_length:
                return "FAIL"
        if actual_success_like and expected.expected_return_uid_list_min_length is not None:
            actual_uid_list_length = _return_uid_list_length(_output_return_values(target.raw))
            if actual_uid_list_length is None or actual_uid_list_length < expected.expected_return_uid_list_min_length:
                return "FAIL"
        if actual_success_like and expected.expected_return_uid_refs:
            actual_uid_refs = _return_uid_refs(_output_return_values(target.raw))
            expected_refs = {_canonical_uid_ref(item) for item in expected.expected_return_uid_refs}
            expected_refs.discard("")
            if actual_uid_refs != expected_refs:
                return "FAIL"
        if actual_success_like and expected.required_return_uid_refs:
            actual_uid_refs = _return_uid_refs(_output_return_values(target.raw))
            required_refs = {_canonical_uid_ref(item) for item in expected.required_return_uid_refs}
            required_refs.discard("")
            if not required_refs.issubset(actual_uid_refs):
                return "FAIL"
        if actual_success_like and expected.forbidden_return_uid_refs:
            actual_uid_refs = _return_uid_refs(_output_return_values(target.raw))
            forbidden_refs = {_canonical_uid_ref(item) for item in expected.forbidden_return_uid_refs}
            forbidden_refs.discard("")
            if actual_uid_refs & forbidden_refs:
                return "FAIL"
        if actual_success_like and expected.forbidden_return_uid_ref_prefixes:
            actual_uid_refs = _return_uid_refs(_output_return_values(target.raw))
            if any(any(ref.startswith(prefix) for prefix in expected.forbidden_return_uid_ref_prefixes) for ref in actual_uid_refs):
                return "FAIL"
        if actual_success_like and expected.expected_return_pattern is not None:
            actual_pattern = _return_payload_pattern(_output_return_values(target.raw))
            if actual_pattern != expected.expected_return_pattern:
                return "FAIL"
        if actual_success_like and expected.expected_return_byte_positions:
            actual_pattern = _return_payload_pattern(_output_return_values(target.raw))
            if actual_pattern is None or len(actual_pattern) % 2:
                return "FAIL"
            actual_bytes = [actual_pattern[index : index + 2].upper() for index in range(0, len(actual_pattern), 2)]
            for offset, expected_byte in expected.expected_return_byte_positions.items():
                if offset < 0 or offset >= len(actual_bytes) or actual_bytes[offset] != expected_byte.upper():
                    return "FAIL"
        if actual_success_like and expected.expected_return_min_values:
            returned_payload = _output_return_values(target.raw)
            for selector, minimum in expected.expected_return_min_values.items():
                if not _return_value_at_least(returned_payload, selector, minimum):
                    return "FAIL"
        if actual_success_like and expected.expected_return_max_values:
            returned_payload = _output_return_values(target.raw)
            for selector, maximum in expected.expected_return_max_values.items():
                if not _return_value_at_most(returned_payload, selector, maximum):
                    return "FAIL"
        if actual_success_like and expected.optional_return_min_values:
            returned_payload = _output_return_values(target.raw)
            for selector, minimum in expected.optional_return_min_values.items():
                if _return_value_by_selector(returned_payload, selector) is not _MISSING_RETURN_VALUE and not _return_value_at_least(returned_payload, selector, minimum):
                    return "FAIL"
        if actual_success_like and expected.optional_return_max_values:
            returned_payload = _output_return_values(target.raw)
            for selector, maximum in expected.optional_return_max_values.items():
                if _return_value_by_selector(returned_payload, selector) is not _MISSING_RETURN_VALUE and not _return_value_at_most(returned_payload, selector, maximum):
                    return "FAIL"
        if actual_success_like and expected.expected_return_allowed_values:
            returned_payload = _output_return_values(target.raw)
            for selector, allowed_values in expected.expected_return_allowed_values.items():
                if not _return_value_in_allowed_set(returned_payload, selector, allowed_values):
                    return "FAIL"
        if actual_success_like and expected.expected_return_bit_masks:
            returned_payload = _output_return_values(target.raw)
            for selector, (must_set, must_clear) in expected.expected_return_bit_masks.items():
                if not _return_value_matches_bit_mask(returned_payload, selector, must_set, must_clear):
                    return "FAIL"
        if actual_success_like and expected.required_return_names:
            returned_payload = _output_return_values(target.raw)
            for name in expected.required_return_names:
                if _return_value_by_name(returned_payload, name) is _MISSING_RETURN_VALUE:
                    return "FAIL"
        if actual_success_like and expected.required_any_return_names:
            returned_payload = _output_return_values(target.raw)
            if returned_payload in (None, [], (), {}):
                pass
            elif isinstance(returned_payload, str) and _normalize_status(returned_payload) in {
                SUCCESS,
                NOT_AUTHORIZED,
                INVALID_PARAMETER,
                INSUFFICIENT_SPACE,
                INSUFFICIENT_ROWS,
                FAIL,
                "PASS",
            }:
                pass
            elif not any(_return_value_by_name(returned_payload, name) is not _MISSING_RETURN_VALUE for name in expected.required_any_return_names):
                return "FAIL"
        if actual_success_like and expected.expected_return_values:
            returned_payload = _output_return_values(target.raw)
            for name, expected_value in expected.expected_return_values.items():
                actual_value = _return_value_by_name(returned_payload, name)
                if actual_value is _MISSING_RETURN_VALUE or not _return_property_matches(actual_value, expected_value):
                    return "FAIL"
        if actual_success_like and expected.forbidden_return_names:
            returned_payload = _output_return_values(target.raw)
            for name in expected.forbidden_return_names:
                if _return_value_by_name(returned_payload, name) is not _MISSING_RETURN_VALUE:
                    return "FAIL"
        if actual_success_like and expected.expected_return_properties:
            actual_properties = _returned_host_properties(_output_return_values(target.raw))
            for name, value in expected.expected_return_properties.items():
                if name not in actual_properties or not _return_property_matches(actual_properties[name], value):
                    return "FAIL"
        if actual_success_like and expected.optional_return_properties:
            actual_properties = _returned_host_properties(_output_return_values(target.raw))
            for name, value in expected.optional_return_properties.items():
                if name in actual_properties and not _return_property_matches(actual_properties[name], value):
                    return "FAIL"
        if actual_success_like and expected.forbidden_return_properties:
            actual_properties = _returned_host_properties(_output_return_values(target.raw))
            if expected.forbidden_return_properties & set(actual_properties):
                return "FAIL"
        if actual_success_like and expected.validate_tper_properties:
            actual_properties = _returned_tper_properties(_output_return_values(target.raw))
            if not _tper_properties_valid(actual_properties):
                return "FAIL"
        returned_cells: dict[int, Any] | None = None
        if actual_success_like and (
            expected.expected_return_cells
            or expected.optional_return_cells
            or expected.expected_return_min_cells
            or expected.expected_return_max_cells
            or expected.expected_return_cell_lte
            or expected.required_return_columns
            or expected.forbidden_return_columns
            or expected.expected_return_column_types
        ):
            returned_cells = _flatten_return_values(_output_return_values(target.raw), target.invoking_symbol)
        if actual_success_like and expected.required_return_columns:
            if returned_cells is None or not expected.required_return_columns <= set(returned_cells):
                return "FAIL"
        if actual_success_like and expected.forbidden_return_columns:
            if returned_cells is not None and expected.forbidden_return_columns & set(returned_cells):
                return "FAIL"
        if actual_success_like and expected.expected_return_column_types:
            if returned_cells is not None:
                for column, type_name in expected.expected_return_column_types.items():
                    if expected.require_typed_return_columns and target.columns and column in target.columns and column not in returned_cells:
                        return "FAIL"
                    if column in returned_cells and not _return_cell_type_valid(type_name, returned_cells[column]):
                        return "FAIL"
        if actual_success_like and expected.expected_return_cells:
            returned = returned_cells or {}
            returned_payload = _output_return_values(target.raw)
            for column, value in expected.expected_return_cells.items():
                if column not in returned:
                    fallback = _reencrypt_status_getter_return_value(target, returned_payload) if column == 12 else _MISSING_RETURN_VALUE
                    if fallback is _MISSING_RETURN_VALUE and len(expected.expected_return_cells) == 1:
                        fallback = _single_cell_getter_return_value(returned_payload)
                    if (
                        fallback is _MISSING_RETURN_VALUE
                        and (
                            (target.invoking_symbol == "MBRControl" and column == 3)
                            or (target.invoking_symbol.startswith("Locking_") and column == 9)
                        )
                        and isinstance(returned_payload, (list, tuple, set))
                    ):
                        fallback = list(returned_payload)
                    if fallback is _MISSING_RETURN_VALUE or not _return_cell_matches(column, fallback, value, target.invoking_symbol):
                        return "FAIL"
                    continue
                if not _return_cell_matches(column, returned[column], value, target.invoking_symbol):
                    return "FAIL"
        if actual_success_like and expected.optional_return_cells:
            returned = returned_cells or {}
            for column, value in expected.optional_return_cells.items():
                if column in returned and not _return_cell_matches(column, returned[column], value, target.invoking_symbol):
                    return "FAIL"
        if actual_success_like and expected.expected_return_min_cells:
            returned = returned_cells or {}
            for column, minimum in expected.expected_return_min_cells.items():
                if column not in returned or not _return_cell_at_least(returned[column], minimum):
                    return "FAIL"
        if actual_success_like and expected.expected_return_max_cells:
            returned = returned_cells or {}
            for column, maximum in expected.expected_return_max_cells.items():
                if column not in returned or not _return_cell_at_most(returned[column], maximum):
                    return "FAIL"
        if actual_success_like and expected.expected_return_cell_lte:
            returned = returned_cells or {}
            for lower_column, upper_column in expected.expected_return_cell_lte:
                if lower_column not in returned or upper_column not in returned:
                    return "FAIL"
                lower = _parse_int(returned[lower_column])
                upper = _parse_int(returned[upper_column])
                if lower is None or upper is None or lower > upper:
                    return "FAIL"
        return "PASS"
    failure_statuses = {
        FAIL,
        NOT_AUTHORIZED,
        INVALID_PARAMETER,
        INSUFFICIENT_SPACE,
        INSUFFICIENT_ROWS,
        SP_DISABLED,
        SP_FROZEN,
    }
    if (
        expected.allow_generic_failure_status
        and actual in failure_statuses
        and expected.allowed_statuses & failure_statuses
    ):
        return "PASS"
    if expected.allow_generic_failure_status and actual in failure_statuses and SUCCESS in expected.forbidden_statuses:
        return "PASS"
    return "FAIL"


def _return_is_uid_list(value: Any) -> bool:
    if isinstance(value, dict):
        for key in (
            "Result",
            "result",
            "UIDs",
            "uids",
            "uid_refs",
            "uidRefs",
            "Rows",
            "rows",
            "row_uids",
            "rowUids",
            "rowUIDs",
            "object_uids",
            "objectUids",
            "objectUIDs",
            "ACL",
            "acl",
            "AccessControlList",
            "accessControlList",
            "access_control_list",
            "ACLUIDs",
            "aclUIDs",
            "aclUids",
            "acl_uids",
            "ACLRefs",
            "aclRefs",
            "acl_refs",
            "ACE",
            "ace",
            "ACEs",
            "aces",
            "ACEEntries",
            "aceEntries",
            "ace_entries",
            "ACLEntries",
            "aclEntries",
            "acl_entries",
            "ACEList",
            "aceList",
            "ace_list",
            "AccessList",
            "accessList",
            "access_list",
            "AccessEntries",
            "accessEntries",
            "access_entries",
            "Entries",
            "entries",
            "ACEUIDs",
            "aceUIDs",
            "aceUids",
            "ace_uids",
            "ACERefs",
            "aceRefs",
            "ace_refs",
            "return",
            "Return",
            "return_value",
            "returnValue",
            "payload",
            "Payload",
            "data",
            "Data",
            "body",
            "Body",
            "Values",
            "values",
        ):
            found, item = _dict_lookup(value, key)
            if found:
                return _return_is_uid_list(item)
        return False
    if not isinstance(value, (list, tuple)):
        return False
    return all(_canonical_uid_ref(item) for item in value)


def _return_is_uinteger_sequence(value: Any, expected_count: int) -> bool:
    values: list[Any]
    if isinstance(value, dict):
        named_values: list[Any] = []
        for aliases in (
            ("FreeRows", "freeRows", "free_rows"),
            ("FreeSpace", "freeSpace", "free_space"),
            ("TableRows", "tableRows", "table_rows"),
            ("Rows", "rows"),
        ):
            found, item = _dict_lookup(value, *aliases)
            if found:
                named_values.append(item)
        if named_values:
            values = named_values
        else:
            for key in ("Result", "result", "return", "Return", "values", "Values", "payload", "Payload", "data", "Data"):
                found, item = _dict_lookup(value, key)
                if found:
                    return _return_is_uinteger_sequence(item, expected_count)
            return False
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        values = [value]
    if len(values) != expected_count:
        return False
    for index, item in enumerate(values):
        if expected_count == 2 and index == 1 and isinstance(item, (list, tuple)):
            continue
        if isinstance(item, bool):
            return False
        parsed = _parse_int(item)
        if parsed is None or parsed < 0:
            return False
    return True


def _return_payload_contains_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, dict):
        return any(_return_payload_contains_bool(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_return_payload_contains_bool(item) for item in value)
    return False


def _high_level_bool_wrapper_success_payload(raw: dict[str, Any], value: Any) -> bool:
    alias = _high_level_function_alias(raw)
    if alias not in {
        "activate",
        "activatelocking",
        "activatelockingsp",
        "enablelockingsp",
        "activatesp",
        "takeownership",
        "takeown",
        "takeowner",
        "changepin",
        "changepassword",
        "changeuserpin",
        "setpin",
        "setpassword",
        "setuserpin",
        "updatepin",
        "updateuserpin",
        "setminpinlength",
        "genkey",
        "genrangekey",
        "generatekey",
        "newkey",
        "newrangekey",
        "createkey",
        "createrangekey",
        "makekey",
        "makerangekey",
        "generaterangekey",
        "rotatekey",
        "regenkey",
        "regeneratekey",
        "refreshkey",
        "refreshmek",
        "renewrangekey",
        "rollkey",
        "rollrangekey",
        "rotaterangekey",
        "regeneraterangekey",
        "rekeyrange",
        "refreshrangekey",
        "generatemek",
        "rotatemek",
        "regeneratemek",
        "setrange",
        "configurerange",
        "enablerangeaccess",
        "writeaccess",
        "readaccess",
        "writedata",
        "putdata",
        "putuserdata",
        "putdatastore",
        "setdata",
        "setdatastore",
        "storedata",
        "storeuserdata",
        "storedatastore",
        "storeds",
        "writebytes",
        "putbytes",
        "storebytes",
        "setbytes",
        "writeds",
        "writedsbytes",
        "writedatastore",
        "writedatastorebytes",
        "writeuserdata",
        "revert",
        "revertadminsp",
        "revertdrive",
        "factoryreset",
        "revertlockingsp",
        "revertlocking",
    }:
        return False
    if not isinstance(value, dict) or not value:
        return False
    allowed_keys = {
        "ok",
        "success",
        "passed",
        "isSuccess",
        "is_success",
        "is_ok",
        "succeeded",
        "successFlag",
        "authorized",
        "allowed",
        "accepted",
        "approved",
    }
    saw_success = False
    for key, item in value.items():
        if str(key) not in allowed_keys:
            return False
        parsed = _optional_bool(item)
        if parsed is not True:
            return False
        saw_success = True
    return saw_success


def _high_level_function_alias(raw: dict[str, Any]) -> str:
    if not isinstance(raw, dict):
        return ""
    inp = raw.get("input")
    if not isinstance(inp, dict):
        inp = raw
    if not isinstance(inp, dict) or "method" in inp:
        return ""
    for key in (
        "function",
        "Function",
        "fn",
        "Fn",
        "func",
        "Func",
        "call",
        "Call",
        "api",
        "API",
        "operation",
        "Operation",
        "operationName",
        "operation_name",
        "functionName",
        "function_name",
        "methodName",
        "method_name",
        "commandName",
        "command_name",
        "name",
        "Name",
    ):
        value = inp.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if re.search(r"[.:/\\]", text):
            parts = [part for part in re.split(r"[.:/\\]+", text) if part]
            if parts:
                text = parts[-1]
        return re.sub(r"[^A-Za-z0-9_]", "", text).lower().replace("_", "")
    return ""


def _return_payload_contains_status_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        if _extract_pattern(value) is not None:
            return False
        return _normalize_status(value) in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}
    if isinstance(value, dict):
        return any(_return_payload_contains_status_bool(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_return_payload_contains_status_bool(item) for item in value)
    return False


def _return_payload_is_bare_status_bool(value: Any) -> bool:
    status_tokens = {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, str):
        if _extract_pattern(value) is not None:
            return False
        return _normalize_status(value) in status_tokens
    if isinstance(value, (list, tuple)):
        return len(value) == 1 and _return_payload_is_bare_status_bool(value[0])
    if isinstance(value, dict):
        if not value:
            return False
        saw_status = False
        for item in value.values():
            if isinstance(item, bool):
                return False
            if isinstance(item, str) and _normalize_status(item) in status_tokens:
                saw_status = True
                continue
            if isinstance(item, (list, tuple, dict)) and _return_payload_is_bare_status_bool(item):
                saw_status = True
                continue
            return False
        return saw_status
    return False


def _return_payload_is_pure_status_bool_envelope(value: Any) -> bool:
    status_bool_keys = {
        "ok",
        "isok",
        "is_ok",
        "success",
        "issuccess",
        "is_success",
        "successflag",
        "passed",
        "succeeded",
    }
    if not isinstance(value, dict) or not value:
        return False
    saw_status_bool = False
    for key, item in value.items():
        normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        if normalized_key not in status_bool_keys:
            return False
        parsed = _optional_bool(item)
        if parsed is None:
            return False
        saw_status_bool = True
    return saw_status_bool


def _locking_single_cell_return_bool(target: Event) -> bool | None:
    if not target.invoking_symbol.startswith("Locking_") or len(target.columns) != 1:
        return None
    column = next(iter(target.columns))
    selector_sets = {
        5: (("locks", "Locks", "lockState", "LockState", "state", "State", "lock", "Lock"), ("readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "readEnabled", "ReadEnabled", "read", "Read", "enabled", "Enabled")),
        6: (("locks", "Locks", "lockState", "LockState", "state", "State", "lock", "Lock"), ("writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "writeEnabled", "WriteEnabled", "write", "Write", "enabled", "Enabled")),
        7: (("locks", "Locks", "lockState", "LockState", "state", "State", "lock", "Lock"), ("readLocked", "ReadLocked", "readLock", "ReadLock", "read", "Read", "locked", "Locked")),
        8: (("locks", "Locks", "lockState", "LockState", "state", "State", "lock", "Lock"), ("writeLocked", "WriteLocked", "writeLock", "WriteLock", "write", "Write", "locked", "Locked")),
    }
    envelope_names, value_names = selector_sets.get(column, ((), ()))
    if not envelope_names:
        return None
    payload = _output_return_values(target.raw)
    if not isinstance(payload, dict):
        return None
    for envelope_name in envelope_names:
        found, envelope = _dict_lookup(payload, envelope_name)
        if not found or not isinstance(envelope, dict):
            continue
        for value_name in value_names:
            value_found, item = _dict_lookup(envelope, value_name)
            if value_found:
                parsed = _optional_bool(item)
                if parsed is not None:
                    return parsed
    return None


def _return_payload_is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, tuple, set)):
        return len(value) == 0
    if isinstance(value, dict):
        if len(value) == 0:
            return True
        for key in ("Result", "result", "return", "Return", "return_values", "ReturnValues", "returnValues", "values", "Values"):
            found, item = _dict_lookup(value, key)
            if found:
                return _return_payload_is_empty(item)
        return False
    return False


def _return_payload_is_byte_like(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if _extract_pattern(value) is not None:
        return True
    if isinstance(value, (bytes, bytearray)):
        return True
    if isinstance(value, str):
        return _normalize_status(value) not in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}
    if isinstance(value, int):
        return False
    if isinstance(value, dict):
        for key in ("Result", "result", "return", "Return", "return_values", "ReturnValues", "returnValues", "Data", "data", "Bytes", "bytes", "Payload", "payload", "Buffer", "buffer", "BufferOut"):
            found, item = _dict_lookup(value, key)
            if found:
                return _return_payload_is_byte_like(item)
        if len(value) == 1:
            return _return_payload_is_byte_like(next(iter(value.values())))
        return False
    if isinstance(value, (list, tuple)):
        if not value:
            return False
        if len(value) == 1:
            return _return_payload_is_byte_like(value[0])
        if _extract_pattern(value) is not None:
            return True
        return all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value)
    return False


def _return_uid_list_length(value: Any) -> int | None:
    if isinstance(value, dict):
        for key in (
            "Result",
            "result",
            "UIDs",
            "uids",
            "uid_refs",
            "uidRefs",
            "Rows",
            "rows",
            "row_uids",
            "rowUids",
            "rowUIDs",
            "object_uids",
            "objectUids",
            "objectUIDs",
            "ACL",
            "acl",
            "AccessControlList",
            "accessControlList",
            "access_control_list",
            "ACLUIDs",
            "aclUIDs",
            "aclUids",
            "acl_uids",
            "ACLRefs",
            "aclRefs",
            "acl_refs",
            "ACE",
            "ace",
            "ACEs",
            "aces",
            "ACEEntries",
            "aceEntries",
            "ace_entries",
            "ACLEntries",
            "aclEntries",
            "acl_entries",
            "ACEList",
            "aceList",
            "ace_list",
            "AccessList",
            "accessList",
            "access_list",
            "AccessEntries",
            "accessEntries",
            "access_entries",
            "Entries",
            "entries",
            "ACEUIDs",
            "aceUIDs",
            "aceUids",
            "ace_uids",
            "ACERefs",
            "aceRefs",
            "ace_refs",
            "return",
            "Return",
            "return_value",
            "returnValue",
            "payload",
            "Payload",
            "data",
            "Data",
            "body",
            "Body",
            "Values",
            "values",
        ):
            found, item = _dict_lookup(value, key)
            if found:
                return _return_uid_list_length(item)
        return None
    if not isinstance(value, (list, tuple)):
        return None
    if not all(_canonical_uid_ref(item) for item in value):
        return None
    return len(value)


ACE_REF_ALIASES = {
    "ACEANYBODY": "ACE_00000001",
    "ACEADMIN": "ACE_00000002",
    "ACEANYBODYGETCOMMONNAME": "ACE_00000003",
    "ACEADMINSSETCOMMONNAME": "ACE_00000004",
    "ACEACEGETALL": "ACE_00038000",
    "ACEACESETBOOLEANEXPRESSION": "ACE_00038001",
    "ACEAUTHORITYGETALL": "ACE_00039000",
    "ACEAUTHORITYSETENABLED": "ACE_00039001",
    "ACEUSER1SETCOMMONNAME": "ACE_00044001",
    "ACEDATASTOREGETALL": "ACE_0003FC00",
    "ACEDATASTORE1GETALL": "ACE_0003FC00",
    "ACEDATASTORESETALL": "ACE_0003FC01",
    "ACEDATASTORE1SETALL": "ACE_0003FC01",
    "ACEMBRCONTROLADMINSSET": "ACE_0003F800",
    "ACEMBRCONTROLSETDONETODOR": "ACE_0003F801",
    "ACECPINUSER1SETPIN": "ACE_0003A801",
    "ACECPINSIDSETPIN": "ACE_00008C03",
    "ACECPINSIDGETNOPIN": "ACE_00008C02",
    "ACECPINMSIDGETPIN": "ACE_00008C04",
    "ACECPINADMINSGETALLNOPIN": "ACE_0003A000",
    "ACECPINADMINSSETPIN": "ACE_0003A001",
    "ACESETENABLED": "ACE_00030001",
    "ACETPERINFOSETPROGRAMMATICRESETENABLE": "ACE_00030003",
    "ACESPSID": "ACE_00030002",
    "ACEDATAREMOVALMECHANISMSETACTIVEDATAREMOVALMECHANISM": "ACE_00050001",
    "ACEKAESMODE": "ACE_0003BFFF",
    "ACEKAES128GLOBALRANGEGENKEY": "ACE_0003B000",
    "ACEKAES128RANGE1GENKEY": "ACE_0003B001",
    "ACEKAES256GLOBALRANGEGENKEY": "ACE_0003B800",
    "ACEKAES256RANGE1GENKEY": "ACE_0003B801",
    "ACELOCKINGGLOBALRANGEGETRANGESTARTTOACTIVEKEY": "ACE_0003D000",
    "ACELOCKINGRANGE1GETRANGESTARTTOACTIVEKEY": "ACE_0003D001",
    "ACELOCKINGGLBLRNGADMINSSET": "ACE_0003F000",
    "ACELOCKINGGLOBALRANGESETRDLOCKED": "ACE_0003E000",
    "ACELOCKINGGLOBALRANGESETWRLOCKED": "ACE_0003E800",
    "ACELOCKINGADMINSRANGESTARTTOLOR": "ACE_0003F001",
    "ACELOCKINGRANGE1SETRDLOCKED": "ACE_0003E001",
    "ACELOCKINGRANGE1SETWRLOCKED": "ACE_0003E801",
}


def _generic_ace_ref_alias(key: str) -> str:
    match = re.fullmatch(r"ACELOCKINGRANGE(\d+)GETRANGESTARTTOACTIVEKEY", key)
    if match:
        return f"ACE_0003{0xD000 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACELOCKINGRANGE(\d+)SETRDLOCKED", key)
    if match:
        return f"ACE_0003{0xE000 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACELOCKINGRANGE(\d+)SETWRLOCKED", key)
    if match:
        return f"ACE_0003{0xE800 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACEKAES(128|256)RANGE(\d+)GENKEY", key)
    if match:
        base = 0xB000 if match.group(1) == "128" else 0xB800
        return f"ACE_0003{base + int(match.group(2)):04X}"
    match = re.fullmatch(r"ACECPINUSER(\d+)SETPIN", key)
    if match:
        return f"ACE_0003{0xA800 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACEUSER(\d+)SETCOMMONNAME", key)
    if match:
        return f"ACE_{0x00044000 + int(match.group(1)):08X}"
    return ""


def _ace_ref_from_uid_text(text: str) -> str:
    uid_ref = _uid_ref(text)
    if not uid_ref:
        return ""
    if not uid_ref.startswith("00000000"):
        return ""
    suffix = uid_ref[-8:].upper()
    explicit_refs = {ref.split("_", 1)[1].upper() for ref in ACE_REF_ALIASES.values() if ref.startswith("ACE_")}
    if suffix in explicit_refs:
        return f"ACE_{suffix}"
    try:
        numeric = int(suffix, 16)
    except ValueError:
        return ""
    dynamic_ranges = (
        (0x0003D000, 0x0003D7FF),
        (0x0003E000, 0x0003E7FF),
        (0x0003E800, 0x0003EFFF),
        (0x0003B000, 0x0003B7FF),
        (0x0003B800, 0x0003BFFF),
        (0x0003A800, 0x0003AFFF),
        (0x00044000, 0x000447FF),
    )
    if any(start <= numeric <= end for start, end in dynamic_ranges):
        return f"ACE_{suffix}"
    return ""


def _canonical_uid_ref(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("uid", "UID", "ref", "Ref", "ace", "ACE", "object", "Object", "name", "Name", "symbol", "Symbol"):
            found, item = _dict_lookup(value, key)
            if not found:
                continue
            ref = _canonical_uid_ref(item)
            if ref:
                return ref
    if not isinstance(value, (dict, list, tuple, set)):
        raw_text = _as_text(value).strip()
        raw_key = re.sub(r"[^A-Za-z0-9]", "", raw_text).upper()
        if raw_key in ACE_REF_ALIASES:
            return ACE_REF_ALIASES[raw_key]
        generic_alias = _generic_ace_ref_alias(raw_key)
        if generic_alias:
            return generic_alias
        raw_match = re.fullmatch(r"ACE_?([0-9A-Fa-f]{8})", raw_text)
        if raw_match:
            return f"ACE_{raw_match.group(1).upper()}"
    symbol, uid = _object_ref_from_value(value)
    candidates = [symbol]
    if uid:
        candidates.append(_object_by_uid(uid))
        candidates.append(uid)
    if not isinstance(value, (dict, list, tuple, set)):
        candidates.append(_as_text(value))

    for candidate in candidates:
        if not candidate:
            continue
        text = _as_text(candidate).strip()
        if re.fullmatch(r"[bB][rR]?(?:'[^']*'|\"[^\"]*\")", text) or re.fullmatch(r"[rR]?[bB](?:'[^']*'|\"[^\"]*\")", text):
            try:
                parsed = ast.literal_eval(text)
            except (SyntaxError, ValueError):
                parsed = None
            if isinstance(parsed, (bytes, bytearray)) and len(parsed) == 8:
                uid_text = bytes(parsed).hex().upper()
                ace_ref = _ace_ref_from_uid_text(uid_text)
                if ace_ref:
                    return ace_ref
                uid_symbol = _object_by_uid(uid_text)
                if uid_symbol.startswith("ACE_"):
                    return ACE_REF_ALIASES.get(re.sub(r"[^A-Za-z0-9]", "", uid_symbol).upper(), uid_symbol)
                return uid_text
        key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
        if key in ACE_REF_ALIASES:
            return ACE_REF_ALIASES[key]
        generic_alias = _generic_ace_ref_alias(key)
        if generic_alias:
            return generic_alias
        match = re.fullmatch(r"ACE_?([0-9A-Fa-f]{8})", text)
        if match:
            return f"ACE_{match.group(1).upper()}"
        if text.startswith("ACE_"):
            return text
        key_uid = _key_symbol_uid(text)
        if key_uid:
            return key_uid
        uid_ref = _uid_ref(text)
        if uid_ref:
            ace_ref = _ace_ref_from_uid_text(uid_ref)
            if ace_ref:
                return ace_ref
            uid_symbol = _object_by_uid(uid_ref)
            if uid_symbol.startswith("ACE_"):
                return ACE_REF_ALIASES.get(re.sub(r"[^A-Za-z0-9]", "", uid_symbol).upper(), uid_symbol)
            return uid_ref
    return ""


def _return_uid_refs(value: Any) -> set[str]:
    refs: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key in (
                "Result",
                "result",
                "UIDs",
                "uids",
                "uid_refs",
                "uidRefs",
                "Rows",
                "rows",
                "row_uids",
                "rowUids",
                "rowUIDs",
                "object_uids",
                "objectUids",
                "objectUIDs",
                "ACL",
                "acl",
                "AccessControlList",
                "accessControlList",
                "access_control_list",
                "ACLUIDs",
                "aclUIDs",
                "aclUids",
                "acl_uids",
                "ACLRefs",
                "aclRefs",
                "acl_refs",
                "ACE",
                "ace",
                "ACEs",
                "aces",
                "ACEEntries",
                "aceEntries",
                "ace_entries",
                "ACLEntries",
                "aclEntries",
                "acl_entries",
                "ACEList",
                "aceList",
                "ace_list",
                "AccessList",
                "accessList",
                "access_list",
                "AccessEntries",
                "accessEntries",
                "access_entries",
                "Entries",
                "entries",
                "ACEUIDs",
                "aceUIDs",
                "aceUids",
                "ace_uids",
                "ACERefs",
                "aceRefs",
                "ace_refs",
                "return",
                "Return",
                "return_value",
                "returnValue",
                "payload",
                "Payload",
                "data",
                "Data",
                "body",
                "Body",
                "Values",
                "values",
            ):
                found, nested = _dict_lookup(item, key)
                if found:
                    walk(nested)
                    return
            ref = _canonical_uid_ref(item)
            if ref:
                refs.add(ref)
                return
            for nested in item.values():
                walk(nested)
            return
        if isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)
            return
        ref = _canonical_uid_ref(item)
        if ref:
            refs.add(ref)

    walk(value)
    return refs


def _return_payload_pattern(value: Any) -> str | None:
    pattern = _extract_pattern(value)
    if pattern is not None:
        return pattern
    if isinstance(value, dict):
        for key in ("Result", "result", "BufferOut", "Data", "data", "bytes", "Bytes"):
            found, item = _dict_lookup(value, key)
            if found:
                pattern = _return_payload_pattern(item)
                if pattern is not None:
                    return pattern
        if len(value) == 1:
            return _return_payload_pattern(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _return_payload_pattern(value[0])
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return _extract_pattern(value)
    return None


def _return_cell_matches(column: int, actual: Any, expected: Any, symbol: str = "") -> bool:
    access_control_log_select_columns = {
        ACCESS_CONTROL_LOG_COLUMN,
        ACCESS_CONTROL_ADD_ACE_LOG_COLUMN,
        ACCESS_CONTROL_REMOVE_ACE_LOG_COLUMN,
        ACCESS_CONTROL_GET_ACL_LOG_COLUMN,
        ACCESS_CONTROL_DELETE_METHOD_LOG_COLUMN,
    }
    if symbol.startswith("AccessControl_") and column in access_control_log_select_columns and _as_text(expected).strip() == "":
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(actual or "")).upper()
        parsed = _parse_int(actual)
        return actual is None or text in {"", "NULL", "NULLUID", "NONE", "LOGNEVER"} or parsed == 0
    if symbol.startswith("AccessControl_") and column == ACCESS_CONTROL_LOGTO_COLUMN and _as_text(expected).strip() == "":
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(actual or "")).upper()
        return actual is None or text in {"", "NULL", "NULLUID", "NONE"} or _clean_uid(actual) == "0000000000000000"
    if symbol.startswith("Authority_") and column in {4, 10, 11, 12}:
        return _authority_ref_matches(actual, expected)
    if symbol.startswith("Authority_") and column == 9:
        return _operation_cell_matches(actual, expected)
    if (symbol == "MBRControl" and column == 3) or (symbol.startswith("Locking_") and column == 9):
        return _reset_types_value_valid(actual) and _reset_types(actual) == _reset_types(expected)
    if symbol.startswith("Table_") and column == 5 and _clean_uid(expected) == "0000000000000000":
        text = _as_text(actual).strip()
        return actual is None or text == "" or text.lower() in {"null", "nulluid", "null_uid"} or _clean_uid(actual) == "0000000000000000"
    if symbol.startswith("ACE_") and column == ACE_BOOLEAN_EXPR_COLUMN:
        return _ace_expression_matches(actual, expected)
    if symbol.startswith("ACE_") and column == ACE_COLUMNS_COLUMN:
        return _ace_columns_match(actual, expected)
    if symbol.startswith("Locking_") and column in {10, 11}:
        return _media_key_ref_matches(actual, expected)
    if isinstance(expected, bool):
        return _as_bool(actual) == expected
    if column == 12:
        actual_state = _parse_reencrypt_state(actual)
        expected_state = _parse_reencrypt_state(expected)
        if actual_state is not None and expected_state is not None:
            return actual_state == expected_state
    expected_int = _parse_int(expected)
    actual_int = _parse_int(actual)
    if expected_int is not None and actual_int is not None:
        return actual_int == expected_int
    expected_text = _as_text(expected).strip()
    actual_text = _as_text(actual).strip()
    expected_hex = re.sub(r"[^0-9A-Fa-f]", "", expected_text).upper()
    actual_hex = re.sub(r"[^0-9A-Fa-f]", "", actual_text).upper()
    if (
        expected_hex
        and actual_hex
        and re.fullmatch(r"[0-9A-Fa-f\s:_-]+", expected_text)
        and re.fullmatch(r"[0-9A-Fa-f\s:_-]+", actual_text)
    ):
        return actual_hex == expected_hex
    return _as_text(actual).strip().upper() == _as_text(expected).strip().upper()


def _authority_ref_matches(actual: Any, expected: Any) -> bool:
    expected_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(expected or "")).upper()
    actual_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(actual or "")).upper()
    expected_uid = _clean_uid(expected)
    actual_uid = _clean_uid(actual)
    if expected_text in {"", "NULL", "NULLUID", "NONE"} or expected_uid == "0000000000000000":
        return actual is None or actual_text in {"", "NULL", "NULLUID", "NONE"} or actual_uid == "0000000000000000"
    expected_auth = _authority_from_value(expected)
    actual_auth = _authority_from_value(actual)
    if expected_auth is not None and actual_auth is not None:
        return expected_auth == actual_auth
    if expected_uid and actual_uid:
        return expected_uid == actual_uid
    return actual_text == expected_text


def _operation_cell_matches(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool):
        return False
    expected_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(expected or "")).upper()
    actual_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(actual or "")).upper()
    aliases = {
        "": {"", "NONE", "NULL", "NULLUID", "0"},
        "NONE": {"", "NONE", "NULL", "NULLUID", "0"},
        "PASSWORD": {"PASSWORD", "1"},
        "EXCHANGE": {"EXCHANGE", "2"},
        "SIGN": {"SIGN", "3"},
        "SYMK": {"SYMK", "SYMMETRICKEY", "4"},
        "HMAC": {"HMAC", "5"},
        "TPERSIGN": {"TPERSIGN", "TPERSIGNING", "6"},
        "TPEREXCHANGE": {"TPEREXCHANGE", "TPEREXCH", "7"},
    }
    return actual_text in aliases.get(expected_text, {expected_text})


def _ace_expression_matches(actual: Any, expected: Any) -> bool:
    actual_expr = _ace_expression_from_value(actual)
    expected_expr = expected if isinstance(expected, AceExpression) else _ace_expression_from_value(expected)
    return actual_expr.operator == expected_expr.operator and actual_expr.authorities == expected_expr.authorities


def _ace_columns_match(actual: Any, expected: Any) -> bool:
    actual_columns = _ace_column_names(actual)
    expected_columns = _ace_column_names(expected)
    return bool(actual_columns) and actual_columns == expected_columns


def _ace_column_names(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, dict):
        out: set[str] = set()
        for item in value.values():
            out.update(_ace_column_names(item))
        return out
    if isinstance(value, (list, tuple, set)):
        out: set[str] = set()
        for item in value:
            out.update(_ace_column_names(item))
        return out
    text = _as_text(value).strip()
    if not text:
        return set()
    parts = re.split(r"[,;/|]+", text)
    if len(parts) == 1:
        parts = [text]
    return {re.sub(r"[^A-Za-z0-9]", "", part).upper() for part in parts if re.sub(r"[^A-Za-z0-9]", "", part)}


def _canonical_media_key_ref(value: Any) -> str:
    if value is None:
        return ""
    if _clean_uid(value) == "0000000000000000":
        return ""
    symbol, uid = _object_ref_from_value(value)
    candidates = [symbol]
    if uid:
        candidates.append(_object_by_uid(uid))
    if not isinstance(value, (dict, list, tuple, set)):
        candidates.append(_as_text(value))
    for candidate in candidates:
        if not candidate:
            continue
        text = _as_text(candidate).strip()
        clean = _clean_uid(text)
        if clean == "0000000000000000":
            return ""
        if clean:
            resolved = _object_by_uid(clean)
            if _range_id_from_key(resolved) is not None:
                return resolved
        normalized = _object_by_uid(text) or text
        if _range_id_from_key(normalized) is not None:
            return normalized
    return _as_text(value).strip().upper()


def _media_key_ref_matches(actual: Any, expected: Any) -> bool:
    expected_ref = _canonical_media_key_ref(expected)
    actual_ref = _canonical_media_key_ref(actual)
    return actual_ref == expected_ref


def _return_cell_at_least(actual: Any, minimum: int) -> bool:
    actual_int = _parse_int(actual)
    return actual_int is not None and actual_int >= minimum


def _return_cell_at_most(actual: Any, maximum: int) -> bool:
    actual_int = _parse_int(actual)
    return actual_int is not None and actual_int <= maximum


_MISSING_RETURN_VALUE = object()


def _return_value_by_selector(value: Any, selector: Any) -> Any:
    if isinstance(selector, tuple):
        for candidate in selector:
            selected = _return_value_by_selector(value, candidate)
            if selected is not _MISSING_RETURN_VALUE:
                return selected
        return _MISSING_RETURN_VALUE
    if isinstance(selector, int) and not isinstance(selector, bool):
        return _return_value_at_position(value, selector)
    return _return_value_by_name(value, selector)


def _return_value_at_position(value: Any, index: int) -> Any:
    if isinstance(value, dict):
        for key in ("Result", "result", "ReturnValues", "returnValues", "Values", "values"):
            found, item = _dict_lookup(value, key)
            if found:
                selected = _return_value_at_position(item, index)
                if selected is not _MISSING_RETURN_VALUE:
                    return selected
        if len(value) == 1:
            return _return_value_at_position(next(iter(value.values())), index)
        return _MISSING_RETURN_VALUE
    if isinstance(value, (list, tuple)):
        if 0 <= index < len(value):
            return value[index]
        return _MISSING_RETURN_VALUE
    return _MISSING_RETURN_VALUE


def _return_value_by_name(value: Any, selector: Any) -> Any:
    wanted = re.sub(r"[^A-Za-z0-9]", "", _as_text(selector)).upper()
    if not wanted:
        return _MISSING_RETURN_VALUE
    aliases = {
        "RANGESTART": {"RANGESTART", "START", "STARTLBA", "LBASTART", "LBA", "SECTOR", "STARTBLOCK", "FIRSTLBA", "BASE", "OFFSET", "BEGIN"},
        "RANGELENGTH": {"RANGELENGTH", "LENGTH", "LEN", "SIZE", "COUNT", "BLOCKS", "SECTORS", "NUMBLOCKS", "BLOCKCOUNT", "SECTORCOUNT"},
        "READLOCKED": {"READLOCKED", "READLOCK", "RLOCKED"},
        "WRITELOCKED": {"WRITELOCKED", "WRITELOCK", "WLOCKED"},
        "READLOCKENABLED": {"READLOCKENABLED", "READENABLED", "RLOCKENABLED"},
        "WRITELOCKENABLED": {"WRITELOCKENABLED", "WRITEENABLED", "WLOCKENABLED"},
        "LOCKONRESET": {"LOCKONRESET", "LOR", "RESETTYPES", "TYPES", "RESETEVENTS", "RESETON", "RESETLIST"},
        "HOSTSESSIONID": {"HOSTSESSIONID", "HOSTSESSION", "HOSTSID", "HSID"},
        "SPSESSIONID": {"SPSESSIONID", "SPSESSION", "SPSID", "TPERSESSIONID", "TPERSESSION", "TPERSID"},
    }.get(wanted, {wanted})
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
            if key_text in aliases:
                return item
            if key_text in {"LOCKS", "LOCK", "LOCKSTATE", "STATE"}:
                selected = _directional_lock_value_from_envelope(item, wanted)
                if selected is not _MISSING_RETURN_VALUE:
                    return selected
            selected = _return_value_by_name(item, selector)
            if selected is not _MISSING_RETURN_VALUE:
                return selected
        return _MISSING_RETURN_VALUE
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).upper()
            if key_text in aliases:
                return value[1]
        for item in value:
            selected = _return_value_by_name(item, selector)
            if selected is not _MISSING_RETURN_VALUE:
                return selected
    return _MISSING_RETURN_VALUE


def _directional_lock_value_from_envelope(value: Any, wanted: str) -> Any:
    if not isinstance(value, dict):
        return _MISSING_RETURN_VALUE
    names = {
        "READLOCKENABLED": {"READLOCKENABLED", "READLOCKINGENABLED", "READENABLED", "READ", "ENABLED"},
        "WRITELOCKENABLED": {"WRITELOCKENABLED", "WRITELOCKINGENABLED", "WRITEENABLED", "WRITE", "ENABLED"},
        "READLOCKED": {"READLOCKED", "READLOCK", "READ", "LOCKED"},
        "WRITELOCKED": {"WRITELOCKED", "WRITELOCK", "WRITE", "LOCKED"},
    }.get(wanted)
    if not names:
        return _MISSING_RETURN_VALUE
    for key, item in value.items():
        key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
        if key_text in names:
            return item
    return _MISSING_RETURN_VALUE


def _return_value_at_least(payload: Any, selector: Any, minimum: int) -> bool:
    selected = _return_value_by_selector(payload, selector)
    actual_int = None if selected is _MISSING_RETURN_VALUE else _parse_int(selected)
    return actual_int is not None and actual_int >= minimum


def _return_value_at_most(payload: Any, selector: Any, maximum: int) -> bool:
    selected = _return_value_by_selector(payload, selector)
    actual_int = None if selected is _MISSING_RETURN_VALUE else _parse_int(selected)
    return actual_int is not None and actual_int <= maximum


def _return_value_in_allowed_set(payload: Any, selector: Any, allowed_values: set[int]) -> bool:
    selected = _return_value_by_selector(payload, selector)
    actual_int = None if selected is _MISSING_RETURN_VALUE else _parse_int(selected)
    return actual_int in allowed_values


def _return_value_matches_bit_mask(payload: Any, selector: Any, must_set: int, must_clear: int) -> bool:
    selected = _return_value_by_selector(payload, selector)
    actual_int = None if selected is _MISSING_RETURN_VALUE else _parse_int(selected)
    if actual_int is None:
        return False
    return (actual_int & must_set) == must_set and (actual_int & must_clear) == 0


def _return_property_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, set) and all(isinstance(item, int) and not isinstance(item, bool) for item in expected):
        return _reset_types(actual) == expected
    if isinstance(expected, bool):
        return _as_bool(actual) == expected
    expected_int = _parse_int(expected)
    actual_int = _parse_int(actual)
    if expected_int is not None or actual_int is not None:
        return expected_int is not None and actual_int == expected_int
    return _as_text(actual) == _as_text(expected)


def _nonnegative_integer_property(value: Any) -> bool:
    parsed = _parse_int(value)
    return parsed is not None and parsed >= 0


def _zero_or_at_least(value: Any, minimum: int) -> bool:
    parsed = _parse_int(value)
    return parsed is not None and (parsed == 0 or parsed >= minimum)


def _property_bool(value: Any) -> bool | None:
    return _optional_bool(value)


def _tper_properties_valid(properties: dict[str, Any]) -> bool:
    for name, value in properties.items():
        if name in {
            "MaxMethods",
            "MaxSubpackets",
            "MaxPackets",
            "MinSessionTimeout",
            "DefTransTimeout",
            "MaxTransTimeout",
            "MinTransTimeout",
            "MaxComIDTime",
        } and not _nonnegative_integer_property(value):
            return False
        if name == "MaxPacketSize" and not _zero_or_at_least(value, 2028):
            return False
        if name == "MaxComPacketSize" and not _zero_or_at_least(value, 2048):
            return False
        if name == "MaxIndTokenSize" and not _zero_or_at_least(value, 1992):
            return False
        if name in {"ContinuedTokens", "SequenceNumbers", "AckNak", "Asynchronous"} and _property_bool(value) is None:
            return False

    if _property_bool(properties.get("AckNak")) is True and _property_bool(properties.get("SequenceNumbers")) is False:
        return False
    if _property_bool(properties.get("Asynchronous")) is True:
        max_methods = _parse_int(properties.get("MaxMethods"))
        if max_methods is not None and max_methods != 0:
            return False
    return True


def _return_cell_type_valid(type_name: str, actual: Any) -> bool:
    normalized = re.sub(r"[^A-Za-z0-9]", "", type_name).lower()
    if normalized == "symmetricmode":
        return _symmetric_mode_value_valid(actual)
    if normalized == "feedbacksize":
        return _feedback_size_value_valid(actual)
    if normalized == "encsupported":
        return _enc_supported_value_valid(actual)
    if normalized == "lifecyclestate":
        return _life_cycle_state_value_valid(actual)
    if normalized == "boolean":
        return _optional_bool(actual) is not None
    if normalized == "bytes8":
        return _fixed_bytes_value_valid(actual, 8)
    if normalized == "bytes12":
        return _fixed_bytes_value_valid(actual, 12)
    if normalized == "bytes16":
        return _fixed_bytes_value_valid(actual, 16)
    if normalized == "bytes20":
        return _fixed_bytes_value_valid(actual, 20)
    if normalized == "bytes32":
        return _fixed_bytes_value_valid(actual, 32)
    if normalized == "bytes48":
        return _fixed_bytes_value_valid(actual, 48)
    if normalized == "bytes64":
        return _fixed_bytes_value_valid(actual, 64)
    if normalized == "password":
        return _max_bytes_value_valid(actual, 32)
    if normalized == "authmethod":
        return _auth_method_value_valid(actual)
    if normalized == "symmetricmodemedia":
        return _symmetric_mode_media_value_valid(actual)
    if normalized == "lastreencstat":
        return _last_reenc_stat_value_valid(actual)
    if normalized == "genstatus":
        return _gen_status_value_valid(actual)
    if normalized == "verifymode":
        return _verify_mode_value_valid(actual)
    if normalized == "advkeymode":
        return _adv_key_mode_value_valid(actual)
    if normalized == "paddingtype":
        return _padding_type_value_valid(actual)
    if normalized == "hashprotocol":
        return _hash_protocol_value_valid(actual)
    if normalized == "protecttypes":
        return _protect_types_value_valid(actual)
    if normalized == "resettypes":
        return _reset_types_value_valid(actual)
    if normalized.startswith("uinteger"):
        return _uinteger_value_valid(actual, normalized)
    return True


def _reset_types_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if value is None or value == "" or value == [] or value == ():
        return True
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in {"true", "false"}:
            return False
        if stripped in {"", "PowerCycle", "Hardware", "HotPlug", "TPer", "Programmatic"}:
            return True
        parsed = _parse_int(value)
        return parsed is not None and parsed >= 0
    if isinstance(value, bytes):
        return True
    if isinstance(value, (list, tuple, set)):
        return all(_reset_types_value_valid(item) for item in value)
    if isinstance(value, dict):
        for key in ("DoneOnReset", "doneOnReset", "LockOnReset", "lockOnReset", "LOR", "lor", "ResetTypes", "resetTypes", "types", "Types", "resetEvents", "reset_events", "resetOn", "reset_on", "resetList", "reset_list", "value", "Value", "return", "Return"):
            found, item = _dict_lookup(value, key)
            if found:
                return _reset_types_value_valid(item)
        return False
    return False


def _uinteger_value_valid(value: Any, normalized_type: str = "uinteger") -> bool:
    if isinstance(value, bool):
        return False
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    parsed = _parse_int(value)
    if parsed is None or parsed < 0:
        return False
    match = re.fullmatch(r"uinteger(\d+)", normalized_type)
    if match:
        max_value = (1 << (8 * int(match.group(1)))) - 1
        return parsed <= max_value
    return True


def _hash_protocol_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1, 2, 3, 4}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"NONE", "SHA1", "SHA256", "SHA384", "SHA512"}


def _protect_types_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if value is None:
        return True
    if isinstance(value, dict):
        values = list(value.values())
        return all(_protect_types_value_valid(item) for item in values)
    if isinstance(value, (list, tuple, set)):
        return all(_protect_types_value_valid(item) for item in value)
    parsed = _parse_int(value)
    if parsed is not None:
        return 0 <= parsed <= 255
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"", "VU", "VENDORUNIQUE", "VENDORUNIQUEPROTECTION"}


def _auth_method_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return 0 <= parsed <= 7
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {
        "",
        "NONE",
        "NULL",
        "NULLUID",
        "PASSWORD",
        "EXCHANGE",
        "SIGN",
        "SYMK",
        "SYMMETRICKEY",
        "HMAC",
        "TPERSIGN",
        "TPERSIGNING",
        "TPEREXCHANGE",
        "TPEREXCH",
    }


def _symmetric_mode_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in set(range(0, 12))
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"ECB", "CBC", "CFB", "OFB", "GCM", "CTR", "CCM", "XTS", "LRW", "EME", "CMC", "XEX"}


def _feedback_size_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    return parsed is not None and 0 <= parsed <= 0xFFFF


def _enc_supported_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"NONE", "MEDIAENCRYPTION"}


def _life_cycle_state_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in set(range(0, 5)) | set(range(8, 14))
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {
        "ISSUED",
        "ISSUEDDISABLED",
        "ISSUEDFROZEN",
        "ISSUEDDISABLEDFROZEN",
        "ISSUEDFAILED",
        "MANUFACTUREDINACTIVE",
        "MANUFACTURED",
        "MANUFACTUREDDISABLED",
        "MANUFACTUREDFROZEN",
        "MANUFACTUREDDISABLEDFROZEN",
        "MANUFACTUREDFAILED",
    }


def _fixed_bytes_value_valid(value: Any, expected_length: int) -> bool:
    if isinstance(value, bool):
        return False
    return _return_payload_length(value) == expected_length


def _max_bytes_value_valid(value: Any, max_length: int) -> bool:
    if isinstance(value, bool):
        return False
    length = _return_payload_length(value)
    return length is not None and 0 <= length <= max_length


def _padding_type_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1, 2, 3, 4}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"NONE", "RSAESPKCS1V15", "RSAESOAEP", "RSASSAPKCS1V15"}


def _verify_mode_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"NOVERIFY", "VERIFYENABLED"}


def _adv_key_mode_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"NOADVANCED", "ADVANCED", "ADVKEY", "ADVANCEDKEY"}


def _last_reenc_stat_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return 0 <= parsed <= 3
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {"SUCCESS", "READERROR", "WRITEERROR", "VERIFYERROR"}


def _gen_status_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in {0, 1, 2, 3, 4, 5, 6, 32, 33, 34}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {
        "NONE",
        "PENDINGTPERERROR",
        "PENDTPERERROR",
        "ACTIVETPERERROR",
        "ACTIVEPAUSEREQUESTED",
        "PENDPAUSEREQUESTED",
        "PENDINGPAUSEREQUESTED",
        "PENDRESETSTOPDETECT",
        "PENDINGRESETSTOPDETECT",
        "KEYERROR",
        "WAITAVAILABLEKEYS",
        "WAITFORTPERRESOURCES",
        "ACTIVERESETSTOPDETECT",
    }


def _symmetric_mode_media_value_valid(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed in set(range(0, 12)) | {23}
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return text in {
        "ECB",
        "CBC",
        "CFB",
        "OFB",
        "GCM",
        "CTR",
        "CCM",
        "XTS",
        "LRW",
        "EME",
        "CMC",
        "XEX",
        "MEDIAENCRYPTION",
        "VU",
        "VENDORUNIQUE",
    }


def _read_result_is_all_zeroes(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0 and all(byte == 0 for byte in value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        normalized = re.sub(r"[^0-9A-Fa-f]", "", text)
        if normalized:
            return set(normalized) == {"0"}
        return re.search(r"\bzero(?:es|s)?\b", text, re.IGNORECASE) is not None
    if isinstance(value, dict):
        for key in ("result", "Result", "data", "Data", "bytes", "Bytes"):
            found, item = _dict_lookup(value, key)
            if found:
                return _read_result_is_all_zeroes(item)
        return len(value) == 1 and _read_result_is_all_zeroes(next(iter(value.values())))
    if isinstance(value, (list, tuple)):
        return len(value) > 0 and all(_read_result_is_all_zeroes(item) for item in value)
    return False


def _reencrypt_status_getter_return_value(target: Event, payload: Any) -> Any:
    if not isinstance(target.raw, dict):
        return _MISSING_RETURN_VALUE
    input_obj = _function_input_section(target.raw)
    if not isinstance(input_obj, dict):
        return _MISSING_RETURN_VALUE
    alias = _function_alias(_function_name(input_obj))
    if alias not in {
        "getreencryptstatus",
        "readreencryptstatus",
        "fetchreencryptstatus",
        "queryreencryptstatus",
        "getreencryptstate",
        "readreencryptstate",
        "fetchreencryptstate",
        "queryreencryptstate",
        "reencryptstatus",
        "getreencryptionstatus",
        "readreencryptionstatus",
        "fetchreencryptionstatus",
        "queryreencryptionstatus",
        "getreencryptionstate",
        "readreencryptionstate",
        "fetchreencryptionstate",
        "queryreencryptionstate",
        "isreencrypting",
    }:
        return _MISSING_RETURN_VALUE
    for name in ("ReEncryptState", "reencryptState", "ReEncryptionState", "reencryptionState", "state", "State", "status", "Status"):
        selected = _return_value_by_name(payload, name)
        if selected is not _MISSING_RETURN_VALUE:
            return selected
    if not isinstance(payload, (dict, list, tuple, set)):
        return payload
    return _MISSING_RETURN_VALUE


def _single_cell_getter_return_value(payload: Any) -> Any:
    for name in ("value", "Value", "result", "Result", "return", "Return", "rv", "RV"):
        selected = _return_value_by_name(payload, name)
        if selected is not _MISSING_RETURN_VALUE:
            return selected
    if not isinstance(payload, (dict, list, tuple, set)):
        return payload
    return _MISSING_RETURN_VALUE


def _method_default_authas_authority(event: Event) -> str | None:
    raw_args = _method_raw_args(event)
    value = _raw_arg_value(
        event.required,
        event.optional,
        raw_args,
        "auth",
        "Auth",
        "defAuth",
        "DefAuth",
        "defaultAuth",
        "DefaultAuth",
        "defaultAuthority",
        "DefaultAuthority",
    )
    return _authority_from_value(value)


def _authority_would_satisfy(state: State, authority: str, required: str) -> bool:
    already_present = authority in state.session.authenticated
    state.session.authenticated.add(authority)
    try:
        return _has_authority(state, required)
    finally:
        if not already_present:
            state.session.authenticated.discard(authority)


def _get_required_authorities_for_relevance(event: Event) -> set[str]:
    symbol = event.invoking_symbol
    if symbol == "C_PIN_SID":
        if not event.columns or PIN_COLUMN in event.columns:
            return set()
        return {"Admins", "SID"}
    if symbol.startswith("C_PIN_"):
        if not event.columns or PIN_COLUMN in event.columns:
            return set()
        return {"Admins"}
    if symbol.startswith("Locking_"):
        return {"Admins"}
    if symbol.startswith("DataStore"):
        return {"Admins", "Users"}
    if symbol.startswith(("Authority_", "ACE_")):
        return {"Admins"}
    return set()


def _target_required_authorities_for_relevance(state: State, event: Event) -> set[str]:
    if event.method == "Set":
        return _set_required_authorities(state, event)
    if event.method in {"CreateTable", "CreateLog", "CreateRow", "DeleteRow", "Delete", "DeleteSP", "DeleteMethod", "AddACE", "RemoveACE", "SetACL", "GenKey", "GetPackage", "SetPackage"}:
        return {"Admins"}
    if event.method == "Activate":
        return {"SID"}
    if event.method == "Erase":
        return {"EraseMaster"}
    if event.method in {"Revert", "RevertSP"}:
        if event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP":
            return {"PSID"}
        if state.session.sp == "LockingSP":
            return {"Admins"}
        return {"SID", "PSID", "Admins"}
    if event.method == "Get":
        return _get_required_authorities_for_relevance(event)
    return set()


def _authority_relevant_for_target(state: State, event: Event, authority: str) -> bool:
    required = _target_required_authorities_for_relevance(state, event)
    if any(_authority_would_satisfy(state, authority, item) for item in required):
        return True

    already_present = authority in state.session.authenticated
    state.session.authenticated.add(authority)
    try:
        if event.method in {"Get", "Set"}:
            symbol = event.invoking_symbol
            if symbol.startswith("Locking_") and _range_master_authorizes(state, _range_id_from_symbol(symbol)):
                return True
            if symbol.startswith("DataStore") and _datastore_master_authorizes(state):
                return True
        if event.method == "Set" and _ace_authorizes_set(state, event):
            return True
        if event.method == "Get":
            symbol = event.invoking_symbol
            range_id = _range_id_from_symbol(symbol)
            if range_id is not None and _ace_satisfied(state, _locking_ace_symbol(0xD000, range_id)):
                return True
            if symbol.startswith("DataStore") and _user_acl_allows_datastore(state, write=False):
                return True
    finally:
        if not already_present:
            state.session.authenticated.discard(authority)

    return not required


def _add_authority_candidate(candidates: list[str], authority: str | None) -> None:
    if authority and authority not in candidates:
        candidates.append(authority)


def _owner_fallback_credential_plausible(state: State, owner: str, credential_text: str) -> bool:
    if owner in state.pins:
        return True
    if owner == "SID" or owner == "EraseMaster" or _is_band_master(owner):
        msid_pin = state.pins.get("MSID")
        if msid_pin is not None and credential_text:
            return credential_text == msid_pin
    return True


def _authas_default_authority_candidates(state: State, event: Event, credential: Any) -> list[str]:
    explicit_default = _method_default_authas_authority(event)
    if explicit_default is not None:
        return [explicit_default]

    candidates: list[str] = []
    credential_text = _credential_text(credential)
    if credential_text:
        for authority, pin in state.pins.items():
            if pin != credential_text:
                continue
            if not _authority_allowed_for_target_method(state, event, authority):
                continue
            if not _authority_is_enabled(state, state.session.sp, authority):
                continue
            if _authority_locked_out(state, authority):
                continue
            if _authority_relevant_for_target(state, event, authority):
                _add_authority_candidate(candidates, authority)
    if candidates:
        return candidates

    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner and owner != "MSID" and _owner_fallback_credential_plausible(state, owner, credential_text):
        _add_authority_candidate(candidates, owner)

    required = _target_required_authorities_for_relevance(state, event)
    if "Admins" in required:
        _add_authority_candidate(candidates, "Admin1" if state.session.sp == "LockingSP" else "SID")
    for authority in sorted(required):
        if authority not in {"Anybody", "Admins", "Users"}:
            if _owner_fallback_credential_plausible(state, authority, credential_text):
                _add_authority_candidate(candidates, authority)
    if "Users" in required:
        _add_authority_candidate(candidates, "User1")
    return candidates


def _apply_invocation_auth_for_target(state: State, event: Event) -> tuple[str | None, bool]:
    if event.method in {"StartSession", "Authenticate"} or not state.session.open:
        return None, False
    candidates = _authas_pairs(event.required, event.optional, _method_raw_args(event))
    if event.authority is not None:
        candidates.insert(0, (event.authority, event.challenge))

    for authority, credential in candidates:
        authorities = [authority] if authority is not None else _authas_default_authority_candidates(state, event, credential)
        for resolved_authority in authorities:
            if resolved_authority in {"Anybody", "Admins", "Users"} or _has_authority(state, resolved_authority):
                continue
            if not _authority_allowed_for_target_method(state, event, resolved_authority):
                continue
            if not _authority_is_enabled(state, state.session.sp, resolved_authority):
                continue
            if _authority_locked_out(state, resolved_authority):
                continue
            if not credential:
                continue
            known_pin = state.pins.get(resolved_authority)
            if known_pin is not None and _credential_text(credential) != known_pin:
                continue
            if not _authority_relevant_for_target(state, event, resolved_authority):
                continue
            state.session.authenticated.add(resolved_authority)
            return resolved_authority, known_pin is None
    return None, False


def _explicit_authas_known_wrong(state: State, event: Event) -> bool:
    if event.method in {"StartSession", "Authenticate"} or not state.session.open:
        return False
    for authority, credential in _authas_pairs(event.required, event.optional, _method_raw_args(event)):
        if authority in {None, "Anybody", "Admins", "Users"} or not credential:
            continue
        if _has_authority(state, authority):
            continue
        if not _authority_allowed_for_target_method(state, event, authority):
            continue
        if _authority_locked_out(state, authority):
            return True
        known_pin = state.pins.get(authority)
        if known_pin is not None and _credential_text(credential) != known_pin:
            return True
    return False


def _tighten_raw_tcg_final_expectation(expected: ExpectedResponse, event: Event) -> ExpectedResponse:
    if not _raw_tcg_method_event(event):
        return expected
    if expected.confidence != "high":
        return expected
    if SUCCESS in expected.allowed_statuses:
        return expected
    if expected.allow_generic_failure_status:
        return expected

    if expected.raw_tcg_exact_status is not None:
        expected.allowed_statuses = {expected.raw_tcg_exact_status}
        return expected

    statuses = set(expected.allowed_statuses)
    if statuses == {INVALID_PARAMETER, FAIL}:
        expected.allowed_statuses = {INVALID_PARAMETER}
    return expected


def judge_target(state: State, event: Event) -> str:
    working_state = state
    if event.implicit_session and not state.session.open and event.kind == "tcg_method":
        working_state = copy.deepcopy(state)
        working_state.session = _implicit_session_for_event(working_state, event, assume_authenticated=False)
    added_authority, credential_unknown = _apply_invocation_auth_for_target(working_state, event)
    try:
        expected = expected_status(working_state, event)
        if _explicit_authas_known_wrong(working_state, event):
            expected.allowed_statuses = {NOT_AUTHORIZED} if _raw_tcg_method_event(event) else {NOT_AUTHORIZED, FAIL}
            expected.forbidden_statuses = set(expected.forbidden_statuses) | {SUCCESS}
        if added_authority is not None and credential_unknown:
            expected.allowed_statuses = set(expected.allowed_statuses) | {NOT_AUTHORIZED}
        expected = _tighten_raw_tcg_final_expectation(expected, event)
        return compare_expected_actual(expected, event)
    finally:
        if added_authority is not None:
            working_state.session.authenticated.discard(added_authority)


def predict_trajectory(trajectory: list[dict[str, Any]]) -> str:
    if not trajectory:
        return "FAIL"
    state = State()
    for raw in trajectory[:-1]:
        apply_transition(state, parse_event(raw))
    return judge_target(state, parse_event(trajectory[-1]))


class Solver:
    def predict(self, dataset):
        return {item["id"]: self.predict_one(item["steps"]) for item in dataset}

    def predict_one(self, steps):
        return predict_trajectory(steps).lower()




__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
