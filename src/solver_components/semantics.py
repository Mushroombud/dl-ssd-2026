"""Shared Opal authority, ACL, object, and table semantics."""

from __future__ import annotations

import ast
from dataclasses import replace
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *


def _range(state: State, range_id: int) -> RangeState:
    if range_id not in state.ranges:
        state.ranges[range_id] = RangeState(range_id=range_id, lock_on_reset=True, lock_on_reset_types={0})
    return state.ranges[range_id]


def _is_loglist_row_symbol(symbol: str, uid: str = "") -> bool:
    return uid == DEFAULT_LOGLIST_ROW_UID or symbol.startswith("LogList_")


def _cec_family_from_table_symbol(symbol: str) -> str | None:
    compact = re.sub(r"[^A-Za-z0-9]", "", symbol or "").upper()
    match = re.fullmatch(r"(?:TABLE)?CEC(160|163|192|224|233|283|384|521)(?:TABLE)?", compact)
    if not match:
        return None
    family = f"C_EC_{match.group(1)}"
    return family if family in C_EC_DEFAULT_CURVE_COLUMNS else None


def _cec_defaulted_row_values(table_symbol: str, values: dict[int, Any]) -> dict[int, Any]:
    family = _cec_family_from_table_symbol(table_symbol)
    row_values = dict(values)
    if family is not None:
        for column, default in C_EC_DEFAULT_CURVE_COLUMNS[family].items():
            row_values.setdefault(column, default)
    return row_values


def _loglist_row_key(symbol: str, uid: str = "") -> str:
    if uid == DEFAULT_LOGLIST_ROW_UID:
        return DEFAULT_LOGLIST_ROW_UID
    return symbol or uid


def _loglist_expected_cells(state: State, event: Event) -> dict[int, Any]:
    key = _loglist_row_key(event.invoking_symbol, event.invoking_uid)
    cells: dict[int, Any] = {}
    if key == DEFAULT_LOGLIST_ROW_UID:
        cells.update({1: "Log", 5: False})
    cells.update(state.loglist_rows.get(key, {}))
    return cells


def _is_issued_authority_symbol(symbol: str) -> bool:
    if symbol in {
        "Authority_Anybody",
        "Authority_Admins",
        "Authority_Makers",
        "Authority_SID",
        "Authority_Users",
        "Authority_PSID",
        "Authority_EraseMaster",
    }:
        return True
    return re.fullmatch(r"Authority_(Admin|User|BandMaster)\d+", symbol) is not None


def _is_issued_ace_symbol(symbol: str) -> bool:
    match = re.fullmatch(r"ACE_([0-9A-Fa-f]{8})", symbol)
    if not match:
        return False
    value = int(match.group(1), 16)
    exact = {
        0x00000001,
        0x00000002,
        0x00000003,
        0x00000004,
        0x00008C02,
        0x00008C03,
        0x00008C04,
        0x00030001,
        0x00030002,
        0x00030003,
        0x00038000,
        0x00038001,
        0x00039000,
        0x00039001,
        0x0003A000,
        0x0003A001,
        0x0003BFFF,
        0x0003F800,
        0x0003F801,
        0x00050001,
    }
    if value in exact:
        return True
    issued_ranges = (
        (0x0003A800, 0x0003AFFF),
        (0x0003B000, 0x0003B7FF),
        (0x0003B800, 0x0003BEFF),
        (0x0003D000, 0x0003D7FF),
        (0x0003E000, 0x0003E7FF),
        (0x0003E800, 0x0003EFFF),
        (0x0003F000, 0x0003F7FF),
        (0x0003FC00, 0x0003FCFF),
        (0x00044000, 0x00044FFF),
    )
    return any(start <= value <= end for start, end in issued_ranges)


def _has_authority(state: State, authority: str) -> bool:
    if authority == "Anybody":
        return state.session.open
    if authority == "Admins":
        if state.session.sp == "LockingSP":
            return any(auth.startswith("Admin") for auth in state.session.authenticated)
        return any(auth == "SID" or auth.startswith("Admin") or auth == "AdminExch" for auth in state.session.authenticated)
    if authority == "Makers":
        return any(auth in {"MakerSymK", "MakerPuK"} for auth in state.session.authenticated)
    if authority == "Users":
        return any(auth.startswith("User") for auth in state.session.authenticated)
    if authority == "PSID":
        return "PSID" in state.session.authenticated
    return authority in state.session.authenticated


def _has_any_authority(state: State, authorities: set[str]) -> bool:
    return any(_has_authority(state, authority) for authority in authorities)


def _range_master_authorizes(state: State, range_id: int | None) -> bool:
    if range_id is None:
        return False
    if "EraseMaster" in state.session.authenticated:
        return True
    return f"BandMaster{range_id}" in state.session.authenticated


def _range_id_known_for_access_control(state: State, range_id: int | None) -> bool:
    return _range_id_support_state(state, range_id) is True


def _range_id_support_state(state: State, range_id: int | None) -> bool | None:
    if range_id is None:
        return False
    if range_id == 0 or range_id in state.created_locking_ranges or range_id in state.ranges:
        return True
    max_ranges = _parse_int(state.locking_info.get("MaxRanges"))
    if max_ranges is None:
        if 1 <= range_id <= 8:
            return True
        return None
    return 1 <= range_id <= max_ranges


def _locking_sp_user_id_support_state(state: State, user_id: int | None) -> bool | None:
    if user_id is None or user_id < 1:
        return False
    observed_count = state.locking_sp_user_authority_count
    if observed_count is None:
        if 1 <= user_id <= 8:
            return True
        return None
    return user_id <= observed_count


def _locking_sp_user_object_support_state(state: State, symbol: str) -> bool | None:
    match = re.fullmatch(r"(?:C_PIN|Authority)_User(\d+)", symbol)
    if not match:
        return None
    return _locking_sp_user_id_support_state(state, int(match.group(1)))


def _max_observed_non_global_range_id(state: State) -> int:
    observed = set(state.created_locking_ranges)
    observed.update(range_id for range_id in state.ranges if range_id != 0)
    return max(observed, default=0)


def _returned_locking_range_id(event: Event) -> int | None:
    returned = _output_return_values(event.raw)
    candidates: list[tuple[str, str]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for val in value.values():
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            symbol, uid = _object_ref_from_value(value)
            if symbol or uid:
                candidates.append((symbol, uid))

    walk(returned)
    for symbol, uid in candidates:
        if not symbol and uid:
            symbol = _object_by_uid(uid)
        range_id = _range_id_from_symbol(symbol)
        if range_id is not None and range_id != 0:
            return range_id
    return None


def _range_backed_access_control_object_exists(state: State, symbol: str) -> bool | None:
    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        return _range_id_support_state(state, range_id)
    range_id = _range_id_from_key(symbol)
    if range_id is not None:
        return _range_id_support_state(state, range_id)
    return None


def _datastore_master_authorizes(state: State) -> bool:
    return "EraseMaster" in state.session.authenticated or any(_is_band_master(authority) for authority in state.session.authenticated)


def _is_user(authority: str | None) -> bool:
    return bool(authority and re.fullmatch(r"User\d+", authority))


def _is_band_master(authority: str | None) -> bool:
    return bool(authority and re.fullmatch(r"BandMaster\d+", authority))


def _user_enabled(state: State, authority: str | None) -> bool:
    if not _is_user(authority):
        return True
    return state.authority_enabled.get(authority, False)


def _authority_is_enabled(state: State, sp: str | None, authority: str | None) -> bool:
    if authority is None or authority == "Anybody":
        return True
    if authority in state.authority_enabled:
        return state.authority_enabled[authority]
    if sp == "AdminSP" and authority == "AdminExch":
        return False
    if authority.startswith("User"):
        return False
    match = re.fullmatch(r"Admin(\d+)", authority)
    if match:
        return sp == "LockingSP" and int(match.group(1)) == 1
    return True


def _authority_locked_out(state: State, authority: str | None) -> bool:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return False
    try_limit = state.pin_try_limits.get(authority, 0)
    return try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit


def _credential_was_invalidated(state: State, authority: str | None, credential: Any) -> bool:
    if authority is None or not credential:
        return False
    return _credential_text(credential) in state.invalidated_pin_values.get(authority, set())


def _authority_allowed_in_sp(sp: str | None, authority: str | None) -> bool:
    if authority is None or authority == "Anybody":
        return True
    if authority == "MSID":
        return False
    if sp == "AdminSP":
        if authority.startswith("User"):
            return False
        return True
    if sp == "LockingSP":
        return authority.startswith(("Admin", "User", "BandMaster")) or authority in {"Admins", "Users", "EraseMaster"}
    return True


def _authority_allowed_for_target_method(state: State, event: Event, authority: str | None) -> bool:
    if event.method == "Erase" and authority == "EraseMaster":
        return True
    if state.session.sp == "LockingSP" and (authority == "EraseMaster" or _is_band_master(authority)):
        if event.invoking_symbol.startswith(("Locking_", "DataStore")):
            return True
        if authority == "EraseMaster" and event.invoking_symbol.startswith("TLS_PSK_Key"):
            return True
    return _authority_allowed_in_sp(state.session.sp, authority)


def _expected_object_sp(event: Event, state: State | None = None) -> str | None:
    symbol = event.invoking_symbol
    if event.method == "Activate":
        return "AdminSP"
    if symbol in ADMIN_ONLY_TABLE_ROWS:
        return "AdminSP"
    if symbol in LOCKING_ONLY_TABLE_ROWS or symbol == "SecretProtectTable" or symbol.startswith("SecretProtect_"):
        return "LockingSP"
    if (
        symbol in {"TPerSign", "TperAttestation", "DataRemovalMechanism", "TPerInfo", "TemplateTable", "SPTable"}
        or symbol.startswith(("_CertData_", "Template_"))
    ):
        return "AdminSP"
    if symbol.startswith("Table_") or symbol in {"Table", "SPInfo", "SPTemplatesTable", "SPTemplates_Base", "SPTemplates_Admin", "MethodIDTable", "AccessControlTable", "ACETable"}:
        return state.session.sp if state is not None and state.session.sp else None
    if symbol in {"AdminSP", "LockingSP", "C_PIN_MSID", "C_PIN_SID"}:
        return "AdminSP"
    if symbol.startswith("UnknownSP_"):
        return "AdminSP"
    if symbol.startswith(("Locking_", "K_AES_", "MBRControl", "DataStore")) or symbol == "MBR":
        return "LockingSP"
    if symbol == "LockingInfo":
        return "LockingSP"
    if symbol in {"C_PIN_EraseMaster", "Authority_EraseMaster"} or symbol.startswith(("C_PIN_BandMaster", "Authority_BandMaster")):
        return "AdminSP"
    if symbol.startswith("C_PIN_Admin"):
        if event.invoking_uid.startswith("0000000B000002"):
            return "AdminSP"
        if event.invoking_uid.startswith("0000000B0001"):
            return "LockingSP"
        return state.session.sp if state is not None and state.session.sp else "LockingSP"
    if symbol.startswith("Authority_Admin"):
        if event.invoking_uid.startswith("00000009000002"):
            return "AdminSP"
        if event.invoking_uid.startswith("000000090001"):
            return "LockingSP"
        return state.session.sp if state is not None and state.session.sp else "LockingSP"
    if symbol.startswith(("C_PIN_User", "Authority_User")):
        return "LockingSP"
    if symbol.startswith("Port"):
        return "AdminSP"
    if symbol.startswith(("Authority_", "ACE_", "TLS_PSK_Key")):
        return state.session.sp if state is not None and state.session.sp else None
    return None


def _session_allows_object(state: State, event: Event) -> bool:
    expected_sp = _expected_object_sp(event, state)
    return expected_sp is None or state.session.sp is None or state.session.sp == expected_sp


def _implicit_session_sp(state: State, event: Event) -> str | None:
    if event.sp is not None:
        return event.sp
    expected = _expected_object_sp(event, state)
    if expected is not None:
        return expected
    if event.authority in {"SID", "Makers", "PSID", "Anybody"}:
        return "AdminSP"
    if event.authority:
        return "LockingSP"
    return None


def _implicit_session_for_event(state: State, event: Event, *, assume_authenticated: bool = False) -> Session:
    authenticated = {"Anybody"}
    if assume_authenticated and event.authority not in {None, "Anybody", "Admins", "Users", "Makers"}:
        authenticated.add(event.authority)
    return Session(open=True, sp=_implicit_session_sp(state, event), write=True, authenticated=authenticated, comid=event.comid)


def _method_supported_in_session(state: State, event: Event) -> bool:
    if event.method in {
        "Properties",
        "StartSession",
        "StartTrustedSession",
        "StartTlsSession",
        "EndSession",
        "CloseSession",
        "SyncSession",
        "SyncTrustedSession",
        "SyncTlsSession",
    }:
        return True
    if not state.session.open:
        return True
    allowed = SUPPORTED_METHODS_BY_SP.get(state.session.sp or "")
    return allowed is None or event.method in allowed


def _disabled_sp_response(state: State, event: Event) -> ExpectedResponse | None:
    sp = state.session.sp
    if not state.session.open or sp is None or state.sp_enabled.get(sp, True):
        return None
    if event.method in {"Authenticate", "DeleteSP", "EndSession", "CloseSession", "SyncSession", "SyncTrustedSession", "SyncTlsSession"}:
        return None
    if event.method == "Set" and event.invoking_symbol == "SPInfo" and set(event.values) == {6}:
        if _is_bool_literal(event.values[6]) and _as_bool(event.values[6]):
            return None
    return ExpectedResponse(
        {SP_DISABLED, FAIL},
        forbidden_statuses={SUCCESS},
        reason="Issued-Disabled SP permits only Authenticate, control-session methods, and Set SPInfo.Enabled to re-enable",
        confidence="high",
    )


def _is_session_manager_target(event: Event) -> bool:
    return event.invoking_symbol in {"", "SessionManager"} or event.invoking_uid == "00000000000000FF"


def _unsupported_method_response(event: Event) -> ExpectedResponse | None:
    if event.method in UNSUPPORTED_OPAL_METHODS or event.method == "UNKNOWN":
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} is not present in Opal AdminSP/LockingSP MethodID tables",
            confidence="high",
        )
    return None


def _set_required_authorities(state: State, event: Event) -> set[str]:
    symbol = event.invoking_symbol
    owner = _pin_owner_by_object(symbol)
    if symbol == "C_PIN_SID":
        return {"SID"}
    if owner and owner.startswith("Admin"):
        if PIN_COLUMN in event.values and _ace_expression_configured(state, "ACE_0003A001"):
            return set()
        return {"Admins", owner, "SID"}
    if owner and owner.startswith("User"):
        if PIN_COLUMN in event.values and set(event.values) <= {PIN_COLUMN}:
            ace_symbol = _pin_user_set_ace_symbol(owner)
            if ace_symbol and _ace_expression_configured(state, ace_symbol):
                return set()
            return {"Admins", owner}
        return {"Admins"}
    if owner and (owner == "EraseMaster" or owner.startswith("BandMaster")):
        return {"Admins", owner, "SID"}
    if symbol.startswith("Authority_BandMaster") and set(event.values) and set(event.values) <= {5}:
        return {"Admins", "SID", "EraseMaster"}
    if symbol.startswith("Authority_User"):
        return {"Admins"}
    if symbol.startswith("Authority_Admin"):
        return {"Admins", "SID"}
    if symbol == "DataStore" and _datastore_ace_configured(state, write=True):
        return set()
    if symbol in {"MBR", "DataStore"}:
        return {"Admins"}
    if symbol == "SPInfo":
        return {"Admins"}
    if symbol.startswith(("Locking_", "MBRControl", "ACE_", "DataStore", "Port")):
        return {"Admins"}
    if symbol.startswith("TLS_PSK_Key"):
        return {"Admins", "EraseMaster"} if state.session.sp == "LockingSP" else {"Admins", "SID"}
    if symbol == "DataRemovalMechanism":
        return {"Admins", "SID"}
    if symbol.startswith("K_AES_"):
        return {"Admins"}
    if symbol.startswith("Authority_"):
        return {"Admins", "SID"}
    return {"Admins", "SID"}


def _ace_locking_grant(symbol: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"ACE_0003([A-F0-9]{4})", symbol)
    if not match:
        return None
    value = int(match.group(1), 16)
    if 0xE000 <= value <= 0xE7FF:
        return "read", value - 0xE000
    if 0xE800 <= value <= 0xEFFF:
        return "write", value - 0xE800
    return None


def _ace_datastore_grant(symbol: str) -> str | None:
    name_match = re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", symbol)
    if name_match:
        return "read" if name_match.group(1) == "Get" else "write"
    match = re.fullmatch(r"ACE_0003FC([0-9A-F]{2})", symbol)
    if not match:
        return None
    if match.group(1) == "00":
        return "read"
    if match.group(1) in {"01", "02"}:
        return "write"
    return None


def _byte_table_symbol_from_descriptor(symbol: str) -> str | None:
    if symbol == "Table_MBR":
        return "MBR"
    if symbol == "Table_DataStore":
        return "DataStore"
    return None


def _configured_datastore_ace_symbols(state: State, write: bool) -> list[str]:
    grant = "write" if write else "read"
    defaults = ["ACE_0003FC01" if write else "ACE_0003FC00"]
    for sp, symbol in state.ace_expressions:
        if sp == (state.session.sp or "") and _ace_datastore_grant(symbol) == grant and symbol not in defaults:
            defaults.append(symbol)
    return defaults


def _datastore_ace_configured(state: State, write: bool) -> bool:
    return any(_ace_expression_configured(state, ace_symbol) for ace_symbol in _configured_datastore_ace_symbols(state, write))


def _extract_authorities(node: Any) -> set[str]:
    authorities: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                walk(key)
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            uid = _clean_uid(value)
            authority = _authority_by_uid(uid)
            if uid == "0000000900030000":
                authorities.add("User1")
            if authority is None:
                authority = _authority_by_name(value)
            if authority is not None:
                authorities.add(authority)
            elif isinstance(value, str):
                for token in _ace_string_tokens(value):
                    if token not in {"and", "or"}:
                        authorities.add(token)

    walk(node)
    return authorities


def _authority_by_name(value: Any) -> str | None:
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or ""))
    if not text:
        return None
    key = text.upper()
    fixed = {
        "ANYBODY": "Anybody",
        "ADMINS": "Admins",
        "USERS": "Users",
        "SID": "SID",
        "MSID": "MSID",
        "PSID": "PSID",
        "MAKERS": "Makers",
        "MAKERSYMK": "MakerSymK",
        "MAKERPUK": "MakerPuK",
        "ERASEMASTER": "EraseMaster",
        "TPERSIGN": "TPerSign",
        "TPEREXCH": "TPerExch",
        "ADMINEXCH": "AdminExch",
        "TPERATTESTATION": "TperAttestation",
    }
    match = re.fullmatch(r"BANDMASTER(\d+)", key)
    if match:
        return f"BandMaster{int(match.group(1))}"
    if key in fixed:
        return fixed[key]
    match = re.fullmatch(r"(ADMIN|USER)(\d+)", key)
    if match:
        return f"{match.group(1).title()}{int(match.group(2))}"
    return None


def _ace_tokens(node: Any) -> list[str]:
    tokens: list[str] = []

    def add_leaf(value: Any) -> None:
        authority = _authority_by_uid(_clean_uid(value)) or _authority_by_name(value)
        if authority is not None:
            tokens.append(authority)
            return
        text = _as_text(value or "").strip().upper()
        if re.fullmatch(r"AND|OR", text):
            tokens.append(text.lower())
            return
        if isinstance(value, str):
            tokens.extend(_ace_string_tokens(value))

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                walk(key)
                walk(val)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
        elif isinstance(value, set):
            for item in sorted(value, key=str):
                walk(item)
        else:
            add_leaf(value)

    walk(node)
    return tokens


def _ace_string_tokens(value: str) -> list[str]:
    tokens: list[str] = []
    for raw in re.findall(r"[A-Za-z][A-Za-z0-9_]*|[0-9A-Fa-f]{16}", value):
        upper = raw.upper()
        if upper in {"AND", "OR"}:
            tokens.append(upper.lower())
            continue
        authority = _authority_by_uid(_clean_uid(raw)) or _authority_by_name(raw)
        if authority is not None:
            tokens.append(authority)
    return tokens


def _ace_expression_from_value(value: Any) -> AceExpression:
    authorities = _extract_authorities(value)
    tokens = tuple(_ace_tokens(value))
    token_ops = {token for token in tokens if token in {"and", "or"}}
    text = repr(value).upper()
    if " OR " in text or "BOOLEAN_ACE - OR" in text or "BOOLEAN_ACE-OR" in text:
        operator = "or"
    elif " AND " in text or "BOOLEAN_ACE - AND" in text or "BOOLEAN_ACE-AND" in text:
        operator = "and"
    elif "and" in token_ops and "or" not in token_ops:
        operator = "and"
    else:
        operator = "or"
    return AceExpression(authorities=authorities, operator=operator, tokens=tokens)


def _evaluate_ace_expression(state: State, expression: AceExpression) -> bool:
    if not expression.authorities:
        return False

    stack: list[bool] = []
    saw_operator = False
    invalid_rpn = False
    for token in expression.tokens:
        if token == "and":
            saw_operator = True
            if len(stack) < 2:
                invalid_rpn = True
                break
            right = stack.pop()
            left = stack.pop()
            stack.append(left and right)
        elif token == "or":
            saw_operator = True
            if len(stack) < 2:
                invalid_rpn = True
                break
            right = stack.pop()
            left = stack.pop()
            stack.append(left or right)
        else:
            stack.append(_has_authority(state, token))
    if saw_operator and not invalid_rpn and len(stack) == 1:
        return stack[0]

    if expression.operator == "and":
        return all(_has_authority(state, authority) for authority in expression.authorities)
    return any(_has_authority(state, authority) for authority in expression.authorities)


def _ace_key(state: State, ace_symbol: str) -> tuple[str, str]:
    return state.session.sp or "", ace_symbol


def _ace_expression_configured(state: State, ace_symbol: str) -> bool:
    return _ace_key(state, ace_symbol) in state.ace_expressions


def _default_ace_expression(sp: str | None, ace_symbol: str) -> AceExpression | None:
    suffix = ace_symbol.removeprefix("ACE_")
    if ace_symbol == "ACE_00000001":
        return AceExpression({"Anybody"})
    if ace_symbol == "ACE_00000002":
        return AceExpression({"Admins"})

    if sp == "AdminSP":
        admin_sp_defaults = {
            "00030001": {"SID"},
            "00008C02": {"Admins", "SID"},
            "00008C03": {"SID"},
            "00008C04": {"Anybody"},
            "0003A001": {"Admins", "SID"},
            "00030003": {"SID"},
            "00030002": {"SID"},
            "00050001": {"Admins", "SID"},
        }
        if suffix in admin_sp_defaults:
            return AceExpression(set(admin_sp_defaults[suffix]))

    if sp == "LockingSP":
        if suffix == "0003BFFF":
            return AceExpression({"Anybody"})
        if suffix.startswith("0003A8"):
            user_index = int(suffix[-4:], 16) - 0xA800
            if user_index > 0:
                return AceExpression({"Admins", f"User{user_index}"})
        admin_prefixes = (
            "000380",
            "000390",
            "000440",
            "0003A0",
            "0003B0",
            "0003B8",
            "0003D0",
            "0003E0",
            "0003E8",
            "0003F0",
            "0003F8",
            "0003FC",
        )
        if suffix.startswith(admin_prefixes):
            return AceExpression({"Admins"})

    return None


def _ace_expression_for(state: State, ace_symbol: str) -> AceExpression | None:
    return state.ace_expressions.get(_ace_key(state, ace_symbol)) or _default_ace_expression(state.session.sp, ace_symbol)


def _ace_satisfied(state: State, ace_symbol: str) -> bool:
    expression = _ace_expression_for(state, ace_symbol)
    return bool(expression and _evaluate_ace_expression(state, expression))


def _pin_user_set_ace_symbol(owner: str) -> str | None:
    match = re.fullmatch(r"User(\d+)", owner)
    if not match:
        return None
    return f"ACE_0003{0xA800 + int(match.group(1)):04X}"


def _pin_user_from_set_ace_symbol(ace_symbol: str) -> str | None:
    match = re.fullmatch(r"ACE_0003([A-F0-9]{4})", ace_symbol)
    if not match:
        return None
    value = int(match.group(1), 16)
    if value <= 0xA800:
        return None
    if value < 0xA800 or value > 0xAFFF:
        return None
    return f"User{value - 0xA800}"


def _locking_ace_symbol(prefix: int, range_id: int) -> str:
    return f"ACE_0003{prefix + range_id:04X}"


def _key_genkey_ace_symbol(symbol: str) -> str | None:
    range_id = _range_id_from_key(symbol)
    if range_id is None:
        return None
    if symbol.startswith("K_AES_128_"):
        return _locking_ace_symbol(0xB000, range_id)
    if symbol.startswith("K_AES_256_"):
        return _locking_ace_symbol(0xB800, range_id)
    return None


def _ace_expression_users(state: State, ace_symbol: str) -> set[str]:
    expression = _ace_expression_for(state, ace_symbol)
    if expression is None:
        return set()
    return {authority for authority in expression.authorities if _is_user(authority)}


def _ace_authorizes_set(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    owner = _pin_owner_by_object(symbol)
    if owner and owner.startswith("Admin") and PIN_COLUMN in event.values and _ace_expression_configured(state, "ACE_0003A001"):
        return _ace_satisfied(state, "ACE_0003A001")
    if owner and owner.startswith("User") and PIN_COLUMN in event.values and set(event.values) <= {PIN_COLUMN}:
        ace_symbol = _pin_user_set_ace_symbol(owner)
        return bool(ace_symbol and _ace_satisfied(state, ace_symbol))

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        columns = set(event.values)
        admin_set_ace = _locking_ace_symbol(0xF000, range_id)
        if columns and columns <= set(range(3, 10)) and _ace_expression_configured(state, admin_set_ace) and _ace_satisfied(state, admin_set_ace):
            return True
        if columns and columns <= {7, 8}:
            checks: list[bool] = []
            for column, prefix, legacy in (
                (7, 0xE000, state.range_read_lock_users),
                (8, 0xE800, state.range_write_lock_users),
            ):
                if column not in columns:
                    continue
                ace_symbol = _locking_ace_symbol(prefix, range_id)
                if _ace_expression_configured(state, ace_symbol):
                    checks.append(_ace_satisfied(state, ace_symbol))
                else:
                    users = {auth for auth in state.session.authenticated if _is_user(auth)}
                    checks.append(bool(users & legacy.get(range_id, set())))
            return bool(checks) and all(checks)

    if symbol.startswith("DataStore"):
        configured = [ace_symbol for ace_symbol in _configured_datastore_ace_symbols(state, write=True) if _ace_expression_configured(state, ace_symbol)]
        if configured:
            return any(_ace_satisfied(state, ace_symbol) for ace_symbol in configured)
        return _user_acl_allows_datastore(state, write=True)

    if symbol.startswith("Authority_"):
        columns = set(event.values)
        if columns and columns <= {5}:
            enabled_ace = "ACE_00030001" if state.session.sp == "AdminSP" else "ACE_00039001"
            if _ace_expression_configured(state, enabled_ace):
                return _ace_satisfied(state, enabled_ace)

    if symbol.startswith("ACE_"):
        columns = set(event.values)
        if ACE_BOOLEAN_EXPR_COLUMN in columns and _ace_expression_configured(state, "ACE_00038001"):
            return _ace_satisfied(state, "ACE_00038001")

    if symbol == "MBRControl":
        columns = set(event.values)
        if not columns or not columns <= {1, 2, 3}:
            return False
        checks: list[bool] = []
        if 1 in columns:
            checks.append(_ace_expression_configured(state, "ACE_0003F800") and _ace_satisfied(state, "ACE_0003F800"))
        if columns & {2, 3}:
            done_allowed = False
            if _ace_expression_configured(state, "ACE_0003F800"):
                done_allowed = done_allowed or _ace_satisfied(state, "ACE_0003F800")
            if _ace_expression_configured(state, "ACE_0003F801"):
                done_allowed = done_allowed or _ace_satisfied(state, "ACE_0003F801")
            checks.append(done_allowed)
        return bool(checks) and all(checks)

    return False


def _user_acl_allows_locking_set(state: State, event: Event) -> bool:
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None:
        return False
    columns = set(event.values)
    if not columns or not columns <= {7, 8}:
        return False
    users = {auth for auth in state.session.authenticated if _is_user(auth)}
    if not users:
        return False
    for user in users:
        if 7 in columns and user not in state.range_read_lock_users.get(range_id, set()):
            continue
        if 8 in columns and user not in state.range_write_lock_users.get(range_id, set()):
            continue
        return True
    return False


def _user_acl_allows_datastore(state: State, write: bool) -> bool:
    configured = [ace_symbol for ace_symbol in _configured_datastore_ace_symbols(state, write) if _ace_expression_configured(state, ace_symbol)]
    if configured:
        return any(_ace_satisfied(state, ace_symbol) for ace_symbol in configured)
    users = {auth for auth in state.session.authenticated if _is_user(auth)}
    if not users:
        return False
    allowed = state.datastore_write_users if write else state.datastore_read_users
    return bool(users & allowed)


def _range_values_invalid_for_geometry(state: State, range_id: int | None, values: dict[int, Any], creating: bool = False) -> bool:
    if range_id == 0 and any(col in values for col in (3, 4)):
        return True
    if any(isinstance(values.get(col), bool) for col in (3, 4) if col in values):
        return True
    current = _range(state, range_id or 0)
    start = _parse_int(values.get(3)) if 3 in values else current.range_start
    length = _parse_int(values.get(4)) if 4 in values else current.range_length
    if start is None or length is None:
        return True
    if start < 0 or length < 0:
        return True

    alignment_required = _as_bool(state.locking_info.get("AlignmentRequired"))
    granularity = _parse_int(state.locking_info.get("AlignmentGranularity"))
    lowest = _parse_int(state.locking_info.get("LowestAlignedLBA")) or 0
    non_global = creating or bool(range_id)
    if non_global and alignment_required and granularity and granularity > 0:
        if 3 in values and start and (start - lowest) % granularity:
            return True
        if 4 in values and length:
            length_alignment = (length - lowest) % granularity if start == 0 else length % granularity
            if length_alignment:
                return True

    if non_global and (creating or 3 in values or 4 in values) and _range_values_overlap(state, range_id, start, length):
        return True
    return False


def _range_values_overlap(state: State, range_id: int | None, start: int, length: int) -> bool:
    if length == 0:
        return False
    end = start + length - 1
    for existing_id, existing in state.ranges.items():
        if existing_id == 0 or existing_id == range_id or existing.range_length == 0:
            continue
        existing_end = existing.range_start + existing.range_length - 1
        if start <= existing_end and existing.range_start <= end:
            return True
    return False


def _parse_data_removal_mechanism(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    aliases = {
        "OVERWRITEDATAERASE": 0,
        "OVERWRITE": 0,
        "BLOCKERASE": 1,
        "BLOCK": 1,
        "CRYPTOGRAPHICERASE": 2,
        "CRYPTOERASE": 2,
        "CRYPTOGRAPHIC": 2,
        "CRYPTO": 2,
        "VENDORSPECIFICERASE": 5,
        "VENDORSPECIFIC": 5,
        "VENDOR": 5,
    }
    return aliases.get(key)


def _master_authorizes_set(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    if symbol.startswith("Locking_"):
        return _range_master_authorizes(state, _range_id_from_symbol(symbol))
    if symbol.startswith("DataStore"):
        return _datastore_master_authorizes(state)
    return False


def _range_reencrypt_busy(range_state: RangeState) -> bool:
    return range_state.reencrypt_state != 1


def _range_reencrypt_active(range_state: RangeState) -> bool:
    return range_state.reencrypt_state == 3


def _global_reencrypt_busy(state: State) -> bool:
    return _range_reencrypt_busy(_range(state, 0))


def _reencrypt_request_invalid(range_state: RangeState, request: int | None) -> bool:
    if request is None:
        return True
    current = range_state.reencrypt_state
    if request == 1:
        return current != 1
    if request == 2:
        return current not in {4, 5}
    if request in {3, 4}:
        return current != 5
    if request == 5:
        return current not in {2, 3}
    return True


def _reencrypt_blocks_set(state: State, event: Event) -> str | None:
    if not event.invoking_symbol.startswith("Locking_"):
        return None
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None:
        return None
    columns = set(event.values)
    if columns & {3, 4}:
        if _global_reencrypt_busy(state):
            return "Global Range re-encryption blocks Locking range geometry changes"
        if _range_reencrypt_busy(_range(state, range_id)):
            return "RangeStart/RangeLength cannot change while the range is re-encrypting"
    if 11 in columns and _range_reencrypt_busy(_range(state, range_id)):
        return "NextKey is writable only when ReEncryptState is IDLE"
    return None


def _range_id_from_delete_uid(uid: str) -> int | None:
    return _range_id_from_symbol(_object_by_uid(uid))


def _byte_table_ref_invalid(value: Any) -> bool:
    uid = _clean_uid(value)
    if uid in {"", "0000000000000000"}:
        return False
    symbol, uid_from_ref = _object_ref_from_value(value)
    return not (_is_byte_table_uid(uid_from_ref or uid) or _is_byte_table_symbol(symbol))


def _media_key_ref_invalid(value: Any) -> bool:
    uid = _clean_uid(value)
    if uid in {"", "0000000000000000"}:
        return False
    symbol, uid_from_ref = _object_ref_from_value(value)
    target = symbol or _object_by_uid(uid_from_ref or uid)
    return _range_id_from_key(target) is None


def _byte_table_set_rows_out_of_bounds(state: State, event: Event) -> bool:
    rows = state.byte_table_rows.get(event.invoking_symbol)
    if rows is None:
        return False
    start_offset = _byte_table_set_start_offset(event)
    payload_length = _byte_table_payload_length(event)
    if start_offset is None or payload_length is None or payload_length <= 0:
        return False
    end_offset = start_offset + payload_length - 1
    return start_offset >= rows or end_offset >= rows


def _set_effective_event(event: Event) -> tuple[Event, ExpectedResponse | None]:
    where_found, where_value = _named_method_arg_value(event, "Where", "where")
    symbol = event.invoking_symbol
    if _is_byte_table_symbol(symbol):
        if _byte_table_where_invalid(event):
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Byte-table Set Where must use row addressing",
                confidence="high",
            )
        return event, None

    if _is_table_symbol(symbol):
        if not where_found:
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set on an object table requires a Where UID",
                confidence="high",
            )
        row_symbol, row_uid = _object_ref_from_value(where_value)
        if not row_symbol and not row_uid:
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set Where must identify an object-table row",
                confidence="high",
            )
        if _next_where_invalid(event):
            return event, ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Table.Set Where must reference a row in the invoking object table",
                confidence="high",
            )
        if not row_symbol and row_uid:
            row_symbol = _object_by_uid(row_uid)
        return replace(event, invoking_symbol=row_symbol, invoking_uid=row_uid, invoking_name=row_symbol), None

    if where_found:
        return event, ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Object.Set must omit Where",
            confidence="high",
        )
    return event, None


def _set_values_omitted(event: Event) -> bool:
    if event.values or _byte_table_has_payload(event):
        return False
    found, value = _named_method_arg_value(
        event,
        "Values",
        "values",
        "RowValues",
        "rowValues",
        "Bytes",
        "bytes",
        "Data",
        "data",
        "Buffer",
        "BufferIn",
        "Payload",
        "payload",
    )
    return not found or _empty_payload(value)


def _set_has_duplicate_value_columns(event: Event) -> bool:
    if _is_byte_table_symbol(event.invoking_symbol):
        return False

    found, values_node = _dict_lookup(
        event.optional,
        "Values",
        "Value",
        "RowValues",
        "rowValues",
        "NamedValues",
        "namedValues",
        "SetValues",
        "setValues",
    )
    if not found:
        found, values_node = _dict_lookup(event.optional, "Row")
    if not found:
        raw_args = _method_raw_args(event)
        values_node = raw_args if isinstance(raw_args, (list, tuple, dict)) else None
    if values_node is None:
        return False

    columns: list[int] = []

    def parse_column_key(value: Any) -> int | None:
        text = _as_text(value).strip()
        if not text:
            return None
        try:
            if re.fullmatch(r"0x[0-9A-Fa-f]+", text):
                return int(text, 16)
            if re.fullmatch(r"\d+", text):
                return int(text, 10)
            if re.fullmatch(r"[0-9A-Fa-f]+", text):
                return int(text, 16)
        except ValueError:
            return None
        return None

    def is_column_pair_sequence(value: Any) -> bool:
        if not isinstance(value, (list, tuple)):
            return False
        pairs = [item for item in value if isinstance(item, (list, tuple)) and len(item) == 2]
        return bool(pairs) and len(pairs) == len(value) and all(parse_column_key(item[0]) is not None for item in pairs)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            sibling_keys = {re.sub(r"[^A-Za-z0-9_]", "", _as_text(key or "")).upper() for key in value}
            for key, val in value.items():
                if (
                    _function_alias(_function_name(_function_input_section(event.raw) if isinstance(event.raw, dict) else {})) == "setpskentry"
                    and re.sub(r"[^A-Za-z0-9_]", "", _as_text(key or "")).lower() in {"psk", "uid", "key", "entry", "index"}
                    and _as_text(key).strip() != "PSK"
                ):
                    continue
                column = parse_column_key(key)
                if column is None:
                    column = _column_from_name(key, event.invoking_symbol, sibling_keys)
                if column is not None:
                    if column == 1 and is_column_pair_sequence(val):
                        walk(val)
                    else:
                        columns.append(column)
                    continue
                walk(val)
            return
        if isinstance(value, (list, tuple)) and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            column = parse_column_key(value[0])
            if column is None:
                column = _column_from_name(value[0], event.invoking_symbol)
            if column is not None:
                if column == 1 and is_column_pair_sequence(value[1]):
                    walk(value[1])
                else:
                    columns.append(column)
                return
            walk(value[1])
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    walk(values_node)
    return len(columns) != len(set(columns))


def _hash_protocol_column_for_symbol(symbol: str) -> int | None:
    if symbol.startswith("C_RSA_"):
        return 0x0C
    if symbol.startswith("C_AES_"):
        return 0x07
    if symbol.startswith("C_HMAC_"):
        return 0x04
    match = re.match(r"C_EC_(160|192|224|256|384|521)", symbol)
    if match is not None:
        return 0x0B
    if re.match(r"C_EC_163", symbol):
        return 0x0D
    if re.match(r"C_EC_233", symbol):
        return 0x0C
    if re.match(r"C_EC_283", symbol):
        return 0x0E
    return None


def _caes_set_values_invalid(symbol: str, values: dict[int, Any]) -> bool:
    mode = values.get(0x04)
    feedback_size = values.get(0x05)
    fixed_byte_lengths = {0x03: 32 if symbol.startswith("C_AES_256") else 16, 0x06: 16}
    for column, expected_length in fixed_byte_lengths.items():
        if column in values:
            actual_length = _byte_payload_length(values[column])
            if actual_length != expected_length:
                return True
    parsed_mode = None
    if 0x04 in values:
        if isinstance(mode, bool):
            return True
        parsed_mode = _parse_int(mode)
        if parsed_mode not in set(range(0, 12)):
            return True
    if 0x05 in values:
        if isinstance(feedback_size, bool):
            return True
        parsed_feedback = _parse_int(feedback_size)
        if parsed_feedback is None or parsed_feedback < 0 or parsed_feedback > 0xFFFF:
            return True
        if parsed_mode == 2 and not 1 <= parsed_feedback <= 16:
            return True
    return False


def _chmac_key_length(symbol: str) -> int | None:
    if symbol.startswith("C_HMAC_160"):
        return 20
    if symbol.startswith("C_HMAC_256"):
        return 32
    if symbol.startswith("C_HMAC_384"):
        return 48
    if symbol.startswith("C_HMAC_512"):
        return 64
    return None


def _invalid_set_values(state: State, event: Event) -> bool:
    symbol = event.invoking_symbol
    if symbol.startswith("_CertData_"):
        return True
    if _is_byte_table_symbol(symbol):
        granularity = state.byte_table_mandatory_granularity.get(symbol)
        return (
            _byte_table_set_invalid(event)
            or _byte_table_set_mandatory_granularity_invalid(event, granularity)
            or _byte_table_set_rows_out_of_bounds(state, event)
        )
    if _is_table_symbol(symbol):
        return True
    if symbol.startswith("Type_") and 4 in event.values:
        return True
    if symbol.startswith(("SPTemplates_", "Template_", "MethodID_", "AccessControl_", "SecretProtect_")):
        return True
    if _is_loglist_row_symbol(symbol, event.invoking_uid):
        columns = set(event.values)
        if not columns or not columns <= {3, 4, 5}:
            return True
        if columns & {3, 4}:
            return True
        return 5 in event.values and not _is_bool_literal(event.values[5])
    if symbol in {"Log", "LogTable"} or symbol.startswith("Log_"):
        return True
    if symbol.startswith("K_AES_"):
        return True
    if symbol.startswith("C_RSA_") and 3 in event.values:
        if isinstance(event.values[3], bool):
            return True
        padding = _parse_int(event.values[3])
        if padding not in {0, 1, 2, 3, 4}:
            return True
    if symbol.startswith("C_AES_") and _caes_set_values_invalid(symbol, event.values):
        return True
    hmac_key_length = _chmac_key_length(symbol)
    if hmac_key_length is not None and 3 in event.values:
        if _byte_payload_length(event.values[3]) != hmac_key_length:
            return True
    hash_column = _hash_protocol_column_for_symbol(symbol)
    if hash_column is not None and hash_column in event.values:
        if isinstance(event.values[hash_column], bool):
            return True
        hash_protocol = _parse_int(event.values[hash_column])
        if hash_protocol not in {0, 1, 2, 3, 4}:
            return True
    if symbol in {"LockingInfo", "MethodIDTable", "Table_MethodID"}:
        return True
    if symbol == "SPInfo":
        columns = set(event.values)
        if not columns or not columns <= {5, 6}:
            return True
        if 5 in event.values:
            if isinstance(event.values[5], bool):
                return True
            timeout = _parse_int(event.values[5])
            if timeout is None or timeout < 0:
                return True
        if 6 in event.values and not _is_bool_literal(event.values[6]):
            return True
        return False
    if symbol in {"AdminSP", "LockingSP"}:
        columns = set(event.values)
        if not columns or not columns <= {7}:
            return True
        return not _is_bool_literal(event.values[7])
    if symbol == "DataRemovalMechanism":
        columns = set(event.values)
        if not columns or not columns <= {1}:
            return True
        mechanism = _parse_data_removal_mechanism(event.values.get(1))
        return mechanism not in DATA_REMOVAL_MECHANISM_VALUES
    if symbol == "TPerInfo":
        columns = set(event.values)
        if not columns or not columns <= {8}:
            return True
        return not _is_bool_literal(event.values[8])
    if symbol == "C_PIN_MSID":
        return True
    if symbol.startswith("C_PIN_"):
        columns = set(event.values)
        allowed = {
            PIN_COLUMN,
            CPIN_CHARSET_COLUMN,
            CPIN_TRY_LIMIT_COLUMN,
            CPIN_TRIES_COLUMN,
            CPIN_PERSISTENCE_COLUMN,
            MIN_PIN_COLUMN,
        }
        if not columns or not columns <= allowed:
            return True
        if CPIN_CHARSET_COLUMN in event.values and _byte_table_ref_invalid(event.values[CPIN_CHARSET_COLUMN]):
            return True
        if CPIN_TRY_LIMIT_COLUMN in event.values:
            if isinstance(event.values[CPIN_TRY_LIMIT_COLUMN], bool):
                return True
            try_limit = _parse_int(event.values[CPIN_TRY_LIMIT_COLUMN])
            if try_limit is None or try_limit < 0:
                return True
        if CPIN_TRIES_COLUMN in event.values:
            if isinstance(event.values[CPIN_TRIES_COLUMN], bool):
                return True
            if _parse_int(event.values[CPIN_TRIES_COLUMN]) != 0:
                return True
        if CPIN_PERSISTENCE_COLUMN in event.values and not _is_bool_literal(event.values[CPIN_PERSISTENCE_COLUMN]):
            return True
        if PIN_COLUMN in event.values:
            if isinstance(event.values[PIN_COLUMN], bool):
                return True
            if event.values[PIN_COLUMN] in {None, ""}:
                return True
        owner = _pin_owner_by_object(symbol)
        if MIN_PIN_COLUMN in event.values:
            if isinstance(event.values[MIN_PIN_COLUMN], bool):
                return True
            min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
            if min_pin is None or min_pin < 0 or min_pin > 32:
                return True
        else:
            min_pin = state.pin_min_lengths.get(owner or "", 0)
        if PIN_COLUMN in event.values:
            pin_length = _credential_length(event.values[PIN_COLUMN])
            if pin_length > 32:
                return True
            if owner and pin_length < min_pin:
                return True
    if symbol.startswith("ACE_"):
        columns = set(event.values)
        if not columns or not columns <= {2, ACE_BOOLEAN_EXPR_COLUMN}:
            return True
        if 2 in event.values and _is_issued_ace_symbol(symbol):
            return True
        if ACE_BOOLEAN_EXPR_COLUMN in event.values:
            expression = _ace_expression_from_value(event.values[ACE_BOOLEAN_EXPR_COLUMN])
            pin_user = _pin_user_from_set_ace_symbol(symbol)
            if state.session.sp == "LockingSP" and pin_user:
                supported = ({"Admins"}, {"Admins", pin_user})
                return expression.operator != "or" or expression.authorities not in supported
    if symbol.startswith("Locking_"):
        range_id = _range_id_from_symbol(symbol)
        columns = set(event.values)
        if not columns or not columns <= ({2} | set(range(3, 20))):
            return True
        for column in (5, 6, 7, 8):
            if column in event.values and not _is_bool_literal(event.values[column]):
                return True
        if 9 in event.values and _reset_list_invalid(event.values[9]):
            return True
        if 16 in event.values and _reset_condition_list_invalid(event.values[16]):
            return True
        if 10 in event.values and _media_key_ref_invalid(event.values[10]):
            return True
        if 12 in event.values:
            return True
        if columns & {17, 18, 19}:
            return True
        if 13 in event.values and _reencrypt_request_invalid(_range(state, range_id or 0), _parse_reencrypt_request(event.values[13])):
            return True
        if 14 in event.values:
            if isinstance(event.values[14], bool):
                return True
            adv_key_mode = _parse_int(event.values[14])
            if adv_key_mode not in {0, 1}:
                return True
        if 15 in event.values:
            if isinstance(event.values[15], bool):
                return True
            verify_mode = _parse_int(event.values[15])
            if verify_mode not in {0, 1}:
                return True
        if 16 in event.values and _contains_bool_token(event.values[16]):
            return True
        if _range_values_invalid_for_geometry(state, range_id, event.values):
            return True
    if symbol.startswith("Authority_"):
        columns = set(event.values)
        if not columns or not columns <= {2, 5, 6, 10, 13, 15, 16}:
            return True
        if 2 in event.values and _is_issued_authority_symbol(symbol):
            return True
        if 5 in event.values and not _is_bool_literal(event.values[5]):
            return True
        if 6 in event.values:
            if isinstance(event.values[6], bool):
                return True
            secure = _parse_int(event.values[6])
            if secure is not None and not 0 <= secure <= 255:
                return True
        for column in (15, 16):
            if column in event.values:
                if isinstance(event.values[column], bool):
                    return True
                parsed = _parse_int(event.values[column])
                if parsed is None or parsed < 0:
                    return True
    if symbol == "MBRControl":
        columns = set(event.values)
        if not columns or not columns <= set(MBR_COLUMNS):
            return True
        for column in (1, 2):
            if column in event.values and not _is_bool_literal(event.values[column]):
                return True
        if 3 in event.values and _reset_list_invalid(event.values[3]):
            return True
    if symbol.startswith("Port"):
        columns = set(event.values)
        if not columns or not columns <= set(PORT_COLUMNS):
            return True
        if 3 in event.values and not _is_bool_literal(event.values[3]):
            return True
        if 2 in event.values and _reset_list_invalid(event.values[2]):
            return True
    if symbol.startswith("TLS_PSK_Key"):
        columns = set(event.values)
        if not columns or not columns <= set(TLS_PSK_COLUMNS):
            return True
        if 3 in event.values and not _is_bool_literal(event.values[3]):
            return True
        if 5 in event.values and event.values[5] in {None, ""}:
            return True
    return False


def _create_table_arg(event: Event, index: int, *names: str) -> tuple[bool, Any]:
    found, value = _named_method_arg_value(event, *names)
    if found:
        return True, value
    raw_args = _method_raw_args(event)
    if not isinstance(raw_args, (list, tuple)) or any(_is_named_pair(item) for item in raw_args):
        return False, None
    if len(raw_args) <= index:
        return False, None
    return True, raw_args[index]


def _create_table_name_text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("name", "Name", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _create_table_name_text(item)
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _create_table_name_text(value[0])
    return _as_text(value or "").strip()


def _create_table_kind(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("kind", "Kind", "name", "Name", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                kind = _create_table_kind(item)
                if kind is not None:
                    return kind
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _create_table_kind(value[0])
    parsed = _parse_int(value)
    if parsed == 1:
        return "object"
    if parsed == 2:
        return "byte"
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if text in {"OBJECT", "OBJECTTABLE", "OBJ"}:
        return "object"
    if text in {"BYTE", "BYTES", "BYTETABLE"}:
        return "byte"
    return None


def _create_table_columns_empty(value: Any) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    text = re.sub(r"\s+", "", _as_text(value or ""))
    return text in {"", "[]", "()", "{}"}


def _create_table_column_schema(value: Any) -> tuple[set[int], tuple[int, ...]]:
    def column_from_definition(item: Any) -> int | None:
        if isinstance(item, dict):
            for key in ("Column", "column", "ColumnID", "columnId", "Name", "name"):
                found, candidate = _dict_lookup(item, key)
                if found:
                    parsed = _parse_int(candidate)
                    if parsed is not None:
                        return parsed
        if isinstance(item, (list, tuple)) and item and not isinstance(item[0], (dict, list, tuple, set)):
            parsed = _parse_int(item[0])
            if parsed is not None:
                return parsed
        parsed = _parse_int(item)
        return parsed if parsed is not None else None

    def is_column_definition(item: Any) -> bool:
        return column_from_definition(item) is not None

    def collect(node: Any) -> set[int]:
        out: set[int] = set()

        def walk(item: Any) -> None:
            column = column_from_definition(item)
            if column is not None:
                out.add(column)
                return
            if isinstance(item, dict):
                for nested in item.values():
                    walk(nested)
            elif isinstance(item, (list, tuple, set)):
                for nested in item:
                    walk(nested)

        walk(node)
        return out

    if isinstance(value, dict):
        found_unique, unique_node = _dict_lookup(value, "Unique", "unique", "UniqueColumns", "uniqueColumns")
        found_non_unique, non_unique_node = _dict_lookup(
            value,
            "NonUnique",
            "nonUnique",
            "NonUniqueColumns",
            "nonUniqueColumns",
            "Columns",
            "columns",
        )
        if found_unique or found_non_unique:
            unique = collect(unique_node) if found_unique else set()
            non_unique = collect(non_unique_node) if found_non_unique else set()
            return unique | non_unique, tuple(sorted(unique))

    if isinstance(value, (list, tuple)) and len(value) == 2 and not is_column_definition(value[0]) and not is_column_definition(value[1]):
        unique = collect(value[0])
        non_unique = collect(value[1])
        if unique or non_unique:
            return unique | non_unique, tuple(sorted(unique))

    columns = collect(value)
    return columns, ()


def _created_table_row_signature(values: dict[int, Any], columns: tuple[int, ...]) -> tuple[str, ...]:
    def value_key(value: Any) -> str:
        parsed = _parse_int(value)
        if parsed is not None:
            return f"int:{parsed}"
        uid = _clean_uid(value)
        if uid:
            return f"uid:{uid}"
        return "text:" + re.sub(r"\s+", " ", _as_text(value)).strip().upper()

    return tuple(value_key(values.get(column)) for column in columns)


def _created_table_unique_conflict(state: State, table_uid: str, values: dict[int, Any]) -> bool:
    unique_columns = state.created_table_unique_columns.get(table_uid, ())
    if not unique_columns or not set(unique_columns) <= set(values):
        return False
    current = _created_table_row_signature(values, unique_columns)
    return any(_created_table_row_signature(row, unique_columns) == current for row in state.created_table_rows.get(table_uid, []))


def _created_table_for_event(state: State, event: Event) -> tuple[str, str] | None:
    if not event.invoking_uid:
        return None
    return state.created_tables.get(event.invoking_uid)


def _created_object_sp_for_uid(state: State, uid: str) -> str | None:
    clean_uid = _clean_uid(uid)
    if not clean_uid:
        return None
    if clean_uid in state.created_tables:
        return state.created_tables[clean_uid][0]
    table_uid = state.created_table_descriptor_uids.get(clean_uid)
    if table_uid is not None:
        table_info = state.created_tables.get(table_uid)
        return table_info[0] if table_info is not None else None
    row_info = state.created_table_row_values_by_uid.get(clean_uid)
    if row_info is not None:
        table_info = state.created_tables.get(row_info[0])
        return table_info[0] if table_info is not None else None
    return None


def _created_object_outside_session(state: State, uid: str) -> bool:
    created_sp = _created_object_sp_for_uid(state, uid)
    return created_sp is not None and state.session.sp is not None and created_sp != state.session.sp


def _is_credential_symbol(symbol: str) -> bool:
    return bool(
        _pin_owner_by_object(symbol)
        or _range_id_from_key(symbol) is not None
        or re.match(r"C_EC_(160|163|192|224|233|283|384|521)", symbol or "") is not None
        or symbol in {"TPerSign", "TperAttestation"}
        or symbol.startswith("TLS_PSK_Key")
    )


def _credential_ref_invalid(value: Any) -> bool:
    symbol, uid = _object_ref_from_value(value)
    if not symbol and uid:
        symbol = _object_by_uid(uid)
    return not symbol or not _is_credential_symbol(symbol)


def _package_credential_arg_invalid(event: Event, *names: str) -> bool:
    found, value = _named_method_arg_value(event, *names)
    if not found:
        return False
    return _credential_ref_invalid(value)


def _package_required_authorities(state: State, event: Event) -> set[str]:
    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner == "SID":
        return {"Admins", "SID"}
    if owner and owner.startswith("Admin"):
        return {"Admins", owner, "SID"}
    if owner and owner.startswith("User"):
        return {"Admins", owner}
    if owner and (owner == "EraseMaster" or owner.startswith("BandMaster")):
        return {"Admins", owner, "SID"}
    if _range_id_from_key(event.invoking_symbol) is not None:
        return {"Admins"}
    if event.invoking_symbol.startswith("TLS_PSK_Key"):
        return {"Admins", "SID"} if state.session.sp == "AdminSP" else {"Admins", "EraseMaster"}
    return {"Admins"}


def _table_method_common_failure(state: State, event: Event, method: str) -> ExpectedResponse | None:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER}, reason=f"{method} is not available on byte tables", confidence="high")
        return None
    if not _is_table_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason=f"{method} is a table method", confidence="high")
    if event.invoking_symbol in {"MBR", "DataStore"} or event.invoking_symbol.startswith("DataStore"):
        return ExpectedResponse({INVALID_PARAMETER}, reason=f"{method} is not available on byte tables", confidence="high")
    return None


def _table_query_common_failure(state: State, event: Event, method: str) -> ExpectedResponse | None:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{method} requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{method} dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{method} is defined for Opal object tables", confidence="high")
        return None
    if not _is_table_symbol(event.invoking_symbol) or _is_byte_table_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{method} is defined for Opal object tables", confidence="high")
    return None


def _ace_method_refs(event: Event) -> list[str]:
    sources: list[Any] = [event.required, event.optional, _method_raw_args(event)]
    refs: list[str] = []

    def walk(value: Any) -> None:
        if not isinstance(value, (dict, list, tuple, set)):
            text = _as_text(value or "").strip()
            if re.fullmatch(r"ACE_[0-9A-Fa-f]{8}", text) or re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", text, flags=re.IGNORECASE):
                symbol = _normalize_name(text)
                if symbol not in refs:
                    refs.append(symbol)
                return
            canonical = _canonical_ace_ref(value)
            if canonical and canonical not in refs:
                refs.append(canonical)
                return
        symbol, _ = _object_ref_from_value(value)
        if symbol.startswith("ACE_") and symbol not in refs:
            refs.append(symbol)
            return
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    for source in sources:
        walk(source)
    return refs


ACE_REF_SYMBOL_ALIASES = {
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


def _generic_ace_symbol_alias(key: str) -> str:
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


def _ace_ref_from_uid_ref(uid_ref: str) -> str:
    if len(uid_ref) != 16 or uid_ref[:8] != "00000000":
        return ""
    candidate = f"ACE_{uid_ref[-8:].upper()}"
    return candidate if _is_issued_ace_symbol(candidate) else ""


def _uid_ref_from_bytes_repr_text(text: str) -> str:
    if not text.startswith(("b'", 'b"', "bytearray(")):
        return ""
    try:
        parsed = ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return ""
    if not isinstance(parsed, (bytes, bytearray)):
        return ""
    return _uid_ref(parsed)


def _canonical_ace_ref(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, (dict, list, tuple, set)):
        text = _as_text(value).strip()
        bytes_uid_ref = _uid_ref_from_bytes_repr_text(text)
        bytes_ace_ref = _ace_ref_from_uid_ref(bytes_uid_ref)
        if bytes_ace_ref:
            return bytes_ace_ref
        key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
        if key in ACE_REF_SYMBOL_ALIASES:
            return ACE_REF_SYMBOL_ALIASES[key]
        generic_alias = _generic_ace_symbol_alias(key)
        if generic_alias:
            return generic_alias
        match = re.fullmatch(r"ACE_?([0-9A-Fa-f]{8})", text)
        if match:
            return f"ACE_{match.group(1).upper()}"
    symbol, uid = _object_ref_from_value(value)
    candidates = [symbol]
    if uid:
        candidates.extend([_object_by_uid(uid), uid])
    if not isinstance(value, (dict, list, tuple, set)):
        candidates.append(_as_text(value))
    for candidate in candidates:
        if not candidate:
            continue
        text = _as_text(candidate).strip()
        key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
        if key in ACE_REF_SYMBOL_ALIASES:
            return ACE_REF_SYMBOL_ALIASES[key]
        generic_alias = _generic_ace_symbol_alias(key)
        if generic_alias:
            return generic_alias
        match = re.fullmatch(r"ACE_?([0-9A-Fa-f]{8})", text)
        if match:
            return f"ACE_{match.group(1).upper()}"
        uid_ref = _uid_ref(text)
        if uid_ref:
            ace_ref = _ace_ref_from_uid_ref(uid_ref)
            if ace_ref:
                return ace_ref
            symbol = _object_by_uid(uid_ref)
            if symbol.startswith("ACE_"):
                return _canonical_ace_ref(symbol)
    return ""


def _canonical_ace_refs(values: list[str] | set[str] | tuple[str, ...]) -> set[str]:
    return {ref for ref in (_canonical_ace_ref(value) for value in values) if ref}


def _setacl_has_empty_acl_argument(event: Event) -> bool:
    found, value = _dict_lookup(event.required, "ACL")
    if not found:
        found, value = _dict_lookup(event.optional, "ACL")
    return found and isinstance(value, (list, tuple, set)) and len(value) == 0


def _ace_ref_exists(ref: str) -> bool:
    canonical = _canonical_ace_ref(ref)
    if not canonical:
        return False
    if canonical in set(ACE_REF_SYMBOL_ALIASES.values()):
        return True
    match = re.fullmatch(r"ACE_([0-9A-Fa-f]{8})", canonical)
    if not match:
        return False
    return _is_issued_ace_symbol(canonical)


def _row_uids(event: Event) -> list[str]:
    rows: Any = None
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Rows")
        if found:
            rows = value
            break
        found, value = _dict_lookup(source, "Row")
        if found and event.method == "DeleteRow":
            rows = value
            break
    if rows is None:
        rows = _mapping_value(event.required, "UID")
        if rows is None:
            rows = _mapping_value(event.optional, "UID")
    if rows is None:
        return []

    out: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for val in value.values():
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            uid = _uid_ref(value)
            if uid:
                out.append(uid)

    walk(rows)
    return out


def _row_object_refs(event: Event) -> list[tuple[str, str]]:
    rows: Any = None
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Rows")
        if found:
            rows = value
            break
        found, value = _dict_lookup(source, "Row")
        if found:
            rows = value
            break
    if rows is None:
        return []

    values = list(rows) if isinstance(rows, (list, tuple, set)) else [rows]
    refs: list[tuple[str, str]] = []
    for value in values:
        symbol, uid = _object_ref_from_value(value)
        if symbol or uid:
            refs.append((symbol, uid))
    return refs


def _created_locking_range_id(state: State, event: Event) -> int:
    returned = _output_return_values(event.raw)
    candidates: list[tuple[str, str]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for val in value.values():
                walk(val)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
        else:
            symbol, uid = _object_ref_from_value(value)
            if symbol or uid:
                candidates.append((symbol, uid))

    walk(returned)
    for symbol, uid in candidates:
        if not symbol and uid:
            symbol = _object_by_uid(uid)
        range_id = _range_id_from_symbol(symbol)
        if range_id is not None and range_id != 0:
            return range_id
    non_global = [range_id for range_id in state.ranges if range_id != 0]
    return (max(non_global) + 1) if non_global else 1


def _get_arg_uid(event: Event, *names: str) -> str:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return _uid_arg(value)
    return ""


def _access_control_combo_key(event: Event) -> tuple[str, str] | None:
    (found_invoking, invoking_value), (found_method, method_value) = _access_control_arg_values(event)
    if not found_invoking and not found_method:
        return None

    symbol, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return None
    if not symbol and invoking_uid:
        symbol = _object_by_uid(invoking_uid)
    return (symbol or invoking_uid, method_name)


def _access_control_combo_key_for_state(state: State, event: Event) -> tuple[str, str] | None:
    combo_key = _access_control_combo_key(event)
    (found_invoking, invoking_value), (found_method, method_value) = _access_control_arg_values(event)
    if not found_invoking or not found_method:
        return combo_key
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return combo_key
    _, invoking_uid = _object_ref_from_value(invoking_value)
    raw_invoking_uid = _clean_uid(invoking_value)
    uid_key = invoking_uid or raw_invoking_uid
    if uid_key and (
        uid_key in state.created_tables
        or uid_key in state.created_table_descriptor_uids
        or uid_key in state.created_table_row_values_by_uid
    ):
        return (uid_key, method_name)
    return combo_key


def _event_method_combo_key(event: Event) -> tuple[str, str]:
    return (event.invoking_symbol or event.invoking_uid, event.method)


def _access_control_target_sp(symbol: str, uid: str, state: State) -> str | None:
    target = Event(raw={}, kind="method", method="", invoking_symbol=symbol, invoking_uid=uid)
    return _expected_object_sp(target, state)


META_ACL_METHOD_NAMES = {"AddACE", "RemoveACE", "GetACL", "DeleteMethod"}

SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS = {
    "Table",
    "SPInfo",
    "SPTemplatesTable",
    "ColumnTable",
    "TypeTable",
    "TemplateTable",
    "MethodIDTable",
    "AccessControlTable",
    "ACETable",
    "AuthorityTable",
    "C_PINTable",
    "SecretProtectTable",
    "SPTable",
    "K_AES_128Table",
    "K_AES_256Table",
    "Table_SPTemplates",
    "Table_Column",
    "Table_Type",
    "Table_Template",
    "Table_MethodID",
    "Table_AccessControl",
    "Table_ACE",
    "Table_Authority",
    "Table_C_PIN",
    "Table_SecretProtect",
    "Table_SP",
    "Table_K_AES_128",
    "Table_K_AES_256",
}

TABLE_LEVEL_GET_ASSOCIATION_DENY = {
    "LockingTable",
    "K_AES_128Table",
    "K_AES_256Table",
}

TABLE_LEVEL_NEXT_ASSOCIATION_DENY = {"K_AES_128Table", "K_AES_256Table"}

LOCKING_TABLE_ACCESSCONTROL_TABLE_SYMBOLS = {"LockingTable", "Table_Locking"}

LOCKING_TABLE_METHOD_ASSOCIATION_DENY = {"Set", "CreateRow", "DeleteRow", "GetFreeRows"}


def _method_combo_deleted(state: State, event: Event) -> bool:
    if _event_method_combo_key(event) in state.deleted_method_associations:
        return True
    if not event.invoking_uid:
        return False
    uid_key = (event.invoking_uid, event.method)
    return uid_key in state.deleted_method_associations


def _combo_exists_for_get_acl(state: State, event: Event) -> bool | None:
    combo_key = _access_control_combo_key_for_state(state, event)
    (found_invoking, invoking_value), (found_method, method_value) = _access_control_arg_values(event)
    if not found_invoking and not found_method:
        return None

    symbol, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    method_name = _method_ref_name(method_value)
    if method_name is None:
        return None
    if combo_key in state.deleted_method_associations:
        return False
    if _created_object_outside_session(state, invoking_uid):
        return False
    if method_name in META_ACL_METHOD_NAMES:
        return False
    if invoking_uid in state.created_tables:
        return method_name in {"Next", "Get", "Set"}
    if invoking_uid in state.created_table_descriptor_uids:
        return method_name == "Get"
    if invoking_uid in state.created_table_row_values_by_uid:
        return method_name in {"Get", "Set", "Delete"}
    if method_name == "SPTemplatesObj":
        return state.session.sp == "LockingSP" and (symbol.startswith("SPTemplates_") or invoking_uid.startswith("00000003"))
    if method_name == "MethodIDObj":
        return state.session.sp == "LockingSP" and (_method_by_uid(invoking_uid) is not None or _method_ref_name(invoking_value) in set(METHOD_UIDS.values()))
    range_backed_exists = _range_backed_access_control_object_exists(state, symbol)
    if range_backed_exists is False:
        return False
    user_object_exists = _locking_sp_user_object_support_state(state, symbol)
    if user_object_exists is False:
        return False
    if not _known_opal_object_symbol(symbol, invoking_uid):
        return False
    target_sp = _access_control_target_sp(symbol, invoking_uid, state)
    if target_sp is not None and state.session.sp is not None and target_sp != state.session.sp:
        return False
    if method_name == "Next":
        if symbol in TABLE_LEVEL_NEXT_ASSOCIATION_DENY:
            return False
        return _is_next_table_target(symbol, invoking_uid)
    if symbol in LOCKING_TABLE_ACCESSCONTROL_TABLE_SYMBOLS and method_name in LOCKING_TABLE_METHOD_ASSOCIATION_DENY:
        return False
    if method_name == "Get":
        if symbol in TABLE_LEVEL_GET_ASSOCIATION_DENY:
            return False
        if state.session.sp == "LockingSP" and (symbol.startswith("SPTemplates_") or symbol.startswith("MethodID_")):
            return False
        return not symbol.startswith("UnknownSP_")
    if method_name == "Set":
        if symbol.startswith("K_AES_") or symbol in {"LockingInfo", "MethodIDTable", "Table_MethodID"}:
            return False
        if symbol in SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS:
            return False
        return not symbol.startswith("UnknownSP_")
    if method_name == "CreateRow":
        if symbol in SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS:
            return False
        return _is_table_symbol(symbol) and symbol not in {"MBR", "DataStore", "MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}
    if method_name == "DeleteRow":
        if symbol in SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS:
            return False
        return _is_table_symbol(symbol) and symbol not in {"MBR", "DataStore", "MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}
    if method_name in {"GetFreeSpace", "CreateTable", "DeleteSP"}:
        return symbol == "ThisSP"
    if method_name == "GetFreeRows":
        if symbol in SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS:
            return False
        return _is_table_symbol(symbol) and not _is_byte_table_symbol(symbol)
    if method_name in {"AddACE", "RemoveACE", "SetACL"}:
        return symbol in {"AccessControlTable", "Table_AccessControl", "AccessControl"}
    if method_name == "GenKey":
        range_id = _range_id_from_key(symbol)
        return range_id is not None and _range_id_support_state(state, range_id) is not False
    if method_name in {"GetPackage", "SetPackage"}:
        return _is_credential_symbol(symbol)
    if method_name == "Erase":
        range_id = _range_id_from_symbol(symbol)
        return range_id is not None and range_id != 0
    if method_name == "Sign":
        return symbol == "TPerSign"
    if method_name == "FirmwareAttestation":
        return symbol == "TperAttestation"
    if method_name == "Activate":
        return symbol == "LockingSP" and state.session.sp == "AdminSP"
    if method_name == "Revert":
        return symbol in {"AdminSP", "ThisSP"} and state.session.sp == "AdminSP"
    if method_name == "RevertSP":
        if state.session.sp == "AdminSP":
            return symbol == "ThisSP"
        return symbol == "ThisSP" and state.session.sp == "LockingSP"
    if method_name in {"Authenticate", "Random"}:
        return symbol == "ThisSP"
    if method_name in {"GetACL", "AddACE", "RemoveACE", "SetACL"}:
        return method_name in SUPPORTED_METHODS_BY_SP.get(state.session.sp or "", set())
    return False




def _matching_range(state: State, lba: tuple[int, int] | None) -> RangeState:
    if lba is None:
        return _range(state, 0)
    start, end = lba
    best: RangeState | None = None
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if start >= r_start and end <= r_end:
            if best is None or range_state.range_length < best.range_length:
                best = range_state
    return best or _range(state, 0)


def _effective_ranges_for_lba(state: State, lba: tuple[int, int] | None) -> list[RangeState]:
    if lba is None:
        return [_range(state, 0)]
    start, end = lba
    overlaps: list[tuple[int, int, RangeState]] = []
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if end < r_start or start > r_end:
            continue
        overlaps.append((max(start, r_start), min(end, r_end), range_state))

    if not overlaps:
        return [_range(state, 0)]

    overlaps.sort(key=lambda item: (item[0], item[1], item[2].range_id))
    ranges: list[RangeState] = []
    seen: set[int] = set()
    for _, _, range_state in overlaps:
        if range_state.range_id not in seen:
            ranges.append(range_state)
            seen.add(range_state.range_id)

    cursor = start
    uncovered = False
    for covered_start, covered_end, _ in overlaps:
        if cursor < covered_start:
            uncovered = True
            break
        cursor = max(cursor, covered_end + 1)
        if cursor > end:
            break
    if cursor <= end:
        uncovered = True
    if uncovered:
        global_range = _range(state, 0)
        if global_range.range_id not in seen:
            ranges.append(global_range)
    return ranges


def _range_segments_for_lba(state: State, lba: tuple[int, int] | None) -> list[tuple[int, int, RangeState]]:
    if lba is None:
        return []
    start, end = lba
    overlaps: list[tuple[int, int, RangeState]] = []
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if end < r_start or start > r_end:
            continue
        overlaps.append((max(start, r_start), min(end, r_end), range_state))

    global_range = _range(state, 0)
    if not overlaps:
        return [(start, end, global_range)]

    overlaps.sort(key=lambda item: (item[0], item[1], item[2].range_id))
    segments: list[tuple[int, int, RangeState]] = []
    cursor = start
    for covered_start, covered_end, range_state in overlaps:
        if cursor < covered_start:
            segments.append((cursor, covered_start - 1, global_range))
        if covered_end >= cursor:
            segments.append((max(cursor, covered_start), covered_end, range_state))
            cursor = covered_end + 1
        if cursor > end:
            break
    if cursor <= end:
        segments.append((cursor, end, global_range))
    return segments


def _range_crossing_error_allowed(state: State, lba: tuple[int, int] | None) -> bool:
    return len(_effective_ranges_for_lba(state, lba)) > 1


def _any_read_locked(state: State, lba: tuple[int, int] | None) -> bool:
    return any(_read_locked(range_state) for range_state in _effective_ranges_for_lba(state, lba))


def _any_write_locked(state: State, lba: tuple[int, int] | None) -> bool:
    return any(_write_locked(range_state) for range_state in _effective_ranges_for_lba(state, lba))


def _read_locked(range_state: RangeState) -> bool:
    return range_state.read_lock_enabled and range_state.read_locked


def _write_locked(range_state: RangeState) -> bool:
    return range_state.write_lock_enabled and range_state.write_locked


def _mbr_shadowing_active(state: State) -> bool:
    return _as_bool(state.mbr.get("Enabled")) and not _as_bool(state.mbr.get("Done"))


def _mbr_shadow_lba_count(state: State) -> int:
    logical_block_size = _parse_int(state.locking_info.get("LogicalBlockSize")) or DEFAULT_LOGICAL_BLOCK_SIZE
    if logical_block_size <= 0:
        logical_block_size = DEFAULT_LOGICAL_BLOCK_SIZE
    table_bytes = state.byte_table_rows.get("MBR", DEFAULT_MBR_SHADOW_BYTES)
    table_bytes = max(DEFAULT_MBR_SHADOW_BYTES, table_bytes)
    return max(1, (table_bytes + logical_block_size - 1) // logical_block_size)


def _mbr_shadow_relation(state: State, lba: tuple[int, int] | None) -> str:
    if not _mbr_shadowing_active(state) or lba is None:
        return "none"
    start, end = lba
    mbr_shadow_lba_count = _mbr_shadow_lba_count(state)
    start_in = 0 <= start < mbr_shadow_lba_count
    end_in = 0 <= end < mbr_shadow_lba_count
    if start_in and end_in:
        return "within"
    if start_in or end_in or start < mbr_shadow_lba_count <= end:
        return "partial"
    return "outside"


def _remembered_pattern_for_lba(state: State, lba: tuple[int, int] | None) -> tuple[str, int, int] | None:
    if lba is None:
        return None
    exact = state.lba_patterns.get(lba)
    if exact is not None:
        return exact
    start, end = lba
    best: tuple[int, tuple[str, int, int]] | None = None
    for (written_start, written_end), remembered in state.lba_patterns.items():
        if written_start <= start and end <= written_end:
            span = written_end - written_start
            if best is None or span < best[0]:
                best = (span, remembered)
    return best[1] if best is not None else None


def _remembered_pattern_analysis_for_lba(state: State, lba: tuple[int, int] | None) -> dict[str, Any] | None:
    if lba is None:
        return None
    start, end = lba
    cursor = start
    segments: list[tuple[int, int, str, int, int]] = []
    while cursor <= end:
        candidates: list[tuple[int, int, int, tuple[str, int, int]]] = []
        for (written_start, written_end), remembered in state.lba_patterns.items():
            if written_start <= cursor <= written_end:
                candidates.append((written_end - written_start, -written_start, written_end, remembered))
        if not candidates:
            break
        _, _, written_end, remembered = min(candidates, key=lambda item: (item[0], item[1], item[2]))
        pattern, range_id, generation = remembered
        segment_end = min(end, written_end)
        segments.append((cursor, segment_end, pattern, range_id, generation))
        cursor = segment_end + 1

    if not segments:
        return None

    patterns = {pattern for _, _, pattern, _, _ in segments}
    stale = False
    for _, _, _, range_id, generation in segments:
        if generation != _range(state, range_id).media_generation:
            stale = True
            break
    return {
        "complete": cursor > end,
        "pattern": next(iter(patterns)) if len(patterns) == 1 else None,
        "stale": stale,
    }

__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
