"""Parsing, normalization, and TCGstorageAPI log decoding helpers."""

from __future__ import annotations

import ast
import re
from typing import Any

from .constants import *
from .models import *


def _clean_uid(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "0000000000000001" if value else "0000000000000000"
    if isinstance(value, int):
        return f"{value & ((1 << 64) - 1):016X}"
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            decoded = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            decoded = ""
        if decoded and re.fullmatch(r"(?:0x)?[0-9A-Fa-f\s:_-]+", decoded):
            cleaned = re.sub(r"[^0-9A-Fa-f]", "", decoded).upper()
            if cleaned:
                return cleaned.zfill(16)[-16:]
        return raw.hex().upper().zfill(16)[-16:]
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    if not cleaned:
        return ""
    return cleaned.zfill(16)[-16:]


def _as_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return str(value)
    return str(value)


def _credential_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("plainText", "PlainText", "plaintext", "PIN", "pin", "Proof", "proof", "HostChallenge", "Challenge", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _credential_text(item)
        if len(value) == 1:
            return _credential_text(next(iter(value.values())))
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _credential_text(value[0])
    return _as_text(value)


def _credential_length(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, dict):
        for key in ("plainText", "PlainText", "plaintext", "PIN", "pin", "Proof", "proof", "HostChallenge", "Challenge", "value", "Value"):
            found, item = _dict_lookup(value, key)
            if found:
                return _credential_length(item)
        if len(value) == 1:
            return _credential_length(next(iter(value.values())))
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _credential_length(value[0])
    return len(_credential_text(value).encode("utf-8"))


def _uid_suffix_index(uid: str, prefix: str) -> int | None:
    if not uid.startswith(prefix) or len(uid) <= len(prefix):
        return None
    suffix = uid[len(prefix):]
    if not re.fullmatch(r"[0-9A-F]+", suffix):
        return None
    value = int(suffix, 16)
    return value or None


def _tcgstorageapi_numbered_index(uid: str, prefix: str) -> int | None:
    value = _uid_suffix_index(uid, prefix)
    if value is None:
        return None
    # TCGstorageAPI LookupIds uses BandMaster0 at the base UID, while many
    # Opal traces use BandMaster1 at the same UID.  Preserve both conventions.
    if value > 1:
        return value - 1
    return value


def _authority_by_uid(uid: str) -> str | None:
    if not uid:
        return None
    if uid in FIXED_AUTH_BY_UID:
        return FIXED_AUTH_BY_UID[uid]

    admin_index = _uid_suffix_index(uid, "000000090001")
    if admin_index is not None and uid != "000000090001FF01":
        return f"Admin{admin_index}"

    admin_sp_index = _uid_suffix_index(uid, "00000009000002")
    if admin_sp_index is not None:
        return f"Admin{admin_sp_index}"

    user_index = _uid_suffix_index(uid, "000000090003")
    if user_index is not None:
        return f"User{user_index}"

    band_master_index = _tcgstorageapi_numbered_index(uid, "00000009000080")
    if band_master_index is not None:
        return f"BandMaster{band_master_index}"

    return None


def _sp_by_uid(uid: str) -> str | None:
    return FIXED_SP_BY_UID.get(uid)


def _sp_by_name(value: Any) -> str | None:
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if text in {"ADMINSP", "ADMIN"}:
        return "AdminSP"
    if text in {"LOCKINGSP", "LOCKING"}:
        return "LockingSP"
    return None


def _sp_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("uid", "UID", "spid", "SPID"):
            sp = _sp_by_uid(_clean_uid(_mapping_value(value, key)))
            if sp is not None:
                return sp
        for key in ("name", "Name"):
            sp = _sp_by_name(_mapping_value(value, key))
            if sp is not None:
                return sp
        for item in value.values():
            sp = _sp_from_value(item)
            if sp is not None:
                return sp
        return None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            sp = _sp_from_value(item)
            if sp is not None:
                return sp
        return None
    return _sp_by_uid(_clean_uid(value)) or _sp_by_name(value)


def _authority_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        name_authority = None
        for key in ("name", "Name"):
            name_authority = _authority_by_name(_mapping_value(value, key))
            if name_authority is not None:
                break
        for key in ("uid", "UID", "authority", "Authority", "HostSigningAuthority"):
            uid = _clean_uid(_mapping_value(value, key))
            if name_authority and name_authority.startswith("BandMaster") and uid.startswith("00000009000080"):
                return name_authority
            authority = _authority_by_uid(uid)
            if authority is not None:
                return authority
        if name_authority is not None:
            return name_authority
        for item in value.values():
            authority = _authority_from_value(item)
            if authority is not None:
                return authority
        return None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            authority = _authority_from_value(item)
            if authority is not None:
                return authority
        return None
    return _authority_by_uid(_clean_uid(value)) or _authority_by_name(value)


def _method_by_uid(uid: str) -> str | None:
    return METHOD_UIDS.get(uid)


ACCESS_CONTROL_INVOKING_ARG_NAMES = (
    "InvokingID",
    "InvokingId",
    "invoking_id",
    "invokingId",
    "InvokingUID",
    "InvokingUid",
    "invoking_uid",
    "invokingUid",
    "InvokingObject",
    "invokingObject",
    "InvokingObjectID",
    "InvokingObjectId",
    "invoking_object_id",
    "invokingObjectId",
    "InvokingObjectUID",
    "InvokingObjectUid",
    "invoking_object_uid",
    "invokingObjectUid",
    "Object",
    "object",
    "ObjectID",
    "ObjectId",
    "object_id",
    "objectId",
    "ObjectUID",
    "ObjectUid",
    "object_uid",
    "objectUid",
    "Table",
    "table",
    "TableUID",
    "TableUid",
    "table_uid",
    "tableUid",
    "Target",
    "target",
    "TargetID",
    "TargetId",
    "target_id",
    "targetId",
    "TargetUID",
    "TargetUid",
    "target_uid",
    "targetUid",
    "Obj",
    "obj",
    "UID",
    "uid",
)

ACCESS_CONTROL_METHOD_ARG_NAMES = (
    "MethodID",
    "MethodId",
    "method_id",
    "methodId",
    "MethodUID",
    "MethodUid",
    "method_uid",
    "methodUid",
    "Method",
    "method",
    "MethodName",
    "method_name",
    "methodName",
    "Operation",
    "operation",
    "OperationID",
    "OperationId",
    "operation_id",
    "operationId",
    "OperationUID",
    "OperationUid",
    "operation_uid",
    "operationUid",
    "OperationName",
    "operation_name",
    "operationName",
    "Op",
    "op",
    "Action",
    "action",
    "ActionID",
    "ActionId",
    "action_id",
    "actionId",
    "ActionUID",
    "ActionUid",
    "action_uid",
    "actionUid",
    "ActionName",
    "action_name",
    "actionName",
)


def _tcgstorageapi_cpin_alias_by_uid(uid: str) -> str | None:
    aliases = {
        "0000000900000001": "C_PIN_SID",
        "0000000900008401": "C_PIN_EraseMaster",
    }
    alias = aliases.get(uid)
    if alias is not None:
        return alias
    band_master_index = _tcgstorageapi_numbered_index(uid, "00000009000080")
    if band_master_index is not None:
        return f"C_PIN_BandMaster{band_master_index}"
    return None


def _object_by_uid(uid: str, fallback_name: str = "") -> str:
    if not uid:
        return _normalize_name(fallback_name)
    normalized = _normalize_name(fallback_name)
    if normalized.startswith("C_PIN_"):
        if re.fullmatch(r"C_PIN_BandMaster\d+", normalized):
            return normalized
        alias = _tcgstorageapi_cpin_alias_by_uid(uid)
        if alias is not None:
            return alias
    if normalized.startswith("Authority_"):
        return normalized
    if uid in FIXED_OBJECT_BY_UID:
        return FIXED_OBJECT_BY_UID[uid]

    method = _method_by_uid(uid)
    if method is not None:
        return f"MethodID_{method}"

    authority = _authority_by_uid(uid)
    if authority is not None:
        return f"Authority_{authority}"

    admin_pin_index = _uid_suffix_index(uid, "0000000B0001")
    if admin_pin_index is not None:
        return f"C_PIN_Admin{admin_pin_index}"

    admin_sp_pin_index = _uid_suffix_index(uid, "0000000B000002")
    if admin_sp_pin_index is not None:
        return f"C_PIN_Admin{admin_sp_pin_index}"

    user_pin_index = _uid_suffix_index(uid, "0000000B0003")
    if user_pin_index is not None:
        return f"C_PIN_User{user_pin_index}"

    band_master_pin_index = _tcgstorageapi_numbered_index(uid, "0000000B000080")
    if band_master_pin_index is not None:
        return f"C_PIN_BandMaster{band_master_pin_index}"

    locking_range_index = _uid_suffix_index(uid, "000008020003")
    if locking_range_index is not None:
        return f"Locking_Range{locking_range_index}"

    enterprise_locking_range_index = _uid_suffix_index(uid, "000008020000")
    if enterprise_locking_range_index is not None and enterprise_locking_range_index > 1:
        return f"Locking_Range{enterprise_locking_range_index - 1}"

    key_128_index = _uid_suffix_index(uid, "000008050003")
    if key_128_index is not None:
        return f"K_AES_128_Range{key_128_index}_Key"

    key_256_index = _uid_suffix_index(uid, "000008060003")
    if key_256_index is not None:
        return f"K_AES_256_Range{key_256_index}_Key"

    data_store_index = _uid_suffix_index(uid, "000010010000")
    if data_store_index is not None:
        return f"DataStore{data_store_index}"

    data_store_index = _uid_suffix_index(uid, "000080010000")
    if data_store_index is not None:
        return f"DataStore{data_store_index}"

    sp_templates_index = _uid_suffix_index(uid, "000000030000")
    if sp_templates_index is not None:
        return f"SPTemplates_{sp_templates_index}"

    secret_protect_index = _uid_suffix_index(uid, "0000001D000000")
    if secret_protect_index is not None:
        return f"SecretProtect_{secret_protect_index}"

    template_index = _uid_suffix_index(uid, "000002040000")
    if template_index is not None:
        return f"Template_{template_index}"

    tls_psk_index = _uid_suffix_index(uid, "0000001E000000")
    if tls_psk_index is not None:
        return f"TLS_PSK_Key{tls_psk_index - 1}"

    port_index = _uid_suffix_index(uid, "000100020001")
    if port_index is not None:
        return f"Port{port_index}"

    port_index = _uid_suffix_index(uid, "000100020000")
    if port_index is not None:
        return f"Port{port_index}"

    access_control_index = _uid_suffix_index(uid, "0000000700")
    if access_control_index is not None:
        return f"AccessControl_{uid[-8:]}"

    ace_index = _uid_suffix_index(uid, "0000000800")
    if ace_index is not None:
        if normalized.startswith("ACE_DataStore"):
            return normalized
        return f"ACE_{uid[-8:]}"

    if normalized == "SP":
        return f"UnknownSP_{uid}"
    return normalized


def _normalize_name(name: Any) -> str:
    text = _as_text(name or "").strip()
    if not text:
        return ""
    compact = text.replace(" ", "")
    match = re.fullmatch(r"Band(\d+)", compact, flags=re.IGNORECASE)
    if match:
        range_id = int(match.group(1))
        return "Locking_GlobalRange" if range_id == 0 else f"Locking_Range{range_id}"
    if re.fullmatch(r"(?:Locking_?)?GlobalRange", compact, flags=re.IGNORECASE):
        return "Locking_GlobalRange"
    match = re.fullmatch(r"(?:Locking_?)?Range(\d+)", compact, flags=re.IGNORECASE)
    if match:
        range_id = int(match.group(1))
        return "Locking_GlobalRange" if range_id == 0 else f"Locking_Range{range_id}"
    match = re.fullmatch(r"ACE_Locking_Range(\d+)_Set_RdLocked", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xE000 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_Locking_Range(\d+)_Set_WrLocked", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xE800 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_Locking_Range(\d+)_Get_RangeStartToActiveKey", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xD000 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_K_AES_(128|256)_Range(\d+)_GenKey", compact, flags=re.IGNORECASE)
    if match:
        base = 0xB000 if match.group(1) == "128" else 0xB800
        return f"ACE_0003{base + int(match.group(2)):04X}"
    match = re.fullmatch(r"ACE_C_PIN_User(\d+)_Set_PIN", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_0003{0xA800 + int(match.group(1)):04X}"
    match = re.fullmatch(r"ACE_User(\d+)_Set_CommonName", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_{0x00044000 + int(match.group(1)):08X}"
    match = re.fullmatch(r"ACE_DataStore(\d*)_(Get|Set)_All", compact, flags=re.IGNORECASE)
    if match:
        index = int(match.group(1) or "1")
        if index == 1:
            return "ACE_0003FC00" if match.group(2).lower() == "get" else "ACE_0003FC01"
        return f"ACE_DataStore{index}_{match.group(2).title()}_All"
    match = re.fullmatch(r"ACE_([0-9A-Fa-f]{8})", compact, flags=re.IGNORECASE)
    if match:
        return f"ACE_{match.group(1).upper()}"
    match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key(?:_UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_Range{int(match.group(2))}_Key"
    match = re.fullmatch(r"K_AES_(128|256)_GlobalRange_Key(?:_UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_GlobalRange_Key"
    match = re.fullmatch(r"K_?AES_?(128|256)_?Range(\d+)_?Key(?:_?UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_Range{int(match.group(2))}_Key"
    match = re.fullmatch(r"K_?AES_?(128|256)_?GlobalRange_?Key(?:_?UID)?", compact, flags=re.IGNORECASE)
    if match:
        return f"K_AES_{match.group(1)}_GlobalRange_Key"
    match = re.fullmatch(r"(?:Table_?)?C_?EC_?(160|163|192|224|233|283|384|521)(?:Table)?", compact, flags=re.IGNORECASE)
    if match:
        return f"C_EC_{match.group(1)}Table"
    match = re.fullmatch(r"Port(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"Port{int(match.group(1))}"
    key = compact.upper()
    if key == "MSID":
        return "C_PIN_MSID"
    if key == "SID":
        return "C_PIN_SID"
    if key == "ERASEMASTER":
        return "C_PIN_EraseMaster"
    if key == "TPERSIGN":
        return "TPerSign"
    if key == "TPERATTESTATION":
        return "TperAttestation"
    if key == "_CERTDATA_TPERSIGN":
        return "_CertData_TPerSign"
    if key == "_CERTDATA_TPERATTESTATION":
        return "_CertData_TPerAttestation"
    match = re.fullmatch(r"C_?PIN_?(SID|MSID|EraseMaster)", compact, flags=re.IGNORECASE)
    if match:
        suffix = match.group(1)
        if suffix.upper() == "SID":
            return "C_PIN_SID"
        if suffix.upper() == "MSID":
            return "C_PIN_MSID"
        return "C_PIN_EraseMaster"
    match = re.fullmatch(r"C_?PIN_?(Admin|User|BandMaster)(\d+)", compact, flags=re.IGNORECASE)
    if match:
        family = match.group(1).title()
        if family == "Bandmaster":
            family = "BandMaster"
        return f"C_PIN_{family}{int(match.group(2))}"
    match = re.fullmatch(r"Authority_?(SID|MSID|PSID|EraseMaster|Admins|Users|Makers)", compact, flags=re.IGNORECASE)
    if match:
        authority = _authority_by_name(match.group(1))
        return f"Authority_{authority}" if authority is not None else compact
    match = re.fullmatch(r"Authority_?(Admin|User|BandMaster)(\d+)", compact, flags=re.IGNORECASE)
    if match:
        family = match.group(1).title()
        if family == "Bandmaster":
            family = "BandMaster"
        return f"Authority_{family}{int(match.group(2))}"
    match = re.fullmatch(r"TLS_?PSK_?Key(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"TLS_PSK_Key{int(match.group(1))}"
    match = re.fullmatch(r"BandMaster(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"C_PIN_BandMaster{int(match.group(1))}"
    match = re.fullmatch(r"Admin(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"C_PIN_Admin{int(match.group(1))}"
    match = re.fullmatch(r"User(\d+)", compact, flags=re.IGNORECASE)
    if match:
        return f"Authority_User{int(match.group(1))}"
    aliases = {
        "SESSIONMANAGERUID": "SessionManager",
        "SMUID": "SessionManager",
        "LOCKING": "LockingTable",
        "C_PIN": "C_PINTable",
        "CPIN": "C_PINTable",
        "AUTHORITY": "AuthorityTable",
        "ACE": "ACETable",
        "ACCESSCONTROL": "AccessControlTable",
        "COLUMN": "ColumnTable",
        "TYPE": "TypeTable",
        "METHODID": "MethodIDTable",
        "SPTEMPLATES": "SPTemplatesTable",
        "TEMPLATE": "TemplateTable",
        "SP": "SPTable",
        "K_AES_256": "K_AES_256Table",
        "KAES256": "K_AES_256Table",
        "K_AES_128": "K_AES_128Table",
        "KAES128": "K_AES_128Table",
    }
    return aliases.get(compact.upper(), compact)


def _pin_owner_by_object(symbol: str) -> str | None:
    if symbol == "C_PIN_SID":
        return "SID"
    if symbol == "C_PIN_MSID":
        return "MSID"
    if symbol == "C_PIN_EraseMaster":
        return "EraseMaster"
    match = re.fullmatch(r"C_PIN_BandMaster(\d+)", symbol)
    if match:
        return f"BandMaster{int(match.group(1))}"
    match = re.fullmatch(r"C_PIN_(Admin|User)(\d+)", symbol)
    if match:
        return f"{match.group(1)}{int(match.group(2))}"
    return None


def _authority_from_cpin_name(name: Any) -> str | None:
    text = _as_text(name or "").strip()
    match = re.fullmatch(r"C_PIN_(Admin|User|BandMaster)(\d+)", text, flags=re.IGNORECASE)
    if match:
        family = match.group(1).title()
        if family == "Bandmaster":
            family = "BandMaster"
        return f"{family}{int(match.group(2))}"
    if re.fullmatch(r"C_PIN_EraseMaster", text, flags=re.IGNORECASE):
        return "EraseMaster"
    return None


def _authority_by_object(symbol: str) -> str | None:
    if symbol.startswith("Authority_"):
        return symbol.removeprefix("Authority_")
    return None


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


def _range_id_from_symbol(symbol: str) -> int | None:
    if symbol == "Locking_GlobalRange":
        return 0
    match = re.fullmatch(r"Locking_Range(\d+)", symbol)
    if match:
        return int(match.group(1))
    return None


def _band_target_from_range_value(value: Any) -> str:
    if isinstance(value, dict):
        nested = _mapping_value(
            value,
            "rangeNo",
            "range",
            "Range",
            "range_no",
            "rangeID",
            "rangeId",
            "range_id",
            "band",
            "Band",
            "bandID",
            "bandId",
            "band_id",
            "bandName",
            "band_name",
            "id",
            "ID",
            "uid",
            "UID",
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "target",
            "Target",
            "operationRequest",
            "OperationRequest",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "rangeValues",
            "RangeValues",
            "geometry",
            "Geometry",
            "window",
            "Window",
            "reset",
            "Reset",
            "resetPolicy",
            "ResetPolicy",
            "reset_policy",
            "types",
            "Types",
            "selection",
            "Selection",
        )
        if nested is not None and nested is not value:
            return _band_target_from_range_value(nested)
    parsed_range = _parse_int(value)
    if parsed_range is None:
        parsed_range = _range_id_from_symbol(_normalize_name(value))
    return f"Band{parsed_range if parsed_range is not None else value}"


def _range_id_from_key(symbol: str) -> int | None:
    if re.fullmatch(r"K_AES_(128|256)_GlobalRange_Key", symbol):
        return 0
    match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key", symbol)
    if match:
        return int(match.group(2))
    return None


def _is_table_symbol(symbol: str) -> bool:
    return symbol in {
        "Table",
        "MethodIDTable",
        "AccessControlTable",
        "ACETable",
        "AuthorityTable",
        "C_PINTable",
        "SecretProtectTable",
        "LockingTable",
        "SPTemplatesTable",
        "TemplateTable",
        "SPTable",
        "K_AES_128Table",
        "K_AES_256Table",
        "MBR",
        "DataStore",
    } or symbol.startswith("Table_") or symbol.endswith("Table")


def _is_next_table_target(symbol: str, uid: str) -> bool:
    if _is_byte_table_symbol(symbol) or _is_byte_table_uid(uid):
        return False
    if _is_table_symbol(symbol):
        return True
    return bool(uid and uid.endswith("00000000"))


def _method_ref_name(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in (
            "uid",
            "UID",
            "method",
            "Method",
            "method_id",
            "methodId",
            "MethodID",
            "MethodId",
            "method_uid",
            "methodUid",
            "MethodUID",
            "MethodUid",
            "operation",
            "Operation",
            "operation_id",
            "operationId",
            "OperationID",
            "OperationId",
            "operation_uid",
            "operationUid",
            "OperationUID",
            "OperationUid",
            "operation_name",
            "operationName",
            "OperationName",
            "op",
            "Op",
            "action",
            "Action",
            "action_id",
            "actionId",
            "ActionID",
            "ActionId",
            "action_uid",
            "actionUid",
            "ActionUID",
            "ActionUid",
            "action_name",
            "actionName",
            "ActionName",
        ):
            method = _method_ref_name(_mapping_value(value, key))
            if method is not None:
                return method
        for key in ("name", "Name", "method_name", "methodName", "MethodName"):
            method = _method_ref_name(_mapping_value(value, key))
            if method is not None:
                return method
        return None
    if isinstance(value, (list, tuple, set)) and len(value) == 1:
        return _method_ref_name(next(iter(value)))
    uid = _clean_uid(value)
    if uid:
        method = _method_by_uid(uid)
        if method is not None:
            return method
    text = _as_text(value or "").strip()
    if not text:
        return None
    normalized = re.sub(r"[^A-Za-z0-9_]", "", text)
    match = re.fullmatch(r"MethodID_(.+)", normalized, flags=re.IGNORECASE)
    if match:
        normalized = match.group(1)
    method_key = re.sub(r"[^A-Za-z0-9]", "", normalized).upper()
    for method in set(METHOD_UIDS.values()) | set().union(*SUPPORTED_METHODS_BY_SP.values()):
        if re.sub(r"[^A-Za-z0-9]", "", method).upper() == method_key:
            return method
    return normalized


def _normalize_status(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) <= 8 and any(byte < 0x20 or byte > 0x7E for byte in raw):
            return _normalize_status(int.from_bytes(raw, "big"))
    if isinstance(value, int) and not isinstance(value, bool):
        numeric = {
            0x00: SUCCESS,
            0x01: NOT_AUTHORIZED,
            0x03: FAIL,
            0x04: FAIL,
            0x05: FAIL,
            0x06: FAIL,
            0x07: FAIL,
            0x08: INVALID_PARAMETER,
            0x09: INSUFFICIENT_SPACE,
            0x0A: INSUFFICIENT_ROWS,
            0x0C: INVALID_PARAMETER,
            0x0D: NOT_AUTHORIZED,
            0x0F: FAIL,
            0x10: FAIL,
            0x11: FAIL,
            0x12: NOT_AUTHORIZED,
            0x3F: FAIL,
            0x40: FAIL,
            0x41: FAIL,
            0x42: FAIL,
        }
        return numeric.get(value, FAIL)
    text = _as_text(value).strip()
    if not text:
        return None
    key = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    if re.fullmatch(r"0X[0-9A-F]+", key):
        return _normalize_status(int(key[2:], 16))
    aliases = {
        "SUCCESS": SUCCESS,
        "SUCCESSCODE": SUCCESS,
        "OK": SUCCESS,
        "TRUE": SUCCESS,
        "PASSED": SUCCESS,
        "SUCCEEDED": SUCCESS,
        "0": SUCCESS,
        "PASS": "PASS",
        "FAIL": FAIL,
        "FALSE": FAIL,
        "NOTAUTHORIZED": NOT_AUTHORIZED,
        "1": NOT_AUTHORIZED,
        "OBSOLETE": FAIL,
        "OBSOLETECODE": FAIL,
        "2": FAIL,
        "INVALIDPARAMETER": INVALID_PARAMETER,
        "12": INVALID_PARAMETER,
        "0C": INVALID_PARAMETER,
        "13": NOT_AUTHORIZED,
        "0D": NOT_AUTHORIZED,
        "INVALIDCOMMAND": INVALID_PARAMETER,
        "INVALIDCOMMANDPARAMETER": INVALID_PARAMETER,
        "OTHERINVALIDCOMMANDPARAMETER": INVALID_PARAMETER,
        "INSUFFICIENTSPACE": INSUFFICIENT_SPACE,
        "9": INSUFFICIENT_SPACE,
        "INSUFFICIENTROWS": INSUFFICIENT_ROWS,
        "10": INSUFFICIENT_ROWS,
        "0A": INSUFFICIENT_ROWS,
        "SPBUSY": FAIL,
        "BUSY": FAIL,
        "SPFAILED": FAIL,
        "FAILED": FAIL,
        "SPDISABLED": FAIL,
        "DISABLED": FAIL,
        "SPFROZEN": FAIL,
        "FROZEN": FAIL,
        "NOSESSIONSAVAILABLE": FAIL,
        "UNIQUENESSCONFLICT": INVALID_PARAMETER,
        "TPERMALFUNCTION": FAIL,
        "TRANSACTIONFAILURE": FAIL,
        "RESPONSEOVERFLOW": FAIL,
        "AUTHORITYLOCKEDOUT": NOT_AUTHORIZED,
        "READLOCKED": FAIL,
        "READLOCK": FAIL,
        "READLOCKFAIL": FAIL,
        "READLOCKEDFAIL": FAIL,
        "WRITELOCKED": FAIL,
        "WRITELOCK": FAIL,
        "WRITELOCKFAIL": FAIL,
        "WRITELOCKEDFAIL": FAIL,
        "TIMEOUT": FAIL,
        "UNEXPECTEDRESULTS": FAIL,
        "TLSALERT": FAIL,
    }
    for prefix in ("STATUSCODE", "PYSEDSTATUSCODE", "TCGSTATUSCODE"):
        if key.startswith(prefix):
            stripped = key.removeprefix(prefix)
            if stripped in aliases:
                return aliases[stripped]
    for alias, normalized in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        if alias and alias != "0" and not re.fullmatch(r"[0-9A-F]+", alias) and alias in key:
            return normalized
    return aliases.get(key, key)


def _normalize_host_io_status(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, bool):
        return SUCCESS if value else FAIL
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    if key in {"SUCCESS", "OK", "PASS", "PASSED", "SUCCEEDED", "DONE", "ALLOWED"}:
        return SUCCESS
    if key in {"FAIL", "FAILED", "ERROR", "ERR", "REJECTED"}:
        return FAIL
    if key in {
        "LOCKED",
        "RANGELOCKED",
        "MEDIALOCKED",
        "BLOCKED",
        "READDENIED",
        "WRITEDENIED",
        "READPROTECTED",
        "WRITEPROTECTED",
    }:
        return FAIL
    if key in {"DENIED", "ACCESSDENIED", "PERMISSIONDENIED", "NOTPERMITTED", "FORBIDDEN"}:
        return NOT_AUTHORIZED
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, bytes):
        return any(value)
    text = _as_text(value).strip().lower()
    return text in {"1", "true", "t", "yes", "y", "enabled", "on"}


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if value in {0, 1}:
            return bool(value)
        return None
    if isinstance(value, bytes):
        if len(value) == 1 and value[0] in {0, 1}:
            return bool(value[0])
        return None
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if text in {"TRUE", "T", "YES", "Y", "ON", "PASS", "SUCCESS", "1"}:
        return True
    if text in {"FALSE", "F", "NO", "N", "OFF", "FAIL", "FAILED", "0"}:
        return False
    return None


def _enabled_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    text = _as_text(value).strip().lower()
    return text in {"1", "true", "t", "yes", "y", "enabled", "on"}


def _is_bool_literal(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return value in {0, 1}
    text = _as_text(value).strip().lower()
    return text in {"0", "1", "true", "false"}


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    text = _as_text(value).strip()
    if not text:
        return None
    text = text.replace(",", "")
    try:
        if re.fullmatch(r"0x[0-9A-Fa-f]+", text):
            return int(text, 16)
        if re.fullmatch(r"[0-9A-Fa-f]{2,}", text) and re.search(r"[A-Fa-f]", text):
            return int(text, 16)
        if re.fullmatch(r"0+[0-9A-Fa-f]+", text) and len(text) > 1:
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _parse_reencrypt_state(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return {
        "IDLE": 1,
        "PENDING": 2,
        "ACTIVE": 3,
        "COMPLETED": 4,
        "COMPLETE": 4,
        "PAUSED": 5,
        "PAUSE": 5,
    }.get(text)


def _parse_reencrypt_request(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return {
        "START": 1,
        "STARTREQ": 1,
        "ADVKEY": 2,
        "ADVKEYREQ": 2,
        "RETIDLE": 3,
        "RETIDLEREQ": 3,
        "CONT": 4,
        "CONTREQ": 4,
        "PAUSE": 5,
        "PAUSEREQ": 5,
    }.get(text)


def _contains_bool_token(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return True
    if isinstance(value, dict):
        return any(_contains_bool_token(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_bool_token(item) for item in value)
    return False


def _reset_types(value: Any) -> set[int]:
    if value is None or value is False or value == "" or value == [] or value == ():
        return set()
    if value is True:
        return {0}
    if isinstance(value, int):
        return {value}
    if isinstance(value, bytes):
        return {int.from_bytes(value, "big")}
    if isinstance(value, (list, tuple, set)):
        out: set[int] = set()
        for item in value:
            out.update(_reset_types(item))
        return out
    raw_text = _as_text(value or "")
    text = re.sub(r"[^A-Za-z0-9]+", "", raw_text).upper()
    named = {
        "POWERCYCLE": 0,
        "POWER": 0,
        "HARDWARERESET": 1,
        "HWRESET": 1,
        "HOTPLUG": 2,
        "HOTPLUGRESET": 2,
        "PROGRAMMATIC": 3,
        "TPERRESET": 3,
    }
    if text in named:
        return {named[text]}
    out: set[int] = set()
    if "POWERCYCLE" in text or text == "POWER":
        out.add(0)
    if "HARDWARERESET" in text or "HWRESET" in text:
        out.add(1)
    if "HOTPLUG" in text:
        out.add(2)
    if "PROGRAMMATIC" in text or "TPERRESET" in text:
        out.add(3)
    for number in re.findall(r"\d+", raw_text):
        out.add(int(number))
    if out:
        return out
    parsed = _parse_int(value)
    return {parsed} if parsed is not None else set()


def _contains_protocol_stack_reset_alias(value: Any) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(_contains_protocol_stack_reset_alias(item) for item in value)
    text = re.sub(r"[^A-Za-z0-9]+", "", _as_text(value or "")).upper()
    return text in {"PROTOCOLSTACKRESET", "STACKRESET", "TCGRESET"}


def _reset_list_invalid(value: Any) -> bool:
    if _contains_bool_token(value) or _contains_protocol_stack_reset_alias(value):
        return True
    reset_types = _reset_types(value)
    if not reset_types:
        return False
    return 0 not in reset_types or not reset_types <= {0, 1, 3}


def _reset_condition_list_invalid(value: Any) -> bool:
    if _contains_bool_token(value) or _contains_protocol_stack_reset_alias(value):
        return True
    reset_types = _reset_types(value)
    if not reset_types:
        return False
    return not reset_types <= {0, 1, 2, 3}


def _reset_event_type(method: str) -> int | None:
    text = re.sub(r"[^A-Za-z0-9]+", "", _as_text(method or "")).upper()
    if text in {"POWERCYCLE", "DOPOWERCYCLE", "POWERCYCLERESET", "DOPOWERCYCLERESET", "POWERRESET", "RESETPOWERCYCLE", "COLDRESET"}:
        return 0
    if text in {"POWERDEVICE", "POWERCYCLEDEVICE", "DEVICEPOWERCYCLE", "POWERCYCLETPER"}:
        return 0
    if text in {"HARDRESET", "HARDWARERESET", "DOHARDWARERESET", "HWRESET", "DEVICERESET", "RESETDEVICE", "PLATFORMRESET"}:
        return 1
    if text in {"HARDWARERESETDEVICE", "RESETHARDWARE"}:
        return 1
    if text in {"HOTPLUG", "HOTPLUGRESET"}:
        return 2
    if text in {"PROTOCOLSTACKRESET", "PROTOCOLRESET", "COMIDRESET", "STACKRESET", "TCGRESET"}:
        return PROTOCOL_STACK_RESET
    if text in {"RESETCOMID", "RESETPROTOCOLSTACK"}:
        return PROTOCOL_STACK_RESET
    if text in {"TPERRESET", "RESETTPER", "PROGRAMMATICRESET"}:
        return 3
    if text == "RESET":
        return 0
    return None


def _reset_method_from_payload(*sources: Any) -> str | None:
    def method_from_value(value: Any) -> str | None:
        parsed = _parse_int(value)
        if parsed == 0:
            return "PowerCycle"
        if parsed == 1:
            return "HardwareReset"
        if parsed == 2:
            return "HotPlug"
        if parsed == 3:
            return "TPerReset"
        if isinstance(value, dict):
            return method_from_mapping(value)
        text = _as_text(value)
        reset_type = _reset_event_type(text)
        if reset_type == 0:
            return "PowerCycle"
        if reset_type == 1:
            return "HardwareReset"
        if reset_type == 2:
            return "HotPlug"
        if reset_type == 3:
            return "TPerReset"
        if reset_type == PROTOCOL_STACK_RESET:
            return "ProtocolStackReset"
        return None

    def method_from_mapping(mapping: Any, depth: int = 0) -> str | None:
        if not isinstance(mapping, dict) or depth > 3:
            return None
        found, value = _dict_lookup(
            mapping,
            "resetType",
            "ResetType",
            "reset_type",
            "type",
            "Type",
            "reset",
            "Reset",
            "resetEvent",
            "ResetEvent",
            "reset_event",
            "event",
            "Event",
            "kind",
            "Kind",
            "target",
            "Target",
            "mode",
            "Mode",
        )
        if found:
            method = method_from_value(value)
            if method is not None:
                return method
        for envelope in (
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "operation",
            "Operation",
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "payload",
            "Payload",
            "target",
            "Target",
            "resetRequest",
            "ResetRequest",
            "protocolResetRequest",
            "ProtocolResetRequest",
            "comIdRequest",
            "ComIDRequest",
            "sessionRequest",
            "SessionRequest",
        ):
            nested = _mapping_value(mapping, envelope)
            if isinstance(nested, dict):
                method = method_from_mapping(nested, depth + 1)
                if method is not None:
                    return method
        return None

    for source in sources:
        method = method_from_mapping(source)
        if method is not None:
            return method
    return None


def _comid_from_value(value: Any) -> str:
    parsed = _parse_int(value)
    if parsed is not None:
        return str(parsed)
    text = _as_text(value).strip()
    return text if text else ""


def _comid_from_mapping(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    found, raw = _dict_lookup(value, "ComID", "ComId", "comID", "comid", "com_id", "ComIDRequest")
    if found:
        if isinstance(raw, dict):
            nested_comid = _comid_from_mapping(raw)
            if nested_comid:
                return nested_comid
        return _comid_from_value(raw)
    for key in (
        "kwargs",
        "KWArgs",
        "kwArgs",
        "args",
        "Args",
        "arguments",
        "Arguments",
        "params",
        "Params",
        "parameters",
        "Parameters",
        "values",
        "Values",
        "request",
        "Request",
        "policy",
        "Policy",
        "config",
        "Config",
        "resetRequest",
        "ResetRequest",
        "protocolResetRequest",
        "ProtocolResetRequest",
        "comIdRequest",
        "ComIDRequest",
        "sessionRequest",
        "SessionRequest",
    ):
        nested = _mapping_value(value, key)
        if isinstance(nested, dict):
            comid = _comid_from_mapping(nested)
            if comid:
                return comid
        elif isinstance(nested, (list, tuple)):
            found, raw = _sequence_named_arg_value(nested, "ComID", "ComId", "comID", "comid", "com_id", "ComIDRequest")
            if found:
                return _comid_from_value(raw)
    return ""


def _comid_from_event_parts(*parts: Any) -> str:
    for part in parts:
        comid = _comid_from_mapping(part)
        if comid:
            return comid
        if isinstance(part, (list, tuple)):
            found, raw = _sequence_named_arg_value(part, "ComID", "ComId", "comID", "comid", "com_id", "ComIDRequest")
            if found:
                comid = _comid_from_value(raw)
                if comid:
                    return comid
    return ""


def _sp_lifecycle_active(value: Any) -> bool | None:
    parsed = _parse_int(value)
    if parsed is not None:
        if parsed == 8:
            return False
        if parsed >= 9:
            return True
        return None
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    if not text:
        return None
    if "INACTIVE" in text or text in {"MANUFACTUREDINACTIVE", "MFGINACTIVE"}:
        return False
    if text in {"MANUFACTURED", "ACTIVE", "ISSUED"} or "ISSUED" in text:
        return True
    return None


def _dict_lookup(mapping: Any, *names: Any) -> tuple[bool, Any]:
    if not isinstance(mapping, dict):
        return False, None
    wanted = {_as_text(name).strip().lower() for name in names}
    for key, value in mapping.items():
        if _as_text(key).strip().lower() in wanted:
            return True, value
    return False, None


def _mapping_value(mapping: Any, *names: Any, default: Any = None) -> Any:
    found, value = _dict_lookup(mapping, *names)
    return value if found else default


def _mapping_section(mapping: Any, *names: Any) -> dict[str, Any]:
    value = _mapping_value(mapping, *names)
    return value if isinstance(value, dict) else {}


def _input_section(raw: dict[str, Any]) -> dict[str, Any]:
    section = _mapping_section(raw, "input", "Input")
    if section:
        if len(section) == 1:
            nested = _mapping_section(section, "call", "Call", "request", "Request", "api", "API")
            if nested and _function_name(nested):
                return nested
        return section
    if len(raw) == 1:
        nested = _mapping_section(raw, "call", "Call", "request", "Request", "api", "API")
        if nested and _function_name(nested):
            return nested
    if any(
        _dict_lookup(
            raw,
            "method",
            "Method",
            "method_name",
            "methodName",
            "MethodName",
            "method_uid",
            "methodUid",
            "MethodUID",
            "invoking_id",
            "InvokingID",
            "invoking_uid",
            "invokingUid",
            "InvokingUID",
            "object",
            "Object",
            "target",
            "Target",
            "argv",
            "ARGV",
            "kwargs",
            "KWArgs",
            "function",
            "Function",
            "fn",
            "Fn",
            "FN",
            "fn_name",
            "fnName",
            "function_id",
            "functionId",
            "func_name",
            "funcName",
            "action_name",
            "actionName",
            "call_name",
            "callName",
            "procedure",
            "Procedure",
            "procedure_name",
            "procedureName",
            "function_name",
            "functionName",
            "FunctionName",
            "api_name",
            "apiName",
            "APIName",
            "method_name",
            "methodName",
            "MethodName",
            "command_name",
            "commandName",
            "CommandName",
            "op",
            "Op",
            "cmd",
            "Cmd",
            "CMD",
            "action",
            "Action",
            "io",
            "IO",
            "request",
            "Request",
            "call",
            "Call",
            "api",
            "API",
            "operation",
            "Operation",
            "operation_name",
            "operationName",
            "OperationName",
            "event",
            "Event",
            "resetType",
            "ResetType",
            "reset_type",
            "name",
            "Name",
        )[0]
        for _ in (None,)
    ):
        return raw
    return {}


def _output_section(raw: dict[str, Any]) -> dict[str, Any]:
    section = _mapping_section(raw, "output", "Output")
    if section:
        if len(section) == 1:
            nested = _mapping_section(section, "output", "Output")
            if nested:
                return nested
        return section
    if _dict_lookup(
        raw,
        "status_codes",
        "statusCodes",
        "StatusCodes",
        "status_code",
        "statusCode",
        "StatusCode",
        "code",
        "Code",
        "rc",
        "RC",
        "returnCode",
        "ReturnCode",
        "status",
        "Status",
        "error",
        "Error",
        "err",
        "Err",
        "hasError",
        "HasError",
        "isError",
        "IsError",
        "failed",
        "Failed",
        "failure",
        "Failure",
        "return_value",
        "ReturnValue",
        "returnValue",
        "returnVal",
        "returnval",
        "ret",
        "Ret",
        "retval",
        "retVal",
        "RetVal",
        "return_values",
        "ReturnValues",
        "returnValues",
        "returned_values",
        "returnedValues",
        "returnedNamedValues",
        "ReturnedNamedValues",
        "namedReturnValues",
        "NamedReturnValues",
        "values",
        "Values",
        "value",
        "Value",
        "data",
        "Data",
        "payload",
        "Payload",
        "bytes",
        "Bytes",
        "buffer",
        "Buffer",
        "blob",
        "Blob",
        "content",
        "Content",
        "hex",
        "Hex",
        "payloadBytes",
        "PayloadBytes",
        "byteArray",
        "ByteArray",
        "response",
        "Response",
        "body",
        "Body",
        "range",
        "Range",
        "rangeInfo",
        "RangeInfo",
        "lockingRange",
        "LockingRange",
        "locking_range",
        "band",
        "Band",
        "ok",
        "OK",
        "success",
        "Success",
        "passed",
        "Passed",
        "isSuccess",
        "IsSuccess",
        "is_ok",
        "isOk",
        "IsOk",
        "succeeded",
        "Succeeded",
        "successFlag",
        "SuccessFlag",
        "authenticated",
        "Authenticated",
        "authentication",
        "Authentication",
        "result",
        "Result",
        "results",
        "Results",
        "rv",
        "RV",
        "kwrv",
        "kwrvs",
        "return",
        "Return",
        "returns",
        "Returns",
    )[0]:
        return raw
    return {}


def _function_input_section(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    section = _mapping_section(raw, "input", "Input")
    if section and len(section) == 1:
        nested = _mapping_section(section, "call", "Call", "request", "Request", "api", "API")
        if nested and _function_name(nested):
            return nested
    if section and _function_name(section):
        return section
    if len(raw) == 1:
        nested = _mapping_section(raw, "call", "Call", "request", "Request", "api", "API")
        if nested and _function_name(nested):
            return nested
    if _function_name(raw):
        return raw
    return section if isinstance(section, dict) else {}


def _invoke_argv(inp: dict[str, Any]) -> list[Any]:
    value = _mapping_value(inp, "argv", "ARGV")
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, list):
        return list(value)
    if _function_name(inp) in {"invoke", "sedinvoke", "pysedinvoke"}:
        value = _mapping_value(inp, "args", "Args", "arguments", "Arguments")
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, list):
            return list(value)
    return []


def _invoke_kwargs(inp: dict[str, Any]) -> dict[str, Any]:
    value = _mapping_value(inp, "kwargs", "KWArgs", "kwArgs", "KwArgs", "kw", "KW", "named", "Named", "namedArgs", "NamedArgs")
    return dict(value) if isinstance(value, dict) else {}


def _function_name(inp: dict[str, Any]) -> str:
    value = _mapping_value(
        inp,
        "function",
        "Function",
        "fn",
        "Fn",
        "FN",
        "fn_name",
        "fnName",
        "function_id",
        "functionId",
        "func_name",
        "funcName",
        "action_name",
        "actionName",
        "call_name",
        "callName",
        "procedure",
        "Procedure",
        "procedure_name",
        "procedureName",
        "func",
        "Func",
        "call",
        "Call",
        "api",
        "API",
        "api_name",
        "apiName",
        "APIName",
        "method_name",
        "methodName",
        "MethodName",
        "command_name",
        "commandName",
        "CommandName",
        "operation",
        "Operation",
        "op",
        "Op",
        "name",
        "Name",
        "function_name",
        "functionName",
        "FunctionName",
        "operation_name",
        "operationName",
        "OperationName",
        "event",
        "Event",
        "resetType",
        "ResetType",
        "reset_type",
    )
    text = _as_text(value or "").strip()
    if re.search(r"[.:/\\]", text):
        parts = [part for part in re.split(r"[.:/\\]+", text) if part]
        if parts:
            text = parts[-1]
    return re.sub(r"[^A-Za-z0-9_]", "", text).lower()


def _function_alias(name: str) -> str:
    return name.replace("_", "")


def _function_args(inp: dict[str, Any]) -> list[Any]:
    value = _mapping_value(inp, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
    if isinstance(value, tuple):
        return list(value)
    return list(value) if isinstance(value, list) else []


def _function_kwargs(inp: dict[str, Any]) -> dict[str, Any]:
    kwargs = _invoke_kwargs(inp)
    positional = _mapping_value(inp, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
    if isinstance(positional, (list, tuple)) and len(positional) == 1 and isinstance(positional[0], dict):
        for key, value in positional[0].items():
            kwargs.setdefault(key, value)
    for container_name in (
        "args",
        "Args",
        "arguments",
        "Arguments",
        "params",
        "Params",
        "parameters",
        "Parameters",
        "options",
        "Options",
        "opts",
        "Opts",
        "config",
        "Config",
        "request",
        "Request",
        "body",
        "Body",
        "payload",
        "Payload",
        "inputArgs",
        "InputArgs",
        "namedArgs",
        "NamedArgs",
    ):
        params = _mapping_value(inp, container_name)
        if isinstance(params, dict):
            for key, value in params.items():
                kwargs.setdefault(key, value)
    controls = {
        "function",
        "function_name",
        "functionname",
        "fn",
        "fn_name",
        "fnname",
        "function_id",
        "functionid",
        "func_name",
        "funcname",
        "action_name",
        "actionname",
        "call_name",
        "callname",
        "procedure",
        "procedure_name",
        "procedurename",
        "func",
        "call",
        "api",
        "api_name",
        "apiname",
        "method_name",
        "methodname",
        "command_name",
        "commandname",
        "operation",
        "op",
        "operation_name",
        "operationname",
        "name",
        "type",
        "method",
        "args",
        "arguments",
        "params",
        "parameters",
        "kwargs",
        "kw",
        "named",
        "input",
        "output",
        "status",
        "statuscodes",
        "status_codes",
        "error",
        "err",
        "haserror",
        "iserror",
        "failed",
        "failure",
        "return",
        "returns",
        "return_value",
        "returnvalue",
        "returnval",
        "ret",
        "retval",
        "return_values",
        "returnvalues",
        "values",
        "passed",
        "issuccess",
        "is_ok",
        "isok",
        "succeeded",
        "successflag",
        "result",
        "results",
        "rv",
        "kwrv",
        "kwrvs",
    }
    for key, value in inp.items():
        normalized = re.sub(r"[^A-Za-z0-9_]", "", _as_text(key)).lower()
        if normalized not in controls and key not in kwargs:
            kwargs[key] = value
    return kwargs


def _arg_or_kw(args: list[Any], kwargs: dict[str, Any], index: int, *names: str) -> Any:
    if len(args) > index:
        return args[index]
    return _mapping_value(kwargs, *names)


SESSION_ID_PAYLOAD_ALIASES = (
    "values",
    "Values",
    "settings",
    "Settings",
    "options",
    "Options",
    "params",
    "Params",
    "parameters",
    "Parameters",
    "policy",
    "Policy",
    "config",
    "Config",
    "request",
    "Request",
    "session",
    "Session",
    "syncSessionRequest",
    "SyncSessionRequest",
    "endSessionRequest",
    "EndSessionRequest",
    "closeSessionRequest",
    "CloseSessionRequest",
    "sessionRequest",
    "SessionRequest",
    "spSessionRequest",
    "SPSessionRequest",
    "securityProviderRequest",
    "SecurityProviderRequest",
)

HOST_SESSION_ID_ALIASES = ("HostSessionID", "hostSessionID", "HostSession", "hostSession", "HostSID", "hostSID", "HSID", "hSID")
SP_SESSION_ID_ALIASES = (
    "SPSessionID",
    "spSessionID",
    "TPerSessionID",
    "tperSessionID",
    "tperSessionId",
    "TPerSession",
    "tperSession",
    "TPerSID",
    "tperSID",
)


def _session_id_payload(args: list[Any], kwargs: dict[str, Any], inp: dict[str, Any]) -> dict[str, Any]:
    payload = _mapping_value(kwargs, *SESSION_ID_PAYLOAD_ALIASES)
    if not isinstance(payload, dict):
        payload = _mapping_value(inp, *SESSION_ID_PAYLOAD_ALIASES)
    if not isinstance(payload, dict) and len(args) > 0 and isinstance(args[0], dict):
        payload = _mapping_value(args[0], *SESSION_ID_PAYLOAD_ALIASES)
        if not isinstance(payload, dict):
            payload = args[0]
    if not isinstance(payload, dict):
        return {}
    for _ in range(2):
        merged_payload = dict(payload)
        for envelope in SESSION_ID_PAYLOAD_ALIASES:
            found_envelope, nested_payload = _dict_lookup(payload, envelope)
            if found_envelope and isinstance(nested_payload, dict) and nested_payload is not payload:
                merged_payload.update(nested_payload)
        if merged_payload == payload:
            break
        payload = merged_payload
    return payload


def _session_ids_from_wrapper(args: list[Any], kwargs: dict[str, Any], inp: dict[str, Any]) -> tuple[Any, Any]:
    host_session_id = _arg_or_kw(args, kwargs, 0, *HOST_SESSION_ID_ALIASES)
    sp_session_id = _arg_or_kw(args, kwargs, 1, *SP_SESSION_ID_ALIASES)
    payload = _session_id_payload(args, kwargs, inp)
    if payload:
        if host_session_id is None:
            host_session_id = _mapping_value(payload, *HOST_SESSION_ID_ALIASES)
        if sp_session_id is None:
            sp_session_id = _mapping_value(payload, *SP_SESSION_ID_ALIASES)
    return host_session_id, sp_session_id


def _high_level_return_value(out: dict[str, Any]) -> tuple[bool, Any]:
    found_return, raw_return = _dict_lookup(
        out,
        "return",
        "Return",
        "returns",
        "Returns",
        "return_value",
        "ReturnValue",
        "returnValue",
        "returnVal",
        "returnval",
        "ret",
        "Ret",
        "retval",
        "retVal",
        "RetVal",
        "return_values",
        "ReturnValues",
        "returnValues",
        "values",
        "Values",
        "value",
        "Value",
        "data",
        "Data",
        "payload",
        "Payload",
        "bytes",
        "Bytes",
        "buffer",
        "Buffer",
        "blob",
        "Blob",
        "content",
        "Content",
        "hex",
        "Hex",
        "payloadBytes",
        "PayloadBytes",
        "byteArray",
        "ByteArray",
        "response",
        "Response",
        "body",
        "Body",
        "range",
        "Range",
        "rangeInfo",
        "RangeInfo",
        "lockingRange",
        "LockingRange",
        "locking_range",
        "band",
        "Band",
        "ok",
        "OK",
        "success",
        "Success",
        "passed",
        "Passed",
        "isSuccess",
        "IsSuccess",
        "is_ok",
        "isOk",
        "IsOk",
        "succeeded",
        "Succeeded",
        "successFlag",
        "SuccessFlag",
        "authenticated",
        "Authenticated",
        "authentication",
        "Authentication",
        "result",
        "Result",
        "results",
        "Results",
        "rvs",
        "RVs",
        "rv",
        "RV",
        "kwrv",
        "kwrvs",
    )
    if found_return:
        return True, raw_return
    output_args = _mapping_section(out, "args", "Args")
    return _dict_lookup(
        output_args,
        "return",
        "Return",
        "returns",
        "Returns",
        "return_value",
        "ReturnValue",
        "returnValue",
        "returnVal",
        "returnval",
        "ret",
        "Ret",
        "retval",
        "retVal",
        "RetVal",
        "return_values",
        "ReturnValues",
        "returnValues",
        "returned_values",
        "returnedValues",
        "returnedNamedValues",
        "ReturnedNamedValues",
        "namedReturnValues",
        "NamedReturnValues",
        "values",
        "Values",
        "value",
        "Value",
        "data",
        "Data",
        "payload",
        "Payload",
        "response",
        "Response",
        "ok",
        "OK",
        "success",
        "Success",
        "passed",
        "Passed",
        "isSuccess",
        "IsSuccess",
        "is_ok",
        "isOk",
        "IsOk",
        "succeeded",
        "Succeeded",
        "successFlag",
        "SuccessFlag",
        "authenticated",
        "Authenticated",
        "authentication",
        "Authentication",
        "result",
        "Result",
        "results",
        "Results",
        "rvs",
        "RVs",
        "rv",
        "RV",
        "kwrv",
        "kwrvs",
    )


def _high_level_status(raw: dict[str, Any], out: dict[str, Any], inp: dict[str, Any]) -> str | None:
    function_alias = _function_alias(_function_name(inp))
    mutating_wrapper_aliases = {
        "addace",
        "addaceentry",
        "addaclentry",
        "appendace",
        "appendaclentry",
        "grantace",
        "grantacl",
        "addlogentry",
        "appendlogentry",
        "writelogentry",
        "storelogentry",
        "createlogentry",
        "addpsk",
        "addpskentry",
        "addrow",
        "activate",
        "activatelocking",
        "activatelockingsp",
        "enablelockingsp",
        "setuplockingsp",
        "initializelockingsp",
        "initlockingsp",
        "activatesp",
        "takeownership",
        "takeown",
        "takeowner",
        "appendlog",
        "appendrow",
        "changepin",
        "changepincode",
        "changepassword",
        "changepasscode",
        "changeuserpin",
        "changeuserpincode",
        "changeuserpasscode",
        "changeuserpassword",
        "changeusercredential",
        "changecredential",
        "setsidpin",
        "setsidpasscode",
        "changesidpin",
        "changesidpasscode",
        "setsidpassword",
        "changesidpassword",
        "setadminpin",
        "setadminpincode",
        "setadminpasscode",
        "changeadminpin",
        "changeadminpincode",
        "changeadminpasscode",
        "setuserpassword",
        "setusercredential",
        "setcredential",
        "updateuserpassword",
        "updateusercredential",
        "updatepassword",
        "updatepasscode",
        "updatecredential",
        "putpin",
        "putpincode",
        "putpassword",
        "putpasscode",
        "putcredential",
        "putuserpassword",
        "putusercredential",
        "clearlog",
        "clearlogentries",
        "allocatelog",
        "configurerange",
        "configurelockingrange",
        "configrange",
        "setlockingrange",
        "setuprange",
        "setband",
        "configureband",
        "configband",
        "setbandrange",
        "updaterange",
        "modifyrange",
        "definerange",
        "createrange",
        "resizerange",
        "moverange",
        "setrangeconfig",
        "setrangegeometry",
        "updaterangegeometry",
        "putrangegeometry",
        "configurerangegeometry",
        "setrangeattributes",
        "updaterangeattributes",
        "setrangewindow",
        "setlbarange",
        "updatelbarange",
        "configurelbarange",
        "setbandconfig",
        "updatebandconfig",
        "setlockingband",
        "updatelockingband",
        "configurelockingband",
        "setlockingrangegeometry",
        "updatelockingrangegeometry",
        "configurelockingrangegeometry",
        "setbandgeometry",
        "updatebandgeometry",
        "configurebandgeometry",
        "defineband",
        "resizeband",
        "moveband",
        "setbandattributes",
        "updatebandattributes",
        "setbandwindow",
        "setlockingrangestate",
        "updatelockingrange",
        "clearlockonreset",
        "setlor",
        "setrangelor",
        "updatelor",
        "updaterangelor",
        "putlor",
        "putrangelor",
        "setresettypes",
        "setrangeresettypes",
        "setlockonresettypes",
        "setrangelockonresettypes",
        "setlockingrangeresettypes",
        "setlockingrangelockonreset",
        "updatelockonreset",
        "updaterangelockonreset",
        "putlockonreset",
        "putrangelockonreset",
        "configurelockonreset",
        "configurerangelockonreset",
        "configurelor",
        "configurerangelor",
        "enablelockonreset",
        "enablerangelockonreset",
        "enablelor",
        "enablerangelor",
        "disablelockonreset",
        "disablerangelockonreset",
        "disablelor",
        "disablerangelor",
        "createbytetable",
        "createlogtable",
        "createtablerow",
        "createobjectrow",
        "maketable",
        "allocatetable",
        "makerow",
        "allocaterow",
        "createobjecttable",
        "newobjecttable",
        "newlog",
        "newlogtable",
        "newtablerow",
        "createrow",
        "createtable",
        "begindataerase",
        "begindataremoval",
        "choosedataremovalmechanism",
        "configuredataremovalmechanism",
        "updatedataremovalmechanism",
        "putdataremovalmechanism",
        "requestreencrypt",
        "dataremoval",
        "clearmbrdone",
        "deletetable",
        "deleteobjectrow",
        "deletetablerow",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "deleteobject",
        "deleterange",
        "deleterow",
        "deleterows",
        "deletemethod",
        "destroyobject",
        "destroyrange",
        "destroyrow",
        "destroytablerow",
        "destroytable",
        "activateAuthority",
        "activateUser",
        "activateauthority",
        "activateuser",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "disableauthority",
        "disablembr",
        "disablereadlock",
        "disablereadlockrange",
        "disablereadlockforrange",
        "disablereadlocking",
        "disablerangereadlock",
        "disablerangereadlocking",
        "disablewritelock",
        "disablewritelockrange",
        "disablewritelockforrange",
        "disablewritelocking",
        "disablerangewritelock",
        "disablerangewritelocking",
        "disableportlock",
        "dataerase",
        "droprow",
        "activateAuthority",
        "activateUser",
        "activateauthority",
        "activateuser",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "enableauthority",
        "enablembr",
        "enablereadlock",
        "enablereadlockrange",
        "enablereadlockforrange",
        "enablereadlocking",
        "enablerangereadlock",
        "enablerangereadlocking",
        "enablewritelock",
        "enablewritelockrange",
        "enablewritelockforrange",
        "enablewritelocking",
        "enablerangewritelock",
        "enablerangewritelocking",
        "enableportlock",
        "erase",
        "erasedata",
        "eraserange",
        "eraselog",
        "factoryreset",
        "fetchdata",
        "flushlog",
        "genkey",
        "genrangekey",
        "generatekey",
        "newkey",
        "newrangekey",
        "createkey",
        "createrangekey",
        "makekey",
        "makerangekey",
        "generaterandom",
        "generaterangekey",
        "generatemek",
        "regenkey",
        "refreshkey",
        "refreshmek",
        "renewrangekey",
        "rollkey",
        "rollrangekey",
        "importcredential",
        "importkey",
        "importkeypackage",
        "importpin",
        "importpinpackage",
        "importcredentialbackup",
        "importkeybackup",
        "importwrappedkey",
        "importpackage",
        "restorecredential",
        "restorekeypackage",
        "restorepin",
        "restorecredentialpackage",
        "restorepinpackage",
        "restorecredentialbackup",
        "loadkeypackage",
        "loadcredentialpackage",
        "writekeypackage",
        "writecredentialpackage",
        "writekeybackup",
        "importpsk",
        "importpskentry",
        "loadpackage",
        "lockread",
        "lockreadrange",
        "lockreadforrange",
        "lockrangeforread",
        "lockinterface",
        "lockport",
        "lockportaccess",
        "lockrangeread",
        "lockrangewrite",
        "lockforread",
        "lockforwrite",
        "lockrange",
        "lockwrite",
        "lockwriterange",
        "lockwriteforrange",
        "lockrangeforwrite",
        "loaddata",
        "markmbrdone",
        "newrow",
        "newtable",
        "pausereencrypt",
        "pausereencryption",
        "putdata",
        "putdatastore",
        "putdatastorebytes",
        "putdatastorepayload",
        "putdsbytes",
        "putdspayload",
        "writedatastorepayload",
        "setdatapayload",
        "writeuserpayload",
        "saveuserpayload",
        "storeuserpayload",
        "setuserpayload",
        "putlogentry",
        "putmbr",
        "putmbrbytes",
        "putmbrtable",
        "writembrpayload",
        "setmbrpayload",
        "savembrbytes",
        "programmbrbytes",
        "putbytes",
        "putuserdata",
        "readaccess",
        "grantdataread",
        "grantuserdataread",
        "grantdataaccess",
        "grantuserdataaccess",
        "grantpayloadread",
        "grantuserpayloadread",
        "allowdataread",
        "allowdataaccess",
        "allowpayloadread",
        "allowreadaccess",
        "setreadaccess",
        "setdataaccess",
        "setpayloadreadaccess",
        "readlock",
        "readlockrange",
        "readlockforrange",
        "rng",
        "getrng",
        "resetlog",
        "restorepackage",
        "setdataremoval",
        "setdataremovalmode",
        "setdataremovalmethod",
        "setrangereadlock",
        "setreadlockforrange",
        "clearreadlockforrange",
        "clearrangereadlock",
        "setrangereadlockenabled",
        "setrangereadlockingenabled",
        "setrangereadlockstate",
        "setrangewritelock",
        "setwritelockforrange",
        "clearwritelockforrange",
        "clearrangewritelock",
        "setrangewritelockenabled",
        "setrangewritelockingenabled",
        "setrangewritelockstate",
        "setreadlockstate",
        "setstartlba",
        "startdataerase",
        "setwritelockstate",
        "readunlock",
        "readunlockrange",
        "readunlockforrange",
        "unlockport",
        "unlockrangeread",
        "unlockrangewrite",
        "removeace",
        "removeaceentry",
        "deleteace",
        "deleteaclentry",
        "dropace",
        "revokeace",
        "revokeacl",
        "removeobject",
        "removerange",
        "removerow",
        "removetablerow",
        "removetable",
        "regeneratekey",
        "regeneraterangekey",
        "regeneratemek",
        "rekeyrange",
        "rekey",
        "refreshrangekey",
        "revert",
        "revertadminsp",
        "revertdrive",
        "revertlockingsp",
        "revertlocking",
        "resetmbrdone",
        "reencrypt",
        "triggerreencrypt",
        "resumereencrypt",
        "resumereencryption",
        "continue_reencrypt",
        "continuereencrypt",
        "continuereencryption",
        "rotatekey",
        "rotaterangekey",
        "rotatemek",
        "sign",
        "signbytes",
        "signpayload",
        "signmessage",
        "signdigest",
        "createsignature",
        "makesignature",
        "generatesignature",
        "signaturecreate",
        "signaturegenerate",
        "tpersignpayload",
        "setlockonreset",
        "getlor",
        "getrangelor",
        "getresettypes",
        "getrangeresettypes",
        "getlockingrangelockonreset",
        "getlockonresettypes",
        "getrangelockonresettypes",
        "getlockingrangeresettypes",
        "readlockonreset",
        "readrangelockonreset",
        "fetchlockonreset",
        "fetchrangelockonreset",
        "readlor",
        "readrangelor",
        "fetchlor",
        "fetchrangelor",
        "islockonresetenabled",
        "israngelockonresetenabled",
        "islockingrangelockonresetenabled",
        "lockonresetenabled",
        "rangelockonresetenabled",
        "haslockonreset",
        "readlockenabled",
        "readlockingenabled",
        "isreadlockingenabled",
        "getrangereadlockenabled",
        "getreadlockenabledrange",
        "getreadlockenabledforrange",
        "israngereadlockenabled",
        "isreadlockenabledrange",
        "isreadlockenabledforrange",
        "getrangereadlockingenabled",
        "israngereadlockingenabled",
        "writelockenabled",
        "writelockingenabled",
        "iswritelockingenabled",
        "getrangewritelockenabled",
        "getwritelockenabledrange",
        "getwritelockenabledforrange",
        "israngewritelockenabled",
        "iswritelockenabledrange",
        "iswritelockenabledforrange",
        "writembrtable",
        "getrangewritelockingenabled",
        "israngewritelockingenabled",
        "readlocked",
        "getrangereadlocked",
        "getreadlockedrange",
        "getreadlockedforrange",
        "israngereadlocked",
        "isreadlockedrange",
        "isreadlockedforrange",
        "isreadlockset",
        "getreadlockstate",
        "getrangereadlockstate",
        "readlockstate",
        "rangereadlockstate",
        "writelocked",
        "writepackage",
        "writelog",
        "updatembr",
        "savembr",
        "savembrbytes",
        "programmbr",
        "programmbrbytes",
        "getrangewritelocked",
        "getwritelockedrange",
        "getwritelockedforrange",
        "israngewritelocked",
        "iswritelockedrange",
        "iswritelockedforrange",
        "iswritelockset",
        "getwritelockstate",
        "getrangewritelockstate",
        "writelockstate",
        "rangewritelockstate",
        "isreencrypting",
        "getadvkeymode",
        "getadvancedkeymode",
        "getverifymode",
        "getgeneralstatus",
        "getlockingrangestatus",
        "getretrylimit",
        "getuserretrylimit",
        "getcredentialretrylimit",
        "getcredentialattemptlimit",
        "getauthattemptlimit",
        "getmaxretries",
        "getusermaxretries",
        "getretrycountlimit",
        "getattemptlimit",
        "getpinattemptlimit",
        "getmaxpinattempts",
        "getnextkey",
        "getnextmek",
        "getpendingkey",
        "getpendingmek",
        "getreencryptkey",
        "getreencryptionkey",
        "getnewkey",
        "getnewmek",
        "getrangenextkey",
        "getrangependingkey",
        "getrangenewkey",
        "getrangependingmek",
        "getrangenewmek",
        "getrangereencryptkey",
        "getrangereencryptionkey",
        "setmbr",
        "setmbrcontrol",
        "putmbrcontrol",
        "storembrcontrol",
        "savembrcontrol",
        "writembrcontrol",
        "programmbrcontrol",
        "setmbrstate",
        "updatembrstate",
        "putmbrstate",
        "storembrstate",
        "savembrstate",
        "configurembrstate",
        "setmbrstatus",
        "updatembrstatus",
        "putmbrstatus",
        "storembrstatus",
        "savembrstatus",
        "configurembrstatus",
        "setmbrdisabled",
        "clearmbrenabled",
        "updatembrenabled",
        "putmbrenabled",
        "storembrenabled",
        "savembrenabled",
        "writembrenabled",
        "updatembrenable",
        "putmbrenable",
        "storembrenable",
        "savembrenable",
        "setmbrdone",
        "updatembrdone",
        "putmbrdone",
        "storembrdone",
        "savembrdone",
        "writembrdone",
        "setmbrdoneflag",
        "updatembrdoneflag",
        "putmbrdoneflag",
        "storembrdoneflag",
        "savembrdoneflag",
        "setmbrcomplete",
        "updatembrcomplete",
        "putmbrcomplete",
        "storembrcomplete",
        "savembrcomplete",
        "completembr",
        "finishmbr",
        "setmbrnotdone",
        "setdonembr",
        "markmbrcomplete",
        "completembr",
        "finishmbr",
        "clearmbrcomplete",
        "resetmbrcomplete",
        "setmbrenable",
        "setmbrenabled",
        "setmbrbytes",
        "setmbrpayload",
        "setmbrdoneonreset",
        "updatembrdoneonreset",
        "putmbrdoneonreset",
        "storembrdoneonreset",
        "savembrdoneonreset",
        "configurembrdoneonreset",
        "setdoneonreset",
        "updatedoneonreset",
        "putdoneonreset",
        "storedoneonreset",
        "savedoneonreset",
        "setmbrdor",
        "updatembrdor",
        "putmbrdor",
        "storembrdor",
        "savembrdor",
        "setmbrresetdone",
        "updatembrresettypes",
        "putmbrresettypes",
        "storembrresettypes",
        "savembrresettypes",
        "setmbrtable",
        "setminpinlength",
        "setpackage",
        "setpinpackage",
        "setcredentialbackup",
        "setwrappedkey",
        "setwrappedpackage",
        "setport",
        "setportlock",
        "setportlocked",
        "setportstate",
        "updateportlock",
        "updateportlocked",
        "updateportstate",
        "putportlock",
        "putportlocked",
        "setauthority",
        "setauthorityenabled",
        "setauthoritylimit",
        "setauthoritystate",
        "setauthorityuses",
        "setcredentialpackage",
        "setdata",
        "setdatabytes",
        "setdatastore",
        "setdatastorebytes",
        "setdatastorepayload",
        "setbytes",
        "setdsbytes",
        "setdspayload",
        "setactivedataremovalmechanism",
        "setdataremovalmechanism",
        "selectdataremovalmechanism",
        "updatedataremovalmechanism",
        "putdataremovalmechanism",
        "setkeypackage",
        "setlimit",
        "setpin",
        "setpincode",
        "setpassword",
        "setuserenable",
        "setuserstate",
        "setuserpin",
        "setuserpincode",
        "setuserpasscode",
        "setuserdata",
        "setpinlimit",
        "setpintrylimit",
        "setpinretrylimit",
        "setpintries",
        "setcredentialtries",
        "setcredentialtrylimit",
        "updatetrylimit",
        "puttrylimit",
        "updatetries",
        "puttries",
        "updateuses",
        "putuses",
        "setpskentry",
        "setpsk",
        "configurepsk",
        "configurepskentry",
        "putpsk",
        "putpskentry",
        "storepsk",
        "storepskentry",
        "savepsk",
        "savepskentry",
        "enablepsk",
        "settlspsk",
        "updatetlspsk",
        "puttlspsk",
        "storetlspsk",
        "savetlspsk",
        "importtlspsk",
        "setpresharedkeyentry",
        "updatepresharedkey",
        "putpresharedkey",
        "storepresharedkey",
        "savepresharedkey",
        "importpresharedkey",
        "restorepresharedkey",
        "setrange",
        "setrangelba",
        "setrangereadlocked",
        "setrangewritelocked",
        "setreadlockedforrange",
        "setwritelockedforrange",
        "setrangelen",
        "setrangelength",
        "setrangesize",
        "setrangestart",
        "setrangestartlba",
        "setrangelockonreset",
        "setlor",
        "setrangelor",
        "updatelor",
        "updaterangelor",
        "putlor",
        "putrangelor",
        "setresettypes",
        "setrangeresettypes",
        "setlockonresettypes",
        "setrangelockonresettypes",
        "setlockingrangeresettypes",
        "setlockingrangelockonreset",
        "updatelockonreset",
        "updaterangelockonreset",
        "putlockonreset",
        "putrangelockonreset",
        "configurelockonreset",
        "configurerangelockonreset",
        "configurelor",
        "configurerangelor",
        "enablelockonreset",
        "enablerangelockonreset",
        "enablelor",
        "enablerangelor",
        "disablelockonreset",
        "disablerangelockonreset",
        "disablelor",
        "disablerangelor",
        "setreadlockenabled",
        "setreadlockingenabled",
        "updatereadlockenabled",
        "putreadlockenabled",
        "setreadlock",
        "setreencryptrequest",
        "updatereencryptrequest",
        "putreencryptrequest",
        "setreadlocked",
        "updatereadlocked",
        "putreadlocked",
        "settries",
        "settrylimit",
        "setusertrylimit",
        "setuserlimit",
        "setuserretries",
        "setuses",
        "setusertries",
        "setuseruses",
        "updateuseruses",
        "putuseruses",
        "setwritelockenabled",
        "setwritelockingenabled",
        "updatewritelockenabled",
        "putwritelockenabled",
        "setwritelock",
        "setwritelocked",
        "updatewritelocked",
        "putwritelocked",
        "startdataremoval",
        "startdataremovaloperation",
        "sanitizedata",
        "secureerasedata",
        "startreencrypt",
        "requestreencrypt",
        "triggerreencrypt",
        "beginreencrypt",
        "beginreencryption",
        "reencryptrange",
        "startreencryption",
        "storedata",
        "storedatastore",
        "storedatastorebytes",
        "storedatastorepayload",
        "storeds",
        "storedsbytes",
        "storedspayload",
        "programdatastore",
        "storeuserdata",
        "savedata",
        "saveuserdata",
        "savedatastore",
        "savedatastorebytes",
        "savedatastorepayload",
        "saveds",
        "savedsbytes",
        "savedspayload",
        "programdatastore",
        "writedatastorepayload",
        "setdatapayload",
        "writeuserpayload",
        "saveuserpayload",
        "storeuserpayload",
        "setuserpayload",
        "storebytes",
        "unpackkey",
        "unpackpackage",
        "unlockread",
        "unlockreadrange",
        "unlockreadforrange",
        "unlockforread",
        "unlockrangeforread",
        "unlockforwrite",
        "unlockrangeforwrite",
        "unlockportaccess",
        "unmarkmbrdone",
        "unwrapkey",
        "unwrapkeypackage",
        "unwrappackage",
        "unlockwrite",
        "unlockwriterange",
        "unlockwriteforrange",
        "updatepin",
        "updatepincode",
        "updateuserpin",
        "updateuserpincode",
        "updateuserpasscode",
        "unlockrange",
        "unlockinterface",
        "writeaccess",
        "grantaccess",
        "grantwriteaccess",
        "grantreadaccess",
        "grantdataread",
        "grantdatawrite",
        "grantuserdataread",
        "grantuserdatawrite",
        "grantdataaccess",
        "grantuserdataaccess",
        "grantpayloadread",
        "grantpayloadwrite",
        "grantuserpayloadread",
        "grantuserpayloadwrite",
        "allowdataread",
        "allowdatawrite",
        "allowdataaccess",
        "allowpayloadread",
        "allowpayloadwrite",
        "allowreadaccess",
        "allowwriteaccess",
        "setreadaccess",
        "setwriteaccess",
        "setdataaccess",
        "setpayloadreadaccess",
        "setpayloadwriteaccess",
        "writebytes",
        "writedatabytes",
        "writedata",
        "writedatastore",
        "writedatastorebytes",
        "writeds",
        "writedsbytes",
        "writeuserdata",
        "writepsk",
        "writepskentry",
        "writembr",
        "writembrdata",
        "writembrbytes",
        "writembrpayload",
        "writembrshadow",
        "writembrshadowbytes",
        "writembrtablebytes",
        "writelock",
        "writelockrange",
        "writelockforrange",
        "writeunlock",
        "writeunlockrange",
        "writeunlockforrange",
        "storembr",
        "storembrbytes",
        "storembrshadow",
        "storembrshadowbytes",
        "storembrtable",
        "setmbrpayload",
        "savembrbytes",
        "programmbr",
        "programmbrbytes",
        "programdatastore",
        "programdatastorebytes",
        "programdatastorepayload",
        "programdsbytes",
        "programdspayload",
    }
    bool_return_mutating_wrapper_aliases = {
        "activate",
        "activatelocking",
        "activatelockingsp",
        "enablelockingsp",
        "setuplockingsp",
        "initializelockingsp",
        "initlockingsp",
        "activatesp",
        "takeownership",
        "takeown",
        "takeowner",
        "changepin",
        "changepincode",
        "changepassword",
        "changepasscode",
        "changeuserpin",
        "changeuserpincode",
        "changeuserpasscode",
        "changeuserpassword",
        "changeusercredential",
        "changecredential",
        "setpin",
        "setpincode",
        "setpassword",
        "setpasscode",
        "setuserpin",
        "setuserpincode",
        "setuserpasscode",
        "setuserpassword",
        "setusercredential",
        "setcredential",
        "updatepin",
        "updatepincode",
        "updateuserpin",
        "updateuserpincode",
        "updateuserpasscode",
        "updateuserpassword",
        "updateusercredential",
        "updatepassword",
        "updatepasscode",
        "updatecredential",
        "putpin",
        "putpincode",
        "putpassword",
        "putpasscode",
        "putcredential",
        "putuserpassword",
        "putusercredential",
        "setsidpin",
        "setsidpasscode",
        "changesidpin",
        "changesidpasscode",
        "setsidpassword",
        "changesidpassword",
        "setadminpin",
        "setadminpincode",
        "setadminpasscode",
        "changeadminpin",
        "changeadminpincode",
        "changeadminpasscode",
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
        "rekey",
        "refreshrangekey",
        "generatemek",
        "rotatemek",
        "regeneratemek",
        "setrange",
        "configurerange",
        "configurelockingrange",
        "configrange",
        "setlockingrange",
        "setuprange",
        "setband",
        "configureband",
        "configband",
        "setbandrange",
        "updaterange",
        "modifyrange",
        "definerange",
        "createrange",
        "resizerange",
        "moverange",
        "setrangeconfig",
        "setrangegeometry",
        "updaterangegeometry",
        "putrangegeometry",
        "configurerangegeometry",
        "setrangeattributes",
        "updaterangeattributes",
        "setrangewindow",
        "setlbarange",
        "updatelbarange",
        "configurelbarange",
        "setbandconfig",
        "updatebandconfig",
        "setlockingband",
        "updatelockingband",
        "configurelockingband",
        "setlockingrangegeometry",
        "updatelockingrangegeometry",
        "configurelockingrangegeometry",
        "setbandgeometry",
        "updatebandgeometry",
        "configurebandgeometry",
        "defineband",
        "resizeband",
        "moveband",
        "setbandattributes",
        "updatebandattributes",
        "setbandwindow",
        "setlockingrangestate",
        "updatelockingrange",
        "clearlockonreset",
        "enablerangeaccess",
        "grantaccess",
        "writeaccess",
        "readaccess",
        "grantwriteaccess",
        "grantreadaccess",
        "grantdataread",
        "grantdatawrite",
        "grantuserdataread",
        "grantuserdatawrite",
        "allowdataread",
        "allowdatawrite",
        "allowreadaccess",
        "allowwriteaccess",
        "setreadaccess",
        "setwriteaccess",
        "writedata",
        "writedatabytes",
        "putdata",
        "putuserdata",
        "putdatastore",
        "putdatastorebytes",
        "putdatastorepayload",
        "putdsbytes",
        "putdspayload",
        "putLog",
        "setdata",
        "setdatabytes",
        "setdatastore",
        "setdatastorebytes",
        "setdatastorepayload",
        "updatedatastore",
        "updatedatastorebytes",
        "updatedatastorepayload",
        "updatedsbytes",
        "updatedspayload",
        "programdatastore",
        "storedata",
        "storeuserdata",
        "storedatastore",
        "storedatastorebytes",
        "storedatastorepayload",
        "storeds",
        "storedsbytes",
        "storedspayload",
        "savedata",
        "savedatablock",
        "savedatachunk",
        "savedatawindow",
        "saveuserdata",
        "savedatastore",
        "savedatastorebytes",
        "savedatastorepayload",
        "saveds",
        "savedsbytes",
        "savedspayload",
        "programdatastore",
        "setdatablock",
        "setdatachunk",
        "setdatasegment",
        "setdatarange",
        "setdataslice",
        "setdatawindow",
        "writedatastorepayload",
        "setdatapayload",
        "writedatablock",
        "writedatachunk",
        "writedatasegment",
        "writedatarange",
        "writedataslice",
        "writedatawindow",
        "writeuserpayload",
        "writeuserdatablock",
        "writeuserdatachunk",
        "writeuserdataslice",
        "saveuserpayload",
        "storeuserpayload",
        "storeuserdatablock",
        "storeuserdatachunk",
        "storeuserdataslice",
        "setuserpayload",
        "writebytes",
        "putbytes",
        "storebytes",
        "storedatablock",
        "storedatachunk",
        "storedatasegment",
        "storedatarange",
        "storedataslice",
        "storedatawindow",
        "setbytes",
        "setdsbytes",
        "writeds",
        "writedsbytes",
        "writedatastore",
        "writedatastorebytes",
        "programdatastore",
        "programdatastorebytes",
        "programdspayload",
        "writeuserdata",
        "writeuserdatastore",
        "setuserdata",
        "revert",
        "revertadminsp",
        "revertdrive",
        "factoryreset",
        "revertlockingsp",
        "revertlocking",
        "advanceKey",
        "advancekey",
        "advKey",
        "advkey",
        "advanceReEncryptKey",
        "advancereencryptkey",
        "commitReEncryptKey",
        "commitreencryptkey",
        "retIdle",
        "retidle",
        "returnIdle",
        "returnidle",
        "returnToIdle",
        "returntoidle",
        "stopReEncrypt",
        "stopreencrypt",
        "cancelReEncrypt",
        "cancelreencrypt",
    }
    boolean_getter_aliases = {
        "getauthority",
        "getauthorityenabled",
        "getportlocked",
        "getportlock",
        "getreadlockenabled",
        "isreadlockenabled",
        "readlockenabled",
        "readlockingenabled",
        "isreadlockingenabled",
        "getrangereadlockenabled",
        "israngereadlockenabled",
        "getrangereadlockingenabled",
        "israngereadlockingenabled",
        "getwritelockenabled",
        "iswritelockenabled",
        "writelockenabled",
        "writelockingenabled",
        "iswritelockingenabled",
        "getrangewritelockenabled",
        "israngewritelockenabled",
        "getrangewritelockingenabled",
        "israngewritelockingenabled",
        "getreadlocked",
        "isreadlocked",
        "readlocked",
        "getrangereadlocked",
        "israngereadlocked",
        "isreadlockset",
        "getreadlockstate",
        "getrangereadlockstate",
        "getwritelocked",
        "iswritelocked",
        "writelocked",
        "getrangewritelocked",
        "israngewritelocked",
        "iswritelockset",
        "getwritelockstate",
        "getrangewritelockstate",
        "getuserenabled",
        "userenabled",
        "isauthorityenabled",
        "authorityenabled",
        "getuserstate",
        "islockonresetenabled",
        "israngelockonresetenabled",
        "islockingrangelockonresetenabled",
        "lockonresetenabled",
        "rangelockonresetenabled",
        "haslockonreset",
        "isportlocked",
        "isportlock",
        "portlocked",
        "isreencrypting",
        "isuserenabled",
    }
    found_return, raw_return = _high_level_return_value(out)
    explicit_status_present = _dict_lookup(
        out,
        "status_codes",
        "statusCodes",
        "StatusCodes",
        "status_code",
        "statusCode",
        "StatusCode",
        "code",
        "Code",
        "rc",
        "RC",
        "returnCode",
        "ReturnCode",
        "status",
        "Status",
    )[0] or _dict_lookup(
        inp,
        "status_codes",
        "statusCodes",
        "StatusCodes",
        "status_code",
        "statusCode",
        "StatusCode",
        "code",
        "Code",
        "rc",
        "RC",
        "returnCode",
        "ReturnCode",
        "status",
        "Status",
    )[0]
    if function_alias == "authenticate" and found_return and isinstance(raw_return, bool) and not explicit_status_present:
        return SUCCESS
    explicit = _normalize_status(_output_status_value(out, inp))
    if explicit == "PASS":
        return SUCCESS
    if explicit in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL}:
        return explicit
    if found_return and isinstance(raw_return, dict):
        nested_explicit = _normalize_status(
            _mapping_value(
                raw_return,
                "status_codes",
                "statusCodes",
                "StatusCodes",
                "status_code",
                "statusCode",
                "StatusCode",
                "code",
                "Code",
                "rc",
                "RC",
                "returnCode",
                "ReturnCode",
                "status",
                "Status",
            )
        )
        if nested_explicit == "PASS":
            return SUCCESS
        if nested_explicit in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL}:
            return nested_explicit
        nested_error_flag = _mapping_value(
            raw_return,
            "error",
            "Error",
            "err",
            "Err",
            "hasError",
            "HasError",
            "isError",
            "IsError",
            "failed",
            "Failed",
            "failure",
            "Failure",
        )
        parsed_nested_error_flag = _optional_bool(nested_error_flag)
        if parsed_nested_error_flag is not None:
            return FAIL if parsed_nested_error_flag else SUCCESS
        if function_alias in mutating_wrapper_aliases:
            nested_denied_flag = _mapping_value(
                raw_return,
                "denied",
                "Denied",
                "unauthorized",
                "Unauthorized",
                "notAuthorized",
                "NotAuthorized",
                "not_authorized",
                "authFailed",
                "AuthFailed",
                "authorizationFailed",
                "AuthorizationFailed",
                "rejected",
                "Rejected",
                "blocked",
                "Blocked",
                "cancelled",
                "Cancelled",
                "canceled",
                "Canceled",
                "forbidden",
                "Forbidden",
                "permissionDenied",
                "PermissionDenied",
                "accessDenied",
                "AccessDenied",
            )
            parsed_nested_denied_flag = _optional_bool(nested_denied_flag)
            if parsed_nested_denied_flag:
                return NOT_AUTHORIZED
            nested_authorized_flag = _mapping_value(
                raw_return,
                "authorized",
                "Authorized",
                "allowed",
                "Allowed",
                "accepted",
                "Accepted",
                "approved",
                "Approved",
            )
            parsed_nested_authorized_flag = _optional_bool(nested_authorized_flag)
            if parsed_nested_authorized_flag is False:
                return NOT_AUTHORIZED
            nested_success_flag = _mapping_value(
                raw_return,
                "ok",
                "OK",
                "success",
                "Success",
                "passed",
                "Passed",
                "isSuccess",
                "IsSuccess",
                "is_ok",
                "isOk",
                "IsOk",
                "succeeded",
                "Succeeded",
                "successFlag",
                "SuccessFlag",
            )
            parsed_nested_success_flag = _optional_bool(nested_success_flag)
            if parsed_nested_success_flag is not None:
                return SUCCESS if parsed_nested_success_flag else FAIL
            if parsed_nested_authorized_flag is True or parsed_nested_denied_flag is False:
                return SUCCESS
    error_flag = _mapping_value(out, "error", "Error", "err", "Err", "hasError", "HasError", "isError", "IsError", "failed", "Failed", "failure", "Failure")
    parsed_error_flag = _optional_bool(error_flag)
    if parsed_error_flag is not None:
        return FAIL if parsed_error_flag else SUCCESS
    if function_alias in mutating_wrapper_aliases:
        denied_flag = _mapping_value(
            out,
            "denied",
            "Denied",
            "unauthorized",
            "Unauthorized",
            "notAuthorized",
            "NotAuthorized",
            "not_authorized",
            "authFailed",
            "AuthFailed",
            "authorizationFailed",
            "AuthorizationFailed",
            "rejected",
            "Rejected",
            "blocked",
            "Blocked",
            "cancelled",
            "Cancelled",
            "canceled",
            "Canceled",
            "forbidden",
            "Forbidden",
            "permissionDenied",
            "PermissionDenied",
            "accessDenied",
            "AccessDenied",
        )
        parsed_denied_flag = _optional_bool(denied_flag)
        if parsed_denied_flag:
            return NOT_AUTHORIZED
        authorized_flag = _mapping_value(out, "authorized", "Authorized", "allowed", "Allowed", "accepted", "Accepted", "approved", "Approved")
        parsed_authorized_flag = _optional_bool(authorized_flag)
        if parsed_authorized_flag is False:
            return NOT_AUTHORIZED
        top_success_flag = _mapping_value(
            out,
            "ok",
            "OK",
            "success",
            "Success",
            "passed",
            "Passed",
            "isSuccess",
            "IsSuccess",
            "is_ok",
            "isOk",
            "IsOk",
            "succeeded",
            "Succeeded",
            "successFlag",
            "SuccessFlag",
        )
        parsed_top_success_flag = _optional_bool(top_success_flag)
        if parsed_top_success_flag is not None:
            return SUCCESS if parsed_top_success_flag else FAIL
        if parsed_authorized_flag is True or parsed_denied_flag is False:
            return SUCCESS
    authenticate_wrapper_aliases = {
        "authenticate",
        "checkuserpin",
        "verifyuserpin",
        "validateuserpin",
        "checkuserpassword",
        "verifyuserpassword",
        "validateuserpassword",
        "validatecredential",
        "checkpassphrase",
        "verifypassphrase",
        "validatepassphrase",
    }
    if function_alias in authenticate_wrapper_aliases and _return_bool(raw, credential_aliases=True) is not None and not explicit_status_present:
        return SUCCESS
    if found_return and function_alias in boolean_getter_aliases and isinstance(raw_return, bool) and not explicit_status_present:
        return SUCCESS
    lockinginfo_scalar_getter_aliases = {
        "getalignmentrequired",
        "readalignmentrequired",
        "fetchalignmentrequired",
        "queryalignmentrequired",
        "loadalignmentrequired",
        "isalignrequired",
        "isalignmentrequired",
        "getalignrequired",
        "getlogicalblocksize",
        "readlogicalblocksize",
        "fetchlogicalblocksize",
        "querylogicalblocksize",
        "loadlogicalblocksize",
        "getblocksize",
        "queryblocksize",
        "getalignmentgranularity",
        "readalignmentgranularity",
        "fetchalignmentgranularity",
        "queryalignmentgranularity",
        "loadalignmentgranularity",
        "getaligngranularity",
        "queryaligngranularity",
        "getlowestalignedlba",
        "readlowestalignedlba",
        "fetchlowestalignedlba",
        "querylowestalignedlba",
        "loadlowestalignedlba",
        "getlowestaligned",
        "querylowestaligned",
        "getmaxranges",
        "readmaxranges",
        "fetchmaxranges",
        "querymaxranges",
        "loadmaxranges",
        "getmaxlockingranges",
        "readmaxlockingranges",
        "fetchmaxlockingranges",
        "querymaxlockingranges",
        "loadmaxlockingranges",
        "getrangecount",
        "readrangecount",
        "fetchrangecount",
        "queryrangecount",
        "loadrangecount",
        "getlockingrangecount",
        "readlockingrangecount",
        "fetchlockingrangecount",
        "querylockingrangecount",
        "loadlockingrangecount",
        "getnumberofranges",
        "readnumberofranges",
        "fetchnumberofranges",
        "querynumberofranges",
        "loadnumberofranges",
        "getnumranges",
        "readnumranges",
        "fetchnumranges",
        "querynumranges",
        "loadnumranges",
        "getrangelimit",
        "readrangelimit",
        "fetchrangelimit",
        "queryrangelimit",
        "loadrangelimit",
        "getlockingrangelimit",
        "readlockingrangelimit",
        "fetchlockingrangelimit",
        "querylockingrangelimit",
        "loadlockingrangelimit",
    }
    if found_return and function_alias in lockinginfo_scalar_getter_aliases and raw_return is not None and not explicit_status_present:
        return SUCCESS
    if (
        found_return
        and function_alias in bool_return_mutating_wrapper_aliases
        and isinstance(raw_return, (dict, list, tuple))
        and not raw_return
    ):
        return FAIL
    if found_return and isinstance(raw_return, (dict, list, tuple)) and function_alias not in {"authenticate", "checkpin"}:
        return SUCCESS
    returned = _return_bool(raw)
    if returned is True:
        return SUCCESS
    if returned is False:
        return FAIL
    if found_return and isinstance(raw_return, (dict, list, tuple)):
        return SUCCESS
    if found_return and raw_return is None:
        return FAIL
    if found_return and raw_return is not False:
        return SUCCESS
    return explicit


def _high_level_event(raw: dict[str, Any], inp: dict[str, Any], out: dict[str, Any]) -> Event | None:
    function_name = _function_name(inp)
    function_alias = _function_alias(function_name)
    args = _function_args(inp)
    kwargs = _function_kwargs(inp)
    status = _high_level_status(raw, out, inp)
    found_return, raw_return = _high_level_return_value(out)
    boolean_getter_aliases = {
        "getauthority",
        "getportlocked",
        "getreadlockenabled",
        "isreadlockenabled",
        "getreadlockenabledrange",
        "getreadlockenabledforrange",
        "isreadlockenabledrange",
        "isreadlockenabledforrange",
        "getwritelockenabled",
        "iswritelockenabled",
        "getwritelockenabledrange",
        "getwritelockenabledforrange",
        "iswritelockenabledrange",
        "iswritelockenabledforrange",
        "getreadlocked",
        "isreadlocked",
        "getreadlockedrange",
        "getreadlockedforrange",
        "isreadlockedrange",
        "isreadlockedforrange",
        "getwritelocked",
        "iswritelocked",
        "getwritelockedrange",
        "getwritelockedforrange",
        "iswritelockedrange",
        "iswritelockedforrange",
        "getuserenabled",
        "islockonresetenabled",
        "isportlocked",
        "isportlock",
        "portlocked",
        "isreencrypting",
        "isuserenabled",
    }
    if (
        found_return
        and _normalize_status(_output_status_value(out, inp)) not in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL}
        and (
            (function_alias in boolean_getter_aliases and raw_return is False)
            or (function_alias in {"authenticate", "checkuserpin", "verifyuserpin", "validateuserpin", "checkuserpassword", "verifyuserpassword", "validateuserpassword", "validatecredential", "checkpassphrase", "verifypassphrase", "validatepassphrase"} and isinstance(raw_return, bool))
            or (
                function_alias
                in {
                    "getreadlockenabled",
                    "isreadlockenabled",
                    "readlockenabled",
                    "readlockingenabled",
                    "isreadlockingenabled",
                    "getrangereadlockenabled",
                    "getreadlockenabledrange",
                    "getreadlockenabledforrange",
                    "israngereadlockenabled",
                    "isreadlockenabledrange",
                    "isreadlockenabledforrange",
                    "getrangereadlockingenabled",
                    "israngereadlockingenabled",
                    "getwritelockenabled",
                    "iswritelockenabled",
                    "writelockenabled",
                    "writelockingenabled",
                    "iswritelockingenabled",
                    "getrangewritelockenabled",
                    "getwritelockenabledrange",
                    "getwritelockenabledforrange",
                    "israngewritelockenabled",
                    "iswritelockenabledrange",
                    "iswritelockenabledforrange",
                    "getrangewritelockingenabled",
                    "israngewritelockingenabled",
                    "getreadlocked",
                    "isreadlocked",
                    "readlocked",
                    "getrangereadlocked",
                    "getreadlockedrange",
                    "getreadlockedforrange",
                    "israngereadlocked",
                    "isreadlockedrange",
                    "isreadlockedforrange",
                    "isreadlockset",
                    "getreadlockstate",
                    "getrangereadlockstate",
                    "getwritelocked",
                    "iswritelocked",
                    "writelocked",
                    "getrangewritelocked",
                    "getwritelockedrange",
                    "getwritelockedforrange",
                    "israngewritelocked",
                    "iswritelockedrange",
                    "iswritelockedforrange",
                    "iswritelockset",
                    "getwritelockstate",
                    "getrangewritelockstate",
                }
                and isinstance(raw_return, bool)
            )
            or (function_alias in {"getrange", "getport", "getpskentry", "readdata"} and raw_return is None)
        )
    ):
        status = SUCCESS

    def authas(default_auth: Any = None, index: int = 2) -> Any:
        value = _arg_or_kw(args, kwargs, index, "authAs", "AuthAs", "auth_as", "authAS")
        return value if value is not None else default_auth

    def range_arg(index: int) -> Any:
        if len(args) > index and isinstance(args[index], dict):
            found, value = _dict_lookup(
                args[index],
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "bandNo",
                "band_no",
                "lockingRange",
                "locking_range",
                "lockingRangeID",
                "lockingRangeId",
                "locking_range_id",
                "rangeNumber",
                "range_number",
                "rangeIndex",
                "range_index",
                "rangeName",
                "range_name",
                "rangeUid",
                "rangeUID",
                "range_uid",
                "name",
                "Name",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
            if found:
                return value
        return _arg_or_kw(
            args,
            kwargs,
            index,
            "rangeNo",
            "range",
            "Range",
            "range_no",
            "rangeID",
            "rangeId",
            "range_id",
            "band",
            "Band",
            "bandID",
            "bandId",
            "band_id",
            "bandName",
            "band_name",
            "bandNo",
            "band_no",
            "lockingRange",
            "locking_range",
            "lockingRangeID",
            "lockingRangeId",
            "locking_range_id",
            "rangeNumber",
            "range_number",
            "rangeIndex",
            "range_index",
            "rangeName",
            "range_name",
            "rangeUid",
            "rangeUID",
            "range_uid",
            "name",
            "Name",
            "id",
            "ID",
            "uid",
            "UID",
            "obj",
            "object",
            "Object",
            "target",
            "Target",
        )

    def top_level_range_arg() -> Any:
        return _mapping_value(
            kwargs,
            "rangeNo",
            "range",
            "Range",
            "range_no",
            "rangeID",
            "rangeId",
            "range_id",
            "band",
            "Band",
            "bandID",
            "bandId",
            "band_id",
            "bandName",
            "band_name",
            "bandNo",
            "band_no",
            "lockingRange",
            "locking_range",
            "lockingRangeID",
            "lockingRangeId",
            "locking_range_id",
            "rangeNumber",
            "range_number",
            "rangeIndex",
            "range_index",
            "rangeName",
            "range_name",
            "rangeUid",
            "rangeUID",
            "range_uid",
            "name",
            "Name",
            "id",
            "ID",
            "uid",
            "UID",
            "obj",
            "object",
            "Object",
            "target",
            "Target",
        )

    def range_like(value: Any) -> bool:
        if isinstance(value, bool):
            return False
        if _parse_int(value) is not None:
            return True
        symbol = _normalize_name(value)
        return _range_id_from_symbol(symbol) is not None

    def authority_like(value: Any) -> bool:
        return _authority_from_value(value) is not None

    def byte_start_arg(index: int) -> Any:
        return _arg_or_kw(
            args,
            kwargs,
            index,
            "startRow",
            "StartRow",
            "startrow",
            "row",
            "Row",
            "offset",
            "Offset",
            "byteOffset",
            "byte_offset",
            "startOffset",
            "start_offset",
            "startByte",
            "start_byte",
            "byteIndex",
            "byte_index",
            "bytePosition",
            "byte_position",
            "index",
            "Index",
            "position",
            "Position",
            "pos",
            "Pos",
            "address",
            "Address",
            "start",
            "Start",
        )

    def readdata_start_arg() -> Any:
        if len(args) > 1:
            parsed = _parse_int(args[1])
            if parsed is not None and not isinstance(args[1], bool):
                return args[1]
        return byte_start_arg(2)

    def byte_end_arg(index: int, start: Any = None) -> Any:
        explicit_end = _arg_or_kw(
            args,
            kwargs,
            index,
            "endRow",
            "EndRow",
            "endrow",
            "endIndex",
            "end_index",
            "endPosition",
            "end_position",
            "end",
            "End",
        )
        if explicit_end is not None:
            return explicit_end
        length = _mapping_value(
            kwargs,
            "length",
            "Length",
            "len",
            "Len",
            "size",
            "Size",
            "count",
            "Count",
            "numBytes",
            "num_bytes",
            "nBytes",
            "nbytes",
            "byteCount",
            "byte_count",
            "byteLength",
            "byte_length",
            "dataLength",
            "data_length",
            "readSize",
            "read_size",
            "windowSize",
            "window_size",
            "bytesToRead",
            "bytes_to_read",
            "readLength",
            "read_length",
            "numBytesToRead",
            "num_bytes_to_read",
            "countBytes",
            "count_bytes",
        )
        parsed_start = _parse_int(start)
        parsed_length = _parse_int(length)
        if parsed_start is not None and parsed_length is not None and parsed_length > 0:
            return parsed_start + parsed_length - 1
        return None

    def cpin_target(auth: Any, explicit_obj: Any = None) -> Any:
        if explicit_obj is not None:
            return explicit_obj
        authority = _authority_from_value(auth)
        if authority == "SID":
            return "C_PIN_SID"
        if authority == "MSID":
            return "C_PIN_MSID"
        if authority == "EraseMaster":
            return "C_PIN_EraseMaster"
        if authority and re.fullmatch(r"(Admin|User|BandMaster)\d+", authority):
            return f"C_PIN_{authority}"
        return auth

    def auth_arg_value(index: int = 0) -> Any:
        return _arg_or_kw(
            args,
            kwargs,
            index,
            "auth",
            "Auth",
            "authority",
            "Authority",
            "user",
            "User",
            "userId",
            "userID",
            "user_id",
            "uid",
            "UID",
            "authorityId",
            "authorityID",
            "authority_id",
            "cpin",
            "C_PIN",
            "cPin",
            "obj",
            "object",
            "Object",
            "target",
            "Target",
            "identity",
            "Identity",
            "username",
            "Username",
            "pinId",
            "pin_id",
            "PINID",
            "credentialId",
            "credential_id",
            "CredentialID",
            "authId",
            "auth_id",
            "AuthID",
            "name",
            "Name",
        )

    if function_alias in {
        "getacl",
        "readacl",
        "fetchacl",
        "queryacl",
        "listacl",
        "getobjectacl",
        "getmethodacl",
        "getassociationacl",
        "getaclforobject",
        "readaclforobject",
        "fetchaclforobject",
        "queryaclforobject",
        "loadaclforobject",
        "getaclformethod",
        "readaclformethod",
        "fetchaclformethod",
        "queryaclformethod",
        "loadaclformethod",
        "getobjectmethodacl",
        "readobjectmethodacl",
        "fetchobjectmethodacl",
        "queryobjectmethodacl",
        "loadobjectmethodacl",
        "getmethodaccesscontrol",
        "readmethodaccesscontrol",
        "fetchmethodaccesscontrol",
        "querymethodaccesscontrol",
        "loadmethodaccesscontrol",
        "getobjectaccesscontrol",
        "readobjectaccesscontrol",
        "fetchobjectaccesscontrol",
        "queryobjectaccesscontrol",
        "loadobjectaccesscontrol",
        "getassociationaccesscontrol",
        "readassociationaccesscontrol",
        "fetchassociationaccesscontrol",
        "queryassociationaccesscontrol",
        "loadassociationaccesscontrol",
        "getaccesscontrolforobject",
        "readaccesscontrolforobject",
        "fetchaccesscontrolforobject",
        "queryaccesscontrolforobject",
        "loadaccesscontrolforobject",
        "getaccesscontrolformethod",
        "readaccesscontrolformethod",
        "fetchaccesscontrolformethod",
        "queryaccesscontrolformethod",
        "loadaccesscontrolformethod",
        "readassociationacl",
        "fetchassociationacl",
        "queryassociationacl",
        "listassociationacl",
        "getaccesscontrollist",
        "readaccesscontrollist",
        "fetchaccesscontrollist",
        "queryaccesscontrollist",
        "listaccesscontrollist",
        "getacelist",
        "readacelist",
        "queryacelist",
        "loadacelist",
        "getaclentries",
        "readaclentries",
        "readaceentries",
        "queryaclentries",
        "queryaceentries",
        "loadaclentries",
        "loadaceentries",
        "fetchaclentries",
        "fetchaceentries",
        "fetchacelist",
        "readobjectacl",
        "fetchobjectacl",
        "queryobjectacl",
        "readmethodacl",
        "fetchmethodacl",
        "querymethodacl",
        "listaces",
        "listaceentries",
        "addace",
        "addaceentry",
        "addaclentry",
        "addaccesscontrolentry",
        "addacetoacl",
        "addaccesscontrolace",
        "appendace",
        "appendaclentry",
        "appendaccesscontrolentry",
        "appendacetoacl",
        "grantace",
        "grantacl",
        "grantaccesscontrolentry",
        "grantacetoacl",
        "removeace",
        "removeaceentry",
        "removeaccesscontrolentry",
        "removeacefromacl",
        "removeaccesscontrolace",
        "deleteace",
        "deleteaclentry",
        "deleteaccesscontrolentry",
        "deleteacefromacl",
        "dropace",
        "revokeace",
        "revokeacl",
        "revokeaccesscontrolentry",
        "revokeacefromacl",
        "setacl",
        "replaceacl",
        "updateacl",
        "replaceaccesscontrolacl",
        "updateaccesscontrolacl",
        "putaccesscontrollist",
        "updateaccesscontrollist",
        "setaccesscontrol",
        "setaccesscontrollist",
        "replaceaccesscontrollist",
        "setobjectacl",
        "replaceobjectacl",
        "updateobjectacl",
        "replacemethodacl",
        "updatemethodacl",
        "setassociationacl",
        "addaclforobject",
        "appendaclforobject",
        "grantaclforobject",
        "addaceforobject",
        "appendaceforobject",
        "grantaceforobject",
        "addaclformethod",
        "appendaclformethod",
        "grantaclformethod",
        "addaceformethod",
        "appendaceformethod",
        "grantaceformethod",
        "addobjectmethodace",
        "appendobjectmethodace",
        "grantobjectmethodace",
        "addobjectaccesscontrolentry",
        "grantobjectaccesscontrolentry",
        "appendobjectaccesscontrolentry",
        "addmethodaccesscontrolentry",
        "grantmethodaccesscontrolentry",
        "appendmethodaccesscontrolentry",
        "removeaclforobject",
        "deleteaclforobject",
        "revokeaclforobject",
        "removeaceforobject",
        "deleteaceforobject",
        "revokeaceforobject",
        "removeaclformethod",
        "deleteaclformethod",
        "revokeaclformethod",
        "removeaceformethod",
        "deleteaceformethod",
        "revokeaceformethod",
        "removeobjectmethodace",
        "deleteobjectmethodace",
        "revokeobjectmethodace",
        "removeobjectaccesscontrolentry",
        "revokeobjectaccesscontrolentry",
        "deleteobjectaccesscontrolentry",
        "removemethodaccesscontrolentry",
        "revokemethodaccesscontrolentry",
        "deletemethodaccesscontrolentry",
        "setaclforobject",
        "replaceaclforobject",
        "updateaclforobject",
        "putaclforobject",
        "setaclformethod",
        "replaceaclformethod",
        "updateaclformethod",
        "putaclformethod",
        "setobjectmethodacl",
        "replaceobjectmethodacl",
        "updateobjectmethodacl",
        "putobjectmethodacl",
        "setobjectaccesscontrol",
        "replaceobjectaccesscontrol",
        "updateobjectaccesscontrol",
        "putobjectaccesscontrol",
        "setmethodaccesscontrol",
        "replacemethodaccesscontrol",
        "updatemethodaccesscontrol",
        "putmethodaccesscontrol",
        "deletemethod",
    }:
        method = {
            "getacl": "GetACL",
            "readacl": "GetACL",
            "fetchacl": "GetACL",
            "queryacl": "GetACL",
            "listacl": "GetACL",
            "getobjectacl": "GetACL",
            "getmethodacl": "GetACL",
            "getassociationacl": "GetACL",
            "getaclforobject": "GetACL",
            "readaclforobject": "GetACL",
            "fetchaclforobject": "GetACL",
            "queryaclforobject": "GetACL",
            "loadaclforobject": "GetACL",
            "getaclformethod": "GetACL",
            "readaclformethod": "GetACL",
            "fetchaclformethod": "GetACL",
            "queryaclformethod": "GetACL",
            "loadaclformethod": "GetACL",
            "getobjectmethodacl": "GetACL",
            "readobjectmethodacl": "GetACL",
            "fetchobjectmethodacl": "GetACL",
            "queryobjectmethodacl": "GetACL",
            "loadobjectmethodacl": "GetACL",
            "getmethodaccesscontrol": "GetACL",
            "readmethodaccesscontrol": "GetACL",
            "fetchmethodaccesscontrol": "GetACL",
            "querymethodaccesscontrol": "GetACL",
            "loadmethodaccesscontrol": "GetACL",
            "getobjectaccesscontrol": "GetACL",
            "readobjectaccesscontrol": "GetACL",
            "fetchobjectaccesscontrol": "GetACL",
            "queryobjectaccesscontrol": "GetACL",
            "loadobjectaccesscontrol": "GetACL",
            "getassociationaccesscontrol": "GetACL",
            "readassociationaccesscontrol": "GetACL",
            "fetchassociationaccesscontrol": "GetACL",
            "queryassociationaccesscontrol": "GetACL",
            "loadassociationaccesscontrol": "GetACL",
            "getaccesscontrolforobject": "GetACL",
            "readaccesscontrolforobject": "GetACL",
            "fetchaccesscontrolforobject": "GetACL",
            "queryaccesscontrolforobject": "GetACL",
            "loadaccesscontrolforobject": "GetACL",
            "getaccesscontrolformethod": "GetACL",
            "readaccesscontrolformethod": "GetACL",
            "fetchaccesscontrolformethod": "GetACL",
            "queryaccesscontrolformethod": "GetACL",
            "loadaccesscontrolformethod": "GetACL",
            "readassociationacl": "GetACL",
            "fetchassociationacl": "GetACL",
            "queryassociationacl": "GetACL",
            "listassociationacl": "GetACL",
            "getaccesscontrollist": "GetACL",
            "readaccesscontrollist": "GetACL",
            "fetchaccesscontrollist": "GetACL",
            "queryaccesscontrollist": "GetACL",
            "listaccesscontrollist": "GetACL",
            "getacelist": "GetACL",
            "readacelist": "GetACL",
            "queryacelist": "GetACL",
            "loadacelist": "GetACL",
            "getaclentries": "GetACL",
            "readaclentries": "GetACL",
            "readaceentries": "GetACL",
            "queryaclentries": "GetACL",
            "queryaceentries": "GetACL",
            "loadaclentries": "GetACL",
            "loadaceentries": "GetACL",
            "fetchaclentries": "GetACL",
            "fetchaceentries": "GetACL",
            "fetchacelist": "GetACL",
            "readobjectacl": "GetACL",
            "fetchobjectacl": "GetACL",
            "queryobjectacl": "GetACL",
            "readmethodacl": "GetACL",
            "fetchmethodacl": "GetACL",
            "querymethodacl": "GetACL",
            "listaces": "GetACL",
            "listaceentries": "GetACL",
            "addace": "AddACE",
            "addaceentry": "AddACE",
            "addaclentry": "AddACE",
            "addaccesscontrolentry": "AddACE",
            "addacetoacl": "AddACE",
            "addaccesscontrolace": "AddACE",
            "appendace": "AddACE",
            "appendaclentry": "AddACE",
            "appendaccesscontrolentry": "AddACE",
            "appendacetoacl": "AddACE",
            "grantace": "AddACE",
            "grantacl": "AddACE",
            "grantaccesscontrolentry": "AddACE",
            "grantacetoacl": "AddACE",
            "removeace": "RemoveACE",
            "removeaceentry": "RemoveACE",
            "removeaccesscontrolentry": "RemoveACE",
            "removeacefromacl": "RemoveACE",
            "removeaccesscontrolace": "RemoveACE",
            "deleteace": "RemoveACE",
            "deleteaclentry": "RemoveACE",
            "deleteaccesscontrolentry": "RemoveACE",
            "deleteacefromacl": "RemoveACE",
            "dropace": "RemoveACE",
            "revokeace": "RemoveACE",
            "revokeacl": "RemoveACE",
            "revokeaccesscontrolentry": "RemoveACE",
            "revokeacefromacl": "RemoveACE",
            "setacl": "SetACL",
            "replaceacl": "SetACL",
            "updateacl": "SetACL",
            "replaceaccesscontrolacl": "SetACL",
            "updateaccesscontrolacl": "SetACL",
            "putaccesscontrollist": "SetACL",
            "updateaccesscontrollist": "SetACL",
            "setaccesscontrol": "SetACL",
            "setaccesscontrollist": "SetACL",
            "replaceaccesscontrollist": "SetACL",
            "setobjectacl": "SetACL",
            "replaceobjectacl": "SetACL",
            "updateobjectacl": "SetACL",
            "replacemethodacl": "SetACL",
            "updatemethodacl": "SetACL",
            "setassociationacl": "SetACL",
            "addaclforobject": "AddACE",
            "appendaclforobject": "AddACE",
            "grantaclforobject": "AddACE",
            "addaceforobject": "AddACE",
            "appendaceforobject": "AddACE",
            "grantaceforobject": "AddACE",
            "addaclformethod": "AddACE",
            "appendaclformethod": "AddACE",
            "grantaclformethod": "AddACE",
            "addaceformethod": "AddACE",
            "appendaceformethod": "AddACE",
            "grantaceformethod": "AddACE",
            "addobjectmethodace": "AddACE",
            "appendobjectmethodace": "AddACE",
            "grantobjectmethodace": "AddACE",
            "addobjectaccesscontrolentry": "AddACE",
            "grantobjectaccesscontrolentry": "AddACE",
            "appendobjectaccesscontrolentry": "AddACE",
            "addmethodaccesscontrolentry": "AddACE",
            "grantmethodaccesscontrolentry": "AddACE",
            "appendmethodaccesscontrolentry": "AddACE",
            "removeaclforobject": "RemoveACE",
            "deleteaclforobject": "RemoveACE",
            "revokeaclforobject": "RemoveACE",
            "removeaceforobject": "RemoveACE",
            "deleteaceforobject": "RemoveACE",
            "revokeaceforobject": "RemoveACE",
            "removeaclformethod": "RemoveACE",
            "deleteaclformethod": "RemoveACE",
            "revokeaclformethod": "RemoveACE",
            "removeaceformethod": "RemoveACE",
            "deleteaceformethod": "RemoveACE",
            "revokeaceformethod": "RemoveACE",
            "removeobjectmethodace": "RemoveACE",
            "deleteobjectmethodace": "RemoveACE",
            "revokeobjectmethodace": "RemoveACE",
            "removeobjectaccesscontrolentry": "RemoveACE",
            "revokeobjectaccesscontrolentry": "RemoveACE",
            "deleteobjectaccesscontrolentry": "RemoveACE",
            "removemethodaccesscontrolentry": "RemoveACE",
            "revokemethodaccesscontrolentry": "RemoveACE",
            "deletemethodaccesscontrolentry": "RemoveACE",
            "setaclforobject": "SetACL",
            "replaceaclforobject": "SetACL",
            "updateaclforobject": "SetACL",
            "putaclforobject": "SetACL",
            "setaclformethod": "SetACL",
            "replaceaclformethod": "SetACL",
            "updateaclformethod": "SetACL",
            "putaclformethod": "SetACL",
            "setobjectmethodacl": "SetACL",
            "replaceobjectmethodacl": "SetACL",
            "updateobjectmethodacl": "SetACL",
            "putobjectmethodacl": "SetACL",
            "setobjectaccesscontrol": "SetACL",
            "replaceobjectaccesscontrol": "SetACL",
            "updateobjectaccesscontrol": "SetACL",
            "putobjectaccesscontrol": "SetACL",
            "setmethodaccesscontrol": "SetACL",
            "replacemethodaccesscontrol": "SetACL",
            "updatemethodaccesscontrol": "SetACL",
            "putmethodaccesscontrol": "SetACL",
            "deletemethod": "DeleteMethod",
        }[function_alias]
        invoking_aliases = (
            "InvokingID",
            "invokingID",
            "invokingId",
            "invoking_id",
            "InvokingUID",
            "invokingUID",
            "invokingUid",
            "invoking_uid",
            "invoking",
            "Invoking",
            "invokingObject",
            "InvokingObject",
            "invokingObjectID",
            "InvokingObjectID",
            "invokingObjectId",
            "InvokingObjectId",
            "invoking_object_id",
            "invokingObjectUID",
            "InvokingObjectUID",
            "invokingObjectUid",
            "InvokingObjectUid",
            "invoking_object_uid",
            "object",
            "Object",
            "objectID",
            "ObjectID",
            "objectId",
            "ObjectId",
            "object_id",
            "objectUID",
            "ObjectUID",
            "objectUid",
            "ObjectUid",
            "object_uid",
            "target",
            "Target",
            "targetID",
            "TargetID",
            "targetId",
            "TargetId",
            "target_id",
            "targetUID",
            "TargetUID",
            "targetUid",
            "TargetUid",
            "target_uid",
            "obj",
            "Obj",
            "uid",
            "UID",
        )
        method_aliases = (
            "MethodID",
            "methodID",
            "methodId",
            "MethodId",
            "method_id",
            "MethodUID",
            "methodUID",
            "methodUid",
            "method_uid",
            "method",
            "Method",
            "methodName",
            "MethodName",
            "method_name",
            "operation",
            "Operation",
            "operationID",
            "OperationID",
            "operationId",
            "OperationId",
            "operation_id",
            "operationUID",
            "OperationUID",
            "operationUid",
            "OperationUid",
            "operation_uid",
            "operationName",
            "OperationName",
            "operation_name",
            "op",
            "Op",
            "action",
            "Action",
            "actionID",
            "ActionID",
            "actionId",
            "ActionId",
            "action_id",
            "actionUID",
            "ActionUID",
            "actionUid",
            "ActionUid",
            "action_uid",
            "targetMethod",
            "TargetMethod",
            "target_method",
            "targetMethodID",
            "TargetMethodID",
            "targetMethodId",
            "TargetMethodId",
            "target_method_id",
            "targetMethodUID",
            "TargetMethodUID",
            "targetMethodUid",
            "TargetMethodUid",
            "target_method_uid",
            "actionName",
            "ActionName",
            "action_name",
        )
        invoking_id = _arg_or_kw(args, kwargs, 0, *invoking_aliases)
        method_id = _arg_or_kw(args, kwargs, 1, *method_aliases)
        acl_payload_aliases = (
            "required",
            "Required",
            "required_args",
            "requiredArgs",
            "RequiredArgs",
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "aclRequest",
            "ACLRequest",
            "acl_request",
            "accessControlRequest",
            "AccessControlRequest",
        )
        acl_payload = _mapping_value(kwargs, *acl_payload_aliases)
        if not isinstance(acl_payload, dict):
            acl_payload = _mapping_value(inp, *acl_payload_aliases)
        if not isinstance(acl_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            acl_payload = _mapping_value(args[0], *acl_payload_aliases)
            if not isinstance(acl_payload, dict):
                acl_payload = args[0]
        if invoking_id is None:
            invoking_id = _mapping_value(inp, *invoking_aliases)
        if invoking_id is None and isinstance(acl_payload, dict):
            invoking_id = _mapping_value(acl_payload, *invoking_aliases)
        if method_id is None:
            method_id = _mapping_value(inp, *method_aliases)
        if method_id is None and isinstance(acl_payload, dict):
            method_id = _mapping_value(acl_payload, *method_aliases)
        association_aliases = (
            "association",
            "Association",
            "assoc",
            "Assoc",
            "aclAssociation",
            "ACLAssociation",
            "accessControlAssociation",
            "AccessControlAssociation",
            "objectMethod",
            "ObjectMethod",
            "targetMethod",
            "TargetMethod",
            "target",
            "Target",
        )
        request_aliases = (
            "aclRequest",
            "ACLRequest",
            "acl_request",
            "accessControlRequest",
            "AccessControlRequest",
            "request",
            "Request",
        )
        if isinstance(acl_payload, dict):
            for _ in range(4):
                merged_acl_payload = dict(acl_payload)
                for envelope in acl_payload_aliases + association_aliases + request_aliases:
                    nested = _mapping_value(acl_payload, envelope)
                    if isinstance(nested, dict) and nested is not acl_payload:
                        merged_acl_payload.update(nested)
                if merged_acl_payload == acl_payload:
                    break
                acl_payload = merged_acl_payload
            if invoking_id is None or isinstance(invoking_id, dict):
                invoking_id = _mapping_value(acl_payload, *invoking_aliases)
            if method_id is None or isinstance(method_id, dict):
                method_id = _mapping_value(acl_payload, *method_aliases)

        def _acl_association_pair(value: Any) -> tuple[Any | None, Any | None]:
            if isinstance(value, dict):
                nested = _mapping_value(value, *(acl_payload_aliases + association_aliases + request_aliases))
                if nested is not None and nested is not value:
                    nested_invoking, nested_method = _acl_association_pair(nested)
                    if nested_invoking is not None or nested_method is not None:
                        return nested_invoking, nested_method
                return _mapping_value(value, *invoking_aliases), _mapping_value(value, *method_aliases)
            if isinstance(value, (list, tuple)) and len(value) >= 2:
                return value[0], value[1]
            return None, None

        if isinstance(invoking_id, dict):
            pair_invoking, pair_method = _acl_association_pair(invoking_id)
            if pair_invoking is not None:
                invoking_id = pair_invoking
            if method_id is None and pair_method is not None:
                method_id = pair_method
        for source in (kwargs, inp, acl_payload if isinstance(acl_payload, dict) else None):
            if not isinstance(source, dict):
                continue
            for alias_group in (association_aliases, request_aliases):
                candidate = _mapping_value(source, *alias_group)
                pair_invoking, pair_method = _acl_association_pair(candidate)
                if (invoking_id is None or isinstance(invoking_id, dict)) and pair_invoking is not None:
                    invoking_id = pair_invoking
                if (method_id is None or isinstance(method_id, dict)) and pair_method is not None:
                    method_id = pair_method
        required = {}
        if invoking_id is not None:
            required["InvokingID"] = invoking_id
        if method_id is not None:
            required["MethodID"] = method_id
        if method in {"AddACE", "RemoveACE"}:
            ace = _arg_or_kw(args, kwargs, 2, "ACE", "ace", "ACEUID", "aceUID", "ACEUid", "aceUid", "ACERef", "aceRef")
            if ace is None and isinstance(acl_payload, dict):
                ace = _mapping_value(
                    acl_payload,
                    "ACE",
                    "ace",
                    "ACEUID",
                    "aceUID",
                    "ACEUid",
                    "aceUid",
                    "ace_uid",
                    "ACERef",
                    "aceRef",
                    "ace_ref",
                    "aceReference",
                    "ACEReference",
                    "entry",
                    "Entry",
                )
            if ace is not None:
                required["ACE"] = ace
        if method == "SetACL":
            acl = _arg_or_kw(
                args,
                kwargs,
                2,
                "ACL",
                "acl",
                "AccessControlList",
                "accessControlList",
                "ACLUIDs",
                "aclUIDs",
                "aclUids",
                "acl_uids",
                "ACLRefs",
                "aclRefs",
                "acl_refs",
                "ACEs",
                "aces",
                "ACEUIDs",
                "aceUIDs",
                "aceUids",
                "ace_uids",
                "ACERefs",
                "aceRefs",
                "ace_refs",
            )
            if acl is None and isinstance(acl_payload, dict):
                acl = _mapping_value(
                    acl_payload,
                    "ACL",
                    "acl",
                    "AccessControlList",
                    "accessControlList",
                    "ACLUIDs",
                    "aclUIDs",
                    "aclUids",
                    "acl_uids",
                    "ACLRefs",
                    "aclRefs",
                    "acl_refs",
                    "ACEs",
                    "aces",
                    "ACEUIDs",
                    "aceUIDs",
                    "aceUids",
                    "ace_uids",
                    "ACERefs",
                    "aceRefs",
                    "ace_refs",
                )
            if acl is not None:
                required["ACL"] = acl
        return Event(
            raw=raw,
            kind="tcg_method",
            method=method,
            invoking_uid="0000000700000000",
            invoking_symbol="AccessControlTable",
            status=status,
            required=required,
            implicit_session=False,
            comid=_comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {
        "properties",
        "getproperties",
        "setproperties",
        "hostproperties",
        "sethostproperties",
        "gethostproperties",
        "updatehostproperties",
        "reporthostproperties",
        "negotiateproperties",
        "gettperproperties",
        "readtperproperties",
        "fetchtperproperties",
        "tperproperties",
        "queryproperties",
        "querytperproperties",
    }:
        optional: dict[str, Any] = {}
        comid = _arg_or_kw(args, kwargs, 0, "ComID", "comid", "comID", "ComId")
        properties_payload_aliases = (
            "HostProperties",
            "hostProperties",
            "HOSTPROPERTIES",
            "properties",
            "Properties",
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "request",
            "Request",
            "policy",
            "Policy",
            "config",
            "Config",
            "hostPropertiesRequest",
            "HostPropertiesRequest",
            "propertiesRequest",
            "PropertiesRequest",
            "sessionRequest",
            "SessionRequest",
            "comIdRequest",
            "ComIDRequest",
        )
        properties_payload = _mapping_value(kwargs, *properties_payload_aliases)
        if not isinstance(properties_payload, dict):
            properties_payload = _mapping_value(inp, *properties_payload_aliases)
        if not isinstance(properties_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            properties_payload = _mapping_value(args[0], *properties_payload_aliases)
            if not isinstance(properties_payload, dict):
                properties_payload = args[0]
        if isinstance(properties_payload, dict):
            for _ in range(2):
                merged_properties_payload = dict(properties_payload)
                for envelope in properties_payload_aliases:
                    found_envelope, nested_properties_payload = _dict_lookup(properties_payload, envelope)
                    if found_envelope and isinstance(nested_properties_payload, dict) and nested_properties_payload is not properties_payload:
                        merged_properties_payload.update(nested_properties_payload)
                if merged_properties_payload == properties_payload:
                    break
                properties_payload = merged_properties_payload
            nested_host = _mapping_value(properties_payload, "HostProperties", "hostProperties", "HOSTPROPERTIES")
            optional["HostProperties"] = nested_host if nested_host is not None else properties_payload
            if comid is None:
                comid = _mapping_value(properties_payload, "ComID", "comid", "comID", "ComId")
        elif function_alias in {"hostproperties", "sethostproperties", "gethostproperties", "updatehostproperties", "reporthostproperties", "negotiateproperties"}:
            optional["HostProperties"] = {}
        if comid is not None:
            optional["ComID"] = comid
        return Event(
            raw=raw,
            kind="tcg_method",
            method="Properties",
            invoking_uid="00000000000000FF",
            invoking_symbol="SessionManager",
            status=status,
            optional=optional,
            implicit_session=False,
            comid=_as_text(comid) if comid is not None else _comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {
        "endsession",
        "closesession",
        "stopsession",
        "terminatesession",
        "abortsesson",
        "abortsession",
        "cancelsession",
        "finishsession",
        "disconnectsession",
        "logout",
        "logOut",
        "endsp",
        "closesp",
        "stopsp",
        "terminatesp",
        "disconnectSP",
        "disconnectsp",
        "abortsp",
    }:
        method = "CloseSession" if function_alias in {"closesession", "closesp"} else "EndSession"
        required = {}
        host_session_id, sp_session_id = _session_ids_from_wrapper(args, kwargs, inp)
        if host_session_id is not None:
            required["HostSessionID"] = host_session_id
        if sp_session_id is not None:
            required["SPSessionID"] = sp_session_id
        return Event(
            raw=raw,
            kind="tcg_method",
            method=method,
            status=status,
            required=required,
            implicit_session=False,
            comid=_comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {"syncsession", "sessionsync", "resyncsession", "refreshsession", "synctrustedsession", "synctlssession"}:
        method = {
            "syncsession": "SyncSession",
            "sessionsync": "SyncSession",
            "resyncsession": "SyncSession",
            "refreshsession": "SyncSession",
            "synctrustedsession": "SyncTrustedSession",
            "synctlssession": "SyncTlsSession",
        }[function_alias]
        required = {}
        host_session_id, sp_session_id = _session_ids_from_wrapper(args, kwargs, inp)
        if host_session_id is not None:
            required["HostSessionID"] = host_session_id
        if sp_session_id is not None:
            required["SPSessionID"] = sp_session_id
        return Event(
            raw=raw,
            kind="tcg_method",
            method=method,
            status=status,
            required=required,
            implicit_session=False,
            comid=_comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {
        "starttrustedsession",
        "starttrusted",
        "begintrusted",
        "trustedstart",
        "opentrustedsession",
        "starttlssession",
        "starttls",
        "begintls",
        "tlsstart",
        "opentlssession",
    }:
        method = "StartTlsSession" if function_alias in {"starttlssession", "starttls", "begintls", "tlsstart", "opentlssession"} else "StartTrustedSession"
        required = {}
        host_session_id, sp_session_id = _session_ids_from_wrapper(args, kwargs, inp)
        if host_session_id is not None:
            required["HostSessionID"] = host_session_id
        if sp_session_id is not None:
            required["SPSessionID"] = sp_session_id
        return Event(
            raw=raw,
            kind="tcg_method",
            method=method,
            status=status,
            required=required,
            implicit_session=False,
            comid=_comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {"startsession", "opensession", "beginsession", "createsession", "connectsession", "startspsession", "openspsession", "beginspsession", "startsp", "opensp", "startadminsession", "beginadminsession", "openadminsession", "createadminsession", "startadminsp", "openadminsp", "startlockingsession", "beginlockingsession", "openlockingsession", "startlockingsp", "openlockingsp"}:
        raw_args_section = _mapping_value(inp, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
        if isinstance(raw_args_section, dict) and (
            _mapping_section(raw_args_section, "required", "Required")
            or _mapping_section(raw_args_section, "optional", "Optional")
        ):
            return None
        spid = _arg_or_kw(args, kwargs, 0, "SPID", "spid", "spID", "sp", "SP", "securityProvider", "security_provider")
        if spid is None and function_alias in {"startadminsession", "beginadminsession", "openadminsession", "createadminsession", "startadminsp", "openadminsp"}:
            spid = "AdminSP"
        if spid is None and function_alias in {"startlockingsession", "beginlockingsession", "openlockingsession", "startlockingsp", "openlockingsp"}:
            spid = "LockingSP"
        auth = auth_arg_value(1)
        if auth is None:
            auth = _mapping_value(kwargs, "HostSigningAuthority", "hostSigningAuthority", "authAs", "AuthAs", "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "username", "Username")
        challenge = _arg_or_kw(
            args,
            kwargs,
            2,
            "HostChallenge",
            "hostChallenge",
            "challenge",
            "Challenge",
            "password",
            "Password",
            "pin",
            "PIN",
            "proof",
            "Proof",
            "secret",
            "Secret",
            "passcode",
            "Passcode",
            "credential",
            "Credential",
        )
        write = _arg_or_kw(args, kwargs, 3, "Write", "write", "rw", "readWrite", "isWrite", "writeSession", "read_write", "write_session")
        read_only = _mapping_value(kwargs, "ReadOnly", "readOnly", "readonly", "read_only", "ro", "RO")
        if write is None and read_only is not None:
            write = not _as_bool(read_only)
        host_session_id = _arg_or_kw(args, kwargs, 4, "HostSessionID", "hostSessionID", "HostSession", "hostSession", "HostSID", "hostSID", "HSID", "hSID")
        session_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "params", "Params", "parameters", "Parameters", "session", "Session",
            "policy", "Policy", "config", "Config", "request", "Request",
            "operation", "Operation", "operationRequest", "OperationRequest",
            "startup", "Startup", "startupRequest", "StartupRequest",
            "target", "Target", "start", "Start", "startSession", "StartSession",
            "startSessionRequest", "StartSessionRequest", "sessionRequest",
            "SessionRequest", "spSessionRequest", "SPSessionRequest",
            "securityProviderRequest", "SecurityProviderRequest",
        )
        session_payload = _mapping_value(kwargs, *session_payload_aliases)
        if not isinstance(session_payload, dict):
            session_payload = _mapping_value(inp, *session_payload_aliases)
        if not isinstance(session_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            session_payload = _mapping_value(args[0], *session_payload_aliases)
            if not isinstance(session_payload, dict):
                session_payload = args[0]
        if isinstance(session_payload, dict):
            for _ in range(4):
                merged_session_payload = dict(session_payload)
                for envelope in (*session_payload_aliases, "credential", "Credential", "auth", "Auth", "authority", "Authority", "proof", "Proof"):
                    found_envelope, nested_session_payload = _dict_lookup(session_payload, envelope)
                    if found_envelope and isinstance(nested_session_payload, dict) and nested_session_payload is not session_payload:
                        merged_session_payload.update(nested_session_payload)
                if merged_session_payload == session_payload:
                    break
                session_payload = merged_session_payload
        if isinstance(session_payload, dict):
            if spid is None:
                spid = _mapping_value(session_payload, "SPID", "spid", "spID", "sp", "SP", "securityProvider", "security_provider")
            if auth is None:
                auth = _mapping_value(session_payload, "HostSigningAuthority", "hostSigningAuthority", "authAs", "AuthAs", "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "username", "Username")
            if challenge is None or isinstance(challenge, dict):
                challenge = _mapping_value(
                    session_payload,
                    "HostChallenge",
                    "hostChallenge",
                    "challenge",
                    "Challenge",
                    "password",
                    "Password",
                    "pin",
                    "PIN",
                    "proof",
                    "Proof",
                    "secret",
                    "Secret",
                    "passcode",
                    "Passcode",
                    "credential",
                    "Credential",
                )
            if isinstance(challenge, dict):
                nested_challenge = _mapping_value(challenge, "HostChallenge", "hostChallenge", "challenge", "Challenge", "password", "Password", "pin", "PIN", "proof", "Proof", "secret", "Secret", "passcode", "Passcode")
                if nested_challenge is not None and not isinstance(nested_challenge, dict):
                    challenge = nested_challenge
            if write is None:
                write = _mapping_value(session_payload, "Write", "write", "rw", "readWrite", "isWrite", "writeSession", "read_write", "write_session")
            if write is None:
                read_only = _mapping_value(session_payload, "ReadOnly", "readOnly", "readonly", "read_only", "ro", "RO")
                if read_only is not None:
                    write = not _as_bool(read_only)
            if host_session_id is None:
                host_session_id = _mapping_value(session_payload, "HostSessionID", "hostSessionID", "HostSession", "hostSession", "HostSID", "hostSID", "HSID", "hSID")
        required = {"SPID": spid, "Write": True if write is None else write}
        if host_session_id is not None:
            required["HostSessionID"] = host_session_id
        optional = {key: value for key, value in kwargs.items()}
        for key in (
            "SPID",
            "spid",
            "spID",
            "sp",
            "SP",
            "securityProvider",
            "security_provider",
            "auth",
            "Auth",
            "authority",
            "Authority",
            "user",
            "User",
            "identity",
            "Identity",
            "username",
            "Username",
            "HostSigningAuthority",
            "hostSigningAuthority",
            "authAs",
            "AuthAs",
            "challenge",
            "Challenge",
            "HostChallenge",
            "hostChallenge",
            "password",
            "Password",
            "pin",
            "PIN",
            "proof",
            "Proof",
            "secret",
            "Secret",
            "passcode",
            "Passcode",
            "credential",
            "Credential",
            "Write",
            "write",
            "rw",
            "readWrite",
            "isWrite",
            "writeSession",
            "read_write",
            "write_session",
            "ReadOnly",
            "readOnly",
            "readonly",
            "read_only",
            "ro",
            "RO",
            "HostSessionID",
            "hostSessionID",
            "HostSession",
            "hostSession",
            "HostSID",
            "hostSID",
            "HSID",
            "hSID",
        ):
            optional.pop(key, None)
        if auth is not None:
            optional["HostSigningAuthority"] = auth
        if challenge is not None:
            optional["HostChallenge"] = challenge
        symbol, uid = _object_ref_from_value("SessionManager")
        return Event(
            raw=raw,
            kind="tcg_method",
            method="StartSession",
            invoking_name="SessionManager",
            invoking_uid=uid or "00000000000000FF",
            invoking_symbol=symbol or "SessionManager",
            status=status,
            required=required,
            optional=optional,
            sp=_sp_from_value(spid),
            authority=_authority_from_value(auth),
            challenge=challenge,
            write_session=_as_bool(required["Write"]),
            implicit_session=False,
            comid=_comid_from_event_parts(required, optional, kwargs, inp, out, raw),
        )

    def pin_arg_value(index: int = 1) -> Any:
        return _arg_or_kw(
            args,
            kwargs,
            index,
            "pin",
            "PIN",
            "newPin",
            "newPIN",
            "new_pin",
            "pinCode",
            "pin_code",
            "password",
            "Password",
            "newPassword",
            "new_password",
            "credential",
            "Credential",
        )

    def build(
        method: str,
        target: Any,
        *,
        optional: dict[str, Any] | None = None,
        raw_args: Any = None,
        sp_value: Any = None,
        auth_value: Any = None,
        challenge: Any = None,
    ) -> Event:
        symbol, uid = _object_ref_from_value(target)
        optional_args = dict(optional or {})
        values = _values(optional_args, raw_args, symbol)
        return Event(
            raw=raw,
            kind="tcg_method",
            method=method,
            invoking_name=_normalize_name(target),
            invoking_uid=uid,
            invoking_symbol=symbol,
            status=status,
            optional=optional_args,
            values=values,
            columns=_cellblock_columns({}, raw_args, method, symbol),
            sp=_sp_from_value(sp_value),
            authority=_authority_from_value(auth_value),
            challenge=challenge,
            implicit_session=True,
            comid=_comid_from_event_parts(kwargs, inp, out, raw),
        )

    if function_alias in {
        "changepin",
        "changepincode",
        "setpin",
        "setpincode",
        "updatepin",
        "updatepincode",
        "changepassword",
        "changepasscode",
        "setpassword",
        "setpasscode",
        "updatepassword",
        "updatepasscode",
        "putpin",
        "putpincode",
        "putpassword",
        "putpasscode",
        "putcredential",
        "putuserpassword",
        "putusercredential",
        "setuserpin",
        "setuserpincode",
        "setuserpasscode",
        "changeuserpin",
        "changeuserpincode",
        "changeuserpasscode",
        "updateuserpin",
        "updateuserpincode",
        "updateuserpasscode",
        "updateuserpassword",
        "updateusercredential",
        "updatecredential",
        "setuserpassword",
        "changeuserpassword",
        "setusercredential",
        "changeusercredential",
        "setcredential",
        "changecredential",
        "setsidpin",
        "setsidpasscode",
        "changesidpin",
        "changesidpasscode",
        "setsidpassword",
        "changesidpassword",
        "setadminpin",
        "setadminpincode",
        "setadminpasscode",
        "changeadminpin",
        "changeadminpincode",
        "changeadminpasscode",
    }:
        sid_pin_aliases = {"setsidpin", "changesidpin", "setsidpasscode", "changesidpasscode", "setsidpassword", "changesidpassword"}
        admin_pin_aliases = {"setadminpin", "changeadminpin", "setadminpincode", "changeadminpincode", "setadminpasscode", "changeadminpasscode"}
        fixed_target_alias = function_alias in sid_pin_aliases or function_alias in admin_pin_aliases
        auth = "SID" if function_alias in sid_pin_aliases else "Admin1" if function_alias in admin_pin_aliases else auth_arg_value(0)
        if auth is None or isinstance(auth, dict):
            auth = _arg_or_kw(args, kwargs, 0, "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
        pin = pin_arg_value(0 if fixed_target_alias else 1)
        pin_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "credentialRequest", "CredentialRequest", "cpinRequest",
            "CPINRequest", "pinRequest", "PinRequest", "policyRequest",
            "PolicyRequest", "credential", "Credential", "cpin", "C_PIN",
            "cPin", "identity", "Identity",
        )
        pin_payload = _mapping_value(kwargs, *pin_payload_aliases)
        if not isinstance(pin_payload, dict):
            pin_payload = _mapping_value(inp, *pin_payload_aliases)
        if isinstance(pin_payload, dict):
            for _ in range(2):
                merged_pin_payload = dict(pin_payload)
                for envelope in pin_payload_aliases:
                    found_envelope, nested_pin_payload = _dict_lookup(pin_payload, envelope)
                    if found_envelope and isinstance(nested_pin_payload, dict) and nested_pin_payload is not pin_payload:
                        merged_pin_payload.update(nested_pin_payload)
                if merged_pin_payload == pin_payload:
                    break
                pin_payload = merged_pin_payload
            if auth is None or isinstance(auth, dict):
                auth = _mapping_value(pin_payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "cpin", "C_PIN", "cPin", "identity", "Identity", "username", "Username", "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "authorityId", "authority_id", "AuthorityID", "userId", "user_id", "UserID", "name", "Name")
            if pin is None:
                pin = _mapping_value(pin_payload, "pin", "PIN", "newPin", "newPIN", "new_pin", "pinCode", "pin_code", "password", "Password", "newPassword", "new_password", "credential", "Credential")
        auth_as = authas(auth)
        if isinstance(pin_payload, dict):
            auth_as = _mapping_value(pin_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        target = cpin_target(auth, _arg_or_kw(args, kwargs, 3, "obj", "object", "Object"))
        return build("Set", target, optional={"PIN": pin, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias == "setminpinlength":
        auth = auth_arg_value(0)
        length = _arg_or_kw(args, kwargs, 1, "len", "length", "Length", "_MinPINLength")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        min_pin_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "credentialRequest", "CredentialRequest", "cpinRequest",
            "CPINRequest", "pinRequest", "PinRequest", "policyRequest",
            "PolicyRequest", "credential", "Credential", "cpin", "C_PIN",
            "cPin", "identity", "Identity", "limits", "Limits",
        )
        min_pin_payload = _mapping_value(kwargs, *min_pin_payload_aliases)
        if not isinstance(min_pin_payload, dict):
            min_pin_payload = _mapping_value(inp, *min_pin_payload_aliases)
        if isinstance(min_pin_payload, dict):
            for _ in range(2):
                merged_min_pin_payload = dict(min_pin_payload)
                for envelope in min_pin_payload_aliases:
                    found_envelope, nested_min_pin_payload = _dict_lookup(min_pin_payload, envelope)
                    if found_envelope and isinstance(nested_min_pin_payload, dict) and nested_min_pin_payload is not min_pin_payload:
                        merged_min_pin_payload.update(nested_min_pin_payload)
                if merged_min_pin_payload == min_pin_payload:
                    break
                min_pin_payload = merged_min_pin_payload
            if auth is None:
                auth = _mapping_value(min_pin_payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "cpin", "C_PIN", "cPin", "identity", "Identity", "credentialId", "credential_id", "pinId", "pin_id")
            if length is None:
                length = _mapping_value(min_pin_payload, "len", "length", "Length", "_MinPINLength", "minPINLength", "MinPINLength", "minimumPINLength", "MinimumPINLength")
        if isinstance(min_pin_payload, dict):
            auth_as = _mapping_value(min_pin_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        target = cpin_target(auth, _arg_or_kw(args, kwargs, 3, "obj", "object", "Object"))
        return build("Set", target, optional={"_MinPINLength": length, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    cpin_counter_setters = {
        "settrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "limit", "Limit", "value", "Value")),
        "setpinlimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "limit", "Limit", "pinLimit", "pin_limit", "value", "Value")),
        "setpintrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "limit", "Limit", "pinTryLimit", "pin_try_limit", "value", "Value")),
        "setpinretrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "retryLimit", "retry_limit", "pinRetryLimit", "pin_retry_limit", "limit", "Limit", "value", "Value")),
        "setusertrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "userTryLimit", "user_try_limit", "limit", "Limit", "value", "Value")),
        "setcredentialtrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "credentialTryLimit", "credential_try_limit", "limit", "Limit", "value", "Value")),
        "setretrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "retryLimit", "retry_limit", "limit", "Limit", "value", "Value")),
        "setuserretrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "userRetryLimit", "user_retry_limit", "retryLimit", "retry_limit", "limit", "Limit", "value", "Value")),
        "setpasswordretrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "passwordRetryLimit", "password_retry_limit", "retryLimit", "retry_limit", "limit", "Limit", "value", "Value")),
        "setcredentialretrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "credentialRetryLimit", "credential_retry_limit", "retryLimit", "retry_limit", "limit", "Limit", "value", "Value")),
        "setmaxretries": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "maxRetries", "max_retries", "retries", "Retries", "limit", "Limit", "value", "Value")),
        "setusermaxretries": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "userMaxRetries", "user_max_retries", "maxRetries", "max_retries", "retries", "Retries", "limit", "Limit", "value", "Value")),
        "updatetrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "limit", "Limit", "value", "Value")),
        "puttrylimit": ("TryLimit", CPIN_TRY_LIMIT_COLUMN, ("TryLimit", "tryLimit", "try_limit", "limit", "Limit", "value", "Value")),
        "settries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "setpintries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "pinTries", "pin_tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "setusertries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "userTries", "user_tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "setuserretries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "retries", "Retries", "userRetries", "user_retries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "setcredentialtries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "credentialTries", "credential_tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "updatetries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
        "puttries": ("Tries", CPIN_TRIES_COLUMN, ("Tries", "tries", "attempts", "Attempts", "count", "Count", "value", "Value")),
    }
    if function_alias in cpin_counter_setters:
        column_name, _column_index, value_aliases = cpin_counter_setters[function_alias]
        if column_name == "TryLimit":
            value_aliases = (
                *value_aliases,
                "retryLimit",
                "retry_limit",
                "maxRetries",
                "max_retries",
                "maxTries",
                "max_tries",
                "attemptLimit",
                "attempt_limit",
                "maxAttempts",
                "max_attempts",
                "pinAttemptLimit",
                "pin_attempt_limit",
                "credentialAttemptLimit",
                "credential_attempt_limit",
            )
        if column_name == "Tries":
            value_aliases = (
                *value_aliases,
                "retryCount",
                "retry_count",
                "pinAttempts",
                "pin_attempts",
                "credentialAttempts",
                "credential_attempts",
            )
        auth = auth_arg_value(0)
        if auth is None or isinstance(auth, dict):
            auth = _arg_or_kw(args, kwargs, 0, "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
        value = _arg_or_kw(args, kwargs, 1, *value_aliases)
        counter_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "target",
            "Target",
            "operationRequest",
            "OperationRequest",
            "limits",
            "Limits",
            "counter",
            "Counter",
            "pinState",
            "PinState",
            "state",
            "State",
            "security",
            "Security",
            "credentialPolicy",
            "CredentialPolicy",
            "credential_policy",
            "pinPolicy",
            "PinPolicy",
            "pin_policy",
            "credentialRequest",
            "CredentialRequest",
            "cpinRequest",
            "CPINRequest",
            "pinRequest",
            "PinRequest",
        )
        try_payload = _mapping_value(kwargs, *counter_payload_aliases)
        if not isinstance(try_payload, dict):
            try_payload = _mapping_value(inp, *counter_payload_aliases)
        if not isinstance(try_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            try_payload = _mapping_value(args[0], *counter_payload_aliases)
            if not isinstance(try_payload, dict):
                try_payload = args[0]

        def _counter_envelope_lookup(payload: Any) -> tuple[bool, Any]:
            if not isinstance(payload, dict):
                return False, None
            found, nested_value = _dict_lookup(payload, column_name, column_name[0].lower() + column_name[1:], *value_aliases)
            if found:
                return True, nested_value
            for envelope in counter_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    found_nested, nested_value = _counter_envelope_lookup(nested)
                    if found_nested:
                        return True, nested_value
            return False, None

        def _counter_auth_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "cpin", "C_PIN", "cPin", "identity", "Identity", "username", "Username", "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in counter_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _counter_auth_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(try_payload, dict):
            for _ in range(4):
                merged_try_payload = dict(try_payload)
                for envelope in counter_payload_aliases:
                    nested_try_payload = _mapping_value(try_payload, envelope)
                    if isinstance(nested_try_payload, dict) and nested_try_payload is not try_payload:
                        merged_try_payload.update(nested_try_payload)
                if merged_try_payload == try_payload:
                    break
                try_payload = merged_try_payload
            if auth is None or isinstance(auth, dict):
                auth = _counter_auth_selector(try_payload)
            if value is None:
                found_value, nested_value = _counter_envelope_lookup(try_payload)
                if found_value:
                    value = nested_value
        if value is None:
            for source in (kwargs, inp, args[0] if len(args) > 0 else None):
                found_value, nested_value = _counter_envelope_lookup(source)
                if found_value:
                    value = nested_value
                    break
        auth_as = authas(auth)
        if isinstance(try_payload, dict):
            auth_as = _mapping_value(try_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        target = cpin_target(auth, _arg_or_kw(args, kwargs, 3, "obj", "object", "Object"))
        return build("Set", target, optional={column_name: value, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    cpin_counter_getters = {
        "gettrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getpinlimit": CPIN_TRY_LIMIT_COLUMN,
        "getpintrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getpinretrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getusertrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getcredentialtrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getretrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getuserretrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getcredentialretrylimit": CPIN_TRY_LIMIT_COLUMN,
        "getcredentialattemptlimit": CPIN_TRY_LIMIT_COLUMN,
        "getauthattemptlimit": CPIN_TRY_LIMIT_COLUMN,
        "getmaxretries": CPIN_TRY_LIMIT_COLUMN,
        "getusermaxretries": CPIN_TRY_LIMIT_COLUMN,
        "getretrycountlimit": CPIN_TRY_LIMIT_COLUMN,
        "getattemptlimit": CPIN_TRY_LIMIT_COLUMN,
        "getpinattemptlimit": CPIN_TRY_LIMIT_COLUMN,
        "getmaxpinattempts": CPIN_TRY_LIMIT_COLUMN,
        "gettries": CPIN_TRIES_COLUMN,
        "getpintries": CPIN_TRIES_COLUMN,
        "getpinattempts": CPIN_TRIES_COLUMN,
        "getusertries": CPIN_TRIES_COLUMN,
        "getuserretries": CPIN_TRIES_COLUMN,
        "getuserattempts": CPIN_TRIES_COLUMN,
        "getcredentialtries": CPIN_TRIES_COLUMN,
        "getcredentialattempts": CPIN_TRIES_COLUMN,
        "getretrycount": CPIN_TRIES_COLUMN,
        "getuserretrycount": CPIN_TRIES_COLUMN,
        "getminpinlength": MIN_PIN_COLUMN,
        "getminimumpinlength": MIN_PIN_COLUMN,
        "getpinminlength": MIN_PIN_COLUMN,
    }
    if function_alias in cpin_counter_getters:
        column_index = cpin_counter_getters[function_alias]
        auth = auth_arg_value(0)
        if auth is None or isinstance(auth, dict):
            auth = _arg_or_kw(args, kwargs, 0, "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
        try_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "policy", "Policy", "config", "Config", "request", "Request",
            "target", "Target", "operationRequest", "OperationRequest",
            "credentialRequest", "CredentialRequest", "cpinRequest",
            "CPINRequest", "pinRequest", "PinRequest",
            "counter", "Counter", "pinState", "PinState", "state", "State",
        )
        try_payload = _mapping_value(kwargs, *try_payload_aliases)
        if not isinstance(try_payload, dict):
            try_payload = _mapping_value(inp, *try_payload_aliases)
        if not isinstance(try_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            try_payload = _mapping_value(args[0], *try_payload_aliases)
            if not isinstance(try_payload, dict):
                try_payload = args[0]
        if isinstance(try_payload, dict):
            for _ in range(4):
                merged_try_payload = dict(try_payload)
                nested_try_payload = _mapping_value(try_payload, *try_payload_aliases, "credential", "Credential", "cpin", "C_PIN", "cPin", "identity", "Identity")
                if isinstance(nested_try_payload, dict) and nested_try_payload is not try_payload:
                    merged_try_payload.update(nested_try_payload)
                if merged_try_payload == try_payload:
                    break
                try_payload = merged_try_payload

        def _counter_getter_auth_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "cpin", "C_PIN", "cPin", "identity", "Identity", "username", "Username", "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in try_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _counter_getter_auth_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(try_payload, dict) and (auth is None or isinstance(auth, dict)):
            auth = _counter_getter_auth_selector(try_payload)
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or authas(auth)
        if isinstance(try_payload, dict):
            auth_as = _mapping_value(try_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        target = cpin_target(auth, _arg_or_kw(args, kwargs, 2, "obj", "object", "Object"))
        return build(
            "Get",
            target,
            optional={"CellBlock": [{"startColumn": column_index}, {"endColumn": column_index}], "authAs": auth_as},
            raw_args={"CellBlock": [{"startColumn": column_index}, {"endColumn": column_index}]},
            auth_value=auth_as,
            challenge=_authas_credential_arg({}, {"authAs": auth_as}, None),
        )

    if function_alias in {
        "authenticate",
        "checkuserpin",
        "verifyuserpin",
        "validateuserpin",
        "checkuserpassword",
        "verifyuserpassword",
        "validateuserpassword",
        "validatecredential",
        "checkpassphrase",
        "verifypassphrase",
        "validatepassphrase",
    }:
        auth = auth_arg_value(0)
        if auth is None or isinstance(auth, dict):
            auth = _arg_or_kw(args, kwargs, 0, "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
        challenge = _arg_or_kw(args, kwargs, 1, "challenge", "Challenge", "pin", "PIN", "proof", "Proof", "password", "Password", "passcode", "Passcode", "secret", "Secret", "credential", "Credential")
        auth_payload_aliases = (
            "values", "Values", "auth", "Auth", "settings", "Settings",
            "options", "Options", "request", "Request", "config", "Config",
            "policy", "Policy", "target", "Target", "operationRequest",
            "OperationRequest", "credentialRequest",
            "CredentialRequest", "authRequest", "AuthRequest",
            "authenticationRequest", "AuthenticationRequest", "proofRequest",
            "ProofRequest", "pinRequest", "PinRequest", "cpinRequest",
            "CPINRequest", "counter", "Counter", "pinState", "PinState",
            "credential", "Credential", "identity", "Identity",
        )
        auth_payload = _mapping_value(kwargs, *auth_payload_aliases)
        if not isinstance(auth_payload, dict):
            auth_payload = _mapping_value(inp, *auth_payload_aliases)
        if isinstance(auth_payload, dict):
            for _ in range(4):
                merged_auth_payload = dict(auth_payload)
                for envelope in auth_payload_aliases:
                    found_envelope, nested_auth_payload = _dict_lookup(auth_payload, envelope)
                    if found_envelope and isinstance(nested_auth_payload, dict) and nested_auth_payload is not auth_payload:
                        merged_auth_payload.update(nested_auth_payload)
                if merged_auth_payload == auth_payload:
                    break
                auth_payload = merged_auth_payload

            def _auth_payload_selector(payload: Any) -> Any:
                if not isinstance(payload, dict):
                    return None
                direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "userId", "userID", "user_id", "uid", "UID", "obj", "object", "Object", "target", "Target", "identity", "Identity", "username", "Username", "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "authorityId", "authority_id", "AuthorityID", "name", "Name")
                if direct is not None and not isinstance(direct, dict):
                    return direct
                for envelope in auth_payload_aliases:
                    found_envelope, nested = _dict_lookup(payload, envelope)
                    if found_envelope and nested is not payload:
                        nested_selector = _auth_payload_selector(nested)
                        if nested_selector is not None:
                            return nested_selector
                return None

            def _auth_payload_proof(payload: Any) -> Any:
                if not isinstance(payload, dict):
                    return None
                direct = _mapping_value(payload, "challenge", "Challenge", "pin", "PIN", "proof", "Proof", "password", "Password", "passcode", "Passcode", "secret", "Secret", "credential", "Credential")
                if direct is not None and not isinstance(direct, dict):
                    return direct
                for envelope in auth_payload_aliases:
                    found_envelope, nested = _dict_lookup(payload, envelope)
                    if found_envelope and nested is not payload:
                        nested_proof = _auth_payload_proof(nested)
                        if nested_proof is not None:
                            return nested_proof
                return None

            if auth is None or isinstance(auth, dict):
                auth = _auth_payload_selector(auth_payload)
            if challenge is None:
                challenge = _auth_payload_proof(auth_payload)
        optional = dict(kwargs)
        if auth is not None:
            optional["Auth"] = auth
        if challenge is not None:
            optional["Proof"] = challenge
        return build("Authenticate", "ThisSP", optional=optional, auth_value=auth, challenge=challenge)

    if function_alias in {"setlockonreset", "setrangelockonreset", "setlockingrangelockonreset", "clearlockonreset", "setlor", "setrangelor", "updatelor", "updaterangelor", "putlor", "putrangelor", "setresettypes", "setrangeresettypes", "setlockonresettypes", "setrangelockonresettypes", "setlockingrangeresettypes", "updatelockonreset", "updaterangelockonreset", "putlockonreset", "putrangelockonreset", "configurelockonreset", "configurerangelockonreset", "configurelor", "configurerangelor", "enablelockonreset", "enablerangelockonreset", "enablelor", "enablerangelor", "disablelockonreset", "disablerangelockonreset", "disablelor", "disablerangelor"}:
        range_no = range_arg(0)
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        lock_on_reset = _arg_or_kw(args, kwargs, 1, "LockOnReset", "lockOnReset", "lock_on_reset", "lor", "LOR", "resetTypes", "reset_types", "types", "Types", "resetEvents", "reset_events", "resetOn", "reset_on", "resetList", "reset_list", "value", "Value", "values", "Values")
        lor_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "operationRequest",
            "OperationRequest",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "rangeValues",
            "RangeValues",
            "geometry",
            "Geometry",
            "window",
            "Window",
            "resetPolicy",
            "ResetPolicy",
            "reset_policy",
            "reset",
            "Reset",
            "types",
            "Types",
            "resetTypes",
            "ResetTypes",
            "resetEvents",
            "ResetEvents",
            "target",
            "Target",
            "query",
            "Query",
        )
        lor_payload = _mapping_value(kwargs, *lor_payload_aliases)
        if not isinstance(lor_payload, dict):
            lor_payload = _mapping_value(inp, *lor_payload_aliases)
        if not isinstance(lor_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            lor_payload = _mapping_value(args[0], *lor_payload_aliases)
            if not isinstance(lor_payload, dict):
                lor_payload = args[0]

        def _lor_envelope_lookup(payload: Any) -> tuple[bool, Any]:
            if not isinstance(payload, dict):
                return False, None
            found, value = _dict_lookup(payload, "LockOnReset", "lockOnReset", "lock_on_reset", "lor", "value", "Value", "resetTypes", "reset_types", "types", "Types", "resetEvents", "reset_events", "resetOn", "reset_on", "resetList", "reset_list")
            if found:
                if isinstance(value, dict):
                    found_nested, nested_value = _lor_envelope_lookup(value)
                    if found_nested:
                        return True, nested_value
                return True, value
            for envelope in lor_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    found_nested, nested_value = _lor_envelope_lookup(nested)
                    if found_nested:
                        return True, nested_value
            return False, None

        if isinstance(lor_payload, dict):
            for _ in range(4):
                merged_lor_payload = dict(lor_payload)
                for envelope in lor_payload_aliases:
                    nested_lor_payload = _mapping_value(lor_payload, envelope)
                    if isinstance(nested_lor_payload, dict) and nested_lor_payload is not lor_payload:
                        merged_lor_payload.update(nested_lor_payload)
                if merged_lor_payload == lor_payload:
                    break
                lor_payload = merged_lor_payload
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    lor_payload,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                )
            if lock_on_reset is None or isinstance(lock_on_reset, dict):
                found_lor, nested_lor = _lor_envelope_lookup(lor_payload)
                if found_lor:
                    lock_on_reset = nested_lor
            auth_as = _mapping_value(lor_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        if function_alias in {"clearlockonreset", "disablelockonreset", "disablerangelockonreset", "disablelor", "disablerangelor"} and lock_on_reset is None:
            lock_on_reset = []
        if function_alias in {"enablelockonreset", "enablerangelockonreset", "enablelor", "enablerangelor"} and lock_on_reset is None:
            lock_on_reset = [0]
        return build(
            "Set",
            _band_target_from_range_value(range_no),
            optional={"LockOnReset": lock_on_reset, "authAs": auth_as},
            auth_value=auth_as,
            challenge=_authas_credential_arg({}, {"authAs": auth_as}, None),
        )

    if function_alias in {
        "getlockonreset",
        "getrangelockonreset",
        "getlockingrangelockonreset",
        "getlor",
        "getrangelor",
        "getresettypes",
        "getrangeresettypes",
        "getlockonresettypes",
        "getrangelockonresettypes",
        "getlockingrangeresettypes",
        "readlockonreset",
        "readrangelockonreset",
        "fetchlockonreset",
        "fetchrangelockonreset",
        "querylockonreset",
        "queryrangelockonreset",
        "loadlockonreset",
        "loadrangelockonreset",
        "readlor",
        "readrangelor",
        "fetchlor",
        "fetchrangelor",
        "querylor",
        "queryrangelor",
        "loadlor",
        "loadrangelor",
        "islockonresetenabled",
        "israngelockonresetenabled",
        "islockingrangelockonresetenabled",
        "lockonresetenabled",
        "rangelockonresetenabled",
        "haslockonreset",
    }:
        range_no = range_arg(0)
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        lor_get_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "target", "Target", "operationRequest", "OperationRequest", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "reset", "Reset", "types", "Types", "range", "Range", "selection", "Selection")
        lor_payload = _mapping_value(kwargs, *lor_get_payload_aliases)
        if not isinstance(lor_payload, dict):
            lor_payload = _mapping_value(inp, *lor_get_payload_aliases)
        if not isinstance(lor_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            lor_payload = _mapping_value(args[0], *lor_get_payload_aliases)
            if not isinstance(lor_payload, dict):
                lor_payload = args[0]
        if isinstance(lor_payload, dict):
            for _ in range(4):
                merged_lor_payload = dict(lor_payload)
                for envelope in lor_get_payload_aliases:
                    nested_lor_payload = _mapping_value(lor_payload, envelope)
                    if isinstance(nested_lor_payload, dict) and nested_lor_payload is not lor_payload:
                        merged_lor_payload.update(nested_lor_payload)
                if merged_lor_payload == lor_payload:
                    break
                lor_payload = merged_lor_payload
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    lor_payload,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                )
            auth_as = _mapping_value(lor_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        cellblock = [{"startColumn": 9}, {"endColumn": 9}]
        return build(
            "Get",
            _band_target_from_range_value(range_no),
            optional={"CellBlock": cellblock, "authAs": auth_as},
            raw_args={"CellBlock": cellblock},
            auth_value=auth_as,
            challenge=_authas_credential_arg({}, {"authAs": auth_as}, None),
        )

    range_field_setters = {
        "setrangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "setrangelba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "setrangestartlba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "setstartlba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "updaterangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "putrangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "storerangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "saverangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "programrangestart": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "updaterangelba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "putrangelba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "updatestartlba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "putstartlba": ("RangeStart", ("start", "Start", "RangeStart", "rangeStart", "range_start", "lba", "LBA", "value", "Value"), None),
        "setrangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "setrangelen": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "setrangesize": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "updaterangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "putrangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "storerangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "saverangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "programrangelength": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "size", "Size", "count", "Count", "value", "Value"), None),
        "updaterangesize": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "putrangesize": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "storerangesize": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "saverangesize": ("RangeLength", ("length", "Length", "RangeLength", "rangeLength", "range_length", "len", "Len", "size", "Size", "count", "Count", "value", "Value"), None),
        "enablereadlock": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablereadlockrange": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablereadlockforrange": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablereadlocking": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablerangereadlock": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablerangereadlocking": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablewritelock": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablewritelockrange": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablewritelockforrange": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablewritelocking": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablerangewritelock": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "enablerangewritelocking": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), True),
        "disablereadlock": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablereadlockrange": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablereadlockforrange": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablereadlocking": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablerangereadlock": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablerangereadlocking": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablewritelock": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablewritelockrange": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablewritelockforrange": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablewritelocking": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablerangewritelock": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "disablerangewritelocking": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "value", "Value"), False),
        "configurerangereadlock": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "configurerangewritelock": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "setreadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "setreadlockingenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "updatereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "putreadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "setrangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "setrangereadlockingenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "updaterangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "putrangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "storerangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "saverangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "configurerangereadlockenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "updatereadlockingenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "putreadlockingenabled": ("ReadLockEnabled", ("enabled", "Enabled", "enable", "Enable", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled", "value", "Value"), None),
        "setwritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "setwritelockingenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "updatewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "putwritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "setrangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "setrangewritelockingenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "updaterangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "putrangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "storerangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "saverangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "configurerangewritelockenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "updatewritelockingenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "putwritelockingenabled": ("WriteLockEnabled", ("enabled", "Enabled", "enable", "Enable", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled", "value", "Value"), None),
        "setreadlock": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setwritelock": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "setrangereadlock": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setreadlockforrange": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), True),
        "clearreadlockforrange": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), False),
        "clearrangereadlock": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), False),
        "setrangewritelock": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "setwritelockforrange": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), True),
        "clearwritelockforrange": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), False),
        "clearrangewritelock": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), False),
        "setreadlockstate": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setwritelockstate": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "setrangereadlockstate": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setrangereadlockedstate": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "markreadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), True),
        "setrangewritelockstate": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "setrangewritelockedstate": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "markwritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), True),
        "lockrangeread": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), True),
        "unlockrangeread": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), False),
        "lockrangewrite": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), True),
        "unlockrangewrite": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), False),
        "setrangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setrangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "setreadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setwritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "updatereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "putreadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "updaterangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "putrangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "storerangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "saverangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "configurerangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "updaterangereadlockstate": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "putrangereadlockstate": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "clearreadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), False),
        "clearrangereadlocked": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), False),
        "updatewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "putwritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "updaterangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "putrangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "storerangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "saverangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "configurerangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "updaterangewritelockstate": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "putrangewritelockstate": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
        "clearwritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), False),
        "clearrangewritelocked": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), False),
        "setreadlockedforrange": ("ReadLocked", ("locked", "Locked", "readLocked", "ReadLocked", "value", "Value"), None),
        "setwritelockedforrange": ("WriteLocked", ("locked", "Locked", "writeLocked", "WriteLocked", "value", "Value"), None),
    }
    if function_alias in range_field_setters:
        column_name, value_aliases, default_value = range_field_setters[function_alias]
        range_no = range_arg(0)
        if range_no is None or isinstance(range_no, dict):
            range_no = top_level_range_arg()
        value = _arg_or_kw(args, kwargs, 1, *value_aliases)
        range_payload = _mapping_value(kwargs, "values", "Values", "settings", "Settings", "options", "Options", "params", "Params", "parameters", "Parameters", "request", "Request", "config", "Config", "policy", "Policy", "security", "Security", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "state", "State", "lockState", "LockState", "locks", "Locks", "lock", "Lock")
        if not isinstance(range_payload, dict):
            range_payload = _mapping_value(inp, "values", "Values", "settings", "Settings", "options", "Options", "params", "Params", "parameters", "Parameters", "request", "Request", "config", "Config", "policy", "Policy", "security", "Security", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "state", "State", "lockState", "LockState", "locks", "Locks", "lock", "Lock")
        if not isinstance(range_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            range_payload = _mapping_value(args[0], "values", "Values", "settings", "Settings", "options", "Options", "params", "Params", "parameters", "Parameters", "request", "Request", "config", "Config", "policy", "Policy", "security", "Security", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "state", "State", "lockState", "LockState", "locks", "Locks", "lock", "Lock")
            if not isinstance(range_payload, dict):
                range_payload = args[0]
        auth_as = None
        if isinstance(range_payload, dict):
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(range_payload, "range", "Range", "rangeId", "rangeID", "range_id", "band", "Band", "bandId", "bandID", "band_id", "bandName", "band_name", "rangeName", "range_name", "id", "ID", "uid", "UID", "obj", "object", "Object", "target", "Target")
            if value is None:
                directional_aliases = {
                    "ReadLockEnabled": ("read", "Read", "readLock", "ReadLock", "readEnabled", "ReadEnabled", "readLockEnabled", "ReadLockEnabled", "readLockingEnabled", "ReadLockingEnabled"),
                    "WriteLockEnabled": ("write", "Write", "writeLock", "WriteLock", "writeEnabled", "WriteEnabled", "writeLockEnabled", "WriteLockEnabled", "writeLockingEnabled", "WriteLockingEnabled"),
                    "ReadLocked": ("read", "Read", "readLock", "ReadLock", "readLocked", "ReadLocked"),
                    "WriteLocked": ("write", "Write", "writeLock", "WriteLock", "writeLocked", "WriteLocked"),
                }.get(column_name, ())
                value = _mapping_value(range_payload, column_name, column_name[0].lower() + column_name[1:], *value_aliases, *directional_aliases)
                if value is None:
                    for nested_key in ("locks", "Locks", "lockState", "LockState", "state", "State", "lock", "Lock"):
                        found_nested, nested_locks = _dict_lookup(range_payload, nested_key)
                        if found_nested and isinstance(nested_locks, dict):
                            value = _mapping_value(nested_locks, column_name, column_name[0].lower() + column_name[1:], *value_aliases, *directional_aliases)
                            if value is not None:
                                break
            auth_as = _mapping_value(range_payload, "authAs", "AuthAs", "auth_as", "authAS")
        if value is None:
            value = default_value
        auth_as = auth_as or _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        return build("Set", _band_target_from_range_value(range_no), optional={column_name: value, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    range_field_getters = {
        "getrangestart": 3,
        "getrangelba": 3,
        "getrangestartlba": 3,
        "getstartlba": 3,
        "readrangestart": 3,
        "fetchrangestart": 3,
        "queryrangestart": 3,
        "loadrangestart": 3,
        "readrangelba": 3,
        "fetchrangelba": 3,
        "queryrangelba": 3,
        "loadrangelba": 3,
        "readstartlba": 3,
        "fetchstartlba": 3,
        "querystartlba": 3,
        "loadstartlba": 3,
        "getrangelength": 4,
        "getrangelen": 4,
        "getrangesize": 4,
        "readrangelength": 4,
        "fetchrangelength": 4,
        "queryrangelength": 4,
        "loadrangelength": 4,
        "readrangesize": 4,
        "fetchrangesize": 4,
        "queryrangesize": 4,
        "loadrangesize": 4,
        "readrangelen": 4,
        "fetchrangelen": 4,
        "queryrangelen": 4,
        "loadrangelen": 4,
        "getreadlockenabled": 5,
        "isreadlockenabled": 5,
        "readlockenabled": 5,
        "readlockingenabled": 5,
        "isreadlockingenabled": 5,
        "getrangereadlockenabled": 5,
        "readreadlockenabled": 5,
        "fetchreadlockenabled": 5,
        "queryreadlockenabled": 5,
        "loadreadlockenabled": 5,
        "readrangereadlockenabled": 5,
        "fetchrangereadlockenabled": 5,
        "queryrangereadlockenabled": 5,
        "loadrangereadlockenabled": 5,
        "getreadlockenabledrange": 5,
        "getreadlockenabledforrange": 5,
        "israngereadlockenabled": 5,
        "isreadlockenabledrange": 5,
        "isreadlockenabledforrange": 5,
        "getrangereadlockingenabled": 5,
        "israngereadlockingenabled": 5,
        "getwritelockenabled": 6,
        "iswritelockenabled": 6,
        "writelockenabled": 6,
        "writelockingenabled": 6,
        "iswritelockingenabled": 6,
        "getrangewritelockenabled": 6,
        "readwritelockenabled": 6,
        "fetchwritelockenabled": 6,
        "querywritelockenabled": 6,
        "loadwritelockenabled": 6,
        "readrangewritelockenabled": 6,
        "fetchrangewritelockenabled": 6,
        "queryrangewritelockenabled": 6,
        "loadrangewritelockenabled": 6,
        "getwritelockenabledrange": 6,
        "getwritelockenabledforrange": 6,
        "israngewritelockenabled": 6,
        "iswritelockenabledrange": 6,
        "iswritelockenabledforrange": 6,
        "getrangewritelockingenabled": 6,
        "israngewritelockingenabled": 6,
        "isreadlocked": 7,
        "getreadlock": 7,
        "readlocked": 7,
        "getrangereadlocked": 7,
        "readreadlocked": 7,
        "fetchreadlocked": 7,
        "queryreadlocked": 7,
        "loadreadlocked": 7,
        "readrangereadlocked": 7,
        "fetchrangereadlocked": 7,
        "queryrangereadlocked": 7,
        "loadrangereadlocked": 7,
        "getreadlockedrange": 7,
        "getreadlockedforrange": 7,
        "israngereadlocked": 7,
        "isreadlockedrange": 7,
        "isreadlockedforrange": 7,
        "isreadlockset": 7,
        "getreadlockstate": 7,
        "readreadlockstate": 7,
        "fetchreadlockstate": 7,
        "queryreadlockstate": 7,
        "loadreadlockstate": 7,
        "getreadlockedstate": 7,
        "getrangereadlockstate": 7,
        "israngereadlockset": 7,
        "readlockstate": 7,
        "rangereadlockstate": 7,
        "rangereadlocked": 7,
        "iswritelocked": 8,
        "getwritelock": 8,
        "writelocked": 8,
        "getrangewritelocked": 8,
        "readwritelocked": 8,
        "fetchwritelocked": 8,
        "querywritelocked": 8,
        "loadwritelocked": 8,
        "readrangewritelocked": 8,
        "fetchrangewritelocked": 8,
        "queryrangewritelocked": 8,
        "loadrangewritelocked": 8,
        "getwritelockedrange": 8,
        "getwritelockedforrange": 8,
        "israngewritelocked": 8,
        "iswritelockedrange": 8,
        "iswritelockedforrange": 8,
        "iswritelockset": 8,
        "getwritelockstate": 8,
        "readwritelockstate": 8,
        "fetchwritelockstate": 8,
        "querywritelockstate": 8,
        "loadwritelockstate": 8,
        "getwritelockedstate": 8,
        "getrangewritelockstate": 8,
        "israngewritelockset": 8,
        "writelockstate": 8,
        "rangewritelockstate": 8,
        "rangewritelocked": 8,
        "getreadlocked": 7,
        "getwritelocked": 8,
    }
    if function_alias in range_field_getters:
        column_index = range_field_getters[function_alias]
        range_no = range_arg(0)
        range_field_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "target", "Target", "rangeValues", "RangeValues", "range", "Range", "selection", "Selection")
        range_payload = _mapping_value(kwargs, *range_field_payload_aliases)
        if not isinstance(range_payload, dict):
            range_payload = _mapping_value(inp, *range_field_payload_aliases)
        if not isinstance(range_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            range_payload = _mapping_value(args[0], *range_field_payload_aliases)
            if not isinstance(range_payload, dict):
                range_payload = args[0]
        auth_as = None
        if isinstance(range_payload, dict):
            for _ in range(2):
                for envelope in range_field_payload_aliases:
                    deeper_range_payload = _mapping_value(range_payload, envelope)
                    if isinstance(deeper_range_payload, dict) and deeper_range_payload is not range_payload:
                        range_payload = {**range_payload, **deeper_range_payload}
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(range_payload, "range", "Range", "rangeId", "rangeID", "range_id", "band", "Band", "bandId", "bandID", "band_id", "bandName", "band_name", "rangeName", "range_name", "id", "ID", "uid", "UID", "obj", "object", "Object", "target", "Target")
            auth_as = _mapping_value(range_payload, "authAs", "AuthAs", "auth_as", "authAS")
        auth_as = auth_as or _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        cellblock = [{"startColumn": column_index}, {"endColumn": column_index}]
        return build("Get", _band_target_from_range_value(range_no), optional={"CellBlock": cellblock, "authAs": auth_as}, raw_args={"CellBlock": cellblock}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias == "getrangelocks":
        range_no = range_arg(0)
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        range_locks_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "target", "Target", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "rangeValues", "RangeValues", "range", "Range", "selection", "Selection")
        range_payload = _mapping_value(kwargs, *range_locks_payload_aliases)
        if not isinstance(range_payload, dict):
            range_payload = _mapping_value(inp, *range_locks_payload_aliases)
        if isinstance(range_payload, dict):
            for _ in range(2):
                for envelope in range_locks_payload_aliases:
                    deeper_range_payload = _mapping_value(range_payload, envelope)
                    if isinstance(deeper_range_payload, dict) and deeper_range_payload is not range_payload:
                        range_payload = {**range_payload, **deeper_range_payload}
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(range_payload, "range", "Range", "rangeId", "rangeID", "range_id", "band", "Band", "bandId", "bandID", "band_id", "bandName", "band_name", "rangeName", "range_name", "id", "ID", "uid", "UID", "obj", "object", "Object", "target", "Target")
            auth_as = _mapping_value(range_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        cellblock = [{"startColumn": 7}, {"endColumn": 8}]
        return build("Get", _band_target_from_range_value(range_no), optional={"CellBlock": cellblock, "authAs": auth_as}, raw_args={"CellBlock": cellblock}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "setrange",
        "configurerange",
        "configurelockingrange",
        "configrange",
        "setlockingrange",
        "setuprange",
        "setband",
        "configureband",
        "configband",
        "setbandrange",
        "updaterange",
        "modifyrange",
        "definerange",
        "createrange",
        "resizerange",
        "moverange",
        "setrangeconfig",
        "setrangegeometry",
        "updaterangegeometry",
        "putrangegeometry",
        "configurerangegeometry",
        "setrangeattributes",
        "updaterangeattributes",
        "setrangewindow",
        "setlbarange",
        "updatelbarange",
        "configurelbarange",
        "setbandconfig",
        "updatebandconfig",
        "setlockingband",
        "updatelockingband",
        "configurelockingband",
        "setlockingrangegeometry",
        "updatelockingrangegeometry",
        "configurelockingrangegeometry",
        "setbandgeometry",
        "updatebandgeometry",
        "configurebandgeometry",
        "defineband",
        "resizeband",
        "moveband",
        "setbandattributes",
        "updatebandattributes",
        "setbandwindow",
        "setlockingrangestate",
        "updatelockingrange",
    }:
        setrange_aliases = {
            "rangestart": "RangeStart",
            "start": "RangeStart",
            "startlba": "RangeStart",
            "lba": "RangeStart",
            "lbastart": "RangeStart",
            "startblock": "RangeStart",
            "firstlba": "RangeStart",
            "base": "RangeStart",
            "offset": "RangeStart",
            "begin": "RangeStart",
            "rangelength": "RangeLength",
            "rangesize": "RangeLength",
            "length": "RangeLength",
            "len": "RangeLength",
            "size": "RangeLength",
            "count": "RangeLength",
            "numblocks": "RangeLength",
            "blocks": "RangeLength",
            "numlbas": "RangeLength",
            "lbacount": "RangeLength",
            "blockcount": "RangeLength",
            "sectorcount": "RangeLength",
            "readlocked": "ReadLocked",
            "readlock": "ReadLocked",
            "rlocked": "ReadLocked",
            "writelocked": "WriteLocked",
            "writelock": "WriteLocked",
            "wlocked": "WriteLocked",
            "readlockenabled": "ReadLockEnabled",
            "readlockingenabled": "ReadLockEnabled",
            "readenabled": "ReadLockEnabled",
            "rlockenabled": "ReadLockEnabled",
            "writelockenabled": "WriteLockEnabled",
            "writelockingenabled": "WriteLockEnabled",
            "writeenabled": "WriteLockEnabled",
            "wlockenabled": "WriteLockEnabled",
            "lockonreset": "LockOnReset",
            "lor": "LockOnReset",
        }
        if len(args) > 0 and range_like(args[0]) and not authority_like(args[0]):
            auth = _mapping_value(kwargs, "auth", "Auth")
            range_no = range_arg(0)
            positional_start = 1
        else:
            auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth")
            range_no = range_arg(1)
            positional_start = 2
        if range_no is None or isinstance(range_no, dict):
            range_no = top_level_range_arg()
        auth_as = _mapping_value(kwargs, "authAs", "AuthAs", "auth_as", "authAS") or auth
        optional = {
            key: value
            for key, value in kwargs.items()
            if re.sub(r"[^A-Za-z0-9_]", "", _as_text(key)).lower()
            not in {
                "auth",
                "rangeno",
                "range",
                "range_no",
                "rangeid",
                "range_id",
                "rangenumber",
                "range_number",
                "rangeindex",
                "range_index",
                "band",
                "bandid",
                "band_id",
                "bandname",
                "band_name",
                "bandno",
                "band_no",
                "lockingrange",
                "locking_range",
                "lockingrangeid",
                "locking_range_id",
                "id",
                "uid",
                "obj",
                "object",
                "target",
                "authas",
                "auth_as",
            }
        }
        canonical_optional: dict[str, Any] = {}
        for key, value in optional.items():
            compact = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            canonical_key = setrange_aliases.get(compact, key)
            canonical_optional[canonical_key] = value
        optional = canonical_optional
        setrange_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "params", "Params", "parameters", "Parameters", "request", "Request", "config", "Config", "policy", "Policy", "security", "Security", "target", "Target", "operationRequest", "OperationRequest", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "state", "State", "lockState", "LockState", "locks", "Locks", "lock", "Lock")
        nested_optional_values = _mapping_value(optional, *setrange_payload_aliases)
        if not isinstance(nested_optional_values, dict):
            nested_optional_values = _mapping_value(inp, *setrange_payload_aliases)
        if isinstance(nested_optional_values, dict):
            for _ in range(4):
                for envelope in setrange_payload_aliases:
                    deeper_optional_values = _mapping_value(nested_optional_values, envelope)
                    if isinstance(deeper_optional_values, dict) and deeper_optional_values is not nested_optional_values:
                        nested_optional_values = {**nested_optional_values, **deeper_optional_values}
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    nested_optional_values,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                )
            if auth_as is None or isinstance(auth_as, dict):
                auth_as = _mapping_value(nested_optional_values, "authAs", "AuthAs", "auth_as", "authAS")
            for key in setrange_payload_aliases:
                optional.pop(key, None)
            for key, value in nested_optional_values.items():
                compact = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                optional[setrange_aliases.get(compact, key)] = value
            for nested_key in ("locks", "Locks", "lockState", "LockState", "state", "State"):
                found_locks, locks_value = _dict_lookup(nested_optional_values, nested_key)
                if isinstance(locks_value, dict):
                    read_value = _mapping_value(locks_value, "read", "Read", "readLocked", "ReadLocked", "r")
                    write_value = _mapping_value(locks_value, "write", "Write", "writeLocked", "WriteLocked", "w")
                    if read_value is not None:
                        optional["ReadLocked"] = read_value
                    if write_value is not None:
                        optional["WriteLocked"] = write_value
                    if found_locks:
                        optional.pop(nested_key, None)
        consumed_positional_indices: set[int] = set()
        if len(args) > positional_start and isinstance(args[positional_start], dict):
            consumed_positional_indices.add(positional_start)
            positional_options = args[positional_start]
            nested_options = _mapping_value(positional_options, *setrange_payload_aliases)
            if isinstance(nested_options, dict):
                positional_options = nested_options
                for _ in range(4):
                    for envelope in setrange_payload_aliases:
                        deeper_options = _mapping_value(positional_options, envelope)
                        if isinstance(deeper_options, dict) and deeper_options is not positional_options:
                            positional_options = {**positional_options, **deeper_options}
            for key, value in positional_options.items():
                compact = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if compact in {
                    "auth",
                    "authas",
                    "auth_as",
                    "rangeno",
                    "range",
                    "range_no",
                    "rangeid",
                    "range_id",
                    "rangenumber",
                    "range_number",
                    "rangeindex",
                    "range_index",
                    "band",
                    "bandid",
                    "band_id",
                    "bandname",
                    "band_name",
                    "bandno",
                    "band_no",
                    "lockingrange",
                    "locking_range",
                    "lockingrangeid",
                    "locking_range_id",
                    "id",
                    "uid",
                    "obj",
                    "object",
                    "target",
                }:
                    continue
                optional[setrange_aliases.get(compact, key)] = value
        positional_fields = (
            (positional_start, "RangeStart"),
            (positional_start + 1, "RangeLength"),
            (positional_start + 2, "ReadLocked"),
            (positional_start + 3, "WriteLocked"),
            (positional_start + 4, "ReadLockEnabled"),
            (positional_start + 5, "WriteLockEnabled"),
            (positional_start + 6, "LockOnReset"),
        )
        for index, name in positional_fields:
            if index in consumed_positional_indices:
                continue
            if len(args) > index and not any(re.sub(r"[^A-Za-z0-9_]", "", _as_text(key)).lower() == name.lower() for key in optional):
                optional[name] = args[index]
        optional["authAs"] = auth_as
        return build("Set", _band_target_from_range_value(range_no), optional=optional, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getrange",
        "getrangeconfig",
        "readrangeconfig",
        "fetchrangeconfig",
        "getlockingrange",
        "querylockingrange",
        "fetchlockingrange",
        "getband",
        "getbandrange",
        "readband",
        "fetchband",
        "queryband",
        "getbandconfig",
        "readbandconfig",
        "fetchbandconfig",
        "getrangeinfo",
        "getrangestate",
        "getrangegeometry",
        "readrangegeometry",
        "getbandgeometry",
        "readbandgeometry",
        "getrangeattributes",
        "getbandattributes",
        "readrange",
        "fetchrange",
        "queryrange",
        "rangestatus",
        "getlockingrangestate",
        "readlockingrange",
        "loadrange",
    }:
        range_no = range_arg(0)
        auth = _arg_or_kw(args, kwargs, 1, "auth", "Auth")
        auth_as = authas(auth)
        getrange_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "target", "Target", "operationRequest", "OperationRequest", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "rangeValues", "RangeValues", "geometry", "Geometry", "window", "Window", "range", "Range", "selection", "Selection")
        range_payload = _mapping_value(kwargs, *getrange_payload_aliases)
        if not isinstance(range_payload, dict):
            range_payload = _mapping_value(inp, *getrange_payload_aliases)
        if not isinstance(range_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            range_payload = _mapping_value(args[0], *getrange_payload_aliases)
            if not isinstance(range_payload, dict):
                range_payload = args[0]
        if isinstance(range_payload, dict):
            for _ in range(4):
                for envelope in getrange_payload_aliases:
                    deeper_range_payload = _mapping_value(range_payload, envelope)
                    if isinstance(deeper_range_payload, dict) and deeper_range_payload is not range_payload:
                        range_payload = {**range_payload, **deeper_range_payload}
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    range_payload,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                )
            if auth is None:
                auth = _mapping_value(range_payload, "auth", "Auth", "authority", "Authority")
            auth_as = _mapping_value(range_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        return build("Get", _band_target_from_range_value(range_no), optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"lockrange", "unlockrange"}:
        range_no = range_arg(0)
        lock_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "target", "Target", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "locks", "Locks", "lock", "Lock", "lockState", "LockState", "state", "State")
        lock_payload = _mapping_value(kwargs, *lock_payload_aliases)
        if not isinstance(lock_payload, dict):
            lock_payload = _mapping_value(inp, *lock_payload_aliases)
        if not isinstance(lock_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            lock_payload = _mapping_value(args[0], *lock_payload_aliases)
            if not isinstance(lock_payload, dict):
                lock_payload = args[0]
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        optional: dict[str, Any] = {}
        default_lock_value = function_alias == "lockrange"
        read_flag = _arg_or_kw(args, kwargs, 2, "read", "Read", "readLock", "ReadLock", "readLocked", "ReadLocked")
        write_flag = _arg_or_kw(args, kwargs, 3, "write", "Write", "writeLock", "WriteLock", "writeLocked", "WriteLocked")
        if isinstance(lock_payload, dict):
            for _ in range(2):
                for envelope in lock_payload_aliases:
                    deeper_lock_payload = _mapping_value(lock_payload, envelope)
                    if isinstance(deeper_lock_payload, dict) and deeper_lock_payload is not lock_payload:
                        lock_payload = {**lock_payload, **deeper_lock_payload}
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(lock_payload, "rangeNo", "range", "Range", "range_no", "rangeID", "rangeId", "range_id", "band", "Band", "bandID", "bandId", "band_id", "bandName", "band_name", "bandNo", "band_no", "rangeName", "range_name", "lockingRange", "locking_range", "id", "ID", "uid", "UID", "obj", "object", "Object", "target", "Target")
            auth_as = _mapping_value(lock_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
            read_flag = _mapping_value(lock_payload, "read", "Read", "readLock", "ReadLock", "readLocked", "ReadLocked") if read_flag is None else read_flag
            write_flag = _mapping_value(lock_payload, "write", "Write", "writeLock", "WriteLock", "writeLocked", "WriteLocked") if write_flag is None else write_flag
        if read_flag is None and write_flag is None:
            optional["ReadLocked"] = default_lock_value
            optional["WriteLocked"] = default_lock_value
        else:
            if _as_bool(read_flag) is not False:
                optional["ReadLocked"] = default_lock_value
            if _as_bool(write_flag) is not False:
                optional["WriteLocked"] = default_lock_value
        optional["authAs"] = auth_as
        return build("Set", _band_target_from_range_value(range_no), optional=optional, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    reencrypt_request_aliases = {
        "startreencrypt": "START_req",
        "requestreencrypt": "START_req",
        "triggerreencrypt": "START_req",
        "reencrypt": "START_req",
        "beginreencrypt": "START_req",
        "beginreencryption": "START_req",
        "reencryptrange": "START_req",
        "startreencryption": "START_req",
        "updatereencryptrequest": "START_req",
        "putreencryptrequest": "START_req",
        "pausereencrypt": "PAUSE_req",
        "pausereencryption": "PAUSE_req",
        "resumereencrypt": "CONT_req",
        "resumereencryption": "CONT_req",
        "continuereencrypt": "CONT_req",
        "continuereencryption": "CONT_req",
        "advanceKey": "ADVKEY_req",
        "advancekey": "ADVKEY_req",
        "advKey": "ADVKEY_req",
        "advkey": "ADVKEY_req",
        "advanceReEncryptKey": "ADVKEY_req",
        "advancereencryptkey": "ADVKEY_req",
        "commitReEncryptKey": "ADVKEY_req",
        "commitreencryptkey": "ADVKEY_req",
        "retIdle": "RETIDLE_req",
        "retidle": "RETIDLE_req",
        "returnIdle": "RETIDLE_req",
        "returnidle": "RETIDLE_req",
        "returnToIdle": "RETIDLE_req",
        "returntoidle": "RETIDLE_req",
        "stopReEncrypt": "RETIDLE_req",
        "stopreencrypt": "RETIDLE_req",
        "cancelReEncrypt": "RETIDLE_req",
        "cancelreencrypt": "RETIDLE_req",
    }
    if function_alias in reencrypt_request_aliases or function_alias == "setreencryptrequest":
        def reencrypt_range_selector(value: Any) -> Any:
            if not isinstance(value, dict):
                return value
            nested_value = _mapping_value(
                value,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "rangeName",
                "range_name",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
            )
            if nested_value is None:
                nested_value = _mapping_value(
                    value,
                    "values",
                    "Values",
                    "settings",
                    "Settings",
                    "options",
                    "Options",
                    "policy",
                    "Policy",
                    "config",
                    "Config",
                    "request",
                    "Request",
                    "query",
                    "Query",
                    "target",
                    "Target",
                    "lockingRequest",
                    "LockingRequest",
                    "rangeRequest",
                    "RangeRequest",
                    "lockingRangeRequest",
                    "LockingRangeRequest",
                    "reencryptRequest",
                    "ReEncryptRequest",
                    "reencrypt",
                    "ReEncrypt",
                    "reEncryption",
                    "ReEncryption",
                )
            return reencrypt_range_selector(nested_value) if isinstance(nested_value, dict) and nested_value is not value else nested_value

        range_no = range_arg(0)
        range_no = reencrypt_range_selector(range_no)
        request = reencrypt_request_aliases.get(function_alias)
        if request is None:
            request = _arg_or_kw(args, kwargs, 1, "ReEncryptRequest", "reencryptRequest", "re_encrypt_request", "request", "Request", "value", "Value")
        reencrypt_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "target",
            "Target",
            "query",
            "Query",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "reencryptRequest",
            "ReEncryptRequest",
            "reencrypt",
            "ReEncrypt",
            "reEncryption",
            "ReEncryption",
        )
        reencrypt_payload = _mapping_value(kwargs, *reencrypt_payload_aliases)
        if not isinstance(reencrypt_payload, dict):
            reencrypt_payload = _mapping_value(inp, *reencrypt_payload_aliases)
        if not isinstance(reencrypt_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            reencrypt_payload = _mapping_value(args[0], *reencrypt_payload_aliases)
            if not isinstance(reencrypt_payload, dict):
                reencrypt_payload = args[0]
        if isinstance(reencrypt_payload, dict):
            for _ in range(4):
                merged_reencrypt_payload = dict(reencrypt_payload)
                for envelope in reencrypt_payload_aliases:
                    nested_reencrypt_payload = _mapping_value(reencrypt_payload, envelope)
                    if isinstance(nested_reencrypt_payload, dict) and nested_reencrypt_payload is not reencrypt_payload:
                        merged_reencrypt_payload.update(nested_reencrypt_payload)
                if merged_reencrypt_payload == reencrypt_payload:
                    break
                reencrypt_payload = merged_reencrypt_payload
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        if isinstance(reencrypt_payload, dict):
            if range_no is None or isinstance(range_no, dict):
                range_no = reencrypt_range_selector(reencrypt_payload)
            if request is None or isinstance(request, dict):
                candidate_request = _mapping_value(reencrypt_payload, "ReEncryptRequest", "reencryptRequest", "re_encrypt_request", "request", "Request", "value", "Value")
                if isinstance(candidate_request, dict) or candidate_request is None:
                    candidate_request = _mapping_value(reencrypt_payload, "ReEncryptRequest", "reencryptRequest", "re_encrypt_request", "value", "Value")
                if isinstance(candidate_request, dict) or candidate_request is None:
                    for envelope in ("values", "Values", "request", "Request", "policy", "Policy", "config", "Config", "reencrypt", "ReEncrypt"):
                        nested_request_payload = _mapping_value(reencrypt_payload, envelope)
                        if isinstance(nested_request_payload, dict):
                            candidate_request = _mapping_value(nested_request_payload, "ReEncryptRequest", "reencryptRequest", "re_encrypt_request", "value", "Value")
                            if not isinstance(candidate_request, dict) and candidate_request is not None:
                                break
                if not isinstance(candidate_request, dict):
                    request = candidate_request
            auth_as = _mapping_value(reencrypt_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        return build("Set", _band_target_from_range_value(range_no), optional={"ReEncryptRequest": request, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
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
        def reencrypt_range_selector(value: Any) -> Any:
            if not isinstance(value, dict):
                return value
            nested_value = _mapping_value(
                value,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "rangeName",
                "range_name",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
            if nested_value is None:
                nested_value = _mapping_value(
                    value,
                    "values",
                    "Values",
                    "settings",
                    "Settings",
                    "options",
                    "Options",
                    "policy",
                    "Policy",
                    "config",
                    "Config",
                    "request",
                    "Request",
                    "query",
                    "Query",
                    "target",
                    "Target",
                    "lockingRequest",
                    "LockingRequest",
                    "rangeRequest",
                    "RangeRequest",
                    "lockingRangeRequest",
                    "LockingRangeRequest",
                    "reencryptRequest",
                    "ReEncryptRequest",
                    "reencrypt",
                    "ReEncrypt",
                    "reEncryption",
                    "ReEncryption",
                )
            return reencrypt_range_selector(nested_value) if isinstance(nested_value, dict) and nested_value is not value else nested_value

        range_no = range_arg(0)
        range_no = reencrypt_range_selector(range_no)
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        reencrypt_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "status", "Status", "target", "Target", "lockingRequest", "LockingRequest", "rangeRequest", "RangeRequest", "lockingRangeRequest", "LockingRangeRequest", "reencryptRequest", "ReEncryptRequest", "reencrypt", "ReEncrypt", "reEncryption", "ReEncryption")
        reencrypt_payload = _mapping_value(kwargs, *reencrypt_payload_aliases)
        if not isinstance(reencrypt_payload, dict):
            reencrypt_payload = _mapping_value(inp, *reencrypt_payload_aliases)
        if not isinstance(reencrypt_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            reencrypt_payload = _mapping_value(args[0], *reencrypt_payload_aliases)
            if not isinstance(reencrypt_payload, dict):
                reencrypt_payload = args[0]
        if isinstance(reencrypt_payload, dict):
            for _ in range(4):
                merged_reencrypt_payload = dict(reencrypt_payload)
                for envelope in reencrypt_payload_aliases:
                    nested_reencrypt_payload = _mapping_value(reencrypt_payload, envelope)
                    if isinstance(nested_reencrypt_payload, dict) and nested_reencrypt_payload is not reencrypt_payload:
                        merged_reencrypt_payload.update(nested_reencrypt_payload)
                if merged_reencrypt_payload == reencrypt_payload:
                    break
                reencrypt_payload = merged_reencrypt_payload
            if range_no is None or isinstance(range_no, dict):
                range_no = reencrypt_range_selector(reencrypt_payload)
            auth_as = _mapping_value(reencrypt_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        cellblock = [{"startColumn": 12}, {"endColumn": 12}]
        return build("Get", _band_target_from_range_value(range_no), raw_args={"CellBlock": cellblock}, optional={"CellBlock": cellblock, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    locking_column_getter_aliases = {
        "getnextkey": 11,
        "getnextmek": 11,
        "getpendingkey": 11,
        "getpendingmek": 11,
        "getreencryptkey": 11,
        "getreencryptionkey": 11,
        "getnewkey": 11,
        "getnewmek": 11,
        "getrangenextkey": 11,
        "getrangependingkey": 11,
        "getrangenewkey": 11,
        "getrangependingmek": 11,
        "getrangenewmek": 11,
        "getrangereencryptkey": 11,
        "getrangereencryptionkey": 11,
        "getadvkeymode": 14,
        "getadvancedkeymode": 14,
        "getverifymode": 15,
        "getcontonreset": 16,
        "getcontinueonreset": 16,
        "getreencryptcontonreset": 16,
        "getreencryptcontinueonreset": 16,
        "iscontonreset": 16,
        "iscontinueonreset": 16,
        "getlastreencryptlba": 17,
        "getlastreencryptionlba": 17,
        "getlastreenclba": 17,
        "getreencryptlba": 17,
        "getreencryptionlba": 17,
        "getlastreencryptstatus": 18,
        "getlastreencryptionstatus": 18,
        "getlastreencstat": 18,
        "getlastreencryptstat": 18,
        "getgeneralstatus": 19,
        "getlockingrangestatus": 19,
    }
    if function_alias in locking_column_getter_aliases:
        def locking_column_range_selector(value: Any) -> Any:
            if not isinstance(value, dict):
                return value
            nested_value = _mapping_value(
                value,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "rangeName",
                "range_name",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
            return locking_column_range_selector(nested_value) if isinstance(nested_value, dict) and nested_value is not value else nested_value

        range_no = range_arg(0)
        range_no = locking_column_range_selector(range_no)
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        getter_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "status", "Status")
        getter_payload = _mapping_value(kwargs, *getter_payload_aliases)
        if not isinstance(getter_payload, dict):
            getter_payload = _mapping_value(inp, *getter_payload_aliases)
        if not isinstance(getter_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            getter_payload = _mapping_value(args[0], *getter_payload_aliases)
            if not isinstance(getter_payload, dict):
                getter_payload = args[0]
        if isinstance(getter_payload, dict):
            for _ in range(2):
                nested_getter_payload = _mapping_value(getter_payload, "policy", "Policy", "config", "Config", "request", "Request", "query", "Query", "status", "Status", "locking", "Locking", "range", "Range", "target", "Target")
                if isinstance(nested_getter_payload, dict) and nested_getter_payload is not getter_payload:
                    getter_payload = {**getter_payload, **nested_getter_payload}
            if range_no is None or isinstance(range_no, dict):
                range_no = locking_column_range_selector(getter_payload)
            auth_as = _mapping_value(getter_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        column = locking_column_getter_aliases[function_alias]
        cellblock = [{"startColumn": column}, {"endColumn": column}]
        return build("Get", _band_target_from_range_value(range_no), raw_args={"CellBlock": cellblock}, optional={"CellBlock": cellblock, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "dataremoval",
        "startdataremoval",
        "startdataremovaloperation",
        "begindataremoval",
        "setdataremovalmechanism",
        "setactivedataremovalmechanism",
        "selectdataremovalmechanism",
        "choosedataremovalmechanism",
        "configuredataremoval",
        "configuredataremovalmechanism",
        "updatedataremovalmechanism",
        "putdataremovalmechanism",
        "setdataremovalmode",
        "setdataremovalmethod",
        "erasedata",
        "dataerase",
        "startdataerase",
        "begindataerase",
        "sanitizedata",
        "secureerasedata",
        "setdataremoval",
    }:
        mechanism = _arg_or_kw(args, kwargs, 0, "ActiveDataRemovalMechanism", "activeDataRemovalMechanism", "mechanism", "Mechanism", "dataRemovalMechanism", "value", "Value")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        removal_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "dataRemovalRequest",
            "DataRemovalRequest",
            "removalRequest",
            "RemovalRequest",
            "adminRequest",
            "AdminRequest",
            "dataRemoval",
            "DataRemoval",
            "activeDataRemoval",
            "ActiveDataRemoval",
            "removal",
            "Removal",
        )
        removal_payload = _mapping_value(kwargs, *removal_payload_aliases)
        if not isinstance(removal_payload, dict):
            removal_payload = _mapping_value(inp, *removal_payload_aliases)
        if not isinstance(removal_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            removal_payload = _mapping_value(args[0], *removal_payload_aliases)
            if not isinstance(removal_payload, dict):
                removal_payload = args[0]
        if isinstance(removal_payload, dict):
            for _ in range(2):
                for envelope in removal_payload_aliases:
                    nested_removal_payload = _mapping_value(removal_payload, envelope)
                    if isinstance(nested_removal_payload, dict) and nested_removal_payload is not removal_payload:
                        removal_payload = {**removal_payload, **nested_removal_payload}
        if isinstance(removal_payload, dict):
            if mechanism is None or isinstance(mechanism, dict):
                mechanism = _mapping_value(removal_payload, "ActiveDataRemovalMechanism", "activeDataRemovalMechanism", "mechanism", "Mechanism", "dataRemovalMechanism", "value", "Value")
            auth_as = _mapping_value(removal_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        return build("Set", "DataRemovalMechanism", optional={"ActiveDataRemovalMechanism": mechanism, "authAs": auth_as}, sp_value="AdminSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getdataremovalmechanism",
        "getactivedataremovalmechanism",
        "readdataremovalmechanism",
        "fetchdataremovalmechanism",
        "querydataremovalmechanism",
        "loaddataremovalmechanism",
        "readactivedataremovalmechanism",
        "fetchactivedataremovalmechanism",
        "queryactivedataremovalmechanism",
        "loadactivedataremovalmechanism",
        "getdataremovalmode",
        "getdataremovalmethod",
        "getdataremoval",
        "readdataremoval",
        "fetchdataremoval",
        "getdataremovalstatus",
        "isdataremovalactive",
    }:
        auth_as = _arg_or_kw(args, kwargs, 0, "authAs", "AuthAs", "auth_as", "authAS")
        removal_get_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "request", "Request", "dataRemovalRequest", "DataRemovalRequest", "removalRequest", "RemovalRequest", "adminRequest", "AdminRequest", "dataRemoval", "DataRemoval", "activeDataRemoval", "ActiveDataRemoval", "removal", "Removal")
        removal_payload = _mapping_value(kwargs, *removal_get_payload_aliases)
        if not isinstance(removal_payload, dict):
            removal_payload = _mapping_value(inp, *removal_get_payload_aliases)
        if isinstance(removal_payload, dict):
            for _ in range(2):
                merged_removal_payload = dict(removal_payload)
                for envelope in removal_get_payload_aliases:
                    nested_removal_payload = _mapping_value(removal_payload, envelope)
                    if isinstance(nested_removal_payload, dict) and nested_removal_payload is not removal_payload:
                        merged_removal_payload.update(nested_removal_payload)
                if merged_removal_payload == removal_payload:
                    break
                removal_payload = merged_removal_payload
            auth_as = _mapping_value(removal_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        cellblock = [{"startColumn": 1}, {"endColumn": 1}]
        return build("Get", "DataRemovalMechanism", raw_args={"CellBlock": cellblock}, optional={"CellBlock": cellblock, "authAs": auth_as}, sp_value="AdminSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    def log_table_target(value: Any) -> Any:
        if value is None:
            return "Log"
        symbol, uid = _object_ref_from_value(value)
        if symbol in {"Log", "LogTable"} or symbol.startswith(("Log_", "UnknownLog_")):
            return value
        text = re.sub(r"[^A-Za-z0-9_]", "", _as_text(value or ""))
        return f"UnknownLog_{text or 'Default'}"

    if function_alias in {"addlog", "appendlog", "writelog", "putlog", "putLog", "putlogentry", "addlogentry", "appendlogentry", "writelogentry", "storelogentry", "createlogentry"}:
        log_target = _arg_or_kw(args, kwargs, 0, "log", "Log", "logTable", "LogTable", "table", "Table", "obj", "object", "Object", "target", "Target")
        entry_name = _arg_or_kw(args, kwargs, 1, "LogEntryName", "logEntryName", "entry", "Entry", "name", "Name", "LogName", "logName")
        data = _arg_or_kw(args, kwargs, 2, "Data", "data", "payload", "Payload", "bytes", "Bytes", "value", "Value")
        auth_as = _arg_or_kw(args, kwargs, 3, "authAs", "AuthAs", "auth_as", "authAS")
        log_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "logRequest", "LogRequest", "addLogRequest", "AddLogRequest",
            "logEntryRequest", "LogEntryRequest",
        )
        log_payload = _mapping_value(kwargs, *log_payload_aliases)
        if not isinstance(log_payload, dict):
            log_payload = _mapping_value(inp, *log_payload_aliases)
        if not isinstance(log_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            log_payload = _mapping_value(args[0], *log_payload_aliases)
            if not isinstance(log_payload, dict):
                log_payload = args[0]
        if isinstance(log_payload, dict):
            for _ in range(2):
                merged_log_payload = dict(log_payload)
                for envelope in log_payload_aliases:
                    found_envelope, nested_log_payload = _dict_lookup(log_payload, envelope)
                    if found_envelope and isinstance(nested_log_payload, dict) and nested_log_payload is not log_payload:
                        merged_log_payload.update(nested_log_payload)
                if merged_log_payload == log_payload:
                    break
                log_payload = merged_log_payload
            if log_target is None or isinstance(log_target, dict):
                log_target = _mapping_value(log_payload, "log", "Log", "logTable", "LogTable", "table", "Table", "obj", "object", "Object", "target", "Target")
            entry_name = _mapping_value(log_payload, "LogEntryName", "logEntryName", "entry", "Entry", "name", "Name", "LogName", "logName") or entry_name
            data = _mapping_value(log_payload, "Data", "data", "payload", "Payload", "bytes", "Bytes", "value", "Value") or data
            auth_as = _mapping_value(log_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if entry_name is not None:
            raw_args["LogEntryName"] = entry_name
        if data is not None:
            raw_args["Data"] = data
        return build("AddLog", log_table_target(log_target), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"clearlog", "flushlog", "synclog", "eraselog", "resetlog", "truncatelog", "clearlogentries"}:
        log_target = _arg_or_kw(args, kwargs, 0, "log", "Log", "logTable", "LogTable", "table", "Table", "obj", "object", "Object", "target", "Target")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        log_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "logRequest", "LogRequest", "clearLogRequest", "ClearLogRequest",
            "flushLogRequest", "FlushLogRequest",
        )
        log_payload = _mapping_value(kwargs, *log_payload_aliases)
        if not isinstance(log_payload, dict):
            log_payload = _mapping_value(inp, *log_payload_aliases)
        if isinstance(log_payload, dict):
            for _ in range(2):
                merged_log_payload = dict(log_payload)
                for envelope in log_payload_aliases:
                    found_envelope, nested_log_payload = _dict_lookup(log_payload, envelope)
                    if found_envelope and isinstance(nested_log_payload, dict) and nested_log_payload is not log_payload:
                        merged_log_payload.update(nested_log_payload)
                if merged_log_payload == log_payload:
                    break
                log_payload = merged_log_payload
            if log_target is None or isinstance(log_target, dict):
                log_target = _mapping_value(log_payload, "log", "Log", "logTable", "LogTable", "table", "Table", "obj", "object", "Object", "target", "Target")
            auth_as = _mapping_value(log_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        method = "FlushLog" if function_alias in {"flushlog", "synclog"} else "ClearLog"
        return build(method, log_table_target(log_target), optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"createlog", "newlog", "makelog", "createlogtable", "newlogtable", "allocatelog"}:
        name = _arg_or_kw(args, kwargs, 0, "NewLogTableName", "newLogTableName", "name", "Name", "LogTableName", "logTableName")
        high_security = _arg_or_kw(args, kwargs, 1, "HighSecurity", "highSecurity", "high_security")
        min_size = _arg_or_kw(args, kwargs, 2, "MinSize", "minSize", "min_size", "size", "Size")
        max_size = _arg_or_kw(args, kwargs, 3, "MaxSize", "maxSize", "max_size", "MaximumSize", "maximumSize")
        hint_size = _arg_or_kw(args, kwargs, 4, "HintSize", "hintSize", "hint_size")
        common = _arg_or_kw(args, kwargs, 5, "CommonName", "commonName", "common_name")
        auth_as = _arg_or_kw(args, kwargs, 6, "authAs", "AuthAs", "auth_as", "authAS")
        log_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "logRequest", "LogRequest", "createLogRequest", "CreateLogRequest",
            "logListRequest", "LogListRequest",
        )
        log_payload = _mapping_value(kwargs, *log_payload_aliases)
        if not isinstance(log_payload, dict):
            log_payload = _mapping_value(inp, *log_payload_aliases)
        if not isinstance(log_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            log_payload = _mapping_value(args[0], *log_payload_aliases)
            if not isinstance(log_payload, dict):
                log_payload = args[0]
        if isinstance(log_payload, dict):
            for _ in range(2):
                merged_log_payload = dict(log_payload)
                for envelope in log_payload_aliases:
                    found_envelope, nested_log_payload = _dict_lookup(log_payload, envelope)
                    if found_envelope and isinstance(nested_log_payload, dict) and nested_log_payload is not log_payload:
                        merged_log_payload.update(nested_log_payload)
                if merged_log_payload == log_payload:
                    break
                log_payload = merged_log_payload
            name = _mapping_value(log_payload, "NewLogTableName", "newLogTableName", "name", "Name", "LogTableName", "logTableName") or name
            high_security = _mapping_value(log_payload, "HighSecurity", "highSecurity", "high_security") if high_security is None else high_security
            min_size = _mapping_value(log_payload, "MinSize", "minSize", "min_size", "size", "Size") if min_size is None else min_size
            max_size = _mapping_value(log_payload, "MaxSize", "maxSize", "max_size", "MaximumSize", "maximumSize") if max_size is None else max_size
            hint_size = _mapping_value(log_payload, "HintSize", "hintSize", "hint_size") if hint_size is None else hint_size
            common = _mapping_value(log_payload, "CommonName", "commonName", "common_name") or common
            auth_as = _mapping_value(log_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if name is not None:
            raw_args["NewLogTableName"] = name
        if high_security is not None:
            raw_args["HighSecurity"] = high_security
        if min_size is not None:
            raw_args["MinSize"] = min_size
        if max_size is not None:
            raw_args["MaxSize"] = max_size
        if hint_size is not None:
            raw_args["HintSize"] = hint_size
        if common is not None:
            raw_args["CommonName"] = common
        return build("CreateLog", "LogList", raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    def crypto_object_target(value: Any, default: str) -> Any:
        if value is None:
            return default
        normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).lower()
        hash_aliases = {
            "sha1": "H_SHA_1",
            "hsha1": "H_SHA_1",
            "hashsha1": "H_SHA_1",
            "sha256": "H_SHA_256",
            "hsha256": "H_SHA_256",
            "hashsha256": "H_SHA_256",
            "sha384": "H_SHA_384",
            "hsha384": "H_SHA_384",
            "hashsha384": "H_SHA_384",
            "sha512": "H_SHA_512",
            "hsha512": "H_SHA_512",
            "hashsha512": "H_SHA_512",
        }
        cipher_aliases = {
            "aes128": "C_AES_128",
            "caes128": "C_AES_128",
            "aes256": "C_AES_256",
            "caes256": "C_AES_256",
            "rsa1024": "C_RSA_1024",
            "crsa1024": "C_RSA_1024",
            "rsa2048": "C_RSA_2048",
            "crsa2048": "C_RSA_2048",
        }
        alias = hash_aliases.get(normalized) or cipher_aliases.get(normalized)
        if alias:
            return alias
        symbol, uid = _object_ref_from_value(value)
        if symbol or uid:
            return value
        return value

    crypto_alias_methods = {
        "hashinit": ("HashInit", "H_SHA_256"),
        "inithash": ("HashInit", "H_SHA_256"),
        "starthash": ("HashInit", "H_SHA_256"),
        "hashBegin": ("HashInit", "H_SHA_256"),
        "hashbegin": ("HashInit", "H_SHA_256"),
        "hashstart": ("HashInit", "H_SHA_256"),
        "beginhash": ("HashInit", "H_SHA_256"),
        "begindigest": ("HashInit", "H_SHA_256"),
        "digestinit": ("HashInit", "H_SHA_256"),
        "sha256init": ("HashInit", "H_SHA_256"),
        "digestStart": ("HashInit", "H_SHA_256"),
        "startdigest": ("HashInit", "H_SHA_256"),
        "digeststart": ("HashInit", "H_SHA_256"),
        "hash": ("Hash", "H_SHA_256"),
        "hashupdate": ("Hash", "H_SHA_256"),
        "updatehash": ("Hash", "H_SHA_256"),
        "hashdata": ("Hash", "H_SHA_256"),
        "computehash": ("Hash", "H_SHA_256"),
        "digest": ("Hash", "H_SHA_256"),
        "hashbytes": ("Hash", "H_SHA_256"),
        "updatedigest": ("Hash", "H_SHA_256"),
        "digestUpdate": ("Hash", "H_SHA_256"),
        "digestupdate": ("Hash", "H_SHA_256"),
        "sha256update": ("Hash", "H_SHA_256"),
        "hashbuffer": ("Hash", "H_SHA_256"),
        "processhash": ("Hash", "H_SHA_256"),
        "processDigest": ("Hash", "H_SHA_256"),
        "processdigest": ("Hash", "H_SHA_256"),
        "hashfinal": ("HashFinalize", "H_SHA_256"),
        "finalhash": ("HashFinalize", "H_SHA_256"),
        "hashfinalize": ("HashFinalize", "H_SHA_256"),
        "hashfinish": ("HashFinalize", "H_SHA_256"),
        "completehash": ("HashFinalize", "H_SHA_256"),
        "finishhash": ("HashFinalize", "H_SHA_256"),
        "finalizehash": ("HashFinalize", "H_SHA_256"),
        "finalDigest": ("HashFinalize", "H_SHA_256"),
        "finaldigest": ("HashFinalize", "H_SHA_256"),
        "finishdigest": ("HashFinalize", "H_SHA_256"),
        "digestfinal": ("HashFinalize", "H_SHA_256"),
        "completedigest": ("HashFinalize", "H_SHA_256"),
        "sha256final": ("HashFinalize", "H_SHA_256"),
        "hmacinit": ("HMACInit", "H_SHA_256"),
        "inithmac": ("HMACInit", "H_SHA_256"),
        "starthmac": ("HMACInit", "H_SHA_256"),
        "hmacstart": ("HMACInit", "H_SHA_256"),
        "beginhmac": ("HMACInit", "H_SHA_256"),
        "initMAC": ("HMACInit", "H_SHA_256"),
        "initmac": ("HMACInit", "H_SHA_256"),
        "macinit": ("HMACInit", "H_SHA_256"),
        "startmac": ("HMACInit", "H_SHA_256"),
        "beginmac": ("HMACInit", "H_SHA_256"),
        "macstart": ("HMACInit", "H_SHA_256"),
        "hmacbegin": ("HMACInit", "H_SHA_256"),
        "sha256hmacinit": ("HMACInit", "H_SHA_256"),
        "hmac": ("HMAC", "H_SHA_256"),
        "hmacupdate": ("HMAC", "H_SHA_256"),
        "hmacdata": ("HMAC", "H_SHA_256"),
        "updatehmac": ("HMAC", "H_SHA_256"),
        "computehmac": ("HMAC", "H_SHA_256"),
        "hmacbytes": ("HMAC", "H_SHA_256"),
        "macupdate": ("HMAC", "H_SHA_256"),
        "updatemac": ("HMAC", "H_SHA_256"),
        "processMAC": ("HMAC", "H_SHA_256"),
        "processmac": ("HMAC", "H_SHA_256"),
        "processhmac": ("HMAC", "H_SHA_256"),
        "hmacdigest": ("HMAC", "H_SHA_256"),
        "digestHMAC": ("HMAC", "H_SHA_256"),
        "digesthmac": ("HMAC", "H_SHA_256"),
        "macDigest": ("HMAC", "H_SHA_256"),
        "macdigest": ("HMAC", "H_SHA_256"),
        "hmacfinal": ("HMACFinalize", "H_SHA_256"),
        "hmacfinalize": ("HMACFinalize", "H_SHA_256"),
        "finishhmac": ("HMACFinalize", "H_SHA_256"),
        "finalhmac": ("HMACFinalize", "H_SHA_256"),
        "finalizehmac": ("HMACFinalize", "H_SHA_256"),
        "hmacfinish": ("HMACFinalize", "H_SHA_256"),
        "completehmac": ("HMACFinalize", "H_SHA_256"),
        "finishmac": ("HMACFinalize", "H_SHA_256"),
        "finalMAC": ("HMACFinalize", "H_SHA_256"),
        "finalmac": ("HMACFinalize", "H_SHA_256"),
        "macfinal": ("HMACFinalize", "H_SHA_256"),
        "completeMAC": ("HMACFinalize", "H_SHA_256"),
        "completemac": ("HMACFinalize", "H_SHA_256"),
        "finalizemac": ("HMACFinalize", "H_SHA_256"),
        "encryptinit": ("EncryptInit", "C_AES_256"),
        "initEncrypt": ("EncryptInit", "C_AES_256"),
        "initencrypt": ("EncryptInit", "C_AES_256"),
        "startencrypt": ("EncryptInit", "C_AES_256"),
        "beginencrypt": ("EncryptInit", "C_AES_256"),
        "beginEncryption": ("EncryptInit", "C_AES_256"),
        "beginencryption": ("EncryptInit", "C_AES_256"),
        "encryptBegin": ("EncryptInit", "C_AES_256"),
        "encryptbegin": ("EncryptInit", "C_AES_256"),
        "encryptstart": ("EncryptInit", "C_AES_256"),
        "aesencryptinit": ("EncryptInit", "C_AES_256"),
        "initEncryption": ("EncryptInit", "C_AES_256"),
        "initencryption": ("EncryptInit", "C_AES_256"),
        "startencryption": ("EncryptInit", "C_AES_256"),
        "encrypt": ("Encrypt", "C_AES_256"),
        "encryptdata": ("Encrypt", "C_AES_256"),
        "updateencrypt": ("Encrypt", "C_AES_256"),
        "encryptUpdate": ("Encrypt", "C_AES_256"),
        "encryptupdate": ("Encrypt", "C_AES_256"),
        "updateEncryption": ("Encrypt", "C_AES_256"),
        "updateencryption": ("Encrypt", "C_AES_256"),
        "encryptbytes": ("Encrypt", "C_AES_256"),
        "encryptbuffer": ("Encrypt", "C_AES_256"),
        "processencrypt": ("Encrypt", "C_AES_256"),
        "processEncryption": ("Encrypt", "C_AES_256"),
        "processencryption": ("Encrypt", "C_AES_256"),
        "doencrypt": ("Encrypt", "C_AES_256"),
        "encryptfinal": ("EncryptFinalize", "C_AES_256"),
        "encryptfinalize": ("EncryptFinalize", "C_AES_256"),
        "finishencrypt": ("EncryptFinalize", "C_AES_256"),
        "finishEncryption": ("EncryptFinalize", "C_AES_256"),
        "finishencryption": ("EncryptFinalize", "C_AES_256"),
        "finalencrypt": ("EncryptFinalize", "C_AES_256"),
        "finalEncryption": ("EncryptFinalize", "C_AES_256"),
        "finalencryption": ("EncryptFinalize", "C_AES_256"),
        "finalizeencrypt": ("EncryptFinalize", "C_AES_256"),
        "encryptfinish": ("EncryptFinalize", "C_AES_256"),
        "completeencrypt": ("EncryptFinalize", "C_AES_256"),
        "completeEncryption": ("EncryptFinalize", "C_AES_256"),
        "completeencryption": ("EncryptFinalize", "C_AES_256"),
        "decryptinit": ("DecryptInit", "C_AES_256"),
        "initDecrypt": ("DecryptInit", "C_AES_256"),
        "initdecrypt": ("DecryptInit", "C_AES_256"),
        "startdecrypt": ("DecryptInit", "C_AES_256"),
        "begindecrypt": ("DecryptInit", "C_AES_256"),
        "beginDecryption": ("DecryptInit", "C_AES_256"),
        "begindecryption": ("DecryptInit", "C_AES_256"),
        "decryptBegin": ("DecryptInit", "C_AES_256"),
        "decryptbegin": ("DecryptInit", "C_AES_256"),
        "decryptstart": ("DecryptInit", "C_AES_256"),
        "aesdecryptinit": ("DecryptInit", "C_AES_256"),
        "initDecryption": ("DecryptInit", "C_AES_256"),
        "initdecryption": ("DecryptInit", "C_AES_256"),
        "startdecryption": ("DecryptInit", "C_AES_256"),
        "decrypt": ("Decrypt", "C_AES_256"),
        "decryptdata": ("Decrypt", "C_AES_256"),
        "updatedecrypt": ("Decrypt", "C_AES_256"),
        "decryptUpdate": ("Decrypt", "C_AES_256"),
        "decryptupdate": ("Decrypt", "C_AES_256"),
        "updateDecryption": ("Decrypt", "C_AES_256"),
        "updatedecryption": ("Decrypt", "C_AES_256"),
        "decryptbytes": ("Decrypt", "C_AES_256"),
        "decryptbuffer": ("Decrypt", "C_AES_256"),
        "processdecrypt": ("Decrypt", "C_AES_256"),
        "processDecryption": ("Decrypt", "C_AES_256"),
        "processdecryption": ("Decrypt", "C_AES_256"),
        "dodecrypt": ("Decrypt", "C_AES_256"),
        "decryptfinal": ("DecryptFinalize", "C_AES_256"),
        "decryptfinalize": ("DecryptFinalize", "C_AES_256"),
        "finishdecrypt": ("DecryptFinalize", "C_AES_256"),
        "finishDecryption": ("DecryptFinalize", "C_AES_256"),
        "finishdecryption": ("DecryptFinalize", "C_AES_256"),
        "finaldecrypt": ("DecryptFinalize", "C_AES_256"),
        "finalDecryption": ("DecryptFinalize", "C_AES_256"),
        "finaldecryption": ("DecryptFinalize", "C_AES_256"),
        "finalizedecrypt": ("DecryptFinalize", "C_AES_256"),
        "decryptfinish": ("DecryptFinalize", "C_AES_256"),
        "completedecrypt": ("DecryptFinalize", "C_AES_256"),
        "completeDecryption": ("DecryptFinalize", "C_AES_256"),
        "completedecryption": ("DecryptFinalize", "C_AES_256"),
    }
    if function_alias in crypto_alias_methods:
        method, default_target = crypto_alias_methods[function_alias]
        target = _arg_or_kw(args, kwargs, 0, "target", "Target", "object", "Object", "obj", "credential", "Credential", "hash", "Hash", "algorithm", "Algorithm", "key", "Key")
        data = _arg_or_kw(args, kwargs, 1, "Data", "data", "DataInput", "dataInput", "Input", "input", "BufferIn", "bufferIn", "payload", "Payload", "bytes", "Bytes")
        buffer_out = _arg_or_kw(args, kwargs, 2, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer")
        auth_as = _arg_or_kw(args, kwargs, 3, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        crypto_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "policy", "Policy", "config", "Config", "request", "Request",
            "operation", "Operation", "cryptoRequest", "CryptoRequest",
            "cipherRequest", "CipherRequest", "hashRequest", "HashRequest",
            "operationRequest", "OperationRequest",
        )
        crypto_payload = _mapping_value(kwargs, *crypto_payload_aliases)
        if not isinstance(crypto_payload, dict):
            crypto_payload = _mapping_value(inp, *crypto_payload_aliases)
        if not isinstance(crypto_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            crypto_payload = _mapping_value(args[0], *crypto_payload_aliases)
            if not isinstance(crypto_payload, dict):
                crypto_payload = args[0]
        if isinstance(crypto_payload, dict):
            for _ in range(2):
                nested_crypto_payload = _mapping_value(
                    crypto_payload,
                    "values",
                    "Values",
                    "settings",
                    "Settings",
                    "options",
                    "Options",
                    "policy",
                    "Policy",
                    "config",
                    "Config",
                    "request",
                    "Request",
                    "operation",
                    "Operation",
                    "cryptoRequest",
                    "CryptoRequest",
                    "cipherRequest",
                    "CipherRequest",
                    "hashRequest",
                    "HashRequest",
                    "operationRequest",
                    "OperationRequest",
                    "crypto",
                    "Crypto",
                    "cipher",
                    "Cipher",
                    "hash",
                    "Hash",
                    "input",
                    "Input",
                )
                if isinstance(nested_crypto_payload, dict) and nested_crypto_payload is not crypto_payload:
                    crypto_payload = {**crypto_payload, **nested_crypto_payload}
            if target is None or isinstance(target, dict):
                target = _mapping_value(crypto_payload, "target", "Target", "object", "Object", "obj", "credential", "Credential", "hash", "Hash", "algorithm", "Algorithm", "key", "Key")
            data = _mapping_value(crypto_payload, "Data", "data", "DataInput", "dataInput", "Input", "input", "BufferIn", "bufferIn", "payload", "Payload", "bytes", "Bytes") or data
            buffer_out = _mapping_value(crypto_payload, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer", "destination", "Destination", "dest", "Dest", "out", "Out") or buffer_out
            auth_as = _mapping_value(crypto_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if data is not None and not method.endswith("Init") and not method.endswith("Finalize"):
            raw_args["DataInput"] = data
        if buffer_out is not None:
            raw_args["BufferOut"] = buffer_out
        return build(method, crypto_object_target(target, default_target), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"verify", "verifydata", "checksignature", "verifysignature", "validatesignature", "verifyproof", "validateproof", "verifyhash", "checkhash", "validatehash", "verifydigest", "checkdigest", "validatedigest", "checkproof", "verifymac", "checkmac", "validatemac"}:
        target = _arg_or_kw(args, kwargs, 0, "target", "Target", "object", "Object", "obj", "credential", "Credential", "hash", "Hash", "algorithm", "Algorithm", "key", "Key")
        proof = _arg_or_kw(args, kwargs, 1, "Proof", "proof", "signature", "Signature", "Data", "data", "payload", "Payload")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        raw_args = {}
        if proof is not None:
            raw_args["Proof"] = proof
        return build("Verify", crypto_object_target(target, "H_SHA_256"), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getpackage",
        "getcredentialpackage",
        "getkeypackage",
        "exportcredential",
        "exportcredentialpackage",
        "readcredentialpackage",
        "exportpackage",
        "exportkeypackage",
        "exportpin",
        "exportpinpackage",
        "exportcredentialbackup",
        "exportkeybackup",
        "exportwrappedkey",
        "exportkey",
        "wrappackage",
        "wrapkey",
        "wrapkeypackage",
        "getwrappedpackage",
        "getwrappedkey",
        "backuppackage",
        "backupkeypackage",
        "backupcredential",
        "backupcredentialpackage",
        "backuppin",
        "backuppinpackage",
        "getpinpackage",
        "getcredentialbackup",
        "readcredentialbackup",
        "fetchcredentialbackup",
        "readkeybackup",
        "readpackage",
        "readkeypackage",
        "dumppackage",
        "dumpcredentialpackage",
        "dumpkeypackage",
    }:
        auth = auth_arg_value(0)
        if auth is None:
            auth = _mapping_value(kwargs, "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "credential", "Credential", "target", "Target", "obj", "object", "Object")
        purpose = _arg_or_kw(args, kwargs, 1, "Purpose", "purpose", "usage", "Usage")
        wrapping_key = _arg_or_kw(args, kwargs, 2, "WrappingKey", "wrappingKey", "wrapping_key", "WrappingKeyUID", "wrappingKeyUID")
        signing_key = _arg_or_kw(args, kwargs, 3, "SigningKey", "signingKey", "signing_key", "SigningKeyUID", "signingKeyUID")
        auth_as = _arg_or_kw(args, kwargs, 4, "authAs", "AuthAs", "auth_as", "authAS") or auth
        package_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "params", "Params", "parameters", "Parameters", "request", "Request",
            "config", "Config", "policy", "Policy", "package", "Package",
            "credential", "Credential", "target", "Target", "packageRequest",
            "PackageRequest", "credentialPackageRequest", "CredentialPackageRequest",
            "keyPackageRequest", "KeyPackageRequest",
        )
        package_payload = _mapping_value(kwargs, *package_payload_aliases)
        if not isinstance(package_payload, dict):
            package_payload = _mapping_value(inp, *package_payload_aliases)
        if not isinstance(package_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            package_payload = _mapping_value(args[0], *package_payload_aliases)
            if not isinstance(package_payload, dict):
                package_payload = args[0]
        if isinstance(package_payload, dict):
            for _ in range(2):
                merged_package_payload = dict(package_payload)
                for envelope in package_payload_aliases:
                    found_envelope, nested_package_payload = _dict_lookup(package_payload, envelope)
                    if found_envelope and isinstance(nested_package_payload, dict) and nested_package_payload is not package_payload:
                        merged_package_payload.update(nested_package_payload)
                if merged_package_payload == package_payload:
                    break
                package_payload = merged_package_payload

        def _package_auth_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "credential", "Credential", "target", "Target", "obj", "object", "Object")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in package_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _package_auth_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(package_payload, dict):
            if auth is None or isinstance(auth, dict):
                selector = _package_auth_selector(package_payload)
                if selector is not None:
                    auth = selector
            purpose = _mapping_value(package_payload, "Purpose", "purpose", "usage", "Usage") or purpose
            wrapping_key = _mapping_value(package_payload, "WrappingKey", "wrappingKey", "wrapping_key", "WrappingKeyUID", "wrappingKeyUID") or wrapping_key
            signing_key = _mapping_value(package_payload, "SigningKey", "signingKey", "signing_key", "SigningKeyUID", "signingKeyUID") or signing_key
            auth_as = _mapping_value(package_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        raw_args = {}
        if purpose is not None:
            raw_args["Purpose"] = purpose
        if wrapping_key is not None:
            raw_args["WrappingKey"] = wrapping_key
        if signing_key is not None:
            raw_args["SigningKey"] = signing_key
        return build("GetPackage", cpin_target(auth, _arg_or_kw(args, kwargs, 5, "obj", "object", "Object", "target", "Target")), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "setpackage",
        "setcredentialpackage",
        "setkeypackage",
        "setpinpackage",
        "setcredentialbackup",
        "setwrappedpackage",
        "setwrappedkey",
        "importpackage",
        "importcredential",
        "importkeypackage",
        "importpin",
        "importpinpackage",
        "importcredentialbackup",
        "importkeybackup",
        "importwrappedkey",
        "importkey",
        "unwrappackage",
        "unwrapkey",
        "unwrapkeypackage",
        "restorepackage",
        "restorecredential",
        "restorekeypackage",
        "restorepin",
        "restorecredentialpackage",
        "restorepinpackage",
        "restorecredentialbackup",
        "loadpackage",
        "loadkeypackage",
        "loadcredentialpackage",
        "writepackage",
        "writekeypackage",
        "writecredentialpackage",
        "writekeybackup",
    }:
        auth = auth_arg_value(0)
        if auth is None:
            auth = _mapping_value(kwargs, "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "credential", "Credential", "target", "Target", "obj", "object", "Object")
        value = _arg_or_kw(args, kwargs, 1, "Value", "value", "Package", "package", "data", "Data", "payload", "Payload")
        wrapping_key = _arg_or_kw(args, kwargs, 2, "WrappingKey", "wrappingKey", "wrapping_key", "WrappingKeyUID", "wrappingKeyUID")
        signing_key = _arg_or_kw(args, kwargs, 3, "SigningKey", "signingKey", "signing_key", "SigningKeyUID", "signingKeyUID")
        auth_as = _arg_or_kw(args, kwargs, 4, "authAs", "AuthAs", "auth_as", "authAS") or auth
        package_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "params", "Params", "parameters", "Parameters", "request", "Request",
            "config", "Config", "policy", "Policy", "package", "Package",
            "credential", "Credential", "target", "Target", "packageRequest",
            "PackageRequest", "credentialPackageRequest", "CredentialPackageRequest",
            "keyPackageRequest", "KeyPackageRequest",
        )
        package_payload = _mapping_value(kwargs, *package_payload_aliases)
        if not isinstance(package_payload, dict):
            package_payload = _mapping_value(inp, *package_payload_aliases)
        if not isinstance(package_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            package_payload = _mapping_value(args[0], *package_payload_aliases)
            if not isinstance(package_payload, dict):
                package_payload = args[0]
        if isinstance(package_payload, dict):
            for _ in range(2):
                merged_package_payload = dict(package_payload)
                for envelope in package_payload_aliases:
                    found_envelope, nested_package_payload = _dict_lookup(package_payload, envelope)
                    if found_envelope and isinstance(nested_package_payload, dict) and nested_package_payload is not package_payload:
                        merged_package_payload.update(nested_package_payload)
                if merged_package_payload == package_payload:
                    break
                package_payload = merged_package_payload

        def _setpackage_auth_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "credential", "Credential", "target", "Target", "obj", "object", "Object")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in package_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _setpackage_auth_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(package_payload, dict):
            if auth is None or isinstance(auth, dict):
                selector = _setpackage_auth_selector(package_payload)
                if selector is not None:
                    auth = selector
            value = _mapping_value(package_payload, "Value", "value", "Package", "package", "data", "Data", "payload", "Payload") or value
            wrapping_key = _mapping_value(package_payload, "WrappingKey", "wrappingKey", "wrapping_key", "WrappingKeyUID", "wrappingKeyUID") or wrapping_key
            signing_key = _mapping_value(package_payload, "SigningKey", "signingKey", "signing_key", "SigningKeyUID", "signingKeyUID") or signing_key
            auth_as = _mapping_value(package_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        raw_args = {}
        if value is not None:
            raw_args["Value"] = value
        if wrapping_key is not None:
            raw_args["WrappingKey"] = wrapping_key
        if signing_key is not None:
            raw_args["SigningKey"] = signing_key
        return build("SetPackage", cpin_target(auth, _arg_or_kw(args, kwargs, 5, "obj", "object", "Object", "target", "Target")), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"createtable", "newtable", "maketable", "allocatetable", "createobjecttable", "newobjecttable", "createbytetable"}:
        name = _arg_or_kw(args, kwargs, 0, "NewTableName", "newTableName", "name", "Name", "TableName", "tableName")
        kind = _arg_or_kw(args, kwargs, 1, "Kind", "kind", "TableKind", "tableKind")
        acl = _arg_or_kw(args, kwargs, 2, "GetSetACL", "getSetACL", "GetSetAcl", "ACL", "acl", "AccessControlList", "accessControlList")
        columns = _arg_or_kw(args, kwargs, 3, "Columns", "columns", "schema", "Schema")
        min_size = _arg_or_kw(args, kwargs, 4, "MinSize", "minSize", "MinimumSize", "minimumSize", "rows", "Rows", "size", "Size")
        max_size = _arg_or_kw(args, kwargs, 5, "MaxSize", "maxSize", "MaximumSize", "maximumSize")
        hint_size = _arg_or_kw(args, kwargs, 6, "HintSize", "hintSize", "hint_size")
        common = _arg_or_kw(args, kwargs, 7, "CommonName", "commonName", "common_name")
        auth_as = _arg_or_kw(args, kwargs, 8, "authAs", "AuthAs", "auth_as", "authAS") or ("Admin1", "new")
        table_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "tableRequest", "TableRequest", "createTableRequest",
            "CreateTableRequest", "schemaRequest", "SchemaRequest",
        )
        table_payload = _mapping_value(kwargs, *table_payload_aliases)
        if not isinstance(table_payload, dict):
            table_payload = _mapping_value(inp, *table_payload_aliases)
        if not isinstance(table_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            table_payload = _mapping_value(args[0], *table_payload_aliases)
            if not isinstance(table_payload, dict):
                table_payload = args[0]
        if isinstance(table_payload, dict):
            for _ in range(2):
                merged_table_payload = dict(table_payload)
                for envelope in table_payload_aliases:
                    found_envelope, nested_table_payload = _dict_lookup(table_payload, envelope)
                    if found_envelope and isinstance(nested_table_payload, dict) and nested_table_payload is not table_payload:
                        merged_table_payload.update(nested_table_payload)
                if merged_table_payload == table_payload:
                    break
                table_payload = merged_table_payload
            payload_name = _mapping_value(table_payload, "NewTableName", "newTableName", "name", "Name", "TableName", "tableName")
            payload_kind = _mapping_value(table_payload, "Kind", "kind", "TableKind", "tableKind")
            payload_acl = _mapping_value(table_payload, "GetSetACL", "getSetACL", "GetSetAcl", "ACL", "acl", "AccessControlList", "accessControlList")
            payload_columns = _mapping_value(table_payload, "Columns", "columns", "schema", "Schema")
            payload_min_size = _mapping_value(table_payload, "MinSize", "minSize", "MinimumSize", "minimumSize", "rows", "Rows", "size", "Size")
            payload_max_size = _mapping_value(table_payload, "MaxSize", "maxSize", "MaximumSize", "maximumSize")
            payload_hint_size = _mapping_value(table_payload, "HintSize", "hintSize", "hint_size")
            payload_common = _mapping_value(table_payload, "CommonName", "commonName", "common_name")
            payload_auth_as = _mapping_value(table_payload, "authAs", "AuthAs", "auth_as", "authAS")
            name = payload_name if payload_name is not None else name
            kind = payload_kind if payload_kind is not None else kind
            acl = payload_acl if payload_acl is not None else acl
            columns = payload_columns if payload_columns is not None else columns
            min_size = payload_min_size if payload_min_size is not None else min_size
            max_size = payload_max_size if payload_max_size is not None else max_size
            hint_size = payload_hint_size if payload_hint_size is not None else hint_size
            common = payload_common if payload_common is not None else common
            auth_as = payload_auth_as if payload_auth_as is not None else auth_as
        if function_alias == "createbytetable" and kind is None:
            kind = "Byte"
        if function_alias in {"createobjecttable", "newobjecttable"} and kind is None:
            kind = "Object"
        raw_args = {}
        for key, value in (
            ("NewTableName", name),
            ("Kind", kind),
            ("GetSetACL", acl),
            ("Columns", columns),
            ("MinSize", min_size),
            ("MaxSize", max_size),
            ("HintSize", hint_size),
            ("CommonName", common),
        ):
            if value is not None:
                raw_args[key] = value
        return build("CreateTable", "ThisSP", raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"next", "getnext", "nextrows", "listnext", "nextuids", "getnextuids", "readnext", "fetchnext", "enumeratenext", "listrows", "scannext", "fetchrows", "readrows", "enumeraterows", "listuids", "scanrows"}:
        table = _arg_or_kw(args, kwargs, 0, "table", "Table", "obj", "object", "Object", "target", "Target")
        count = _arg_or_kw(args, kwargs, 1, "Count", "count", "limit", "Limit", "n", "N")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        next_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "nextRequest", "NextRequest", "tableRequest", "TableRequest",
            "rowRequest", "RowRequest", "queryRequest", "QueryRequest",
        )
        next_payload = _mapping_value(kwargs, *next_payload_aliases)
        if not isinstance(next_payload, dict):
            next_payload = _mapping_value(inp, *next_payload_aliases)
        if isinstance(next_payload, dict):
            for _ in range(2):
                merged_next_payload = dict(next_payload)
                for envelope in next_payload_aliases:
                    found_envelope, nested_next_payload = _dict_lookup(next_payload, envelope)
                    if found_envelope and isinstance(nested_next_payload, dict) and nested_next_payload is not next_payload:
                        merged_next_payload.update(nested_next_payload)
                if merged_next_payload == next_payload:
                    break
                next_payload = merged_next_payload
            if table is None or isinstance(table, dict):
                table = _mapping_value(next_payload, "table", "Table", "obj", "object", "Object", "target", "Target")
            payload_count = _mapping_value(next_payload, "Count", "count", "limit", "Limit", "n", "N")
            if payload_count is not None:
                count = payload_count
            auth_as = _mapping_value(next_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if count is not None:
            raw_args["Count"] = count
        return build("Next", table or "Table", raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"getfreespace", "freespace", "queryfreespace", "getavailablespace", "availablespace", "remainingspace", "freespacebytes", "availablebytes", "getavailablebytes", "queryavailablespace", "spaceavailable", "getremainingspace", "remainingbytes", "freebytes", "getfreebytes", "spacefree", "availablestorage", "getavailablestorage"}:
        auth_as = _arg_or_kw(args, kwargs, 0, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        free_space_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "freeSpaceRequest", "FreeSpaceRequest", "spaceRequest", "SpaceRequest",
            "spRequest", "SPRequest", "securityProviderRequest", "SecurityProviderRequest",
        )
        free_space_payload = _mapping_value(kwargs, *free_space_payload_aliases)
        if not isinstance(free_space_payload, dict):
            free_space_payload = _mapping_value(inp, *free_space_payload_aliases)
        if isinstance(free_space_payload, dict):
            for _ in range(2):
                merged_free_space_payload = dict(free_space_payload)
                for envelope in free_space_payload_aliases:
                    found_envelope, nested_free_space_payload = _dict_lookup(free_space_payload, envelope)
                    if found_envelope and isinstance(nested_free_space_payload, dict) and nested_free_space_payload is not free_space_payload:
                        merged_free_space_payload.update(nested_free_space_payload)
                if merged_free_space_payload == free_space_payload:
                    break
                free_space_payload = merged_free_space_payload
            auth_as = _mapping_value(free_space_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        return build("GetFreeSpace", "ThisSP", optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"createrow", "newrow", "insertrow", "addrow", "appendrow", "createtablerow", "newtablerow", "makerow", "allocaterow", "createobjectrow", "inserttablerow", "appendtablerow", "addtablerow"}:
        table = _arg_or_kw(args, kwargs, 0, "table", "Table", "obj", "object", "Object", "target", "Target")
        row_values = _arg_or_kw(args, kwargs, 1, "Values", "values", "RowValues", "rowValues", "row", "Row", "data", "Data")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or ("Admin1", "new")
        row_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "rowRequest", "RowRequest", "createRowRequest", "CreateRowRequest",
            "tableRequest", "TableRequest",
        )
        row_payload = _mapping_value(kwargs, *row_payload_aliases)
        if not isinstance(row_payload, dict):
            row_payload = _mapping_value(inp, *row_payload_aliases)
        if isinstance(row_payload, dict):
            for _ in range(2):
                merged_row_payload = dict(row_payload)
                for envelope in row_payload_aliases:
                    found_envelope, nested_row_payload = _dict_lookup(row_payload, envelope)
                    if found_envelope and isinstance(nested_row_payload, dict) and nested_row_payload is not row_payload:
                        merged_row_payload.update(nested_row_payload)
                if merged_row_payload == row_payload:
                    break
                row_payload = merged_row_payload
            if table is None or isinstance(table, dict):
                table = _mapping_value(row_payload, "table", "Table", "obj", "object", "Object", "target", "Target")
            row_values = _mapping_value(row_payload, "Values", "values", "RowValues", "rowValues", "row", "Row", "data", "Data") or row_values
            auth_as = _mapping_value(row_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        optional = {"authAs": auth_as}
        if isinstance(row_values, dict):
            optional.update(row_values)
        elif row_values is not None:
            optional["Values"] = row_values
        return build("CreateRow", table or "Locking", raw_args=row_values, optional=optional, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"deleterow", "removerow", "destroyrow", "deletetablerow", "removetablerow", "droprow", "deleteobjectrow", "removeobjectrow", "destroytablerow", "eraserow", "deleterows", "removerows"}:
        table = _arg_or_kw(args, kwargs, 0, "table", "Table", "obj", "object", "Object", "target", "Target")
        rows = _arg_or_kw(args, kwargs, 1, "Rows", "rows", "Row", "row", "UID", "uid", "rowUID", "rowUid", "row_id", "rowId")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or ("Admin1", "new")
        row_delete_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "deleteRowRequest", "DeleteRowRequest", "rowRequest", "RowRequest",
            "tableRequest", "TableRequest", "deleteRequest", "DeleteRequest",
        )
        row_payload = _mapping_value(kwargs, *row_delete_payload_aliases)
        if not isinstance(row_payload, dict):
            row_payload = _mapping_value(inp, *row_delete_payload_aliases)
        if isinstance(row_payload, dict):
            for _ in range(2):
                merged_row_payload = dict(row_payload)
                for envelope in row_delete_payload_aliases:
                    found_envelope, nested_row_payload = _dict_lookup(row_payload, envelope)
                    if found_envelope and isinstance(nested_row_payload, dict) and nested_row_payload is not row_payload:
                        merged_row_payload.update(nested_row_payload)
                if merged_row_payload == row_payload:
                    break
                row_payload = merged_row_payload
            if table is None or isinstance(table, dict):
                table = _mapping_value(row_payload, "table", "Table", "obj", "object", "Object", "target", "Target")
            payload_rows = _mapping_value(row_payload, "Rows", "rows", "Row", "row", "UID", "uid", "rowUID", "rowUid", "row_id", "rowId")
            if payload_rows is not None:
                rows = payload_rows
            auth_as = _mapping_value(row_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if rows is not None:
            raw_args["Rows"] = rows
        return build("DeleteRow", table or "Locking", raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"getfreerows", "freerows", "tablequery", "querytable", "queryfreerows", "availablerows", "getavailablerows", "remainingrows", "freerowcount", "availablerowcount", "getremainingrows"}:
        table = _arg_or_kw(args, kwargs, 0, "table", "Table", "obj", "object", "Object", "target", "Target")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        query_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "queryRequest", "QueryRequest", "tableQueryRequest", "TableQueryRequest",
            "freeRowsRequest", "FreeRowsRequest", "tableRequest", "TableRequest",
            "rowRequest", "RowRequest",
        )
        query_payload = _mapping_value(kwargs, *query_payload_aliases)
        if not isinstance(query_payload, dict):
            query_payload = _mapping_value(inp, *query_payload_aliases)
        if isinstance(query_payload, dict):
            for _ in range(2):
                merged_query_payload = dict(query_payload)
                for envelope in query_payload_aliases:
                    found_envelope, nested_query_payload = _dict_lookup(query_payload, envelope)
                    if found_envelope and isinstance(nested_query_payload, dict) and nested_query_payload is not query_payload:
                        merged_query_payload.update(nested_query_payload)
                if merged_query_payload == query_payload:
                    break
                query_payload = merged_query_payload
            if table is None or isinstance(table, dict):
                table = _mapping_value(query_payload, "table", "Table", "obj", "object", "Object", "target", "Target")
            auth_as = _mapping_value(query_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        return build("GetFreeRows", table or "Table", optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"deleteobject", "removeobject", "destroyobject", "deleterange", "removerange", "destroyrange"}:
        target = _arg_or_kw(args, kwargs, 0, "target", "Target", "obj", "object", "Object", "uid", "UID", "range", "Range", "band", "Band")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or ("Admin1", "new")
        object_delete_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "deleteRequest", "DeleteRequest", "deleteObjectRequest", "DeleteObjectRequest",
            "objectRequest", "ObjectRequest", "rangeRequest", "RangeRequest",
            "tableRequest", "TableRequest",
        )
        delete_payload = _mapping_value(kwargs, *object_delete_payload_aliases)
        if not isinstance(delete_payload, dict):
            delete_payload = _mapping_value(inp, *object_delete_payload_aliases)
        if isinstance(delete_payload, dict):
            for _ in range(2):
                merged_delete_payload = dict(delete_payload)
                for envelope in object_delete_payload_aliases:
                    found_envelope, nested_delete_payload = _dict_lookup(delete_payload, envelope)
                    if found_envelope and isinstance(nested_delete_payload, dict) and nested_delete_payload is not delete_payload:
                        merged_delete_payload.update(nested_delete_payload)
                if merged_delete_payload == delete_payload:
                    break
                delete_payload = merged_delete_payload
            payload_target = _mapping_value(delete_payload, "target", "Target", "obj", "object", "Object", "uid", "UID", "range", "Range", "band", "Band")
            if payload_target is not None:
                target = payload_target
            auth_as = _mapping_value(delete_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        if function_alias in {"deleterange", "removerange", "destroyrange"}:
            target = _band_target_from_range_value(target)
        return build("Delete", target or "", optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"deletetable", "removetable", "destroytable"}:
        target = _arg_or_kw(args, kwargs, 0, "table", "Table", "target", "Target", "obj", "object", "Object", "uid", "UID")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or ("Admin1", "new")
        table_delete_payload_aliases = (
            "settings", "Settings", "options", "Options", "values", "Values",
            "request", "Request", "config", "Config", "policy", "Policy",
            "deleteRequest", "DeleteRequest", "deleteTableRequest", "DeleteTableRequest",
            "tableRequest", "TableRequest", "objectRequest", "ObjectRequest",
        )
        delete_payload = _mapping_value(kwargs, *table_delete_payload_aliases)
        if not isinstance(delete_payload, dict):
            delete_payload = _mapping_value(inp, *table_delete_payload_aliases)
        if isinstance(delete_payload, dict):
            for _ in range(2):
                merged_delete_payload = dict(delete_payload)
                for envelope in table_delete_payload_aliases:
                    found_envelope, nested_delete_payload = _dict_lookup(delete_payload, envelope)
                    if found_envelope and isinstance(nested_delete_payload, dict) and nested_delete_payload is not delete_payload:
                        merged_delete_payload.update(nested_delete_payload)
                if merged_delete_payload == delete_payload:
                    break
                delete_payload = merged_delete_payload
            payload_target = _mapping_value(delete_payload, "table", "Table", "target", "Target", "obj", "object", "Object", "uid", "UID")
            if payload_target is not None:
                target = payload_target
            auth_as = _mapping_value(delete_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        clean_target = _clean_uid(target)
        if len(clean_target) == 16 and clean_target[8:] == "00000000" and clean_target[:8] != "00000000":
            target = "00000001" + clean_target[:8]
        return build("Delete", target or "", optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"xor", "xordata", "xorbytes", "xordatabytes", "onetimepad", "onetimepadxor", "otpxor"}:
        pattern_input = _arg_or_kw(args, kwargs, 0, "PatternInput", "patternInput", "pattern_input", "Pattern", "pattern")
        data = _arg_or_kw(args, kwargs, 1, "Input", "input", "Data", "data", "Bytes", "bytes", "BufferIn", "bufferIn", "payload", "Payload")
        buffer_out = _arg_or_kw(args, kwargs, 2, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer")
        delete_pattern = _arg_or_kw(args, kwargs, 3, "DeletePattern", "deletePattern", "Delete", "delete")
        auth_as = _arg_or_kw(args, kwargs, 4, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        xor_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "xorRequest", "XorRequest", "XORRequest", "cryptoRequest",
            "CryptoRequest", "byteTableRequest", "ByteTableRequest",
            "operationRequest", "OperationRequest", "cipherRequest", "CipherRequest",
        )
        xor_payload = _mapping_value(kwargs, *xor_payload_aliases)
        if not isinstance(xor_payload, dict):
            xor_payload = _mapping_value(inp, *xor_payload_aliases)
        if not isinstance(xor_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            xor_payload = _mapping_value(args[0], *xor_payload_aliases)
            if not isinstance(xor_payload, dict):
                xor_payload = args[0]
        if isinstance(xor_payload, dict):
            for _ in range(2):
                merged_xor_payload = dict(xor_payload)
                for envelope in xor_payload_aliases:
                    found_envelope, nested_xor_payload = _dict_lookup(xor_payload, envelope)
                    if found_envelope and isinstance(nested_xor_payload, dict) and nested_xor_payload is not xor_payload:
                        merged_xor_payload.update(nested_xor_payload)
                if merged_xor_payload == xor_payload:
                    break
                xor_payload = merged_xor_payload
            payload_pattern_input = _mapping_value(xor_payload, "PatternInput", "patternInput", "pattern_input", "Pattern", "pattern")
            payload_data = _mapping_value(xor_payload, "Input", "input", "Data", "data", "Bytes", "bytes", "BufferIn", "bufferIn", "payload", "Payload")
            payload_buffer_out = _mapping_value(xor_payload, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer")
            if payload_pattern_input is not None:
                pattern_input = payload_pattern_input
            if payload_data is not None:
                data = payload_data
            if payload_buffer_out is not None:
                buffer_out = payload_buffer_out
            delete_pattern = _mapping_value(xor_payload, "DeletePattern", "deletePattern", "Delete", "delete") if delete_pattern is None else delete_pattern
            auth_as = _mapping_value(xor_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        raw_args = {}
        if pattern_input is not None:
            raw_args["PatternInput"] = pattern_input
        if data is not None:
            raw_args["Input"] = data
        if buffer_out is not None:
            raw_args["BufferOut"] = buffer_out
        if delete_pattern is not None:
            raw_args["DeletePattern"] = delete_pattern
        return build("XOR", "ThisSP", raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "readlock",
        "lockread",
        "lockforread",
        "readlockrange",
        "lockreadrange",
        "readlockforrange",
        "lockreadforrange",
        "lockrangeforread",
        "writelock",
        "lockwrite",
        "lockforwrite",
        "writelockrange",
        "lockwriterange",
        "writelockforrange",
        "lockwriteforrange",
        "lockrangeforwrite",
        "readunlock",
        "unlockread",
        "unlockforread",
        "readunlockrange",
        "unlockreadrange",
        "readunlockforrange",
        "unlockreadforrange",
        "unlockrangeforread",
        "writeunlock",
        "unlockwrite",
        "unlockforwrite",
        "writeunlockrange",
        "unlockwriterange",
        "writeunlockforrange",
        "unlockwriteforrange",
        "unlockrangeforwrite",
    }:
        if len(args) > 1 and authority_like(args[0]) and range_like(args[1]):
            auth = args[0]
            range_no = args[1]
            lock_value = _arg_or_kw(args, kwargs, 2, "locked", "lock", "value")
            auth_as = _mapping_value(kwargs, "authAs", "AuthAs", "auth_as", "authAS") or auth
        else:
            range_no = range_arg(0)
            lock_value = _arg_or_kw(args, kwargs, 1, "locked", "lock", "value")
            auth = _arg_or_kw(args, kwargs, 2, "auth", "Auth")
            auth_as = authas(auth)
        lock_payload = _mapping_value(kwargs, "values", "Values", "settings", "Settings", "options", "Options")
        if not isinstance(lock_payload, dict):
            lock_payload = _mapping_value(inp, "values", "Values", "settings", "Settings", "options", "Options")
        if not isinstance(lock_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            lock_payload = _mapping_value(args[0], "values", "Values", "settings", "Settings", "options", "Options")
            if not isinstance(lock_payload, dict):
                lock_payload = args[0]
        if isinstance(lock_payload, dict):
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    lock_payload,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                )
            if lock_value is None:
                lock_value = _mapping_value(lock_payload, "locked", "lock", "value", "Value")
            if auth is None:
                auth = _mapping_value(lock_payload, "auth", "Auth", "authority", "Authority")
            auth_as = _mapping_value(lock_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        column = "ReadLocked" if function_alias in {"readlock", "lockread", "lockforread", "readlockrange", "lockreadrange", "readlockforrange", "lockreadforrange", "lockrangeforread", "readunlock", "unlockread", "unlockforread", "readunlockrange", "unlockreadrange", "readunlockforrange", "unlockreadforrange", "unlockrangeforread"} else "WriteLocked"
        default_lock_value = function_alias in {"readlock", "lockread", "lockforread", "readlockrange", "lockreadrange", "readlockforrange", "lockreadforrange", "lockrangeforread", "writelock", "lockwrite", "lockforwrite", "writelockrange", "lockwriterange", "writelockforrange", "lockwriteforrange", "lockrangeforwrite"}
        if lock_value is None:
            lock_value = _mapping_value(kwargs, column)
        optional = {column: default_lock_value if lock_value is None else lock_value, "authAs": auth_as}
        return build("Set", _band_target_from_range_value(range_no), optional=optional, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    authority_counter_setters = {
        "setauthoritylimit": ("Limit", 15, ("limit", "Limit", "authorityLimit", "authority_limit", "value", "Value")),
        "setauthlimit": ("Limit", 15, ("limit", "Limit", "authLimit", "auth_limit", "authorityLimit", "authority_limit", "value", "Value")),
        "setmaxauthentications": ("Limit", 15, ("limit", "Limit", "maxAuthentications", "max_authentications", "authentications", "Authentications", "value", "Value")),
        "setusermaxauthentications": ("Limit", 15, ("limit", "Limit", "userMaxAuthentications", "user_max_authentications", "maxAuthentications", "max_authentications", "authentications", "Authentications", "value", "Value")),
        "setauthorityuselimit": ("Limit", 15, ("limit", "Limit", "useLimit", "use_limit", "authorityUseLimit", "authority_use_limit", "authorityLimit", "authority_limit", "value", "Value")),
        "setuseruselimit": ("Limit", 15, ("limit", "Limit", "userUseLimit", "user_use_limit", "useLimit", "use_limit", "userLimit", "user_limit", "value", "Value")),
        "setauthorityuses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "count", "Count", "value", "Value")),
        "setuserlimit": ("Limit", 15, ("limit", "Limit", "authorityLimit", "authority_limit", "userLimit", "user_limit", "value", "Value")),
        "setuseruses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "userUses", "user_uses", "count", "Count", "value", "Value")),
        "updateuseruses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "userUses", "user_uses", "count", "Count", "value", "Value")),
        "putuseruses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "userUses", "user_uses", "count", "Count", "value", "Value")),
        "setlimit": ("Limit", 15, ("limit", "Limit", "authorityLimit", "authority_limit", "value", "Value")),
        "setuses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "count", "Count", "value", "Value")),
        "updateuses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "count", "Count", "value", "Value")),
        "putuses": ("Uses", 16, ("uses", "Uses", "authorityUses", "authority_uses", "count", "Count", "value", "Value")),
    }
    if function_alias in authority_counter_setters:
        column_name, _column_index, value_aliases = authority_counter_setters[function_alias]
        if column_name == "Limit":
            value_aliases = (
                *value_aliases,
                "authLimit",
                "auth_limit",
                "useLimit",
                "use_limit",
                "maxAuthentications",
                "max_authentications",
                "maxAuths",
                "max_auths",
                "authenticationLimit",
                "authentication_limit",
                "credentialLimit",
                "credential_limit",
                "credentialUseLimit",
                "credential_use_limit",
            )
        if column_name == "Uses":
            value_aliases = (
                *value_aliases,
                "useCount",
                "use_count",
                "authUseCount",
                "auth_use_count",
                "credentialUses",
                "credential_uses",
                "credentialUseCount",
                "credential_use_count",
            )
        authority = _arg_or_kw(args, kwargs, 0, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username", "authId", "auth_id", "AuthID", "authorityId", "authority_id", "AuthorityID", "userId", "user_id", "UserID", "name", "Name")
        value = _arg_or_kw(args, kwargs, 1, *value_aliases)
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or "Admin1"
        authority_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "limits",
            "Limits",
            "security",
            "Security",
            "authorityPolicy",
            "AuthorityPolicy",
            "authority_policy",
            "authPolicy",
            "AuthPolicy",
            "auth_policy",
            "authorityRequest",
            "AuthorityRequest",
            "authRequest",
            "AuthRequest",
            "identityRequest",
            "IdentityRequest",
        )
        authority_payload = _mapping_value(kwargs, *authority_payload_aliases)
        if not isinstance(authority_payload, dict):
            authority_payload = _mapping_value(inp, *authority_payload_aliases)
        if not isinstance(authority_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            authority_payload = _mapping_value(args[0], *authority_payload_aliases)
            if not isinstance(authority_payload, dict):
                authority_payload = args[0]

        def _authority_counter_envelope_lookup(payload: Any) -> tuple[bool, Any]:
            if not isinstance(payload, dict):
                return False, None
            found, nested_value = _dict_lookup(payload, column_name, column_name[0].lower() + column_name[1:], *value_aliases)
            if found:
                return True, nested_value
            for envelope in authority_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    found_nested, nested_value = _authority_counter_envelope_lookup(nested)
                    if found_nested:
                        return True, nested_value
            return False, None

        def _authority_counter_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username", "authId", "auth_id", "AuthID", "authorityId", "authority_id", "AuthorityID", "userId", "user_id", "UserID", "name", "Name", "obj", "object", "Object", "target", "Target")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in authority_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _authority_counter_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(authority_payload, dict):
            if authority is None or isinstance(authority, dict):
                authority = _authority_counter_selector(authority_payload)
            if value is None:
                found_value, nested_value = _authority_counter_envelope_lookup(authority_payload)
                if found_value:
                    value = nested_value
            auth_as = _mapping_value(authority_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        if value is None:
            for source in (kwargs, inp, args[0] if len(args) > 0 else None):
                found_value, nested_value = _authority_counter_envelope_lookup(source)
                if found_value:
                    value = nested_value
                    break
        return build("Set", authority, optional={column_name: value, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    authority_counter_getters = {
        "getauthoritylimit": 15,
        "getauthlimit": 15,
        "getmaxauthentications": 15,
        "getusermaxauthentications": 15,
        "getauthorityuselimit": 15,
        "getuseruselimit": 15,
        "getuserlimit": 15,
        "getauthorityuses": 16,
        "getauthorityusecount": 16,
        "getauthuses": 16,
        "getauthusecount": 16,
        "getauthenticationuses": 16,
        "getuseruses": 16,
        "getuserusecount": 16,
        "getuserauthenticationuses": 16,
        "getcredentialuses": 16,
        "getcredentialusecount": 16,
        "getusecount": 16,
        "getlimit": 15,
        "getuses": 16,
    }
    if function_alias in authority_counter_getters:
        column_index = authority_counter_getters[function_alias]
        authority = _arg_or_kw(args, kwargs, 0, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username", "authId", "auth_id", "AuthID", "authorityId", "authority_id", "AuthorityID", "userId", "user_id", "UserID", "name", "Name")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "Admin1"
        authority_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "query",
            "Query",
            "selector",
            "Selector",
            "authority",
            "Authority",
            "identity",
            "Identity",
            "credential",
            "Credential",
            "target",
            "Target",
            "authorityRequest",
            "AuthorityRequest",
            "authRequest",
            "AuthRequest",
            "identityRequest",
            "IdentityRequest",
        )
        authority_payload = _mapping_value(kwargs, *authority_payload_aliases)
        if not isinstance(authority_payload, dict):
            authority_payload = _mapping_value(inp, *authority_payload_aliases)
        if not isinstance(authority_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            authority_payload = _mapping_value(args[0], *authority_payload_aliases)
            if not isinstance(authority_payload, dict):
                authority_payload = args[0]

        def _authority_counter_getter_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(
                payload,
                "auth",
                "Auth",
                "authority",
                "Authority",
                "user",
                "User",
                "uid",
                "UID",
                "identity",
                "Identity",
                "username",
                "Username",
                "authId",
                "auth_id",
                "AuthID",
                "authorityId",
                "authority_id",
                "AuthorityID",
                "userId",
                "user_id",
                "UserID",
                "name",
                "Name",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in authority_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _authority_counter_getter_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(authority_payload, dict):
            if authority is None or isinstance(authority, dict):
                selector = _authority_counter_getter_selector(authority_payload)
                if selector is not None:
                    authority = selector
            auth_as = _mapping_value(authority_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        cellblock = [{"startColumn": column_index}, {"endColumn": column_index}]
        return build("Get", authority, optional={"CellBlock": cellblock, "authAs": auth_as}, raw_args={"CellBlock": cellblock}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "activateAuthority",
        "activateUser",
        "activateauthority",
        "activateuser",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "enableauthority",
        "setauthority",
        "setauthorityenabled",
        "setauthoritystate",
        "disableauthority",
        "enableuser",
        "disableuser",
        "setuserenabled",
        "setuserenable",
        "setuserstate",
    }:
        auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username")
        enable = _arg_or_kw(args, kwargs, 1, "enable", "Enabled")
        if function_alias in {"setauthority", "setauthorityenabled", "setauthoritystate"} and enable is None:
            enable = _arg_or_kw(args, kwargs, 1, "enabled", "value", "Value")
        if function_alias in {"setuserenabled", "setuserenable", "setuserstate"} and enable is None:
            enable = _arg_or_kw(args, kwargs, 1, "enabled", "value", "Value")
        target = _arg_or_kw(args, kwargs, 2, "obj", "object", "Object") or auth
        auth_as = _arg_or_kw(args, kwargs, 3, "authAs", "AuthAs", "auth_as", "authAS") or auth
        authority_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "authorityRequest", "AuthorityRequest", "authRequest",
            "AuthRequest", "identityRequest", "IdentityRequest", "userRequest",
            "UserRequest", "policyRequest", "PolicyRequest", "authority",
            "Authority", "identity", "Identity", "user", "User",
        )
        authority_payload = _mapping_value(kwargs, *authority_payload_aliases)
        if not isinstance(authority_payload, dict):
            authority_payload = _mapping_value(inp, *authority_payload_aliases)
        if isinstance(authority_payload, dict):
            for _ in range(2):
                merged_authority_payload = dict(authority_payload)
                for envelope in authority_payload_aliases:
                    found_envelope, nested_authority_payload = _dict_lookup(authority_payload, envelope)
                    if found_envelope and isinstance(nested_authority_payload, dict) and nested_authority_payload is not authority_payload:
                        merged_authority_payload.update(nested_authority_payload)
                if merged_authority_payload == authority_payload:
                    break
                authority_payload = merged_authority_payload
            if auth is None:
                auth = _mapping_value(authority_payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username")
            if enable is None:
                payload_enable = _mapping_value(authority_payload, "enable", "Enabled", "enabled", "value", "Value")
                if payload_enable is not None:
                    enable = payload_enable
            payload_target = _mapping_value(authority_payload, "obj", "object", "Object", "target", "Target")
            target = payload_target if payload_target is not None else target or auth
            auth_as = _mapping_value(authority_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        if function_alias in {"disableauthority", "disableuser", "deactivateauthority", "deactivateuser", "deactivateAuthority", "deactivateUser"} and enable is None:
            enable = False
        if function_alias in {"enableauthority", "enableuser", "activateauthority", "activateuser", "activateAuthority", "activateUser"} and enable is None:
            enable = True
        return build("Set", target, optional={"Enabled": enable, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "setport",
        "lockport",
        "lockinterface",
        "lockportaccess",
        "enableportlock",
        "unlockport",
        "unlockinterface",
        "unlockportaccess",
        "disableportlock",
        "setportlocked",
        "setportstate",
        "setportlock",
        "updateportlocked",
        "updateportstate",
        "updateportlock",
        "putportlocked",
        "putportlock",
    }:
        port = _arg_or_kw(args, kwargs, 0, "port", "Port", "uid", "UID", "port_id", "portId", "PortID", "id", "ID", "interface", "Interface", "interface_id", "interfaceId", "InterfaceID", "portName", "port_name", "name", "Name", "obj", "object", "Object", "target", "Target")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "SID"
        port_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "state",
            "State",
            "control",
            "Control",
            "port",
            "Port",
            "portRequest",
            "PortRequest",
            "adminRequest",
            "AdminRequest",
            "target",
            "Target",
        )
        port_payload = _mapping_value(kwargs, *port_payload_aliases)
        if not isinstance(port_payload, dict):
            port_payload = _mapping_value(inp, *port_payload_aliases)
        if not isinstance(port_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            port_payload = _mapping_value(args[0], *port_payload_aliases)
            if not isinstance(port_payload, dict):
                port_payload = args[0]

        def _port_selector_from_payload(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "port", "Port", "uid", "UID", "port_id", "portId", "PortID", "id", "ID", "interface", "Interface", "interface_id", "interfaceId", "InterfaceID", "portName", "port_name", "name", "Name", "obj", "object", "Object", "target", "Target")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in port_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _port_selector_from_payload(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        def _port_locked_from_payload(payload: Any) -> tuple[bool, Any]:
            if not isinstance(payload, dict):
                return False, None
            found, value = _dict_lookup(payload, "PortLocked", "portLocked", "locked", "Locked", "isLocked", "IsLocked", "lock", "Lock", "portLock", "PortLock", "value", "Value")
            if found:
                return True, value
            for envelope in port_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_found, nested_value = _port_locked_from_payload(nested)
                    if nested_found:
                        return True, nested_value
            return False, None

        if isinstance(port_payload, dict):
            if port is None or isinstance(port, dict):
                selector = _port_selector_from_payload(port_payload)
                if selector is not None:
                    port = selector
            auth_as = _mapping_value(port_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
            for key in port_payload_aliases:
                kwargs.pop(key, None)
            kwargs = {**kwargs, **port_payload}
        optional = {
            key: value
            for key, value in kwargs.items()
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            not in {"port", "uid", "portid", "id", "interface", "interfaceid", "portname", "name", "obj", "object", "target", "authas"}
        }
        if function_alias in {"lockport", "lockinterface", "lockportaccess", "enableportlock"} and not any(re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() in {"locked", "lock", "islocked", "portlock", "portlocked", "value"} for key in optional):
            optional["PortLocked"] = True
        if function_alias in {"unlockport", "unlockinterface", "unlockportaccess", "disableportlock"} and not any(re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() in {"locked", "lock", "islocked", "portlock", "portlocked", "value"} for key in optional):
            optional["PortLocked"] = False
        for key in list(optional):
            normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            if normalized_key in {"locked", "lock", "islocked", "portlock", "portlocked", "value"}:
                optional["PortLocked"] = optional.pop(key)
        if isinstance(port_payload, dict) and "PortLocked" not in optional:
            found_locked, nested_locked = _port_locked_from_payload(port_payload)
            if found_locked:
                optional["PortLocked"] = nested_locked
        optional["authAs"] = auth_as
        return build("Set", port, optional=optional, sp_value="AdminSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "random",
        "getrandom",
        "generaterandom",
        "generaterandombytes",
        "randombytes",
        "getrandombytes",
        "readrandombytes",
        "fetchrandombytes",
        "rng",
        "getrng",
        "rngbytes",
        "readrandom",
        "fetchrandom",
        "randombuffer",
        "entropy",
        "getentropy",
        "readentropy",
        "fetchentropy",
        "generateentropy",
        "entropybytes",
    }:
        count = _arg_or_kw(args, kwargs, 0, "count", "Count", "numBytes", "num_bytes", "length", "Length", "size", "Size")
        buffer_out = _arg_or_kw(args, kwargs, 1, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer")
        random_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "policy", "Policy", "config", "Config", "request", "Request",
            "operation", "Operation", "randomRequest", "RandomRequest",
            "rngRequest", "RNGRequest", "entropyRequest", "EntropyRequest",
            "operationRequest", "OperationRequest",
        )
        random_payload = _mapping_value(kwargs, *random_payload_aliases)
        if not isinstance(random_payload, dict):
            random_payload = _mapping_value(inp, *random_payload_aliases)
        if not isinstance(random_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            random_payload = _mapping_value(args[0], *random_payload_aliases)
            if not isinstance(random_payload, dict):
                random_payload = args[0]
        if isinstance(random_payload, dict):
            for _ in range(4):
                merged_random_payload = dict(random_payload)
                for envelope in (
                    "values", "Values", "settings", "Settings", "options", "Options",
                    "policy", "Policy", "config", "Config", "request", "Request",
                    "operation", "Operation", "randomRequest", "RandomRequest",
                    "rngRequest", "RNGRequest", "entropyRequest", "EntropyRequest",
                    "operationRequest", "OperationRequest", "random", "Random", "rng", "RNG",
                ):
                    nested_random_payload = _mapping_value(random_payload, envelope)
                    if isinstance(nested_random_payload, dict) and nested_random_payload is not random_payload:
                        merged_random_payload.update(nested_random_payload)
                if merged_random_payload == random_payload:
                    break
                random_payload = merged_random_payload
        if isinstance(random_payload, dict) and (count is None or isinstance(count, dict)):
            payload_count = _mapping_value(random_payload, "count", "Count", "numBytes", "num_bytes", "length", "Length", "size", "Size", "byteCount", "byte_count", "bytes", "Bytes")
            if payload_count is not None:
                count = payload_count
        if isinstance(random_payload, dict) and buffer_out is None:
            buffer_out = _mapping_value(random_payload, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer", "destination", "Destination", "dest", "Dest", "out", "Out")
        optional = {"Count": count if count is not None else 32}
        if buffer_out is not None:
            optional["BufferOut"] = buffer_out
        return build("Random", "ThisSP", raw_args=count if count is not None else 32, optional=optional, sp_value="AdminSP")

    if function_alias in {"takeownership", "takeown", "takeowner"}:
        credential = _arg_or_kw(args, kwargs, 0, "pin", "PIN", "sid", "SID", "credential", "Credential", "password", "Password", "newPin", "newPIN")
        ownership_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "credential",
            "Credential",
            "credentialRequest",
            "CredentialRequest",
            "ownershipRequest",
            "OwnershipRequest",
            "takeOwnershipRequest",
            "TakeOwnershipRequest",
            "spRequest",
            "SPRequest",
            "lifecycleRequest",
            "LifecycleRequest",
            "securityProviderRequest",
            "SecurityProviderRequest",
        )
        ownership_payload = _mapping_value(kwargs, *ownership_payload_aliases)
        if not isinstance(ownership_payload, dict):
            ownership_payload = _mapping_value(inp, *ownership_payload_aliases)
        if not isinstance(ownership_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            ownership_payload = _mapping_value(args[0], *ownership_payload_aliases)
            if not isinstance(ownership_payload, dict):
                ownership_payload = args[0]
        if isinstance(ownership_payload, dict):
            for _ in range(2):
                merged_ownership_payload = dict(ownership_payload)
                for envelope in ownership_payload_aliases:
                    found_envelope, nested_ownership_payload = _dict_lookup(ownership_payload, envelope)
                    if found_envelope and isinstance(nested_ownership_payload, dict) and nested_ownership_payload is not ownership_payload:
                        merged_ownership_payload.update(nested_ownership_payload)
                if merged_ownership_payload == ownership_payload:
                    break
                ownership_payload = merged_ownership_payload
            credential = _mapping_value(
                ownership_payload,
                "pin",
                "PIN",
                "sid",
                "SID",
                "credential",
                "Credential",
                "password",
                "Password",
                "newPin",
                "newPIN",
                "authAs",
                "AuthAs",
                "auth_as",
                "authAS",
            ) or credential
            if isinstance(credential, dict):
                nested_credential = _mapping_value(
                    credential,
                    "pin",
                    "PIN",
                    "proof",
                    "Proof",
                    "password",
                    "Password",
                    "secret",
                    "Secret",
                    "value",
                    "Value",
                )
                if nested_credential is not None and not isinstance(nested_credential, dict):
                    credential = nested_credential
        auth_as = ("SID", credential)
        return build("Activate", "LockingSP", optional={"authAs": auth_as}, sp_value="AdminSP", auth_value=auth_as, challenge=credential)

    if function_alias in {"activate", "activatelocking", "activatelockingsp", "enablelocking", "enablelockingsp", "setuplockingsp", "provisionlockingsp", "initializelockingsp", "initlockingsp", "activatesp"}:
        auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or auth
        activate_credential = _arg_or_kw(args, kwargs, 2, "proof", "Proof", "credential", "Credential", "pin", "PIN", "password", "Password", "secret", "Secret")
        activate_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "credential",
            "Credential",
            "auth",
            "Auth",
            "activateRequest",
            "ActivateRequest",
            "spRequest",
            "SPRequest",
            "lifecycleRequest",
            "LifecycleRequest",
            "securityProviderRequest",
            "SecurityProviderRequest",
        )
        activate_payload = _mapping_value(kwargs, *activate_payload_aliases)
        if not isinstance(activate_payload, dict):
            activate_payload = _mapping_value(inp, *activate_payload_aliases)
        if not isinstance(activate_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            activate_payload = _mapping_value(args[0], *activate_payload_aliases)
            if not isinstance(activate_payload, dict):
                activate_payload = args[0]
        if isinstance(activate_payload, dict):
            for _ in range(2):
                merged_activate_payload = dict(activate_payload)
                for envelope in activate_payload_aliases:
                    found_envelope, nested_activate_payload = _dict_lookup(activate_payload, envelope)
                    if found_envelope and isinstance(nested_activate_payload, dict) and nested_activate_payload is not activate_payload:
                        merged_activate_payload.update(nested_activate_payload)
                if merged_activate_payload == activate_payload:
                    break
                activate_payload = merged_activate_payload
            if auth is None or isinstance(auth, dict):
                auth = _mapping_value(activate_payload, "auth", "Auth", "authority", "Authority", "user", "User", "identity", "Identity", "username", "Username")
            if activate_credential is None or isinstance(activate_credential, dict):
                activate_credential = _mapping_value(
                    activate_payload,
                    "proof",
                    "Proof",
                    "credential",
                    "Credential",
                    "pin",
                    "PIN",
                    "password",
                    "Password",
                    "secret",
                    "Secret",
                    "HostChallenge",
                    "hostChallenge",
                    "challenge",
                    "Challenge",
                    "value",
                    "Value",
                )
            if isinstance(activate_credential, dict):
                nested_activate_credential = _mapping_value(
                    activate_credential,
                    "proof",
                    "Proof",
                    "pin",
                    "PIN",
                    "password",
                    "Password",
                    "secret",
                    "Secret",
                    "HostChallenge",
                    "hostChallenge",
                    "challenge",
                    "Challenge",
                    "value",
                    "Value",
                )
                if nested_activate_credential is not None and not isinstance(nested_activate_credential, dict):
                    activate_credential = nested_activate_credential
            auth_as = _mapping_value(activate_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        if activate_credential is not None and auth is not None and not isinstance(auth_as, (list, tuple, dict)):
            auth_as = (auth, activate_credential)
        challenge = activate_credential if activate_credential is not None else _authas_credential_arg({}, {"authAs": auth_as}, None)
        return build("Activate", "LockingSP", optional={"authAs": auth_as}, sp_value="AdminSP", auth_value=auth_as, challenge=challenge)

    if function_alias in {"erase", "eraserange"}:
        range_no = range_arg(0)
        erase_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "target",
            "Target",
            "eraseRequest",
            "EraseRequest",
            "erase",
            "Erase",
            "keyRequest",
            "KeyRequest",
            "mediaKeyRequest",
            "MediaKeyRequest",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "credential",
            "Credential",
        )
        erase_payload = _mapping_value(kwargs, *erase_payload_aliases)
        if not isinstance(erase_payload, dict):
            erase_payload = _mapping_value(inp, *erase_payload_aliases)
        if not isinstance(erase_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            erase_payload = _mapping_value(args[0], *erase_payload_aliases)
            if not isinstance(erase_payload, dict):
                erase_payload = args[0]
        if isinstance(erase_payload, dict):
            for _ in range(2):
                merged_erase_payload = dict(erase_payload)
                for envelope in erase_payload_aliases:
                    found_envelope, nested_erase_payload = _dict_lookup(erase_payload, envelope)
                    if found_envelope and isinstance(nested_erase_payload, dict) and nested_erase_payload is not erase_payload:
                        merged_erase_payload.update(nested_erase_payload)
                if merged_erase_payload == erase_payload:
                    break
                erase_payload = merged_erase_payload
        if (range_no is None or isinstance(range_no, dict)) and isinstance(erase_payload, dict):
            range_no = _mapping_value(
                erase_payload,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "bandNo",
                "band_no",
                "rangeName",
                "range_name",
                "lockingRangeID",
                "lockingRangeId",
                "locking_range_id",
                "rangeNumber",
                "range_number",
                "rangeIndex",
                "range_index",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        erase_credential = _arg_or_kw(args, kwargs, 2, "proof", "Proof", "credential", "Credential", "pin", "PIN", "password", "Password", "secret", "Secret")
        if auth_as is None and isinstance(erase_payload, dict):
            auth_as = _mapping_value(erase_payload, "authAs", "AuthAs", "auth_as", "authAS", "auth", "Auth", "authority", "Authority")
        if isinstance(erase_payload, dict) and (erase_credential is None or isinstance(erase_credential, dict)):
            erase_credential = _mapping_value(erase_payload, "proof", "Proof", "credential", "Credential", "pin", "PIN", "password", "Password", "secret", "Secret", "value", "Value")
        if isinstance(erase_credential, dict):
            nested_erase_credential = _mapping_value(erase_credential, "proof", "Proof", "pin", "PIN", "password", "Password", "secret", "Secret", "value", "Value")
            if nested_erase_credential is not None and not isinstance(nested_erase_credential, dict):
                erase_credential = nested_erase_credential
            else:
                erase_credential = None
        auth_as = auth_as or "EraseMaster"
        if erase_credential is not None and not isinstance(auth_as, (list, tuple, dict)):
            auth_as = (auth_as, erase_credential)
        challenge = erase_credential if erase_credential is not None else _authas_credential_arg({}, {"authAs": auth_as}, None)
        return build("Erase", _band_target_from_range_value(range_no), optional={"authAs": auth_as}, auth_value=auth_as, challenge=challenge)

    if function_alias in {
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
        "rekey",
        "refreshrangekey",
        "generatemek",
        "rotatemek",
        "regeneratemek",
    }:
        target = _arg_or_kw(args, kwargs, 0, "range_key", "rangeKey", "key", "Key", "mek", "MEK", "activeKey", "ActiveKey")
        auth = _arg_or_kw(args, kwargs, 1, "auth", "Auth")
        genkey_credential = _arg_or_kw(args, kwargs, 2, "proof", "Proof", "credential", "Credential", "pin", "PIN", "password", "Password", "secret", "Secret")
        genkey_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "target",
            "Target",
            "keyRequest",
            "KeyRequest",
            "mediaKeyRequest",
            "MediaKeyRequest",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "credential",
            "Credential",
        )
        genkey_payload = _mapping_value(kwargs, *genkey_payload_aliases)
        if not isinstance(genkey_payload, dict):
            genkey_payload = _mapping_value(inp, *genkey_payload_aliases)
        if len(args) > 0 and isinstance(args[0], dict):
            dict_target = _mapping_value(args[0], "range_key", "rangeKey", "key", "Key", "mek", "MEK", "activeKey", "ActiveKey")
            if dict_target is not None:
                target = dict_target
            else:
                target = None
            dict_auth = _mapping_value(args[0], "auth", "Auth", "authAs", "AuthAs", "auth_as", "authAS")
            if dict_auth is not None:
                auth = dict_auth
            if not isinstance(genkey_payload, dict):
                genkey_payload = _mapping_value(args[0], *genkey_payload_aliases)
                if not isinstance(genkey_payload, dict):
                    genkey_payload = args[0]
        if isinstance(genkey_payload, dict):
            for _ in range(2):
                merged_genkey_payload = dict(genkey_payload)
                for envelope in genkey_payload_aliases:
                    found_envelope, nested_genkey_payload = _dict_lookup(genkey_payload, envelope)
                    if found_envelope and isinstance(nested_genkey_payload, dict) and nested_genkey_payload is not genkey_payload:
                        merged_genkey_payload.update(nested_genkey_payload)
                if merged_genkey_payload == genkey_payload:
                    break
                genkey_payload = merged_genkey_payload
            dict_target = _mapping_value(genkey_payload, "range_key", "rangeKey", "key", "Key", "mek", "MEK", "activeKey", "ActiveKey", "target", "Target")
            if dict_target is not None:
                target = dict_target
            elif target is None:
                target = None
            dict_auth = _mapping_value(genkey_payload, "auth", "Auth", "authority", "Authority", "authAs", "AuthAs", "auth_as", "authAS")
            if dict_auth is not None:
                auth = dict_auth
            if genkey_credential is None or isinstance(genkey_credential, dict):
                genkey_credential = _mapping_value(genkey_payload, "proof", "Proof", "credential", "Credential", "pin", "PIN", "password", "Password", "secret", "Secret", "value", "Value")
            if isinstance(genkey_credential, dict):
                nested_genkey_credential = _mapping_value(genkey_credential, "proof", "Proof", "pin", "PIN", "password", "Password", "secret", "Secret", "value", "Value")
                if nested_genkey_credential is not None and not isinstance(nested_genkey_credential, dict):
                    genkey_credential = nested_genkey_credential
                else:
                    genkey_credential = None
        if len(args) > 1 and authority_like(args[0]) and not authority_like(args[1]):
            auth = args[0]
            target = args[1]
        range_no = _mapping_value(
            kwargs,
            "rangeNo",
            "range",
            "Range",
            "range_no",
            "rangeID",
            "rangeId",
            "range_id",
            "band",
            "Band",
            "bandID",
            "bandId",
            "band_id",
            "bandName",
            "band_name",
            "bandNo",
            "band_no",
            "rangeName",
            "range_name",
            "lockingRangeID",
            "lockingRangeId",
            "locking_range_id",
            "rangeNumber",
            "range_number",
            "rangeIndex",
            "range_index",
            "id",
            "ID",
            "uid",
            "UID",
            "obj",
            "object",
            "Object",
            "target",
            "Target",
        )
        if range_no is None and isinstance(genkey_payload, dict):
            range_no = _mapping_value(
                genkey_payload,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "bandName",
                "band_name",
                "bandNo",
                "band_no",
                "rangeName",
                "range_name",
                "lockingRangeID",
                "lockingRangeId",
                "locking_range_id",
                "rangeNumber",
                "range_number",
                "rangeIndex",
                "range_index",
                "id",
                "ID",
                "uid",
                "UID",
                "obj",
                "object",
                "Object",
                "target",
                "Target",
            )
        if isinstance(range_no, dict):
            range_no = _mapping_value(
                range_no,
                "rangeNo",
                "range",
                "Range",
                "range_no",
                "rangeID",
                "rangeId",
                "range_id",
                "band",
                "Band",
                "bandID",
                "bandId",
                "band_id",
                "id",
                "ID",
                "uid",
                "UID",
                "target",
                "Target",
            )
        if isinstance(target, dict):
            nested_target = _mapping_value(
                target,
                "range_key",
                "rangeKey",
                "key",
                "Key",
                "mek",
                "MEK",
                "activeKey",
                "ActiveKey",
                "uid",
                "UID",
                "target",
                "Target",
            )
            if nested_target is not None and nested_target is not target:
                target = nested_target
            else:
                target_range = _mapping_value(
                    target,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "id",
                    "ID",
                )
                if target_range is not None:
                    target = None
                    range_no = target_range
        if target is None and range_no is not None:
            parsed_range = _parse_int(range_no)
            if parsed_range is None:
                parsed_range = _range_id_from_symbol(_normalize_name(range_no))
            target = "K_AES_256_GlobalRange_Key" if parsed_range == 0 else f"K_AES_256_Range{parsed_range or range_no}_Key"
        elif _parse_int(target) is not None and not isinstance(target, bool):
            parsed_range = _parse_int(target)
            target = "K_AES_256_GlobalRange_Key" if parsed_range == 0 else f"K_AES_256_Range{parsed_range}_Key"
        if genkey_credential is not None and auth is not None and not isinstance(auth, (list, tuple, dict)):
            auth = (auth, genkey_credential)
        auth_as = authas(auth)
        challenge = genkey_credential if genkey_credential is not None else _authas_credential_arg({}, {"authAs": auth_as}, None)
        return build("GenKey", target, optional={"authAs": auth_as}, auth_value=auth_as, challenge=challenge)

    revert_payload_aliases = (
        "values",
        "Values",
        "settings",
        "Settings",
        "options",
        "Options",
        "params",
        "Params",
        "parameters",
        "Parameters",
        "policy",
        "Policy",
        "config",
        "Config",
        "request",
        "Request",
        "operation",
        "Operation",
        "revert",
        "Revert",
        "revertRequest",
        "RevertRequest",
        "revertSpRequest",
        "RevertSPRequest",
        "spRequest",
        "SPRequest",
        "lifecycleRequest",
        "LifecycleRequest",
        "securityProviderRequest",
        "SecurityProviderRequest",
    )
    revert_payload = _mapping_value(kwargs, *revert_payload_aliases)
    if not isinstance(revert_payload, dict):
        revert_payload = _mapping_value(inp, *revert_payload_aliases)
    if not isinstance(revert_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
        revert_payload = _mapping_value(args[0], *revert_payload_aliases)
        if not isinstance(revert_payload, dict):
            revert_payload = args[0]
    if isinstance(revert_payload, dict):
        for _ in range(2):
            merged_revert_payload = dict(revert_payload)
            for envelope in revert_payload_aliases:
                found_envelope, nested_revert_payload = _dict_lookup(revert_payload, envelope)
                if found_envelope and isinstance(nested_revert_payload, dict) and nested_revert_payload is not revert_payload:
                    merged_revert_payload.update(nested_revert_payload)
            if merged_revert_payload == revert_payload:
                break
            revert_payload = merged_revert_payload

    def _revert_credential_value(value: Any) -> Any:
        if isinstance(value, dict):
            nested = _mapping_value(value, "psid", "PSID", "credential", "Credential", "cred", "Cred", "pin", "PIN", "proof", "Proof", "password", "Password", "secret", "Secret", "value", "Value")
            if nested is not None and nested is not value:
                return _revert_credential_value(nested)
        return value

    revertsp_target = _arg_or_kw(args, kwargs, 0, "target", "Target", "sp", "SP", "spid", "SPID", "object", "Object")
    if revertsp_target is None and isinstance(revert_payload, dict):
        revertsp_target = _mapping_value(revert_payload, "target", "Target", "sp", "SP", "spid", "SPID", "object", "Object")
    revertsp_targets_locking = function_alias == "revertsp" and _sp_from_value(revertsp_target) == "LockingSP"
    revertsp_targets_admin = function_alias == "revertsp" and _sp_from_value(revertsp_target) in {"AdminSP", None}
    revertsp_admin_credential = _arg_or_kw(args, kwargs, 0, "psid", "PSID", "credential", "Credential", "cred", "Cred", "pin", "PIN")
    if revertsp_admin_credential is None and isinstance(revert_payload, dict):
        revertsp_admin_credential = _mapping_value(revert_payload, "psid", "PSID", "credential", "Credential", "cred", "Cred", "pin", "PIN", "proof", "Proof")
    revertsp_admin_credential = _revert_credential_value(revertsp_admin_credential)
    revertsp_has_admin_credential = revertsp_admin_credential is not None
    if function_alias in {"revert", "revertdrive", "revertadminsp", "factoryreset", "factoryresetdrive", "psidrevert"} or (
        function_alias == "revertsp" and revertsp_targets_admin and revertsp_has_admin_credential
    ):
        psid = _arg_or_kw(args, kwargs, 0, "psid", "PSID")
        if psid is None:
            psid = revertsp_admin_credential
        if isinstance(revert_payload, dict) and (psid is None or isinstance(psid, dict)):
            payload_psid = _mapping_value(revert_payload, "psid", "PSID", "credential", "Credential", "cred", "Cred", "pin", "PIN")
            if payload_psid is not None:
                psid = _revert_credential_value(payload_psid)
        optional = {"authAs": ("PSID", psid)}
        if not isinstance(psid, str):
            optional["__PSIDCredentialMap"] = psid
        return build("RevertSP", "ThisSP", optional=optional, sp_value="AdminSP", auth_value=("PSID", psid), challenge=psid)

    if function_alias in {"revertlockingsp", "revertlocking"} or revertsp_targets_locking:
        cred_index = 1 if revertsp_targets_locking else 0
        cred = _arg_or_kw(args, kwargs, cred_index, "cred", "credential", "pin", "PIN")
        if isinstance(revert_payload, dict) and (cred is None or isinstance(cred, dict)):
            payload_cred = _mapping_value(revert_payload, "cred", "Credential", "credential", "pin", "PIN", "proof", "Proof")
            if payload_cred is not None:
                cred = _revert_credential_value(payload_cred)
        optional = {"authAs": ("Admin1", cred)}
        keep_global = _mapping_value(
            kwargs,
            "KeepGlobalRangeKey",
            "keepGlobalRangeKey",
            "KeepGlobalRange",
            "keepGlobalRange",
            "preserveGlobalRangeKey",
            "PreserveGlobalRangeKey",
            "preserveGlobalRange",
            "PreserveGlobalRange",
            "keepGlobalKey",
            "KeepGlobalKey",
        )
        if keep_global is None and isinstance(revert_payload, dict):
            keep_global = _mapping_value(
                revert_payload,
                "KeepGlobalRangeKey",
                "keepGlobalRangeKey",
                "KeepGlobalRange",
                "keepGlobalRange",
                "preserveGlobalRangeKey",
                "PreserveGlobalRangeKey",
                "preserveGlobalRange",
                "PreserveGlobalRange",
                "keepGlobalKey",
                "KeepGlobalKey",
            )
        if keep_global is not None:
            optional["KeepGlobalRangeKey"] = keep_global
        return build("RevertSP", "ThisSP", optional=optional, sp_value="LockingSP", auth_value=("Admin1", cred), challenge=cred)

    if function_alias in {"tpersign", "signdata", "tpersigndata", "sign", "signbytes", "signpayload", "signmessage", "signdigest", "createsignature", "generatesignature", "makesignature", "signaturecreate", "signaturegenerate", "tpersignpayload", "maketpersignature", "createtpersignature", "generatetpersignature"}:
        payload = _arg_or_kw(args, kwargs, 0, "dataInput", "Data", "data", "Input", "payload", "Payload", "bytes", "Bytes")
        target = _mapping_value(kwargs, "target", "Target", "object", "Object", "obj", "credential", "Credential", "hash", "Hash", "algorithm", "Algorithm", "key", "Key")
        buffer_out = _arg_or_kw(args, kwargs, 2, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        sign_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "policy", "Policy", "config", "Config", "request", "Request",
            "operation", "Operation", "signRequest", "SignRequest",
            "signatureRequest", "SignatureRequest", "operationRequest", "OperationRequest",
        )
        sign_payload = _mapping_value(kwargs, *sign_payload_aliases)
        if not isinstance(sign_payload, dict):
            sign_payload = _mapping_value(inp, *sign_payload_aliases)
        if not isinstance(sign_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            sign_payload = _mapping_value(args[0], *sign_payload_aliases)
            if not isinstance(sign_payload, dict):
                sign_payload = args[0]
        if isinstance(sign_payload, dict):
            for _ in range(2):
                nested_sign_payload = _mapping_value(
                    sign_payload,
                    "values",
                    "Values",
                    "settings",
                    "Settings",
                    "options",
                    "Options",
                    "policy",
                    "Policy",
                    "config",
                    "Config",
                    "request",
                    "Request",
                    "operation",
                    "Operation",
                    "signRequest",
                    "SignRequest",
                    "signatureRequest",
                    "SignatureRequest",
                    "operationRequest",
                    "OperationRequest",
                    "sign",
                    "Sign",
                    "signature",
                    "Signature",
                    "input",
                    "Input",
                )
                if isinstance(nested_sign_payload, dict) and nested_sign_payload is not sign_payload:
                    sign_payload = {**sign_payload, **nested_sign_payload}
            if payload is None or isinstance(payload, dict):
                payload = _mapping_value(sign_payload, "dataInput", "Data", "data", "Input", "payload", "Payload", "bytes", "Bytes")
            if target is None:
                target = _mapping_value(sign_payload, "target", "Target", "object", "Object", "obj", "credential", "Credential", "hash", "Hash", "algorithm", "Algorithm", "key", "Key")
            if buffer_out is None:
                buffer_out = _mapping_value(sign_payload, "BufferOut", "bufferOut", "Output", "output", "buffer", "Buffer", "destination", "Destination", "dest", "Dest", "out", "Out")
            auth_as = _mapping_value(sign_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        if target is not None and function_alias not in {"tpersign", "tpersigndata", "signdata"}:
            raw_args = {}
            if payload is not None:
                raw_args["Input"] = {"Data": payload}
            if buffer_out is not None:
                raw_args["BufferOut"] = buffer_out
            return build("Sign", crypto_object_target(target, "H_SHA_256"), raw_args=raw_args, optional={**raw_args, "authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))
        return build("Sign", "TPerSign", raw_args=(payload,), optional={"authAs": auth_as, "Data": payload}, sp_value="AdminSP", auth_value=auth_as)

    if function_alias == "setmbr":
        mbr_payload_aliases = ("values", "Values", "settings", "Settings", "options", "Options", "policy", "Policy", "config", "Config", "state", "State", "control", "Control", "status", "Status", "write", "Write", "window", "Window", "range", "Range", "slice", "Slice", "block", "Block", "chunk", "Chunk", "segment", "Segment", "span", "Span", "bounds", "Bounds", "byteRange", "ByteRange", "byte_range", "request", "Request")
        mbr_payload = _mapping_value(kwargs, *mbr_payload_aliases)
        if not isinstance(mbr_payload, dict):
            mbr_payload = _mapping_value(inp, *mbr_payload_aliases)
        if not isinstance(mbr_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            mbr_payload = _mapping_value(args[0], *mbr_payload_aliases)
            if not isinstance(mbr_payload, dict):
                mbr_payload = args[0]
        if isinstance(mbr_payload, dict):
            nested_mbr_payload = _mapping_value(mbr_payload, "window", "Window", "range", "Range", "slice", "Slice", "block", "Block", "chunk", "Chunk", "segment", "Segment", "span", "Span", "bounds", "Bounds", "byteRange", "ByteRange", "byte_range")
            if isinstance(nested_mbr_payload, dict):
                mbr_payload = nested_mbr_payload
            for _ in range(2):
                nested_control_payload = _mapping_value(mbr_payload, "policy", "Policy", "config", "Config", "state", "State", "control", "Control", "status", "Status", "request", "Request", "reset", "Reset")
                if isinstance(nested_control_payload, dict) and nested_control_payload is not mbr_payload:
                    mbr_payload = {**mbr_payload, **nested_control_payload}
        source = mbr_payload if isinstance(mbr_payload, dict) else kwargs
        enabled = _mapping_value(source, "Enabled", "enabled", "enable", "Enable", "MBREnable", "mbrEnable", "mbr_enable") if isinstance(source, dict) else None
        done = _mapping_value(source, "Done", "done", "MBRDone", "mbrDone", "mbr_done") if isinstance(source, dict) else None
        done_on_reset = _mapping_value(source, "DoneOnReset", "doneOnReset", "done_on_reset", "MBRDoneOnReset", "mbrDoneOnReset", "DOR", "dor", "resetTypes", "reset_types") if isinstance(source, dict) else None
        auth_as = _mapping_value(source, "authAs", "AuthAs", "auth_as", "authAS") if isinstance(source, dict) else None
        auth_as = auth_as or _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        if enabled is not None or done is not None or done_on_reset is not None:
            optional: dict[str, Any] = {"authAs": auth_as}
            if enabled is not None:
                optional["Enabled"] = enabled
            if done is not None:
                optional["Done"] = done
            if done_on_reset is not None:
                optional["DoneOnReset"] = done_on_reset
            return build("Set", "MBRControl", optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))
        data = _arg_or_kw(args, kwargs, 1, "data", "Data", "payload", "Payload", "bytes", "Bytes", "value", "Value", "hex", "Hex")
        data_first_arg = False
        if data is None and args and not isinstance(args[0], dict) and _parse_int(args[0]) is None:
            data = args[0]
            data_first_arg = True
        if data is None and isinstance(source, dict):
            data = _mapping_value(source, "data", "Data", "payload", "Payload", "bytes", "Bytes", "value", "Value", "hex", "Hex")
        if data is not None:
            start = byte_start_arg(1 if data_first_arg else 0)
            if start is None and isinstance(source, dict):
                start = _mapping_value(source, "startRow", "StartRow", "row", "Row", "offset", "Offset", "byteOffset", "byte_offset", "startOffset", "start_offset", "start", "Start", "index", "Index", "position", "Position")
            if start is None:
                start = 0
            return build("Set", "MBR", raw_args=(("startRow", start), ("Bytes", data)), optional={"authAs": auth_as, "Where": {"Row": start}, "Bytes": data}, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "setmbrdone",
        "setmbrdoneflag",
        "setmbrcomplete",
        "completembr",
        "finishmbr",
        "setdonembr",
        "markmbrcomplete",
        "clearmbrcomplete",
        "resetmbrcomplete",
        "setmbrnotdone",
        "clearmbrdone",
        "resetmbrdone",
        "unmarkmbrdone",
        "setmbrenable",
        "setmbrenabled",
        "clearmbrenabled",
        "setmbrdisabled",
        "setmbrcontrol",
        "putmbrcontrol",
        "storembrcontrol",
        "savembrcontrol",
        "writembrcontrol",
        "programmbrcontrol",
        "setmbrstate",
        "updatembrstate",
        "putmbrstate",
        "storembrstate",
        "savembrstate",
        "configurembrstate",
        "setmbrstatus",
        "updatembrstatus",
        "putmbrstatus",
        "storembrstatus",
        "savembrstatus",
        "configurembrstatus",
        "setmbrdoneonreset",
        "setdoneonreset",
        "setmbrdor",
        "setmbrresetdone",
        "markmbrdoneonreset",
        "clearmbrdoneonreset",
        "setmbrdoneafterreset",
        "setmbrdoneonpowercycle",
        "setmbrdoneonresettypes",
        "setmbrresettypes",
        "configurembrcontrol",
        "updatembrcontrol",
        "updatembrenabled",
        "putmbrenabled",
        "storembrenabled",
        "savembrenabled",
        "writembrenabled",
        "updatembrenable",
        "putmbrenable",
        "storembrenable",
        "savembrenable",
        "updatembrdone",
        "putmbrdone",
        "storembrdone",
        "savembrdone",
        "writembrdone",
        "updatembrdoneflag",
        "putmbrdoneflag",
        "storembrdoneflag",
        "savembrdoneflag",
        "updatembrcomplete",
        "putmbrcomplete",
        "storembrcomplete",
        "savembrcomplete",
        "updatembrdoneonreset",
        "putmbrdoneonreset",
        "storembrdoneonreset",
        "savembrdoneonreset",
        "configurembrdoneonreset",
        "updatedoneonreset",
        "putdoneonreset",
        "storedoneonreset",
        "savedoneonreset",
        "updatembrdor",
        "putmbrdor",
        "storembrdor",
        "savembrdor",
        "updatembrresettypes",
        "putmbrresettypes",
        "storembrresettypes",
        "savembrresettypes",
        "enablembr",
        "disablembr",
        "markmbrdone",
    }:
        mbr_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "policy",
            "Policy",
            "config",
            "Config",
            "state",
            "State",
            "control",
            "Control",
            "status",
            "Status",
            "request",
            "Request",
            "mbrRequest",
            "MBRRequest",
            "mbrControlRequest",
            "MBRControlRequest",
            "bootRequest",
            "BootRequest",
            "mbrControl",
            "MBRControl",
            "mbr_control",
            "reset",
            "Reset",
        )
        mbr_payload = _mapping_value(kwargs, *mbr_payload_aliases)
        if not isinstance(mbr_payload, dict):
            mbr_payload = _mapping_value(inp, *mbr_payload_aliases)
        if not isinstance(mbr_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            mbr_payload = _mapping_value(args[0], *mbr_payload_aliases)
            if not isinstance(mbr_payload, dict):
                mbr_payload = args[0]
        if isinstance(mbr_payload, dict):
            for _ in range(2):
                merged_mbr_payload = dict(mbr_payload)
                for envelope in mbr_payload_aliases:
                    nested_mbr_payload = _mapping_value(mbr_payload, envelope)
                    if isinstance(nested_mbr_payload, dict) and nested_mbr_payload is not mbr_payload:
                        merged_mbr_payload.update(nested_mbr_payload)
                if merged_mbr_payload == mbr_payload:
                    break
                mbr_payload = merged_mbr_payload
        optional: dict[str, Any] = {}
        source = mbr_payload if isinstance(mbr_payload, dict) else kwargs
        if function_alias in {
            "setmbrdone",
            "updatembrdone",
            "putmbrdone",
            "storembrdone",
            "savembrdone",
            "writembrdone",
            "setmbrdoneflag",
            "updatembrdoneflag",
            "putmbrdoneflag",
            "storembrdoneflag",
            "savembrdoneflag",
            "setmbrcomplete",
            "updatembrcomplete",
            "putmbrcomplete",
            "storembrcomplete",
            "savembrcomplete",
            "completembr",
            "finishmbr",
            "setdonembr",
            "setmbrnotdone",
            "clearmbrdone",
            "clearmbrcomplete",
            "resetmbrdone",
            "resetmbrcomplete",
            "unmarkmbrdone",
            "markmbrdone",
            "markmbrcomplete",
        }:
            done = _arg_or_kw(args, kwargs, 0, "done", "Done", "MBRDone", "mbrDone", "mbr_done", "value", "Value")
            if done is None and isinstance(source, dict):
                done = _mapping_value(source, "done", "Done", "MBRDone", "mbrDone", "mbr_done", "value", "Value")
            if function_alias in {"markmbrdone", "markmbrcomplete", "completembr", "finishmbr", "setmbrdoneflag", "setmbrcomplete"} and done is None:
                done = True
            if function_alias in {"setmbrnotdone", "clearmbrdone", "clearmbrcomplete", "resetmbrdone", "resetmbrcomplete", "unmarkmbrdone"} and done is None:
                done = False
            optional["Done"] = done
        elif function_alias in {
            "setmbrenable",
            "setmbrenabled",
            "updatembrenabled",
            "putmbrenabled",
            "storembrenabled",
            "savembrenabled",
            "writembrenabled",
            "updatembrenable",
            "putmbrenable",
            "storembrenable",
            "savembrenable",
            "setmbrdisabled",
            "clearmbrenabled",
            "enablembr",
            "disablembr",
        }:
            enabled = _arg_or_kw(args, kwargs, 0, "enabled", "Enabled", "enable", "Enable", "MBREnable", "mbrEnable", "mbr_enable", "value", "Value")
            if enabled is None and isinstance(source, dict):
                enabled = _mapping_value(source, "enabled", "Enabled", "enable", "Enable", "MBREnable", "mbrEnable", "mbr_enable", "value", "Value")
            if function_alias in {"enablembr", "setmbrenable", "setmbrenabled"} and enabled is None:
                enabled = True
            if function_alias in {"disablembr", "setmbrdisabled", "clearmbrenabled"} and enabled is None:
                enabled = False
            optional["Enabled"] = enabled
        elif function_alias in {
            "setmbrdoneonreset",
            "setdoneonreset",
            "setmbrdor",
            "setmbrresetdone",
            "markmbrdoneonreset",
            "clearmbrdoneonreset",
            "setmbrdoneafterreset",
            "setmbrdoneonpowercycle",
            "setmbrdoneonresettypes",
            "setmbrresettypes",
            "updatembrdoneonreset",
            "putmbrdoneonreset",
            "storembrdoneonreset",
            "savembrdoneonreset",
            "configurembrdoneonreset",
            "updatedoneonreset",
            "putdoneonreset",
            "storedoneonreset",
            "savedoneonreset",
            "updatembrdor",
            "putmbrdor",
            "storembrdor",
            "savembrdor",
            "updatembrresettypes",
            "putmbrresettypes",
            "storembrresettypes",
            "savembrresettypes",
        }:
            done_on_reset = _arg_or_kw(
                args,
                kwargs,
                0,
                "DoneOnReset",
                "doneOnReset",
                "done_on_reset",
                "MBRDoneOnReset",
                "mbrDoneOnReset",
                "DOR",
                "dor",
                "resetTypes",
                "reset_types",
                "value",
                "Value",
            )
            if done_on_reset is None and isinstance(source, dict):
                done_on_reset = _mapping_value(
                    source,
                    "DoneOnReset",
                    "doneOnReset",
                    "done_on_reset",
                    "MBRDoneOnReset",
                    "mbrDoneOnReset",
                    "DOR",
                    "dor",
                    "resetTypes",
                    "reset_types",
                    "value",
                    "Value",
                )
            if function_alias == "setmbrdoneonpowercycle" and done_on_reset is None:
                done_on_reset = [0]
            if function_alias == "clearmbrdoneonreset" and done_on_reset is None:
                done_on_reset = []
            optional["DoneOnReset"] = done_on_reset
        else:
            enabled = _mapping_value(source, "Enabled", "enabled", "enable", "Enable", "MBREnable", "mbrEnable", "mbr_enable") if isinstance(source, dict) else None
            done = _mapping_value(source, "Done", "done", "MBRDone", "mbrDone", "mbr_done") if isinstance(source, dict) else None
            done_on_reset = _mapping_value(source, "DoneOnReset", "doneOnReset", "done_on_reset", "MBRDoneOnReset", "mbrDoneOnReset", "DOR", "dor", "resetTypes", "reset_types") if isinstance(source, dict) else None
            if enabled is not None:
                optional["Enabled"] = enabled
            if done is not None:
                optional["Done"] = done
            if done_on_reset is not None:
                optional["DoneOnReset"] = done_on_reset
        auth_as = _mapping_value(source, "authAs", "AuthAs", "auth_as", "authAS") if isinstance(source, dict) else None
        auth_as = auth_as or _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS")
        optional["authAs"] = auth_as
        return build("Set", "MBRControl", optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getmbrcontrol",
        "readmbrcontrol",
        "fetchmbrcontrol",
        "querymbrcontrol",
        "getmbrstate",
        "readmbrstate",
        "fetchmbrstate",
        "querymbrstate",
        "loadmbrstate",
        "getmbrstatus",
        "readmbrstatus",
        "fetchmbrstatus",
        "querymbrstatus",
        "loadmbrstatus",
        "getmbrenabled",
        "ismbrenabled",
        "readmbrenabled",
        "fetchmbrenabled",
        "querymbrenabled",
        "loadmbrenabled",
        "getmbrenable",
        "readmbrenable",
        "fetchmbrenable",
        "querymbrenable",
        "loadmbrenable",
        "getmbrdone",
        "ismbrdone",
        "readmbrdone",
        "fetchmbrdone",
        "querymbrdone",
        "loadmbrdone",
        "getmbrcomplete",
        "ismbrcomplete",
        "readmbrcomplete",
        "fetchmbrcomplete",
        "querymbrcomplete",
        "loadmbrcomplete",
        "getmbrdoneflag",
        "readmbrdoneflag",
        "fetchmbrdoneflag",
        "querymbrdoneflag",
        "loadmbrdoneflag",
        "readmbrcompleteflag",
        "fetchmbrcompleteflag",
        "querymbrcompleteflag",
        "getmbrdoneonreset",
        "readmbrdoneonreset",
        "fetchmbrdoneonreset",
        "querymbrdoneonreset",
        "loadmbrdoneonreset",
        "getdoneonreset",
        "readdoneonreset",
        "fetchdoneonreset",
        "querydoneonreset",
        "loaddoneonreset",
        "getmbrdor",
        "readmbrdor",
        "fetchmbrdor",
        "querymbrdor",
        "loadmbrdor",
        "getmbrresettypes",
        "readmbrresettypes",
        "fetchmbrresettypes",
        "querymbrresettypes",
        "loadmbrresettypes",
        "ismbrdoneonreset",
    }:
        auth_as = _arg_or_kw(args, kwargs, 0, "authAs", "AuthAs", "auth_as", "authAS")
        mbr_payload = _mapping_value(kwargs, "values", "Values", "settings", "Settings", "options", "Options")
        if not isinstance(mbr_payload, dict):
            mbr_payload = _mapping_value(inp, "values", "Values", "settings", "Settings", "options", "Options")
        if isinstance(mbr_payload, dict):
            auth_as = _mapping_value(mbr_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        optional = {"authAs": auth_as}
        raw_args: Any | None = None
        if function_alias in {"getmbrenabled", "ismbrenabled", "readmbrenabled", "fetchmbrenabled", "querymbrenabled", "loadmbrenabled", "getmbrenable", "readmbrenable", "fetchmbrenable", "querymbrenable", "loadmbrenable"}:
            raw_args = {"CellBlock": [{"startColumn": 1}, {"endColumn": 1}]}
            optional["CellBlock"] = raw_args["CellBlock"]
        elif function_alias in {
            "getmbrdone",
            "ismbrdone",
            "readmbrdone",
            "fetchmbrdone",
            "querymbrdone",
            "loadmbrdone",
            "getmbrcomplete",
            "ismbrcomplete",
            "readmbrcomplete",
            "fetchmbrcomplete",
            "querymbrcomplete",
            "loadmbrcomplete",
            "getmbrdoneflag",
            "readmbrdoneflag",
            "fetchmbrdoneflag",
            "querymbrdoneflag",
            "loadmbrdoneflag",
            "readmbrcompleteflag",
            "fetchmbrcompleteflag",
            "querymbrcompleteflag",
        }:
            raw_args = {"CellBlock": [{"startColumn": 2}, {"endColumn": 2}]}
            optional["CellBlock"] = raw_args["CellBlock"]
        elif function_alias in {
            "getmbrdoneonreset",
            "readmbrdoneonreset",
            "fetchmbrdoneonreset",
            "querymbrdoneonreset",
            "loadmbrdoneonreset",
            "getdoneonreset",
            "readdoneonreset",
            "fetchdoneonreset",
            "querydoneonreset",
            "loaddoneonreset",
            "getmbrdor",
            "readmbrdor",
            "fetchmbrdor",
            "querymbrdor",
            "loadmbrdor",
            "getmbrresettypes",
            "readmbrresettypes",
            "fetchmbrresettypes",
            "querymbrresettypes",
            "loadmbrresettypes",
            "ismbrdoneonreset",
        }:
            raw_args = {"CellBlock": [{"startColumn": 3}, {"endColumn": 3}]}
            optional["CellBlock"] = raw_args["CellBlock"]
        if found_return and isinstance(raw_return, dict):
            returned_columns = sorted(_flatten_return_values(raw_return, "MBRControl"))
            if returned_columns:
                raw_args = {"CellBlock": [{"startColumn": returned_columns[0]}, {"endColumn": returned_columns[-1]}]}
                optional["CellBlock"] = raw_args["CellBlock"]
        return build("Get", "MBRControl", raw_args=raw_args, optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "writembr",
        "storembr",
        "storembrblock",
        "storembrchunk",
        "storembrsegment",
        "storembrrange",
        "storembrslice",
        "storembrwindow",
        "storembrbytes",
        "storembrshadow",
        "storembrshadowbytes",
        "storembrtable",
        "setmbrblock",
        "setmbrchunk",
        "setmbrsegment",
        "setmbrrange",
        "setmbrslice",
        "setmbrwindow",
        "setmbrbytes",
        "setmbrdata",
        "setmbrpayload",
        "setmbrshadow",
        "setmbrshadowbytes",
        "setmbrtable",
        "writembrbytes",
        "writembrblock",
        "writembrchunk",
        "writembrdata",
        "writembrpayload",
        "writembrsegment",
        "writembrrange",
        "writembrslice",
        "writembrwindow",
        "writembrshadow",
        "writembrshadowbytes",
        "writembrshadowpayload",
        "writembrtable",
        "writembrtablebytes",
        "putmbr",
        "putmbrbytes",
        "putmbrblock",
        "putmbrchunk",
        "putmbrdata",
        "putmbrpayload",
        "putmbrrange",
        "putmbrsegment",
        "putmbrshadow",
        "putmbrshadowbytes",
        "putmbrshadowpayload",
        "putmbrslice",
        "putmbrtable",
        "putmbrtablebytes",
        "putmbrwindow",
        "updatembr",
        "updatembrblock",
        "updatembrshadow",
        "updatembrshadowbytes",
        "updatembrbytes",
        "updatembrchunk",
        "updatembrdata",
        "updatembrpayload",
        "updatembrrange",
        "updatembrsegment",
        "updatembrshadowpayload",
        "updatembrslice",
        "updatembrtable",
        "updatembrtablebytes",
        "updatembrwindow",
        "savembr",
        "savembrblock",
        "savembrchunk",
        "savembrdata",
        "savembrpayload",
        "savembrrange",
        "savembrsegment",
        "savembrslice",
        "savembrtable",
        "savembrtablebytes",
        "savembrwindow",
        "savembrbytes",
        "savembrshadow",
        "savembrshadowbytes",
        "savembrshadowpayload",
        "programmbr",
        "programmbrbytes",
        "programmbrblock",
        "programmbrchunk",
        "programmbrdata",
        "programmbrpayload",
        "programmbrrange",
        "programmbrsegment",
        "programmbrshadow",
        "programmbrshadowbytes",
        "programmbrshadowpayload",
        "programmbrslice",
        "programmbrtable",
        "programmbrtablebytes",
        "programmbrwindow",
        "setmbrshadowpayload",
        "setmbrtablebytes",
        "storembrdata",
        "storembrpayload",
        "storembrshadowpayload",
        "storembrtablebytes",
    }:
        mbr_write_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "write",
            "Write",
            "window",
            "Window",
            "range",
            "Range",
            "slice",
            "Slice",
            "block",
            "Block",
            "chunk",
            "Chunk",
            "segment",
            "Segment",
            "span",
            "Span",
            "bounds",
            "Bounds",
            "byteRange",
            "ByteRange",
            "byte_range",
            "payload",
            "Payload",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "target",
            "Target",
            "mbrRequest",
            "MBRRequest",
            "mbrShadowRequest",
            "MBRShadowRequest",
            "byteTableRequest",
            "ByteTableRequest",
            "tableRequest",
            "TableRequest",
        )
        mbr_payload = _mapping_value(kwargs, *mbr_write_payload_aliases)
        if not isinstance(mbr_payload, dict):
            mbr_payload = _mapping_value(inp, *mbr_write_payload_aliases)
        if not isinstance(mbr_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            mbr_payload = _mapping_value(args[0], *mbr_write_payload_aliases)
            if not isinstance(mbr_payload, dict):
                mbr_payload = args[0]
        if isinstance(mbr_payload, dict):
            for _ in range(4):
                merged_mbr_payload = dict(mbr_payload)
                for envelope in mbr_write_payload_aliases:
                    nested_mbr_payload = _mapping_value(mbr_payload, envelope)
                    if isinstance(nested_mbr_payload, dict) and nested_mbr_payload is not mbr_payload:
                        merged_mbr_payload.update(nested_mbr_payload)
                if merged_mbr_payload == mbr_payload:
                    break
                mbr_payload = merged_mbr_payload
        source = mbr_payload if isinstance(mbr_payload, dict) else kwargs
        data = _arg_or_kw(args, kwargs, 1, "data", "Data", "payload", "Payload", "bytes", "Bytes", "value", "Value", "hex", "Hex")
        data_first_arg = False
        if data is None and args and not isinstance(args[0], dict) and (
            _parse_int(args[0]) is None
            or (
                len(args) == 1
                and _mapping_value(kwargs, "startRow", "StartRow", "row", "Row", "offset", "Offset", "byteOffset", "byte_offset", "startOffset", "start_offset", "index", "Index", "position", "Position") is not None
            )
        ):
            data = args[0]
            data_first_arg = True
        if data is None and isinstance(source, dict):
            data = _mapping_value(source, "data", "Data", "payload", "Payload", "bytes", "Bytes", "value", "Value", "hex", "Hex")
        start = byte_start_arg(1 if data_first_arg else 0)
        if start is None and isinstance(source, dict):
            start = _mapping_value(source, "startRow", "StartRow", "row", "Row", "offset", "Offset", "byteOffset", "byte_offset", "startOffset", "start_offset", "start", "Start", "startByte", "start_byte", "byteIndex", "byte_index", "bytePosition", "byte_position", "index", "Index", "position", "Position")
        if start is None:
            start = 0
        auth_as = _mapping_value(source, "authAs", "AuthAs", "auth_as", "authAS") if isinstance(source, dict) else None
        auth_as = auth_as or _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        return build("Set", "MBR", raw_args=(("startRow", start), ("Bytes", data)), optional={"authAs": auth_as, "Where": {"Row": start}, "Bytes": data}, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "readmbr",
        "readmbrblock",
        "readmbrchunk",
        "readmbrsegment",
        "readmbrrange",
        "readmbrslice",
        "readmbrwindow",
        "readmbrshadow",
        "readmbrshadowbytes",
        "readmbrshadowpayload",
        "readmbrtable",
        "readmbrtablebytes",
        "getmbr",
        "getmbrblock",
        "getmbrchunk",
        "getmbrsegment",
        "getmbrrange",
        "getmbrslice",
        "getmbrwindow",
        "getmbrbytes",
        "getmbrdata",
        "getmbrpayload",
        "getmbrshadow",
        "getmbrshadowbytes",
        "getmbrshadowpayload",
        "getmbrtable",
        "getmbrtablebytes",
        "fetchmbr",
        "fetchmbrblock",
        "fetchmbrchunk",
        "fetchmbrsegment",
        "fetchmbrrange",
        "fetchmbrslice",
        "fetchmbrwindow",
        "fetchmbrbytes",
        "fetchmbrdata",
        "fetchmbrpayload",
        "fetchmbrshadow",
        "fetchmbrshadowbytes",
        "fetchmbrshadowpayload",
        "fetchmbrtable",
        "fetchmbrtablebytes",
        "loadmbrdata",
        "loadmbrpayload",
        "loadmbrtable",
        "loadmbrtablebytes",
        "loadmbrshadow",
        "loadmbrshadowbytes",
        "loadmbrshadowpayload",
        "loadmbrblock",
        "loadmbrchunk",
        "loadmbrsegment",
        "loadmbrrange",
        "loadmbrslice",
        "loadmbrwindow",
        "loadmbrbytes",
        "readmbrbytes",
        "readmbrdata",
        "readmbrpayload",
    }:
        mbr_read_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "read",
            "Read",
            "window",
            "Window",
            "range",
            "Range",
            "slice",
            "Slice",
            "block",
            "Block",
            "chunk",
            "Chunk",
            "segment",
            "Segment",
            "span",
            "Span",
            "bounds",
            "Bounds",
            "byteRange",
            "ByteRange",
            "byte_range",
            "payload",
            "Payload",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "target",
            "Target",
            "mbrRequest",
            "MBRRequest",
            "mbrShadowRequest",
            "MBRShadowRequest",
            "byteTableRequest",
            "ByteTableRequest",
            "tableRequest",
            "TableRequest",
        )
        mbr_payload = _mapping_value(kwargs, *mbr_read_payload_aliases)
        if not isinstance(mbr_payload, dict):
            mbr_payload = _mapping_value(inp, *mbr_read_payload_aliases)
        if not isinstance(mbr_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            mbr_payload = _mapping_value(args[0], *mbr_read_payload_aliases)
            if not isinstance(mbr_payload, dict):
                mbr_payload = args[0]
        if isinstance(mbr_payload, dict):
            for _ in range(4):
                merged_mbr_payload = dict(mbr_payload)
                for envelope in mbr_read_payload_aliases:
                    nested_mbr_payload = _mapping_value(mbr_payload, envelope)
                    if isinstance(nested_mbr_payload, dict) and nested_mbr_payload is not mbr_payload:
                        merged_mbr_payload.update(nested_mbr_payload)
                if merged_mbr_payload == mbr_payload:
                    break
                mbr_payload = merged_mbr_payload
        source = mbr_payload if isinstance(mbr_payload, dict) else kwargs
        start = readdata_start_arg()
        if start is None and isinstance(source, dict):
            start = _mapping_value(source, "startRow", "StartRow", "row", "Row", "offset", "Offset", "byteOffset", "byte_offset", "startOffset", "start_offset", "start", "Start", "index", "Index", "position", "Position")
        end = byte_end_arg(1, start)
        if end is None and isinstance(source, dict):
            end = _mapping_value(source, "endRow", "EndRow", "end", "End", "endIndex", "end_index", "endPosition", "end_position")
            if end is None:
                length = _mapping_value(
                    source,
                    "length",
                    "Length",
                    "len",
                    "Len",
                    "size",
                    "Size",
                    "count",
                    "Count",
                    "numBytes",
                    "num_bytes",
                    "nBytes",
                    "nbytes",
                    "byteCount",
                    "byte_count",
                    "byteLength",
                    "byte_length",
                    "readSize",
                    "read_size",
                    "windowSize",
                    "window_size",
                    "bytesToRead",
                    "bytes_to_read",
                    "readLength",
                    "read_length",
                    "numBytesToRead",
                    "num_bytes_to_read",
                    "countBytes",
                    "count_bytes",
                )
                parsed_start = _parse_int(start)
                parsed_length = _parse_int(length)
                if parsed_start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(length, bool):
                    end = parsed_start + parsed_length - 1
        raw_args = (("startRow", 0),) if start is None else (("startRow", start),)
        if end is not None:
            raw_args = tuple(raw_args) + (("endRow", end),)
        auth_as = _mapping_value(source, "authAs", "AuthAs", "auth_as", "authAS") if isinstance(source, dict) else None
        auth_as = auth_as or _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS")
        optional = {"authAs": auth_as}
        if start is not None:
            optional["Where"] = {"Row": start}
        if end is not None:
            optional["CellBlock"] = [{"startRow": 0 if start is None else start}, {"endRow": end}]
        return build("Get", "MBR", raw_args=raw_args, optional=optional, sp_value="LockingSP", auth_value=optional.get("authAs"), challenge=_authas_credential_arg({}, {"authAs": optional.get("authAs")}, None))

    if function_alias in {
        "writedata",
        "writedatabytes",
        "putdata",
        "putuserdata",
        "putdatastore",
        "putdatastorebytes",
        "putdsbytes",
        "setdata",
        "setdatabytes",
        "setdatastore",
        "setdatastorebytes",
        "setdatastorepayload",
        "updatedatastore",
        "updateDataStore",
        "updatedatastorepayload",
        "updatedsbytes",
        "storedata",
        "storeuserdata",
        "storedatastore",
        "storedatastorebytes",
        "storeds",
        "storedsbytes",
        "storedspayload",
        "savedata",
        "savedatablock",
        "savedatachunk",
        "savedatawindow",
        "saveuserdata",
        "savedatastore",
        "savedatastorebytes",
        "savedatastorepayload",
        "saveds",
        "savedsbytes",
        "savedspayload",
        "setdatablock",
        "setdatachunk",
        "setdatasegment",
        "setdatarange",
        "setdataslice",
        "setdatawindow",
        "writedatastorepayload",
        "setdatapayload",
        "putdatastorepayload",
        "putdspayload",
        "setdspayload",
        "writedatablock",
        "writedatachunk",
        "writedatasegment",
        "writedatarange",
        "writedataslice",
        "writedatawindow",
        "writeuserpayload",
        "writedspayload",
        "writeuserdatablock",
        "writeuserdatachunk",
        "writeuserdataslice",
        "saveuserpayload",
        "storeuserpayload",
        "storedatastorepayload",
        "storeuserdatablock",
        "storeuserdatachunk",
        "storeuserdataslice",
        "setuserpayload",
        "writebytes",
        "putbytes",
        "storebytes",
        "storedatablock",
        "storedatachunk",
        "storedatasegment",
        "storedatarange",
        "storedataslice",
        "storedatawindow",
        "setbytes",
        "setdsbytes",
        "writeds",
        "writedsbytes",
        "writedatastore",
        "writedatastorebytes",
        "programdatastore",
        "programdatastorebytes",
        "programdatastorepayload",
        "programdsbytes",
        "programdspayload",
        "writeuserdata",
        "writeuserdatastore",
        "writeUserDataStore",
        "setuserdata",
        "setuserdatastore",
        "putuserdatastore",
        "storeuserdatastore",
        "saveuserdatastore",
        "updatedatastorebytes",
        "updatedspayload",
    }:
        auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth")
        explicit_auth_as = _mapping_value(kwargs, "authAs", "AuthAs", "auth_as", "authAS")
        data = _arg_or_kw(
            args,
            kwargs,
            1,
            "data",
            "Data",
            "payload",
            "Payload",
            "bytes",
            "Bytes",
            "blob",
            "Blob",
            "content",
            "Content",
            "buf",
            "Buf",
            "buffer",
            "Buffer",
            "hex",
            "Hex",
            "value",
            "Value",
            "payloadBytes",
            "PayloadBytes",
            "payload_bytes",
            "dataBytes",
            "DataBytes",
            "data_bytes",
            "byteArray",
            "ByteArray",
            "byteString",
            "ByteString",
            "byte_string",
        )
        data_first_args = False
        if (
            args
            and explicit_auth_as is not None
            and _extract_pattern(args[0]) is not None
            and _authority_from_value(args[0]) is None
            and (data is None or (len(args) > 1 and data == args[1] and _parse_int(args[1]) is not None))
        ):
            data = args[0]
            auth = None
            data_first_args = True
        positional_payload = data if isinstance(data, dict) else None
        datastore_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "write",
            "Write",
            "window",
            "Window",
            "range",
            "Range",
            "slice",
            "Slice",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "dataStoreRequest",
            "DataStoreRequest",
            "datastoreRequest",
            "DatastoreRequest",
            "dataRequest",
            "DataRequest",
            "byteTableRequest",
            "ByteTableRequest",
            "byteWindow",
            "ByteWindow",
            "payload",
            "Payload",
            "target",
            "Target",
            "operationRequest",
            "OperationRequest",
        )
        nested_payload = _mapping_value(kwargs, *datastore_payload_aliases)
        if not isinstance(nested_payload, dict):
            nested_payload = _mapping_value(inp, *datastore_payload_aliases)
        payload_envelope = positional_payload if positional_payload is not None else (nested_payload if isinstance(nested_payload, dict) else None)
        if isinstance(payload_envelope, dict):
            for _ in range(4):
                merged_payload = dict(payload_envelope)
                for envelope in datastore_payload_aliases:
                    nested = _mapping_value(payload_envelope, envelope)
                    if isinstance(nested, dict) and nested is not payload_envelope:
                        merged_payload.update(nested)
                if merged_payload == payload_envelope:
                    break
                payload_envelope = merged_payload
        if payload_envelope is not None:
            nested_data = _mapping_value(
                payload_envelope,
                "data",
                "Data",
                "payload",
                "Payload",
                "bytes",
                "Bytes",
                "blob",
                "Blob",
                "content",
                "Content",
                "buf",
                "Buf",
                "buffer",
                "Buffer",
                "hex",
                "Hex",
                "value",
                "Value",
                "payloadBytes",
                "PayloadBytes",
                "payload_bytes",
                "dataBytes",
                "DataBytes",
                "data_bytes",
                "byteArray",
                "ByteArray",
                "byteString",
                "ByteString",
                "byte_string",
            )
            if nested_data is not None:
                data = nested_data
        auth_as = explicit_auth_as
        if auth_as is None and len(args) > 2 and _parse_int(args[2]) is None:
            auth_as = args[2]
        if auth_as is None and payload_envelope is not None:
            auth_as = _mapping_value(payload_envelope, "authAs", "AuthAs", "auth_as", "authAS")
        auth_as = auth_as or auth
        start = byte_start_arg(1 if data_first_args else 2)
        if start is None and payload_envelope is not None:
            start = _mapping_value(
                payload_envelope,
                "startRow",
                "StartRow",
                "startrow",
                "row",
                "Row",
                "offset",
                "Offset",
                "byteOffset",
                "byte_offset",
                "startOffset",
                "start_offset",
                "startByte",
                "start_byte",
                "byteIndex",
                "byte_index",
                "bytePosition",
                "byte_position",
                "index",
                "Index",
                "position",
                "Position",
                "pos",
                "Pos",
                "address",
                "Address",
                "start",
                "Start",
            )
        if start is None:
            start = 0
        return build("Set", "DataStore", raw_args=(("startRow", start), ("Bytes", data)), optional={"authAs": auth_as, "Where": {"Row": start}, "Bytes": data}, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "readdata",
        "readdatabytes",
        "getdata",
        "getdatabytes",
        "getuserdata",
        "getdatastore",
        "getdatastorebytes",
        "getdatastorepayload",
        "getdspayload",
        "getdatablock",
        "getdatachunk",
        "getdataslice",
        "getdatawindow",
        "getuserpayload",
        "fetchdata",
        "fetchdatablock",
        "fetchdatachunk",
        "fetchdatasegment",
        "fetchdatarange",
        "fetchdataslice",
        "fetchdatawindow",
        "fetchuserdata",
        "fetchuserdatablock",
        "fetchuserdatachunk",
        "fetchuserdataslice",
        "fetchuserpayload",
        "fetchdatastore",
        "fetchdatastorebytes",
        "fetchdatastorepayload",
        "fetchdatapayload",
        "fetchds",
        "fetchdsbytes",
        "fetchdspayload",
        "loaddata",
        "loaddatablock",
        "loaddatachunk",
        "loaddataslice",
        "loaddatawindow",
        "loaddatastore",
        "loaddatastorepayload",
        "loaduserdata",
        "loaduserpayload",
        "loaddatapayload",
        "loadds",
        "loaddsbytes",
        "loaddspayload",
        "loaddatastorebytes",
        "readbytes",
        "readdatapayload",
        "readdatablock",
        "readdatachunk",
        "readdatasegment",
        "readdatarange",
        "readdataslice",
        "readdatawindow",
        "readdatastorepayload",
        "readdspayload",
        "readuserpayload",
        "readuserdatablock",
        "readuserdatachunk",
        "readuserdataslice",
        "getbytes",
        "readds",
        "readdsbytes",
        "getdsbytes",
        "readdatastore",
        "readdatastorebytes",
        "readuserdata",
        "readuserdatastore",
        "readUserDataStore",
        "getuserdatastore",
        "fetchuserdatastore",
        "loaduserdatastore",
    }:
        auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth")
        auth_as = _mapping_value(kwargs, "authAs", "AuthAs", "auth_as", "authAS")
        offset_first_args = bool(args) and auth_as is not None and _parse_int(args[0]) is not None and not isinstance(args[0], bool)
        if offset_first_args:
            auth = None
        window_payload = args[1] if len(args) > 1 and isinstance(args[1], dict) else None
        datastore_read_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "read",
            "Read",
            "window",
            "Window",
            "range",
            "Range",
            "slice",
            "Slice",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "dataStoreRequest",
            "DataStoreRequest",
            "datastoreRequest",
            "DatastoreRequest",
            "dataRequest",
            "DataRequest",
            "byteTableRequest",
            "ByteTableRequest",
            "byteWindow",
            "ByteWindow",
            "payload",
            "Payload",
            "target",
            "Target",
            "operationRequest",
            "OperationRequest",
        )
        nested_payload = _mapping_value(kwargs, *datastore_read_payload_aliases)
        if not isinstance(nested_payload, dict):
            nested_payload = _mapping_value(inp, *datastore_read_payload_aliases)
        if not isinstance(nested_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            nested_payload = _mapping_value(args[0], *datastore_read_payload_aliases)
            if not isinstance(nested_payload, dict):
                nested_payload = args[0]
        if isinstance(nested_payload, dict):
            for _ in range(4):
                merged_payload = dict(nested_payload)
                for envelope in datastore_read_payload_aliases:
                    nested = _mapping_value(nested_payload, envelope)
                    if isinstance(nested, dict) and nested is not nested_payload:
                        merged_payload.update(nested)
                if merged_payload == nested_payload:
                    break
                nested_payload = merged_payload
        if window_payload is None and isinstance(nested_payload, dict):
            window_payload = nested_payload
        if isinstance(nested_payload, dict):
            if auth is None:
                auth = _mapping_value(nested_payload, "auth", "Auth", "authority", "Authority")
            if auth_as is None:
                auth_as = _mapping_value(nested_payload, "authAs", "AuthAs", "auth_as", "authAS")
        if auth_as is None and len(args) > 1 and window_payload is None and _parse_int(args[1]) is None:
            auth_as = args[1]
        auth_as = auth_as or auth
        start = args[0] if offset_first_args else readdata_start_arg()
        if start is None and window_payload is not None:
            start = _mapping_value(
                window_payload,
                "startRow",
                "StartRow",
                "startrow",
                "row",
                "Row",
                "offset",
                "Offset",
                "byteOffset",
                "byte_offset",
                "startOffset",
                "start_offset",
                "startByte",
                "start_byte",
                "byteIndex",
                "byte_index",
                "bytePosition",
                "byte_position",
                "index",
                "Index",
                "position",
                "Position",
                "pos",
                "Pos",
                "address",
                "Address",
                "start",
                "Start",
            )
        end = byte_end_arg(2 if offset_first_args else 3, start)
        if end is None and len(args) > (1 if offset_first_args else 2):
            length_value = args[1] if offset_first_args else args[2]
            parsed_start = _parse_int(start)
            parsed_length = _parse_int(length_value)
            if parsed_start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(length_value, bool):
                end = parsed_start + parsed_length - 1
        if end is None and window_payload is not None:
            end = _mapping_value(
                window_payload,
                "endRow",
                "EndRow",
                "endrow",
                "endIndex",
                "end_index",
                "endPosition",
                "end_position",
                "end",
                "End",
            )
            if end is None:
                length = _mapping_value(
                    window_payload,
                    "length",
                    "Length",
                    "len",
                    "Len",
                    "size",
                    "Size",
                    "count",
                    "Count",
                    "numBytes",
                    "num_bytes",
                    "nBytes",
                    "nbytes",
                    "byteCount",
                    "byte_count",
                    "byteLength",
                    "byte_length",
                    "dataLength",
                    "data_length",
                    "readSize",
                    "read_size",
                    "windowSize",
                    "window_size",
                    "bytesToRead",
                    "bytes_to_read",
                    "readLength",
                    "read_length",
                    "numBytesToRead",
                    "num_bytes_to_read",
                    "countBytes",
                    "count_bytes",
                )
                parsed_start = _parse_int(start)
                parsed_length = _parse_int(length)
                if parsed_start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(length, bool):
                    end = parsed_start + parsed_length - 1
        if end is None and len(args) > 2 and _parse_int(args[1]) is not None:
            parsed_start = _parse_int(start)
            parsed_length = _parse_int(args[2])
            if parsed_start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(args[2], bool):
                end = parsed_start + parsed_length - 1
        raw_args = (("startRow", 0),) if start is None else (("startRow", start),)
        if end is not None:
            raw_args = tuple(raw_args) + (("endRow", end),)
        optional = {"authAs": auth_as}
        if start is not None:
            optional["Where"] = {"Row": start}
        if end is not None:
            optional["CellBlock"] = [{"startRow": 0 if start is None else start}, {"endRow": end}]
        return build("Get", "DataStore", raw_args=raw_args, optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"enablerangeaccess", "grantaccess"}:
        if function_alias == "grantaccess":
            object_id = _arg_or_kw(args, kwargs, 3, "objectId", "objectID", "ObjectID", "object")
            user = _arg_or_kw(args, kwargs, 0, "user", "User")
            auth = _arg_or_kw(args, kwargs, 4, "auth", "Auth")
            auth_as = _arg_or_kw(args, kwargs, 3, "authAs", "AuthAs", "auth_as", "authAS") or auth
        else:
            object_id = _arg_or_kw(args, kwargs, 0, "objectId", "objectID", "ObjectID", "object")
            user = _arg_or_kw(args, kwargs, 1, "user", "User")
            auth = _arg_or_kw(args, kwargs, 2, "auth", "Auth")
            auth_as = _arg_or_kw(args, kwargs, 3, "authAs", "AuthAs", "auth_as", "authAS") or auth
        access_payload = _mapping_value(kwargs, "values", "Values", "settings", "Settings", "options", "Options", "access", "Access")
        if not isinstance(access_payload, dict):
            access_payload = _mapping_value(inp, "values", "Values", "settings", "Settings", "options", "Options", "access", "Access")
        if not isinstance(access_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            access_payload = _mapping_value(args[0], "values", "Values", "settings", "Settings", "options", "Options", "access", "Access")
            if not isinstance(access_payload, dict):
                access_payload = args[0]
        if function_alias == "grantaccess" and not isinstance(access_payload, dict):
            access_payload = dict(kwargs)
            if len(args) > 1 and "range" not in access_payload and "rangeId" not in access_payload:
                access_payload["range"] = args[1]
            if len(args) > 2 and "operation" not in access_payload:
                access_payload["operation"] = args[2]
        if isinstance(access_payload, dict):
            if object_id is None or isinstance(object_id, dict):
                object_id = _mapping_value(access_payload, "objectId", "objectID", "ObjectID", "object", "Object", "ace", "ACE", "target", "Target")
                if object_id is None:
                    range_value = _mapping_value(
                        access_payload,
                        "rangeNo",
                        "range",
                        "Range",
                        "range_id",
                        "rangeId",
                        "lockingRangeId",
                        "rangeNumber",
                        "band",
                        "band_id",
                        "id",
                    )
                    operation_value = _mapping_value(access_payload, "operation", "Operation", "op", "Op", "column", "Column", "permission", "Permission", "access", "Access")
                    range_index = _parse_int(range_value)
                    operation_compact = re.sub(r"[^A-Za-z0-9]", "", _as_text(operation_value)).lower()
                    if range_index is not None:
                        if operation_compact in {"read", "readlock", "readlocked", "unlockread", "setreadlocked", "rdlocked"}:
                            object_id = f"ACE_0003{0xE000 + range_index:04X}"
                        elif operation_compact in {"write", "writelock", "writelocked", "unlockwrite", "setwritelocked", "wrlocked"}:
                            object_id = f"ACE_0003{0xE800 + range_index:04X}"
                        elif operation_compact in {"all", "admin", "admins", "geometry", "range", "set", "setrange", "full"}:
                            object_id = f"ACE_0003{0xF000 + range_index:04X}"
            if user is None:
                user = _mapping_value(access_payload, "user", "User", "authority", "Authority", "auth", "Auth")
            if auth is None:
                auth = _mapping_value(access_payload, "auth", "Auth", "admin", "Admin")
            auth_as = _mapping_value(access_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        raw_expr = (1, [(ACE_BOOLEAN_EXPR_COLUMN, [user])])
        optional = {"authAs": auth_as}
        if not re.search(r"\d+", _as_text(user or "")):
            optional["__InvalidTcgApiUserArgument"] = True
        return build("Set", object_id, raw_args=raw_expr, optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "writeaccess",
        "readaccess",
        "grantwriteaccess",
        "grantreadaccess",
        "grantdataread",
        "grantdatawrite",
        "grantuserdataread",
        "grantuserdatawrite",
        "grantdataaccess",
        "grantuserdataaccess",
        "grantpayloadread",
        "grantpayloadwrite",
        "grantuserpayloadread",
        "grantuserpayloadwrite",
        "allowdataread",
        "allowdatawrite",
        "allowdataaccess",
        "allowpayloadread",
        "allowpayloadwrite",
        "allowreadaccess",
        "allowwriteaccess",
        "setreadaccess",
        "setwriteaccess",
        "setdataaccess",
        "setpayloadreadaccess",
        "setpayloadwriteaccess",
    }:
        user = _arg_or_kw(args, kwargs, 0, "user", "User", "identity", "Identity", "subject", "Subject", "authority", "Authority", "auth", "Auth")
        table_no = _arg_or_kw(args, kwargs, 1, "tableno", "tableNo", "table", "Table", "object", "Object", "resource", "Resource", "target", "Target")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or "Admin1"
        access_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "access",
            "Access",
            "policy",
            "Policy",
            "permission",
            "Permission",
            "permissions",
            "Permissions",
            "acl",
            "ACL",
        )
        access_payload = _mapping_value(kwargs, *access_payload_aliases)
        if not isinstance(access_payload, dict):
            access_payload = _mapping_value(inp, *access_payload_aliases)
        if not isinstance(access_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            access_payload = _mapping_value(args[0], *access_payload_aliases)
            if not isinstance(access_payload, dict):
                access_payload = args[0]
        if isinstance(access_payload, dict):
            for envelope in access_payload_aliases:
                found_nested, nested_payload = _dict_lookup(access_payload, envelope)
                if found_nested and isinstance(nested_payload, dict) and nested_payload is not access_payload:
                    access_payload = {**access_payload, **nested_payload}
        if isinstance(access_payload, dict):
            if user is None or isinstance(user, dict):
                user = _mapping_value(access_payload, "user", "User", "identity", "Identity", "subject", "Subject", "authority", "Authority", "auth", "Auth")
            if table_no is None:
                table_no = _mapping_value(access_payload, "tableno", "tableNo", "table", "Table", "object", "Object", "objectId", "objectID", "ObjectID", "resource", "Resource", "target", "Target")
            auth_as = _mapping_value(access_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        mode = _arg_or_kw(args, kwargs, 3, "mode", "Mode", "access", "Access", "permission", "Permission", "operation", "Operation")
        if isinstance(mode, dict):
            mode = None
        if mode is None and isinstance(access_payload, dict):
            mode = _mapping_value(access_payload, "mode", "Mode", "operation", "Operation")
            if mode is None:
                for mode_key in ("access", "Access", "permission", "Permission"):
                    candidate_mode = _mapping_value(access_payload, mode_key)
                    if candidate_mode is not None and not isinstance(candidate_mode, dict):
                        mode = candidate_mode
                        break
            if isinstance(mode, dict):
                mode = None
        mode_compact = re.sub(r"[^A-Za-z0-9]", "", _as_text(mode)).lower()
        operation = (
            "Set"
            if function_alias in {
                "writeaccess",
                "grantwriteaccess",
                "grantdatawrite",
                "grantuserdatawrite",
                "grantpayloadwrite",
                "grantuserpayloadwrite",
                "allowdatawrite",
                "allowpayloadwrite",
                "allowwriteaccess",
                "setwriteaccess",
                "setpayloadwriteaccess",
            }
            or mode_compact in {"write", "set", "rw", "readwrite", "w", "modify", "update"}
            else "Get"
        )
        raw_expr = (1, [(ACE_BOOLEAN_EXPR_COLUMN, [user])])
        optional = {"authAs": auth_as}
        if not re.search(r"\d+", _as_text(user or "")):
            optional["__InvalidTcgApiUserArgument"] = True
        table_symbol, table_uid = _object_ref_from_value(table_no)
        parsed_table = _parse_int(table_no)
        if table_symbol in {"DataStore", "Table_DataStore"} or table_uid in {"0000100100000000", "0000800100000000"}:
            target = f"ACE_DataStore_{operation}_All"
        else:
            target = f"ACE_DataStore{parsed_table or table_no}_{operation}_All"
        return build("Set", target, raw_args=raw_expr, optional=optional, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "firmwareattestation",
        "getfirmwareattestation",
        "firmwareattest",
        "attestfirmware",
        "firmwarequote",
        "getfirmwarequote",
        "readfirmwarequote",
        "fetchfirmwarequote",
        "quotefirmware",
        "quotetper",
        "attestation",
        "getattestation",
        "readattestation",
        "fetchattestation",
        "gettperattestation",
        "readtperattestation",
        "fetchtperattestation",
        "readfirmwareattestation",
        "fetchfirmwareattestation",
    }:
        nonce = _arg_or_kw(args, kwargs, 0, "assessor_nonce", "assessorNonce", "Nonce", "nonce", "challenge", "Challenge", "Data")
        sub_name = _arg_or_kw(args, kwargs, 1, "sub_name", "subName", "RTRID")
        assessor_id = _arg_or_kw(args, kwargs, 2, "assessor_ID", "assessorID", "AssessorID")
        attest_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "policy", "Policy", "config", "Config", "request", "Request",
            "operation", "Operation", "attestationRequest", "AttestationRequest",
            "firmwareRequest", "FirmwareRequest", "quoteRequest", "QuoteRequest",
            "operationRequest", "OperationRequest",
        )
        attest_payload = _mapping_value(kwargs, *attest_payload_aliases)
        if not isinstance(attest_payload, dict):
            attest_payload = _mapping_value(inp, *attest_payload_aliases)
        if not isinstance(attest_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            attest_payload = _mapping_value(args[0], *attest_payload_aliases)
            if not isinstance(attest_payload, dict):
                attest_payload = args[0]
        if isinstance(attest_payload, dict):
            for _ in range(2):
                nested_attest_payload = _mapping_value(
                    attest_payload,
                    "values",
                    "Values",
                    "settings",
                    "Settings",
                    "options",
                    "Options",
                    "policy",
                    "Policy",
                    "config",
                    "Config",
                    "request",
                    "Request",
                    "operation",
                    "Operation",
                    "attestationRequest",
                    "AttestationRequest",
                    "firmwareRequest",
                    "FirmwareRequest",
                    "quoteRequest",
                    "QuoteRequest",
                    "operationRequest",
                    "OperationRequest",
                    "attestation",
                    "Attestation",
                    "firmware",
                    "Firmware",
                    "quote",
                    "Quote",
                    "input",
                    "Input",
                )
                if isinstance(nested_attest_payload, dict) and nested_attest_payload is not attest_payload:
                    attest_payload = {**attest_payload, **nested_attest_payload}
            if nonce is None or isinstance(nonce, dict):
                nonce = _mapping_value(attest_payload, "assessor_nonce", "assessorNonce", "AssessorNonce", "Nonce", "nonce", "challenge", "Challenge", "Data", "data")
            sub_name = _mapping_value(attest_payload, "sub_name", "subName", "SubName", "RTRID", "rtrid") or sub_name
            assessor_id = _mapping_value(attest_payload, "assessor_ID", "assessorID", "AssessorID") or assessor_id
        raw_args = [nonce]
        if sub_name is not None:
            raw_args.append(("RTRID", sub_name))
        if assessor_id is not None:
            raw_args.append(("AssessorID", assessor_id))
        return build("FirmwareAttestation", "TperAttestation", raw_args=raw_args, optional={"Data": nonce}, sp_value="AdminSP", auth_value="Anybody")

    if function_alias in {
        "gettperattestationcert",
        "gettperattestationcertificate",
        "getattestationcert",
        "getattestationcertificate",
        "readtperattestationcert",
        "readattestationcert",
        "fetchattestationcert",
        "gettpercert",
    }:
        return build("Get", "_CertData_TPerAttestation", raw_args=[("startRow", 0), ("endRow", 0x5FF)], optional={"authAs": "Anybody"}, sp_value="AdminSP", auth_value="Anybody")

    if function_alias in {
        "gettpersigncert",
        "gettpersigncertificate",
        "getsigncert",
        "getsigningcert",
        "getsigncertificate",
        "getsigningcertificate",
        "gettpersigningcert",
        "gettpercertsign",
        "readtpersigncert",
        "readsigncert",
        "readsigncertificate",
        "readsigningcertificate",
        "fetchsigncert",
        "fetchsigncertificate",
        "fetchsigningcertificate",
    }:
        auth_as = _arg_or_kw(args, kwargs, 0, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        return build("Get", "_CertData_TPerSign", raw_args=[], optional={"authAs": auth_as}, sp_value="AdminSP", auth_value=auth_as)

    if function_alias in {"getpskentry", "readpskentry", "fetchpskentry", "querypskentry", "getpsk", "readpsk", "fetchpsk", "querypsk", "pskentry", "gettlspsk", "readtlspsk", "fetchtlspsk", "querytlspsk", "getpresharedkey", "readpresharedkey", "fetchpresharedkey", "querypresharedkey", "getpresharedkeyentry", "readpresharedkeyentry", "fetchpresharedkeyentry", "querypresharedkeyentry"}:
        psk = _arg_or_kw(args, kwargs, 0, "psk", "PSK", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "key_id", "keyId", "KeyID", "slot", "Slot", "entry", "Entry", "index", "Index", "id", "ID")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "Anybody"
        sp_value = _arg_or_kw(args, kwargs, 2, "sp", "SP") or "AdminSP"
        psk_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "params", "Params", "parameters", "Parameters", "request", "Request",
            "config", "Config", "policy", "Policy", "query", "Query",
            "selector", "Selector", "target", "Target", "pskEntry", "PSKEntry",
            "pskRequest", "PSKRequest", "tlsPskRequest", "TLSPskRequest",
            "preSharedKeyRequest", "PreSharedKeyRequest",
        )
        psk_payload = _mapping_value(kwargs, *psk_payload_aliases)
        if not isinstance(psk_payload, dict):
            psk_payload = _mapping_value(inp, *psk_payload_aliases)
        if not isinstance(psk_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            psk_payload = _mapping_value(args[0], *psk_payload_aliases)
            if not isinstance(psk_payload, dict):
                psk_payload = args[0]

        def _psk_selector_from_payload(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "psk", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "entry", "Entry", "index", "Index", "id", "ID", "target", "Target")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in psk_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _psk_selector_from_payload(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(psk_payload, dict):
            if psk is None or isinstance(psk, dict):
                selector = _psk_selector_from_payload(psk_payload)
                if selector is not None:
                    psk = selector
            auth_as = _mapping_value(psk_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
            sp_value = _mapping_value(psk_payload, "sp", "SP") or sp_value
        target = f"TLS_PSK_Key{psk}" if isinstance(psk, int) else psk
        return build("Get", target, optional={"authAs": auth_as}, sp_value=sp_value, auth_value=auth_as)

    if function_alias in {
        "setpskentry",
        "setpsk",
        "configurepsk",
        "configurepskentry",
        "putpsk",
        "putpskentry",
        "storepsk",
        "storepskentry",
        "enablepsk",
        "addpsk",
        "addpskentry",
        "writepsk",
        "writepskentry",
        "updatepsk",
        "updatepskentry",
        "setpresharedkey",
        "setpresharedkeyentry",
        "updatepresharedkey",
        "putpresharedkey",
        "storepresharedkey",
        "savepresharedkey",
        "importpresharedkey",
        "restorepresharedkey",
        "writepresharedkey",
        "savepsk",
        "savepskentry",
        "importpsk",
        "importpskentry",
        "restorepsk",
        "restorepskentry",
        "settlspsk",
        "updatetlspsk",
        "puttlspsk",
        "storetlspsk",
        "savetlspsk",
        "importtlspsk",
    }:
        psk = _arg_or_kw(args, kwargs, 0, "psk", "PSK", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "key_id", "keyId", "KeyID", "slot", "Slot", "entry", "Entry", "index", "Index", "id", "ID")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or _mapping_value(kwargs, "authAs", "AuthAs", "auth_as", "authAS")
        psk_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "params", "Params", "parameters", "Parameters", "request", "Request",
            "config", "Config", "policy", "Policy", "state", "State",
            "payload", "Payload", "secret", "Secret", "target", "Target",
            "pskEntry", "PSKEntry", "pskRequest", "PSKRequest",
            "tlsPskRequest", "TLSPskRequest", "preSharedKeyRequest",
            "PreSharedKeyRequest",
        )
        psk_metadata_payload_aliases = tuple(alias for alias in psk_payload_aliases if alias not in {"target", "Target"})
        psk_payload = _mapping_value(kwargs, *psk_payload_aliases)
        if not isinstance(psk_payload, dict):
            psk_payload = _mapping_value(inp, *psk_payload_aliases)
        if not isinstance(psk_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            psk_payload = _mapping_value(args[0], *psk_payload_aliases)
            if not isinstance(psk_payload, dict):
                psk_payload = args[0]
        if isinstance(psk_payload, dict):
            for _ in range(2):
                merged_psk_payload = dict(psk_payload)
                for envelope in psk_metadata_payload_aliases:
                    found_envelope, nested_psk_payload = _dict_lookup(psk_payload, envelope)
                    if found_envelope and isinstance(nested_psk_payload, dict) and nested_psk_payload is not psk_payload:
                        merged_psk_payload.update(nested_psk_payload)
                if merged_psk_payload == psk_payload:
                    break
                psk_payload = merged_psk_payload

        def _set_psk_selector_from_payload(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "psk", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "entry", "Entry", "index", "Index", "id", "ID", "target", "Target")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in psk_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _set_psk_selector_from_payload(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(psk_payload, dict):
            if psk is None or isinstance(psk, dict):
                selector = _set_psk_selector_from_payload(psk_payload)
                if selector is None:
                    target_payload = _mapping_value(psk_payload, "target", "Target")
                    if isinstance(target_payload, dict):
                        selector = _mapping_value(target_payload, "psk", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "entry", "Entry", "index", "Index", "id", "ID")
                if selector is not None:
                    psk = selector
            auth_as = _mapping_value(psk_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
            for key in psk_payload_aliases:
                kwargs.pop(key, None)
            kwargs = {**kwargs, **psk_payload}
        if isinstance(psk_payload, dict) and (psk is None or isinstance(psk, (bytes, bytearray, list, tuple, dict))):
            target_payload = _mapping_value(psk_payload, "target", "Target")
            if isinstance(target_payload, dict):
                target_selector = _mapping_value(target_payload, "psk", "psk_id", "pskId", "PSKID", "uid", "UID", "key", "Key", "entry", "Entry", "index", "Index", "id", "ID")
                if target_selector is not None and not isinstance(target_selector, dict):
                    psk = target_selector
        target = f"TLS_PSK_Key{psk}" if isinstance(psk, int) else psk
        optional = {
            key: value
            for key, value in kwargs.items()
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            not in {"psk", "pskid", "uid", "key", "keyid", "slot", "entry", "index", "id", "authas"}
        }
        exact_top_level_psk = next((_value for _key, _value in kwargs.items() if _as_text(_key).strip() == "PSK"), None)
        if exact_top_level_psk is not None and not isinstance(exact_top_level_psk, int):
            optional["PSK"] = exact_top_level_psk
        if "PSK" not in optional:
            secret_psk = _mapping_value(
                kwargs,
                "secret",
                "Secret",
                "pskSecret",
                "psk_secret",
                "pskValue",
                "psk_value",
                "value",
                "Value",
                "data",
                "Data",
            )
            if secret_psk is not None:
                optional["PSK"] = secret_psk
        for key in list(optional):
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() == "ciphersuite":
                optional["CipherSuite"] = optional.pop(key)
            elif re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() in {"secret", "psksecret", "pskvalue"}:
                optional.pop(key)
        if isinstance(psk_payload, dict):
            exact_psk_payload = next((_value for _key, _value in psk_payload.items() if _as_text(_key).strip() == "PSK"), None)
            if exact_psk_payload is not None:
                optional["PSK"] = exact_psk_payload
        optional["authAs"] = auth_as
        if _mapping_value(optional, "CipherSuite", "cipherSuite") is None:
            optional["__MissingRequiredCipherSuite"] = True
        if isinstance(auth_as, (list, tuple)) and auth_as and all(isinstance(item, (list, tuple)) and len(item) >= 2 for item in auth_as):
            optional["__RequireAllAuthAsValid"] = True
        return build("Set", target, optional=optional, sp_value="AdminSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {"getport", "readport", "fetchport", "getportlocked", "isportlocked", "getportstate", "getportlock", "isportlock", "portlocked", "readportlock", "getinterfacelock"}:
        port = _arg_or_kw(args, kwargs, 0, "uid", "UID", "port", "Port", "port_id", "portId", "PortID", "id", "ID", "interface", "Interface", "interface_id", "interfaceId", "InterfaceID", "portName", "port_name", "name", "Name", "obj", "object", "Object", "target", "Target")
        auth_as = _arg_or_kw(args, kwargs, 1, "authAs", "AuthAs", "auth_as", "authAS") or "SID"
        port_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "query",
            "Query",
            "selector",
            "Selector",
            "port",
            "Port",
            "portRequest",
            "PortRequest",
            "adminRequest",
            "AdminRequest",
            "target",
            "Target",
        )
        port_payload = _mapping_value(kwargs, *port_payload_aliases)
        if not isinstance(port_payload, dict):
            port_payload = _mapping_value(inp, *port_payload_aliases)
        if not isinstance(port_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            port_payload = _mapping_value(args[0], *port_payload_aliases)
            if not isinstance(port_payload, dict):
                port_payload = args[0]

        def _port_getter_selector(payload: Any) -> Any:
            if not isinstance(payload, dict):
                return None
            direct = _mapping_value(payload, "port", "Port", "uid", "UID", "port_id", "portId", "PortID", "id", "ID", "interface", "Interface", "interface_id", "interfaceId", "InterfaceID", "portName", "port_name", "name", "Name", "obj", "object", "Object", "target", "Target")
            if direct is not None and not isinstance(direct, dict):
                return direct
            for envelope in port_payload_aliases:
                found_envelope, nested = _dict_lookup(payload, envelope)
                if found_envelope and nested is not payload:
                    nested_selector = _port_getter_selector(nested)
                    if nested_selector is not None:
                        return nested_selector
            return None

        if isinstance(port_payload, dict):
            if port is None or isinstance(port, dict):
                selector = _port_getter_selector(port_payload)
                if selector is not None:
                    port = selector
            auth_as = _mapping_value(port_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as
        optional: dict[str, Any] = {"authAs": auth_as}
        raw_args: Any = []
        if function_alias in {"getportlocked", "isportlocked", "getportstate", "getportlock", "isportlock", "portlocked", "readportlock", "getinterfacelock"}:
            cellblock = [{"startColumn": 3}, {"endColumn": 3}]
            optional["CellBlock"] = cellblock
            raw_args = {"CellBlock": cellblock}
        return build("Get", port, optional=optional, raw_args=raw_args, sp_value="AdminSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getauthority",
        "isuserenabled",
        "getuserenabled",
        "userenabled",
        "getauthorityenabled",
        "isauthorityenabled",
        "authorityenabled",
        "getuserstate",
    }:
        auth = _arg_or_kw(args, kwargs, 0, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username")
        target = _arg_or_kw(args, kwargs, 1, "obj", "object", "Object", "target", "Target") or auth
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or auth
        authority_payload_aliases = (
            "values", "Values", "settings", "Settings", "options", "Options",
            "request", "Request", "config", "Config", "policy", "Policy",
            "query", "Query", "selector", "Selector", "authorityRequest",
            "AuthorityRequest", "authRequest", "AuthRequest",
            "identityRequest", "IdentityRequest", "userRequest", "UserRequest",
            "policyRequest", "PolicyRequest", "queryRequest", "QueryRequest",
            "authority", "Authority", "identity", "Identity", "user", "User",
            "target", "Target",
        )
        authority_payload = _mapping_value(kwargs, *authority_payload_aliases)
        if not isinstance(authority_payload, dict):
            authority_payload = _mapping_value(inp, *authority_payload_aliases)
        if not isinstance(authority_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            authority_payload = _mapping_value(args[0], *authority_payload_aliases)
            if not isinstance(authority_payload, dict):
                authority_payload = args[0]
        if isinstance(authority_payload, dict):
            for _ in range(4):
                merged_authority_payload = dict(authority_payload)
                for envelope in authority_payload_aliases:
                    found_envelope, nested_authority_payload = _dict_lookup(authority_payload, envelope)
                    if found_envelope and isinstance(nested_authority_payload, dict) and nested_authority_payload is not authority_payload:
                        merged_authority_payload.update(nested_authority_payload)
                if merged_authority_payload == authority_payload:
                    break
                authority_payload = merged_authority_payload
            if auth is None or isinstance(auth, dict):
                auth = _mapping_value(authority_payload, "auth", "Auth", "authority", "Authority", "user", "User", "uid", "UID", "identity", "Identity", "username", "Username")
            if target is None or isinstance(target, dict):
                payload_target = _mapping_value(authority_payload, "obj", "object", "Object", "target", "Target")
                target = payload_target if payload_target is not None else auth
            auth_as = _mapping_value(authority_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        return build("Get", target, optional={"authAs": auth_as}, auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getmek",
        "readmek",
        "getactivekey",
        "getrangeactivekey",
        "activekey",
        "getactivemek",
        "getcurrentkey",
        "getcurrentmek",
        "getrangekey",
        "readrangekey",
        "getrangecurrentkey",
        "getmediakey",
        "getrangemediakey",
        "getactivemediakey",
        "getlockingkey",
        "getmediaencryptionkey",
        "getrangemediaencryptionkey",
        "getencryptionkey",
        "getrangeencryptionkey",
    }:
        range_no = range_arg(0)
        auth = _arg_or_kw(args, kwargs, 1, "auth", "Auth")
        auth_as = _arg_or_kw(args, kwargs, 2, "authAs", "AuthAs", "auth_as", "authAS") or auth
        mek_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "params",
            "Params",
            "parameters",
            "Parameters",
            "policy",
            "Policy",
            "config",
            "Config",
            "request",
            "Request",
            "target",
            "Target",
            "keyRequest",
            "KeyRequest",
            "mediaKeyRequest",
            "MediaKeyRequest",
            "lockingRequest",
            "LockingRequest",
            "rangeRequest",
            "RangeRequest",
            "lockingRangeRequest",
            "LockingRangeRequest",
            "credential",
            "Credential",
        )
        mek_payload = _mapping_value(kwargs, *mek_payload_aliases)
        if not isinstance(mek_payload, dict):
            mek_payload = _mapping_value(inp, *mek_payload_aliases)
        if not isinstance(mek_payload, dict) and len(args) > 0 and isinstance(args[0], dict):
            mek_payload = _mapping_value(args[0], *mek_payload_aliases)
            if not isinstance(mek_payload, dict):
                mek_payload = args[0]
        if isinstance(mek_payload, dict):
            for _ in range(2):
                merged_mek_payload = dict(mek_payload)
                for envelope in mek_payload_aliases:
                    found_envelope, nested_mek_payload = _dict_lookup(mek_payload, envelope)
                    if found_envelope and isinstance(nested_mek_payload, dict) and nested_mek_payload is not mek_payload:
                        merged_mek_payload.update(nested_mek_payload)
                if merged_mek_payload == mek_payload:
                    break
                mek_payload = merged_mek_payload
            if range_no is None or isinstance(range_no, dict):
                range_no = _mapping_value(
                    mek_payload,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "bandName",
                    "band_name",
                    "bandNo",
                    "band_no",
                    "rangeName",
                    "range_name",
                    "lockingRange",
                    "locking_range",
                    "lockingRangeID",
                    "lockingRangeId",
                    "locking_range_id",
                    "rangeNumber",
                    "range_number",
                    "rangeIndex",
                    "range_index",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "obj",
                    "object",
                    "Object",
                    "target",
                    "Target",
                    "key",
                    "Key",
                    "range_key",
                    "rangeKey",
                    "mek",
                    "MEK",
                    "activeKey",
                    "ActiveKey",
                )
            if isinstance(range_no, dict):
                range_no = _mapping_value(
                    range_no,
                    "rangeNo",
                    "range",
                    "Range",
                    "range_no",
                    "rangeID",
                    "rangeId",
                    "range_id",
                    "band",
                    "Band",
                    "bandID",
                    "bandId",
                    "band_id",
                    "id",
                    "ID",
                    "uid",
                    "UID",
                    "key",
                    "Key",
                    "range_key",
                    "rangeKey",
                    "mek",
                    "MEK",
                    "activeKey",
                    "ActiveKey",
                    "target",
                    "Target",
                )
            if auth is None:
                auth = _mapping_value(mek_payload, "auth", "Auth", "authority", "Authority")
            auth_as = _mapping_value(mek_payload, "authAs", "AuthAs", "auth_as", "authAS") or auth_as or auth
        if range_no is None:
            key_selector = _mapping_value(kwargs, "key", "Key", "range_key", "rangeKey", "mek", "MEK", "activeKey", "ActiveKey")
            if key_selector is not None:
                parsed_key_range = _parse_int(key_selector)
                if parsed_key_range is None:
                    parsed_key_range = _range_id_from_key(_normalize_name(key_selector))
                if parsed_key_range is not None:
                    range_no = parsed_key_range
        return build("Get", _band_target_from_range_value(range_no), raw_args=[(3, 0x0A), (4, 0x0A)], optional={"authAs": auth_as}, sp_value="LockingSP", auth_value=auth_as, challenge=_authas_credential_arg({}, {"authAs": auth_as}, None))

    if function_alias in {
        "getalignmentrequired",
        "readalignmentrequired",
        "fetchalignmentrequired",
        "queryalignmentrequired",
        "loadalignmentrequired",
        "isalignrequired",
        "isalignmentrequired",
        "getalignrequired",
        "getlogicalblocksize",
        "readlogicalblocksize",
        "fetchlogicalblocksize",
        "querylogicalblocksize",
        "loadlogicalblocksize",
        "getblocksize",
        "queryblocksize",
        "getalignmentgranularity",
        "readalignmentgranularity",
        "fetchalignmentgranularity",
        "queryalignmentgranularity",
        "loadalignmentgranularity",
        "getaligngranularity",
        "queryaligngranularity",
        "getlowestalignedlba",
        "readlowestalignedlba",
        "fetchlowestalignedlba",
        "querylowestalignedlba",
        "loadlowestalignedlba",
        "getlowestaligned",
        "querylowestaligned",
    }:
        column = {
            "getalignmentrequired": 7,
            "readalignmentrequired": 7,
            "fetchalignmentrequired": 7,
            "queryalignmentrequired": 7,
            "loadalignmentrequired": 7,
            "isalignrequired": 7,
            "isalignmentrequired": 7,
            "getalignrequired": 7,
            "getlogicalblocksize": 8,
            "readlogicalblocksize": 8,
            "fetchlogicalblocksize": 8,
            "querylogicalblocksize": 8,
            "loadlogicalblocksize": 8,
            "getblocksize": 8,
            "queryblocksize": 8,
            "getalignmentgranularity": 9,
            "readalignmentgranularity": 9,
            "fetchalignmentgranularity": 9,
            "queryalignmentgranularity": 9,
            "loadalignmentgranularity": 9,
            "getaligngranularity": 9,
            "queryaligngranularity": 9,
            "getlowestalignedlba": 10,
            "readlowestalignedlba": 10,
            "fetchlowestalignedlba": 10,
            "querylowestalignedlba": 10,
            "loadlowestalignedlba": 10,
            "getlowestaligned": 10,
            "querylowestaligned": 10,
        }[function_alias]
        return build("Get", "LockingInfo", raw_args=[(3, column), (4, column)], sp_value="LockingSP", auth_value="Anybody")

    if function_alias in {
        "getmaxranges",
        "readmaxranges",
        "fetchmaxranges",
        "querymaxranges",
        "loadmaxranges",
        "getmaxlockingranges",
        "readmaxlockingranges",
        "fetchmaxlockingranges",
        "querymaxlockingranges",
        "loadmaxlockingranges",
        "getrangecount",
        "readrangecount",
        "fetchrangecount",
        "queryrangecount",
        "loadrangecount",
        "getlockingrangecount",
        "readlockingrangecount",
        "fetchlockingrangecount",
        "querylockingrangecount",
        "loadlockingrangecount",
        "getnumberofranges",
        "readnumberofranges",
        "fetchnumberofranges",
        "querynumberofranges",
        "loadnumberofranges",
        "getnumranges",
        "readnumranges",
        "fetchnumranges",
        "querynumranges",
        "loadnumranges",
        "getrangelimit",
        "readrangelimit",
        "fetchrangelimit",
        "queryrangelimit",
        "loadrangelimit",
        "getlockingrangelimit",
        "readlockingrangelimit",
        "fetchlockingrangelimit",
        "querylockingrangelimit",
        "loadlockingrangelimit",
    }:
        return build("Get", "LockingInfo", raw_args=[(3, 4), (4, 4)], sp_value="LockingSP", auth_value="Anybody")

    if function_alias in {
        "lockinginfo",
        "getlockinginfo",
        "readlockinginfo",
        "fetchlockinginfo",
        "querylockinginfo",
        "loadlockinginfo",
        "getlockinginfotable",
        "readlockinginfotable",
        "fetchlockinginfotable",
        "querylockinginfotable",
        "loadlockinginfotable",
        "getrangesupport",
        "readrangesupport",
        "fetchrangesupport",
        "queryrangesupport",
        "loadrangesupport",
    }:
        return build("Get", "LockingInfo", sp_value="LockingSP", auth_value="Anybody")

    return None


def _method_info_from_input(inp: dict[str, Any]) -> Any:
    method = _mapping_value(inp, "method", "Method")
    if method is not None:
        return method
    for name in (
        "method_name",
        "methodName",
        "MethodName",
        "method_id",
        "methodId",
        "MethodID",
        "method_uid",
        "methodUid",
        "MethodUID",
        "operationName",
        "operation_name",
        "OperationName",
        "functionName",
        "function_name",
        "FunctionName",
        "name",
        "Name",
    ):
        value = _mapping_value(inp, name)
        if value is not None:
            return value
    argv = _invoke_argv(inp)
    if len(argv) >= 2:
        return argv[1]
    return None


def _args_with_kwargs(args: Any, kwargs: dict[str, Any]) -> Any:
    if not kwargs:
        return args
    if isinstance(args, dict):
        _, required = _dict_lookup(args, "required", "Required", "required_args", "requiredArgs", "RequiredArgs")
        _, optional = _dict_lookup(args, "optional", "Optional", "optional_args", "optionalArgs", "OptionalArgs")
        if isinstance(required, dict) or isinstance(optional, dict):
            merged_optional = dict(optional) if isinstance(optional, dict) else {}
            merged_optional.update(kwargs)
            raw_args = _mapping_value(args, "_raw_args", "raw_args", "rawArgs", "RawArgs", default=args)
            return {"required": dict(required) if isinstance(required, dict) else {}, "optional": merged_optional, "_raw_args": raw_args}
    return {"required": {}, "optional": dict(kwargs), "_raw_args": args}


def _method_args_node(raw: dict[str, Any]) -> Any:
    inp = _input_section(raw)
    argv = _invoke_argv(inp)
    kwargs = _invoke_kwargs(inp)
    if argv:
        return {"required": {}, "optional": kwargs, "_raw_args": argv[2:]}
    method_info = _method_info_from_input(inp)
    if not isinstance(method_info, dict):
        args = _mapping_value(inp, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
        if args is not None:
            return _args_with_kwargs(args, kwargs)
        required = _mapping_value(inp, "required", "Required", "required_args", "requiredArgs", "RequiredArgs")
        optional = _mapping_value(inp, "optional", "Optional", "optional_args", "optionalArgs", "OptionalArgs")
        if required is not None or optional is not None:
            merged_optional = dict(optional) if isinstance(optional, dict) else {}
            merged_optional.update(kwargs)
            return {"required": required or {}, "optional": merged_optional}
        if kwargs:
            return {"required": {}, "optional": dict(kwargs)}
        return None
    args = _mapping_value(method_info, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
    if args is not None:
        return _args_with_kwargs(args, kwargs)
    for source in (method_info, inp):
        if isinstance(source, dict):
            required = _mapping_value(source, "required", "Required", "required_args", "requiredArgs", "RequiredArgs")
            optional = _mapping_value(source, "optional", "Optional", "optional_args", "optionalArgs", "OptionalArgs")
            if required is not None or optional is not None:
                merged_optional = dict(optional) if isinstance(optional, dict) else {}
                merged_optional.update(kwargs)
                return {"required": required or {}, "optional": merged_optional}
    args = _mapping_value(inp, "args", "Args", "arguments", "Arguments", "params", "Params", "parameters", "Parameters")
    return _args_with_kwargs(args, kwargs)


def _method_args(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Any]:
    args = _method_args_node(raw)
    if isinstance(args, dict):
        _, required = _dict_lookup(args, "required", "Required", "required_args", "requiredArgs", "RequiredArgs")
        _, optional = _dict_lookup(args, "optional", "Optional", "optional_args", "optionalArgs", "OptionalArgs")
        raw_args = _mapping_value(args, "_raw_args", "raw_args", "rawArgs", "RawArgs", default=args)
        return (
            dict(required) if isinstance(required, dict) else {},
            dict(optional) if isinstance(optional, dict) else {},
            raw_args,
        )
    return {}, {}, args


def _walk_column_values(node: Any) -> dict[int, Any]:
    out: dict[int, Any] = {}

    def parse_column_key(key: Any) -> int | None:
        text = _as_text(key).strip()
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
            for key, val in value.items():
                column = parse_column_key(key)
                if column is not None:
                    out[column] = val
                    continue
                walk(val)
        elif isinstance(value, (list, tuple)) and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            column = parse_column_key(value[0])
            if column is not None:
                if column == 1 and is_column_pair_sequence(value[1]):
                    walk(value[1])
                    return
                out[column] = value[1]
                return
            walk(value[1])
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, tuple):
            for item in value:
                walk(item)

    walk(node)
    return out


def _column_from_name(name: Any, symbol: str = "", siblings: set[str] | None = None) -> int | None:
    key = re.sub(r"[^A-Za-z0-9_]", "", _as_text(name or "")).upper()
    if not key:
        return None
    if key in {"PIN"}:
        return PIN_COLUMN
    if symbol.startswith("C_PIN_"):
        cpin_names = {
            "CHARSET": CPIN_CHARSET_COLUMN,
            "CHARACTERSET": CPIN_CHARSET_COLUMN,
            "TRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "PINLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "PINTRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "USERTRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "RETRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "USERRETRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "CREDENTIALRETRYLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "ATTEMPTLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "PINATTEMPTLIMIT": CPIN_TRY_LIMIT_COLUMN,
            "MAXATTEMPTS": CPIN_TRY_LIMIT_COLUMN,
            "MAXPINATTEMPTS": CPIN_TRY_LIMIT_COLUMN,
            "TRIES": CPIN_TRIES_COLUMN,
            "PINTRIES": CPIN_TRIES_COLUMN,
            "USERTRIES": CPIN_TRIES_COLUMN,
            "ATTEMPTS": CPIN_TRIES_COLUMN,
            "PINATTEMPTS": CPIN_TRIES_COLUMN,
            "USERATTEMPTS": CPIN_TRIES_COLUMN,
            "CREDENTIALATTEMPTS": CPIN_TRIES_COLUMN,
            "RETRYCOUNT": CPIN_TRIES_COLUMN,
            "USERRETRYCOUNT": CPIN_TRIES_COLUMN,
            "PERSISTENCE": CPIN_PERSISTENCE_COLUMN,
        }
        if key in cpin_names:
            return cpin_names[key]
    if key in {"_MINPINLENGTH", "MINPINLENGTH", "MINIMUMPINLENGTH", "PINMINLENGTH"}:
        return MIN_PIN_COLUMN
    if symbol == "SPInfo":
        spinfo_names = {
            "SPSESSIONTIMEOUT": 5,
            "ENABLED": 6,
        }
        if key in spinfo_names:
            return spinfo_names[key]
    if symbol.startswith("Locking_"):
        locking_names = {
            "RANGESTART": 3,
            "START": 3,
            "STARTLBA": 3,
            "RANGELENGTH": 4,
            "LENGTH": 4,
            "READLOCKENABLED": 5,
            "WRITELOCKENABLED": 6,
            "READLOCKED": 7,
            "WRITELOCKED": 8,
            "LOCKONRESET": 9,
            "LOR": 9,
            "RESETTYPES": 9,
            "RESET_TYPES": 9,
            "TYPES": 9,
            "RESETEVENTS": 9,
            "RESET_EVENTS": 9,
            "RESETON": 9,
            "RESET_ON": 9,
            "RESETLIST": 9,
            "RESET_LIST": 9,
            "ACTIVEKEY": 10,
            "NEXTKEY": 11,
            "REENCRYPTSTATE": 12,
            "ADVKEYMODE": 14,
            "ADV_KEY_MODE": 14,
            "ADVANCEDKEYMODE": 14,
            "ADVANCED_KEY_MODE": 14,
            "VERIFYMODE": 15,
            "VERIFY_MODE": 15,
            "VERIFICATIONMODE": 15,
            "VERIFICATION_MODE": 15,
            "CONTONRESET": 16,
            "CONT_ON_RESET": 16,
            "CONTINUEONRESET": 16,
            "CONTINUE_ON_RESET": 16,
            "RESETCONTINUE": 16,
            "RESET_CONTINUE": 16,
            "REENCRYPTCONTONRESET": 16,
            "REENCRYPT_CONT_ON_RESET": 16,
            "REENCRYPTCONTINUEONRESET": 16,
            "REENCRYPT_CONTINUE_ON_RESET": 16,
            "LASTREENCRYPTLBA": 17,
            "LAST_REENCRYPT_LBA": 17,
            "LASTREENCRYPTIONLBA": 17,
            "LAST_REENCRYPTION_LBA": 17,
            "REENCRYPTLBA": 17,
            "REENCRYPT_LBA": 17,
            "REENCRYPTIONLBA": 17,
            "REENCRYPTION_LBA": 17,
            "LASTREENCSTAT": 18,
            "LAST_REENC_STAT": 18,
            "LASTREENCRYPTSTATUS": 18,
            "LAST_REENCRYPT_STATUS": 18,
            "LASTREENCRYPTIONSTATUS": 18,
            "LAST_REENCRYPTION_STATUS": 18,
            "LASTREENCRYPTSTAT": 18,
            "LAST_REENCRYPT_STAT": 18,
            "GENERALSTATUS": 19,
            "GENERAL_STATUS": 19,
            "RANGESTATUS": 19,
            "RANGE_STATUS": 19,
            "LOCKINGRANGESTATUS": 19,
            "LOCKING_RANGE_STATUS": 19,
        }
        if key in locking_names:
            return locking_names[key]
    if symbol.startswith("Authority_"):
        authority_names = {
            "ISCLASS": 3,
            "CLASS": 4,
            "ENABLED": 5,
            "SECURE": 6,
            "HASHANDSIGN": 7,
            "PRESENTCERTIFICATE": 8,
            "OPERATION": 9,
            "CREDENTIAL": 10,
            "RESPONSESIGN": 11,
            "RESPONSEEXCH": 12,
            "CLOCKSTART": 13,
            "CLOCKEND": 14,
            "LIMIT": 15,
            "AUTHORITYLIMIT": 15,
            "USERLIMIT": 15,
            "AUTHLIMIT": 15,
            "AUTHENTICATIONLIMIT": 15,
            "AUTHUSELIMIT": 15,
            "AUTHORITYUSELIMIT": 15,
            "USERUSELIMIT": 15,
            "USELIMIT": 15,
            "MAXUSES": 15,
            "MAXAUTHENTICATIONS": 15,
            "MAXAUTHS": 15,
            "CREDENTIALLIMIT": 15,
            "CREDENTIALUSELIMIT": 15,
            "USES": 16,
            "AUTHORITYUSES": 16,
            "USERUSES": 16,
            "USECOUNT": 16,
            "AUTHUSECOUNT": 16,
            "AUTHORITYUSECOUNT": 16,
            "CREDENTIALUSECOUNT": 16,
            "CREDENTIALUSES": 16,
            "LOG": 17,
            "LOGTO": 18,
        }
        if key in authority_names:
            return authority_names[key]
    if symbol in {"AdminSP", "LockingSP"} and key == "FROZEN":
        return 7
    common_object_names = {
        "UID": 0,
        "NAME": 1,
        "COMMONNAME": 2,
    }
    if key in common_object_names:
        return common_object_names[key]
    if symbol == "Table" or symbol.startswith("Table_"):
        table_descriptor_names = {
            "TEMPLATEID": 3,
            "KIND": 4,
            "COLUMN": 5,
            "COLUMNS": 5,
            "NUMCOLUMNS": 6,
            "NUMBEROFCOLUMNS": 6,
            "ROWS": 7,
            "ROWSFREE": 8,
            "ROWBYTES": 9,
            "LASTID": 10,
            "MINSIZE": 11,
            "MAXSIZE": 12,
            "MANDATORYWRITEGRANULARITY": TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN,
            "RECOMMENDEDACCESSGRANULARITY": TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN,
        }
        if key in table_descriptor_names:
            return table_descriptor_names[key]
    if symbol.startswith("ACE_"):
        ace_names = {
            "BOOLEANEXPR": ACE_BOOLEAN_EXPR_COLUMN,
            "BOOLEANEXPRESSION": ACE_BOOLEAN_EXPR_COLUMN,
            "COLUMNS": ACE_COLUMNS_COLUMN,
        }
        if key in ace_names:
            return ace_names[key]
    if symbol.startswith("AccessControl_") or symbol in {"AccessControl", "AccessControlTable"}:
        access_control_names = {
            "INVOKINGID": 1,
            "METHODID": 2,
            "ACL": ACCESS_CONTROL_ACL_COLUMN,
            "ACCESSCONTROL": ACCESS_CONTROL_ACL_COLUMN,
            "ACCESSCONTROLLIST": ACCESS_CONTROL_ACL_COLUMN,
            "LOG": ACCESS_CONTROL_LOG_COLUMN,
            "LOGSELECT": ACCESS_CONTROL_LOG_COLUMN,
            "ADDACEACL": 6,
            "REMOVEACEACL": 7,
            "GETACLACL": 8,
            "DELETEMETHODACL": 9,
            "ACLADDACELOG": ACCESS_CONTROL_ADD_ACE_LOG_COLUMN,
            "ADDACELOG": ACCESS_CONTROL_ADD_ACE_LOG_COLUMN,
            "REMOVEACELOG": ACCESS_CONTROL_REMOVE_ACE_LOG_COLUMN,
            "GETACLLOG": ACCESS_CONTROL_GET_ACL_LOG_COLUMN,
            "DELETEMETHODLOG": ACCESS_CONTROL_DELETE_METHOD_LOG_COLUMN,
            "LOGTO": ACCESS_CONTROL_LOGTO_COLUMN,
        }
        if key in access_control_names:
            return access_control_names[key]
    if symbol.startswith("SecretProtect_") or symbol in {"SecretProtect", "SecretProtectTable"}:
        secretprotect_names = {
            "TABLE": 1,
            "TABLEREF": 1,
            "COLUMN": 2,
            "COLUMNNUMBER": 2,
            "PROTECTMECHANISMS": 3,
        }
        if key in secretprotect_names:
            return secretprotect_names[key]
    if symbol.startswith("K_AES_"):
        k_aes_names = {
            "KEY": K_AES_KEY_COLUMN,
            "MODE": K_AES_MODE_COLUMN,
        }
        if key in k_aes_names:
            return k_aes_names[key]
    cec_match = re.match(r"C_EC_(160|163|192|224|233|283|384|521)", symbol)
    if cec_match:
        c_ec_names = {
            "P": 3,
            "R": 4,
            "B": 5,
            "X": 6,
            "Y": 7,
            "ALPHA": 8,
            "U": 9,
            "V": 10,
            "HASH": 11,
            "CHAINLIMIT": 12,
            "CERTIFICATE": 13,
        }
        if cec_match.group(1) in {"163", "283"}:
            c_ec_names.update({"K1": 3, "K2": 4, "K3": 5, "R": 6, "A": 7, "B": 8, "X": 9, "Y": 10, "ALPHA": 11, "U": 12, "V": 13, "HASH": 14, "CHAINLIMIT": 15, "CERTIFICATE": 16})
        elif cec_match.group(1) == "233":
            c_ec_names.update({"K": 3, "R": 4, "A": 5, "B": 6, "X": 7, "Y": 8, "ALPHA": 9, "U": 10, "V": 11, "HASH": 12, "CHAINLIMIT": 13, "CERTIFICATE": 14})
        if key in c_ec_names:
            return c_ec_names[key]
    if symbol in {"LogList", "LogListTable"} or symbol.startswith("LogList_"):
        loglist_names = {
            "LOG": 3,
            "SERIAL": 4,
            "HIGHSECURITY": 5,
        }
        if key in loglist_names:
            return loglist_names[key]
    if symbol in {"Log", "LogTable"} or symbol.startswith("Log_"):
        log_names = {
            "PREV": 1,
            "NEXT": 2,
            "SESSION": 3,
            "SIGNINGAUTHORITY": 4,
            "SIGNINGAUTHNAME": 5,
            "EXCHANGEAUTHORITY": 6,
            "EXCHANGEAUTHNAME": 7,
            "MONOTONICTIME": 8,
            "EXACTTIME": 9,
            "TIMEKIND": 10,
            "LOGKIND": 11,
            "DATA": 13,
        }
        if key in log_names:
            return log_names[key]
    locking_names = {
        "RANGESTART": 3,
        "RANGELENGTH": 4,
        "READLOCKENABLED": 5,
        "WRITELOCKENABLED": 6,
        "READLOCKED": 7,
        "WRITELOCKED": 8,
        "LOCKONRESET": 9,
        "ACTIVEKEY": 10,
        "NEXTKEY": 11,
        "REENCRYPTSTATE": 12,
        "REENCRYPTREQUEST": 13,
        "REENCYPTREQUEST": 13,
        "ADVKEYMODE": 14,
        "VERIFYMODE": 15,
        "CONTONRESET": 16,
        "LASTREENCRYPTLBA": 17,
        "LASTREENCSTAT": 18,
        "LASTREENCRYPTSTATE": 18,
        "LASTREENCSTATE": 18,
        "GENERALSTATUS": 19,
    }
    if key in locking_names:
        return locking_names[key]
    if key in {"ENABLED", "ENABLE", "ISENABLED", "IS_ENABLED", "ACTIVE", "MBRENABLED", "MBRENABLE"}:
        sibling_keys = siblings or set()
        if symbol == "MBRControl":
            return 1
        if symbol.startswith("TLS_PSK_Key") or "CIPHERSUITE" in sibling_keys or "CIPHER_SUITE" in sibling_keys or "PSK" in sibling_keys:
            return 3
        return 5
    if key in {"DONE", "MBRDONE"} and symbol == "MBRControl":
        return 2
    if key in {"DONEONRESET", "MBRDONEONRESET", "RESETTYPES", "RESET_TYPES", "TYPES", "RESETEVENTS", "RESET_EVENTS", "RESETON", "RESET_ON", "RESETLIST", "RESET_LIST"} and symbol == "MBRControl":
        return 3
    if symbol.startswith("Port") and key in {"LOCKED", "ISLOCKED", "PORTLOCK", "PORT_LOCK", "PORTLOCKED", "LOCKSTATE", "LOCK_STATE", "PORTLOCKSTATE", "PORT_LOCK_STATE", "PORTSTATE", "PORT_STATE"}:
        return 3
    if key == "PORTLOCKED":
        return 3
    if symbol.startswith("TLS_PSK_Key") and key in {"PSK", "SECRET", "PSKSECRET", "PSK_SECRET", "PSKVALUE", "PSK_VALUE", "PRESHAREDKEY", "PRE_SHARED_KEY", "KEYMATERIAL", "KEY_MATERIAL"}:
        return 4
    if key == "PSK":
        return 4
    if symbol.startswith("TLS_PSK_Key") and key in {"CIPHERSUITE", "CIPHER_SUITE", "SUITE", "TLSCIPHERSUITE", "TLS_CIPHER_SUITE"}:
        return 5
    if key == "CIPHERSUITE":
        return 5
    if key in {
        "ACTIVEDATAREMOVALMECHANISM",
        "DATAREMOVALMECHANISM",
        "MECHANISM",
        "ACTIVEMECHANISM",
        "ACTIVE_MECHANISM",
        "REMOVALMECHANISM",
        "REMOVAL_MECHANISM",
        "DATAREMOVALMODE",
        "DATA_REMOVAL_MODE",
        "DATAREMOVALMETHOD",
        "DATA_REMOVAL_METHOD",
        "MODE",
        "METHOD",
        "SELECTEDMECHANISM",
        "SELECTED_MECHANISM",
        "CURRENTMECHANISM",
        "CURRENT_MECHANISM",
    } and symbol == "DataRemovalMechanism":
        return 1
    if key == "PROGRAMMATICRESETENABLE" and symbol == "TPerInfo":
        return 8
    locking_info_names = {
        "MAXRANGES": 4,
        "ALIGNMENTREQUIRED": 7,
        "LOGICALBLOCKSIZE": 8,
        "ALIGNMENTGRANULARITY": 9,
        "LOWESTALIGNEDLBA": 10,
    }
    if key in {"LIFECYCLE", "LIFECYCLESTATE", "LIFECYCLESTATEVALUE"}:
        return 6
    return locking_info_names.get(key)


def _walk_named_column_values(node: Any, symbol: str = "") -> dict[int, Any]:
    out: dict[int, Any] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            sibling_keys = {re.sub(r"[^A-Za-z0-9_]", "", _as_text(key or "")).upper() for key in value}
            for key, val in value.items():
                column = _column_from_name(key, symbol, sibling_keys)
                if column is not None:
                    out[column] = val
                    continue
                walk(val)
        elif isinstance(value, (list, tuple)) and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            column = _column_from_name(value[0], symbol)
            if column is not None:
                out[column] = value[1]
                return
            walk(value[1])
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    walk(node)
    return out


def _values(optional: dict[str, Any], raw_args: Any, symbol: str = "") -> dict[int, Any]:
    found, values_node = _dict_lookup(
        optional,
        "Values",
        "Value",
        "RowValues",
        "rowValues",
        "NamedValues",
        "namedValues",
        "SetValues",
        "setValues",
    )
    if found:
        values = _walk_column_values(values_node)
        values.update(_walk_named_column_values(values_node, symbol))
        return values
    found, row_node = _dict_lookup(optional, "Row")
    if found:
        values = _walk_column_values(row_node)
        values.update(_walk_named_column_values(row_node, symbol))
        return values

    named = _walk_named_column_values(optional, symbol)
    if named:
        return named

    # TCGstorageAPI noNamed calls sometimes appear as positional arguments rather
    # than optional.Values.  Only keep plausible column/value pairs.
    row = None
    if isinstance(raw_args, dict):
        required = _mapping_section(raw_args, "required", "Required")
        optional_args = _mapping_section(raw_args, "optional", "Optional")
        row = _mapping_value(optional_args, "Row")
        if row is None:
            row = _mapping_value(required, "Row")
    source = row if row is not None else raw_args
    if isinstance(source, (list, tuple, dict)):
        decoded = _walk_column_values(source)
        decoded.update(_walk_named_column_values(source, symbol))
        return {k: v for k, v in decoded.items() if k in set(range(0, 64)) | {MIN_PIN_COLUMN}}
    return {}


def _is_byte_table_symbol(symbol: str) -> bool:
    return symbol == "MBR" or symbol.startswith("DataStore") or symbol.startswith("_CertData_")


def _is_byte_table_uid(uid: str) -> bool:
    if uid in {"0000080400000000", "0000100100000000", "0000800100000000", "0001000400000000", "0001001F00000000"}:
        return True
    return uid.startswith(("000010010000", "000080010000"))


def _has_explicit_row_values(event: Any) -> bool:
    values = _mapping_value(event.optional, "Values", "Value", "RowValues", "rowValues", "NamedValues", "namedValues", "SetValues", "setValues")
    return values is not None and bool(_walk_column_values(values))


def _contains_payload_bytes(value: Any) -> bool:
    payload_names = (
        "Bytes",
        "bytes",
        "Data",
        "data",
        "Buffer",
        "BufferIn",
        "Payload",
        "payload",
        "Blob",
        "blob",
        "Content",
        "content",
        "Buf",
        "buf",
        "Hex",
        "hex",
        "Value",
        "value",
        "payloadBytes",
        "PayloadBytes",
        "dataBytes",
        "DataBytes",
        "byteArray",
        "ByteArray",
    )
    payload_key_names = {"bytes", "data", "buffer", "bufferin", "payload", "blob", "content", "buf", "hex", "value", "payloadbytes", "databytes", "bytearray", "1"}
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, dict):
        found, payload = _dict_lookup(value, *payload_names)
        if found and _contains_payload_bytes(payload):
            return True
        return any(_contains_payload_bytes(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                if key_text in payload_key_names and _contains_payload_bytes(item[1]):
                    return True
                continue
            if _contains_payload_bytes(item):
                return True
    return False


def _byte_table_has_payload(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(
            source,
            "Bytes",
            "bytes",
            "Data",
            "data",
            "Buffer",
            "BufferIn",
            "Payload",
            "payload",
            "Blob",
            "blob",
            "Content",
            "content",
            "Buf",
            "buf",
            "Hex",
            "hex",
            "Value",
            "value",
            "payloadBytes",
            "PayloadBytes",
            "dataBytes",
            "DataBytes",
            "byteArray",
            "ByteArray",
        )
        if found and _contains_payload_bytes(value):
            return True
    return _contains_payload_bytes(_method_raw_args(event))


def _byte_payload_length(value: Any) -> int | None:
    payload_names = (
        "Bytes",
        "bytes",
        "Data",
        "data",
        "Buffer",
        "BufferIn",
        "Payload",
        "payload",
        "Blob",
        "blob",
        "Content",
        "content",
        "Buf",
        "buf",
        "Hex",
        "hex",
        "Value",
        "value",
        "payloadBytes",
        "PayloadBytes",
        "dataBytes",
        "DataBytes",
        "byteArray",
        "ByteArray",
    )
    payload_key_names = {"bytes", "data", "buffer", "bufferin", "payload", "blob", "content", "buf", "hex", "value", "payloadbytes", "databytes", "bytearray", "1"}
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        compact = re.sub(r"[\s:_-]", "", text)
        if compact.lower().startswith("0x"):
            compact = compact[2:]
        if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            return len(compact) // 2
        return len(text.encode("utf-8"))
    if isinstance(value, dict):
        found, payload = _dict_lookup(value, *payload_names)
        if found:
            length = _byte_payload_length(payload)
            if length is not None:
                return length
        for item in value.values():
            length = _byte_payload_length(item)
            if length is not None:
                return length
        return None
    if isinstance(value, (list, tuple)):
        if value and all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value):
            return len(value)
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower()
            if key_text in payload_key_names:
                return _byte_payload_length(value[1])
            if key_text in {
                "cellblock",
                "where",
                "row",
                "startrow",
                "endrow",
                "start",
                "end",
                "table",
                "startcolumn",
                "endcolumn",
                "column",
                "columns",
                "startcol",
                "endcol",
                "0",
                "2",
                "3",
                "4",
            }:
                return None
        for item in value:
            length = _byte_payload_length(item)
            if length is not None:
                return length
    return None


def _byte_table_payload_length(event: Any) -> int | None:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Bytes", "bytes", "Data", "data", "Buffer", "BufferIn", "Payload", "payload", "Value", "value", "payloadBytes", "PayloadBytes", "dataBytes", "DataBytes", "byteArray", "ByteArray")
        if found:
            length = _byte_payload_length(value)
            if length is not None:
                return length
    return _byte_payload_length(_method_raw_args(event))


def _byte_table_pair_invalid(key: Any, value: Any, method: str) -> bool:
    key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
    if isinstance(key, bool):
        return True
    if key_text in {"bytes", "data", "buffer", "bufferin", "payload", "blob", "content", "buf", "hex", "value", "payloadbytes", "databytes", "bytearray"}:
        return False
    if method == "Set" and _parse_int(key) == 1 and isinstance(value, (bytes, bytearray, str)):
        return False
    if key_text == "where":
        if isinstance(value, (dict, list, tuple, set)):
            return False
        if isinstance(value, bool):
            return True
        parsed_value = _parse_int(value)
        return parsed_value is None or parsed_value < 0
    if key_text in {"startrow", "startindex", "startposition", "startoffset", "offset", "byteoffset", "index", "position", "pos", "address", "row", "start", "endrow", "endindex", "endposition", "endoffset", "end"}:
        if isinstance(value, bool):
            return True
        parsed_value = _parse_int(value)
        return parsed_value is None or parsed_value < 0
    if key_text in {"startcolumn", "endcolumn", "column", "columns", "startcol", "endcol", "col"}:
        return True
    parsed = _parse_int(key)
    if parsed in {1, 2}:
        if isinstance(value, bool):
            return True
        parsed_value = _parse_int(value)
        return parsed_value is None or parsed_value < 0
    return parsed is not None and parsed not in {0, 1, 2}


def _byte_table_raw_args_invalid(event: Any) -> bool:
    raw_args = _method_raw_args(event)
    if raw_args is None or isinstance(raw_args, dict):
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, val in value.items():
                if _byte_table_pair_invalid(key, val, event.method):
                    return True
                if walk(val):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                key, val = value
                if _byte_table_pair_invalid(key, val, event.method):
                    return True
                return False if isinstance(val, (bytes, bytearray, str)) else walk(val)
            return any(walk(item) for item in value)
        return False

    return walk(raw_args)


def _raw_arg_values_by_key(value: Any, *names: str) -> list[Any]:
    wanted = {re.sub(r"[^A-Za-z0-9]", "", name).lower() for name in names}
    found: list[Any] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, val in item.items():
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if key_text in wanted:
                    found.append(val)
                walk(val)
            return
        if isinstance(item, (list, tuple)):
            if len(item) == 2 and not isinstance(item[0], (dict, list, tuple, set)):
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                if key_text in wanted:
                    found.append(item[1])
                    return
            for nested in item:
                walk(nested)

    walk(value)
    return found


def _contains_explicit_uid_option(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            if key_text in {"uid", "object", "objectid"}:
                return True
            if _contains_explicit_uid_option(item):
                return True
        return False
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower()
            if key_text in {"uid", "object", "objectid"}:
                return True
            return _contains_explicit_uid_option(value[1])
        return any(_contains_explicit_uid_option(item) for item in value)
    if isinstance(value, set):
        return any(_contains_explicit_uid_option(item) for item in value)
    return False


def _byte_table_where_has_row_address(where: Any) -> bool:
    row_names = (
        "Row",
        "row",
        "startRow",
        "StartRow",
        "startrow",
        "startIndex",
        "startPosition",
        "startOffset",
        "offset",
        "byteOffset",
        "index",
        "position",
        "pos",
        "address",
        "start",
    )
    row_key_names = {"row", "startrow", "startindex", "startposition", "startoffset", "offset", "byteoffset", "index", "position", "pos", "address", "start"}
    if isinstance(where, dict):
        found, row = _dict_lookup(where, *row_names)
        return found and _parse_int(row) is not None
    if isinstance(where, (list, tuple)) and len(where) == 2 and not isinstance(where[0], (dict, list, tuple, set)):
        key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(where[0])).lower()
        return key_text in row_key_names and _parse_int(where[1]) is not None
    if isinstance(where, (list, tuple, set)):
        return any(_byte_table_where_has_row_address(item) for item in where)
    return isinstance(where, int) and not isinstance(where, bool)


def _byte_table_where_has_bool_row_address(where: Any) -> bool:
    row_names = (
        "Row",
        "row",
        "startRow",
        "StartRow",
        "startrow",
        "startIndex",
        "startPosition",
        "startOffset",
        "offset",
        "byteOffset",
        "index",
        "position",
        "pos",
        "address",
        "start",
    )
    row_key_names = {"row", "startrow", "startindex", "startposition", "startoffset", "offset", "byteoffset", "index", "position", "pos", "address", "start"}
    if isinstance(where, dict):
        found, row = _dict_lookup(where, *row_names)
        return (found and isinstance(row, bool)) or any(_byte_table_where_has_bool_row_address(item) for item in where.values())
    if isinstance(where, (list, tuple)) and len(where) == 2 and not isinstance(where[0], (dict, list, tuple, set)):
        key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(where[0])).lower()
        return key_text in row_key_names and isinstance(where[1], bool)
    if isinstance(where, (list, tuple, set)):
        return any(_byte_table_where_has_bool_row_address(item) for item in where)
    return False


def _row_number_value_invalid(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    parsed = _parse_int(value)
    return parsed is None or parsed < 0


def _byte_table_where_row_value_invalid(where: Any) -> bool:
    if isinstance(where, dict):
        found, row = _dict_lookup(
            where,
            "Row",
            "row",
            "startRow",
            "StartRow",
            "startrow",
            "startIndex",
            "startPosition",
            "startOffset",
            "offset",
            "byteOffset",
            "index",
            "position",
            "pos",
            "address",
            "start",
        )
        if found:
            return _row_number_value_invalid(row)
        return any(_byte_table_where_row_value_invalid(item) for item in where.values())
    if isinstance(where, (list, tuple)) and len(where) == 2 and not isinstance(where[0], (dict, list, tuple, set)):
        key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(where[0])).lower()
        if key_text in {"row", "startrow", "startindex", "startposition", "startoffset", "offset", "byteoffset", "index", "position", "pos", "address", "start"}:
            return _row_number_value_invalid(where[1])
        return False
    if isinstance(where, (list, tuple, set)):
        return any(_byte_table_where_row_value_invalid(item) for item in where)
    return _row_number_value_invalid(where)


def _byte_table_where_offset(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None and not isinstance(value, bool):
        return parsed
    if isinstance(value, dict):
        for key in (
            "Where",
            "where",
            "CellBlock",
            "Cellblock",
            "cellblock",
            "Row",
            "row",
            "startRow",
            "StartRow",
            "startrow",
            "startIndex",
            "startPosition",
            "startOffset",
            "offset",
            "byteOffset",
            "index",
            "position",
            "pos",
            "address",
            "start",
        ):
            found, item = _dict_lookup(value, key)
            if found:
                parsed = _byte_table_where_offset(item)
                if parsed is not None:
                    return parsed
        return None
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower()
            if key_text in {"where", "row", "startrow", "startindex", "startposition", "startoffset", "offset", "byteoffset", "index", "position", "pos", "address", "start", "0"}:
                return _byte_table_where_offset(value[1])
            return None
        for item in value:
            parsed = _byte_table_where_offset(item)
            if parsed is not None:
                return parsed
    return None


def _wrapper_byte_start_from_input(event: Any) -> int | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    if _function_alias(_function_name(input_obj)) not in {"writedata", "readdata"}:
        return None
    args = _function_args(input_obj)
    kwargs = _function_kwargs(input_obj)
    function_alias = _function_alias(_function_name(input_obj))
    candidates: list[Any] = []
    if function_alias == "readdata" and len(args) > 1:
        candidates.append(args[1])
    if len(args) > 2:
        candidates.append(args[2])
    for name in (
        "startRow",
        "StartRow",
        "startrow",
        "row",
        "Row",
        "offset",
        "Offset",
        "byteOffset",
        "byte_offset",
        "startOffset",
        "start_offset",
        "startByte",
        "start_byte",
        "byteIndex",
        "byte_index",
        "bytePosition",
        "byte_position",
        "index",
        "Index",
        "position",
        "Position",
        "pos",
        "Pos",
        "address",
        "Address",
        "start",
        "Start",
    ):
        value = _mapping_value(kwargs, name)
        if value is not None:
            candidates.append(value)
    for value in candidates:
        parsed = _byte_table_where_offset(value) if isinstance(value, (dict, list, tuple)) else _parse_int(value)
        if parsed is not None and not isinstance(value, bool):
            return parsed
    return None


def _wrapper_byte_end_from_input(event: Any, start: int | None) -> int | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict) or _function_alias(_function_name(input_obj)) != "readdata":
        return None
    args = _function_args(input_obj)
    kwargs = _function_kwargs(input_obj)
    candidates: list[Any] = []
    if len(args) > 1 and isinstance(args[1], dict):
        explicit_end = _mapping_value(args[1], "endRow", "EndRow", "endrow", "endIndex", "end_index", "endPosition", "end_position", "end", "End")
        parsed_end = _parse_int(explicit_end)
        if parsed_end is not None and not isinstance(explicit_end, bool):
            return parsed_end
        length = _mapping_value(args[1], "length", "Length", "len", "Len", "size", "Size", "count", "Count", "numBytes", "num_bytes", "nBytes", "nbytes", "byteCount", "byte_count", "byteLength", "byte_length", "dataLength", "data_length", "readSize", "read_size", "windowSize", "window_size")
        parsed_length = _parse_int(length)
        if start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(length, bool):
            return start + parsed_length - 1
    if len(args) > 2:
        parsed_start = _parse_int(args[1]) if len(args) > 1 else None
        parsed_length = _parse_int(args[2])
        if parsed_start is not None and parsed_length is not None and parsed_length > 0 and not isinstance(args[2], bool):
            return parsed_start + parsed_length - 1
    if len(args) > 3:
        candidates.append(args[3])
    for name in ("endRow", "EndRow", "endrow", "endIndex", "end_index", "endPosition", "end_position", "end", "End"):
        value = _mapping_value(kwargs, name)
        if value is not None:
            candidates.append(value)
    for value in candidates:
        parsed = _parse_int(value)
        if parsed is not None and not isinstance(value, bool):
            return parsed
    length = _mapping_value(kwargs, "length", "Length", "len", "Len", "size", "Size", "count", "Count", "numBytes", "num_bytes", "nBytes", "nbytes", "byteCount", "byte_count", "byteLength", "byte_length", "dataLength", "data_length", "readSize", "read_size", "windowSize", "window_size")
    parsed_length = _parse_int(length)
    if start is not None and parsed_length is not None and parsed_length > 0:
        return start + parsed_length - 1
    return None


def _byte_table_set_start_offset(event: Any) -> int | None:
    wrapper_start = _wrapper_byte_start_from_input(event)
    if wrapper_start is not None:
        return wrapper_start
    where = _mapping_value(event.required, "Where")
    if where is None:
        where = _mapping_value(event.optional, "Where")
    if where is not None:
        return _byte_table_where_offset(where)
    cellblock = _mapping_value(event.required, "Cellblock", "CellBlock")
    if cellblock is None:
        cellblock = _mapping_value(event.optional, "Cellblock", "CellBlock")
    if cellblock is not None:
        return _byte_table_where_offset(cellblock)
    raw_args = _method_raw_args(event)
    parsed = _byte_table_where_offset(raw_args)
    return 0 if parsed is None else parsed


def _byte_table_get_range(event: Any) -> tuple[int, int] | None:
    start: int | None = None
    end: int | None = None
    length: int | None = None

    wrapper_start = _wrapper_byte_start_from_input(event)
    if wrapper_start is not None:
        start = wrapper_start
        wrapper_end = _wrapper_byte_end_from_input(event, wrapper_start)
        end = wrapper_end if wrapper_end is not None else wrapper_start

    def assign(component: str, value: Any) -> None:
        nonlocal start, end, length
        parsed = _parse_int(value)
        if parsed is None or isinstance(value, bool):
            return
        if component == "startrow":
            start = parsed
        elif component == "endrow":
            end = parsed
        elif component == "length":
            length = parsed

    aliases = {
        1: "startrow",
        2: "endrow",
        "startrow": "startrow",
        "startindex": "startrow",
        "startposition": "startrow",
        "startoffset": "startrow",
        "offset": "startrow",
        "byteoffset": "startrow",
        "index": "startrow",
        "position": "startrow",
        "pos": "startrow",
        "address": "startrow",
        "start": "startrow",
        "row": "startrow",
        "endrow": "endrow",
        "endindex": "endrow",
        "endposition": "endrow",
        "endoffset": "endrow",
        "end": "endrow",
        "length": "length",
        "len": "length",
        "size": "length",
        "count": "length",
        "numbytes": "length",
        "nbytes": "length",
        "bytecount": "length",
        "bytelength": "length",
        "datalength": "length",
        "bytestoread": "length",
        "readlength": "length",
        "numbytestoread": "length",
        "countbytes": "length",
    }

    def component_for_key(key: Any) -> str | None:
        parsed = _parse_int(key)
        if parsed in aliases:
            return aliases[parsed]
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        return aliases.get(text)

    def walk(value: Any, *, direct_cellblock: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized_key == "cellblock":
                    walk(item, direct_cellblock=True)
                    continue
                component = component_for_key(key)
                if component is not None:
                    assign(component, item)
                walk(item, direct_cellblock=False)
            return
        if isinstance(value, (list, tuple)):
            if direct_cellblock and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                component = component_for_key(value[0])
                if component is not None:
                    assign(component, value[1])
                    return
            for item in value:
                walk(item, direct_cellblock=direct_cellblock)

    walk(_mapping_value(event.required, "Cellblock", "CellBlock"), direct_cellblock=True)
    walk(event.required, direct_cellblock=False)
    walk(_mapping_value(event.optional, "Cellblock", "CellBlock"), direct_cellblock=True)
    walk(event.optional, direct_cellblock=False)
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        walk(_mapping_value(raw_args, "Cellblock", "CellBlock"), direct_cellblock=True)
        walk(raw_args, direct_cellblock=False)
    else:
        walk(raw_args, direct_cellblock=True)

    if start is None:
        start = 0
    if end is None and length is not None and length > 0:
        end = start + length - 1
    if end is None:
        end = start
    return (min(start, end), max(start, end))


def _byte_table_get_reversed_range(event: Any) -> bool:
    row_range = _byte_table_get_range(event)
    if row_range is None:
        return False

    def parse_component(value: Any) -> int | None:
        parsed = _parse_int(value)
        if parsed is None or isinstance(value, bool):
            return None
        return parsed

    wrapper_start = _wrapper_byte_start_from_input(event)
    if wrapper_start is not None:
        wrapper_end = _wrapper_byte_end_from_input(event, wrapper_start)
        if wrapper_end is not None and wrapper_start > wrapper_end:
            return True

    starts: list[int] = []
    ends: list[int] = []
    aliases = {
        1: "startrow",
        2: "endrow",
        "startrow": "startrow",
        "startindex": "startrow",
        "startposition": "startrow",
        "startoffset": "startrow",
        "offset": "startrow",
        "byteoffset": "startrow",
        "index": "startrow",
        "position": "startrow",
        "pos": "startrow",
        "address": "startrow",
        "start": "startrow",
        "row": "startrow",
        "endrow": "endrow",
        "endindex": "endrow",
        "endposition": "endrow",
        "endoffset": "endrow",
        "end": "endrow",
    }

    def component_for_key(key: Any) -> str | None:
        parsed = _parse_int(key)
        if parsed in aliases:
            return aliases[parsed]
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        return aliases.get(text)

    def collect(component: str, value: Any) -> None:
        parsed = parse_component(value)
        if parsed is None:
            return
        if component == "startrow":
            starts.append(parsed)
        elif component == "endrow":
            ends.append(parsed)

    def walk(value: Any, *, direct_cellblock: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized_key == "cellblock":
                    walk(item, direct_cellblock=True)
                    continue
                component = component_for_key(key)
                if component is not None:
                    collect(component, item)
                walk(item, direct_cellblock=False)
            return
        if isinstance(value, (list, tuple)):
            if direct_cellblock and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                component = component_for_key(value[0])
                if component is not None:
                    collect(component, value[1])
                    return
            for item in value:
                walk(item, direct_cellblock=direct_cellblock)

    walk(_mapping_value(event.required, "Cellblock", "CellBlock"), direct_cellblock=True)
    walk(event.required, direct_cellblock=False)
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        walk(_mapping_value(raw_args, "Cellblock", "CellBlock"), direct_cellblock=True)
        walk(raw_args, direct_cellblock=False)
    else:
        walk(raw_args, direct_cellblock=True)
    return bool(starts and ends and starts[-1] > ends[-1])


def _byte_table_where_invalid(event: Any) -> bool:
    if event.columns:
        return True
    where = _mapping_value(event.required, "Where")
    if where is None:
        where = _mapping_value(event.optional, "Where")

    where_values = [where] if where is not None else []
    if where is None:
        raw_args = _method_raw_args(event)
        where_values.extend(_raw_arg_values_by_key(raw_args, "Where"))
    if not where_values:
        return False

    def where_value_invalid(where_value: Any) -> bool:
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(where_value)).lower()
        if _byte_table_where_row_value_invalid(where_value):
            return True
        if _byte_table_where_has_bool_row_address(where_value):
            return True
        if _byte_table_where_has_row_address(where_value):
            offset = _byte_table_where_offset(where_value)
            if offset is not None and offset < 0:
                return True
            return "endrow" in text or "startcolumn" in text or "endcolumn" in text or "column" in text or "table" in text
        row_symbol, uid = _object_ref_from_value(where_value)
        if row_symbol or uid:
            return True
        if "startcolumn" in text or "endcolumn" in text or "column" in text or "table" in text:
            return True
        return bool(_walk_column_values(where_value)) and "row" not in text and "startrow" not in text

    return any(where_value_invalid(value) for value in where_values)


def _byte_table_get_row_negative(event: Any) -> bool:
    row_range = _byte_table_get_range(event)
    return row_range is not None and (row_range[0] < 0 or row_range[1] < 0)


def _byte_table_get_row_value_invalid(event: Any) -> bool:
    def component_for_key(key: Any) -> str | None:
        parsed = _parse_int(key)
        if parsed == 1:
            return "startrow"
        if parsed == 2:
            return "endrow"
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        if text in {"startrow", "row"}:
            return "startrow"
        if text == "endrow":
            return "endrow"
        return None

    def walk(value: Any, *, direct_cellblock: bool = False) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized_key == "cellblock":
                    if walk(item, direct_cellblock=True):
                        return True
                    continue
                component = component_for_key(key)
                if component is not None and _row_number_value_invalid(item):
                    return True
                if walk(item, direct_cellblock=False):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            if direct_cellblock and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                component = component_for_key(value[0])
                return component is not None and _row_number_value_invalid(value[1])
            return any(walk(item, direct_cellblock=direct_cellblock) for item in value)
        return False

    if walk(_mapping_value(event.required, "Cellblock", "CellBlock"), direct_cellblock=True):
        return True
    if walk(event.required, direct_cellblock=False):
        return True
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        if walk(_mapping_value(raw_args, "Cellblock", "CellBlock"), direct_cellblock=True):
            return True
        return walk(raw_args, direct_cellblock=False)
    input_obj = event.raw.get("input", {}) if isinstance(event.raw, dict) else {}
    is_method_call = isinstance(input_obj, dict) and "method" in input_obj
    return walk(raw_args, direct_cellblock=is_method_call)


def _byte_table_get_startrow_uid_invalid(event: Any) -> bool:
    def component_for_key(key: Any) -> str | None:
        parsed = _parse_int(key)
        if parsed == 1:
            return "startrow"
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        if text in {"startrow", "row"}:
            return "startrow"
        return None

    def walk(value: Any, *, direct_cellblock: bool = False) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized_key == "cellblock":
                    if walk(item, direct_cellblock=True):
                        return True
                    continue
                component = component_for_key(key)
                if component == "startrow" and _contains_explicit_uid_option(item):
                    return True
                if walk(item, direct_cellblock=False):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            if direct_cellblock and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                component = component_for_key(value[0])
                return component == "startrow" and _contains_explicit_uid_option(value[1])
            return any(walk(item, direct_cellblock=direct_cellblock) for item in value)
        return False

    if walk(_mapping_value(event.required, "Cellblock", "CellBlock"), direct_cellblock=True):
        return True
    if walk(event.required, direct_cellblock=False):
        return True
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        if walk(_mapping_value(raw_args, "Cellblock", "CellBlock"), direct_cellblock=True):
            return True
        return walk(raw_args, direct_cellblock=False)
    input_obj = event.raw.get("input", {}) if isinstance(event.raw, dict) else {}
    is_method_call = isinstance(input_obj, dict) and "method" in input_obj
    return walk(raw_args, direct_cellblock=is_method_call)


def _byte_table_get_invalid(event: Any) -> bool:
    return (
        _byte_table_where_invalid(event)
        or _byte_table_get_reversed_range(event)
        or _byte_table_get_row_value_invalid(event)
        or _byte_table_get_startrow_uid_invalid(event)
        or _byte_table_raw_args_invalid(event)
        or _byte_table_get_row_negative(event)
    )


def _cellblock_components(event: Any) -> set[str]:
    components: set[str] = set()
    aliases = {
        0: "table",
        1: "startrow",
        2: "endrow",
        3: "startcolumn",
        4: "endcolumn",
        "table": "table",
        "startrow": "startrow",
        "startindex": "startrow",
        "startposition": "startrow",
        "startoffset": "startrow",
        "offset": "startrow",
        "byteoffset": "startrow",
        "index": "startrow",
        "position": "startrow",
        "pos": "startrow",
        "address": "startrow",
        "start": "startrow",
        "row": "startrow",
        "endrow": "endrow",
        "endindex": "endrow",
        "endposition": "endrow",
        "endoffset": "endrow",
        "end": "endrow",
        "length": "endrow",
        "len": "endrow",
        "size": "endrow",
        "count": "endrow",
        "numbytes": "endrow",
        "nbytes": "endrow",
        "bytecount": "endrow",
        "bytelength": "endrow",
        "datalength": "endrow",
        "startcolumn": "startcolumn",
        "startcol": "startcolumn",
        "column": "startcolumn",
        "endcolumn": "endcolumn",
        "endcol": "endcolumn",
    }

    def component_for_key(key: Any) -> str | None:
        parsed = _parse_int(key)
        if parsed in aliases:
            return aliases[parsed]
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        return aliases.get(text)

    def walk(value: Any, *, direct_cellblock: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized_key == "cellblock":
                    walk(item, direct_cellblock=True)
                    continue
                component = component_for_key(key)
                if component is not None and direct_cellblock:
                    components.add(component)
                elif component is not None and normalized_key in aliases:
                    components.add(component)
                walk(item, direct_cellblock=False)
            return
        if isinstance(value, (list, tuple)):
            if direct_cellblock and len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                component = component_for_key(value[0])
                if component is not None:
                    components.add(component)
                    return
            for item in value:
                walk(item, direct_cellblock=direct_cellblock)

    walk(_mapping_value(event.required, "Cellblock", "CellBlock"), direct_cellblock=True)
    walk(event.required, direct_cellblock=False)
    walk(_mapping_value(event.optional, "Cellblock", "CellBlock"), direct_cellblock=True)
    walk(event.optional, direct_cellblock=False)
    input_obj = event.raw.get("input", {}) if isinstance(event.raw, dict) else {}
    is_method_call = isinstance(input_obj, dict) and "method" in input_obj
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        walk(_mapping_value(raw_args, "Cellblock", "CellBlock"), direct_cellblock=True)
        walk(raw_args, direct_cellblock=False)
    elif is_method_call:
        walk(raw_args, direct_cellblock=True)
    return components


def _byte_table_set_row_negative(event: Any) -> bool:
    start_offset = _byte_table_set_start_offset(event)
    return start_offset is not None and start_offset < 0


def _byte_table_set_invalid(event: Any) -> bool:
    return (
        _has_explicit_row_values(event)
        or _byte_table_where_invalid(event)
        or _byte_table_raw_args_invalid(event)
        or _byte_table_set_row_negative(event)
        or not _byte_table_has_payload(event)
    )


def _byte_table_set_mandatory_granularity_invalid(event: Any, granularity: int | None) -> bool:
    if granularity is None or granularity <= 1 or not _byte_table_has_payload(event):
        return False
    start_offset = _byte_table_set_start_offset(event)
    payload_length = _byte_table_payload_length(event)
    if start_offset is None or payload_length is None:
        return False
    return start_offset % granularity != 0 or payload_length % granularity != 0


def _method_raw_args(event: Any) -> Any:
    return _method_args_node(event.raw)


def _bare_authority_symbol(name: Any, method: str, values: dict[int, Any], columns: set[int]) -> str | None:
    authority = _authority_by_name(name) or _authority_from_cpin_name(name)
    if authority is None or authority in {"Anybody", "Admins", "SID", "MSID", "PSID", "TPerSign", "TperAttestation"}:
        return None
    if method == "Set" and values and set(values) <= {5}:
        return f"Authority_{authority}"
    if method == "Get" and (not columns or columns & {5}):
        return f"Authority_{authority}"
    return None


def _empty_payload(value: Any) -> bool:
    return value is None or value == "" or value == b"" or value == () or value == [] or value == {}


def _has_method_payload(event: Any, *names: str) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found and not _empty_payload(value):
            return True
    raw_args = _method_raw_args(event)
    if raw_args is None:
        return False
    if isinstance(raw_args, dict):
        for key, value in raw_args.items():
            if key in {"required", "optional"}:
                continue
            if not _empty_payload(value):
                return True
        return False
    return not _empty_payload(raw_args)


def _is_named_pair(value: Any, names: set[str] | None = None) -> bool:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return False
    if names is None:
        return isinstance(value[0], str) or isinstance(value[0], int)
    return _as_text(value[0]).strip().lower() in names


def _sequence_named_arg_value(raw_args: Any, *names: str) -> tuple[bool, Any]:
    if not isinstance(raw_args, (list, tuple)):
        return False, None
    wanted = {_as_text(name).lower() for name in names}

    def walk(sequence: Any) -> tuple[bool, Any]:
        if not isinstance(sequence, (list, tuple)):
            return False, None
        for item in sequence:
            if isinstance(item, dict):
                for key, value in item.items():
                    if _as_text(key).lower() in wanted:
                        return True, value
                    found, nested = walk(value)
                    if found:
                        return True, nested
            elif isinstance(item, (list, tuple)) and len(item) == 2 and _as_text(item[0]).lower() in wanted:
                return True, item[1]
            else:
                found, nested = walk(item)
                if found:
                    return True, nested
        return False, None

    return walk(raw_args)


def _raw_first_positional_arg(raw_args: Any, named_keys: set[str] | None = None) -> Any:
    if raw_args is None or isinstance(raw_args, dict):
        return None
    if isinstance(raw_args, (list, tuple)):
        if not raw_args:
            return None
        if _is_named_pair(raw_args, named_keys):
            return None
        first = raw_args[0]
        if _is_named_pair(first, named_keys):
            return None
        return first
    return raw_args


def _firmware_attestation_has_nonce(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "AssessorNonce", "Nonce", "Data", "Input")
        if found:
            return not _empty_payload(value)
    raw_args = _method_raw_args(event)
    first = _raw_first_positional_arg(raw_args, {"0", "1", "rtrid", "assessorid", "subname"})
    return not _empty_payload(first)


def _sign_has_payload(event: Any) -> bool:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Data", "Input", "Buffer")
        if found:
            return not _empty_payload(value)
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "Data", "Input", "Buffer")
        if found and not _empty_payload(value):
            return True
        return False
    found, value = _sequence_named_arg_value(raw_args, "Data", "Input", "Buffer")
    if found:
        return not _empty_payload(value)
    first = _raw_first_positional_arg(raw_args)
    return not _empty_payload(first)


def _input_payload_length(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, dict):
        found, payload = _dict_lookup(value, "Data", "Input", "Buffer", "BufferIn", "Bytes", "Payload", "AssessorNonce", "Nonce")
        if found:
            length = _input_payload_length(payload)
            if length is not None:
                return length
        lengths = [_input_payload_length(item) for item in value.values()]
        lengths = [length for length in lengths if length is not None]
        return max(lengths) if lengths else None
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _input_payload_length(value[0])
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return len(value)
        lengths: list[int] = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                if key in {"data", "input", "buffer", "bufferin", "bytes", "payload", "assessornonce", "nonce", "0"}:
                    length = _input_payload_length(item[1])
                    if length is not None:
                        lengths.append(length)
                continue
            length = _input_payload_length(item)
            if length is not None:
                lengths.append(length)
        return max(lengths) if lengths else None
    return None


def _payload_too_long(event: Any, limit: int) -> bool:
    candidates = []
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "Data", "Input", "AssessorNonce", "Nonce")
        if found:
            candidates.append(value)
    raw_args = _method_raw_args(event)
    if not isinstance(raw_args, dict):
        candidates.append(raw_args)
    for value in candidates:
        length = _input_payload_length(value)
        if length is not None and length > limit:
            return True
    return False


def _method_arg_value(event: Any, *names: str) -> Any:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return value
    return raw_args


def _named_method_arg_value(event: Any, *names: str) -> tuple[bool, Any]:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return True, value
    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return True, value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return True, value
    return False, None


def _access_control_positional_args(raw_args: Any) -> list[Any]:
    if raw_args is None or isinstance(raw_args, dict):
        return []
    if not isinstance(raw_args, (list, tuple)):
        return [raw_args]
    if len(raw_args) == 1 and isinstance(raw_args[0], (list, tuple)) and len(raw_args[0]) == 2:
        first, second = raw_args[0]
        if not isinstance(first, dict) and _method_ref_name(second) is not None:
            return [first, second]
    named_keys = {
        _as_text(name).lower()
        for name in (*ACCESS_CONTROL_INVOKING_ARG_NAMES, *ACCESS_CONTROL_METHOD_ARG_NAMES, "ACE", "ace", "ACEID", "ACEId", "ace_id", "aceId")
    }
    positional: list[Any] = []
    for item in raw_args:
        if isinstance(item, (list, tuple)) and len(item) == 2 and _as_text(item[0]).strip().lower() in named_keys:
            continue
        if isinstance(item, dict):
            has_named_key = any(_as_text(key).strip().lower() in named_keys for key in item)
            if has_named_key:
                continue
        positional.append(item)
    return positional


def _access_control_arg_values(event: Any) -> tuple[tuple[bool, Any], tuple[bool, Any]]:
    raw_args = _method_raw_args(event)
    positional = _access_control_positional_args(raw_args)
    if (
        isinstance(raw_args, (list, tuple))
        and len(raw_args) == 1
        and isinstance(raw_args[0], (list, tuple))
        and len(raw_args[0]) == 2
        and len(positional) >= 2
    ):
        return (True, positional[0]), (True, positional[1])
    found_invoking, invoking_value = _named_method_arg_value(event, *ACCESS_CONTROL_INVOKING_ARG_NAMES)
    found_method, method_value = _named_method_arg_value(event, *ACCESS_CONTROL_METHOD_ARG_NAMES)
    if not found_invoking and len(positional) >= 1:
        found_invoking, invoking_value = True, positional[0]
    if not found_method and len(positional) >= 2:
        found_method, method_value = True, positional[1]
    return (found_invoking, invoking_value), (found_method, method_value)


def _raw_arg_value(required: dict[str, Any], optional: dict[str, Any], raw_args: Any, *names: str) -> Any:
    for source in (required, optional):
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, *names)
        if found:
            return value
    found, value = _sequence_named_arg_value(raw_args, *names)
    if found:
        return value
    return None


def _recursive_named_value(value: Any, *names: str) -> Any:
    if isinstance(value, dict):
        found, item = _dict_lookup(value, *names)
        if found:
            return item
        for item in value.values():
            nested = _recursive_named_value(item, *names)
            if nested is not None:
                return nested
    elif isinstance(value, (list, tuple)):
        found, item = _sequence_named_arg_value(value, *names)
        if found:
            return item
        for item in value:
            nested = _recursive_named_value(item, *names)
            if nested is not None:
                return nested
    return None


HOST_PROPERTY_INITIALS: dict[str, Any] = {
    "MaxSubpackets": 1,
    "MaxPacketSize": 1004,
    "MaxPackets": 1,
    "MaxComPacketSize": 1024,
    "MaxIndTokenSize": 968,
    "MaxAggTokenSize": 968,
    "MaxMethods": 1,
    "ContinuedTokens": False,
    "SequenceNumbers": False,
    "AckNak": False,
    "Asynchronous": False,
}

OPAL_HOST_PROPERTY_INITIALS: dict[str, Any] = {
    "MaxSubpackets": 1,
    "MaxPacketSize": 2028,
    "MaxPackets": 1,
    "MaxComPacketSize": 2048,
    "MaxIndTokenSize": 1992,
    "MaxMethods": 1,
}

HOST_PROPERTY_ALIASES: dict[str, str] = {
    "MAXSUBPACKETS": "MaxSubpackets",
    "MAXPACKETSIZE": "MaxPacketSize",
    "MAXPACKETS": "MaxPackets",
    "MAXCOMPACKETSIZE": "MaxComPacketSize",
    "MAXINDTOKENSIZE": "MaxIndTokenSize",
    "MAXAGGTOKENSIZE": "MaxAggTokenSize",
    "MAXMETHODS": "MaxMethods",
    "CONTINUEDTOKENS": "ContinuedTokens",
    "SEQUENCENUMBERS": "SequenceNumbers",
    "ACKNAK": "AckNak",
    "ASYNCHRONOUS": "Asynchronous",
}

TPER_PROPERTY_ALIASES: dict[str, str] = {
    **HOST_PROPERTY_ALIASES,
    "DEFSESSIONTIMEOUT": "DefSessionTimeout",
    "DEFAULTSESSIONTIMEOUT": "DefSessionTimeout",
    "MAXSESSIONTIMEOUT": "MaxSessionTimeout",
    "MINSESSIONTIMEOUT": "MinSessionTimeout",
    "DEFTRANSTIMEOUT": "DefTransTimeout",
    "DEFAULTTRANSTIMEOUT": "DefTransTimeout",
    "MAXTRANSTIMEOUT": "MaxTransTimeout",
    "MINTRANSTIMEOUT": "MinTransTimeout",
    "MAXCOMIDTIME": "MaxComIDTime",
}


def _host_property_name(value: Any) -> str | None:
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return HOST_PROPERTY_ALIASES.get(key)


def _tper_property_name(value: Any) -> str | None:
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).upper()
    return TPER_PROPERTY_ALIASES.get(key)


def _host_property_initials() -> dict[str, Any]:
    return dict(HOST_PROPERTY_INITIALS)


def _opal_host_property_initials() -> dict[str, Any]:
    return dict(OPAL_HOST_PROPERTY_INITIALS)


def _host_property_entries(value: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def add(name: Any, item: Any) -> None:
        prop = _host_property_name(name)
        if prop is not None:
            out[prop] = item

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for host_key in ("HostProperties", "hostProperties", "HOSTPROPERTIES"):
                found, nested = _dict_lookup(item, host_key)
                if found:
                    walk(nested)
                    return
            row_name = None
            row_value = None
            for key, value in item.items():
                normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key or "")).upper()
                if normalized in {"PROPERTY", "PROPERTYNAME", "NAME", "KEY"}:
                    row_name = value
                elif normalized in {"VALUE", "PROPERTYVALUE", "VAL"}:
                    row_value = value
            if row_name is not None and row_value is not None:
                add(row_name, row_value)
                return
            for key, nested in item.items():
                add(key, nested)
                if _host_property_name(key) is None:
                    walk(nested)
            return
        if isinstance(item, (list, tuple)):
            if len(item) == 2 and not isinstance(item[0], (dict, list, tuple, set)):
                add(item[0], item[1])
                return
            for nested in item:
                walk(nested)

    walk(value)
    return out


def _submitted_host_properties(event: Event) -> dict[str, Any]:
    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, "HostProperties", "hostProperties", "HOSTPROPERTIES")
        if found:
            return _host_property_entries(value)
    found, value = _dict_lookup(_method_raw_args(event), "HostProperties", "hostProperties", "HOSTPROPERTIES") if isinstance(_method_raw_args(event), dict) else (False, None)
    if found:
        return _host_property_entries(value)
    raw = _method_raw_args(event)
    found, value = _sequence_named_arg_value(raw, "HostProperties", "hostProperties", "HOSTPROPERTIES")
    if found:
        return _host_property_entries(value)
    return {}


def _host_properties_parameter_present(event: Event) -> bool:
    for source in (event.required, event.optional):
        found, _ = _dict_lookup(source, "HostProperties", "hostProperties", "HOSTPROPERTIES")
        if found:
            return True
    raw = _method_raw_args(event)
    if isinstance(raw, dict):
        found, _ = _dict_lookup(raw, "HostProperties", "hostProperties", "HOSTPROPERTIES")
        if found:
            return True
    found, _ = _sequence_named_arg_value(raw, "HostProperties", "hostProperties", "HOSTPROPERTIES")
    return found


def _returned_host_properties(value: Any) -> dict[str, Any]:
    return _host_property_entries(value)


def _returned_tper_properties(value: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def add(name: Any, item: Any) -> None:
        prop = _tper_property_name(name)
        if prop is not None:
            out[prop] = item

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            found, nested = _dict_lookup(item, "Properties", "properties", "TPERProperties", "TPerProperties")
            if found:
                walk(nested)
                return
            host_found, _ = _dict_lookup(item, "HostProperties", "hostProperties", "HOSTPROPERTIES")
            if host_found:
                return
            row_name = None
            row_value = None
            for key, nested in item.items():
                normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key or "")).upper()
                if normalized in {"PROPERTY", "PROPERTYNAME", "NAME", "KEY"}:
                    row_name = nested
                elif normalized in {"VALUE", "PROPERTYVALUE", "VAL"}:
                    row_value = nested
            if row_name is not None and row_value is not None:
                add(row_name, row_value)
                return
            for key, nested in item.items():
                add(key, nested)
                if _tper_property_name(key) is None:
                    walk(nested)
            return
        if isinstance(item, (list, tuple)):
            if len(item) == 2 and not isinstance(item[0], (dict, list, tuple, set)):
                add(item[0], item[1])
                return
            for nested in item:
                walk(nested)

    walk(value)
    return out


def _session_id_key(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    text = _as_text(value).strip()
    if not text:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if compact and re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", text.replace("_", "").replace("-", "")):
        return str(int(compact, 16))
    return text


def _start_session_positional(raw_args: Any) -> tuple[Any, Any, Any, Any]:
    if not isinstance(raw_args, (list, tuple)) or _is_named_pair(raw_args):
        return None, None, None, None
    if raw_args and _is_named_pair(raw_args[0]):
        return None, None, None, None
    spid = None
    write = None
    if len(raw_args) >= 3:
        spid, write = raw_args[1], raw_args[2]
    elif len(raw_args) >= 2 and _sp_from_value(raw_args[0]) is not None:
        spid, write = raw_args[0], raw_args[1]
    else:
        return None, None, None, None

    authority = None
    challenge = None
    for item in raw_args[3:]:
        parsed_authority = _authority_from_value(item)
        if parsed_authority is not None and authority is None:
            authority = item
            continue
        if challenge is None:
            challenge = item
    return spid, write, authority, challenge


def _authenticate_authority_arg(raw_args: Any) -> Any:
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "Authority", "HostSigningAuthority", "AuthAs", "authAs")
        if found:
            return value
    if not isinstance(raw_args, (list, tuple)):
        return None

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            found, item = _dict_lookup(value, "Authority", "HostSigningAuthority", "AuthAs", "authAs")
            if found:
                return item
            for item in value.values():
                found = walk(item)
                if found is not None:
                    return found
            return None
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and _as_text(value[0]).lower() in {"0", "challenge", "hostchallenge"}:
                return None
            for item in value:
                if _authority_from_value(item) is not None:
                    return item
                found = walk(item)
                if found is not None:
                    return found
        else:
            if _authority_from_value(value) is not None:
                return value
        return None

    return walk(raw_args)


def _authenticate_challenge_arg(raw_args: Any, authority_value: Any = None) -> Any:
    if not isinstance(raw_args, (list, tuple)) or _is_named_pair(raw_args):
        return None
    if authority_value is not None:
        for item in raw_args:
            if item is authority_value:
                continue
            if item == authority_value:
                continue
            if _authority_from_value(item) is None:
                return item
    for item in raw_args:
        if _authority_from_value(item) is None:
            return item
    return None


def _authas_credential_arg(required: dict[str, Any], optional: dict[str, Any], raw_args: Any) -> Any:
    def from_value(value: Any) -> Any:
        if isinstance(value, dict):
            found, item = _dict_lookup(value, "AuthAs", "authAs")
            if found:
                return from_value(item)
            found, item = _dict_lookup(
                value,
                "Credential",
                "credential",
                "Cred",
                "cred",
                "PIN",
                "pin",
                "Proof",
                "proof",
                "HostChallenge",
                "Challenge",
                "plainText",
                "PlainText",
            )
            if found:
                return item
            authority = _authority_from_value(_mapping_value(value, "Authority", "HostSigningAuthority", "auth", "Auth"))
            if authority is not None:
                found, item = _dict_lookup(value, "Value", "value")
                if found:
                    return item
            for item in value.values():
                found = from_value(item)
                if found is not None:
                    return found
            return None
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower() in {"authas", "hostsigningauthority"}:
                return from_value(value[1])
            if len(value) >= 2 and _authority_from_value(value[0]) is not None:
                return value[1]
            if len(value) >= 2 and _unspecified_authority(value[0]):
                return value[1]
            for item in value:
                found = from_value(item)
                if found is not None:
                    return found
        return None

    for source in (required, optional):
        found, value = _dict_lookup(source, "AuthAs", "authAs")
        if found:
            credential = from_value(value)
            if credential is not None:
                return credential
    if isinstance(raw_args, dict):
        credential = from_value(raw_args)
        if credential is not None:
            return credential
    return from_value(raw_args)


def _unspecified_authority(value: Any) -> bool:
    if value is None:
        return True
    text = _as_text(value).strip().lower()
    return text in {"", "none", "null"}


def _authas_pairs(required: dict[str, Any], optional: dict[str, Any], raw_args: Any) -> list[tuple[str | None, Any]]:
    sources: list[Any] = []
    for source in (required, optional):
        found, value = _dict_lookup(source, "AuthAs", "authAs")
        if found:
            sources.append(value)
    if isinstance(raw_args, dict):
        found, value = _dict_lookup(raw_args, "AuthAs", "authAs")
        if found:
            sources.append(value)
    found, value = _sequence_named_arg_value(raw_args, "AuthAs", "authAs")
    if found:
        sources.append(value)

    pairs: list[tuple[str | None, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            found, nested = _dict_lookup(value, "AuthAs", "authAs")
            if found:
                walk(nested)
                return
            found_authority, raw_authority = _dict_lookup(value, "Authority", "HostSigningAuthority", "auth", "Auth")
            authority = _authority_from_value(raw_authority) if found_authority else None
            credential = _authas_credential_arg({}, {"authAs": value}, None)
            if authority is not None and credential is not None:
                pairs.append((authority, credential))
                return
            if found_authority and _unspecified_authority(raw_authority) and credential is not None:
                pairs.append((None, credential))
                return
            for item in value.values():
                walk(item)
            return
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower() in {"authas", "hostsigningauthority"}:
                walk(value[1])
                return
            if len(value) >= 2 and not isinstance(value[0], (dict, list, tuple, set)):
                authority = _authority_from_value(value[0])
                if authority is not None:
                    pairs.append((authority, value[1]))
                    return
                if _unspecified_authority(value[0]):
                    pairs.append((None, value[1]))
                    return
            for item in value:
                walk(item)

    for source in sources:
        walk(source)
    return pairs


def _random_count(event: Any) -> int | None:
    value = _method_arg_value(event, "Count", "count")
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    if isinstance(value, bool):
        return None
    return _parse_int(value)


def _next_count_invalid(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "Count", "count")
    if not found:
        return False
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            return True
        value = value[0]
    if isinstance(value, bool):
        return True
    parsed = _parse_int(value)
    return parsed is None or parsed < 0


def _uid_arg(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("uid", "UID", "row", "Row", "object", "Object"):
            uid = _clean_uid(_mapping_value(value, key))
            if uid:
                return uid
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _uid_arg(value[0])
    return _clean_uid(value)


def _uid_ref(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, bytes, bytearray)):
        return _clean_uid(value)
    text = _as_text(value).strip()
    if not text or not re.fullmatch(r"(?:0x)?[0-9A-Fa-f\s:_-]+", text):
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
    return cleaned.zfill(16)[-16:] if cleaned else ""


def _object_ref_from_value(value: Any) -> tuple[str, str]:
    if isinstance(value, dict):
        name = ""
        for key in ("name", "Name", "symbol", "Symbol"):
            found, name_value = _dict_lookup(value, key)
            if found:
                name = _as_text(name_value)
                break
        for key in (
            "uid",
            "UID",
            "row",
            "Row",
            "object",
            "Object",
            "objectID",
            "ObjectID",
            "object_id",
            "ObjectUID",
            "object_uid",
            "table",
            "Table",
            "TableUID",
            "table_uid",
            "target",
            "Target",
            "TargetID",
            "target_id",
            "TargetUID",
            "target_uid",
        ):
            found, raw_uid = _dict_lookup(value, key)
            if found:
                uid = _uid_ref(raw_uid)
                if uid:
                    return _object_by_uid(uid, name), uid
                symbol, nested_uid = _object_ref_from_value(raw_uid)
                if symbol or nested_uid:
                    return symbol, nested_uid
        if name:
            return _normalize_name(name), ""
        for item in value.values():
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    if isinstance(value, (list, tuple)):
        if len(value) == 1:
            return _object_ref_from_value(value[0])
        for item in value:
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    if isinstance(value, set):
        for item in sorted(value, key=str):
            symbol, uid = _object_ref_from_value(item)
            if symbol or uid:
                return symbol, uid
        return "", ""
    symbol = _normalize_name(value)
    if _known_opal_object_symbol(symbol):
        return symbol, ""
    uid = _uid_ref(value)
    if uid:
        return _object_by_uid(uid), uid
    return symbol, ""


def _known_opal_object_symbol(symbol: str, uid: str = "") -> bool:
    if not symbol:
        return False
    if uid and not symbol.startswith("UnknownSP_"):
        return True
    if symbol in set(FIXED_OBJECT_BY_UID.values()) | {
        "Table",
        "SPInfo",
        "ColumnTable",
        "TypeTable",
        "Table_TPerInfo",
        "Table_Template",
        "MethodIDTable",
        "AccessControlTable",
        "ACETable",
        "AuthorityTable",
        "C_PINTable",
        "SecretProtectTable",
        "LockingTable",
        "MBR",
        "DataStore",
        "DataRemovalMechanism",
        "MBRControl",
        "LockingInfo",
        "TPerSign",
        "TperAttestation",
        "TPerInfo",
    }:
        return True
    if _is_table_symbol(symbol) or _is_byte_table_symbol(symbol):
        return True
    return bool(
        re.fullmatch(r"(C_PIN|Authority)_(SID|MSID|PSID|Admins|Makers|EraseMaster|BandMaster\d+|Admin\d+|User\d+)", symbol)
        or re.fullmatch(r"Locking_(GlobalRange|Range\d+)", symbol)
        or re.fullmatch(r"K_AES_(128|256)_(GlobalRange|Range\d+)_Key", symbol)
        or re.fullmatch(r"TLS_PSK_Key\d+", symbol)
        or re.fullmatch(r"Port\d+", symbol)
        or re.fullmatch(r"ACE_[0-9A-F]{8}", symbol)
        or re.fullmatch(r"ACE_DataStore\d+_(Get|Set)_All", symbol)
        or symbol.startswith("AccessControl_")
        or symbol.startswith("MethodID_")
        or symbol.startswith("SecretProtect_")
        or symbol.startswith("SPTemplates_")
        or symbol.startswith("Template_")
    )


def _table_family(symbol: str) -> str:
    aliases = {
        "MethodIDTable": "MethodID",
        "AccessControlTable": "AccessControl",
        "ColumnTable": "Column",
        "TypeTable": "Type",
        "ACETable": "ACE",
        "AuthorityTable": "Authority",
        "C_PINTable": "C_PIN",
        "SecretProtectTable": "SecretProtect",
        "LockingTable": "Locking",
        "SPTemplatesTable": "SPTemplates",
        "TemplateTable": "Template",
        "SPTable": "SP",
        "K_AES_128Table": "K_AES_128",
        "K_AES_256Table": "K_AES_256",
    }
    if symbol in aliases:
        return aliases[symbol]
    if symbol.startswith("Table_"):
        return symbol.removeprefix("Table_")
    if symbol.endswith("Table"):
        return symbol.removesuffix("Table")
    return symbol


def _next_where_invalid(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "Where", "where")
    if not found:
        return False
    row_symbol, uid = _object_ref_from_value(value)
    if not uid and not row_symbol:
        return True
    if _is_byte_table_uid(uid) or _is_byte_table_symbol(row_symbol):
        return True

    family = _table_family(event.invoking_symbol)
    if family == "Table":
        return not row_symbol.startswith("Table_")
    if family == "MethodID":
        return _method_by_uid(uid) is None and _method_ref_name(value) not in set(METHOD_UIDS.values())
    if family == "C_PIN":
        return not row_symbol.startswith("C_PIN_")
    if family == "Locking":
        return not row_symbol.startswith("Locking_")
    if family == "K_AES_128":
        return not row_symbol.startswith("K_AES_128_")
    if family == "K_AES_256":
        return not row_symbol.startswith("K_AES_256_")
    if family == "Authority":
        authority = _authority_from_value(value)
        if authority is not None:
            row_symbol = f"Authority_{authority}"
        return not row_symbol.startswith("Authority_")
    if family == "ACE":
        return not row_symbol.startswith("ACE_")
    if family == "AccessControl":
        return not (row_symbol.startswith("AccessControl_") or (uid.startswith("00000007") and uid != "0000000700000000"))
    if family == "SecretProtect":
        return not row_symbol.startswith("SecretProtect_")
    if family == "SPTemplates":
        return not row_symbol.startswith("SPTemplates_")
    if family == "Template":
        return not row_symbol.startswith("Template_")
    if family == "SP":
        return not (row_symbol in {"AdminSP", "LockingSP"} or row_symbol.startswith("UnknownSP_") or uid.startswith("00000205"))
    if row_symbol.startswith("UnknownSP_") or _is_byte_table_symbol(row_symbol):
        return True
    return False


def _keep_global_range_key(event: Any) -> bool:
    found, value = _named_method_arg_value(event, "KeepGlobalRangeKey", "KeepGlobalRange", "060000", "0x060000", "393216")
    if found:
        return _as_bool(value)

    raw_args = _method_raw_args(event)
    if isinstance(raw_args, (list, tuple)):
        for item in raw_args:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            key, value = item
            if _parse_int(key) == 0x060000 or re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower() == "keepglobalrangekey":
                return _as_bool(value)
    return False


def _flatten_return_values(value: Any, symbol: str = "") -> dict[int, Any]:
    returned = _walk_column_values(value)
    returned.update(_walk_named_column_values(value, symbol))
    return returned


def _cellblock_columns(required: dict[str, Any], raw_args: Any = None, method: str = "", symbol: str = "") -> set[int]:
    columns: set[int] = set()

    def add_bounds(start: int | None, end: int | None) -> None:
        if start is not None and end is not None:
            columns.update(range(min(start, end), max(start, end) + 1))
        elif start is not None:
            columns.add(start)
        elif end is not None:
            columns.add(end)

    def bounds_from_mapping(item: dict[str, Any]) -> tuple[int | None, int | None]:
        start: int | None = None
        end: int | None = None
        found, start_value = _dict_lookup(item, "startColumn", "StartColumn", "start_column", "startCol", "StartCol")
        if found:
            start = _parse_int(start_value)
            if start is None:
                start = _column_from_name(start_value, symbol)
        found, end_value = _dict_lookup(item, "endColumn", "EndColumn", "end_column", "endCol", "EndCol")
        if found:
            end = _parse_int(end_value)
            if end is None:
                end = _column_from_name(end_value, symbol)
        return start, end

    def add_from_cellblock(cellblock: Any) -> None:
        if isinstance(cellblock, dict):
            cellblock = [cellblock]
        if not isinstance(cellblock, list):
            return
        start: int | None = None
        end: int | None = None
        for item in cellblock:
            if not isinstance(item, dict):
                continue
            item_start, item_end = bounds_from_mapping(item)
            start = item_start if item_start is not None else start
            end = item_end if item_end is not None else end
        add_bounds(start, end)

    add_from_cellblock(_mapping_value(required, "Cellblock", "CellBlock"))
    add_bounds(*bounds_from_mapping(required))

    if raw_args is not None:
        if isinstance(raw_args, dict):
            add_from_cellblock(_mapping_value(raw_args, "Cellblock", "CellBlock"))
            add_bounds(*bounds_from_mapping(raw_args))
        found_start, raw_start = _sequence_named_arg_value(raw_args, "startColumn", "StartColumn", "start_column", "startCol", "StartCol")
        found_end, raw_end = _sequence_named_arg_value(raw_args, "endColumn", "EndColumn", "end_column", "endCol", "EndCol")
        if found_start or found_end:
            add_bounds(_parse_int(raw_start) if found_start else None, _parse_int(raw_end) if found_end else None)
        if method == "Get" and not isinstance(raw_args, dict):
            start: int | None = None
            end: int | None = None

            def walk_no_named(value: Any) -> None:
                nonlocal start, end
                if isinstance(value, dict):
                    for key, val in value.items():
                        parsed = _parse_int(key)
                        if parsed == 3:
                            start = _parse_int(val)
                        elif parsed == 4:
                            end = _parse_int(val)
                        else:
                            walk_no_named(val)
                    return
                if isinstance(value, (list, tuple)):
                    if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                        parsed = _parse_int(value[0])
                        if parsed == 3:
                            start = _parse_int(value[1])
                            return
                        if parsed == 4:
                            end = _parse_int(value[1])
                            return
                    for item in value:
                        walk_no_named(item)

            walk_no_named(raw_args)
            add_bounds(start, end)

    return columns


def _parse_lba(text: Any) -> tuple[int, int] | None:
    if text is None:
        return None
    nums = [
        parsed
        for token in re.findall(r"0x[0-9A-Fa-f]+|\d+", _as_text(text))
        for parsed in [_parse_int(token)]
        if parsed is not None
    ]
    if not nums:
        return None
    if len(nums) == 1:
        return nums[0], nums[0]
    return min(nums[0], nums[1]), max(nums[0], nums[1])


def _lba_from_args(args: dict[str, Any]) -> tuple[int, int] | None:
    direct = _mapping_value(args, "LBA", "lba", "Lba", "lba_range", "lbaRange", "LBARange", "LbaRange", "range", "Range")
    parsed = _parse_lba(direct)
    if parsed is not None:
        return parsed

    start = _mapping_value(
        args,
        "start_lba",
        "StartLBA",
        "startLBA",
        "startLba",
        "lba_start",
        "LBAStart",
        "lbaStart",
        "start_block",
        "startBlock",
        "StartBlock",
        "offset",
        "Offset",
        "start",
        "Start",
    )
    end = _mapping_value(args, "end_lba", "EndLBA", "endLBA", "endLba", "lba_end", "LBAEnd", "lbaEnd", "end_block", "endBlock", "EndBlock", "end", "End")
    length = _mapping_value(
        args,
        "num_blocks",
        "NumBlocks",
        "numBlocks",
        "block_count",
        "BlockCount",
        "blockCount",
        "lba_count",
        "LBACount",
        "lbaCount",
        "sector_count",
        "SectorCount",
        "sectorCount",
        "count",
        "Count",
        "length",
        "Length",
        "sectors",
        "Sectors",
    )
    start_int = _parse_int(start)
    end_int = _parse_int(end)
    length_int = _parse_int(length)
    if start_int is None:
        return None
    if end_int is not None:
        return min(start_int, end_int), max(start_int, end_int)
    if length_int is not None and length_int > 0:
        return start_int, start_int + length_int - 1
    return start_int, start_int


def _extract_pattern(text: Any) -> str | None:
    if text is None:
        return None
    if isinstance(text, (bytes, bytearray)):
        return bytes(text).hex().upper()
    if isinstance(text, (list, tuple)) and text:
        if all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in text):
            return bytes(text).hex().upper()
        hex_items: list[str] = []
        for item in text:
            if not isinstance(item, str):
                hex_items = []
                break
            compact_item = re.sub(r"[\s:_-]", "", item.strip())
            if compact_item.lower().startswith("0x"):
                compact_item = compact_item[2:]
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", compact_item):
                hex_items = []
                break
            hex_items.append(compact_item.upper())
        if hex_items:
            return "".join(hex_items)
    value = _as_text(text).strip()
    match = re.search(r"Pattern\s+([0-9A-Fa-f]+)", value)
    if match:
        return match.group(1).upper()
    if re.fullmatch(r"b(['\"]).*\1", value):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            parsed = None
        if isinstance(parsed, (bytes, bytearray)):
            return bytes(parsed).hex().upper()
    compact = re.sub(r"[\s:_-]", "", value)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return compact.upper()
    return None


def _host_status(output: dict[str, Any]) -> str | None:
    status_value = _mapping_value(output, "status_codes", "statusCodes", "StatusCodes", "status", "Status")
    host_status = _normalize_host_io_status(status_value)
    if host_status is not None:
        return host_status
    status = _normalize_status(status_value)
    if status in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
        return status
    if status is not None:
        return status
    output_args = _mapping_section(output, "args", "Args")
    result = _mapping_value(output_args, "result", "Result")
    if result is None:
        result = _mapping_value(output, "result", "Result")
    host_status = _normalize_host_io_status(result)
    if host_status is not None:
        return host_status
    normalized = _normalize_status(result)
    if normalized in {FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS}:
        return normalized
    for payload_name in (
        "return",
        "Return",
        "return_value",
        "ReturnValue",
        "returnValue",
        "payload",
        "Payload",
        "response",
        "Response",
        "error",
        "Error",
    ):
        payload = _mapping_value(output, payload_name)
        host_status = _normalize_host_io_status(payload)
        if host_status is not None:
            return host_status
        normalized = _normalize_status(payload)
        if normalized in {FAIL, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS}:
            return normalized
    return None


def _output_status_value(output: dict[str, Any], inp: dict[str, Any] | None = None) -> Any:
    status_names = (
        "status_codes",
        "statusCodes",
        "StatusCodes",
        "status_code",
        "statusCode",
        "StatusCode",
        "code",
        "Code",
        "rc",
        "RC",
        "returnCode",
        "ReturnCode",
        "status",
        "Status",
    )
    value = _mapping_value(output, *status_names)
    if value is not None:
        return value
    if inp is not None:
        value = _mapping_value(inp, *status_names)
        if value is not None:
            return value
    for returned_name in ("return", "Return", "returns", "Returns", "return_value", "ReturnValue", "returnValue", "return_values", "ReturnValues", "returnValues", "values", "Values"):
        found, returned = _dict_lookup(output, returned_name)
        if found and isinstance(returned, (list, tuple)) and returned:
            if _extract_pattern(returned) is not None:
                continue
            if isinstance(returned[0], int) and not isinstance(returned[0], bool):
                if returned[0] == 0:
                    return SUCCESS
                continue
            if not isinstance(returned[0], (str, bytes, bytearray)):
                continue
            normalized = _normalize_status(returned[0])
            if normalized in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
                return normalized
    output_args = _mapping_section(output, "args", "Args")
    for source in (output_args, output):
        candidate = _mapping_value(source, "result", "Result")
        normalized = _normalize_status(candidate)
        if normalized in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
            return normalized
    return None


def _output_return_values(raw: dict[str, Any]) -> Any:
    def preserve_function_return_list(alias: str, returned: Any) -> bool:
        if alias in {"getnext", "next", "nextrows", "listnext", "nextuids", "getnextuids", "readnext", "fetchnext", "enumeratenext", "listrows", "scannext", "fetchrows", "readrows", "enumeraterows", "listuids", "scanrows"}:
            return isinstance(returned, (list, tuple))
        if alias in {"getfreerows", "freerows", "tablequery", "querytable", "queryfreerows", "availablerows", "getavailablerows", "remainingrows", "freerowcount", "availablerowcount", "getremainingrows"}:
            return isinstance(returned, (list, tuple))
        if alias in {"getacl", "readacl", "fetchacl", "queryacl", "listacl", "getobjectacl", "getmethodacl", "getassociationacl", "getaccesscontrollist", "getacelist", "getaclentries", "readaclentries", "fetchaclentries", "fetchacelist", "listaces", "listaceentries", "acl", "accesscontrolacl", "getaccesscontrolacl"}:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getmbrcontrol",
            "mbrcontrol",
            "readmbrcontrol",
            "getmbr",
            "readmbr",
            "fetchmbr",
            "getmbrbytes",
            "readmbrbytes",
            "fetchmbrbytes",
            "getmbrdata",
            "readmbrdata",
            "fetchmbrdata",
            "getmbrpayload",
            "readmbrpayload",
            "fetchmbrpayload",
            "getmbrshadow",
            "readmbrshadow",
            "fetchmbrshadow",
            "getmbrshadowbytes",
            "readmbrshadowbytes",
            "fetchmbrshadowbytes",
            "getmbrtable",
            "readmbrtable",
            "fetchmbrtable",
            "getmbrblock",
            "readmbrblock",
            "fetchmbrblock",
            "getmbrsegment",
            "readmbrsegment",
            "fetchmbrsegment",
            "getmbrrange",
            "readmbrrange",
            "fetchmbrrange",
            "getmbrchunk",
            "readmbrchunk",
            "fetchmbrchunk",
            "getmbrwindow",
            "readmbrwindow",
            "fetchmbrwindow",
            "getmbrslice",
            "readmbrslice",
            "fetchmbrslice",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {"getpskentry", "readpskentry", "fetchpskentry", "getpsk", "readpsk", "fetchpsk", "pskentry", "getpresharedkey", "readpresharedkey", "fetchpresharedkey"}:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getpackage",
            "getcredentialpackage",
            "getkeypackage",
            "exportcredential",
            "exportcredentialpackage",
            "readcredentialpackage",
            "exportpackage",
            "exportkeypackage",
            "exportpin",
            "exportpinpackage",
            "exportcredentialbackup",
            "exportkeybackup",
            "exportwrappedkey",
            "exportkey",
            "wrappackage",
            "wrapkey",
            "wrapkeypackage",
            "getwrappedpackage",
            "getwrappedkey",
            "backuppackage",
            "backupkeypackage",
            "backupcredential",
            "backupcredentialpackage",
            "backuppin",
            "backuppinpackage",
            "getpinpackage",
            "getcredentialbackup",
            "readcredentialbackup",
            "fetchcredentialbackup",
            "readkeybackup",
            "readpackage",
            "readkeypackage",
            "dumppackage",
            "dumpcredentialpackage",
            "dumpkeypackage",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "randombytes",
            "getrandombytes",
            "generaterandombytes",
            "generaterandom",
            "getrandom",
            "rng",
            "getrng",
            "rngbytes",
            "readrandom",
            "fetchrandom",
            "randombuffer",
            "getentropy",
            "generateentropy",
            "entropybytes",
            "random",
            "randomdata",
            "randombytesout",
            "getrandomdata",
            "hash",
            "hashupdate",
            "updatehash",
            "hashdata",
            "computehash",
            "digest",
            "hashbytes",
            "updatedigest",
            "sha256update",
            "hashbuffer",
            "processhash",
            "hashfinal",
            "finalhash",
            "hashfinalize",
            "hashfinish",
            "completehash",
            "finishhash",
            "finalizehash",
            "finishdigest",
            "digestfinal",
            "completedigest",
            "sha256final",
            "hmac",
            "hmacupdate",
            "hmacdata",
            "updatehmac",
            "computehmac",
            "hmacbytes",
            "macupdate",
            "updatemac",
            "processhmac",
            "hmacdigest",
            "hmacfinal",
            "hmacfinalize",
            "finishhmac",
            "finalhmac",
            "finalizehmac",
            "hmacfinish",
            "completehmac",
            "finishmac",
            "macfinal",
            "finalizemac",
            "encrypt",
            "encryptdata",
            "updateencrypt",
            "encryptbytes",
            "encryptbuffer",
            "processencrypt",
            "doencrypt",
            "encryptfinal",
            "encryptfinalize",
            "finishencrypt",
            "finalencrypt",
            "finalizeencrypt",
            "encryptfinish",
            "completeencrypt",
            "decrypt",
            "decryptdata",
            "updatedecrypt",
            "decryptbytes",
            "decryptbuffer",
            "processdecrypt",
            "dodecrypt",
            "decryptfinal",
            "decryptfinalize",
            "finishdecrypt",
            "finaldecrypt",
            "finalizedecrypt",
            "decryptfinish",
            "completedecrypt",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getattestationcert",
            "getattestationcertificate",
            "readtperattestationcert",
            "readattestationcert",
            "fetchattestationcert",
            "gettpercert",
            "getsigncert",
            "getsigningcert",
            "gettpersigningcert",
            "gettpercertsign",
            "readtpersigncert",
            "readsigncert",
            "fetchsigncert",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "tpersign",
            "signdata",
            "tpersigndata",
            "sign",
            "signbytes",
            "signpayload",
            "signmessage",
            "signdigest",
            "createsignature",
            "generatesignature",
            "makesignature",
            "signaturecreate",
            "signaturegenerate",
            "tpersignpayload",
            "firmwareattestation",
            "firmwareattest",
            "attestfirmware",
            "getfirmwareattestation",
            "firmwarequote",
            "getfirmwarequote",
            "quotefirmware",
            "attestation",
            "getattestation",
            "readattestation",
            "fetchattestation",
            "gettperattestation",
            "readtperattestation",
            "fetchtperattestation",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getmbrdoneonreset",
            "readmbrdoneonreset",
            "fetchmbrdoneonreset",
            "querymbrdoneonreset",
            "loadmbrdoneonreset",
            "getdoneonreset",
            "readdoneonreset",
            "fetchdoneonreset",
            "querydoneonreset",
            "loaddoneonreset",
            "getmbrdor",
            "readmbrdor",
            "fetchmbrdor",
            "querymbrdor",
            "loadmbrdor",
            "getmbrresettypes",
            "readmbrresettypes",
            "fetchmbrresettypes",
            "querymbrresettypes",
            "loadmbrresettypes",
            "ismbrdoneonreset",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getlockonreset",
            "getrangelockonreset",
            "getlockingrangelockonreset",
            "getlor",
            "getrangelor",
            "getresettypes",
            "getrangeresettypes",
            "getlockonresettypes",
            "getrangelockonresettypes",
            "getlockingrangeresettypes",
            "readlockonreset",
            "readrangelockonreset",
            "fetchlockonreset",
            "fetchrangelockonreset",
            "querylockonreset",
            "queryrangelockonreset",
            "loadlockonreset",
            "loadrangelockonreset",
            "readlor",
            "readrangelor",
            "fetchlor",
            "fetchrangelor",
            "querylor",
            "queryrangelor",
            "loadlor",
            "loadrangelor",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "readdata",
            "readdatastore",
            "getdata",
        }:
            return isinstance(returned, (list, tuple))
        if alias in {
            "getrange",
            "lockinginfo",
            "getlockinginfo",
        }:
            return isinstance(returned, (list, tuple))
        if alias not in {"createlog", "newlog", "makelog", "createlogtable", "newlogtable", "allocatelog"}:
            return False
        if not isinstance(returned, (list, tuple)):
            return False
        if not returned:
            return True
        return _normalize_status(returned[0]) not in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}

    def high_level_object_return(returned: Any) -> Any:
        if isinstance(returned, (list, tuple)) and len(returned) == 2 and isinstance(returned[1], bool):
            first = returned[0]
            if first is None or isinstance(first, (dict, list, tuple, bytes, bytearray)):
                return first
            if _normalize_status(first) not in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
                return first
        return None

    def method_return_payload(
        returned: Any,
        *,
        legacy_tuple: bool = False,
        allow_numeric_status: bool = True,
    ) -> Any:
        if not isinstance(returned, (list, tuple)) or not returned:
            return returned
        high_level_return = high_level_object_return(returned)
        if high_level_return is not None or (len(returned) == 2 and isinstance(returned[1], bool) and returned[0] is None):
            return high_level_return
        first = returned[0]
        normalized = _normalize_status(first)
        textual_status = isinstance(first, str) and re.sub(r"[^A-Za-z]", "", first).upper() in {
            "SUCCESS",
            "PASS",
            "FAIL",
            "NOTAUTHORIZED",
            "INVALIDPARAMETER",
            "INSUFFICIENTSPACE",
            "INSUFFICIENTROWS",
        }
        if normalized in {SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, INSUFFICIENT_SPACE, INSUFFICIENT_ROWS, FAIL, "PASS"}:
            if not allow_numeric_status and not textual_status:
                return returned
            if len(returned) < 2:
                return [] if legacy_tuple else returned
            if len(returned) >= 3 and not _empty_payload(returned[2]):
                return returned[2]
            return returned[1]
        if legacy_tuple and len(returned) >= 3 and not _empty_payload(returned[2]):
            return returned[2]
        return returned

    output = _output_section(raw)
    names = (
        "return_values",
        "ReturnValues",
        "returnValues",
        "return_value",
        "ReturnValue",
        "returnValue",
        "returnVal",
        "returnval",
        "retVal",
        "RetVal",
        "returned_values",
        "returnedValues",
        "returnedNamedValues",
        "ReturnedNamedValues",
        "namedReturnValues",
        "NamedReturnValues",
        "rvs",
        "RVs",
        "rv",
        "RV",
        "kwrvs",
        "kwrv",
        "results",
        "Results",
        "ACL",
        "acl",
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
        "ACEUIDs",
        "aceUIDs",
        "aceUids",
        "ace_uids",
        "ACERefs",
        "aceRefs",
        "ace_refs",
        "values",
        "Values",
        "value",
        "Value",
        "data",
        "Data",
        "payload",
        "Payload",
        "bytes",
        "Bytes",
        "buffer",
        "Buffer",
        "blob",
        "Blob",
        "content",
        "Content",
        "hex",
        "Hex",
        "payloadBytes",
        "PayloadBytes",
        "byteArray",
        "ByteArray",
        "response",
        "Response",
        "body",
        "Body",
        "range",
        "Range",
        "rangeInfo",
        "RangeInfo",
        "lockingRange",
        "LockingRange",
        "locking_range",
        "band",
        "Band",
        "ok",
        "OK",
        "is_ok",
        "isOk",
        "IsOk",
        "isSuccess",
        "IsSuccess",
        "passed",
        "Passed",
        "success",
        "Success",
        "succeeded",
        "Succeeded",
        "successFlag",
        "SuccessFlag",
        "authenticated",
        "Authenticated",
        "authentication",
        "Authentication",
    )
    found, value = _dict_lookup(output, *names)
    if found:
        return method_return_payload(value, allow_numeric_status=False)
    found, returned = _dict_lookup(output, "return", "Return", "returns", "Returns")
    if found and isinstance(returned, (list, tuple)):
        input_obj = _function_input_section(raw)
        alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
        if preserve_function_return_list(alias, returned):
            return returned
        return method_return_payload(returned, legacy_tuple=True)
    if found:
        return returned
    output_args = _mapping_section(output, "args", "Args")
    found, value = _dict_lookup(output_args, *names)
    if found:
        return method_return_payload(value, allow_numeric_status=False)
    found, returned = _dict_lookup(output_args, "return", "Return", "returns", "Returns")
    if found and isinstance(returned, (list, tuple)):
        input_obj = _function_input_section(raw)
        alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
        if preserve_function_return_list(alias, returned):
            return returned
        return method_return_payload(returned, legacy_tuple=True)
    if found:
        return returned
    nested_output = _mapping_section(output, "output", "Output")
    if nested_output:
        found, value = _dict_lookup(nested_output, *names)
        if found:
            return method_return_payload(value, allow_numeric_status=False)
        found, returned = _dict_lookup(nested_output, "return", "Return", "returns", "Returns")
        if found and isinstance(returned, (list, tuple)):
            input_obj = _function_input_section(raw)
            alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
            if preserve_function_return_list(alias, returned):
                return returned
            return method_return_payload(returned, legacy_tuple=True)
        if found:
            return returned
        nested_args = _mapping_section(nested_output, "args", "Args")
        found, value = _dict_lookup(nested_args, *names)
        if found:
            return method_return_payload(value, allow_numeric_status=False)
        found, returned = _dict_lookup(nested_args, "return", "Return", "returns", "Returns")
        if found and isinstance(returned, (list, tuple)):
            input_obj = _function_input_section(raw)
            alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
            if preserve_function_return_list(alias, returned):
                return returned
            return method_return_payload(returned, legacy_tuple=True)
        if found:
            return returned
        nested_result = _mapping_value(nested_args, "result", "Result", default=_mapping_value(nested_output, "result", "Result"))
        if nested_result is not None:
            return nested_result
    return _mapping_value(output_args, "result", "Result", default=_mapping_value(output, "result", "Result"))


def _return_bool(raw: dict[str, Any], *, credential_aliases: bool = False) -> bool | None:
    def from_value(value: Any) -> bool | None:
        parsed = _optional_bool(value)
        if parsed is not None:
            return parsed
        if isinstance(value, dict):
            for key in (
                "Result",
                "result",
                "OK",
                "ok",
                "isOK",
                "isOk",
                "is_ok",
                "isSuccess",
                "IsSuccess",
                "Success",
                "success",
                "successFlag",
                "SuccessFlag",
                "Passed",
                "passed",
                "Succeeded",
                "succeeded",
                "Authenticated",
                "authenticated",
                "Authentication",
                "authentication",
                "Valid",
                "valid",
                "isValid",
                "IsValid",
                "verified",
                "Verified",
                "Enabled",
                "enabled",
                "Enable",
                "enable",
                "isEnabled",
                "IsEnabled",
                "Locked",
                "locked",
                "PortLocked",
                "portLocked",
                "PortLock",
                "portLock",
                "LockState",
                "lockState",
                "State",
                "state",
                "PortLockState",
                "portLockState",
                "PortState",
                "portState",
                "isLocked",
                "IsLocked",
                "isPortLocked",
                "IsPortLocked",
                "AuthorityEnabled",
                "authorityEnabled",
                "UserEnabled",
                "userEnabled",
                "isUserEnabled",
                "IsUserEnabled",
                "enabledFlag",
                "EnabledFlag",
                "ReEncrypting",
                "reencrypting",
                "ReEncryptionActive",
                "reencryptionActive",
                "isReEncrypting",
                "IsReEncrypting",
                "return",
                "Return",
                "rv",
                "RV",
                "value",
                "Value",
            ):
                found, item = _dict_lookup(value, key)
                if found:
                    parsed = from_value(item)
                    if parsed is not None:
                        return parsed
            for key in (
                "Disabled",
                "disabled",
                "Disable",
                "disable",
                "isDisabled",
                "IsDisabled",
                "AuthorityDisabled",
                "authorityDisabled",
                "UserDisabled",
                "userDisabled",
                "isUserDisabled",
                "IsUserDisabled",
                "disabledFlag",
                "DisabledFlag",
            ):
                found, item = _dict_lookup(value, key)
                if found:
                    parsed = from_value(item)
                    if parsed is not None:
                        return not parsed
            named_bool_values: list[bool] = []
            for key, item in value.items():
                normalized_key = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
                if normalized_key in {
                    "READLOCKED",
                    "ISREADLOCKED",
                    "ISRANGEREADLOCKED",
                    "WRITELOCKED",
                    "ISWRITELOCKED",
                    "ISRANGEWRITELOCKED",
                    "READLOCKENABLED",
                    "ISREADLOCKENABLED",
                    "ISREADLOCKINGENABLED",
                    "ISRANGEREADLOCKENABLED",
                    "ISRANGEREADLOCKINGENABLED",
                    "WRITELOCKENABLED",
                    "ISWRITELOCKENABLED",
                    "ISWRITELOCKINGENABLED",
                    "ISRANGEWRITELOCKENABLED",
                    "ISRANGEWRITELOCKINGENABLED",
                }:
                    parsed = from_value(item)
                    if parsed is not None:
                        named_bool_values.append(parsed)
                elif normalized_key in {"READLOCKDISABLED", "WRITELOCKDISABLED"}:
                    parsed = from_value(item)
                    if parsed is not None:
                        named_bool_values.append(not parsed)
            if len(named_bool_values) == 1:
                return named_bool_values[0]
            if credential_aliases:
                for key in (
                    "Matched",
                    "matched",
                    "Match",
                    "match",
                    "Matches",
                    "matches",
                    "isMatch",
                    "IsMatch",
                    "isMatched",
                    "IsMatched",
                    "isVerified",
                    "IsVerified",
                    "Accepted",
                    "accepted",
                    "Authorized",
                    "authorized",
                    "Allowed",
                    "allowed",
                    "Approved",
                    "approved",
                    "Confirmed",
                    "confirmed",
                    "CredentialValid",
                    "credentialValid",
                    "credential_valid",
                    "CredentialMatched",
                    "credentialMatched",
                    "credential_matched",
                    "PinValid",
                    "pinValid",
                    "pin_valid",
                    "PinMatched",
                    "pinMatched",
                    "pin_matched",
                ):
                    found, item = _dict_lookup(value, key)
                    if found:
                        parsed = from_value(item)
                        if parsed is not None:
                            return parsed
                for key in (
                    "Credential",
                    "credential",
                    "Credentials",
                    "credentials",
                    "Auth",
                    "auth",
                    "AuthenticationResult",
                    "authenticationResult",
                    "Authentication",
                    "authentication",
                    "Verification",
                    "verification",
                    "Proof",
                    "proof",
                    "Response",
                    "response",
                    "Output",
                    "output",
                ):
                    found, item = _dict_lookup(value, key)
                    if found and isinstance(item, dict):
                        parsed = from_value(item)
                        if parsed is not None:
                            return parsed
            return None
        if isinstance(value, (list, tuple)):
            if len(value) == 1:
                return from_value(value[0])
            for item in value:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                    bool_keys = {"result", "ok", "isok", "issuccess", "success", "successflag", "passed", "succeeded", "authenticated", "authentication", "valid", "isvalid", "verified", "enabled", "enable", "isenabled", "lockstate", "state", "rv", "return"}
                    inverse_bool_keys = {"disabled", "disable", "isdisabled"}
                    if credential_aliases:
                        bool_keys |= {
                            "matched",
                            "match",
                            "matches",
                            "ismatch",
                            "ismatched",
                            "isverified",
                            "accepted",
                            "authorized",
                            "allowed",
                            "approved",
                            "confirmed",
                            "credentialvalid",
                            "credentialmatched",
                            "pinvalid",
                            "pinmatched",
                        }
                    if key in bool_keys:
                        parsed = from_value(item[1])
                        if parsed is not None:
                            return parsed
                    if key in inverse_bool_keys:
                        parsed = from_value(item[1])
                        if parsed is not None:
                            return not parsed
                elif isinstance(item, dict):
                    parsed = from_value(item)
                    if parsed is not None:
                        return parsed
            return None
        return None

    parsed_return = from_value(_output_return_values(raw))
    if parsed_return is not None:
        return parsed_return
    if credential_aliases:
        parsed_output = from_value(_output_section(raw))
        if parsed_output is not None:
            return parsed_output
    return None


def parse_event(raw: dict[str, Any]) -> Event:
    inp = _input_section(raw)
    out = _output_section(raw)

    function_name = _function_name(inp)
    function_alias = _function_alias(function_name)
    if function_alias in {
        "debugpackets",
        "currentciphersuite",
        "fipsapprovedmode",
        "fipscompliance",
        "haslockedrange",
        "maxlba",
        "msid",
        "ports",
        "ssc",
        "usepsk",
        "wwn",
        "close",
    }:
        return Event(
            raw=raw,
            kind="host_io",
            method=function_alias,
            status=_high_level_status(raw, out, inp),
            comid=_comid_from_event_parts(inp, out, raw),
        )

    if function_alias in {
        "powercycle",
        "dopowercycle",
        "powercycledevice",
        "devicepowercycle",
        "powercycletper",
        "powercyclereset",
        "dopowercyclereset",
        "powerreset",
        "resetpowercycle",
        "coldreset",
        "hardreset",
        "hardwarereset",
        "dohardwarereset",
        "hardwareresetdevice",
        "resethardware",
        "hwreset",
        "devicereset",
        "resetdevice",
        "platformreset",
        "hotplug",
        "hotplugreset",
        "reset",
        "tcgreset",
        "stackreset",
        "protocolreset",
        "protocolstackreset",
        "resetprotocolstack",
        "comidreset",
        "resetcomid",
        "tperreset",
        "resettper",
        "programmaticreset",
    }:
        status = _high_level_status(raw, out, inp)
        if status is None:
            status = SUCCESS if _return_bool(raw) is not False else FAIL
        method = function_name
        if function_alias == "reset":
            args = _function_args(inp)
            kwargs = _function_kwargs(inp)
            method = _reset_method_from_payload(kwargs, inp, args[0] if args and isinstance(args[0], dict) else None) or method
        return Event(
            raw=raw,
            kind="host_io",
            method=method,
            status=status,
            comid=_comid_from_event_parts(inp, out, raw),
        )

    if function_alias in {
        "checkpin",
        "checkpincode",
        "checkpasscode",
        "verifypin",
        "verifypincode",
        "verifypasscode",
        "validatepin",
        "validatepincode",
        "validatepasscode",
        "authenticateuser",
        "checkcredential",
        "verifycredential",
        "checkpassword",
        "verifypassword",
        "validatepassword",
    }:
        args_list = _function_args(inp)
        kwargs = _function_kwargs(inp)
        auth_value = args_list[0] if args_list else _mapping_value(
            kwargs,
            "auth",
            "Auth",
            "Authority",
            "authority",
            "user",
            "User",
            "userId",
            "userID",
            "user_id",
            "uid",
            "UID",
            "authorityId",
            "authorityID",
            "authority_id",
            "obj",
            "object",
            "Object",
            "target",
            "Target",
            "identity",
            "Identity",
            "username",
            "Username",
            "pinId",
            "pin_id",
            "PINID",
            "credentialId",
            "credential_id",
            "CredentialID",
            "authId",
            "auth_id",
            "AuthID",
            "name",
            "Name",
        )
        challenge = args_list[1] if len(args_list) > 1 else _mapping_value(
            kwargs,
            "pin",
            "PIN",
            "cred",
            "credential",
            "password",
            "Password",
            "passcode",
            "Passcode",
            "secret",
            "Secret",
            "pinCode",
            "pin_code",
            "proof",
            "Proof",
            "challenge",
            "Challenge",
        )
        pin_payload_aliases = (
            "values",
            "Values",
            "settings",
            "Settings",
            "options",
            "Options",
            "request",
            "Request",
            "config",
            "Config",
            "policy",
            "Policy",
            "target",
            "Target",
            "operationRequest",
            "OperationRequest",
            "credentialRequest",
            "CredentialRequest",
            "cpinRequest",
            "CPINRequest",
            "pinRequest",
            "PinRequest",
            "authRequest",
            "AuthRequest",
            "authenticationRequest",
            "AuthenticationRequest",
            "proofRequest",
            "ProofRequest",
            "credential",
            "Credential",
            "identity",
            "Identity",
        )
        pin_payload = _mapping_value(kwargs, *pin_payload_aliases)
        if not isinstance(pin_payload, dict):
            pin_payload = _mapping_value(inp, *pin_payload_aliases)
        if not isinstance(pin_payload, dict) and args_list and isinstance(args_list[0], dict):
            pin_payload = _mapping_value(args_list[0], *pin_payload_aliases)
            if not isinstance(pin_payload, dict):
                pin_payload = args_list[0]
        if isinstance(pin_payload, dict):
            for _ in range(4):
                merged_pin_payload = dict(pin_payload)
                for envelope in pin_payload_aliases:
                    nested_pin_payload = _mapping_value(pin_payload, envelope)
                    if isinstance(nested_pin_payload, dict) and nested_pin_payload is not pin_payload:
                        merged_pin_payload.update(nested_pin_payload)
                if merged_pin_payload == pin_payload:
                    break
                pin_payload = merged_pin_payload

            def _pin_payload_selector(payload: Any) -> Any:
                if not isinstance(payload, dict):
                    return None
                direct = _mapping_value(payload, "auth", "Auth", "Authority", "authority", "user", "User", "userId", "userID", "user_id", "uid", "UID", "authorityId", "authorityID", "authority_id", "obj", "object", "Object", "target", "Target", "identity", "Identity", "username", "Username", "pinId", "pin_id", "PINID", "credentialId", "credential_id", "CredentialID", "authId", "auth_id", "AuthID", "name", "Name")
                if direct is not None and not isinstance(direct, dict):
                    return direct
                for envelope in pin_payload_aliases:
                    nested = _mapping_value(payload, envelope)
                    if nested is not None and nested is not payload:
                        nested_selector = _pin_payload_selector(nested)
                        if nested_selector is not None:
                            return nested_selector
                return None

            def _pin_payload_proof(payload: Any) -> Any:
                if not isinstance(payload, dict):
                    return None
                direct = _mapping_value(payload, "pin", "PIN", "cred", "credential", "password", "Password", "passcode", "Passcode", "secret", "Secret", "pinCode", "pin_code", "proof", "Proof", "challenge", "Challenge")
                if direct is not None and not isinstance(direct, dict):
                    return direct
                for envelope in pin_payload_aliases:
                    nested = _mapping_value(payload, envelope)
                    if nested is not None and nested is not payload:
                        nested_proof = _pin_payload_proof(nested)
                        if nested_proof is not None:
                            return nested_proof
                return None

            if auth_value is None or isinstance(auth_value, dict):
                auth_value = _pin_payload_selector(pin_payload)
            if challenge is None:
                challenge = _pin_payload_proof(pin_payload)
        return Event(
            raw=raw,
            kind="tcg_method",
            method="Authenticate",
            invoking_name="ThisSP",
            invoking_uid="0000000000000001",
            invoking_symbol="ThisSP",
            status=SUCCESS,
            optional=kwargs,
            sp=_sp_from_value(_mapping_value(kwargs, "sp", "SP")),
            authority=_authority_from_value(auth_value),
            challenge=challenge,
            implicit_session=True,
            comid=_comid_from_event_parts(inp, out, raw),
        )

    high_level = _high_level_event(raw, inp, out)
    if high_level is not None:
        return high_level

    found_command, command = _dict_lookup(
        inp,
        "command",
        "Command",
        "cmd",
        "Cmd",
        "CMD",
        "operation",
        "Operation",
        "op",
        "Op",
        "action",
        "Action",
        "io",
        "IO",
        "request",
        "Request",
        "type",
        "Type",
    )
    if not found_command:
        found_command, command = _dict_lookup(
            raw,
            "command",
            "Command",
            "cmd",
            "Cmd",
            "CMD",
            "operation",
            "Operation",
            "op",
            "Op",
            "action",
            "Action",
            "io",
            "IO",
            "request",
            "Request",
            "type",
            "Type",
        )
    if not found_command:
        method_candidate = _method_info_from_input(inp)
        if isinstance(method_candidate, str) and method_candidate.strip().lower() in {
            "read",
            "write",
            "powercycle",
            "dopowercycle",
            "powercycledevice",
            "devicepowercycle",
            "powercycletper",
            "powercyclereset",
            "dopowercyclereset",
            "powerreset",
            "resetpowercycle",
            "coldreset",
            "hardreset",
            "hardwarereset",
            "dohardwarereset",
            "hardwareresetdevice",
            "resethardware",
            "hwreset",
            "devicereset",
            "resetdevice",
            "platformreset",
            "tcgreset",
            "tperreset",
            "resettper",
            "programmaticreset",
            "protocolreset",
            "protocolstackreset",
            "resetprotocolstack",
            "comidreset",
            "resetcomid",
            "stackreset",
        }:
            found_command, command = True, method_candidate
    if found_command:
        method = _as_text(command or "UNKNOWN")
        args = _mapping_section(inp, "args", "Args", "arguments", "Arguments")
        if not args:
            args = {
                key: value
                for key, value in inp.items()
                if _as_text(key).strip().lower() not in {"command", "cmd", "method", "type", "operation", "op", "action", "io", "request"}
            }
        if not args:
            args = _mapping_section(raw, "args", "Args", "arguments", "Arguments")
        if not args:
            args = {
                key: value
                for key, value in raw.items()
                if _as_text(key).strip().lower() not in {"input", "output", "command", "cmd", "method", "type", "operation", "op", "action", "io", "request"}
            }
        output_args = _mapping_section(out, "args", "Args")
        result = _mapping_value(out, "result", "Result")
        if result is None:
            result = _mapping_value(output_args, "result", "Result")
        if result is None:
            result = _mapping_value(
                output_args,
                "return",
                "Return",
                "return_value",
                "ReturnValue",
                "returnValue",
                "value",
                "Value",
                "data",
                "Data",
                "payload",
                "Payload",
                "response",
                "Response",
                "pattern",
                "Pattern",
                "buffer",
                "Buffer",
            )
        if result is None:
            result = _mapping_value(
                out,
                "return",
                "Return",
                "return_value",
                "ReturnValue",
                "returnValue",
                "value",
                "Value",
                "data",
                "Data",
                "payload",
                "Payload",
                "response",
                "Response",
                "pattern",
                "Pattern",
                "buffer",
                "Buffer",
            )
        write_payload = _mapping_value(
            args,
            "pattern",
            "Pattern",
            "data",
            "Data",
            "payload",
            "Payload",
            "value",
            "Value",
            "buffer",
            "Buffer",
        )
        return Event(
            raw=raw,
            kind="host_io",
            method=method,
            status=_host_status(out),
            lba=_lba_from_args(args),
            pattern=_extract_pattern(write_payload),
            read_result=_extract_pattern(result),
            comid=_comid_from_event_parts(args, inp, out, raw),
        )

    argv = _invoke_argv(inp)
    method_info = _method_info_from_input(inp) or {}
    required, optional, raw_args = _method_args(raw)
    required = dict(required)
    optional = dict(optional)
    control_keys = {
        "input",
        "output",
        "method",
        "method_name",
        "methodname",
        "method_id",
        "methodid",
        "method_uid",
        "methoduid",
        "invoking_id",
        "invokingid",
        "invoking_uid",
        "invokinguid",
        "invoking_name",
        "invokingname",
        "invoking",
        "object",
        "object_id",
        "objectid",
        "target",
        "target_id",
        "targetid",
        "args",
        "arguments",
        "params",
        "parameters",
        "required",
        "required_args",
        "requiredargs",
        "optional",
        "optional_args",
        "optionalargs",
        "argv",
        "kwargs",
        "kw",
        "named",
        "status",
        "status_codes",
        "statuscodes",
        "command",
        "operation",
        "type",
    }
    for key, value in inp.items():
        normalized_key = re.sub(r"[^A-Za-z0-9_]", "", _as_text(key)).lower()
        if normalized_key not in control_keys and key not in optional and key not in required:
            optional[key] = value
    invoking = _mapping_value(
        inp,
        "invoking_id",
        "InvokingID",
        "invokingId",
        "invoking_uid",
        "InvokingUID",
        "invokingUid",
        "invoking",
        "Invoking",
        "object",
        "Object",
        "object_id",
        "objectId",
        "ObjectID",
        "target",
        "Target",
        "target_id",
        "targetId",
        "TargetID",
    ) or {}
    if not invoking and argv:
        invoking = argv[0]
    if isinstance(invoking, dict):
        invoking_uid = _clean_uid(_mapping_value(invoking, "uid", "UID"))
        invoking_name_source = _mapping_value(invoking, "name", "Name")
    else:
        invoking_uid = _clean_uid(invoking)
        invoking_name_source = _mapping_value(inp, "invoking_name", "InvokingName", "invokingName", "name", "Name", default=invoking)
    invoking_name = _normalize_name(invoking_name_source or "")
    invoking_symbol = _object_by_uid(invoking_uid, invoking_name)
    if isinstance(method_info, dict):
        method_uid = _clean_uid(_mapping_value(method_info, "uid", "UID"))
        method_name = _mapping_value(method_info, "name", "Name")
    else:
        method_uid = _clean_uid(method_info)
        method_name = method_info
    method_from_uid = _method_by_uid(method_uid)
    method_text = "" if method_name is None else _as_text(method_name).strip()
    if method_from_uid is not None and (not method_text or _uid_ref(method_name)):
        method = method_from_uid
    else:
        method = _method_ref_name(method_text) if method_text else None
        method = method or method_from_uid or "UNKNOWN"
    if method in {"GetACL", "AddACE", "RemoveACE", "DeleteMethod"} and (
        "InvokingID" not in required or "MethodID" not in required
    ):
        positional_args: list[Any] = []
        if isinstance(raw_args, (list, tuple)):
            positional_args = list(raw_args)
        elif isinstance(raw_args, dict):
            nested_required = _mapping_value(raw_args, "required", "Required", "required_args", "requiredArgs", "RequiredArgs")
            if isinstance(nested_required, (list, tuple)):
                positional_args = list(nested_required)
        if len(positional_args) == 1 and isinstance(positional_args[0], dict):
            positional_args = []
        if len(positional_args) >= 2:
            required.setdefault("InvokingID", positional_args[0])
            required.setdefault("MethodID", positional_args[1])
        if len(positional_args) >= 3 and method in {"AddACE", "RemoveACE"}:
            required.setdefault("ACE", positional_args[2])
        meta_values = _mapping_value(inp, "values", "Values", "params", "Params", "parameters", "Parameters")
        if not isinstance(meta_values, dict) and isinstance(method_info, dict):
            meta_values = _mapping_value(method_info, "values", "Values", "params", "Params", "parameters", "Parameters")
        if isinstance(meta_values, dict):
            nested_meta_args = _mapping_value(meta_values, "args", "Args", "argv", "ARGV")
            if isinstance(nested_meta_args, (list, tuple)) and len(nested_meta_args) == 1 and isinstance(nested_meta_args[0], dict):
                meta_values = {**nested_meta_args[0], **meta_values}
            for key in (
                "InvokingID",
                "invokingID",
                "invokingId",
                "invoking_id",
                "invoking",
                "Invoking",
                "invokingObject",
                "InvokingObject",
                "invokingObjectID",
                "InvokingObjectID",
                "invokingObjectId",
                "InvokingObjectId",
                "invoking_object_id",
                "invokingObjectUID",
                "InvokingObjectUID",
                "invokingObjectUid",
                "InvokingObjectUid",
                "invoking_object_uid",
                "InvokingUID",
                "invokingUID",
                "invokingUid",
                "invoking_uid",
                "object",
                "Object",
                "objectID",
                "ObjectID",
                "objectId",
                "ObjectId",
                "object_id",
                "objectUID",
                "ObjectUID",
                "objectUid",
                "ObjectUid",
                "object_uid",
                "target",
                "Target",
                "targetID",
                "TargetID",
                "targetId",
                "TargetId",
                "target_id",
                "targetUID",
                "TargetUID",
                "targetUid",
                "TargetUid",
                "target_uid",
                "obj",
                "Obj",
                "uid",
                "UID",
                "MethodID",
                "methodID",
                "methodId",
                "MethodId",
                "method_id",
                "MethodUID",
                "methodUID",
                "methodUid",
                "method_uid",
                "method",
                "Method",
                "methodName",
                "MethodName",
                "method_name",
                "operation",
                "Operation",
                "operationID",
                "OperationID",
                "operationId",
                "OperationId",
                "operation_id",
                "operationUID",
                "OperationUID",
                "operationUid",
                "OperationUid",
                "operation_uid",
                "operationName",
                "OperationName",
                "operation_name",
                "op",
                "Op",
                "action",
                "Action",
                "actionID",
                "ActionID",
                "actionId",
                "ActionId",
                "action_id",
                "actionUID",
                "ActionUID",
                "actionUid",
                "ActionUid",
                "action_uid",
                "targetMethod",
                "TargetMethod",
                "target_method",
                "targetMethodID",
                "TargetMethodID",
                "targetMethodId",
                "TargetMethodId",
                "target_method_id",
                "targetMethodUID",
                "TargetMethodUID",
                "targetMethodUid",
                "TargetMethodUid",
                "target_method_uid",
                "actionName",
                "ActionName",
                "action_name",
            ):
                found, value = _dict_lookup(meta_values, key)
                if found:
                    normalized_meta_key = re.sub(r"[^A-Za-z0-9]", "", key).lower()
                    canonical = "MethodID" if normalized_meta_key in {"methodid", "methoduid", "method", "methodname", "operation", "operationid", "operationuid", "operationname", "op", "action", "actionid", "actionuid", "actionname", "targetmethod", "targetmethodid", "targetmethoduid"} else "InvokingID"
                    required.setdefault(canonical, value)
    values = _values(optional, raw_args, invoking_symbol)
    columns = _cellblock_columns({**required, **optional}, raw_args, method, invoking_symbol)
    cpin_alias = _tcgstorageapi_cpin_alias_by_uid(invoking_uid)
    explicit_authority_name = bool(invoking_name_source) and invoking_symbol.startswith("Authority_")
    if cpin_alias is not None and not invoking_symbol.startswith("C_PIN_") and (
        not explicit_authority_name
    ) and (
        PIN_COLUMN in values
        or columns
        & {
            PIN_COLUMN,
            CPIN_CHARSET_COLUMN,
            CPIN_TRY_LIMIT_COLUMN,
            CPIN_TRIES_COLUMN,
            CPIN_PERSISTENCE_COLUMN,
        }
    ):
        invoking_symbol = cpin_alias
        values = _values(optional, raw_args, invoking_symbol)
    pin_owner = _authority_by_object(invoking_symbol)
    if not invoking_uid and method == "Set" and pin_owner and PIN_COLUMN in values:
        invoking_symbol = f"C_PIN_{pin_owner}"
        values = _values(optional, raw_args, invoking_symbol)
    if not invoking_uid:
        authority_symbol = _bare_authority_symbol(invoking_name_source, method, values, columns)
        if authority_symbol is not None:
            invoking_symbol = authority_symbol
    spid_value = _raw_arg_value(required, optional, raw_args, "SPID", "SP", "sp")
    positional_spid, positional_write, positional_authority, positional_challenge = (
        _start_session_positional(raw_args) if method == "StartSession" else (None, None, None, None)
    )
    if spid_value is None:
        spid_value = positional_spid
    auth_value = _raw_arg_value(required, optional, raw_args, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    if auth_value is None and method == "Authenticate":
        auth_value = _authenticate_authority_arg(raw_args)
    if auth_value is None:
        auth_value = positional_authority
    challenge = _raw_arg_value(required, optional, raw_args, "Proof", "proof", "HostChallenge", "Challenge", 0, "0")
    if challenge is None:
        challenge = _authas_credential_arg(required, optional, raw_args)
    if challenge is None and method == "Authenticate":
        challenge = _authenticate_challenge_arg(raw_args, auth_value)
    if challenge is None:
        challenge = positional_challenge
    write_value = _raw_arg_value(required, optional, raw_args, "Write", "write")
    if write_value is None:
        write_value = positional_write

    return Event(
        raw=raw,
        kind="tcg_method",
        method=method,
        invoking_name=invoking_name,
        invoking_uid=invoking_uid,
        invoking_symbol=invoking_symbol,
        status=_normalize_status(_output_status_value(out, inp)),
        required=required,
        optional=optional,
        values=values,
        columns=columns,
        sp=_sp_from_value(spid_value),
        authority=_authority_from_value(auth_value),
        challenge=challenge,
        write_session=_as_bool(write_value),
        comid=_comid_from_event_parts(required, optional, raw_args, inp, out, raw),
        implicit_session=bool(argv)
        and method
        not in {"Properties", "StartSession", "StartTrustedSession", "StartTlsSession", "EndSession", "CloseSession", "SyncSession", "SyncTrustedSession", "SyncTlsSession"},
    )



__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
