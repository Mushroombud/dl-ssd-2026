"""State transitions applied from successful context records."""

from __future__ import annotations

from dataclasses import replace
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *


READ_WRITE_PERSISTENT_METHODS = {
    "Set",
    "CreateTable",
    "CreateLog",
    "CreateRow",
    "DeleteRow",
    "Delete",
    "DeleteSP",
    "DeleteMethod",
    "AddACE",
    "RemoveACE",
    "SetACL",
    "SetPackage",
    "Activate",
    "GenKey",
    "Erase",
    "Revert",
    "RevertSP",
}

HOST_SESSION_ID_NAMES = ("HostSessionID", "hostSessionID", "HostSession", "hostSession", "HostSID", "hostSID", "HSID", "hSID")
SP_SESSION_ID_NAMES = (
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


def _auth_from_authenticate_event(event: Event) -> str | None:
    return (
        event.authority
        or _authority_from_value(_mapping_value(event.required, "Authority"))
        or _authority_from_value(_mapping_value(event.required, "HostSigningAuthority"))
    )


def _mark_successful_authentication(state: State, authority: str | None) -> None:
    if authority == "SID":
        state.sid_ever_authenticated = True


def _apply_start_session_success(state: State, event: Event) -> None:
    authenticated: set[str] = set()
    authority = event.authority or "Anybody"
    authenticated.add(authority)
    _mark_successful_authentication(state, authority)
    _increment_authority_use(state, authority)
    if event.challenge and authority != "Anybody":
        state.pins[authority] = _credential_text(event.challenge)
        state.pin_tries[authority] = 0
    if event.sp == "LockingSP":
        state.locking_sp_activated = True
    returned = _output_return_values(event.raw)
    state.session = Session(
        open=True,
        sp=event.sp,
        write=event.write_session,
        authenticated=authenticated,
        host_session_id=_session_id_key(_recursive_named_value(returned, *HOST_SESSION_ID_NAMES)),
        sp_session_id=_session_id_key(_recursive_named_value(returned, *SP_SESSION_ID_NAMES)),
        startup_host_challenge=_raw_arg_value(event.required, event.optional, _method_raw_args(event), "HostChallenge", "Challenge") is not None,
        comid=event.comid,
    )
    state.pending_deleted_sp = None


def _increment_failed_authority_try(state: State, authority: str | None) -> None:
    if authority and authority not in {"Anybody", "Admins", "Users"}:
        try_limit = state.pin_try_limits.get(authority, 0)
        if try_limit > 0:
            state.pin_tries[authority] = min(try_limit, state.pin_tries.get(authority, 0) + 1)


def _increment_authority_use(state: State, authority: str | None) -> None:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return
    state.authority_uses[authority] = max(0, state.authority_uses.get(authority, 0)) + 1


def _authority_limit_reached_for_transition(state: State, authority: str | None) -> bool:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return False
    limit = state.authority_limits.get(authority, 0)
    return limit > 0 and state.authority_uses.get(authority, 0) >= limit


def _auth_failure_counts_as_pin_try(state: State, event: Event, authority: str | None) -> bool:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return False
    sp = event.sp if event.method == "StartSession" else state.session.sp
    if not _authority_allowed_in_sp(sp, authority):
        return False
    if not _authority_is_enabled(state, sp, authority):
        return False
    if _authority_limit_reached_for_transition(state, authority):
        return False
    return True


def _failed_authas_authorities(state: State, event: Event) -> set[str]:
    if event.method in {"StartSession", "Authenticate"}:
        return set()

    failed: set[str] = set()
    pairs = _authas_pairs(event.required, event.optional, _method_raw_args(event))
    if event.authority is not None:
        pairs.append((event.authority, event.challenge))

    for authority, credential in pairs:
        if authority in {None, "Anybody", "Admins", "Users"} or not credential:
            continue
        known_pin = state.pins.get(authority)
        if known_pin is not None and _credential_text(credential) != known_pin:
            failed.add(authority)
    return failed


def _apply_get_success(state: State, event: Event) -> None:
    symbol = event.invoking_symbol
    returned = _flatten_return_values(_output_return_values(event.raw), symbol)
    owner = _pin_owner_by_object(symbol)

    if owner and MIN_PIN_COLUMN in returned:
        min_pin = _parse_int(returned[MIN_PIN_COLUMN])
        if min_pin is not None:
            state.pin_min_lengths[owner] = min_pin
    if owner and CPIN_TRY_LIMIT_COLUMN in returned:
        try_limit = _parse_int(returned[CPIN_TRY_LIMIT_COLUMN])
        if try_limit is not None:
            state.pin_try_limits[owner] = max(0, try_limit)
            if try_limit == 0:
                state.pin_tries[owner] = 0
    if owner and CPIN_TRIES_COLUMN in returned:
        tries = _parse_int(returned[CPIN_TRIES_COLUMN])
        if tries is not None:
            state.pin_tries[owner] = max(0, tries)
    if owner and CPIN_PERSISTENCE_COLUMN in returned:
        state.pin_persistence[owner] = _as_bool(returned[CPIN_PERSISTENCE_COLUMN])
    if symbol == "C_PIN_MSID" and PIN_COLUMN in returned:
        state.pins["MSID"] = _credential_text(returned[PIN_COLUMN])
        return

    if symbol in {"AdminSP", "LockingSP"}:
        if symbol == "LockingSP" and 6 in returned:
            lifecycle_value = returned[6]
            lifecycle = _parse_int(lifecycle_value)
            if lifecycle is not None:
                state.observed_sp_lifecycle["LockingSP"] = lifecycle
            active = _sp_lifecycle_active(lifecycle_value)
            if active is not None:
                state.locking_sp_activated = active
        if 7 in returned:
            state.sp_frozen[symbol] = _as_bool(returned[7])
        return

    if symbol == "LockingInfo":
        input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
        function_alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
        single_getter_column = {
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
            "getmaxranges": 4,
            "readmaxranges": 4,
            "fetchmaxranges": 4,
            "querymaxranges": 4,
            "loadmaxranges": 4,
            "getmaxlockingranges": 4,
            "readmaxlockingranges": 4,
            "fetchmaxlockingranges": 4,
            "querymaxlockingranges": 4,
            "loadmaxlockingranges": 4,
            "getrangecount": 4,
            "readrangecount": 4,
            "fetchrangecount": 4,
            "queryrangecount": 4,
            "loadrangecount": 4,
            "getlockingrangecount": 4,
            "readlockingrangecount": 4,
            "fetchlockingrangecount": 4,
            "querylockingrangecount": 4,
            "loadlockingrangecount": 4,
            "getnumberofranges": 4,
            "readnumberofranges": 4,
            "fetchnumberofranges": 4,
            "querynumberofranges": 4,
            "loadnumberofranges": 4,
            "getnumranges": 4,
            "readnumranges": 4,
            "fetchnumranges": 4,
            "querynumranges": 4,
            "loadnumranges": 4,
            "getrangelimit": 4,
            "readrangelimit": 4,
            "fetchrangelimit": 4,
            "queryrangelimit": 4,
            "loadrangelimit": 4,
            "getlockingrangelimit": 4,
            "readlockingrangelimit": 4,
            "fetchlockingrangelimit": 4,
            "querylockingrangelimit": 4,
            "loadlockingrangelimit": 4,
        }.get(function_alias)
        if single_getter_column in event.columns and single_getter_column not in returned:
            payload = _output_return_values(event.raw)
            scalar = None
            if not isinstance(payload, (dict, list, tuple, set)):
                scalar = payload
            elif isinstance(payload, dict):
                scalar = _mapping_value(payload, "value", "Value", "result", "Result", "return", "Return", "rv", "RV")
            parsed_scalar = _as_bool(scalar) if single_getter_column == 7 and isinstance(scalar, bool) else _parse_int(scalar)
            if parsed_scalar is not None:
                returned = dict(returned)
                returned[single_getter_column] = parsed_scalar
        for column, value in returned.items():
            if column in LOCKING_INFO_COLUMNS:
                state.locking_info[LOCKING_INFO_COLUMNS[column]] = value
        return

    if symbol == "TPerInfo" and 8 in returned:
        state.programmatic_reset_enabled = _as_bool(returned[8])
        return

    byte_table_symbol = _byte_table_symbol_from_descriptor(symbol)
    if byte_table_symbol is not None:
        if 7 in returned:
            rows = _parse_int(returned[7])
            if rows is not None and rows >= 0:
                state.byte_table_rows[byte_table_symbol] = rows
        if TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN in returned:
            mandatory = _parse_int(returned[TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN])
            if mandatory is not None and mandatory > 0:
                state.byte_table_mandatory_granularity[byte_table_symbol] = mandatory
        if TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN in returned:
            recommended = _parse_int(returned[TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN])
            if recommended is not None and recommended > 0:
                state.byte_table_recommended_granularity[byte_table_symbol] = recommended
        return

    if symbol == "SPInfo" and state.session.sp is not None:
        if 5 in returned:
            timeout = _parse_int(returned[5])
            if timeout is not None:
                state.sp_session_timeouts[state.session.sp] = max(0, timeout)
        if 6 in returned:
            state.sp_enabled[state.session.sp] = _as_bool(returned[6])
        return

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        range_state = _range(state, range_id)
        _update_range_from_columns(range_state, returned)
        return

    if symbol == "MBRControl":
        for column, value in returned.items():
            if column in MBR_COLUMNS:
                state.mbr[MBR_COLUMNS[column]] = value
        return

    if symbol == "DataRemovalMechanism" and 1 in returned:
        state.data_removal_mechanism = returned[1]
        return

    authority = _authority_by_object(symbol)
    if authority:
        _update_authority_from_columns(state, authority, returned)


def _apply_level0_opal_ssc_v2_success(state: State, event: Event) -> None:
    if not _is_level0_opal_ssc_v2_event(event):
        return
    behavior = _level0_return_value(
        event.raw,
        "RangeCrossingBehavior",
        "Range Crossing Behavior",
        "RangeCrossing",
    )
    parsed = _parse_int(behavior)
    if parsed in {0, 1}:
        state.range_crossing_behavior = parsed
    sid_revert_behavior = _level0_return_value(
        event.raw,
        "BehaviorOfCPINSIDPINUponTPerRevert",
        "Behavior of C_PIN_SID PIN upon TPer Revert",
        "SIDPINRevertBehavior",
    )
    parsed_sid_revert_behavior = _parse_int(sid_revert_behavior)
    if parsed_sid_revert_behavior in {0x00, 0xFF}:
        state.sid_pin_revert_behavior = parsed_sid_revert_behavior
    user_authority_count = _level0_return_value(
        event.raw,
        "NumberOfLockingSPUserAuthorities",
        "Number of Locking SP User Authorities",
        "LockingSPUserAuthorities",
    )
    parsed_user_authority_count = _parse_int(user_authority_count)
    if parsed_user_authority_count is not None and parsed_user_authority_count >= 0:
        state.locking_sp_user_authority_count = parsed_user_authority_count


def _is_level0_opal_ssc_v2_event(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    inp = _input_section(event.raw)
    args = _mapping_section(inp, "args", "Args", "arguments", "Arguments")
    if not args:
        args = _mapping_section(event.raw, "args", "Args", "arguments", "Arguments")
    feature_code = _parse_int(
        _first_mapping_value(args, inp, event.raw, names=("FeatureCode", "featureCode", "feature_code", "code", "Code"))
    )
    feature_name = re.sub(
        r"[^A-Za-z0-9]",
        "",
        _as_text(_first_mapping_value(args, inp, event.raw, names=("Feature", "feature", "Name", "name")) or ""),
    ).lower()
    return feature_code == 0x0203 or feature_name in {"opalsscv2", "opalv2", "opalsscv2feature"}


def _first_mapping_value(*sources: Any, names: tuple[str, ...]) -> Any:
    for source in sources:
        if not isinstance(source, dict):
            continue
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    return None


def _level0_return_value(raw: dict[str, Any], *names: str) -> Any:
    payload = _output_return_values(raw)
    return _payload_value_by_name(payload, names)


def _payload_value_by_name(value: Any, names: tuple[str, ...]) -> Any:
    wanted = {re.sub(r"[^A-Za-z0-9]", "", _as_text(name)).upper() for name in names}
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper() in wanted:
                return item
        for item in value.values():
            selected = _payload_value_by_name(item, names)
            if selected is not None:
                return selected
    if isinstance(value, (list, tuple, set)):
        for item in value:
            selected = _payload_value_by_name(item, names)
            if selected is not None:
                return selected
    return None


def _update_range_from_columns(range_state: RangeState, values: dict[int, Any]) -> None:
    for column, value in values.items():
        field_name = LOCKING_COLUMNS.get(column)
        if field_name is None:
            continue
        if field_name == "RangeStart":
            parsed = _parse_int(value)
            if parsed is not None:
                range_state.range_start = parsed
        elif field_name == "RangeLength":
            parsed = _parse_int(value)
            if parsed is not None:
                range_state.range_length = parsed
                range_state.range_length_known = True
        elif field_name == "ReadLockEnabled":
            range_state.read_lock_enabled = _as_bool(value)
        elif field_name == "WriteLockEnabled":
            range_state.write_lock_enabled = _as_bool(value)
        elif field_name == "ReadLocked":
            range_state.read_locked = _as_bool(value)
        elif field_name == "WriteLocked":
            range_state.write_locked = _as_bool(value)
        elif field_name == "LockOnReset":
            range_state.lock_on_reset_types = _reset_types(value)
            range_state.lock_on_reset = bool(range_state.lock_on_reset_types)
        elif field_name == "ActiveKey":
            range_state.active_key = str(value)
            range_state.active_key_known = True
        elif field_name == "NextKey":
            range_state.next_key = None if _clean_uid(value) in {"", "0000000000000000"} else str(value)
            range_state.next_key_known = True
        elif field_name == "ReEncryptState":
            parsed = _parse_reencrypt_state(value)
            if parsed is not None:
                range_state.reencrypt_state = parsed
        elif field_name == "ReEncryptRequest":
            request = _parse_reencrypt_request(value)
            if request is not None:
                range_state.reencrypt_request = request
                _apply_reencrypt_request_success(range_state, request)
        elif field_name == "AdvKeyMode":
            range_state.adv_key_mode = _parse_int(value)
        elif field_name == "VerifyMode":
            range_state.verify_mode = _parse_int(value)
        elif field_name == "ContOnReset":
            range_state.cont_on_reset = value
        elif field_name == "LastReEncryptLBA":
            range_state.last_reencrypt_lba = _parse_int(value)
        elif field_name == "LastReEncStat":
            range_state.last_reenc_stat = value
        elif field_name == "GeneralStatus":
            range_state.general_status = value


def _apply_reencrypt_request_success(range_state: RangeState, request: int) -> None:
    previous_state = range_state.reencrypt_state
    if request == 1:
        range_state.reencrypt_state = 2
        range_state.last_reencrypt_lba = 0xFFFFFFFFFFFFFFFF
        range_state.general_status = None
    elif request == 2:
        range_state.active_key = range_state.next_key
        range_state.active_key_known = range_state.next_key_known
        range_state.next_key = None
        range_state.next_key_known = True
        range_state.reencrypt_state = 1
        range_state.general_status = None
    elif request == 3:
        range_state.reencrypt_state = 1
        range_state.general_status = None
    elif request == 4:
        range_state.reencrypt_state = 2
        range_state.general_status = None
    elif request == 5:
        range_state.reencrypt_state = 5
        if previous_state == 3:
            range_state.general_status = 3
        elif previous_state == 2:
            range_state.general_status = 4


def _secure_mode_value(value: Any) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return max(0, parsed)
    text = _as_text(value).strip().lower()
    if not text:
        return None
    if text in {"none", "null", "plaintext", "plain"}:
        return 0
    return 1


def _hash_and_sign_required(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed != 0
    text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return text not in {"", "0", "NONE", "NULL", "FALSE", "F", "NO", "N"}


def _uid_ref_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        for key in ("uid", "UID", "value", "Value", "ref", "Ref"):
            found, nested = _dict_lookup(value, key)
            if found:
                return _uid_ref_present(nested)
    if isinstance(value, (list, tuple, set)):
        return any(_uid_ref_present(item) for item in value)
    cleaned = _clean_uid(value)
    if cleaned:
        return any(char != "0" for char in cleaned)
    text = _as_text(value).strip().lower()
    return text not in {"", "0", "none", "null", "null uid", "nulluid"}


def _credential_symbol_from_value(value: Any) -> str | None:
    if not _uid_ref_present(value):
        return None
    if isinstance(value, dict):
        for key in ("uid", "UID", "credential", "Credential", "object", "Object", "value", "Value", "ref", "Ref"):
            found, nested = _dict_lookup(value, key)
            if found:
                symbol = _credential_symbol_from_value(nested)
                if symbol:
                    return symbol
        for key in ("name", "Name"):
            found, nested = _dict_lookup(value, key)
            if found:
                normalized = _normalize_name(nested)
                if normalized:
                    return normalized
        for nested in value.values():
            symbol = _credential_symbol_from_value(nested)
            if symbol:
                return symbol
        return None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            symbol = _credential_symbol_from_value(item)
            if symbol:
                return symbol
        return None
    uid = _clean_uid(value)
    symbol = _object_by_uid(uid, _as_text(value))
    return symbol or None


def _update_authority_from_columns(state: State, authority: str, values: dict[int, Any]) -> None:
    if 5 in values:
        state.authority_enabled[authority] = _enabled_bool(values[5])
    if 6 in values:
        secure = _secure_mode_value(values[6])
        if secure is not None:
            state.authority_secure[authority] = secure
    if 7 in values:
        state.authority_hash_and_sign[authority] = _hash_and_sign_required(values[7])
    if 10 in values:
        state.authority_credential_present[authority] = _uid_ref_present(values[10])
        state.authority_credential_symbol[authority] = _credential_symbol_from_value(values[10])
    if 11 in values:
        state.authority_response_sign[authority] = _authority_from_value(values[11])
    if 12 in values:
        state.authority_response_exchange[authority] = _authority_from_value(values[12])
    if 13 in values:
        state.authority_response_exchange[authority] = _authority_from_value(values[13])
    if 15 in values:
        limit = _parse_int(values[15])
        if limit is not None:
            state.authority_limits[authority] = max(0, limit)
    if 16 in values:
        uses = _parse_int(values[16])
        if uses is not None:
            state.authority_uses[authority] = max(0, uses)


def _byte_table_payload_pattern(event: Event) -> str | None:
    payload_keys = (
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
        "payloadBytes",
        "PayloadBytes",
        "byteArray",
        "ByteArray",
    )
    payload_key_names = {
        "bytes",
        "data",
        "buffer",
        "bufferin",
        "payload",
        "blob",
        "content",
        "buf",
        "hex",
        "payloadbytes",
        "bytearray",
        "1",
    }

    for source in (event.required, event.optional):
        found, value = _dict_lookup(source, *payload_keys)
        if found:
            pattern = _extract_pattern(value)
            if pattern is not None:
                return pattern

    def walk(value: Any) -> str | None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if key_text in payload_key_names:
                    pattern = _extract_pattern(item)
                    if pattern is not None:
                        return pattern
                nested = walk(item)
                if nested is not None:
                    return nested
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(item[0])).lower()
                    if key_text in payload_key_names:
                        pattern = _extract_pattern(item[1])
                        if pattern is not None:
                            return pattern
                nested = walk(item)
                if nested is not None:
                    return nested
        return None

    return walk(_method_raw_args(event))


def _hex_payload_bytes(pattern: str | None) -> list[str] | None:
    if pattern is None or len(pattern) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", pattern):
        return None
    return [pattern[index : index + 2].upper() for index in range(0, len(pattern), 2)]


def _contiguous_byte_pattern(bytes_by_offset: dict[int, str]) -> str | None:
    contiguous: list[str] = []
    index = 0
    while index in bytes_by_offset:
        contiguous.append(bytes_by_offset[index])
        index += 1
    return "".join(contiguous) if contiguous else None


def _fully_contiguous_from_zero(bytes_by_offset: dict[int, str]) -> bool:
    if not bytes_by_offset:
        return False
    return set(bytes_by_offset) == set(range(max(bytes_by_offset) + 1))


def _apply_set_success(state: State, event: Event) -> None:
    event, where_error = _set_effective_event(event)
    if where_error is not None:
        return

    symbol = event.invoking_symbol
    if symbol == "MBR":
        pattern = _byte_table_payload_pattern(event)
        if pattern is not None:
            start_offset = _byte_table_set_start_offset(event)
            payload_bytes = _hex_payload_bytes(pattern)
            if start_offset is not None and payload_bytes is not None:
                for offset, byte in enumerate(payload_bytes, start=start_offset):
                    state.mbr_table_bytes[offset] = byte
                contiguous = _contiguous_byte_pattern(state.mbr_table_bytes)
                if contiguous is not None and _fully_contiguous_from_zero(state.mbr_table_bytes):
                    state.mbr_table_pattern = contiguous
                else:
                    state.mbr_table_pattern = None
            elif start_offset in (None, 0):
                state.mbr_table_pattern = pattern
                state.mbr_table_bytes.clear()
        return

    if symbol.startswith("DataStore"):
        pattern = _byte_table_payload_pattern(event)
        if pattern is not None:
            start_offset = _byte_table_set_start_offset(event)
            payload_bytes = _hex_payload_bytes(pattern)
            if start_offset is not None and payload_bytes is not None:
                for offset, byte in enumerate(payload_bytes, start=start_offset):
                    state.datastore_bytes[offset] = byte
                contiguous = _contiguous_byte_pattern(state.datastore_bytes)
                if contiguous is not None and _fully_contiguous_from_zero(state.datastore_bytes):
                    state.datastore_pattern = contiguous
                else:
                    state.datastore_pattern = None
            elif start_offset in (None, 0):
                state.datastore_pattern = pattern
                state.datastore_bytes.clear()
        return

    if symbol.startswith("Port"):
        row = state.port_values.setdefault(symbol, {})
        for column, value in event.values.items():
            if column in PORT_COLUMNS:
                row[column] = value
        return

    if symbol.startswith("TLS_PSK_Key"):
        row = state.psk_values.setdefault(symbol, {})
        for column, value in event.values.items():
            if column in TLS_PSK_COLUMNS:
                row[column] = value
        return

    if symbol.startswith("ACE_") and ACE_BOOLEAN_EXPR_COLUMN in event.values:
        expression = _ace_expression_from_value(event.values[ACE_BOOLEAN_EXPR_COLUMN])
        state.ace_expressions[_ace_key(state, symbol)] = expression

        grant = _ace_locking_grant(symbol)
        if grant is not None:
            kind, range_id = grant
            target = state.range_read_lock_users if kind == "read" else state.range_write_lock_users
            target[range_id] = _ace_expression_users(state, symbol)
            return

        datastore_grant = _ace_datastore_grant(symbol)
        if datastore_grant is not None:
            target = state.datastore_read_users if datastore_grant == "read" else state.datastore_write_users
            target.clear()
            target.update(_ace_expression_users(state, symbol))
            return

        return

    grant = _ace_locking_grant(symbol)
    if grant is not None:
        kind, range_id = grant
        users = {auth for auth in _extract_authorities(event.values.get(ACE_BOOLEAN_EXPR_COLUMN, event.raw)) if _is_user(auth)}
        target = state.range_read_lock_users if kind == "read" else state.range_write_lock_users
        target.setdefault(range_id, set()).update(users)
        return

    datastore_grant = _ace_datastore_grant(symbol)
    if datastore_grant is not None:
        users = {auth for auth in _extract_authorities(event.values.get(ACE_BOOLEAN_EXPR_COLUMN, event.raw)) if _is_user(auth)}
        target = state.datastore_read_users if datastore_grant == "read" else state.datastore_write_users
        target.update(users)
        return

    owner = _pin_owner_by_object(symbol)
    if owner and PIN_COLUMN in event.values:
        state.pins[owner] = _credential_text(event.values[PIN_COLUMN])
        state.invalidated_pin_values.pop(owner, None)
        state.pin_tries[owner] = 0
        if MIN_PIN_COLUMN in event.values:
            min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
            if min_pin is not None:
                state.pin_min_lengths[owner] = min_pin
    if owner and CPIN_TRY_LIMIT_COLUMN in event.values:
        try_limit = _parse_int(event.values[CPIN_TRY_LIMIT_COLUMN])
        if try_limit is not None:
            state.pin_try_limits[owner] = max(0, try_limit)
            if try_limit == 0:
                state.pin_tries[owner] = 0
    if owner and CPIN_TRIES_COLUMN in event.values:
        tries = _parse_int(event.values[CPIN_TRIES_COLUMN])
        if tries is not None:
            state.pin_tries[owner] = max(0, tries)
    if owner and CPIN_PERSISTENCE_COLUMN in event.values:
        state.pin_persistence[owner] = _as_bool(event.values[CPIN_PERSISTENCE_COLUMN])
    if owner and PIN_COLUMN in event.values:
        return
    if owner and MIN_PIN_COLUMN in event.values:
        min_pin = _parse_int(event.values[MIN_PIN_COLUMN])
        if min_pin is not None:
            state.pin_min_lengths[owner] = min_pin
        return

    authority = _authority_by_object(symbol)
    if authority and set(event.values) & {5, 6, 7, 10, 13, 15, 16}:
        _update_authority_from_columns(state, authority, event.values)
        return

    if symbol in {"AdminSP", "LockingSP"} and 7 in event.values:
        state.sp_frozen[symbol] = _as_bool(event.values[7])
        return

    if _is_loglist_row_symbol(symbol, event.invoking_uid):
        key = _loglist_row_key(symbol, event.invoking_uid)
        row = state.loglist_rows.setdefault(key, {})
        if 5 in event.values:
            row[5] = _as_bool(event.values[5])
        return

    range_id = _range_id_from_symbol(symbol)
    if range_id is not None:
        _update_range_from_columns(_range(state, range_id), event.values)
        return

    if symbol == "MBRControl":
        for column, value in event.values.items():
            if column in MBR_COLUMNS:
                state.mbr[MBR_COLUMNS[column]] = value
        return

    if symbol == "DataRemovalMechanism" and 1 in event.values:
        state.data_removal_mechanism = event.values[1]
        return

    if symbol == "TPerInfo" and 8 in event.values:
        state.programmatic_reset_enabled = _as_bool(event.values[8])
        return

    if symbol == "SPInfo" and state.session.sp is not None:
        if 5 in event.values:
            timeout = _parse_int(event.values[5])
            if timeout is not None:
                state.sp_session_timeouts[state.session.sp] = max(0, timeout)
        if 6 in event.values:
            state.sp_enabled[state.session.sp] = _as_bool(event.values[6])
        return

    if symbol.startswith("Table_"):
        table_uid = state.created_table_descriptor_uids.get(event.invoking_uid)
        if table_uid:
            if 11 in event.values:
                min_size = _parse_int(event.values[11])
                if min_size is not None and min_size >= 0:
                    state.created_table_min_sizes[table_uid] = min_size
            if 12 in event.values:
                max_size = _parse_int(event.values[12])
                if max_size is not None and max_size >= 0:
                    state.created_table_max_sizes[table_uid] = max_size
        return


SESSION_TIMEOUT_PROPERTIES = {
    "DEFSESSIONTIMEOUT": "def",
    "DEFAULTSESSIONTIMEOUT": "def",
    "MAXSESSIONTIMEOUT": "max",
    "MINSESSIONTIMEOUT": "min",
}


TRANS_TIMEOUT_PROPERTIES = {
    "DEFTRANSTIMEOUT": "def_trans",
    "DEFAULTTRANSTIMEOUT": "def_trans",
    "MAXTRANSTIMEOUT": "max_trans",
    "MINTRANSTIMEOUT": "min_trans",
}


def _timeout_property_name(value: Any) -> str | None:
    key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value or "")).upper()
    return SESSION_TIMEOUT_PROPERTIES.get(key) or TRANS_TIMEOUT_PROPERTIES.get(key)


def _coerced_host_property_value(name: str, value: Any) -> Any:
    initial = OPAL_HOST_PROPERTY_INITIALS.get(name, HOST_PROPERTY_INITIALS.get(name))
    if isinstance(initial, bool):
        return _as_bool(value)
    parsed = _parse_int(value)
    if parsed is None:
        return None
    if initial is None:
        return max(0, parsed)
    return max(int(initial or 0), max(0, parsed))


def _apply_host_property_response(state: State, event: Event, returned: dict[str, Any]) -> None:
    if not returned:
        return
    current = _opal_host_property_initials()
    for name, value in returned.items():
        coerced = _coerced_host_property_value(name, value)
        if coerced is not None:
            current[name] = coerced
    if current.get("AckNak") is True and current.get("SequenceNumbers") is False:
        current["AckNak"] = False
        current["SequenceNumbers"] = False
    if event.comid:
        state.host_properties_by_comid[event.comid] = current
    else:
        state.host_properties = current


def _return_uids(value: Any) -> list[str]:
    out: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for nested in item.values():
                walk(nested)
            return
        if isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)
            return
        uid = _clean_uid(item)
        if uid:
            out.append(uid)

    walk(value)
    return out


def _apply_properties_success(state: State, event: Event) -> None:
    returned = _output_return_values(event.raw)
    if _host_properties_parameter_present(event):
        _apply_host_property_response(state, event, _returned_host_properties(returned))

    def apply_property(kind: str | None, value: Any) -> None:
        if kind is None:
            return
        parsed = _parse_int(value)
        if parsed is None:
            return
        parsed = max(0, parsed)
        if kind == "def":
            state.tper_def_session_timeout = parsed
        elif kind == "max":
            state.tper_max_session_timeout = parsed
        elif kind == "min":
            state.tper_min_session_timeout = parsed
        elif kind == "def_trans":
            state.tper_def_trans_timeout = parsed
        elif kind == "max_trans":
            state.tper_max_trans_timeout = parsed
        elif kind == "min_trans":
            state.tper_min_trans_timeout = parsed

    def named_value_from_row(row: dict[Any, Any]) -> tuple[str | None, Any]:
        property_name = None
        property_value = None
        for key, value in row.items():
            normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key or "")).upper()
            if normalized in {"PROPERTY", "PROPERTYNAME", "NAME", "KEY"}:
                property_name = _timeout_property_name(value)
            elif normalized in {"VALUE", "PROPERTYVALUE", "VAL"}:
                property_value = value
        return property_name, property_value

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            property_name, property_value = named_value_from_row(value)
            apply_property(property_name, property_value)
            for key, item in value.items():
                apply_property(_timeout_property_name(key), item)
                walk(item)
            return
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
                apply_property(_timeout_property_name(value[0]), value[1])
            for item in value:
                walk(item)

    walk(returned)


def _apply_create_row_success(state: State, event: Event) -> None:
    if _created_table_for_event(state, event) is not None:
        row_values = dict(event.values)
        state.created_table_rows.setdefault(event.invoking_uid, []).append(row_values)
        meta_acl_authorities = _created_row_meta_acl_authorities(state)
        for row_uid in _return_uids(_output_return_values(event.raw)):
            _clear_access_control_state_for_invoking_ids(state, {row_uid})
            state.created_table_row_values_by_uid[row_uid] = (event.invoking_uid, row_values)
            state.created_table_row_meta_acl_authorities[row_uid] = set(meta_acl_authorities)
        state.created_table_allocated_rows[event.invoking_uid] = max(
            state.created_table_allocated_rows.get(event.invoking_uid, 0),
            len(state.created_table_rows[event.invoking_uid]),
        )
        return
    if _cec_family_from_table_symbol(event.invoking_symbol) is not None:
        table_key = event.invoking_uid or event.invoking_symbol
        row_values = _cec_defaulted_row_values(event.invoking_symbol, event.values)
        state.created_tables.setdefault(table_key, (state.session.sp or "", "object"))
        state.created_table_rows.setdefault(table_key, []).append(row_values)
        meta_acl_authorities = _created_row_meta_acl_authorities(state)
        for row_uid in _return_uids(_output_return_values(event.raw)):
            _clear_access_control_state_for_invoking_ids(state, {row_uid})
            state.created_table_row_values_by_uid[row_uid] = (table_key, row_values)
            state.created_table_row_meta_acl_authorities[row_uid] = set(meta_acl_authorities)
        state.created_table_allocated_rows[table_key] = max(
            state.created_table_allocated_rows.get(table_key, 0),
            len(state.created_table_rows[table_key]),
        )
        return
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    range_id = _created_locking_range_id(state, event)
    _clear_access_control_state_for_invoking_ids(state, {_locking_range_invoking_id(range_id)})
    state.created_locking_ranges.add(range_id)
    range_state = _range(state, range_id)
    _update_range_from_columns(range_state, event.values)


def _locking_range_invoking_id(range_id: int) -> str:
    return "Locking_GlobalRange" if range_id == 0 else f"Locking_Range{range_id}"


def _clear_access_control_state_for_invoking_ids(state: State, invoking_ids: set[str]) -> None:
    state.deleted_method_associations = {
        combo
        for combo in state.deleted_method_associations
        if combo[0] not in invoking_ids
    }
    state.access_control_acl_additions = {
        combo: refs
        for combo, refs in state.access_control_acl_additions.items()
        if combo[0] not in invoking_ids
    }
    state.access_control_acl_removals = {
        combo: refs
        for combo, refs in state.access_control_acl_removals.items()
        if combo[0] not in invoking_ids
    }
    state.access_control_acl_replacements = {
        combo: refs
        for combo, refs in state.access_control_acl_replacements.items()
        if combo[0] not in invoking_ids
    }


def _tombstone_method_associations(state: State, invoking_ids: set[str], method_names: tuple[str, ...]) -> None:
    _clear_access_control_state_for_invoking_ids(state, invoking_ids)
    for invoking_id in invoking_ids:
        for method_name in method_names:
            state.deleted_method_associations.add((invoking_id, method_name))


def _remove_range_state(state: State, range_id: int) -> None:
    range_invoking_id = _locking_range_invoking_id(range_id)
    _tombstone_method_associations(state, {range_invoking_id}, ("Get", "Set", "Delete", "Erase"))
    state.ranges.pop(range_id, None)
    state.created_locking_ranges.discard(range_id)
    state.range_read_lock_users.pop(range_id, None)
    state.range_write_lock_users.pop(range_id, None)
    state.lba_patterns = {
        lba: remembered
        for lba, remembered in state.lba_patterns.items()
        if remembered[1] != range_id
    }


def _apply_delete_row_success(state: State, event: Event) -> None:
    if event.invoking_symbol in {"Table", "TableTable", "Table_Table"} or event.invoking_uid == "0000000100000000":
        descriptor_uids = [uid for _, uid in _row_object_refs(event)] + _row_uids(event)
        for descriptor_uid in descriptor_uids:
            table_uid = state.created_table_descriptor_uids.get(_clean_uid(descriptor_uid))
            if table_uid:
                _remove_created_table_state(state, table_uid)
        return
    if _created_table_for_event(state, event) is not None:
        for _, row_uid in _row_object_refs(event):
            if not row_uid:
                continue
            _remove_created_table_row_state(state, row_uid)
        for row_uid in _row_uids(event):
            _remove_created_table_row_state(state, row_uid)
        return
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return
    refs = _row_object_refs(event) or [(_object_by_uid(uid), uid) for uid in _row_uids(event)]
    for symbol, uid in refs:
        range_id = _range_id_from_symbol(symbol) if symbol else _range_id_from_symbol(_object_by_uid(uid))
        if range_id is None or range_id == 0:
            continue
        _remove_range_state(state, range_id)


def _created_row_meta_acl_authorities(state: State) -> set[str]:
    authorities = {authority for authority in state.session.authenticated if authority != "Anybody"}
    return authorities or {"Anybody"}


def _remove_created_table_row_state(state: State, row_uid: str) -> None:
    clean_uid = _clean_uid(row_uid)
    if not clean_uid:
        return
    table_and_values = state.created_table_row_values_by_uid.pop(clean_uid, None)
    state.created_table_row_meta_acl_authorities.pop(clean_uid, None)
    if table_and_values is not None:
        table_uid, row_values = table_and_values
        rows = state.created_table_rows.get(table_uid)
        if rows is not None:
            state.created_table_rows[table_uid] = [row for row in rows if row is not row_values]
            state.created_table_allocated_rows[table_uid] = len(state.created_table_rows[table_uid])
    _tombstone_method_associations(state, {clean_uid}, ("Get", "Set", "Delete"))


def _apply_delete_success(state: State, event: Event) -> None:
    if event.invoking_uid in state.created_table_row_values_by_uid:
        _remove_created_table_row_state(state, event.invoking_uid)
        return
    table_uid = state.created_table_descriptor_uids.get(event.invoking_uid)
    if table_uid:
        _remove_created_table_state(state, table_uid)
        return
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is not None and range_id != 0:
        _remove_range_state(state, range_id)


def _apply_delete_method_success(state: State, event: Event) -> None:
    combo_key = _access_control_combo_key_for_state(state, event)
    if combo_key is not None:
        state.deleted_method_associations.add(combo_key)


def _apply_acl_mutation_success(state: State, event: Event) -> None:
    combo_key = _access_control_combo_key_for_state(state, event)
    if combo_key is None:
        return
    refs = _canonical_ace_refs(_ace_method_refs(event))
    if not refs:
        if event.method == "SetACL" and _setacl_has_empty_acl_argument(event):
            state.access_control_acl_replacements[combo_key] = set()
            state.access_control_acl_additions.pop(combo_key, None)
            state.access_control_acl_removals.pop(combo_key, None)
        return
    if event.method == "SetACL":
        state.access_control_acl_replacements[combo_key] = set(refs)
        state.access_control_acl_additions.pop(combo_key, None)
        state.access_control_acl_removals.pop(combo_key, None)
    elif event.method == "AddACE":
        replacement = state.access_control_acl_replacements.get(combo_key)
        if replacement is not None:
            replacement.update(refs)
            return
        state.access_control_acl_removals.setdefault(combo_key, set()).difference_update(refs)
        state.access_control_acl_additions.setdefault(combo_key, set()).update(refs)
    elif event.method == "RemoveACE":
        replacement = state.access_control_acl_replacements.get(combo_key)
        if replacement is not None:
            replacement.difference_update(refs)
            return
        state.access_control_acl_additions.setdefault(combo_key, set()).difference_update(refs)
        state.access_control_acl_removals.setdefault(combo_key, set()).update(refs)


def _create_table_return_uid(event: Event) -> str:
    returned = _output_return_values(event.raw)

    def walk_uid_key(value: Any) -> str:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
                if key_text in {"UID", "TABLEUID"}:
                    uid = _uid_ref(item)
                    if uid:
                        return uid
                nested = walk_uid_key(item)
                if nested:
                    return nested
        if isinstance(value, (list, tuple, set)):
            for item in value:
                nested = walk_uid_key(item)
                if nested:
                    return nested
        return ""

    uid = walk_uid_key(returned)
    if uid:
        return uid
    if isinstance(returned, (list, tuple)) and returned:
        first = returned[0]
        if not isinstance(first, dict):
            return _uid_ref(first)
    return ""


def _create_table_return_rows(event: Event) -> int | None:
    returned = _output_return_values(event.raw)

    def walk_rows_key(value: Any) -> int | None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
                if key_text == "ROWS":
                    parsed = _parse_int(item)
                    if parsed is not None:
                        return parsed
                nested = walk_rows_key(item)
                if nested is not None:
                    return nested
        if isinstance(value, (list, tuple, set)):
            for item in value:
                nested = walk_rows_key(item)
                if nested is not None:
                    return nested
        return None

    rows = walk_rows_key(returned)
    if rows is not None:
        return rows
    if isinstance(returned, (list, tuple)) and len(returned) >= 2:
        return _parse_int(returned[1])
    return None


def _table_descriptor_uid_from_table_uid(table_uid: str) -> str:
    uid = _clean_uid(table_uid)
    if len(uid) == 16 and uid[8:] == "00000000" and uid[:8] != "00000000":
        return "00000001" + uid[:8]
    return ""


def _remove_created_table_state(state: State, table_uid: str) -> None:
    table_uid = _clean_uid(table_uid)
    if not table_uid:
        return
    descriptor_uids = {
        descriptor_uid
        for descriptor_uid, mapped_table_uid in state.created_table_descriptor_uids.items()
        if mapped_table_uid == table_uid
    }
    removed_invoking_ids = {table_uid, *descriptor_uids}

    name_key = state.created_table_name_by_uid.pop(table_uid, None)
    if name_key is not None:
        state.created_table_names.discard(name_key)
    state.created_tables.pop(table_uid, None)
    state.created_table_columns.pop(table_uid, None)
    state.created_table_unique_columns.pop(table_uid, None)
    state.created_table_rows.pop(table_uid, None)
    state.created_table_min_sizes.pop(table_uid, None)
    state.created_table_max_sizes.pop(table_uid, None)
    state.created_table_allocated_rows.pop(table_uid, None)
    state.created_table_getset_acls.pop(table_uid, None)
    removed_row_uids = {
        row_uid
        for row_uid, table_and_values in state.created_table_row_values_by_uid.items()
        if table_and_values[0] == table_uid
    }
    state.created_table_row_values_by_uid = {
        row_uid: table_and_values
        for row_uid, table_and_values in state.created_table_row_values_by_uid.items()
        if table_and_values[0] != table_uid
    }
    for row_uid in removed_row_uids:
        state.created_table_row_meta_acl_authorities.pop(row_uid, None)
    for descriptor_uid in descriptor_uids:
        state.created_table_descriptor_uids.pop(descriptor_uid, None)

    removed_invoking_ids |= removed_row_uids
    _tombstone_method_associations(state, removed_invoking_ids, ("Next", "Get", "Set", "Delete"))


def _apply_create_table_success(state: State, event: Event) -> None:
    if state.session.sp is None:
        return
    found_name, name_value = _create_table_arg(event, 0, "NewTableName", "Name", "TableName")
    found_common, common_value = _create_table_arg(event, 7, "CommonName")
    found_kind, kind_value = _create_table_arg(event, 1, "Kind", "TableKind")
    found_columns, columns_value = _create_table_arg(event, 3, "Columns")
    found_acl, acl_value = _create_table_arg(event, 2, "GetSetACL", "GetSetAcl", "ACL", "AccessControlList")
    name_key = (
        state.session.sp,
        _create_table_name_text(name_value) if found_name else "",
        _create_table_name_text(common_value) if found_common else "",
    )
    if found_name:
        state.created_table_names.add(name_key)
    kind = _create_table_kind(kind_value) if found_kind else None
    uid = _create_table_return_uid(event)
    if uid and kind is not None:
        descriptor_uid = _table_descriptor_uid_from_table_uid(uid)
        invoking_ids = {uid}
        if descriptor_uid:
            invoking_ids.add(descriptor_uid)
        _clear_access_control_state_for_invoking_ids(state, invoking_ids)
        if found_name:
            state.created_table_name_by_uid[uid] = name_key
        state.created_tables[uid] = (state.session.sp, kind)
        if descriptor_uid:
            state.created_table_descriptor_uids[descriptor_uid] = uid
        found_min, min_value = _create_table_arg(event, 4, "MinSize", "MinimumSize")
        min_size = _parse_int(min_value) if found_min else None
        if min_size is not None:
            state.created_table_min_sizes[uid] = min_size
        found_max, max_value = _create_table_arg(event, 5, "MaxSize", "MaximumSize")
        max_size = _parse_int(max_value) if found_max else None
        if max_size is not None:
            state.created_table_max_sizes[uid] = max_size
        rows = _create_table_return_rows(event)
        if rows is not None:
            state.created_table_allocated_rows[uid] = rows
        if found_columns:
            columns, unique_columns = _create_table_column_schema(columns_value)
            state.created_table_columns[uid] = columns
            state.created_table_unique_columns[uid] = unique_columns
            state.created_table_rows.setdefault(uid, [])
        if found_acl:
            state.created_table_getset_acls[uid] = _canonical_ace_refs(acl_value if isinstance(acl_value, (list, tuple, set)) else [acl_value])


def _apply_create_log_success(state: State, event: Event) -> None:
    if state.session.sp is None:
        return
    found_name, name_value = _create_table_arg(event, 0, "NewLogTableName", "Name", "LogTableName")
    if not found_name:
        return
    found_common, common_value = _create_table_arg(event, 5, "CommonName")
    state.created_table_names.add(
        (
            state.session.sp,
            _create_table_name_text(name_value),
            _create_table_name_text(common_value) if found_common else "",
        )
    )


def _getacl_invoking_range_id(event: Event) -> int | None:
    (found_invoking, invoking_value), _ = _access_control_arg_values(event)
    if not found_invoking:
        return None
    symbol, invoking_uid = _object_ref_from_value(invoking_value)
    if not symbol and invoking_uid:
        symbol = _object_by_uid(invoking_uid)
    range_id = _range_id_from_symbol(symbol)
    if range_id is None:
        range_id = _range_id_from_key(symbol)
    return range_id


def _apply_erase_success(state: State, event: Event) -> None:
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return
    _range(state, range_id).media_generation += 1
    state.pins.pop(f"BandMaster{range_id}", None)
    state.authority_enabled.pop(f"BandMaster{range_id}", None)


def _invalidate_lba_patterns(state: State, keep_global: bool = False) -> None:
    state.lba_patterns = {
        lba: (pattern, range_id, generation if keep_global and range_id == 0 else -1)
        for lba, (pattern, range_id, generation) in state.lba_patterns.items()
    }


def _reset_locking_sp(state: State, keep_global_key: bool = False) -> None:
    global_generation = _range(state, 0).media_generation
    state.locking_sp_activated = False
    state.sp_enabled.pop("LockingSP", None)
    state.sp_frozen.pop("LockingSP", None)
    state.authority_enabled = {k: v for k, v in state.authority_enabled.items() if not k.startswith(("User", "Admin"))}
    state.authority_limits = {k: v for k, v in state.authority_limits.items() if not k.startswith(("User", "Admin"))}
    state.authority_uses = {k: v for k, v in state.authority_uses.items() if not k.startswith(("User", "Admin"))}
    state.authority_hash_and_sign = {k: v for k, v in state.authority_hash_and_sign.items() if not k.startswith(("User", "Admin"))}
    state.authority_response_sign = {k: v for k, v in state.authority_response_sign.items() if not k.startswith(("User", "Admin"))}
    state.authority_response_exchange = {k: v for k, v in state.authority_response_exchange.items() if not k.startswith(("User", "Admin"))}
    state.pins = {k: v for k, v in state.pins.items() if not k.startswith(("User", "Admin"))}
    state.invalidated_pin_values = {k: v for k, v in state.invalidated_pin_values.items() if not k.startswith(("User", "Admin"))}
    state.pin_min_lengths = {k: v for k, v in state.pin_min_lengths.items() if not k.startswith(("User", "Admin"))}
    state.pin_try_limits = {k: v for k, v in state.pin_try_limits.items() if not k.startswith(("User", "Admin"))}
    state.pin_tries = {k: v for k, v in state.pin_tries.items() if not k.startswith(("User", "Admin"))}
    state.pin_persistence = {k: v for k, v in state.pin_persistence.items() if not k.startswith(("User", "Admin"))}
    state.ranges = {}
    state.created_locking_ranges.clear()
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    state.deleted_method_associations.clear()
    removed_table_uids = {uid for uid, info in state.created_tables.items() if info[0] == "LockingSP"}
    for uid in removed_table_uids:
        _remove_created_table_state(state, uid)
    state.mbr.clear()
    state.mbr_table_pattern = None
    state.mbr_table_bytes.clear()
    state.datastore_pattern = None
    state.datastore_bytes.clear()
    state.byte_table_rows.clear()
    state.byte_table_mandatory_granularity.clear()
    state.byte_table_recommended_granularity.clear()
    state.loglist_rows.clear()
    if keep_global_key:
        _range(state, 0).media_generation = global_generation
    else:
        _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state, keep_global=keep_global_key)


def _complete_delete_sp(state: State, sp: str | None) -> None:
    if sp is None or sp == "AdminSP":
        return
    if sp == "LockingSP":
        _reset_locking_sp(state)
    state.deleted_sps.add(sp)
    state.sp_enabled.pop(sp, None)
    state.sp_frozen.pop(sp, None)


def _reset_factory_state(state: State) -> None:
    msid_pin = state.pins.get("MSID")
    sid_pin = state.pins.get("SID")
    sid_ever_authenticated = state.sid_ever_authenticated
    global_generation = _range(state, 0).media_generation
    state.pins.clear()
    state.invalidated_pin_values.clear()
    state.pin_min_lengths.clear()
    state.pin_try_limits.clear()
    state.pin_tries.clear()
    state.pin_persistence.clear()
    if msid_pin is not None:
        state.pins["MSID"] = msid_pin
    if sid_ever_authenticated and state.sid_pin_revert_behavior == 0x00:
        if msid_pin is not None:
            state.pins["SID"] = msid_pin
    elif sid_ever_authenticated:
        if sid_pin is not None:
            state.invalidated_pin_values.setdefault("SID", set()).add(sid_pin)
        state.pins.pop("SID", None)
    elif sid_pin is not None:
        state.pins["SID"] = sid_pin
    elif msid_pin is not None:
        state.pins["SID"] = msid_pin
    state.sid_ever_authenticated = False
    state.authority_enabled.clear()
    state.authority_secure.clear()
    state.authority_hash_and_sign.clear()
    state.authority_credential_present.clear()
    state.authority_credential_symbol.clear()
    state.authority_response_sign.clear()
    state.authority_response_exchange.clear()
    state.authority_limits.clear()
    state.authority_uses.clear()
    state.locking_sp_activated = False
    state.observed_sp_lifecycle.clear()
    state.sp_enabled.clear()
    state.sp_frozen.clear()
    state.deleted_sps.clear()
    state.pending_deleted_sp = None
    state.created_table_names.clear()
    state.created_table_name_by_uid.clear()
    state.created_tables.clear()
    state.created_table_columns.clear()
    state.created_table_unique_columns.clear()
    state.created_table_rows.clear()
    state.created_table_row_values_by_uid.clear()
    state.created_table_row_meta_acl_authorities.clear()
    state.created_table_descriptor_uids.clear()
    state.created_table_min_sizes.clear()
    state.created_table_max_sizes.clear()
    state.created_table_allocated_rows.clear()
    state.created_table_getset_acls.clear()
    state.programmatic_reset_enabled = False
    state.locking_info.clear()
    state.ranges = {}
    state.created_locking_ranges.clear()
    state.range_read_lock_users.clear()
    state.range_write_lock_users.clear()
    state.datastore_read_users.clear()
    state.datastore_write_users.clear()
    state.ace_expressions.clear()
    state.deleted_method_associations.clear()
    state.mbr.clear()
    state.mbr_table_pattern = None
    state.mbr_table_bytes.clear()
    state.datastore_pattern = None
    state.datastore_bytes.clear()
    state.byte_table_rows.clear()
    state.byte_table_mandatory_granularity.clear()
    state.byte_table_recommended_granularity.clear()
    state.loglist_rows.clear()
    state.host_properties.clear()
    state.host_properties_by_comid.clear()
    _range(state, 0).media_generation = global_generation + 1
    _invalidate_lba_patterns(state)


def _protocol_stack_reset_matches_session(state: State, comid: str) -> bool:
    if not state.session.open:
        return False
    if not comid or not state.session.comid:
        return True
    return state.session.comid == comid


def _apply_reset_event(state: State, reset_type: int, comid: str = "") -> None:
    abort_current_session = reset_type != PROTOCOL_STACK_RESET or _protocol_stack_reset_matches_session(state, comid)
    current_session = state.session
    if abort_current_session:
        state.session = Session()
        state.pending_deleted_sp = None
    if reset_type in {0, 1}:
        state.host_properties = _opal_host_property_initials()
        for known_comid in list(state.host_properties_by_comid):
            state.host_properties_by_comid[known_comid] = _opal_host_property_initials()
    elif reset_type == PROTOCOL_STACK_RESET:
        if comid:
            state.host_properties_by_comid[comid] = _opal_host_property_initials()
        else:
            state.host_properties = _opal_host_property_initials()
    if reset_type == PROTOCOL_STACK_RESET:
        if not abort_current_session:
            state.session = current_session
        return
    if reset_type == 0:
        for authority, persistent in list(state.pin_persistence.items()):
            if not persistent:
                state.pin_tries[authority] = 0
    for range_state in state.ranges.values():
        if reset_type in range_state.lock_on_reset_types and (
            range_state.read_lock_enabled or range_state.write_lock_enabled
        ):
            range_state.read_locked = True
            range_state.write_locked = True
        if range_state.reencrypt_state in {2, 3} and range_state.cont_on_reset is not None and not _reset_types(range_state.cont_on_reset):
            previous_state = range_state.reencrypt_state
            range_state.reencrypt_state = 5
            range_state.general_status = 5 if previous_state == 2 else 34
    if reset_type in _reset_types(state.mbr.get("DoneOnReset", "PowerCycle")):
        state.mbr["Done"] = 0


def _crypto_stream_kind(method: str) -> str | None:
    if method.startswith("Hash"):
        return "Hash"
    if method.startswith("HMAC"):
        return "HMAC"
    if method.startswith("Encrypt"):
        return "Encrypt"
    if method.startswith("Decrypt"):
        return "Decrypt"
    return None


def _crypto_stream_key(event: Event) -> tuple[str, str] | None:
    kind = _crypto_stream_kind(event.method)
    if kind is None:
        return None
    invoking = event.invoking_symbol or event.invoking_uid or event.invoking_name
    if not invoking:
        return None
    return (kind, invoking)


def _apply_crypto_stream_success(state: State, event: Event) -> None:
    key = _crypto_stream_key(event)
    if key is None:
        return
    if event.method.endswith("Init"):
        state.crypto_streams[key] = True
        found_buffer_out, _ = _named_method_arg_value(event, "BufferOut", "bufferOut", "Output", "output")
        if found_buffer_out:
            state.crypto_stream_bufferout.add(key)
        else:
            state.crypto_stream_bufferout.discard(key)
    elif event.method.endswith("Finalize"):
        state.crypto_streams[key] = False
        state.crypto_stream_bufferout.discard(key)


def _xor_byte_table_symbol(value: Any) -> str:
    symbol, uid = _object_ref_from_value(value)
    if not symbol and uid:
        symbol = _object_by_uid(uid)
    if not symbol and isinstance(value, dict):
        for key in ("CellBlock", "Cellblock", "cellblock"):
            nested = _mapping_value(value, key)
            if nested is not None:
                symbol = _xor_byte_table_symbol(nested)
                if symbol:
                    return symbol
        for key in ("Table", "table", "TableUID", "tableUID", "Object", "object", "UID", "uid", "Name", "name"):
            nested = _mapping_value(value, key)
            if nested is not None:
                symbol = _xor_byte_table_symbol(nested)
                if symbol:
                    return symbol
    if not symbol and _is_byte_table_symbol(_as_text(value)):
        symbol = _as_text(value)
    return symbol or ""


def _xor_known_pattern(state: State, symbol: str) -> str | None:
    if symbol.startswith("DataStore"):
        return state.datastore_pattern
    if symbol == "MBR":
        return state.mbr_table_pattern
    return None


def _xor_cellblock_range(value: Any) -> tuple[int, int] | None:
    start: int | None = None
    end: int | None = None
    length: int | None = None
    saw_cellblock = False

    def assign(component: str, item: Any) -> None:
        nonlocal start, end, length
        parsed = _parse_int(item)
        if parsed is None or isinstance(item, bool):
            return
        if component == "start":
            start = parsed
        elif component == "end":
            end = parsed
        elif component == "length":
            length = parsed

    aliases = {
        "startrow": "start",
        "startindex": "start",
        "startoffset": "start",
        "offset": "start",
        "row": "start",
        "start": "start",
        "endrow": "end",
        "endindex": "end",
        "endoffset": "end",
        "end": "end",
        "length": "length",
        "len": "length",
        "size": "length",
        "count": "length",
    }

    def component_for_key(key: Any) -> str | None:
        text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
        return aliases.get(text)

    def walk(item: Any, *, direct_cellblock: bool = False) -> None:
        nonlocal saw_cellblock
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized == "cellblock":
                    saw_cellblock = True
                    walk(nested, direct_cellblock=True)
                    continue
                component = component_for_key(key)
                if component is not None:
                    assign(component, nested)
                walk(nested, direct_cellblock=False)
            return
        if isinstance(item, (list, tuple)):
            if direct_cellblock and len(item) == 2 and not isinstance(item[0], (dict, list, tuple, set)):
                component = component_for_key(item[0])
                if component is not None:
                    assign(component, item[1])
                    return
            for nested in item:
                walk(nested, direct_cellblock=direct_cellblock)

    walk(value)
    if not saw_cellblock:
        return None
    if start is None:
        start = 0
    if end is None and length is not None and length > 0:
        end = start + length - 1
    if end is None:
        end = start
    return (min(start, end), max(start, end))


def _xor_cellblock_pattern(state: State, value: Any) -> str | None:
    row_range = _xor_cellblock_range(value)
    if row_range is None:
        return None
    symbol = _xor_byte_table_symbol(value)
    start, end = row_range
    source_bytes = state.datastore_bytes if symbol.startswith("DataStore") else state.mbr_table_bytes if symbol == "MBR" else {}
    if source_bytes:
        out: list[str] = []
        for offset in range(start, end + 1):
            byte = source_bytes.get(offset)
            if byte is None:
                return None
            out.append(byte)
        return "".join(out)
    known = _xor_known_pattern(state, symbol)
    known_bytes = _hex_payload_bytes(known)
    if known_bytes is None or end >= len(known_bytes):
        return None
    return "".join(known_bytes[offset] for offset in range(start, end + 1))


def _xor_result_pattern(input_pattern: str | None, pattern_input: str | None) -> str | None:
    input_bytes = _hex_payload_bytes(input_pattern)
    pattern_bytes = _hex_payload_bytes(pattern_input)
    if input_bytes is None or pattern_bytes is None or len(pattern_bytes) < len(input_bytes):
        return None
    return "".join(f"{int(data, 16) ^ int(pattern_bytes[index], 16):02X}" for index, data in enumerate(input_bytes))


def _store_byte_table_pattern(state: State, symbol: str, start_offset: int, pattern: str) -> None:
    payload_bytes = _hex_payload_bytes(pattern)
    if payload_bytes is None:
        return
    if symbol.startswith("DataStore"):
        for offset, byte in enumerate(payload_bytes, start=start_offset):
            state.datastore_bytes[offset] = byte
        contiguous = _contiguous_byte_pattern(state.datastore_bytes)
        state.datastore_pattern = contiguous if contiguous is not None and _fully_contiguous_from_zero(state.datastore_bytes) else None
    elif symbol == "MBR":
        for offset, byte in enumerate(payload_bytes, start=start_offset):
            state.mbr_table_bytes[offset] = byte
        contiguous = _contiguous_byte_pattern(state.mbr_table_bytes)
        state.mbr_table_pattern = contiguous if contiguous is not None and _fully_contiguous_from_zero(state.mbr_table_bytes) else None


def _apply_xor_success(state: State, event: Event) -> None:
    buffer_out = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "BufferOut", "bufferOut", "Output", "output")
    if buffer_out is not None:
        pattern_input = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "PatternInput", "patternInput", "Pattern", "pattern")
        pattern_symbol = _xor_byte_table_symbol(pattern_input)
        input_value = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "Input", "input", "Data", "data", "Bytes", "bytes", "BufferIn", "bufferIn", "Buffer", "buffer")
        input_pattern = _byte_table_payload_pattern(event) or _xor_cellblock_pattern(state, input_value)
        result_pattern = _xor_result_pattern(input_pattern, _xor_known_pattern(state, pattern_symbol))
        output_symbol = _xor_byte_table_symbol(buffer_out)
        output_offset = _byte_table_where_offset(buffer_out) or 0
        if result_pattern is not None and output_symbol:
            _store_byte_table_pattern(state, output_symbol, output_offset, result_pattern)

    delete_pattern = _as_bool(_raw_arg_value(event.required, event.optional, _method_raw_args(event), "DeletePattern", "deletePattern", "Delete", "delete"))
    if not delete_pattern:
        return
    pattern_input = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "PatternInput", "patternInput", "Pattern", "pattern")
    symbol, uid = _object_ref_from_value(pattern_input)
    if not symbol and uid:
        symbol = _object_by_uid(uid)
    if not symbol and _is_byte_table_symbol(_as_text(pattern_input)):
        symbol = _as_text(pattern_input)
    if symbol.startswith("DataStore"):
        length = len(_hex_payload_bytes(state.datastore_pattern) or [])
        if length:
            state.datastore_pattern = "00" * length
            state.datastore_bytes = {index: "00" for index in range(length)}
    elif symbol == "MBR":
        length = len(_hex_payload_bytes(state.mbr_table_pattern) or [])
        if length:
            state.mbr_table_pattern = "00" * length
            state.mbr_table_bytes = {index: "00" for index in range(length)}


def apply_transition(state: State, event: Event) -> None:
    if event.kind == "host_io" and event.method == "wwn" and event.is_success:
        wwn = _output_return_values(event.raw)
        if wwn is not None and wwn is not False:
            state.wwn = wwn
        return

    if event.kind == "host_io" and event.method == "msid" and event.is_success:
        msid = _output_return_values(event.raw)
        if msid is not None and msid is not False:
            credential = _credential_text(msid)
            if credential:
                state.pins["MSID"] = credential
                state.pins.setdefault("SID", credential)
        return

    if event.kind == "host_io" and event.is_success:
        _apply_level0_opal_ssc_v2_success(state, event)

    reset_type = _reset_event_type(event.method)
    if event.kind == "host_io" and event.is_success and reset_type is not None:
        if reset_type == 3 and not state.programmatic_reset_enabled:
            return
        _apply_reset_event(state, reset_type, event.comid)
        return

    if event.implicit_session and event.kind == "tcg_method":
        if event.is_success:
            _mark_successful_authentication(state, event.authority)
            if event.method != "Authenticate":
                _increment_authority_use(state, event.authority)
                if event.authority:
                    state.pin_tries[event.authority] = 0
        saved_session = state.session
        state.session = _implicit_session_for_event(state, event, assume_authenticated=event.is_success)
        try:
            apply_transition(state, replace(event, implicit_session=False))
        finally:
            state.session = saved_session
        return

    if event.method in {"EndSession", "CloseSession"} and event.is_success:
        host_session_id = _session_id_key(
            _raw_arg_value(event.required, event.optional, _method_raw_args(event), *HOST_SESSION_ID_NAMES)
        )
        if host_session_id is not None and state.session.host_session_id is not None and host_session_id != state.session.host_session_id:
            return
        sp_session_id = _session_id_key(
            _raw_arg_value(event.required, event.optional, _method_raw_args(event), *SP_SESSION_ID_NAMES)
        )
        if sp_session_id is not None and state.session.sp_session_id is not None and sp_session_id != state.session.sp_session_id:
            return
        if state.pending_deleted_sp == state.session.sp:
            _complete_delete_sp(state, state.pending_deleted_sp)
        state.pending_deleted_sp = None
        state.session = Session()
        return

    if event.method == "StartSession" and event.is_success:
        _apply_start_session_success(state, event)
        return

    if event.method in {"StartTrustedSession", "StartTlsSession"} and event.is_success:
        return

    if event.method == "Properties" and event.is_success:
        _apply_properties_success(state, event)
        return

    if not event.is_success:
        if event.status == NOT_AUTHORIZED:
            authority = event.authority if event.method == "StartSession" else _auth_from_authenticate_event(event)
            if _auth_failure_counts_as_pin_try(state, event, authority):
                _increment_failed_authority_try(state, authority)
        for authority in _failed_authas_authorities(state, event):
            _increment_failed_authority_try(state, authority)
        return

    if _failed_authas_authorities(state, event):
        return

    if event.method == "Authenticate":
        authority = _auth_from_authenticate_event(event)
        authenticated = _return_bool(event.raw, credential_aliases=True)
        if authenticated is False:
            if _auth_failure_counts_as_pin_try(state, event, authority):
                _increment_failed_authority_try(state, authority)
            return
        if authority:
            _mark_successful_authentication(state, authority)
            state.session.authenticated.add(authority)
            _increment_authority_use(state, authority)
            state.pin_tries[authority] = 0
            challenge = (
                event.challenge
                or _mapping_value(event.optional, "Proof", "proof")
                or _mapping_value(event.required, "Proof", "proof")
                or _mapping_value(event.optional, "Challenge")
                or _mapping_value(event.required, "Challenge")
                or _mapping_value(event.required, "HostChallenge")
            )
            if challenge and authority != "Anybody":
                state.pins[authority] = _credential_text(challenge)
        return

    if event.method == "GetACL":
        range_id = _getacl_invoking_range_id(event)
        if range_id is not None and range_id != 0:
            _range(state, range_id)
        return

    if event.method == "Get":
        _apply_get_success(state, event)
        return

    if event.method in READ_WRITE_PERSISTENT_METHODS and state.session.open and not state.session.write:
        return

    if event.method == "Set":
        state.session.write = True
        _apply_set_success(state, event)
        return

    if event.method == "CreateTable":
        state.session.write = True
        _apply_create_table_success(state, event)
        return

    if event.method == "CreateLog":
        state.session.write = True
        _apply_create_log_success(state, event)
        return

    if event.method == "CreateRow":
        state.session.write = True
        _apply_create_row_success(state, event)
        return

    if event.method == "DeleteRow":
        state.session.write = True
        _apply_delete_row_success(state, event)
        return

    if event.method == "Delete":
        state.session.write = True
        _apply_delete_success(state, event)
        return

    if event.method == "DeleteSP":
        state.session.write = True
        state.pending_deleted_sp = state.session.sp
        return

    if event.method == "DeleteMethod":
        state.session.write = True
        _apply_delete_method_success(state, event)
        return

    if event.method in {"AddACE", "RemoveACE", "SetACL"}:
        state.session.write = True
        _apply_acl_mutation_success(state, event)
        return

    if event.method == "SetPackage":
        state.session.write = True
        owner = _pin_owner_by_object(event.invoking_symbol)
        if owner:
            old_pin = state.pins.pop(owner, None)
            if old_pin is not None:
                state.invalidated_pin_values.setdefault(owner, set()).add(old_pin)
            state.pin_tries[owner] = 0
            return
        range_id = _range_id_from_key(event.invoking_symbol)
        if range_id is not None:
            _range(state, range_id).media_generation += 1
        return

    if event.method == "Activate" and event.invoking_symbol == "LockingSP":
        state.session.write = True
        state.locking_sp_activated = True
        if "SID" in state.pins:
            state.pins["Admin1"] = state.pins["SID"]
        elif "MSID" in state.pins and "Admin1" not in state.pins:
            state.pins["Admin1"] = state.pins["MSID"]
        return

    if event.method == "GenKey":
        owner = _pin_owner_by_object(event.invoking_symbol)
        if owner:
            old_pin = state.pins.pop(owner, None)
            if old_pin is not None:
                state.invalidated_pin_values.setdefault(owner, set()).add(old_pin)
            state.pin_tries[owner] = 0
            return
        range_id = _range_id_from_key(event.invoking_symbol)
        if range_id is not None:
            _range(state, range_id).media_generation += 1
        return

    if event.method in CRYPTO_STREAM_METHODS:
        _apply_crypto_stream_success(state, event)
        return

    if event.method == "XOR":
        _apply_xor_success(state, event)
        return

    if event.method == "Erase":
        state.session.write = True
        _apply_erase_success(state, event)
        return

    if event.method in {"Revert", "RevertSP"}:
        state.session.write = True
        if (
            (event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP")
            or (event.method == "Revert" and state.session.sp == "AdminSP" and event.invoking_symbol in {"AdminSP", "ThisSP"})
        ):
            _reset_factory_state(state)
        elif state.session.sp == "LockingSP" or event.invoking_symbol == "LockingSP":
            keep = _keep_global_range_key(event)
            _reset_locking_sp(state, keep_global_key=keep)
        else:
            sid_pin = state.pins.get("SID")
            msid_pin = state.pins.get("MSID")
            state.pins.clear()
            state.invalidated_pin_values.clear()
            state.pin_min_lengths.clear()
            state.pin_try_limits.clear()
            state.pin_tries.clear()
            state.pin_persistence.clear()
            if msid_pin is not None:
                state.pins["MSID"] = msid_pin
            if sid_pin is not None:
                state.pins["SID"] = sid_pin
        state.session = Session()
        return

    if event.kind == "host_io" and event.method == "Write" and event.lba is not None and event.pattern is not None:
        crossing_rejected = _range_crossing_error_allowed(state, event.lba) and state.range_crossing_behavior == 1
        if (
            _mbr_shadow_relation(state, event.lba) not in {"within", "partial"}
            and not _any_write_locked(state, event.lba)
            and not crossing_rejected
        ):
            write_start, write_end = event.lba
            payload_bytes = _hex_payload_bytes(event.pattern)
            lba_count = write_end - write_start + 1
            for segment_start, segment_end, range_state in _range_segments_for_lba(state, event.lba):
                segment_pattern = event.pattern
                if payload_bytes is not None and len(payload_bytes) == lba_count:
                    offset = segment_start - write_start
                    length = segment_end - segment_start + 1
                    segment_pattern = "".join(payload_bytes[offset : offset + length])
                state.lba_patterns[(segment_start, segment_end)] = (
                    segment_pattern,
                    range_state.range_id,
                    range_state.media_generation,
                )




__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
