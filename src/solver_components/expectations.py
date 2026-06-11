"""Expected-response rules for TCG methods and host I/O."""

from __future__ import annotations

import ast
from dataclasses import replace
import re
from typing import Any

from .constants import *
from .models import *
from .parsing import *
from .semantics import *


STARTUP_AUTHORITY_OPERATIONS = {
    "Anybody": "Sign",
    "MakerSymK": "SymK",
    "MakerPuK": "Sign",
    "SID": "Password",
    "TPerSign": "TPerSign",
    "TPerExch": "TPerExchange",
    "AdminExch": "Exchange",
}

UNKNOWN_RESPONSE_SIGN_AUTHORITY = "__unknown_response_sign_authority__"
_MISSING_PAYLOAD_VALUE = object()


CONTROL_SESSION_METHODS = {
    "Properties",
    "StartSession",
    "SyncSession",
    "StartTrustedSession",
    "SyncTrustedSession",
    "CloseSession",
    "EndSession",
    "StartTlsSession",
    "SyncTlsSession",
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


def _explicit_session_manager_target(event: Event) -> bool:
    return event.invoking_uid == "00000000000000FF" or event.invoking_symbol == "SessionManager"


def _wrapper_authas_failure(state: State, event: Event) -> ExpectedResponse | None:
    if not event.implicit_session or event.kind != "tcg_method":
        return None
    if event.method in {"Authenticate", "StartSession"}:
        return None
    pairs = _authas_pairs(event.required, event.optional, _method_raw_args(event))
    if not pairs and event.authority is not None:
        pairs.append((event.authority, event.challenge))
    for authority, credential in pairs:
        if authority in {None, "Anybody", "Admins", "Users", "Makers"}:
            continue
        if not credential:
            continue
        if _authority_locked_out(state, authority):
            return ExpectedResponse(
                {NOT_AUTHORIZED, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Wrapper authAs authority is locked out",
                confidence="high",
            )
        if _authority_limit_reached(state, authority):
            return ExpectedResponse(
                {NOT_AUTHORIZED, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Wrapper authAs authority has reached its nonzero Authority.Limit",
                confidence="high",
            )
        known_pin = state.pins.get(authority)
        if known_pin is not None and _credential_text(credential) != known_pin:
            return ExpectedResponse(
                {NOT_AUTHORIZED, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Wrapper authAs credential does not match tracked authority credential",
                confidence="high",
            )
    return None


def _raw_tcg_method_event(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    return not (isinstance(input_obj, dict) and _function_name(input_obj))


def _object_table_get_symbol(symbol: str) -> bool:
    return symbol == "Table" or symbol.endswith("Table")


def _is_datastore_wrapper_readdata(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
        "readdata",
        "getdata",
        "fetchdata",
        "loaddata",
        "readdatastore",
        "getdatastore",
        "getdatastorebytes",
        "getdatastorepayload",
        "getdspayload",
        "fetchdatastore",
        "fetchdatastorebytes",
        "fetchdatastorepayload",
        "fetchds",
        "fetchdsbytes",
        "fetchdspayload",
        "loaddatastore",
        "loaddatastorebytes",
        "loaddatastorepayload",
        "loadds",
        "loaddsbytes",
        "loaddspayload",
        "readuserdata",
        "readuserpayload",
        "readdatastorebytes",
        "readdatastorepayload",
        "readdspayload",
        "getuserdata",
        "fetchuserdata",
        "fetchuserpayload",
        "loaduserdata",
        "loaduserpayload",
        "readuserdatastore",
        "getuserdatastore",
        "fetchuserdatastore",
        "loaduserdatastore",
    }


def _is_datastore_wrapper_writedata(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
        "writedata",
        "setdata",
        "putdata",
        "storedata",
        "savedata",
        "writedatastore",
        "setdatastore",
        "putdatastore",
        "putdatastorebytes",
        "putdatastorepayload",
        "putdsbytes",
        "putdspayload",
        "storedatastore",
        "storedatastorebytes",
        "storedatastorepayload",
        "storeds",
        "storedsbytes",
        "storedspayload",
        "savedatastore",
        "savedatastorebytes",
        "savedatastorepayload",
        "saveds",
        "savedsbytes",
        "savedspayload",
        "updatedatastore",
        "updatedatastorebytes",
        "updatedatastorepayload",
        "updatedsbytes",
        "updatedspayload",
        "programdatastore",
        "writeuserdata",
        "writeuserpayload",
        "writedatastorebytes",
        "writedatastorepayload",
        "writeds",
        "writedsbytes",
        "writedspayload",
        "setdatastorepayload",
        "setdsbytes",
        "setdspayload",
        "programdatastorebytes",
        "programdatastorepayload",
        "programdsbytes",
        "programdspayload",
        "setuserdata",
        "putuserdata",
        "storeuserdata",
        "saveuserdata",
        "saveuserpayload",
        "storeuserpayload",
        "setuserpayload",
        "writeuserdatastore",
        "setuserdatastore",
        "putuserdatastore",
        "storeuserdatastore",
        "saveuserdatastore",
    }


def _datastore_wrapper_readdata_has_window(event: Event) -> bool:
    if not _is_datastore_wrapper_readdata(event):
        return False
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    args = _function_args(input_obj)
    kwargs = _function_kwargs(input_obj)

    def has_window_keys(mapping: Any) -> bool:
        if not isinstance(mapping, dict):
            return False
        for key in mapping:
            normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
            if normalized in {
                "startrow",
                "row",
                "offset",
                "byteoffset",
                "index",
                "position",
                "pos",
                "address",
                "start",
                "endrow",
                "endindex",
                "endposition",
                "end",
                "length",
                "len",
                "size",
                "count",
                "numbytes",
                "nbytes",
                "bytecount",
                "bytelength",
                "datalength",
            }:
                return True
        return False

    if len(args) > 1 and _parse_int(args[1]) is not None and not isinstance(args[1], bool):
        return True
    if len(args) > 1 and has_window_keys(args[1]):
        return True
    if len(args) > 0 and isinstance(args[0], dict):
        nested = _mapping_value(args[0], "values", "Values", "settings", "Settings", "options", "Options", "read", "Read", "window", "Window")
        if has_window_keys(nested) or has_window_keys(args[0]):
            return True
    if len(args) > 2:
        return True
    if has_window_keys(kwargs):
        return True
    nested = _mapping_value(kwargs, "values", "Values", "settings", "Settings", "options", "Options", "read", "Read", "window", "Window")
    if has_window_keys(nested):
        return True
    nested = _mapping_value(input_obj, "values", "Values", "settings", "Settings", "options", "Options", "read", "Read", "window", "Window")
    if has_window_keys(nested):
        return True
    return False


def _datastore_wrapper_access_authorized(state: State, event: Event, *, write: bool) -> bool | None:
    wrapper_kind = _is_datastore_wrapper_writedata(event) if write else _is_datastore_wrapper_readdata(event)
    if not wrapper_kind or event.authority is None:
        return None
    wrapper_session = replace(
        state.session,
        open=True,
        sp=event.sp or state.session.sp or "LockingSP",
        authenticated={event.authority},
    )
    wrapper_state = replace(state, session=wrapper_session)
    if _datastore_ace_configured(wrapper_state, write=write):
        return _datastore_master_authorizes(wrapper_state) or _user_acl_allows_datastore(wrapper_state, write=write)
    return (
        _has_authority(wrapper_state, "Admins")
        or _datastore_master_authorizes(wrapper_state)
        or _user_acl_allows_datastore(wrapper_state, write=write)
    )


def _wrapper_scoped_authority_state(state: State, event: Event, *function_aliases: str) -> State | None:
    if not event.implicit_session or event.authority is None:
        return None
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    alias = _function_alias(_function_name(input_obj))
    if function_aliases and alias not in set(function_aliases):
        return None
    wrapper_session = replace(
        state.session,
        open=True,
        sp=event.sp or state.session.sp,
        authenticated={event.authority},
    )
    return replace(state, session=wrapper_session)


def _is_tcgstorageapi_getrange(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
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
    }


def _is_tcgstorageapi_lockonreset_value_getter(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
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
        "fetchlockonreset",
        "querylockonreset",
        "loadlockonreset",
        "readrangelockonreset",
        "fetchrangelockonreset",
        "queryrangelockonreset",
        "loadrangelockonreset",
        "readlor",
        "fetchlor",
        "querylor",
        "loadlor",
        "readrangelor",
        "fetchrangelor",
        "queryrangelor",
        "loadrangelor",
    }


def _tcgstorageapi_lockinginfo_single_getter_column(event: Event) -> int | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    return {
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
    }.get(_function_alias(_function_name(input_obj)))


def _tcgstorageapi_locking_bool_getter(event: Event) -> str | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    return {
        "getreadlockenabled": "ReadLockEnabled",
        "isreadlockenabled": "ReadLockEnabled",
        "readlockenabled": "ReadLockEnabled",
        "readlockingenabled": "ReadLockEnabled",
        "isreadlockingenabled": "ReadLockEnabled",
        "getrangereadlockenabled": "ReadLockEnabled",
        "readreadlockenabled": "ReadLockEnabled",
        "fetchreadlockenabled": "ReadLockEnabled",
        "queryreadlockenabled": "ReadLockEnabled",
        "loadreadlockenabled": "ReadLockEnabled",
        "readrangereadlockenabled": "ReadLockEnabled",
        "fetchrangereadlockenabled": "ReadLockEnabled",
        "queryrangereadlockenabled": "ReadLockEnabled",
        "loadrangereadlockenabled": "ReadLockEnabled",
        "israngereadlockenabled": "ReadLockEnabled",
        "getrangereadlockingenabled": "ReadLockEnabled",
        "israngereadlockingenabled": "ReadLockEnabled",
        "getwritelockenabled": "WriteLockEnabled",
        "iswritelockenabled": "WriteLockEnabled",
        "writelockenabled": "WriteLockEnabled",
        "writelockingenabled": "WriteLockEnabled",
        "iswritelockingenabled": "WriteLockEnabled",
        "getrangewritelockenabled": "WriteLockEnabled",
        "readwritelockenabled": "WriteLockEnabled",
        "fetchwritelockenabled": "WriteLockEnabled",
        "querywritelockenabled": "WriteLockEnabled",
        "loadwritelockenabled": "WriteLockEnabled",
        "readrangewritelockenabled": "WriteLockEnabled",
        "fetchrangewritelockenabled": "WriteLockEnabled",
        "queryrangewritelockenabled": "WriteLockEnabled",
        "loadrangewritelockenabled": "WriteLockEnabled",
        "israngewritelockenabled": "WriteLockEnabled",
        "getrangewritelockingenabled": "WriteLockEnabled",
        "israngewritelockingenabled": "WriteLockEnabled",
        "getreadlocked": "ReadLocked",
        "getreadlock": "ReadLocked",
        "isreadlocked": "ReadLocked",
        "readlocked": "ReadLocked",
        "getrangereadlocked": "ReadLocked",
        "readreadlocked": "ReadLocked",
        "fetchreadlocked": "ReadLocked",
        "queryreadlocked": "ReadLocked",
        "loadreadlocked": "ReadLocked",
        "readrangereadlocked": "ReadLocked",
        "fetchrangereadlocked": "ReadLocked",
        "queryrangereadlocked": "ReadLocked",
        "loadrangereadlocked": "ReadLocked",
        "israngereadlocked": "ReadLocked",
        "isreadlockset": "ReadLocked",
        "getreadlockstate": "ReadLocked",
        "readreadlockstate": "ReadLocked",
        "fetchreadlockstate": "ReadLocked",
        "queryreadlockstate": "ReadLocked",
        "loadreadlockstate": "ReadLocked",
        "getreadlockedstate": "ReadLocked",
        "getrangereadlockstate": "ReadLocked",
        "israngereadlockset": "ReadLocked",
        "readlockstate": "ReadLocked",
        "rangereadlockstate": "ReadLocked",
        "rangereadlocked": "ReadLocked",
        "getwritelocked": "WriteLocked",
        "getwritelock": "WriteLocked",
        "iswritelocked": "WriteLocked",
        "writelocked": "WriteLocked",
        "getrangewritelocked": "WriteLocked",
        "readwritelocked": "WriteLocked",
        "fetchwritelocked": "WriteLocked",
        "querywritelocked": "WriteLocked",
        "loadwritelocked": "WriteLocked",
        "readrangewritelocked": "WriteLocked",
        "fetchrangewritelocked": "WriteLocked",
        "queryrangewritelocked": "WriteLocked",
        "loadrangewritelocked": "WriteLocked",
        "israngewritelocked": "WriteLocked",
        "iswritelockset": "WriteLocked",
        "getwritelockstate": "WriteLocked",
        "readwritelockstate": "WriteLocked",
        "fetchwritelockstate": "WriteLocked",
        "querywritelockstate": "WriteLocked",
        "loadwritelockstate": "WriteLocked",
        "getwritelockedstate": "WriteLocked",
        "getrangewritelockstate": "WriteLocked",
        "israngewritelockset": "WriteLocked",
        "writelockstate": "WriteLocked",
        "rangewritelockstate": "WriteLocked",
        "rangewritelocked": "WriteLocked",
        "islockonresetenabled": "LockOnResetEnabled",
        "israngelockonresetenabled": "LockOnResetEnabled",
        "islockingrangelockonresetenabled": "LockOnResetEnabled",
        "lockonresetenabled": "LockOnResetEnabled",
        "rangelockonresetenabled": "LockOnResetEnabled",
        "haslockonreset": "LockOnResetEnabled",
    }.get(_function_alias(_function_name(input_obj)))


def _is_tcgstorageapi_getmek(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
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
    }


def _is_tcgstorageapi_getnextkey(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
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
    }


def _tcgstorageapi_reencrypt_bool_getter(event: Event) -> str | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    return {"isreencrypting": "ReEncrypting"}.get(_function_alias(_function_name(input_obj)))


def _tcgstorageapi_port_bool_getter(event: Event) -> str | None:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return None
    return {
        "getportlocked": "PortLocked",
        "isportlocked": "PortLocked",
        "getportstate": "PortLocked",
        "getportlock": "PortLocked",
        "isportlock": "PortLocked",
        "portlocked": "PortLocked",
        "readportlock": "PortLocked",
        "getinterfacelock": "PortLocked",
    }.get(_function_alias(_function_name(input_obj)))


def _is_tcgstorageapi_getport(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {"getport", "readport", "fetchport"}


def _is_tcgstorageapi_getpskentry(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
        "getpskentry",
        "readpskentry",
        "fetchpskentry",
        "querypskentry",
        "getpsk",
        "readpsk",
        "fetchpsk",
        "querypsk",
        "pskentry",
        "gettlspsk",
        "readtlspsk",
        "fetchtlspsk",
        "querytlspsk",
        "getpresharedkey",
        "readpresharedkey",
        "fetchpresharedkey",
        "querypresharedkey",
        "getpresharedkeyentry",
        "readpresharedkeyentry",
        "fetchpresharedkeyentry",
        "querypresharedkeyentry",
    }


def _is_tcgstorageapi_getauthority(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {
        "getauthority",
        "isuserenabled",
        "getuserenabled",
        "userenabled",
        "getauthorityenabled",
        "isauthorityenabled",
        "authorityenabled",
        "getuserstate",
    }


def _is_tcgstorageapi_startsession(event: Event) -> bool:
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    if not isinstance(input_obj, dict):
        return False
    return _function_alias(_function_name(input_obj)) in {"startsession", "opensession", "startsp", "opensp"}


def _key_symbol_uid(symbol: str | None) -> str:
    if not symbol:
        return ""
    if symbol == "K_AES_128_GlobalRange_Key":
        return "0000080500000001"
    if symbol == "K_AES_256_GlobalRange_Key":
        return "0000080600000001"
    match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key", symbol)
    if not match:
        return ""
    family = "05" if match.group(1) == "128" else "06"
    return f"000008{family}0003{int(match.group(2)):04X}"


def _payload_value_by_name(value: Any, name: str) -> Any:
    wanted = re.sub(r"[^A-Za-z0-9]", "", _as_text(name)).upper()
    if not wanted:
        return _MISSING_PAYLOAD_VALUE
    aliases = {
        "RANGESTART": {"RANGESTART", "START", "STARTLBA", "LBASTART", "LBA", "SECTOR", "STARTBLOCK", "FIRSTLBA", "BASE", "OFFSET", "BEGIN"},
        "RANGELENGTH": {"RANGELENGTH", "LENGTH", "LEN", "SIZE", "COUNT", "BLOCKS", "SECTORS", "NUMBLOCKS", "BLOCKCOUNT", "SECTORCOUNT"},
        "READLOCKED": {"READLOCKED", "READLOCK", "RLOCKED"},
        "WRITELOCKED": {"WRITELOCKED", "WRITELOCK", "WLOCKED"},
        "READLOCKENABLED": {"READLOCKENABLED", "READENABLED", "RLOCKENABLED"},
        "WRITELOCKENABLED": {"WRITELOCKENABLED", "WRITEENABLED", "WLOCKENABLED"},
        "LOCKONRESET": {"LOCKONRESET", "LOR", "RESETTYPES", "TYPES", "RESETEVENTS", "RESETON", "RESETLIST"},
    }.get(wanted, {wanted})
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
            if key_text in aliases:
                return item
            if key_text in {"LOCKS", "LOCK", "LOCKSTATE", "STATE"}:
                selected = _directional_lock_payload_value(item, wanted)
                if selected is not _MISSING_PAYLOAD_VALUE:
                    return selected
            selected = _payload_value_by_name(item, name)
            if selected is not _MISSING_PAYLOAD_VALUE:
                return selected
        return _MISSING_PAYLOAD_VALUE
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).upper()
            if key_text in aliases:
                return value[1]
        for item in value:
            selected = _payload_value_by_name(item, name)
            if selected is not _MISSING_PAYLOAD_VALUE:
                return selected
    return _MISSING_PAYLOAD_VALUE


def _directional_lock_payload_value(value: Any, wanted: str) -> Any:
    if not isinstance(value, dict):
        return _MISSING_PAYLOAD_VALUE
    names = {
        "READLOCKENABLED": {"READLOCKENABLED", "READLOCKINGENABLED", "READENABLED", "READ", "ENABLED"},
        "WRITELOCKENABLED": {"WRITELOCKENABLED", "WRITELOCKINGENABLED", "WRITEENABLED", "WRITE", "ENABLED"},
        "READLOCKED": {"READLOCKED", "READLOCK", "READ", "LOCKED"},
        "WRITELOCKED": {"WRITELOCKED", "WRITELOCK", "WRITE", "LOCKED"},
    }.get(wanted)
    if not names:
        return _MISSING_PAYLOAD_VALUE
    for key, item in value.items():
        key_text = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper()
        if key_text in names:
            return item
    return _MISSING_PAYLOAD_VALUE


def _single_cell_payload_value(payload: Any) -> Any:
    for name in ("value", "Value", "result", "Result", "return", "Return", "rv", "RV"):
        selected = _payload_value_by_name(payload, name)
        if selected is not _MISSING_PAYLOAD_VALUE:
            return selected
    if not isinstance(payload, (dict, list, tuple, set)):
        return payload
    return _MISSING_PAYLOAD_VALUE


def _observed_getrange_return_values(event: Event, expected_values: dict[str, Any]) -> dict[str, Any]:
    if not _is_tcgstorageapi_getrange(event):
        return {}
    payload = _output_return_values(event.raw)
    return {
        name: expected
        for name, expected in expected_values.items()
        if _payload_value_by_name(payload, name) is not _MISSING_PAYLOAD_VALUE
    }


def _observed_return_values(payload: Any, expected_values: dict[str, Any]) -> dict[str, Any]:
    return {
        name: expected
        for name, expected in expected_values.items()
        if _payload_value_by_name(payload, name) is not _MISSING_PAYLOAD_VALUE
    }


def _byte_table_known_get_range(
    state: State,
    event: Event,
    *,
    symbol: str,
    default_rows: int,
) -> tuple[int, int] | None:
    start, end = _byte_table_get_range(event) or (0, 0)
    if "endrow" in _cellblock_components(event) or _is_datastore_wrapper_readdata(event):
        return start, end
    rows = state.byte_table_rows.get(symbol, default_rows)
    if rows <= 0 or start >= rows:
        return start, end
    return start, rows - 1


def _known_byte_table_pattern(
    bytes_by_offset: dict[int, str],
    *,
    start: int,
    end: int,
    fallback_pattern: str | None,
) -> str | None:
    if end < start:
        return None
    length = end - start + 1
    if length > len(bytes_by_offset):
        return fallback_pattern if start == 0 else None
    if any(offset not in bytes_by_offset for offset in range(start, end + 1)):
        return fallback_pattern if start == 0 else None
    return "".join(bytes_by_offset[offset] for offset in range(start, end + 1))


def _datastore_get_expected_pattern(state: State, event: Event) -> str | None:
    if _is_datastore_wrapper_readdata(event) and not _datastore_wrapper_readdata_has_window(event) and state.datastore_pattern is not None:
        return state.datastore_pattern
    if not state.datastore_bytes:
        return state.datastore_pattern
    known_range = _byte_table_known_get_range(state, event, symbol="DataStore", default_rows=0x00A00000)
    if known_range is None:
        return None
    start, end = known_range
    return _known_byte_table_pattern(
        state.datastore_bytes,
        start=start,
        end=end,
        fallback_pattern=state.datastore_pattern,
    )


def _datastore_get_expected_byte_positions(state: State, event: Event) -> dict[int, str]:
    if not state.datastore_bytes:
        return {}
    known_range = _byte_table_get_range(event)
    if known_range is None:
        return {}
    start, end = known_range
    return {
        offset - start: byte
        for offset, byte in state.datastore_bytes.items()
        if start <= offset <= end
    }


def _datastore_get_expected_min_length(state: State, event: Event) -> int | None:
    if not state.datastore_bytes or _is_datastore_wrapper_readdata(event):
        return None
    start, _ = _byte_table_get_range(event) or (0, 0)
    byte_positions = _datastore_get_expected_byte_positions(state, event)
    if "endrow" in _cellblock_components(event):
        if not byte_positions:
            return None
        return max(byte_positions) + 1
    rows = state.byte_table_rows.get("DataStore", 0x00A00000)
    if start < rows:
        return rows - start
    return None


def _mbr_get_expected_pattern(state: State, event: Event) -> str | None:
    if not state.mbr_table_bytes:
        return state.mbr_table_pattern
    known_range = _byte_table_known_get_range(state, event, symbol="MBR", default_rows=0x08000000)
    if known_range is None:
        return None
    start, end = known_range
    return _known_byte_table_pattern(
        state.mbr_table_bytes,
        start=start,
        end=end,
        fallback_pattern=state.mbr_table_pattern,
    )


def _mbr_get_expected_min_length(state: State, event: Event) -> int | None:
    if not state.mbr_table_bytes or "endrow" in _cellblock_components(event):
        return None
    start, _ = _byte_table_get_range(event) or (0, 0)
    rows = state.byte_table_rows.get("MBR", 0x08000000)
    if start < rows:
        return rows - start
    return None


def _mbr_get_expected_byte_positions(state: State, event: Event) -> dict[int, str]:
    if not state.mbr_table_bytes:
        return {}
    known_range = _byte_table_get_range(event)
    if known_range is None:
        return {}
    start, end = known_range
    return {
        offset - start: byte
        for offset, byte in state.mbr_table_bytes.items()
        if start <= offset <= end
    }


def _hex_pattern_bytes(pattern: str | None) -> list[str] | None:
    if pattern is None or len(pattern) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", pattern):
        return None
    return [pattern[index : index + 2].upper() for index in range(0, len(pattern), 2)]


def _mbr_shadow_read_expected_byte_positions(state: State, event: Event) -> dict[int, str]:
    if event.lba is None:
        return {}
    logical_block_size = _parse_int(state.locking_info.get("LogicalBlockSize")) or DEFAULT_LOGICAL_BLOCK_SIZE
    if logical_block_size <= 0:
        logical_block_size = DEFAULT_LOGICAL_BLOCK_SIZE
    start_lba, end_lba = event.lba
    start_byte = start_lba * logical_block_size
    end_byte = ((end_lba + 1) * logical_block_size) - 1
    known_bytes = dict(state.mbr_table_bytes)
    if not known_bytes:
        pattern_bytes = _hex_pattern_bytes(state.mbr_table_pattern)
        if pattern_bytes is not None:
            known_bytes = {offset: byte for offset, byte in enumerate(pattern_bytes)}
    return {
        offset - start_byte: byte
        for offset, byte in known_bytes.items()
        if start_byte <= offset <= end_byte
    }


def _byte_table_get_rows_out_of_bounds(state: State, event: Event) -> bool:
    rows = state.byte_table_rows.get(event.invoking_symbol)
    if rows is None:
        return False
    start, end = _byte_table_get_range(event) or (0, 0)
    return start >= rows or end >= rows


def _get_cellblock_parameter_error(state: State, event: Event) -> str | None:
    components = _cellblock_components(event)
    if not components:
        return None

    created = _created_table_for_event(state, event)
    if created is not None:
        _, kind = created
        if kind == "byte":
            if "table" in components:
                return "Get invoked on a table must omit the Cellblock Table component"
            if components & {"startcolumn", "endcolumn"}:
                return "Get invoked on a byte table must omit Cellblock column components"
            return None
        if kind == "object":
            if "table" in components:
                return "Get invoked on a table must omit the Cellblock Table component"
            if "endrow" in components:
                return "Get invoked on an object table must omit Cellblock endRow"
            if "startrow" not in components:
                return "Get invoked on an object table requires Cellblock startRow"
            return None

    symbol = event.invoking_symbol
    uid = event.invoking_uid
    if _is_byte_table_symbol(symbol) or _is_byte_table_uid(uid):
        if "table" in components:
            return "Get invoked on a table must omit the Cellblock Table component"
        if components & {"startcolumn", "endcolumn"}:
            return "Get invoked on a byte table must omit Cellblock column components"
        return None

    if _object_table_get_symbol(symbol):
        if "table" in components:
            return "Get invoked on a table must omit the Cellblock Table component"
        if "endrow" in components:
            return "Get invoked on an object table must omit Cellblock endRow"
        if "startrow" not in components:
            return "Get invoked on an object table requires Cellblock startRow"
        return None

    if components & {"table", "startrow", "endrow"}:
        return "Get invoked on an object must omit Cellblock Table, startRow, and endRow components"
    return None


def _startup_authority_arg(event: Event, *names: str) -> str | None:
    value = _raw_arg_value(event.required, event.optional, _method_raw_args(event), *names)
    return _authority_from_value(value)


def _startup_role_error(event: Event) -> str | None:
    host_signing = _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    host_exchange = _startup_authority_arg(event, "HostExchangeAuthority")
    if host_signing:
        operation = STARTUP_AUTHORITY_OPERATIONS.get(host_signing)
        if operation in {"Exchange", "TPerExchange", "TPerSign"}:
            return f"{host_signing} has Operation {operation} and is not valid as HostSigningAuthority"
    if host_exchange:
        operation = STARTUP_AUTHORITY_OPERATIONS.get(host_exchange)
        if operation != "Exchange":
            return f"{host_exchange} has Operation {operation or 'unknown'} and is not valid as HostExchangeAuthority"
    return None


def _startup_host_control_authority(event: Event) -> str | None:
    return _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs") or _startup_authority_arg(
        event, "HostExchangeAuthority"
    )


def _startup_exchange_certificate_flow(event: Event) -> bool:
    host_exchange = _startup_authority_arg(event, "HostExchangeAuthority")
    if not host_exchange or STARTUP_AUTHORITY_OPERATIONS.get(host_exchange) != "Exchange":
        return False
    host_challenge = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "HostChallenge")
    host_exchange_cert = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "HostExchangeCert")
    return not _empty_payload(host_challenge) and not _empty_payload(host_exchange_cert)


def _uinteger_arg_invalid(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    parsed = _parse_int(value)
    return parsed is None or parsed < 0


def _session_id_uinteger_error(event: Event, *names: str) -> str | None:
    found, value = _named_method_arg_value(event, *names)
    if found and _uinteger_arg_invalid(value):
        return f"{names[0]} must be a uinteger"
    return None


def _startup_write_error(event: Event) -> str | None:
    found, value = _named_method_arg_value(event, "Write", "write")
    if found and not _is_bool_literal(value):
        return "StartSession Write must be boolean"
    return None


def _default_response_sign_authority(sp: str | None, authority: str | None) -> str | None:
    if authority is None:
        return None
    if sp == "AdminSP" and authority in {
        "Anybody",
        "Makers",
        "MakerSymK",
        "MakerPuK",
        "SID",
        "Admin1",
        "AdminExch",
    }:
        return None
    if sp == "LockingSP" and (
        authority in {"Anybody", "Admins", "Users", "Admin1"}
        or _is_user(authority)
        or _is_band_master(authority)
        or authority == "EraseMaster"
    ):
        return None
    return UNKNOWN_RESPONSE_SIGN_AUTHORITY


def _startup_sp_signing_authority(state: State, event: Event) -> str | None:
    host_control = _startup_host_control_authority(event)
    if host_control is None:
        return None
    if host_control in state.authority_response_sign:
        return state.authority_response_sign[host_control]
    return _default_response_sign_authority(event.sp, host_control)


def _start_session_forbidden_return_names(event: Event) -> set[str]:
    if _startup_exchange_certificate_flow(event):
        return set()
    host_signing = _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    operation = STARTUP_AUTHORITY_OPERATIONS.get(host_signing or "")
    if operation in {"Sign", "SymK", "HMAC"}:
        return set()
    return {"SPChallenge"}


def _syncsession_forbidden_return_names(state: State, event: Event) -> set[str]:
    forbidden = set(_start_session_forbidden_return_names(event))
    sp_signing = _startup_sp_signing_authority(state, event)
    if sp_signing is None:
        forbidden.add("SignedHash")
    return forbidden


def _secure_mode_requires_messaging(state: State, authority: str | None) -> bool:
    if authority is None:
        return False
    secure = state.authority_secure.get(authority)
    return secure is not None and secure != 0


def _exchange_credential_state(state: State, authority: str | None) -> bool | None:
    if authority is None:
        return False
    present = state.authority_credential_present.get(authority)
    if present is not True:
        return present
    credential_symbol = state.authority_credential_symbol.get(authority)
    if credential_symbol is None:
        return True
    if credential_symbol.startswith("C_PIN"):
        return False
    return True


def _authority_limit_reached(state: State, authority: str | None) -> bool:
    if authority is None or authority in {"Anybody", "Admins", "Users", "Makers"}:
        return False
    limit = state.authority_limits.get(authority, 0)
    return limit > 0 and state.authority_uses.get(authority, 0) >= limit


def _startup_session_key_error(state: State, event: Event) -> str | None:
    host_signing = _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    host_exchange = _startup_authority_arg(event, "HostExchangeAuthority")
    host_control = host_signing or host_exchange
    if not _secure_mode_requires_messaging(state, host_control):
        return None

    response_exchange_observed = host_control in state.authority_response_exchange
    sp_exchange = state.authority_response_exchange.get(host_control)
    candidates: list[str] = []
    if sp_exchange:
        candidates.append(sp_exchange)
    if host_exchange:
        candidates.append(host_exchange)

    if not candidates:
        if response_exchange_observed:
            return f"{host_control} requires secure messaging but no exchange authority is available for session keys"
        return None

    credential_states = [_exchange_credential_state(state, candidate) for candidate in candidates]
    if any(state_value is True for state_value in credential_states):
        return None
    if any(state_value is None for state_value in credential_states):
        return None
    return f"{host_control} requires secure messaging but no exchange authority references an appropriate credential"


def _startup_signed_hash_error(state: State, event: Event) -> str | None:
    host_signing = _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    host_exchange = _startup_authority_arg(event, "HostExchangeAuthority")
    host_control = host_signing or host_exchange
    if host_control is None or not state.authority_hash_and_sign.get(host_control, False):
        return None
    signed_hash = _raw_arg_value(
        event.required,
        event.optional,
        _method_raw_args(event),
        "SignedHash",
        "signedHash",
        "Signed_Hash",
        "HostSignedHash",
        "HostSignature",
    )
    if _empty_payload(signed_hash):
        return f"{host_control} requires SignedHash during session startup"
    return None


def _startup_session_timeout_error(state: State, event: Event) -> str | None:
    found, value = _named_method_arg_value(event, "SessionTimeout", "sessionTimeout", "session_timeout")
    if not found:
        return None

    if _uinteger_arg_invalid(value):
        return "StartSession SessionTimeout must be a non-negative integer"
    timeout = _parse_int(value)
    if timeout is None:
        return "StartSession SessionTimeout must be a non-negative integer"

    sp_timeout = state.sp_session_timeouts.get(event.sp or "")
    max_timeout = state.tper_max_session_timeout
    min_timeout = state.tper_min_session_timeout

    if timeout == 0:
        if max_timeout is not None and max_timeout != 0:
            return "SessionTimeout zero is permitted only when MaxSessionTimeout is zero"
        if sp_timeout is not None and sp_timeout != 0:
            return "SessionTimeout zero is permitted only when the SPInfo SPSessionTimeout is zero"
        return None

    if max_timeout is not None and max_timeout > 0 and timeout > max_timeout:
        return "SessionTimeout exceeds the TPer MaxSessionTimeout property"
    if min_timeout is not None and min_timeout > 0 and timeout < min_timeout:
        return "SessionTimeout is below the TPer MinSessionTimeout property"
    if sp_timeout is not None and sp_timeout > 0 and timeout > sp_timeout:
        return "SessionTimeout exceeds the SPInfo SPSessionTimeout column"
    return None


def _startup_trans_timeout_error(state: State, event: Event) -> str | None:
    found, value = _named_method_arg_value(event, "TransTimeout", "transTimeout", "trans_timeout")
    if not found:
        return None

    if _uinteger_arg_invalid(value):
        return "StartSession TransTimeout must be a non-negative integer"
    timeout = _parse_int(value)
    if timeout is None:
        return "StartSession TransTimeout must be a non-negative integer"

    max_timeout = state.tper_max_trans_timeout
    min_timeout = state.tper_min_trans_timeout

    if max_timeout is not None and max_timeout > 0 and timeout > max_timeout:
        return "TransTimeout exceeds the TPer MaxTransTimeout property"
    if min_timeout is not None and min_timeout > 0 and timeout < min_timeout:
        return "TransTimeout is below the TPer MinTransTimeout property"
    return None


def _start_session_success_kwargs(state: State, event: Event) -> dict[str, Any]:
    min_values: dict[Any, int] = {"InitialCredit": 0}
    max_values: dict[Any, int] = {}
    required_names = set() if _is_tcgstorageapi_startsession(event) else {"HostSessionID", "SPSessionID"}
    expected_values: dict[str, Any] = {}

    host_session_id = _raw_arg_value(event.required, event.optional, _method_raw_args(event), *HOST_SESSION_ID_NAMES)
    if _session_id_key(host_session_id) is not None:
        expected_values["HostSessionID"] = host_session_id

    trans_min = 0
    found, value = _named_method_arg_value(event, "TransTimeout", "transTimeout", "trans_timeout")
    if found:
        requested = _parse_int(value)
        if requested is not None:
            trans_min = max(trans_min, requested)
    if state.tper_min_trans_timeout is not None and state.tper_min_trans_timeout > 0:
        trans_min = max(trans_min, state.tper_min_trans_timeout)
    min_values["TransTimeout"] = trans_min
    if state.tper_max_trans_timeout is not None and state.tper_max_trans_timeout > 0:
        max_values["TransTimeout"] = state.tper_max_trans_timeout
    if _startup_exchange_certificate_flow(event):
        required_names.update({"SPChallenge", "SPExchangeCert"})
    host_signing = _startup_authority_arg(event, "HostSigningAuthority", "Authority", "authAs", "AuthAs")
    if STARTUP_AUTHORITY_OPERATIONS.get(host_signing or "") in {"Sign", "SymK", "HMAC"}:
        required_names.add("SPChallenge")

    return {
        "required_return_names": required_names,
        "expected_return_values": expected_values,
        "forbidden_return_names": _syncsession_forbidden_return_names(state, event),
        "optional_return_min_values": min_values,
        "optional_return_max_values": max_values,
    }


def _startup_initial_credit_error(event: Event) -> str | None:
    found, value = _named_method_arg_value(event, "InitialCredit", "initialCredit", "initial_credit")
    if found and _uinteger_arg_invalid(value):
        return "StartSession InitialCredit must be a uinteger"
    return None


def _expected_start_session_while_open(state: State, event: Event) -> ExpectedResponse:
    if state.tper_max_sessions == 1:
        return ExpectedResponse(
            {FAIL, INVALID_PARAMETER, NOT_AUTHORIZED, SP_BUSY},
            forbidden_statuses={SUCCESS},
            reason="Observed TPer MaxSessions=1 means the single open session consumes all available session slots",
            confidence="high",
        )
    if state.session.sp == event.sp:
        if state.session.write or event.write_session:
            return ExpectedResponse(
                {SP_BUSY},
                forbidden_statuses={SUCCESS},
                reason="StartSession to an SP with an existing session is SP_BUSY when either session is read-write",
                confidence="high",
            )
        return ExpectedResponse(
            {SUCCESS},
            reason="A second read-only StartSession to the same SP is not SP_BUSY by the reconstructed state",
            confidence="medium",
        )
    if state.session.sp == "AdminSP" and state.session.write:
        return ExpectedResponse(
            {SP_BUSY, FAIL, INVALID_PARAMETER, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="A read-write AdminSP session cannot be combined with a session to any other SP",
            confidence="high",
        )
    if event.sp == "AdminSP" and event.write_session:
        return ExpectedResponse(
            {SP_BUSY, FAIL, INVALID_PARAMETER, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="A read-write AdminSP StartSession cannot be opened while another SP session is open",
            confidence="high",
        )
    return ExpectedResponse(
        {SUCCESS, FAIL, INVALID_PARAMETER},
        reason="Concurrent sessions to a different SP are outside the single-session reconstruction model",
        confidence="low",
    )


def _expected_start_session(state: State, event: Event) -> ExpectedResponse:
    if not _is_session_manager_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="StartSession must target the Session Manager", confidence="high")
    if event.sp is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="StartSession has unknown or invalid SPID", confidence="high")
    write_error = _startup_write_error(event)
    if write_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=write_error, confidence="high")
    if state.session.open:
        return _expected_start_session_while_open(state, event)
    if event.sp in state.deleted_sps:
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.sp} has been deleted and no longer accepts sessions",
            confidence="high",
        )
    if event.sp in state.sp_failed:
        return ExpectedResponse(
            {FAIL, INVALID_PARAMETER, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"{event.sp} is in the observed Failed lifecycle state and cannot complete session startup",
            confidence="high",
        )
    if state.sp_frozen.get(event.sp, False):
        return ExpectedResponse({FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.sp} is frozen and cannot accept new sessions", confidence="high")
    spid_uid = _clean_uid(_raw_arg_value(event.required, event.optional, _method_raw_args(event), "SPID", "SP", "sp"))
    enterprise_locking_sp = spid_uid == "0000020500010001"
    if event.sp == "LockingSP" and not state.locking_sp_activated and not enterprise_locking_sp:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, reason="LockingSP is not activated in reconstructed state", confidence="medium")

    session_id_error = _session_id_uinteger_error(event, *HOST_SESSION_ID_NAMES)
    if session_id_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_id_error, confidence="high")

    authority = event.authority or "Anybody"
    startup_role_error = _startup_role_error(event)
    if startup_role_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=startup_role_error, confidence="high")
    if authority in {"Admins", "Users", "Makers"}:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="StartSession HostSigningAuthority must be an individual authority", confidence="high")
    host_control = _startup_host_control_authority(event)
    if host_control is not None and not _authority_is_enabled(state, event.sp, host_control):
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"{host_control} is disabled and cannot be authenticated during session startup",
            confidence="high",
        )
    session_timeout_error = _startup_session_timeout_error(state, event)
    if session_timeout_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_timeout_error, confidence="high")
    trans_timeout_error = _startup_trans_timeout_error(state, event)
    if trans_timeout_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=trans_timeout_error, confidence="high")
    initial_credit_error = _startup_initial_credit_error(event)
    if initial_credit_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=initial_credit_error, confidence="high")
    session_key_error = _startup_session_key_error(state, event)
    if session_key_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_key_error, confidence="high")
    signed_hash_error = _startup_signed_hash_error(state, event)
    if signed_hash_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=signed_hash_error, confidence="high")
    success_kwargs = _start_session_success_kwargs(state, event)
    if authority == "Anybody":
        return ExpectedResponse(
            {SUCCESS},
            **success_kwargs,
            reason="Unauthenticated session is permitted",
            confidence="high",
        )
    if authority == "TPerSign":
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="TPerSign has Operation TPerSign and is valid during startup only as SPSigningAuthority, not HostSigningAuthority",
            confidence="high",
        )
    if not _authority_allowed_in_sp(event.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{authority} is not an authority in {event.sp}", confidence="high")
    if not _authority_is_enabled(state, event.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} is not enabled", confidence="high")
    if _authority_limit_reached(state, authority):
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"{authority} has reached its nonzero Authority.Limit",
            confidence="high",
        )
    operation = STARTUP_AUTHORITY_OPERATIONS.get(authority)
    if operation in {"Sign", "SymK", "HMAC"}:
        return ExpectedResponse(
            {SUCCESS},
            **success_kwargs,
            reason=f"{authority} startup uses {operation} challenge-response; host proof is supplied by StartTrustedSession",
            confidence="high",
        )
    challenge = _credential_text(event.challenge)
    if not challenge:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Credential authority requires a host challenge", confidence="high")
    try_limit = state.pin_try_limits.get(authority, 0)
    if try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} credential is locked out by TryLimit", confidence="high")
    if _credential_was_invalidated(state, authority, challenge):
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"{authority} challenge matches a credential value invalidated by GenKey",
            confidence="high",
        )

    known_pin = state.pins.get(authority)
    if known_pin is None:
        return ExpectedResponse(
            {SUCCESS, NOT_AUTHORIZED},
            **success_kwargs,
            reason=f"{authority} credential is unknown from history",
            confidence="low",
        )
    if challenge != known_pin:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{authority} challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        **success_kwargs,
        reason=f"{authority} challenge matches tracked PIN",
        confidence="high",
    )


def _expected_start_trusted_session(state: State, event: Event) -> ExpectedResponse:
    if not _is_session_manager_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} must target the Session Manager", confidence="high")
    if not state.session.open:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason=f"{event.method} requires an existing session startup exchange", confidence="high")
    session_id_error = _session_id_uinteger_error(event, *HOST_SESSION_ID_NAMES) or _session_id_uinteger_error(event, *SP_SESSION_ID_NAMES)
    if session_id_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_id_error, confidence="high")
    host_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *HOST_SESSION_ID_NAMES)
    )
    if host_session_id is not None and state.session.host_session_id is not None and host_session_id != state.session.host_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} HostSessionID does not match the preceding StartSession exchange",
            confidence="high",
        )
    sp_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *SP_SESSION_ID_NAMES)
    )
    if sp_session_id is not None and state.session.sp_session_id is not None and sp_session_id != state.session.sp_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} SPSessionID does not match the preceding StartSession exchange",
            confidence="high",
        )
    if state.session.startup_sp_challenge:
        host_response = _raw_arg_value(event.required, event.optional, _method_raw_args(event), "HostResponse", "hostResponse", "Response", "response")
        if _empty_payload(host_response):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason=f"{event.method} requires HostResponse because SyncSession returned SPChallenge",
                confidence="high",
            )
    forbidden_return_names = set() if state.session.startup_host_challenge else {"SPResponse"}
    return ExpectedResponse(
        {SUCCESS},
        forbidden_return_names=forbidden_return_names,
        reason=f"{event.method} continues the existing session startup exchange",
        confidence="medium",
    )


def _expected_sync_session(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="medium")
    session_id_error = _session_id_uinteger_error(event, *HOST_SESSION_ID_NAMES) or _session_id_uinteger_error(event, *SP_SESSION_ID_NAMES)
    if session_id_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_id_error, confidence="high")
    host_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *HOST_SESSION_ID_NAMES)
    )
    if host_session_id is not None and state.session.host_session_id is not None and host_session_id != state.session.host_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} HostSessionID does not match the preceding StartSession exchange",
            confidence="high",
        )
    sp_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *SP_SESSION_ID_NAMES)
    )
    if sp_session_id is not None and state.session.sp_session_id is not None and sp_session_id != state.session.sp_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} SPSessionID does not match the preceding StartSession exchange",
            confidence="high",
        )
    required_return_names: set[str] = set()
    expected_return_values: dict[str, Any] = {}
    if _raw_tcg_method_event(event):
        required_return_names = {"HostSessionID", "SPSessionID"}
        if state.session.host_session_id is not None:
            expected_return_values["HostSessionID"] = state.session.host_session_id
        if state.session.sp_session_id is not None:
            expected_return_values["SPSessionID"] = state.session.sp_session_id
    return ExpectedResponse(
        {SUCCESS},
        required_return_names=required_return_names,
        expected_return_values=expected_return_values,
        reason=f"{event.method} matches the open session identifiers when provided",
        confidence="high",
    )


def _expected_end_session(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="medium")
    session_id_error = _session_id_uinteger_error(event, *HOST_SESSION_ID_NAMES) or _session_id_uinteger_error(event, *SP_SESSION_ID_NAMES)
    if session_id_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=session_id_error, confidence="high")
    host_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *HOST_SESSION_ID_NAMES)
    )
    if host_session_id is not None and state.session.host_session_id is not None and host_session_id != state.session.host_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} HostSessionID does not match the open session",
            confidence="high",
        )
    sp_session_id = _session_id_key(
        _raw_arg_value(event.required, event.optional, _method_raw_args(event), *SP_SESSION_ID_NAMES)
    )
    if sp_session_id is not None and state.session.sp_session_id is not None and sp_session_id != state.session.sp_session_id:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} SPSessionID does not match the open session",
            confidence="high",
        )
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0 if _raw_tcg_method_event(event) else None,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason=f"{event.method} closes the open session identifiers when provided",
        confidence="high",
    )


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


def _crypto_stream_object_error(kind: str, event: Event) -> str | None:
    name = event.invoking_name or ""
    symbol = name if name.startswith(("H_SHA_", "C_AES_", "C_RSA_", "C_EC_", "C_HMAC_")) else event.invoking_symbol or name
    if not symbol and event.invoking_uid:
        symbol = _object_by_uid(event.invoking_uid)
    if not symbol or symbol.startswith("Unknown"):
        return None
    if kind in {"Hash", "HMAC"} and not symbol.startswith("H_SHA_"):
        return f"{event.method} is defined on H_SHA_* hash objects, not {symbol}"
    if kind in {"Encrypt", "Decrypt"} and symbol.startswith("H_SHA_"):
        return f"{event.method} is defined on credential objects, not H_SHA_* hash objects"
    return None


def _hash_result_size_bytes(symbol: str) -> int | None:
    if symbol.startswith("H_SHA_1"):
        return 20
    if symbol.startswith("H_SHA_256"):
        return 32
    if symbol.startswith("H_SHA_384"):
        return 48
    if symbol.startswith("H_SHA_512"):
        return 64
    return None


def _hash_symbol_for_event(event: Event) -> str:
    symbol = event.invoking_name or ""
    if not symbol.startswith("H_SHA_"):
        symbol = event.invoking_symbol or symbol
    if not symbol.startswith("H_SHA_") and event.invoking_uid:
        symbol = _object_by_uid(event.invoking_uid)
    return symbol


def _expected_crypto_stream_method(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an open session", confidence="medium")
    key = _crypto_stream_key(event)
    if key is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an invoking crypto object", confidence="medium")
    object_error = _crypto_stream_object_error(key[0], event)
    if object_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=object_error, confidence="high")
    cellblock_error = _crypto_datastore_cellblock_access_error(state, event)
    if cellblock_error is not None:
        return cellblock_error
    stream_open = state.crypto_streams.get(key, False)
    if event.method.endswith("Init"):
        if stream_open:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} cannot start a second open {key[0]} stream for the same object", confidence="high")
        found_buffer_out, buffer_out = _named_method_arg_value(event, "BufferOut", "bufferOut", "Output", "output")
        if event.method == "HashInit" and found_buffer_out:
            digest_size = _hash_result_size_bytes(_hash_symbol_for_event(event))
            capacity = _byte_table_cellblock_capacity(buffer_out)
            if digest_size is not None and capacity is not None and capacity < digest_size:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="HashInit BufferOut cellblock must be large enough to hold the hash result", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason=f"{event.method} opens a {key[0]} stream and returns an empty list",
            confidence="medium",
        )
    if not stream_open:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an open {key[0]} stream", confidence="high")
    found_buffer_out, buffer_out = _named_method_arg_value(event, "BufferOut", "bufferOut", "Output", "output")
    if event.method in {"Encrypt", "Decrypt"} and found_buffer_out:
        input_value = _xor_named_arg(event, "DataInput", "dataInput", "Input", "input", "Buffer", "buffer")
        input_pattern = _xor_payload_pattern(input_value)
        capacity = _byte_table_cellblock_capacity(buffer_out)
        if input_pattern is not None and capacity is not None and capacity < len(input_pattern) // 2:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} BufferOut cellblock must be large enough to hold the input byte size", confidence="high")
        return ExpectedResponse({SUCCESS}, expected_return_length=0, forbid_return_bool_literal=True, reason=f"{event.method} with BufferOut stores output bytes and returns an empty result", confidence="high")
    if event.method == "HMACFinalize" and key in state.crypto_stream_bufferout:
        digest_size = _hash_result_size_bytes(_hash_symbol_for_event(event))
        capacity = _byte_table_cellblock_capacity(state.crypto_stream_bufferout_value.get(key))
        if digest_size is not None and capacity is not None and capacity < digest_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="HMACFinalize cannot succeed when HMACInit BufferOut is smaller than the HMAC result", confidence="high")
    if event.method in {"Hash", "HMAC"} and key in state.crypto_stream_bufferout:
        return ExpectedResponse({SUCCESS}, expected_return_length=0, forbid_return_bool_literal=True, reason=f"{key[0]}Init BufferOut stores output and makes {event.method} return an empty result", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        forbid_return_bool_literal=True,
        forbid_return_bool_payload=True,
        require_return_byte_payload=True,
        expected_return_min_length=1 if event.method in {"Hash", "HMAC", "Encrypt", "Decrypt"} else None,
        reason=f"{event.method} is valid while the {key[0]} stream is open and returns byte data when BufferOut is omitted",
        confidence="medium",
    )


def _xor_named_arg(event: Event, *names: str) -> Any:
    found, value = _named_method_arg_value(event, *names)
    return value if found else None


def _xor_payload_pattern(value: Any) -> str | None:
    pattern = _extract_pattern(value)
    if pattern is not None:
        return pattern
    if isinstance(value, dict):
        for key in ("Data", "data", "Bytes", "bytes", "Input", "input", "Buffer", "BufferIn", "Payload", "payload"):
            found, nested = _dict_lookup(value, key)
            if found:
                pattern = _xor_payload_pattern(nested)
                if pattern is not None:
                    return pattern
        if len(value) == 1:
            return _xor_payload_pattern(next(iter(value.values())))
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], (str, bytes)):
            key = re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).lower()
            if key in {"data", "bytes", "input", "buffer", "bufferin", "payload"}:
                return _xor_payload_pattern(value[1])
        for nested in value:
            pattern = _xor_payload_pattern(nested)
            if pattern is not None:
                return pattern
    return None


def _xor_hex_bytes(pattern: str | None) -> list[int] | None:
    if pattern is None:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", pattern)
    if not compact or len(compact) % 2 != 0:
        return None
    return [int(compact[index : index + 2], 16) for index in range(0, len(compact), 2)]


def _xor_pattern_input_symbol(value: Any) -> str:
    symbol, uid = _object_ref_from_value(value)
    if symbol:
        return symbol
    if uid:
        return _object_by_uid(uid)
    text = _as_text(value)
    return text if _is_byte_table_symbol(text) else ""


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
    symbol = _explicit_byte_table_ref_symbol(value)
    if not symbol:
        return None
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
    known_bytes = _xor_hex_bytes(known)
    if known_bytes is None or end >= len(known_bytes):
        return None
    return "".join(f"{known_bytes[offset]:02X}" for offset in range(start, end + 1))


def _byte_table_cellblock_capacity(value: Any) -> int | None:
    has_byte_row_window = False

    def walk(item: Any) -> None:
        nonlocal has_byte_row_window
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).lower()
                if normalized in {"startrow", "endrow", "row", "startindex", "endindex", "startoffset", "endoffset", "offset", "length", "len", "size"}:
                    has_byte_row_window = True
                walk(nested)
            return
        if isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)

    walk(value)
    if not has_byte_row_window:
        return None
    row_range = _xor_cellblock_range(value)
    if row_range is None:
        return None
    start, end = row_range
    return end - start + 1


def _explicit_byte_table_ref_symbol(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("Table", "TableUID", "table", "tableUID", "Object", "ObjectID", "UID", "uid", "Name", "name"):
            found, item = _dict_lookup(value, key)
            if found:
                symbol, uid = _object_ref_from_value(item)
                symbol = symbol or _object_by_uid(uid)
                if _is_byte_table_symbol(symbol) or _is_byte_table_uid(uid):
                    return symbol or _object_by_uid(uid)
        found, cellblock = _dict_lookup(value, "CellBlock", "Cellblock", "cellblock")
        if found:
            symbol = _explicit_byte_table_ref_symbol(cellblock)
            if symbol:
                return symbol
        for item in value.values():
            symbol = _explicit_byte_table_ref_symbol(item)
            if symbol:
                return symbol
        return ""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            symbol = _explicit_byte_table_ref_symbol(item)
            if symbol:
                return symbol
        return ""
    symbol, uid = _object_ref_from_value(value)
    symbol = symbol or _object_by_uid(uid)
    if _is_byte_table_symbol(symbol) or _is_byte_table_uid(uid):
        return symbol or _object_by_uid(uid)
    return ""


def _datastore_access_authorized(state: State, *, write: bool) -> bool:
    if _datastore_ace_configured(state, write=write):
        return _datastore_master_authorizes(state) or _user_acl_allows_datastore(state, write=write)
    return _has_authority(state, "Admins") or _datastore_master_authorizes(state) or _user_acl_allows_datastore(state, write=write)


def _byte_table_cellblock_access_authorized(state: State, symbol: str, *, write: bool) -> bool:
    if symbol.startswith("DataStore"):
        return _datastore_access_authorized(state, write=write)
    if symbol == "MBR":
        return not write or _has_authority(state, "Admins")
    return True


def _crypto_datastore_cellblock_access_error(state: State, event: Event) -> ExpectedResponse | None:
    input_names = ("DataInput", "dataInput", "Input", "input", "BufferIn", "bufferIn", "Buffer", "buffer", "ProofBuffer", "proofBuffer", "Proof", "proof", "Data", "data")
    output_names = ("BufferOut", "bufferOut", "Output", "output")
    for names, write in ((input_names, False), (output_names, True)):
        for name in names:
            found, value = _named_method_arg_value(event, name)
            if not found:
                continue
            symbol = _explicit_byte_table_ref_symbol(value)
            if not (symbol.startswith("DataStore") or symbol == "MBR"):
                continue
            if write and not state.session.write:
                return ExpectedResponse(
                    {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                    forbidden_statuses={SUCCESS},
                    reason=f"Crypto BufferOut references {symbol} and therefore requires write access to that byte-table cellblock",
                    confidence="high",
                )
            if not _byte_table_cellblock_access_authorized(state, symbol, write=write):
                access = "Set" if write else "Get"
                return ExpectedResponse(
                    {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                    forbidden_statuses={SUCCESS},
                    reason=f"Crypto cellblock parameter references {symbol} but {access} access control on that cellblock is not fulfilled",
                    confidence="high",
                )
    return None


def _xor_result_pattern(data_pattern: str, pattern_pattern: str) -> str | None:
    data = _xor_hex_bytes(data_pattern)
    pattern = _xor_hex_bytes(pattern_pattern)
    if data is None or pattern is None or len(pattern) < len(data):
        return None
    return "".join(f"{data_byte ^ pattern[index]:02X}" for index, data_byte in enumerate(data))


def _expected_xor(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR requires an open SP session", confidence="medium")
    if event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP", ""} and not event.invoking_symbol.startswith("UnknownSP_"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR is an SP method", confidence="medium")
    cellblock_error = _crypto_datastore_cellblock_access_error(state, event)
    if cellblock_error is not None:
        return cellblock_error

    pattern_input = _xor_named_arg(event, "PatternInput", "patternInput", "Pattern", "pattern")
    if pattern_input is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR requires a PatternInput byte-table reference", confidence="high")
    if _byte_table_ref_invalid(pattern_input):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR PatternInput must reference a byte table", confidence="high")

    input_value = _xor_named_arg(event, "Input", "input", "Data", "data", "Bytes", "bytes", "BufferIn", "bufferIn", "Buffer", "buffer")
    input_pattern = _xor_payload_pattern(input_value)
    if input_pattern is None:
        input_pattern = _xor_cellblock_pattern(state, input_value)
    input_bytes = _xor_hex_bytes(input_pattern)
    if input_bytes is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR requires direct input bytes or a valid input cellblock", confidence="high")

    pattern_symbol = _xor_pattern_input_symbol(pattern_input)
    known_pattern = _xor_known_pattern(state, pattern_symbol)
    known_pattern_bytes = _xor_hex_bytes(known_pattern)
    if known_pattern_bytes is not None and len(known_pattern_bytes) < len(input_bytes):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR PatternInput must be at least as large as the input data", confidence="high")

    delete_pattern = _as_bool(_xor_named_arg(event, "DeletePattern", "deletePattern", "Delete", "delete"))
    found_buffer_out, buffer_out = _named_method_arg_value(event, "BufferOut", "bufferOut", "Output", "output")
    if (delete_pattern or found_buffer_out) and not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR DeletePattern or BufferOut requires write access to the referenced byte table", confidence="medium")
    if delete_pattern and not _byte_table_cellblock_access_authorized(state, pattern_symbol, write=True):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="XOR DeletePattern requires Set access to the PatternInput byte table",
            confidence="high",
        )

    if found_buffer_out:
        buffer_len = _byte_payload_length(buffer_out)
        if buffer_len is not None and buffer_len < len(input_bytes):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="XOR BufferOut cellblock must be at least as large as the result", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=True,
            reason="XOR with BufferOut specified writes the result to the cellblock and returns an empty result",
            confidence="high",
        )

    if known_pattern is not None:
        result_pattern = _xor_result_pattern(input_pattern or "", known_pattern)
        if result_pattern is not None:
            return ExpectedResponse({SUCCESS}, expected_return_pattern=result_pattern, reason="XOR without BufferOut returns the bytewise XOR of input data and PatternInput", confidence="high")

    return ExpectedResponse({SUCCESS}, reason="XOR without BufferOut returns the XOR operation result", confidence="medium")


def _expected_verify(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Verify requires an open SP session", confidence="medium")
    if not (event.invoking_symbol or event.invoking_uid or event.invoking_name):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Verify requires an invoking hash object or public key credential", confidence="medium")
    invoking_symbol = event.invoking_name if event.invoking_name.startswith(("H_SHA_", "C_RSA_", "C_EC_")) else event.invoking_symbol or event.invoking_name
    if invoking_symbol and not invoking_symbol.startswith(("H_SHA_", "C_RSA_", "C_EC_", "Unknown")):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Verify is defined only on H_SHA hash objects or RSA/EC public key credentials", confidence="high")
    if invoking_symbol.startswith(("C_RSA_", "C_EC_")):
        found_input, _ = _named_method_arg_value(event, "DataInput", "dataInput", "Input", "input", "Buffer", "buffer")
        found_proof, _ = _named_method_arg_value(event, "Proof", "proof", "ProofBuffer", "proofBuffer")
        if not found_proof:
            found_data, data_value = _named_method_arg_value(event, "Data", "data")
            found_proof = found_data and isinstance(data_value, dict) and any(_dict_lookup(data_value, key)[0] for key in ("Proof", "proof", "ProofBuffer", "proofBuffer"))
        if not found_input or not found_proof:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Verify on a public key credential requires both input data and proof data", confidence="high")
    cellblock_error = _crypto_datastore_cellblock_access_error(state, event)
    if cellblock_error is not None:
        return cellblock_error
    return ExpectedResponse(
        {SUCCESS},
        require_return_bool=True,
        forbid_return_status_bool_payload=True,
        reason="Successful Verify returns a Boolean verification result",
        confidence="high",
    )


def _expected_authenticate(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Authenticate requires an open session", confidence="high")
    authority = (
        event.authority
        or _authority_from_value(_mapping_value(event.required, "Authority"))
        or _authority_from_value(_mapping_value(event.required, "HostSigningAuthority"))
    )
    if authority is None:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Authenticate requires an Authority parameter", confidence="high")
    if authority == "Anybody":
        return ExpectedResponse({SUCCESS}, expected_return_bool=True, forbid_return_status_bool_payload=True, reason="Anybody Authenticate succeeds with result True when syntax is otherwise valid", confidence="high")
    if authority in {"Admins", "Users", "Makers"}:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Authenticate requires an individual authority", confidence="high")
    if not _authority_allowed_in_sp(state.session.sp, authority):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason=f"{authority} is not an authority in {state.session.sp}", confidence="high")
    proof = _mapping_value(event.optional, "Proof", "proof") or _mapping_value(event.required, "Proof", "proof")
    operation = STARTUP_AUTHORITY_OPERATIONS.get(authority)
    if proof is not None and authority != "Anybody" and operation is not None and operation != "Password":
        return ExpectedResponse(
            {INVALID_PARAMETER},
            forbidden_statuses={SUCCESS},
            expected_return_length=0,
            reason="Authenticate in Awaiting Challenge state rejects Proof supplied to a non-Password/non-Anybody authority",
            confidence="high",
        )
    if authority == "TPerSign":
        return ExpectedResponse({SUCCESS}, expected_return_bool=False, forbidden_return_bool=True, forbid_return_status_bool_payload=True, reason="TPerSign has Operation TPerSign and is not appropriate for explicit Authenticate", confidence="high")
    if not _authority_is_enabled(state, state.session.sp, authority):
        return ExpectedResponse({SUCCESS}, expected_return_bool=False, forbidden_return_bool=True, forbid_return_status_bool_payload=True, reason=f"{authority} is not enabled and Authenticate returns result False", confidence="high")
    if _authority_limit_reached(state, authority):
        return ExpectedResponse(
            {SUCCESS},
            expected_return_bool=False,
            forbidden_return_bool=True,
            forbid_return_status_bool_payload=True,
            reason=f"{authority} has reached its nonzero Authority.Limit",
            confidence="high",
        )
    try_limit = state.pin_try_limits.get(authority, 0)
    if try_limit > 0 and state.pin_tries.get(authority, 0) >= try_limit:
        return ExpectedResponse(
            {SUCCESS},
            expected_return_bool=False,
            forbidden_return_bool=True,
            forbid_return_status_bool_payload=True,
            reason=f"{authority} credential is locked out by TryLimit and Authenticate reports failure in its Success result",
            confidence="high",
        )
    challenge = (
        event.challenge
        or proof
        or _mapping_value(event.optional, "Challenge")
        or _mapping_value(event.required, "Challenge")
        or _mapping_value(event.required, "HostChallenge")
    )
    if _credential_was_invalidated(state, authority, challenge):
        return ExpectedResponse(
            {SUCCESS},
            expected_return_bool=False,
            forbidden_return_bool=True,
            forbid_return_status_bool_payload=True,
            reason=f"{authority} Authenticate challenge matches a credential value invalidated by GenKey",
            confidence="high",
        )
    known_pin = state.pins.get(authority)
    if known_pin is None:
        return ExpectedResponse({SUCCESS, NOT_AUTHORIZED}, reason=f"{authority} credential is unknown from history", confidence="low")
    if _credential_text(challenge) != known_pin:
        return ExpectedResponse({SUCCESS}, expected_return_bool=False, forbidden_return_bool=True, forbid_return_status_bool_payload=True, reason=f"{authority} authentication challenge does not match tracked PIN", confidence="high")
    return ExpectedResponse({SUCCESS}, expected_return_bool=True, forbidden_return_bool=False, forbid_return_status_bool_payload=True, reason=f"{authority} authentication challenge matches tracked PIN", confidence="high")


def _hash_protocol_column_for_symbol(symbol: str) -> int | None:
    if symbol.startswith("C_RSA_"):
        return 0x0C
    if symbol.startswith("C_AES_"):
        return 0x07
    if symbol.startswith("C_HMAC_"):
        return 0x04
    if re.match(r"C_EC_(160|192|224|256|384|521)", symbol):
        return 0x0B
    if re.match(r"C_EC_163", symbol):
        return 0x0D
    if re.match(r"C_EC_233", symbol):
        return 0x0C
    if re.match(r"C_EC_283", symbol):
        return 0x0E
    return None


def _credential_get_column_types(symbol: str, columns: set[int]) -> dict[int, str]:
    column_types: dict[int, str] = {}
    if symbol.startswith("H_SHA_") and (3 in columns or 4 in columns):
        if symbol.startswith("H_SHA_1"):
            type_name = "bytes_20"
        elif symbol.startswith("H_SHA_256"):
            type_name = "bytes_32"
        elif symbol.startswith("H_SHA_384"):
            type_name = "bytes_48"
        elif symbol.startswith("H_SHA_512"):
            type_name = "bytes_64"
        else:
            type_name = ""
        if type_name:
            if 3 in columns:
                column_types[3] = type_name
            if 4 in columns:
                column_types[4] = type_name
    if symbol.startswith("C_RSA_") and 3 in columns:
        column_types[3] = "padding_type"
    if symbol.startswith("C_HMAC_") and 3 in columns:
        if symbol.startswith("C_HMAC_160"):
            column_types[3] = "bytes_20"
        elif symbol.startswith("C_HMAC_256"):
            column_types[3] = "bytes_32"
        elif symbol.startswith("C_HMAC_384"):
            column_types[3] = "bytes_48"
        elif symbol.startswith("C_HMAC_512"):
            column_types[3] = "bytes_64"
    if symbol.startswith("C_AES_"):
        if 0x03 in columns:
            column_types[0x03] = "bytes_32" if symbol.startswith("C_AES_256") else "bytes_16"
        if 0x04 in columns:
            column_types[0x04] = "symmetric_mode"
        if 0x05 in columns:
            column_types[0x05] = "feedback_size"
        if 0x06 in columns:
            column_types[0x06] = "bytes_16"
    hash_column = _hash_protocol_column_for_symbol(symbol)
    if hash_column is not None and hash_column in columns:
        column_types[hash_column] = "hash_protocol"
    return column_types


def _invoking_object_definitely_absent(event: Event) -> bool:
    uid = _clean_uid(event.invoking_uid)
    if not uid or event.invoking_symbol:
        return False
    return uid in {"0000000000000000", "FFFFFFFFFFFFFFFF"}


def _expected_get(state: State, event: Event) -> ExpectedResponse:
    wrapper_get_state = _wrapper_scoped_authority_state(
        state,
        event,
        "getrange",
        "getmek",
        "getauthority",
        "isuserenabled",
        "getuserenabled",
        "userenabled",
        "getauthorityenabled",
        "isauthorityenabled",
        "authorityenabled",
        "getuserstate",
        "getpskentry",
        "readpskentry",
        "fetchpskentry",
        "querypskentry",
        "getpsk",
        "readpsk",
        "fetchpsk",
        "querypsk",
        "pskentry",
        "gettlspsk",
        "readtlspsk",
        "fetchtlspsk",
        "querytlspsk",
        "getpresharedkey",
        "readpresharedkey",
        "fetchpresharedkey",
        "querypresharedkey",
        "getpresharedkeyentry",
        "readpresharedkeyentry",
        "fetchpresharedkeyentry",
        "querypresharedkeyentry",
        "getreadlockenabled",
        "isreadlockenabled",
        "getwritelockenabled",
        "iswritelockenabled",
        "getreadlocked",
        "getreadlock",
        "isreadlocked",
        "getreadlockedstate",
        "israngereadlockset",
        "rangereadlocked",
        "getwritelocked",
        "getwritelock",
        "iswritelocked",
        "getwritelockedstate",
        "israngewritelockset",
        "rangewritelocked",
    )
    if wrapper_get_state is not None:
        state = wrapper_get_state
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Get requires an open session", confidence="high")
    if _invoking_object_definitely_absent(event):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Get fails if the table/object does not exist",
            confidence="high",
        )
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Get object does not belong to current SP", confidence="medium")
    if _created_object_outside_session(state, event.invoking_uid):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER},
            forbidden_statuses={SUCCESS},
            reason="Get target is a dynamically created object in a different SP security domain",
            confidence="high",
        )
    cellblock_error = _get_cellblock_parameter_error(state, event)
    if cellblock_error is not None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=cellblock_error, confidence="high")

    symbol = event.invoking_symbol
    if symbol.startswith("_CertData_"):
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Certificate byte table Get cannot request column values in the Cellblock", confidence="high")
        input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
        is_wrapper = isinstance(input_obj, dict) and bool(_function_name(input_obj))
        return ExpectedResponse(
            {SUCCESS},
            forbid_return_bool_literal=True,
            forbid_return_bool_payload=True,
            require_return_byte_payload=True,
            expected_return_min_length=1 if is_wrapper else None,
            reason="TCGstorageAPI reads TPer certificate byte tables through AdminSP as Anybody and successful reads return certificate bytes",
            confidence="medium",
        )
    if symbol == "C_PIN_MSID" and (not event.columns or PIN_COLUMN in event.columns):
        column_types = {PIN_COLUMN: "password"} if PIN_COLUMN in event.columns else {}
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            reason="C_PIN_MSID PIN is readable by Anybody in AdminSP and uses the password max-bytes type",
            confidence="high",
        )
    if symbol == "C_PIN_SID" and event.columns and PIN_COLUMN in event.columns:
        return ExpectedResponse({SUCCESS}, reason="Unreadable C_PIN_SID PIN cell is omitted from non-byte table Get results", confidence="high")
    if symbol == "C_PIN_SID" and not event.columns:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Full C_PIN_SID Get may include protected PIN; use CellBlock to omit unreadable PIN", confidence="medium")
    if symbol == "C_PIN_SID":
        if not _has_any_authority(state, {"Admins", "SID"}):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN_SID non-PIN columns require Admins or SID", confidence="medium")
        expected_cells = _cpin_expected_cells(state, event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_column_types=_cpin_get_column_types(event.columns),
            require_typed_return_columns=bool(_cpin_get_column_types(event.columns)),
            forbid_return_bool_literal=bool(event.columns & {CPIN_TRY_LIMIT_COLUMN, CPIN_TRIES_COLUMN}),
            reason="Authorized C_PIN_SID non-PIN Get is allowed and known C_PIN state cells must match",
            confidence="high" if expected_cells else "medium",
        )
    created_row = state.created_table_row_values_by_uid.get(event.invoking_uid)
    if created_row is not None:
        table_key, row_values = created_row
        if _cec_family_from_table_symbol(table_key) is not None:
            requested = event.columns or set(row_values)
            expected_cells = {column: value for column, value in row_values.items() if column in requested}
            return ExpectedResponse(
                {SUCCESS},
                expected_return_cells=expected_cells,
                reason="Created C_EC rows must retain supplied values and default omitted curve parameter cells",
                confidence="high" if expected_cells else "medium",
            )
    if symbol.startswith("C_PIN_") and event.columns and PIN_COLUMN in event.columns:
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types={PIN_COLUMN: "password"},
            reason="Unreadable C_PIN PIN cells are omitted from non-byte table Get results; any returned PIN cell must still match the password type",
            confidence="high",
        )
    if symbol.startswith("C_PIN_") and not event.columns:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Full C_PIN Get may include protected PIN; use CellBlock to omit unreadable PIN", confidence="medium")
    if symbol.startswith("C_PIN_"):
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="C_PIN non-PIN columns require Admins", confidence="medium")
        expected_cells = _cpin_expected_cells(state, event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_column_types=_cpin_get_column_types(event.columns),
            require_typed_return_columns=bool(_cpin_get_column_types(event.columns)),
            forbid_return_bool_literal=bool(event.columns & {CPIN_TRY_LIMIT_COLUMN, CPIN_TRIES_COLUMN}),
            reason="Authorized C_PIN non-PIN Get is allowed and known C_PIN state cells must match",
            confidence="high" if expected_cells else "medium",
        )
    if symbol == "TPerInfo":
        column_types = {}
        if not event.columns or 0 in event.columns:
            column_types[0] = "bytes_8"
        if not event.columns or 1 in event.columns:
            column_types[1] = "uinteger_8"
        if not event.columns or 2 in event.columns:
            column_types[2] = "bytes_12"
        for column in (3, 4, 5):
            if not event.columns or column in event.columns:
                column_types[column] = "uinteger_4"
        if not event.columns or 6 in event.columns:
            column_types[6] = "uinteger_8"
        if not event.columns or 8 in event.columns:
            column_types[8] = "boolean"
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(event.columns and column_types),
            reason="TPerInfo is readable by Anybody and returned UID/GUDID/ProgrammaticResetEnable cells must match their declared types",
            confidence="high" if column_types else "medium",
        )
    if symbol in {"AdminSP", "LockingSP", "SP"}:
        column_types = {}
        if 0 in event.columns:
            column_types[0] = "bytes_8"
        if 5 in event.columns:
            column_types[5] = "uinteger_8"
        if 6 in event.columns:
            column_types[6] = "life_cycle_state"
        if 7 in event.columns:
            column_types[7] = "boolean"
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            reason="SP table LifeCycleState and Frozen cells must match their declared return types",
            confidence="high" if column_types else "medium",
        )
    if symbol == "LockingInfo":
        input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
        function_alias = _function_alias(_function_name(input_obj)) if isinstance(input_obj, dict) else ""
        single_getter_column = _tcgstorageapi_lockinginfo_single_getter_column(event)
        returned_cells = _flatten_return_values(_output_return_values(event.raw), symbol)
        if single_getter_column is not None and single_getter_column not in returned_cells:
            scalar_cell = _single_cell_payload_value(_output_return_values(event.raw))
            if scalar_cell is not _MISSING_PAYLOAD_VALUE:
                returned_cells = dict(returned_cells)
                returned_cells[single_getter_column] = scalar_cell
        returned_max_ranges = _parse_int(returned_cells.get(4))
        max_observed_range = _max_observed_non_global_range_id(state)
        if returned_max_ranges is not None and max_observed_range > returned_max_ranges:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="LockingInfo MaxRanges cannot be lower than a previously observed non-global Locking/K_AES range id",
                confidence="high",
            )
        known_cells = {
            column: state.locking_info[name]
            for column, name in LOCKING_INFO_COLUMNS.items()
            if name in state.locking_info
        }
        observed_values = _observed_return_values(_output_return_values(event.raw), state.locking_info)
        locking_info_wrapper = function_alias in {
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
            "getmaxranges",
            "readmaxranges",
            "fetchmaxranges",
            "querymaxranges",
            "loadmaxranges",
        }
        expected_cells = {}
        if single_getter_column is not None:
            known_name = LOCKING_INFO_COLUMNS.get(single_getter_column)
            if known_name in state.locking_info:
                expected_cells[single_getter_column] = state.locking_info[known_name]
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_values=observed_values,
            required_any_return_names=set() if single_getter_column is not None else (set(LOCKING_INFO_COLUMNS.values()) if locking_info_wrapper else set()),
            require_non_empty_return_payload=locking_info_wrapper,
            optional_return_cells=known_cells,
            expected_return_column_types={
                column: type_name
                for column, type_name in {
                    0: "bytes_8",
                    2: "uinteger_4",
                    3: "enc_supported",
                    4: "uinteger_4",
                    5: "uinteger_4",
                }.items()
                if column in event.columns and single_getter_column is None
            },
            require_typed_return_columns=bool(event.columns and single_getter_column is None),
            forbid_return_bool_literal=single_getter_column != 7,
            reason="LockingInfo geometry columns may be retrieved by Anybody and repeated observations must remain stable",
            confidence="high" if known_cells or observed_values else "medium",
        )
    if symbol.startswith("MethodID_"):
        expected_cells = _methodid_expected_cells(event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            reason="MethodID rows are Anybody-readable and known MethodID Name cells must match their method UID",
            confidence="high" if expected_cells else "medium",
        )
    if _is_loglist_row_symbol(symbol, event.invoking_uid):
        known_cells = _loglist_expected_cells(state, event)
        requested = event.columns or set(known_cells)
        expected_cells = {column: value for column, value in known_cells.items() if column in requested}
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            reason="Known LogList row default/modified cells must match Log Template state",
            confidence="high" if expected_cells else "medium",
        )
    if symbol.startswith("C_RSA_"):
        column_types = _credential_get_column_types(symbol, event.columns)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            reason="C_RSA Format/Hash columns are typed enumerations and successful Get values must be valid enum values",
            confidence="high" if column_types else "medium",
        )
    if symbol.startswith("H_SHA_"):
        column_types = _credential_get_column_types(symbol, event.columns)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            reason="H_SHA Proof/Accumulator cells are fixed-byte hash-width values and successful Get values must match the declared byte size",
            confidence="high" if column_types else "medium",
        )
    hash_column = _hash_protocol_column_for_symbol(symbol)
    if hash_column is not None:
        column_types = _credential_get_column_types(symbol, event.columns)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            reason="Credential typed columns must return values valid for their declared Core table types",
            confidence="high" if column_types else "medium",
        )
    if symbol.startswith("SecretProtect_"):
        expected_cells = _secretprotect_expected_cells(event)
        column_types = {3: "protect_types"} if 3 in event.columns else {}
        return ExpectedResponse(
            {SUCCESS, INVALID_PARAMETER, FAIL},
            expected_return_cells=expected_cells,
            expected_return_column_types=column_types,
            require_typed_return_columns=bool(column_types),
            allow_status_alternatives=True,
            reason="If a concrete Opal SecretProtect row is returned successfully, its Table and ColumnNumber cells identify the protected K_AES Key column",
            confidence="high" if expected_cells or column_types else "medium",
        )
    if symbol.startswith("Locking_"):
        protected_columns = set(range(3, 20))
        range_id = _range_id_from_symbol(symbol)
        range_was_observed = range_id in state.ranges if range_id is not None else False
        get_auth_state = _wrapper_scoped_authority_state(
            state,
            event,
            "getrange",
            "getmek",
            "getreadlockenabled",
            "isreadlockenabled",
            "readreadlockenabled",
            "fetchreadlockenabled",
            "queryreadlockenabled",
            "loadreadlockenabled",
            "readrangereadlockenabled",
            "fetchrangereadlockenabled",
            "queryrangereadlockenabled",
            "loadrangereadlockenabled",
            "getwritelockenabled",
            "iswritelockenabled",
            "readwritelockenabled",
            "fetchwritelockenabled",
            "querywritelockenabled",
            "loadwritelockenabled",
            "readrangewritelockenabled",
            "fetchrangewritelockenabled",
            "queryrangewritelockenabled",
            "loadrangewritelockenabled",
            "getreadlocked",
            "getreadlock",
            "isreadlocked",
            "readreadlocked",
            "fetchreadlocked",
            "queryreadlocked",
            "loadreadlocked",
            "readrangereadlocked",
            "fetchrangereadlocked",
            "queryrangereadlocked",
            "loadrangereadlocked",
            "getreadlockedstate",
            "readreadlockstate",
            "fetchreadlockstate",
            "queryreadlockstate",
            "loadreadlockstate",
            "israngereadlockset",
            "rangereadlocked",
            "getwritelocked",
            "getwritelock",
            "iswritelocked",
            "readwritelocked",
            "fetchwritelocked",
            "querywritelocked",
            "loadwritelocked",
            "readrangewritelocked",
            "fetchrangewritelocked",
            "queryrangewritelocked",
            "loadrangewritelocked",
            "getwritelockedstate",
            "readwritelockstate",
            "fetchwritelockstate",
            "querywritelockstate",
            "loadwritelockstate",
            "israngewritelockset",
            "rangewritelocked",
        ) or state
        range_acl = range_id is not None and _ace_satisfied(get_auth_state, _locking_ace_symbol(0xD000, range_id))
        range_master = _range_master_authorizes(get_auth_state, range_id)
        if (not event.columns or event.columns & protected_columns) and not _has_authority(get_auth_state, "Admins") and not range_acl and not range_master:
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Locking range state columns require Admins", confidence="high")
        range_support = _range_id_support_state(state, range_id)
        if range_support is False:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Locking range id is outside observed LockingInfo.MaxRanges support",
                confidence="high",
            )
        allowed_statuses = {SUCCESS}
        if range_support is None:
            allowed_statuses.update({INVALID_PARAMETER, FAIL})
        expected_cells: dict[int, Any] = {}
        expected_values: dict[str, Any] = {}
        expected_uid_refs: set[str] = set()
        forbidden_columns: set[int] = set()
        column_types: dict[int, str] = {}
        if range_id is not None:
            range_state = _range(state, range_id)
            bool_getter = _tcgstorageapi_locking_bool_getter(event)
            if bool_getter == "ReadLockEnabled":
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=range_state.read_lock_enabled,
                    forbidden_return_bool=not range_state.read_lock_enabled,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI locking boolean getter returns the tracked ReadLockEnabled value",
                    confidence="high" if range_support is not None else "medium",
                )
            if bool_getter == "WriteLockEnabled":
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=range_state.write_lock_enabled,
                    forbidden_return_bool=not range_state.write_lock_enabled,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI locking boolean getter returns the tracked WriteLockEnabled value",
                    confidence="high" if range_support is not None else "medium",
                )
            if bool_getter == "ReadLocked":
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=range_state.read_locked,
                    forbidden_return_bool=not range_state.read_locked,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI locking boolean getter returns the tracked ReadLocked value",
                    confidence="high" if range_support is not None else "medium",
                )
            if bool_getter == "WriteLocked":
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=range_state.write_locked,
                    forbidden_return_bool=not range_state.write_locked,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI locking boolean getter returns the tracked WriteLocked value",
                    confidence="high" if range_support is not None else "medium",
                )
            if bool_getter == "LockOnResetEnabled":
                enabled = bool(range_state.lock_on_reset_types or range_state.lock_on_reset)
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=enabled,
                    forbidden_return_bool=not enabled,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI locking boolean getter returns whether LockOnReset is configured",
                    confidence="high" if range_support is not None else "medium",
                )
            reencrypt_bool_getter = _tcgstorageapi_reencrypt_bool_getter(event)
            if reencrypt_bool_getter == "ReEncrypting":
                active = _parse_reencrypt_state(range_state.reencrypt_state) in {2, 3, 5}
                return ExpectedResponse(
                    allowed_statuses,
                    expected_return_bool=active,
                    forbidden_return_bool=not active,
                    allow_status_alternatives=range_support is None,
                    reason="TCGstorageAPI ReEncrypt boolean getter returns whether ReEncryptState is pending, active, or paused",
                    confidence="high" if range_support is not None else "medium",
                )
            required_range_names: set[str] = set()
            if range_was_observed and _is_tcgstorageapi_getrange(event):
                expected_values = _observed_getrange_return_values(
                    event,
                    {
                        "RangeStart": range_state.range_start,
                        "RangeLength": range_state.range_length,
                        "ReadLockEnabled": range_state.read_lock_enabled,
                        "WriteLockEnabled": range_state.write_lock_enabled,
                        "ReadLocked": range_state.read_locked,
                        "WriteLocked": range_state.write_locked,
                        "LockOnReset": range_state.lock_on_reset_types,
                    },
                )
                if range_state.read_locked or range_state.write_locked:
                    required_range_names.update({"ReadLocked", "WriteLocked"})
            if 3 in event.columns:
                expected_cells[3] = range_state.range_start
            if 4 in event.columns:
                expected_cells[4] = range_state.range_length
            if 5 in event.columns:
                expected_cells[5] = range_state.read_lock_enabled
            if 6 in event.columns:
                expected_cells[6] = range_state.write_lock_enabled
            if 7 in event.columns:
                expected_cells[7] = range_state.read_locked
            if 8 in event.columns:
                expected_cells[8] = range_state.write_locked
            if 9 in event.columns:
                column_types[9] = "reset_types"
                expected_cells[9] = range_state.lock_on_reset_types
            if 10 in event.columns and range_state.active_key_known:
                if _is_tcgstorageapi_getmek(event):
                    active_key_uid = _key_symbol_uid(range_state.active_key)
                    if active_key_uid:
                        expected_uid_refs = {active_key_uid}
                else:
                    expected_cells[10] = range_state.active_key
            if 11 in event.columns and range_state.next_key_known:
                if _is_tcgstorageapi_getnextkey(event):
                    next_key_uid = _key_symbol_uid(range_state.next_key)
                    if next_key_uid:
                        expected_uid_refs = {next_key_uid}
                    else:
                        expected_cells[11] = range_state.next_key
                else:
                    expected_cells[11] = range_state.next_key
            if 12 in event.columns:
                expected_cells[12] = range_state.reencrypt_state
            if 13 in event.columns:
                forbidden_columns.add(13)
            if 14 in event.columns and range_state.adv_key_mode is not None:
                column_types[14] = "adv_key_mode"
                expected_cells[14] = range_state.adv_key_mode
            elif 14 in event.columns:
                column_types[14] = "adv_key_mode"
            if 15 in event.columns:
                column_types[15] = "verify_mode"
                if range_state.verify_mode is not None:
                    expected_cells[15] = range_state.verify_mode
            if event.columns == {16} and range_state.cont_on_reset is not None:
                expected_cells[16] = range_state.cont_on_reset
            if 17 in event.columns and range_state.last_reencrypt_lba is not None:
                expected_cells[17] = range_state.last_reencrypt_lba
            if 18 in event.columns:
                column_types[18] = "last_reenc_stat"
                if range_state.last_reenc_stat is not None:
                    expected_cells[18] = range_state.last_reenc_stat
            if 19 in event.columns:
                column_types[19] = "gen_status"
                if range_state.general_status is not None:
                    expected_cells[19] = range_state.general_status
        return ExpectedResponse(
            allowed_statuses,
            expected_return_cells=expected_cells,
            expected_return_values=expected_values,
            expected_return_uid_refs=expected_uid_refs,
            expected_return_min_length=1 if range_was_observed and _is_tcgstorageapi_getrange(event) else None,
            required_any_return_names=(
                required_range_names
                or {"RangeStart", "RangeLength", "ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset"}
                if _is_tcgstorageapi_getrange(event)
                else set()
            ),
            forbidden_return_columns=forbidden_columns,
            expected_return_column_types=column_types if range_id is not None else {},
            allow_status_alternatives=range_support is None,
            forbid_return_bool_literal=(
                _is_tcgstorageapi_getrange(event)
                or _is_tcgstorageapi_lockonreset_value_getter(event)
                or _is_tcgstorageapi_getmek(event)
                or _is_tcgstorageapi_getnextkey(event)
                or bool(event.columns & {14, 18})
            ),
            reason="Authorized Locking range Get is allowed when the optional range exists; unobserved Range9+ may also be absent",
            confidence="high" if range_support is not None else "medium",
        )
    if symbol == "MBRControl":
        expected_cells = _mbrcontrol_expected_cells(state, event)
        function_alias = _function_alias(_function_name(_input_section(event.raw)))
        scalar_reset_getter = function_alias in {
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
        }
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_column_types={3: "reset_types"} if (not event.columns or 3 in event.columns) else {},
            require_typed_return_columns=bool(event.columns and 3 in event.columns and not scalar_reset_getter),
            forbid_return_bool_literal=bool(event.columns & {3}),
            reason="MBRControl Get is permitted by ACE_Anybody and known MBRControl cells must match preconfiguration or prior successful Set state",
            confidence="high" if expected_cells else "medium",
        )
    if symbol == "DataRemovalMechanism":
        expected_cells = {}
        if (not event.columns or 1 in event.columns) and state.data_removal_mechanism is not None:
            expected_cells[1] = state.data_removal_mechanism
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            forbid_return_bool_literal=True,
            reason="DataRemovalMechanism Get is allowed and known ActiveDataRemovalMechanism must match prior successful Set state",
            confidence="high" if expected_cells else "medium",
        )
    if symbol == "MBR":
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        if _byte_table_get_rows_out_of_bounds(state, event):
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="MBR byte-table Get row is outside the observed descriptor Rows bound", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_pattern=_mbr_get_expected_pattern(state, event),
            expected_return_byte_positions=_mbr_get_expected_byte_positions(state, event),
            expected_return_min_length=_mbr_get_expected_min_length(state, event),
            forbid_return_bool_literal=True,
            require_return_byte_payload=True,
            reason="MBR byte table Get is permitted by ACE_Anybody and must match tracked MBR bytes when known",
            confidence="high" if state.mbr_table_pattern is not None or state.mbr_table_bytes else "medium",
        )
    if symbol.startswith("K_AES_") and event.method == "Get":
        columns = set(event.columns)
        range_support = _range_id_support_state(state, _range_id_from_key(symbol))
        if range_support is False:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES range key id is outside observed LockingInfo.MaxRanges support",
                confidence="high",
            )
        optional_absence_statuses = {INVALID_PARAMETER, FAIL} if range_support is None else set()
        if not columns:
            return ExpectedResponse(
                {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Get without a Cellblock can include the protected Key column",
                confidence="medium",
            )
        if columns - {0, 1, 2, K_AES_KEY_COLUMN, K_AES_MODE_COLUMN}:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Get requested columns outside the K_AES row definition",
                confidence="high",
            )
        if K_AES_KEY_COLUMN in columns:
            return ExpectedResponse(
                {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="K_AES Key is SecretProtect-protected from Get",
                confidence="high",
            )
        if K_AES_MODE_COLUMN in columns and _ace_expression_configured(state, "ACE_0003BFFF") and not _ace_satisfied(state, "ACE_0003BFFF"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="K_AES Mode Get is blocked by personalized ACE_K_AES_Mode", confidence="high")
        if K_AES_MODE_COLUMN not in columns:
            return ExpectedResponse(
                {SUCCESS} | optional_absence_statuses,
                forbidden_return_columns={K_AES_KEY_COLUMN},
                allow_status_alternatives=range_support is None,
                reason="K_AES metadata Get does not include the protected Key column when the optional key row exists",
                confidence="medium",
            )
        return ExpectedResponse(
            {SUCCESS} | optional_absence_statuses,
            required_return_columns={K_AES_MODE_COLUMN},
            forbidden_return_columns={K_AES_KEY_COLUMN},
            expected_return_column_types={K_AES_MODE_COLUMN: "symmetric_mode_media"},
            require_typed_return_columns=True,
            allow_status_alternatives=range_support is None,
            reason="K_AES Mode Get is permitted by ACE_K_AES_Mode when the optional key row exists",
            confidence="high" if range_support is not None else "medium",
        )
    if symbol.startswith("DataStore"):
        if _byte_table_get_invalid(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Byte table Get cannot request column values in the Cellblock", confidence="high")
        if _byte_table_get_rows_out_of_bounds(state, event):
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="DataStore byte-table Get row is outside the observed descriptor Rows bound", confidence="high")
        wrapper_authorized = _datastore_wrapper_access_authorized(state, event, write=False)
        if wrapper_authorized is not None:
            authorized = wrapper_authorized
        elif _datastore_ace_configured(state, write=False):
            authorized = _datastore_master_authorizes(state) or _user_acl_allows_datastore(state, write=False)
        else:
            authorized = _has_authority(state, "Admins") or _datastore_master_authorizes(state) or _user_acl_allows_datastore(state, write=False)
        if not authorized:
            return ExpectedResponse(
                {SUCCESS},
                expected_return_length=0,
                reason="Unauthorized DataStore byte-table Get returns an empty results list",
                confidence="high",
            )
        return ExpectedResponse(
            {SUCCESS},
            expected_return_pattern=_datastore_get_expected_pattern(state, event),
            expected_return_byte_positions=_datastore_get_expected_byte_positions(state, event),
            expected_return_min_length=_datastore_get_expected_min_length(state, event),
            forbid_return_bool_literal=True,
            forbid_return_bool_payload=True,
            require_return_byte_payload=True,
            reason="Authorized DataStore Get is allowed and must match the tracked byte-table payload when known",
            confidence="high" if state.datastore_pattern is not None or state.datastore_bytes else "medium",
        )
    if symbol in {"Table_MBR", "Table_DataStore"}:
        expected_cells, optional_cells, min_cells, max_cells, cell_lte = _table_descriptor_expected_cells(state, event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            optional_return_cells=optional_cells,
            expected_return_min_cells=min_cells,
            expected_return_max_cells=max_cells,
            expected_return_cell_lte=cell_lte,
            reason="Known Opal byte-table descriptor cells must match their preconfigured kind and minimum row count",
            confidence="high" if expected_cells or optional_cells or min_cells or max_cells or cell_lte else "medium",
        )
    if symbol.startswith("Table_"):
        expected_cells, optional_cells, min_cells, max_cells, cell_lte = _table_descriptor_expected_cells(state, event)
        if expected_cells or optional_cells or min_cells or max_cells or cell_lte:
            return ExpectedResponse(
                {SUCCESS},
                expected_return_cells=expected_cells,
                optional_return_cells=optional_cells,
                expected_return_min_cells=min_cells,
                expected_return_max_cells=max_cells,
                expected_return_cell_lte=cell_lte,
                reason="Known Opal object-table descriptor granularity cells must be zero",
                confidence="high",
            )
    if symbol.startswith("AccessControl_"):
        expected_cells = _accesscontrol_expected_cells(event)
        if event.columns and ACCESS_CONTROL_ACL_COLUMN in event.columns:
            if expected_cells:
                return ExpectedResponse(
                    {SUCCESS},
                    expected_return_cells=expected_cells,
                    forbidden_return_columns={ACCESS_CONTROL_ACL_COLUMN},
                    reason="Direct AccessControl.Get may omit or reject the unreadable ACL cell, but successful metadata cells in the requested range must match",
                    confidence="high",
                )
            return ExpectedResponse(
                {SUCCESS},
                forbidden_return_columns={ACCESS_CONTROL_ACL_COLUMN},
                reason="AccessControl ACL column is readable only through GetACL; direct non-byte Get may omit the unreadable cell",
                confidence="high",
            )
        if not event.columns:
            if expected_cells:
                return ExpectedResponse(
                    {SUCCESS},
                    expected_return_cells=expected_cells,
                    forbidden_return_columns={ACCESS_CONTROL_ACL_COLUMN},
                    reason="AccessControl ACL column is readable only through GetACL; full direct Get may omit ACL but known issued metadata cells must still match",
                    confidence="high",
                )
            return ExpectedResponse(
                {SUCCESS},
                forbidden_return_columns={ACCESS_CONTROL_ACL_COLUMN},
                reason="AccessControl ACL column is readable only through GetACL; direct non-byte Get may omit the unreadable cell",
                confidence="high",
            )
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            reason="AccessControl metadata columns may be retrieved directly and known issued metadata cells must match",
            confidence="high" if expected_cells else "medium",
        )
    if symbol.startswith("Authority_"):
        if event.columns and event.columns <= PUBLIC_COMMON_NAME_COLUMNS:
            return ExpectedResponse({SUCCESS}, reason=f"{symbol} UID/CommonName Get is permitted by ACE_Anybody_Get_CommonName", confidence="high")
        get_auth_state = _wrapper_scoped_authority_state(state, event, "getauthority") or state
        if not _has_authority(get_auth_state, "Admins") and not _ace_satisfied(get_auth_state, "ACE_00039000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        authority = _authority_by_object(symbol)
        if _is_tcgstorageapi_getauthority(event):
            enabled = _authority_is_enabled(state, state.session.sp, authority)
            return ExpectedResponse(
                {SUCCESS},
                expected_return_bool=enabled,
                forbidden_return_bool=not enabled,
                reason=f"TCGstorageAPI getAuthority returns the tracked Authority.Enabled value for {authority}",
                confidence="high",
            )
        expected_cells = _authority_expected_cells(state, event)
        column_types = {9: "auth_method"} if (not event.columns or 9 in event.columns) else {}
        column_types.update(_authority_get_column_types(event.columns))
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_column_types=column_types,
            forbid_return_bool_literal=bool(event.columns & {15, 16}),
            reason=f"Authorized {symbol} Get is allowed and known Authority state cells must match",
            confidence="high" if expected_cells else "medium",
        )
    if symbol.startswith("Port"):
        requested = event.columns or set(PORT_COLUMNS)
        expected_cells = {
            column: value
            for column, value in state.port_values.get(symbol, {}).items()
            if column in requested
        }
        port_locked_getter = _tcgstorageapi_port_bool_getter(event) == "PortLocked"
        port_row_getter = _is_tcgstorageapi_getport(event)
        expected_port_bool: bool | None = None
        if (port_locked_getter or port_row_getter) and 3 in expected_cells:
            locked = _as_bool(expected_cells[3])
            if locked is not None:
                expected_port_bool = locked
        if port_locked_getter and expected_port_bool is not None:
            return ExpectedResponse(
                {SUCCESS},
                expected_return_bool=expected_port_bool,
                forbidden_return_bool=not expected_port_bool,
                reason="TCGstorageAPI Port boolean getter returns the tracked PortLocked value",
                confidence="high",
            )
        if port_row_getter and expected_port_bool is not None:
            expected_cells = {column: value for column, value in expected_cells.items() if column != 3}
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            expected_return_bool=expected_port_bool,
            forbidden_return_bool=(not expected_port_bool) if expected_port_bool is not None else None,
            required_any_return_names={
                "PortLocked",
                "portLocked",
                "locked",
                "Locked",
                "isLocked",
                "IsLocked",
                "portLock",
                "PortLock",
                "lockState",
                "LockState",
                "portLockState",
                "PortLockState",
                "portState",
                "PortState",
            } if port_row_getter else set(),
            forbid_return_bool_literal=port_row_getter,
            forbid_bare_status_return_payload=port_row_getter,
            reason="Port Get is readable and tracked Port state cells must match",
            confidence="high" if expected_cells or expected_port_bool is not None else "medium",
        )
    if symbol.startswith("TLS_PSK_Key"):
        get_auth_state = _wrapper_scoped_authority_state(state, event, "getpskentry") or state
        required = _package_required_authorities(get_auth_state, event)
        if not _has_any_authority(get_auth_state, required):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires one of {sorted(required)}", confidence="medium")
        returned_cells = _flatten_return_values(_output_return_values(event.raw), symbol)
        requested = event.columns or set(returned_cells) or set(TLS_PSK_COLUMNS)
        expected_cells = {
            column: value
            for column, value in state.psk_values.get(symbol, {}).items()
            if column in requested
        }
        psk_return_names = set(TLS_PSK_COLUMNS.values()) | {
            "isEnabled",
            "IsEnabled",
            "is_enabled",
            "active",
            "Active",
            "cipher_suite",
            "Cipher_Suite",
            "tlsCipherSuite",
            "TLSCipherSuite",
            "tls_cipher_suite",
            "suite",
            "Suite",
            "secret",
            "Secret",
            "pskSecret",
            "PSKSecret",
            "psk_secret",
            "pskValue",
            "PSKValue",
            "psk_value",
            "preSharedKey",
            "PreSharedKey",
            "pre_shared_key",
            "keyMaterial",
            "KeyMaterial",
            "key_material",
        }
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            required_any_return_names=psk_return_names if _is_tcgstorageapi_getpskentry(event) else set(),
            expected_return_min_length=(
                1
                if _is_tcgstorageapi_getpskentry(event) and _output_return_values(event.raw) is not None
                else None
            ),
            forbid_return_bool_literal=_is_tcgstorageapi_getpskentry(event),
            reason="Authorized TLS_PSK_Key Get is allowed and tracked PSK metadata cells must match",
            confidence="high" if expected_cells else "medium",
        )
    if symbol.startswith("ACE_"):
        if event.columns and event.columns <= PUBLIC_COMMON_NAME_COLUMNS:
            return ExpectedResponse({SUCCESS}, reason=f"{symbol} UID/CommonName Get is permitted by ACE_Anybody_Get_CommonName", confidence="high")
        if not _has_authority(state, "Admins") and not _ace_satisfied(state, "ACE_00038000"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{symbol} Get requires Admins", confidence="medium")
        expected_cells = _ace_expected_cells(state, event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_cells=expected_cells,
            reason=f"Authorized {symbol} Get is allowed and known ACE preconfiguration cells must match",
            confidence="high" if expected_cells else "medium",
        )
    return ExpectedResponse({SUCCESS}, reason="Generic Get is permitted in an open session", confidence="medium")


def _ace_expected_cells(state: State, event: Event) -> dict[int, Any]:
    requested = event.columns or {ACE_BOOLEAN_EXPR_COLUMN, ACE_COLUMNS_COLUMN}
    symbol = event.invoking_symbol
    row = _known_ace_row(state.session.sp, symbol)
    configured_expression = state.ace_expressions.get(_ace_key(state, symbol))
    if not row and configured_expression is None:
        return {}
    expected: dict[int, Any] = {}
    if ACE_BOOLEAN_EXPR_COLUMN in requested:
        expected[ACE_BOOLEAN_EXPR_COLUMN] = configured_expression if configured_expression is not None else row["expr"]
    if row and ACE_COLUMNS_COLUMN in requested:
        expected[ACE_COLUMNS_COLUMN] = row["columns"]
    return expected


def _accesscontrol_expected_cells(event: Event) -> dict[int, Any]:
    requested = event.columns
    logging_columns = {
        ACCESS_CONTROL_LOG_COLUMN,
        ACCESS_CONTROL_ADD_ACE_LOG_COLUMN,
        ACCESS_CONTROL_REMOVE_ACE_LOG_COLUMN,
        ACCESS_CONTROL_GET_ACL_LOG_COLUMN,
        ACCESS_CONTROL_DELETE_METHOD_LOG_COLUMN,
        ACCESS_CONTROL_LOGTO_COLUMN,
    }
    suffix = event.invoking_symbol.removeprefix("AccessControl_").upper()
    identity = _accesscontrol_identity_for_suffix(suffix)
    if identity is not None:
        expected: dict[int, Any] = {}
        invoking_id, method_id = identity
        if not requested or 1 in requested:
            expected[1] = invoking_id
        if not requested or 2 in requested:
            expected[2] = method_id
        if requested and not (requested & logging_columns):
            return expected
        for column in (
            ACCESS_CONTROL_LOG_COLUMN,
            ACCESS_CONTROL_ADD_ACE_LOG_COLUMN,
            ACCESS_CONTROL_REMOVE_ACE_LOG_COLUMN,
            ACCESS_CONTROL_GET_ACL_LOG_COLUMN,
            ACCESS_CONTROL_DELETE_METHOD_LOG_COLUMN,
        ):
            if not requested or column in requested:
                expected[column] = _accesscontrol_default_log_for_suffix(suffix) if column == ACCESS_CONTROL_LOG_COLUMN else ""
        if not requested or ACCESS_CONTROL_LOGTO_COLUMN in requested:
            expected[ACCESS_CONTROL_LOGTO_COLUMN] = ""
        return expected
    return {}


def _accesscontrol_default_log_for_suffix(suffix: str) -> str:
    if re.fullmatch(r"[0-9A-F]{8}", suffix):
        value = int(suffix, 16)
        if 0x0003F000 <= value <= 0x0003F7FF:
            return "LogAlways"
    return ""


def _accesscontrol_identity_for_suffix(suffix: str) -> tuple[str, str] | None:
    static_rows = {
        "0003F800": ("00 00 08 03 00 00 00 01", "Set"),  # MBRControl Set
        "0003F801": ("00 00 08 03 00 00 00 01", "Get"),  # MBRControl Get
        "0003FC00": ("00 00 10 01 00 00 00 00", "Get"),  # DataStore Get
        "0003FC01": ("00 00 10 01 00 00 00 00", "Set"),  # DataStore Set
    }
    if suffix in static_rows:
        return static_rows[suffix]
    if not re.fullmatch(r"[0-9A-F]{8}", suffix):
        return None
    value = int(suffix, 16)
    cpin_user = value - 0x0003A800
    if 1 <= cpin_user <= 8:
        return (f"00 00 00 0B 00 03 {cpin_user >> 8:02X} {cpin_user & 0xFF:02X}", "Set")
    if value == 0x0003B000:
        return ("00 00 08 05 00 00 00 01", "GenKey")
    if value == 0x0003B800:
        return ("00 00 08 06 00 00 00 01", "GenKey")
    locking_set_range = value - 0x0003F000
    if 0 <= locking_set_range <= 0x7FF:
        if locking_set_range == 0:
            return ("00 00 08 02 00 00 00 01", "Set")
        return (f"00 00 08 02 00 03 {locking_set_range >> 8:02X} {locking_set_range & 0xFF:02X}", "Set")
    kaes_128_range = value - 0x0003B000
    if 1 <= kaes_128_range <= 8:
        return (f"00 00 08 05 00 03 {kaes_128_range >> 8:02X} {kaes_128_range & 0xFF:02X}", "GenKey")
    kaes_256_range = value - 0x0003B800
    if 1 <= kaes_256_range <= 8:
        return (f"00 00 08 06 00 03 {kaes_256_range >> 8:02X} {kaes_256_range & 0xFF:02X}", "GenKey")
    if 0x00038000 <= value <= 0x00038FFF:
        return (f"00 00 00 08 00 03 {value >> 8 & 0xFF:02X} {value & 0xFF:02X}", "Get")
    if 0x00039000 <= value <= 0x0003FFFF:
        return (f"00 00 00 08 00 03 {value >> 8 & 0xFF:02X} {value & 0xFF:02X}", "Set")
    if 0x00044000 <= value <= 0x00044FFF:
        return (f"00 00 00 08 00 04 {value >> 8 & 0xFF:02X} {value & 0xFF:02X}", "Set")
    return None


def _secretprotect_expected_cells(event: Event) -> dict[int, Any]:
    match = re.fullmatch(r"SecretProtect_(\d+)", event.invoking_symbol)
    if not match:
        return {}
    row_index = int(match.group(1))
    table_by_row = {
        0x1D: "0000000100000805",  # Table_K_AES_128
        0x1E: "0000000100000806",  # Table_K_AES_256
    }
    table_uid = table_by_row.get(row_index)
    if table_uid is None:
        return {}
    requested = event.columns or {1, 2}
    expected: dict[int, Any] = {}
    if 1 in requested:
        expected[1] = table_uid
    if 2 in requested:
        expected[2] = K_AES_KEY_COLUMN
    return expected


def _known_ace_row(sp: str | None, symbol: str) -> dict[str, Any] | None:
    suffix = symbol.removeprefix("ACE_")
    shared = {
        "00000001": ("Anybody", {"All"}),
        "00000002": ("Admins", {"All"}),
    }
    admin_sp = {
        "00030001": ("SID", {"Enabled"}),
        "00008C02": ("Admins OR SID", {"UID", "CharSet", "TryLimit", "Tries", "Persistence"}),
        "00008C03": ("SID", {"PIN"}),
        "00008C04": ("Anybody", {"UID", "PIN"}),
        "0003A001": ("Admins OR SID", {"PIN"}),
        "00030003": ("SID", {"ProgrammaticResetEnable"}),
        "00030002": ("SID", {"All"}),
        "00050001": ("Admins OR SID", {"ActiveDataRemovalMechanism"}),
    }
    locking_sp = {
        "00000003": ("Anybody", {"UID", "CommonName"}),
        "00000004": ("Admins", {"CommonName"}),
        "00038000": ("Admins", {"All"}),
        "00038001": ("Admins", {"BooleanExpr"}),
        "00039000": ("Admins", {"All"}),
        "00039001": ("Admins", {"Enabled"}),
        "00044001": ("Admins", {"CommonName"}),
        "0003A000": ("Admins", {"UID", "CharSet", "TryLimit", "Tries", "Persistence"}),
        "0003A001": ("Admins", {"PIN"}),
        "0003A801": ("Admins OR User1", {"PIN"}),
        "0003BFFF": ("Anybody", {"Mode"}),
        "0003B000": ("Admins", {"All"}),
        "0003B001": ("Admins", {"All"}),
        "0003B800": ("Admins", {"All"}),
        "0003B801": ("Admins", {"All"}),
        "0003D000": ("Admins", {"RangeStart", "RangeLength", "ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset", "ActiveKey"}),
        "0003D001": ("Admins", {"RangeStart", "RangeLength", "ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset", "ActiveKey"}),
        "0003E000": ("Admins", {"ReadLocked"}),
        "0003E001": ("Admins", {"ReadLocked"}),
        "0003E800": ("Admins", {"WriteLocked"}),
        "0003E801": ("Admins", {"WriteLocked"}),
        "0003F000": ("Admins", {"ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset"}),
        "0003F001": ("Admins", {"RangeStart", "RangeLength", "ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset"}),
        "0003F800": ("Admins", {"Enable", "Done", "DoneOnReset"}),
        "0003F801": ("Admins", {"Done", "DoneOnReset"}),
        "0003FC00": ("Admins", {"All"}),
        "0003FC01": ("Admins", {"All"}),
    }
    source = dict(shared)
    if sp == "AdminSP":
        source.update(admin_sp)
    elif sp == "LockingSP":
        source.update(locking_sp)
        numeric_suffix = int(suffix, 16) if re.fullmatch(r"[0-9A-Fa-f]{8}", suffix) else None
        if numeric_suffix is not None:
            if 0x0003B001 <= numeric_suffix <= 0x0003B7FF:
                return {"expr": _ace_expression_from_value("Admins"), "columns": {"All"}}
            if 0x0003B801 <= numeric_suffix <= 0x0003BEFF:
                return {"expr": _ace_expression_from_value("Admins"), "columns": {"All"}}
            if 0x0003D001 <= numeric_suffix <= 0x0003D7FF:
                return {
                    "expr": _ace_expression_from_value("Admins"),
                    "columns": {"RangeStart", "RangeLength", "ReadLockEnabled", "WriteLockEnabled", "ReadLocked", "WriteLocked", "LockOnReset", "ActiveKey"},
                }
            if 0x0003E001 <= numeric_suffix <= 0x0003E7FF:
                return {"expr": _ace_expression_from_value("Admins"), "columns": {"ReadLocked"}}
            if 0x0003E801 <= numeric_suffix <= 0x0003EFFF:
                return {"expr": _ace_expression_from_value("Admins"), "columns": {"WriteLocked"}}
        if suffix.startswith("0003A8"):
            user_index = int(suffix[-4:], 16) - 0xA800
            if user_index > 0:
                return {"expr": _ace_expression_from_value(f"Admins OR User{user_index}"), "columns": {"PIN"}}
        if suffix.startswith("000440"):
            user_index = int(suffix[-4:], 16) - 0x4000
            if user_index > 0:
                return {"expr": _ace_expression_from_value("Admins"), "columns": {"CommonName"}}
    if suffix not in source:
        return None
    expression, columns = source[suffix]
    return {"expr": _ace_expression_from_value(expression), "columns": columns}


def _table_descriptor_expected_cells(
    state: State,
    event: Event,
) -> tuple[dict[int, Any], dict[int, Any], dict[int, int], dict[int, int], tuple[tuple[int, int], ...]]:
    requested = event.columns
    if not requested:
        return {}, {}, {}, {}, ()
    expected: dict[int, Any] = {}
    optional: dict[int, Any] = {}
    minimum: dict[int, int] = {}
    maximum: dict[int, int] = {}
    cell_lte: list[tuple[int, int]] = []
    if event.invoking_symbol in {"Table_MBR", "Table_DataStore"} and 4 in requested:
        expected[4] = "Byte"
    if _byte_table_symbol_from_descriptor(event.invoking_symbol) is not None and 5 in requested:
        optional[5] = "0000000000000000"
    if _byte_table_symbol_from_descriptor(event.invoking_symbol) is not None and 6 in requested:
        optional[6] = 1
    if event.invoking_symbol == "Table_MBR" and 7 in requested:
        minimum[7] = 0x08000000
    if event.invoking_symbol == "Table_DataStore" and 7 in requested:
        minimum[7] = 0x00A00000
        if state.expected_datastore_rows is not None:
            expected[7] = state.expected_datastore_rows
    if event.invoking_symbol.startswith("Table_") and _byte_table_symbol_from_descriptor(event.invoking_symbol) is None:
        for column in (TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN, TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN):
            if column in requested:
                expected[column] = 0
    elif _byte_table_symbol_from_descriptor(event.invoking_symbol) is not None:
        if TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN in requested:
            minimum[TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN] = 1
            maximum[TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN] = 8192
        if {
            TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN,
            TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN,
        } <= requested:
            cell_lte.append((TABLE_MANDATORY_WRITE_GRANULARITY_COLUMN, TABLE_RECOMMENDED_ACCESS_GRANULARITY_COLUMN))
    return expected, optional, minimum, maximum, tuple(cell_lte)


def _cpin_expected_cells(state: State, event: Event) -> dict[int, Any]:
    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner is None:
        return {}
    requested = event.columns
    expected: dict[int, Any] = {}
    if (not requested or CPIN_TRY_LIMIT_COLUMN in requested) and owner in state.pin_try_limits:
        expected[CPIN_TRY_LIMIT_COLUMN] = state.pin_try_limits[owner]
    if (not requested or CPIN_TRIES_COLUMN in requested) and owner in state.pin_tries:
        expected[CPIN_TRIES_COLUMN] = state.pin_tries[owner]
    if (not requested or CPIN_PERSISTENCE_COLUMN in requested) and owner in state.pin_persistence:
        expected[CPIN_PERSISTENCE_COLUMN] = state.pin_persistence[owner]
    if (not requested or MIN_PIN_COLUMN in requested) and owner in state.pin_min_lengths:
        expected[MIN_PIN_COLUMN] = state.pin_min_lengths[owner]
    return expected


def _cpin_get_column_types(columns: set[int]) -> dict[int, str]:
    requested = columns or {CPIN_TRY_LIMIT_COLUMN, CPIN_TRIES_COLUMN}
    column_types: dict[int, str] = {}
    if CPIN_TRY_LIMIT_COLUMN in requested:
        column_types[CPIN_TRY_LIMIT_COLUMN] = "uinteger"
    if CPIN_TRIES_COLUMN in requested:
        column_types[CPIN_TRIES_COLUMN] = "uinteger"
    return column_types


def _authority_expected_cells(state: State, event: Event) -> dict[int, Any]:
    authority = _authority_by_object(event.invoking_symbol)
    if authority is None:
        return {}
    requested = event.columns
    expected: dict[int, Any] = {}
    static_cells = _authority_static_cells(authority)
    for column, value in static_cells.items():
        if not requested or column in requested:
            expected[column] = value
    if requested == {8} and _authority_present_certificate_default(authority) is not None:
        expected[8] = _authority_present_certificate_default(authority)
    if (not requested or 15 in requested) and authority in state.authority_limits:
        expected[15] = state.authority_limits[authority]
    if (not requested or 16 in requested) and authority in state.authority_uses:
        expected[16] = state.authority_uses[authority]
    return expected


def _authority_get_column_types(columns: set[int]) -> dict[int, str]:
    requested = columns or {15, 16}
    column_types: dict[int, str] = {}
    if 15 in requested:
        column_types[15] = "uinteger"
    if 16 in requested:
        column_types[16] = "uinteger"
    return column_types


def _authority_static_cells(authority: str) -> dict[int, Any]:
    defaults: dict[str, dict[int, Any]] = {
        "Anybody": {3: False, 4: "", 9: "Sign"},
        "Admins": {3: True, 4: ""},
        "Makers": {3: True, 4: ""},
        "Users": {3: True, 4: ""},
        "MakerSymK": {3: False, 4: "Makers", 9: "SymK"},
        "MakerPuK": {3: False, 4: "Makers", 9: "Sign"},
        "SID": {3: False, 4: "", 9: "Password"},
        "TPerSign": {3: False, 4: "", 9: "TPerSign"},
        "TPerExch": {3: False, 4: "", 9: "TPerExchange"},
        "AdminExch": {3: False, 4: "Admins", 9: "Exchange"},
    }
    if re.fullmatch(r"Admin\d+", authority):
        return {3: False, 4: "Admins", 9: "Password"}
    if authority == "User1":
        return {3: False, 4: "", 9: "Password"}
    if re.fullmatch(r"User\d+", authority):
        return {3: False, 4: "Users", 9: "Password"}
    return defaults.get(authority, {})


def _authority_present_certificate_default(authority: str) -> bool | None:
    if authority in {
        "Anybody",
        "Admins",
        "Makers",
        "Users",
        "MakerSymK",
        "MakerPuK",
        "SID",
        "TPerSign",
        "TPerExch",
        "AdminExch",
    }:
        return False
    if re.fullmatch(r"(Admin|User)\d+", authority):
        return False
    return None


def _mbrcontrol_expected_cells(state: State, event: Event) -> dict[int, Any]:
    returned_payload = _output_return_values(event.raw)
    function_alias = _function_alias(_function_name(_input_section(event.raw)))
    wrapper_getter = function_alias in {
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
    }
    if (
        returned_payload in (None, [], (), {})
        and not wrapper_getter
        and not any(field in state.mbr for field in ("Enabled", "Done", "DoneOnReset"))
    ):
        return {}
    cells: dict[int, Any] = {
        1: False,
        2: False,
        3: "PowerCycle",
    }
    for field, column in (("Enabled", 1), ("Done", 2), ("DoneOnReset", 3)):
        if field in state.mbr:
            cells[column] = state.mbr[field]
    requested = event.columns or set(cells)
    return {column: value for column, value in cells.items() if column in requested}


def _methodid_expected_cells(event: Event) -> dict[int, Any]:
    method_name = _method_by_uid(event.invoking_uid)
    if method_name is None:
        return {}
    requested = event.columns or {1}
    if 1 not in requested:
        return {}
    return {1: method_name}


def _expected_create_row(state: State, event: Event) -> ExpectedResponse:
    common = _table_method_common_failure(state, event, "CreateRow")
    if common is not None:
        return common
    if _created_table_for_event(state, event) is not None:
        if not event.values:
            return ExpectedResponse({INVALID_PARAMETER}, reason="CreateRow requires row values", confidence="high")
        declared_columns = state.created_table_columns.get(event.invoking_uid, set())
        if declared_columns and set(event.values) != declared_columns:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL, INSUFFICIENT_ROWS},
                forbidden_statuses={SUCCESS},
                reason="CreateRow row_data must supply exactly the columns declared for the created object table",
                confidence="high",
            )
        if _created_table_unique_conflict(state, event.invoking_uid, event.values):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL, INSUFFICIENT_ROWS},
                forbidden_statuses={SUCCESS},
                reason="CreateRow unique column value combination already exists in the created object table",
                confidence="high",
            )
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateRow requires Admins authority", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_uid_list=True,
            expected_return_uid_list_length=1,
            reason="Authorized CreateRow is allowed on this created object table and returns the created row UID",
            confidence="high",
        )
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateRow is not permitted on MethodID or AccessControl tables", confidence="high")
    if _cec_family_from_table_symbol(event.invoking_symbol) is not None:
        if not event.values:
            return ExpectedResponse({INVALID_PARAMETER}, reason="CreateRow requires row values", confidence="high")
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateRow requires Admins authority", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_uid_list=True,
            expected_return_uid_list_length=1,
            forbidden_return_uid_ref_prefixes={"ACE_"},
            reason="Authorized C_EC CreateRow may omit documented curve parameters because the TPer supplies their defaults",
            confidence="high",
        )
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="Opal row creation is only modeled for Locking range rows", confidence="medium")
    if not event.values:
        return ExpectedResponse({INVALID_PARAMETER}, reason="CreateRow requires row values", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateRow requires Admins authority", confidence="high")

    if event.invoking_symbol in {"LockingTable", "Table_Locking"}:
        if state.session.sp != "LockingSP":
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Locking rows belong to LockingSP", confidence="high")
        if _global_reencrypt_busy(state):
            return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason="Global Range re-encryption blocks Locking CreateRow", confidence="high")
        if not {3, 4}.issubset(event.values):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow requires RangeStart and RangeLength", confidence="high")
        if _range_values_invalid_for_geometry(state, None, event.values, creating=True):
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow violates range geometry or alignment", confidence="high")
        start = _parse_int(event.values.get(3))
        length = _parse_int(event.values.get(4))
        if start is None or length is None:
            return ExpectedResponse({INVALID_PARAMETER}, reason="Locking CreateRow range values must be numeric", confidence="high")
        max_ranges = _parse_int(state.locking_info.get("MaxRanges"))
        returned_range_id = _returned_locking_range_id(event)
        if returned_range_id is None and _return_payload_has_object_ref(_output_return_values(event.raw)):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Locking CreateRow success must return a Locking range row UID, not an unrelated object UID",
                confidence="high",
            )
        if max_ranges is not None and returned_range_id is not None and returned_range_id > max_ranges:
            return ExpectedResponse(
                {INSUFFICIENT_ROWS, INSUFFICIENT_SPACE, INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Locking CreateRow cannot return a range id above observed LockingInfo.MaxRanges",
                confidence="high",
            )
        if max_ranges is not None and len([range_id for range_id in state.ranges if range_id != 0]) >= max_ranges:
            return ExpectedResponse({INSUFFICIENT_ROWS, INSUFFICIENT_SPACE, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Locking CreateRow exceeds MaxRanges", confidence="medium")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_uid_list=True,
            expected_return_uid_list_length=1,
            reason="Authorized Locking CreateRow is allowed and returns the created Locking range UID",
            confidence="high",
        )

    return ExpectedResponse(
        {SUCCESS},
        expected_return_uid_list=True,
        expected_return_uid_list_length=1,
        reason="Authorized CreateRow is allowed on this object table and returns the created row UID",
        confidence="medium",
    )


def _expected_delete_row(state: State, event: Event) -> ExpectedResponse:
    common = _table_method_common_failure(state, event, "DeleteRow")
    if common is not None:
        return common
    if _created_table_for_event(state, event) is not None:
        if not _row_object_refs(event) and not _row_uids(event):
            return ExpectedResponse({INVALID_PARAMETER}, reason="DeleteRow requires row UIDs", confidence="high")
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteRow requires Admins authority", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized DeleteRow returns an empty list on this created object table",
            confidence="medium",
        )
    if event.invoking_symbol in {"MethodIDTable", "Table_MethodID", "AccessControlTable", "Table_AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="DeleteRow is not permitted on MethodID or AccessControl tables", confidence="high")
    if event.invoking_symbol not in {"LockingTable", "Table_Locking"}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="Opal row deletion is only modeled for Locking range rows", confidence="medium")
    row_refs = _row_object_refs(event)
    if not row_refs and not _row_uids(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="DeleteRow requires row UIDs", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteRow requires Admins authority", confidence="high")
    if event.invoking_symbol in {"LockingTable", "Table_Locking"}:
        if _global_reencrypt_busy(state):
            return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason="Global Range re-encryption blocks Locking DeleteRow", confidence="high")
        refs = row_refs or [(_object_by_uid(uid), uid) for uid in _row_uids(event)]
        for symbol, uid in refs:
            range_id = _range_id_from_symbol(symbol) if symbol else _range_id_from_delete_uid(uid)
            if range_id is None:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Locking DeleteRow must reference Locking range rows", confidence="high")
            if range_id == 0:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GlobalRange cannot be deleted", confidence="high")
            range_support = _range_id_support_state(state, range_id)
            if range_support is False:
                return ExpectedResponse(
                    {INVALID_PARAMETER, FAIL},
                    forbidden_statuses={SUCCESS},
                    reason="Locking DeleteRow targets a range id outside observed LockingInfo.MaxRanges support",
                    confidence="high",
                )
            if range_id is not None and _range_reencrypt_active(_range(state, range_id)):
                return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason="ACTIVE re-encryption blocks deleting this Locking object", confidence="high")
            if range_support is None:
                return ExpectedResponse(
                    {SUCCESS, INVALID_PARAMETER, FAIL},
                    expected_return_length=0,
                    forbid_return_bool_literal=_raw_tcg_method_event(event),
                    allow_status_alternatives=True,
                    reason="Authorized DeleteRow succeeds if the optional range exists, but unobserved Range9+ may also be absent",
                    confidence="medium",
                )
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason="Authorized DeleteRow returns an empty list on this object table",
        confidence="medium",
    )


def _expected_delete(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Delete object does not belong to current SP", confidence="medium")
    if _created_object_outside_session(state, event.invoking_uid):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER},
            forbidden_statuses={SUCCESS},
            reason="Delete target is a dynamically created object in a different SP security domain",
            confidence="high",
        )
    if event.invoking_uid in state.created_table_row_values_by_uid:
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete of a created row object requires Admins authority", confidence="medium")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized Delete of a created row object deletes the row and its associated AccessControl rows",
            confidence="medium",
        )
    if event.invoking_uid in state.created_table_descriptor_uids:
        if not _has_authority(state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete of a created table descriptor requires Admins authority", confidence="medium")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized Delete of a table descriptor deletes the associated created table and returns an empty list",
            confidence="medium",
        )
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="Delete is modeled for deletable non-global Locking range rows",
            confidence="medium",
        )
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Delete requires Admins authority", confidence="high")
    range_support = _range_id_support_state(state, range_id)
    if range_support is False:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Delete targets a Locking range id outside observed LockingInfo.MaxRanges support",
            confidence="high",
        )
    if _global_reencrypt_busy(state):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason="Global Range re-encryption blocks deleting any Locking object", confidence="high")
    if _range_reencrypt_active(_range(state, range_id)):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason="ACTIVE re-encryption blocks deleting this Locking object", confidence="high")
    if range_support is None:
        return ExpectedResponse(
            {SUCCESS, INVALID_PARAMETER, FAIL},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            allow_status_alternatives=True,
            reason="Authorized Delete succeeds if the optional range exists, but unobserved Range9+ may also be absent",
            confidence="medium",
        )
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason="Authorized Delete removes the Locking range row and returns an empty list",
        confidence="medium",
    )


def _expected_delete_sp(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires a read-write session", confidence="high")
    if state.session.sp is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="DeleteSP must be invoked within an SP session", confidence="high")
    if event.invoking_symbol not in {"", "ThisSP", state.session.sp}:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="DeleteSP is an SP method invoked on ThisSP/current SP",
            confidence="high",
        )
    if state.session.sp == "AdminSP":
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason="AdminSP deletion through DeleteSP is not modeled as an Opal owner operation",
            confidence="medium",
        )
    if state.session.sp in state.deleted_sps:
        return ExpectedResponse({FAIL, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="DeleteSP target SP is already deleted", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteSP requires normal Admins access control", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        reason="Authorized DeleteSP returns an empty list and schedules the current SP for deletion when the session closes",
        confidence="high",
    )


def _expected_create_table(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires a read-write session", confidence="high")
    if state.session.sp is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable must be invoked within an SP session", confidence="high")
    if event.invoking_symbol not in {"", "ThisSP", state.session.sp}:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable is an SP method invoked on ThisSP/current SP", confidence="high")
    if not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateTable requires normal Admins access control", confidence="high")

    required_args = [
        _create_table_arg(event, 0, "NewTableName", "Name", "TableName"),
        _create_table_arg(event, 1, "Kind", "TableKind"),
        _create_table_arg(event, 2, "GetSetACL", "GetSetAcl", "ACL", "AccessControlList"),
        _create_table_arg(event, 3, "Columns"),
        _create_table_arg(event, 4, "MinSize", "MinimumSize"),
    ]
    if not all(found for found, _ in required_args):
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="CreateTable requires NewTableName, Kind, GetSetACL, Columns, and MinSize",
            confidence="high",
        )

    (_, name_value), (_, kind_value), (_, _acl_value), (_, columns_value), (_, min_size_value) = required_args
    name = _create_table_name_text(name_value)
    if not name:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable NewTableName must be non-empty", confidence="high")
    if len(name.encode("utf-8")) > 32:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable NewTableName must be at most 32 bytes", confidence="high")
    kind = _create_table_kind(kind_value)
    if kind is None:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable Kind must be Object or Byte", confidence="high")

    if _uinteger_arg_invalid(min_size_value):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable MinSize must be a non-negative integer", confidence="high")
    min_size = _parse_int(min_size_value)

    found_max, max_size_value = _create_table_arg(event, 5, "MaxSize", "MaximumSize")
    found_hint, hint_size_value = _create_table_arg(event, 6, "HintSize")
    if kind == "byte" and (found_max or found_hint):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Byte table CreateTable cannot include MaxSize or HintSize", confidence="high")
    if kind == "byte" and not _create_table_columns_empty(columns_value):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Byte table CreateTable requires an empty Columns list", confidence="high")

    max_size: int | None = None
    if found_max:
        if _uinteger_arg_invalid(max_size_value):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable MaxSize must be an unsigned integer", confidence="high")
        max_size = _parse_int(max_size_value)
        if max_size is None or max_size < min_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable MaxSize must be at least MinSize", confidence="high")
    if found_hint:
        if _uinteger_arg_invalid(hint_size_value):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable HintSize must be an unsigned integer", confidence="medium")
        hint_size = _parse_int(hint_size_value)
        if hint_size is None or hint_size < 0:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable HintSize must be an unsigned integer", confidence="medium")

    found_common, common_value = _create_table_arg(event, 7, "CommonName")
    common_name = _create_table_name_text(common_value) if found_common else ""
    if len(common_name.encode("utf-8")) > 32:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable CommonName must be at most 32 bytes", confidence="high")
    key = (state.session.sp, name, common_name)
    if key in state.created_table_names:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateTable Name/CommonName combination already exists", confidence="high")

    return ExpectedResponse(
        {SUCCESS},
        forbidden_statuses={FAIL},
        expected_return_length=2,
        expected_return_min_values={("Rows", 1): min_size},
        expected_return_max_values={("Rows", 1): max_size} if max_size is not None else {},
        reason="Authorized CreateTable parameters satisfy Core table creation constraints and successful CreateTable returns UID and Rows",
        confidence="medium",
    )


def _expected_set(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Set requires a read-write session", confidence="high")
    if _invoking_object_definitely_absent(event):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Set fails if the table/object does not exist",
            confidence="high",
        )
    set_auth_state = _wrapper_scoped_authority_state(
        state,
        event,
        "setrange",
        "readlock",
        "writelock",
        "readunlock",
        "writeunlock",
        "changepin",
        "changepincode",
        "changepassword",
        "changepasscode",
        "setpin",
        "setpincode",
        "setpassword",
        "setpasscode",
        "updatepin",
        "updatepincode",
        "updatepassword",
        "updatepasscode",
        "setcredential",
        "updatecredential",
        "putpin",
        "putpincode",
        "putpassword",
        "putpasscode",
        "putcredential",
        "putuserpassword",
        "putusercredential",
        "setminpinlength",
        "activateAuthority",
        "activateUser",
        "activateauthority",
        "activateuser",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "enableauthority",
        "setauthorityenabled",
        "setauthoritystate",
        "setuserenabled",
        "setuserenable",
        "setuserstate",
        "setport",
        "setpskentry",
        "setpsk",
        "configurepsk",
        "configurepskentry",
        "putpsk",
        "putpskentry",
        "storepsk",
        "storepskentry",
        "enablepsk",
        "updatepsk",
        "updatepskentry",
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
        "setpresharedkey",
        "setpresharedkeyentry",
        "writepresharedkey",
        "updatepresharedkey",
        "putpresharedkey",
        "storepresharedkey",
        "savepresharedkey",
        "importpresharedkey",
        "restorepresharedkey",
    ) or state
    if not _session_allows_object(set_auth_state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Set object does not belong to current SP", confidence="medium")
    if _created_object_outside_session(state, event.invoking_uid):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER},
            forbidden_statuses={SUCCESS},
            reason="Set target is a dynamically created object in a different SP security domain",
            confidence="high",
        )
    event, where_error = _set_effective_event(event)
    if where_error is not None:
        return where_error
    set_auth_state = _wrapper_scoped_authority_state(
        state,
        event,
        "setrange",
        "readlock",
        "writelock",
        "readunlock",
        "writeunlock",
        "changepin",
        "changepincode",
        "changepassword",
        "changepasscode",
        "setpin",
        "setpincode",
        "setpassword",
        "setpasscode",
        "updatepin",
        "updatepincode",
        "updatepassword",
        "updatepasscode",
        "setcredential",
        "updatecredential",
        "putpin",
        "putpincode",
        "putpassword",
        "putpasscode",
        "putcredential",
        "putuserpassword",
        "putusercredential",
        "setminpinlength",
        "activateAuthority",
        "activateUser",
        "activateauthority",
        "activateuser",
        "deactivateAuthority",
        "deactivateUser",
        "deactivateauthority",
        "deactivateuser",
        "enableauthority",
        "setauthorityenabled",
        "setauthoritystate",
        "setuserenabled",
        "setuserenable",
        "setuserstate",
        "setport",
        "setpskentry",
        "setpsk",
        "configurepsk",
        "configurepskentry",
        "putpsk",
        "putpskentry",
        "storepsk",
        "storepskentry",
        "enablepsk",
        "updatepsk",
        "updatepskentry",
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
        "setpresharedkey",
        "setpresharedkeyentry",
        "writepresharedkey",
        "updatepresharedkey",
        "putpresharedkey",
        "storepresharedkey",
        "savepresharedkey",
        "importpresharedkey",
        "restorepresharedkey",
    ) or set_auth_state
    if not _session_allows_object(set_auth_state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Set target row does not belong to current SP", confidence="high")
    if _created_object_outside_session(state, event.invoking_uid):
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER},
            forbidden_statuses={SUCCESS},
            reason="Set target row is a dynamically created object in a different SP security domain",
            confidence="high",
        )
    wrapper_datastore_authorized = _datastore_wrapper_access_authorized(state, event, write=True) if event.invoking_symbol.startswith("DataStore") else None
    if wrapper_datastore_authorized is False:
        return ExpectedResponse(
            {NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Wrapper writeData DataStore Set authorization is evaluated under the wrapper authAs authority",
            confidence="high",
        )
    required = _set_required_authorities(set_auth_state, event)
    if (
        wrapper_datastore_authorized is not True
        and not _has_any_authority(set_auth_state, required)
        and not _master_authorizes_set(set_auth_state, event)
        and not _ace_authorizes_set(set_auth_state, event)
    ):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"Set requires one of {sorted(required)}", confidence="high")
    if _as_bool(_mapping_value(event.optional, "__InvalidTcgApiUserArgument")):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="TCGstorageAPI access wrapper requires a user identifier with digits", confidence="high")
    if _as_bool(_mapping_value(event.optional, "__MissingRequiredCipherSuite")):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="TCGstorageAPI setPskEntry requires CipherSuite", confidence="high")
    if _as_bool(_mapping_value(event.optional, "__RequireAllAuthAsValid")):
        for authority, credential in _authas_pairs(event.required, event.optional, _method_raw_args(event)):
            if authority in {None, "Anybody", "Admins", "Users"}:
                continue
            if not credential:
                return ExpectedResponse({NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="Wrapper-level Set requires each authAs credential to be present", confidence="high")
            if _authority_locked_out(state, authority):
                return ExpectedResponse({NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="Wrapper-level Set failed a secondary authAs authority state check", confidence="high")
            known_pin = state.pins.get(authority)
            if known_pin is not None and _credential_text(credential) != known_pin:
                return ExpectedResponse({NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="Wrapper-level Set failed a secondary authAs credential check", confidence="high")
    if _set_values_omitted(event):
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Set without Values succeeds with no effect",
            confidence="high",
        )
    if _set_has_duplicate_value_columns(event):
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Set RowValues contains the same column multiple times",
            confidence="high",
        )
    range_id = _range_id_from_symbol(event.invoking_symbol)
    range_support: bool | None = True
    optional_absence_statuses: set[str] = set()
    if range_id is not None:
        range_support = _range_id_support_state(state, range_id)
        if range_support is False:
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="Locking range Set targets a range id outside observed LockingInfo.MaxRanges support",
                confidence="high",
            )
        optional_absence_statuses = {INVALID_PARAMETER, FAIL} if range_support is None else set()
    reencrypt_block = _reencrypt_blocks_set(state, event)
    if reencrypt_block is not None:
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, raw_tcg_exact_status=FAIL, reason=reencrypt_block, confidence="high")
    table_size_expectation = _expected_table_descriptor_size_set(state, event)
    if table_size_expectation is not None:
        return table_size_expectation
    if _invalid_set_values(state, event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="Set contains values disallowed by Opal table semantics", confidence="medium")
    optional_reset_support = False
    if event.invoking_symbol.startswith("Locking_") and 9 in event.values:
        reset_types = _reset_types(event.values[9])
        optional_reset_support = 1 in reset_types and 0 in reset_types and reset_types <= {0, 1, 3}
    if event.invoking_symbol == "MBRControl" and 3 in event.values:
        reset_types = _reset_types(event.values[3])
        optional_reset_support = 1 in reset_types and 0 in reset_types and reset_types <= {0, 1, 3}
    if optional_reset_support:
        return ExpectedResponse(
            {SUCCESS, INVALID_PARAMETER},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            allow_status_alternatives=True,
            reason="Opal requires reset-type lists {0} and {0,3}, while Hardware-containing {0,1} and {0,1,3} are optional TPer support",
            confidence="high",
        )
    return ExpectedResponse(
        {SUCCESS} | optional_absence_statuses,
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        allow_status_alternatives=range_support is None,
        reason="Authorized Set returns an empty list when the target row exists; unobserved Range9+ may also be absent",
        confidence="high" if range_support is not None else "medium",
    )


def _expected_table_descriptor_size_set(state: State, event: Event) -> ExpectedResponse | None:
    if not event.invoking_symbol.startswith("Table_"):
        return None
    columns = set(event.values)
    if not columns or not columns <= {11, 12}:
        return None

    table_uid = state.created_table_descriptor_uids.get(event.invoking_uid)
    min_size = state.created_table_min_sizes.get(table_uid or "")
    rows = state.created_table_allocated_rows.get(table_uid or "")

    requested_min = None
    if 11 in event.values:
        requested_min = _parse_int(event.values[11])
        if requested_min is None or requested_min < 0:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Table MinSize must be an unsigned integer", confidence="high")
        if min_size is not None and requested_min < min_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Table MinSize cannot be set lower than the recorded MinSize", confidence="high")

    if 12 in event.values:
        requested_max = _parse_int(event.values[12])
        if requested_max is None or requested_max < 0:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Table MaxSize must be an unsigned integer", confidence="high")
        effective_min_size = requested_min if requested_min is not None else min_size
        if requested_max != 0 and effective_min_size is not None and requested_max < effective_min_size:
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Table MaxSize below MinSize must fail with INVALID_PARAMETER", confidence="high")
        if requested_max != 0 and rows is not None and requested_max < rows:
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="Table MaxSize below current Rows must fail with INVALID_PARAMETER", confidence="high")

    return ExpectedResponse(
        {SUCCESS, INVALID_PARAMETER, FAIL},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        allow_status_alternatives=True,
        reason="Table descriptor MinSize and MaxSize are user-settable, but the TPer may reject changes",
        confidence="medium",
    )


def _expected_activate(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open or not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate requires an AdminSP read-write session", confidence="high")
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate operates through AdminSP", confidence="high")
    if event.invoking_symbol != "LockingSP":
        return ExpectedResponse({INVALID_PARAMETER}, reason="Activate must target a manufactured SP object such as LockingSP", confidence="high")
    if not _has_authority(state, "SID"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Activate requires SID authority", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason="Authorized LockingSP Activate is allowed",
        confidence="high",
    )


def _expected_genkey(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires a read-write session", confidence="high")
    auth_state = _wrapper_scoped_authority_state(
        state,
        event,
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
    ) or state
    if not _session_allows_object(auth_state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GenKey object does not belong to current SP", confidence="high")
    found_exponent, _ = _named_method_arg_value(event, "PublicExponent", "publicExponent")
    found_pin_length, pin_length_value = _named_method_arg_value(event, "PinLength", "pinLength", "PINLength")
    owner = _pin_owner_by_object(event.invoking_symbol)
    if owner:
        if owner == "MSID":
            return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED, FAIL}, forbidden_statuses={SUCCESS}, reason="C_PIN_MSID cannot be regenerated with GenKey", confidence="medium")
        if found_exponent:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PublicExponent is valid only for C_RSA GenKey", confidence="high")
        if found_pin_length and _uinteger_arg_invalid(pin_length_value):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="C_PIN GenKey PinLength must be a uinteger", confidence="high")
        pin_length = _parse_int(pin_length_value) if found_pin_length else 32
        if pin_length is None or pin_length > 32:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="C_PIN GenKey PinLength must be 0..32", confidence="high")
        required = _set_required_authorities(auth_state, Event(raw=event.raw, kind=event.kind, method="Set", invoking_symbol=event.invoking_symbol, invoking_uid=event.invoking_uid, values={PIN_COLUMN: ""}))
        if not _has_any_authority(auth_state, required):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"C_PIN GenKey requires one of {sorted(required)}", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized C_PIN GenKey returns an empty list",
            confidence="high",
        )

    if re.fullmatch(r"C_RSA_(1024|2048)", event.invoking_symbol or ""):
        if found_pin_length:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PinLength is valid only for C_PIN GenKey", confidence="high")
        if found_exponent:
            _, exponent_value = _named_method_arg_value(event, "PublicExponent", "publicExponent")
            if _uinteger_arg_invalid(exponent_value):
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="C_RSA GenKey PublicExponent must be a uinteger", confidence="high")
        if not _has_authority(auth_state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason="C_RSA GenKey requires Admins authority", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized C_RSA GenKey returns an empty list and may include PublicExponent",
            confidence="high",
        )

    if re.fullmatch(r"C_AES_(128|256)|C_HMAC_(160|256|384|512)|C_EC_(160|163|192|224|233|256|283|384|521)", event.invoking_symbol or ""):
        if found_pin_length:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PinLength is valid only for C_PIN GenKey", confidence="high")
        if found_exponent:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PublicExponent is valid only for C_RSA GenKey", confidence="high")
        if not _has_authority(auth_state, "Admins"):
            return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.invoking_symbol} GenKey requires Admins authority", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=0,
            forbid_return_bool_literal=_raw_tcg_method_event(event),
            reason="Authorized non-C_PIN credential GenKey returns an empty list",
            confidence="high",
        )

    if found_pin_length:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PinLength is valid only for C_PIN GenKey", confidence="high")
    if found_exponent:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="PublicExponent is valid only for C_RSA GenKey", confidence="high")
    if auth_state.session.sp != "LockingSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="K_AES GenKey key object belongs to LockingSP", confidence="high")
    if _range_id_from_key(event.invoking_symbol) is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="GenKey must target a K_AES range key or C_PIN credential", confidence="high")
    ace_symbol = _key_genkey_ace_symbol(event.invoking_symbol)
    if not _has_authority(auth_state, "Admins") and not (ace_symbol and _ace_satisfied(auth_state, ace_symbol)):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GenKey requires Admins authority", confidence="high")
    range_id = _range_id_from_key(event.invoking_symbol)
    range_support = _range_id_support_state(state, range_id)
    if range_support is False:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="K_AES GenKey targets a range key id outside observed LockingInfo.MaxRanges support",
            confidence="high",
        )
    optional_absence_statuses = {INVALID_PARAMETER, FAIL} if range_support is None else set()
    if range_id is not None and _range_reencrypt_busy(_range(state, range_id)):
        return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason="GenKey on a range key is blocked while ReEncryptState is not IDLE", confidence="high")
    return ExpectedResponse(
        {SUCCESS} | optional_absence_statuses,
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        allow_status_alternatives=range_support is None,
        reason="Authorized GenKey returns an empty list when the optional key row exists; unobserved Range9+ may also be absent",
        confidence="high" if range_support is not None else "medium",
    )


def _expected_get_package(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetPackage requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GetPackage object does not belong to current SP", confidence="high")
    if not _is_credential_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage must target a credential object", confidence="high")
    found_purpose, purpose = _named_method_arg_value(event, "Purpose")
    if not found_purpose:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage requires a Purpose parameter", confidence="high")
    if _empty_payload(purpose):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage Purpose must not be empty", confidence="high")
    if _package_credential_arg_invalid(event, "WrappingKey", "WrappingKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage WrappingKey must reference a credential", confidence="high")
    if _package_credential_arg_invalid(event, "SigningKey", "SigningKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="GetPackage SigningKey must reference a credential", confidence="high")
    required = _package_required_authorities(state, event)
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"GetPackage requires one of {sorted(required)}", confidence="high")
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    is_wrapper = isinstance(input_obj, dict) and _function_alias(_function_name(input_obj)) in {
        "getpackage",
        "getcredentialpackage",
        "getkeypackage",
        "exportpackage",
        "readpackage",
        "backuppackage",
        "dumppackage",
        "exportcredential",
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
        "readkeypackage",
        "backupkeypackage",
        "backupcredential",
        "backuppin",
        "backuppinpackage",
        "getpinpackage",
        "getcredentialbackup",
        "readcredentialbackup",
        "fetchcredentialbackup",
        "readkeybackup",
        "exportcredentialpackage",
        "readcredentialpackage",
        "backupcredentialpackage",
        "dumpcredentialpackage",
        "dumpkeypackage",
    }
    return ExpectedResponse(
        {SUCCESS},
        require_return_byte_payload=True,
        expected_return_min_length=1 if is_wrapper else None,
        reason="Authorized GetPackage retrieves credential material as a package byte payload",
        confidence="medium",
    )


def _expected_set_package(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="SetPackage requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="SetPackage requires a read-write session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="SetPackage object does not belong to current SP", confidence="high")
    if not _is_credential_symbol(event.invoking_symbol):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage must target a credential object", confidence="high")
    found_value, value = _named_method_arg_value(event, "Value", "Package")
    if not found_value or _empty_payload(value):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage requires a Value package", confidence="high")
    if _package_credential_arg_invalid(event, "WrappingKey", "WrappingKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage WrappingKey must reference a credential", confidence="high")
    if _package_credential_arg_invalid(event, "SigningKey", "SigningKeyUID"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="SetPackage SigningKey must reference a credential", confidence="high")
    required = _package_required_authorities(state, event)
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"SetPackage requires one of {sorted(required)}", confidence="high")
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    is_wrapper = isinstance(input_obj, dict) and _function_alias(_function_name(input_obj)) in {
        "setpackage",
        "setcredentialpackage",
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
        "setkeypackage",
    }
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=None if is_wrapper else 0,
        forbidden_return_bool=None if is_wrapper else True,
        reason="Authorized SetPackage updates credential material from a package and returns an empty list",
        confidence="medium",
    )


def _expected_erase(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires an open Enterprise/Locking session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires a read-write session", confidence="high")
    auth_state = _wrapper_scoped_authority_state(state, event, "erase") or state
    range_id = _range_id_from_symbol(event.invoking_symbol)
    if range_id is None or range_id == 0:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Erase must target a non-global Band/Locking range", confidence="high")
    if not _has_authority(auth_state, "EraseMaster"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Erase requires EraseMaster authority", confidence="high")
    return ExpectedResponse({SUCCESS}, reason="Authorized Erase invalidates the target band media", confidence="medium")


def _expected_sign(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Sign requires an open session", confidence="high")
    cellblock_error = _crypto_datastore_cellblock_access_error(state, event)
    if cellblock_error is not None:
        return cellblock_error
    if event.invoking_symbol != "TPerSign":
        invoking_symbol = event.invoking_name if event.invoking_name.startswith(("H_SHA_", "C_RSA_", "C_EC_")) else event.invoking_symbol or event.invoking_name
        if invoking_symbol and not invoking_symbol.startswith(("H_SHA_", "C_RSA_", "C_EC_", "Unknown")):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Sign is defined only on H_SHA hash objects or RSA/EC public key credentials", confidence="high")
        if invoking_symbol.startswith(("C_RSA_", "C_EC_")) and not _sign_has_payload(event):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Sign on a public key credential requires direct input data or an input cellblock", confidence="high")
        found_buffer_out, buffer_out = _named_method_arg_value(event, "BufferOut", "bufferOut", "Output", "output")
        if found_buffer_out:
            input_value = _xor_named_arg(event, "DataInput", "dataInput", "Input", "input", "Data", "data", "Buffer", "buffer")
            input_pattern = _xor_payload_pattern(input_value)
            capacity = _byte_table_cellblock_capacity(buffer_out)
            if input_pattern is not None and capacity is not None and capacity < len(input_pattern) // 2:
                return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Sign BufferOut cellblock must be large enough to hold the direct input byte size", confidence="high")
            return ExpectedResponse({SUCCESS}, expected_return_length=0, forbid_return_bool_literal=True, reason="Sign with BufferOut specified stores the signed data and returns an empty result", confidence="high")
        return ExpectedResponse(
            {SUCCESS},
            forbid_return_bool_literal=True,
            forbid_return_bool_payload=True,
            require_return_byte_payload=True,
            expected_return_min_length=1,
            reason="Generic Crypto Template Sign returns signed bytes when BufferOut is omitted",
            confidence="medium",
        )
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="TPerSign belongs to AdminSP", confidence="high")
    if not _sign_has_payload(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="Sign requires host data or an input buffer", confidence="high")
    if _payload_too_long(event, 256):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="TCGstorageAPI TPerSign signs payloads up to 256 bytes", confidence="medium")
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    is_wrapper = isinstance(input_obj, dict) and bool(_function_name(input_obj))
    return ExpectedResponse(
        {SUCCESS},
        forbid_return_bool_literal=True,
        forbid_return_bool_payload=True,
        require_return_byte_payload=True,
        expected_return_min_length=1 if is_wrapper else None,
        reason="TPerSign.Sign is callable by Anybody in an AdminSP session",
        confidence="medium",
    )


def _expected_firmware_attestation(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="FirmwareAttestation requires an open AdminSP session", confidence="high")
    if state.session.sp != "AdminSP":
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="TperAttestation belongs to AdminSP", confidence="high")
    if event.invoking_symbol != "TperAttestation":
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="FirmwareAttestation must target the TperAttestation authority", confidence="medium")
    if not _firmware_attestation_has_nonce(event):
        return ExpectedResponse({INVALID_PARAMETER}, reason="FirmwareAttestation requires an assessor nonce", confidence="high")
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    is_wrapper = isinstance(input_obj, dict) and bool(_function_name(input_obj))
    return ExpectedResponse(
        {SUCCESS},
        forbid_return_bool_literal=True,
        forbid_return_bool_payload=True,
        require_return_byte_payload=True,
        expected_return_min_length=1 if is_wrapper else None,
        reason="TCGstorageAPI invokes FirmwareAttestation as Anybody on AdminSP and successful responses return attestation bytes",
        confidence="medium",
    )


def _random_unsupported_arg(event: Event) -> str | None:
    allowed = {"count", "numbytes", "length", "size", "bytecount", "bytes", "bufferout", "buffer", "output", "destination", "dest", "out"}
    container_keys = {
        "required", "requiredargs", "optional", "optionalargs", "values",
        "settings", "options", "policy", "config", "request", "operation",
        "command", "cmd", "action",
        "random", "rng", "randomrequest", "rngrequest", "entropyrequest",
        "operationrequest", "rawargs",
    }

    def normalized(value: Any) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", _as_text(value)).lower()

    def check_mapping(mapping: Any) -> str | None:
        if not isinstance(mapping, dict):
            return None
        for key in mapping:
            key_name = normalized(key)
            if key_name in container_keys:
                unsupported = check_mapping(mapping.get(key))
                if unsupported is not None:
                    return unsupported
                continue
            if key_name and key_name not in allowed and key_name not in container_keys:
                return _as_text(key)
        return None

    for source in (event.required, event.optional):
        unsupported = check_mapping(source)
        if unsupported is not None:
            return unsupported

    raw_args = _method_raw_args(event)
    if isinstance(raw_args, dict):
        return check_mapping(raw_args)
    if not isinstance(raw_args, (list, tuple)):
        return None

    def walk(sequence: Any) -> str | None:
        if not isinstance(sequence, (list, tuple)):
            return None
        if len(sequence) == 2 and isinstance(sequence[0], (str, bytes)):
            key_name = normalized(sequence[0])
            if key_name and key_name not in allowed:
                return _as_text(sequence[0])
            return None
        for item in sequence:
            if isinstance(item, dict):
                unsupported = check_mapping(item)
                if unsupported is not None:
                    return unsupported
                continue
            unsupported = walk(item)
            if unsupported is not None:
                return unsupported
        return None

    return walk(raw_args)


def _expected_random(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Random requires an open SP session", confidence="medium")
    if event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP", ""} and not event.invoking_symbol.startswith("UnknownSP_"):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, reason="Random is an SP method", confidence="medium")
    unsupported_arg = _random_unsupported_arg(event)
    if unsupported_arg is not None:
        return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS}, reason=f"Random does not support parameter {unsupported_arg}", confidence="high")
    count = _random_count(event)
    if count is None:
        return ExpectedResponse({INVALID_PARAMETER}, reason="Random requires a Count parameter", confidence="high")
    if count < 0 or count > 32:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Opal Random Count must be between 0 and 32 bytes", confidence="high")
    cellblock_error = _crypto_datastore_cellblock_access_error(state, event)
    if cellblock_error is not None:
        return cellblock_error
    found_buffer_out, buffer_out = _named_method_arg_value(event, "BufferOut", "bufferOut", "Buffer")
    if found_buffer_out:
        capacity = _byte_table_cellblock_capacity(buffer_out)
        if capacity is not None and capacity < count:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Random BufferOut cellblock must be large enough to hold Count bytes", confidence="high")
        return ExpectedResponse({SUCCESS}, expected_return_length=0, forbid_return_bool_literal=True, reason="Random with BufferOut specified returns an empty Result", confidence="high")
    return ExpectedResponse({SUCCESS}, expected_return_length=count, forbid_return_bool_literal=True, require_return_byte_payload=bool(count), reason="Random Count is within the Opal mandatory supported range", confidence="high")


def _expected_next(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="Next requires an open session", confidence="medium")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Next table does not belong to current SP", confidence="medium")
    created = _created_table_for_event(state, event)
    if created is not None:
        table_sp, kind = created
        if state.session.sp is not None and table_sp != state.session.sp:
            return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Next dynamic table does not belong to current SP", confidence="high")
        if kind == "byte":
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next is defined only for Opal object tables", confidence="high")
    elif not _is_next_table_target(event.invoking_symbol, event.invoking_uid):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next is defined only for Opal object tables", confidence="high")
    if _next_count_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Count must be an unsigned integer", confidence="high")
    if _next_where_invalid(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Next Where must reference a row in the invoking object table", confidence="medium")
    forbidden_prefixes = set()
    if event.invoking_symbol and not event.invoking_symbol.startswith("ACE"):
        forbidden_prefixes.add("ACE_")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_uid_list=True,
        forbidden_return_uid_ref_prefixes=forbidden_prefixes,
        reason="Next is allowed on Opal object tables and returns a list of UID column values",
        confidence="medium",
    )


def _is_log_table_target(event: Event) -> bool:
    symbol = event.invoking_symbol
    return symbol in {"Log", "LogTable"} or symbol.startswith("Log_") or symbol.startswith("UnknownLog_")


def _is_log_list_target(event: Event) -> bool:
    symbol = event.invoking_symbol
    return symbol in {"LogList", "LogListTable"} or symbol.startswith("LogList_") or symbol.startswith("UnknownLogList_")


def _expected_add_log(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="AddLog requires an open session", confidence="high")
    if not _is_log_table_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="AddLog is defined only on Log tables", confidence="high")
    found_name, _ = _named_method_arg_value(event, "LogEntryName", "Name", "LogName")
    found_data, _ = _named_method_arg_value(event, "Data")
    if not found_name or not found_data:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="AddLog requires LogEntryName and Data parameters", confidence="high")
    if _payload_too_long(event, 64):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Log entry Data field is limited to 64 bytes", confidence="high")
    input_obj = _function_input_section(event.raw) if isinstance(event.raw, dict) else {}
    is_wrapper = isinstance(input_obj, dict) and _function_alias(_function_name(input_obj)) in {
        "addlog",
        "appendlog",
        "writelog",
        "putlog",
        "putLog",
        "putlogentry",
        "addlogentry",
        "appendlogentry",
        "writelogentry",
        "storelogentry",
        "createlogentry",
    }
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=not is_wrapper,
        reason="Successful AddLog returns an empty list; wrapper Boolean success is still accepted",
        confidence="high",
    )


def _expected_create_log(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateLog requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="CreateLog requires a read-write session", confidence="high")
    if not _is_log_list_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog is a LogList table method", confidence="high")

    required_args = [
        _create_table_arg(event, 0, "NewLogTableName", "Name", "LogTableName"),
        _create_table_arg(event, 1, "HighSecurity"),
        _create_table_arg(event, 2, "MinSize"),
    ]
    if not all(found for found, _ in required_args):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog requires NewLogTableName, HighSecurity, and MinSize", confidence="high")

    (_, name_value), (_, high_security), (_, min_size_value) = required_args
    name = _create_table_name_text(name_value)
    if not name:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog NewLogTableName must be non-empty", confidence="high")
    if not _is_bool_literal(high_security):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog HighSecurity must be boolean", confidence="high")
    if _uinteger_arg_invalid(min_size_value):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog MinSize must be an unsigned integer", confidence="high")
    min_size = _parse_int(min_size_value)

    found_max, max_size_value = _create_table_arg(event, 3, "MaxSize", "MaximumSize")
    if found_max:
        if _uinteger_arg_invalid(max_size_value):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog MaxSize must be an unsigned integer", confidence="medium")
        max_size = _parse_int(max_size_value)
        if max_size is None or max_size < min_size:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog MaxSize must be at least MinSize", confidence="medium")
    found_hint, hint_size_value = _create_table_arg(event, 4, "HintSize")
    if found_hint:
        if _uinteger_arg_invalid(hint_size_value):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog HintSize must be an unsigned integer", confidence="medium")
        hint_size = _parse_int(hint_size_value)
        if hint_size is None or hint_size < 0:
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog HintSize must be an unsigned integer", confidence="medium")

    found_common, common_value = _create_table_arg(event, 5, "CommonName")
    common_name = _create_table_name_text(common_value) if found_common else ""
    if (state.session.sp or "", name, common_name) in state.created_table_names:
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="CreateLog cannot create a duplicate Log table name/CommonName", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        forbidden_statuses={FAIL},
        expected_return_length=3,
        forbid_return_bool_literal=True,
        reason="Successful CreateLog returns LogListUID, LogTableUID, and Rows",
        confidence="medium",
    )


def _expected_log_maintenance(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason=f"{event.method} modifies or commits Log table state and requires a read-write session", confidence="medium")
    if not _is_log_table_target(event):
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} is defined only on existing Log tables", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason=f"Successful {event.method} returns an empty list",
        confidence="high",
    )


def _expected_table_query(state: State, event: Event) -> ExpectedResponse:
    common = _table_query_common_failure(state, event, event.method)
    if common is not None:
        return common
    if event.method == "GetFreeRows":
        return ExpectedResponse(
            {SUCCESS},
            expected_return_length=1,
            expected_return_uinteger_count=1,
            forbid_return_bool_literal=True,
            reason="Successful GetFreeRows returns FreeRows",
            confidence="high",
        )
    return ExpectedResponse({SUCCESS}, reason=f"{event.method} is allowed on Opal object tables", confidence="medium")


def _expected_get_free_space(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetFreeSpace requires an open session", confidence="high")
    if not _session_allows_object(state, event):
        return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER}, reason="GetFreeSpace SP target does not belong to current SP", confidence="medium")
    if event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP", ""} and not event.invoking_symbol.startswith("UnknownSP_"):
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="GetFreeSpace is an SP method invoked on ThisSP",
            confidence="high",
        )
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=2,
        expected_return_uinteger_count=2,
        forbid_return_bool_literal=True,
        reason="Successful GetFreeSpace returns FreeSpace and TableRows",
        confidence="high",
    )


def _psid_map_contains_wwn(psid_map: dict[Any, Any], wwn: Any) -> bool:
    variants: set[Any] = {wwn}
    text = _as_text(wwn)
    if text:
        variants.update({text, text.lower(), text.upper()})
    parsed = _parse_int(wwn)
    if parsed is not None:
        variants.update({parsed, hex(parsed), hex(parsed).lower(), hex(parsed).upper()})
    return any(key in psid_map for key in variants)


def _expected_revert(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires a read-write session", confidence="high")
    if event.method == "RevertSP" and event.invoking_symbol not in {"ThisSP", "AdminSP", "LockingSP"}:
        return ExpectedResponse({INVALID_PARAMETER}, reason="RevertSP must be invoked on ThisSP/SP object", confidence="medium")
    if event.method == "Revert" and event.invoking_symbol not in {"AdminSP", "LockingSP", "ThisSP"}:
        return ExpectedResponse({INVALID_PARAMETER}, reason="Revert must target an SP object", confidence="medium")
    if event.method == "RevertSP" and state.session.sp == "AdminSP" and event.invoking_symbol == "ThisSP":
        required = {"PSID"}
    elif state.session.sp == "LockingSP":
        required = {"Admins"}
    else:
        required = {"SID", "PSID", "Admins"}
    found_psid_map, psid_map = _dict_lookup(event.optional, "__PSIDCredentialMap")
    if found_psid_map and state.wwn is not None and isinstance(psid_map, dict) and not _psid_map_contains_wwn(psid_map, state.wwn):
        return ExpectedResponse({FAIL}, forbidden_statuses={SUCCESS}, reason="TCGstorageAPI revert returns False when the PSID map lacks this drive WWN", confidence="high")
    if not _has_any_authority(state, required):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires one of {sorted(required)}", confidence="high")
    if event.method == "RevertSP" and state.session.sp == "LockingSP" and _keep_global_range_key(event):
        global_range = _range(state, 0)
        if _read_locked(global_range) and _write_locked(global_range):
            return ExpectedResponse({FAIL}, forbidden_statuses={SUCCESS}, reason="KeepGlobalRangeKey RevertSP fails when Global Range is read-locked and write-locked", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason=f"Authorized {event.method} returns an empty list",
        confidence="medium",
    )


def _expected_get_acl(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetACL requires an open session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, reason="GetACL is invoked on the AccessControl table", confidence="medium")
    (found_invoking, _), (found_method, _) = _access_control_arg_values(event)
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="GetACL requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS, INVALID_PARAMETER, FAIL},
            reason="GetACL references an InvokingID/MethodID combination with no AccessControl row",
            confidence="high",
        )
    meta_acl = _known_meta_acl_authorization(state, event, "GetACL")
    if meta_acl == "empty":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="The association's GetACLACL is empty, so GetACL is not invocable",
            confidence="high",
        )
    if meta_acl == "created_unsatisfied":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="GetACLACL for this created row association is not satisfied",
            confidence="high",
        )
    if meta_acl == "admins" and not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="GetACLACL requires Admins authority", confidence="high")
    combo_key = _access_control_combo_key_for_state(state, event)
    required_uid_refs = state.access_control_acl_additions.get(combo_key, set()) if combo_key is not None else set()
    forbidden_uid_refs = state.access_control_acl_removals.get(combo_key, set()) if combo_key is not None else set()
    expected_acl_refs = _known_acl_return_refs(state, event)
    min_uid_refs = _created_row_get_acl_min_refs(state, event)
    range_support = _getacl_invoking_range_support_state(state, event)
    optional_absence_statuses = {NOT_AUTHORIZED} if range_support is None else set()
    return ExpectedResponse(
        {SUCCESS} | optional_absence_statuses,
        forbidden_statuses={INVALID_PARAMETER, FAIL} if range_support is None else set(),
        expected_return_uid_list=True,
        expected_return_uid_list_length=len(expected_acl_refs) if expected_acl_refs is not None else None,
        expected_return_uid_list_min_length=min_uid_refs,
        expected_return_uid_refs=expected_acl_refs or set(),
        required_return_uid_refs=required_uid_refs,
        forbidden_return_uid_refs=forbidden_uid_refs,
        allow_status_alternatives=range_support is None,
        reason="GetACL is permitted by Opal GetACLACL preconfiguration for known associations and returns a list of ACE uidrefs; unobserved Range9+ associations may also be absent before MaxRanges is known",
        confidence="medium" if range_support is None else "high",
    )


def _getacl_invoking_range_support_state(state: State, event: Event) -> bool | None:
    (found_invoking, invoking_value), _ = _access_control_arg_values(event)
    if not found_invoking:
        return False
    symbol, invoking_uid = _object_ref_from_value(invoking_value)
    if not symbol and invoking_uid:
        symbol = _object_by_uid(invoking_uid)
    range_id = _range_id_from_symbol(symbol)
    if range_id is None:
        range_id = _range_id_from_key(symbol)
    return _range_id_support_state(state, range_id)


def _created_row_get_acl_min_refs(state: State, event: Event) -> int | None:
    (found_invoking, invoking_value), (found_method, method_value) = _access_control_arg_values(event)
    if not found_invoking or not found_method:
        return None
    _, invoking_uid = _object_ref_from_value(invoking_value)
    if invoking_uid not in state.created_table_row_values_by_uid:
        return None
    method_name = _method_ref_name(method_value)
    if method_name in {"Get", "Set", "Delete"}:
        return 1
    return None


def _known_meta_acl_authorization(state: State, event: Event, meta_method: str) -> str | None:
    combo_key = _access_control_combo_key_for_state(state, event)
    if combo_key is None:
        return None
    invoking_symbol, method_name = combo_key
    invoking = re.sub(r"[^A-Za-z0-9_]", "", _as_text(invoking_symbol))

    if state.session.sp == "AdminSP" and invoking == "SPInfo" and method_name == "Get":
        if meta_method == "AddACE":
            return "anybody"
        if meta_method in {"RemoveACE", "GetACL", "DeleteMethod"}:
            return "empty"

    if state.session.sp == "LockingSP" and invoking.startswith("C_PIN_User") and method_name == "Set":
        if meta_method == "GetACL":
            return "anybody"
        if meta_method in {"AddACE", "RemoveACE", "DeleteMethod"}:
            return "empty"

    if state.session.sp == "LockingSP" and invoking in {"ThisSP", "LockingSP"} and method_name == "RevertSP":
        if meta_method == "GetACL":
            return "admins"
        if meta_method in {"AddACE", "RemoveACE", "DeleteMethod"}:
            return "empty"

    if invoking in state.created_table_row_values_by_uid and method_name in {"Get", "Set", "Delete"}:
        authorities = state.created_table_row_meta_acl_authorities.get(invoking)
        if not authorities:
            return "created_satisfied" if _has_authority(state, "Admins") else "created_unsatisfied"
        if "Anybody" in authorities or _has_any_authority(state, authorities):
            return "created_satisfied"
        return "created_unsatisfied"
    if invoking in state.created_row_side_effect_ace_by_uid and method_name in {"Get", "Set", "Delete"}:
        row_uid = state.created_row_side_effect_ace_by_uid.get(invoking)
        authorities = state.created_table_row_meta_acl_authorities.get(row_uid or "")
        if not authorities:
            return "created_satisfied" if _has_authority(state, "Admins") else "created_unsatisfied"
        if "Anybody" in authorities or _has_any_authority(state, authorities):
            return "created_satisfied"
        return "created_unsatisfied"

    created_table_uid = invoking if invoking in state.created_tables else state.created_table_descriptor_uids.get(invoking)
    if created_table_uid is not None:
        created_methods = {"Next", "Get", "Set"} if invoking in state.created_tables else {"Get"}
        if method_name in created_methods:
            refs = state.created_table_getset_acls.get(created_table_uid)
            if refs is not None:
                if not refs:
                    return "empty"
                if "ACE_00000001" in refs:
                    return "anybody"

    preconfigured = _known_preconfigured_acl_row(state, invoking, method_name)
    if preconfigured:
        if meta_method == "GetACL":
            return "anybody"
        if meta_method in {"AddACE", "RemoveACE", "DeleteMethod"}:
            return "empty"

    return None


def _known_acl_return_refs(state: State, event: Event) -> set[str] | None:
    combo_key = _access_control_combo_key_for_state(state, event)
    if combo_key is None:
        return None
    if combo_key in state.access_control_acl_replacements:
        return set(state.access_control_acl_replacements[combo_key])
    (found_invoking, invoking_value), _ = _access_control_arg_values(event)
    _, invoking_uid = _object_ref_from_value(invoking_value) if found_invoking else ("", "")
    raw_invoking_uid = _clean_uid(invoking_value) if found_invoking else ""
    if invoking_uid in state.created_table_row_values_by_uid or raw_invoking_uid in state.created_table_row_values_by_uid:
        return None
    side_effect_ace_uid = invoking_uid if invoking_uid in state.created_row_side_effect_ace_by_uid else raw_invoking_uid if raw_invoking_uid in state.created_row_side_effect_ace_by_uid else ""
    if side_effect_ace_uid:
        return {side_effect_ace_uid}
    invoking_symbol, method_name = combo_key
    invoking = re.sub(r"[^A-Za-z0-9_]", "", _as_text(invoking_symbol))

    if state.session.sp == "AdminSP" and invoking == "SPInfo" and method_name == "Get":
        return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})

    if state.session.sp == "AdminSP":
        known_admin_acls: dict[tuple[str, str], set[str]] = {
            ("Table", "Next"): {"ACE_00000001"},
            ("Table", "Get"): {"ACE_00000001"},
            ("SPTemplatesTable", "Get"): {"ACE_00000001"},
            ("MethodIDTable", "Next"): {"ACE_00000001"},
            ("ACETable", "Next"): {"ACE_00000001"},
            ("AuthorityTable", "Next"): {"ACE_00000001"},
            ("C_PINTable", "Next"): {"ACE_00000001"},
            ("TPerInfo", "Get"): {"ACE_00000001"},
            ("TemplateTable", "Next"): {"ACE_00000001"},
            ("TemplateTable", "Get"): {"ACE_00000001"},
            ("SPTable", "Next"): {"ACE_00000001"},
            ("SPTable", "Get"): {"ACE_00000001"},
            ("AdminSP", "Get"): {"ACE_00000001"},
            ("AdminSP", "Revert"): {"ACE_00030002", "ACE_00000002"},
            ("LockingSP", "Activate"): {"ACE_00030002"},
            ("ThisSP", "Authenticate"): {"ACE_00000001"},
            ("ThisSP", "Random"): {"ACE_00000001"},
            ("Authority_Makers", "Set"): {"ACE_00030001"},
            ("Authority_Admin1", "Set"): {"ACE_00030001"},
            ("C_PIN_SID", "Get"): {"ACE_00008C02"},
            ("C_PIN_SID", "Set"): {"ACE_00008C03"},
            ("C_PIN_MSID", "Get"): {"ACE_00008C04"},
            ("C_PIN_Admin1", "Get"): {"ACE_00008C02"},
            ("C_PIN_Admin1", "Set"): {"ACE_0003A001"},
            ("TPerInfo", "Set"): {"ACE_00030003"},
            ("DataRemovalMechanism", "Get"): {"ACE_00000001"},
            ("DataRemovalMechanism", "Set"): {"ACE_00050001"},
        }
        if (invoking, method_name) in known_admin_acls:
            return _acl_refs_with_dynamic_state(state, combo_key, known_admin_acls[(invoking, method_name)])
        if method_name == "Get" and (
            invoking.startswith("Table_")
            or invoking.startswith("SPTemplates_")
            or invoking.startswith("MethodID_")
            or invoking.startswith("ACE_")
            or invoking.startswith("Authority_")
            or invoking.startswith("Template_")
        ):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})

    if state.session.sp == "LockingSP" and invoking.startswith("C_PIN_User") and method_name == "Set":
        match = re.fullmatch(r"C_PIN_User(\d+)", invoking)
        if match:
            return _acl_refs_with_dynamic_state(state, combo_key, {f"ACE_0003{0xA800 + int(match.group(1)):04X}"})

    if state.session.sp == "LockingSP" and invoking in {"ThisSP", "LockingSP"} and method_name == "RevertSP":
        return _acl_refs_with_dynamic_state(state, combo_key, set())

    if state.session.sp == "LockingSP":
        cpin_user_match = re.fullmatch(r"C_PIN_User(\d+)", invoking)
        if cpin_user_match and method_name == "Get":
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_0003A000"})
        authority_user_match = re.fullmatch(r"Authority_User(\d+)", invoking)
        if authority_user_match and method_name == "Get":
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00039000", "ACE_00000003"})
        if authority_user_match and method_name == "Set":
            user_index = int(authority_user_match.group(1))
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00039001", f"ACE_{0x00044000 + user_index:08X}"})
        locking_range_match = re.fullmatch(r"Locking_Range(\d+)", invoking)
        if locking_range_match and method_name == "Get":
            range_index = int(locking_range_match.group(1))
            if _range_id_support_state(state, range_index) is False:
                return None
            if range_index in state.created_locking_ranges:
                return None
            return _acl_refs_with_dynamic_state(state, combo_key, {f"ACE_{0x0003D000 + range_index:08X}", "ACE_00000003"})
        if locking_range_match and method_name == "Set":
            range_index = int(locking_range_match.group(1))
            if _range_id_support_state(state, range_index) is False:
                return None
            if range_index in state.created_locking_ranges:
                return None
            return _acl_refs_with_dynamic_state(
                state,
                combo_key,
                {"ACE_0003F001", f"ACE_{0x0003E000 + range_index:08X}", f"ACE_{0x0003E800 + range_index:08X}", "ACE_00000004"},
            )
        key_range_match = re.fullmatch(r"K_AES_(128|256)_Range(\d+)_Key", invoking)
        if key_range_match and method_name == "Get":
            range_index = int(key_range_match.group(2))
            if _range_id_support_state(state, range_index) is False:
                return None
            if range_index in state.created_locking_ranges:
                return None
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_0003BFFF"})
        if key_range_match and method_name == "GenKey":
            base = 0x0003B000 if key_range_match.group(1) == "128" else 0x0003B800
            range_index = int(key_range_match.group(2))
            if _range_id_support_state(state, range_index) is False:
                return None
            if range_index in state.created_locking_ranges:
                return None
            return _acl_refs_with_dynamic_state(state, combo_key, {f"ACE_{base + range_index:08X}"})
        known_locking_acls: dict[tuple[str, str], set[str]] = {
            ("ThisSP", "Authenticate"): set(),
            ("ThisSP", "Random"): set(),
            ("SPInfo", "Get"): set(),
            ("Table", "Next"): set(),
            ("Table", "Get"): {"ACE_00000001"},
            ("SPTemplatesTable", "Next"): set(),
            ("SPTemplates_Base", "SPTemplatesObj"): {"ACE_00000001"},
            ("SPTemplates_Admin", "SPTemplatesObj"): {"ACE_00000001"},
            ("MethodIDTable", "Next"): {"ACE_00000001"},
            ("MethodID_Next", "MethodIDObj"): {"ACE_00000001"},
            ("ACETable", "Next"): {"ACE_00000001"},
            ("ACE_00038000", "Get"): {"ACE_00038000"},
            ("ACE_00039000", "Get"): {"ACE_00038000"},
            ("ACE_0003A000", "Get"): {"ACE_00038000"},
            ("ACE_0003A801", "Get"): {"ACE_00038000"},
            ("ACE_00038000", "Set"): {"ACE_00038001"},
            ("ACE_00039000", "Set"): {"ACE_00038001"},
            ("ACE_0003A801", "Set"): {"ACE_00038001"},
            ("AuthorityTable", "Next"): {"ACE_00000001"},
            ("Authority_Admin1", "Get"): {"ACE_00039000", "ACE_00000003"},
            ("Authority_User1", "Get"): {"ACE_00039000", "ACE_00000003"},
            ("Authority_Admin1", "Set"): {"ACE_00000004"},
            ("Authority_Admin2", "Set"): {"ACE_00039001", "ACE_00000004"},
            ("DataStore", "Get"): {"ACE_0003FC00"},
            ("DataStore", "Set"): {"ACE_0003FC01"},
            ("C_PINTable", "Next"): {"ACE_00000001"},
            ("C_PIN_Admin1", "Get"): {"ACE_0003A000"},
            ("C_PIN_Admin1", "Set"): {"ACE_0003A001"},
            ("C_PIN_User1", "Get"): {"ACE_0003A000"},
            ("MBRControl", "Get"): {"ACE_00000001"},
            ("MBRControl", "Set"): {"ACE_0003F800", "ACE_0003F801"},
            ("MBR", "Get"): {"ACE_00000001"},
            ("MBR", "Set"): {"ACE_00000002"},
            ("SecretProtectTable", "Next"): {"ACE_00000001"},
            ("SecretProtectTable", "Get"): {"ACE_00000001"},
            ("SecretProtect_1", "Get"): {"ACE_00000001"},
            ("LockingTable", "Next"): {"ACE_00000001"},
            ("LockingInfo", "Get"): {"ACE_00000001"},
            ("Authority_User1", "Set"): {"ACE_00039001", "ACE_00044001"},
            ("Locking_GlobalRange", "Get"): {"ACE_0003D000", "ACE_00000003"},
            ("Locking_GlobalRange", "Set"): {"ACE_0003F000", "ACE_0003E000", "ACE_0003E800", "ACE_00000004"},
            ("Locking_Range1", "Get"): {"ACE_0003D001", "ACE_00000003"},
            ("Locking_Range1", "Set"): {"ACE_0003F001", "ACE_0003E001", "ACE_0003E801", "ACE_00000004"},
            ("K_AES_128_GlobalRange_Key", "Get"): {"ACE_0003BFFF"},
            ("K_AES_128_Range1_Key", "Get"): {"ACE_0003BFFF"},
            ("K_AES_256_GlobalRange_Key", "Get"): {"ACE_0003BFFF"},
            ("K_AES_256_Range1_Key", "Get"): {"ACE_0003BFFF"},
            ("K_AES_128_GlobalRange_Key", "GenKey"): {"ACE_0003B000"},
            ("K_AES_128_Range1_Key", "GenKey"): {"ACE_0003B001"},
            ("K_AES_256_GlobalRange_Key", "GenKey"): {"ACE_0003B800"},
            ("K_AES_256_Range1_Key", "GenKey"): {"ACE_0003B801"},
        }
        if (invoking, method_name) in known_locking_acls:
            return _acl_refs_with_dynamic_state(state, combo_key, known_locking_acls[(invoking, method_name)])
        if method_name == "Get" and re.fullmatch(r"SecretProtect_\d+", invoking):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})
        if method_name == "Get" and invoking.startswith("Table_"):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})
        if method_name == "SPTemplatesObj" and invoking.startswith("SPTemplates_"):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})
        if method_name == "MethodIDObj" and invoking.startswith("MethodID_"):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00000001"})
        if method_name == "Get" and invoking.startswith("ACE_"):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00038000"})
        if method_name == "Set" and invoking.startswith("ACE_"):
            return _acl_refs_with_dynamic_state(state, combo_key, {"ACE_00038001"})

    return None


def _acl_refs_with_dynamic_state(state: State, combo_key: tuple[str, str], base_refs: set[str]) -> set[str]:
    if combo_key in state.access_control_acl_replacements:
        return set(state.access_control_acl_replacements[combo_key])
    refs = _canonical_ace_refs(base_refs)
    refs |= state.access_control_acl_additions.get(combo_key, set())
    refs -= state.access_control_acl_removals.get(combo_key, set())
    return refs


def _known_preconfigured_acl_row(state: State, invoking: str, method_name: str) -> bool:
    if state.session.sp not in {"AdminSP", "LockingSP"}:
        return False
    if invoking in {"AccessControl", "AccessControlTable", "Table_AccessControl"} and method_name in {
        "AddACE",
        "RemoveACE",
        "GetACL",
        "SetACL",
        "DeleteMethod",
    }:
        return False
    if invoking.startswith("Unknown"):
        return False
    return True


def _expected_acl_mutation(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires a read-write session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason=f"{event.method} must be invoked on the AccessControl table", confidence="high")
    (found_invoking, _), (found_method, _) = _access_control_arg_values(event)
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        if event.method in {"AddACE", "RemoveACE"}:
            return ExpectedResponse(
                {NOT_AUTHORIZED},
                forbidden_statuses={SUCCESS, INVALID_PARAMETER, FAIL},
                reason=f"{event.method} references an InvokingID/MethodID combination with no AccessControl row",
                confidence="high",
            )
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} references an unknown InvokingID/MethodID association",
            confidence="high",
        )
    meta_acl = _known_meta_acl_authorization(state, event, event.method)
    if meta_acl == "empty":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"The association's {event.method} meta-ACL is empty, so {event.method} is not invocable",
            confidence="high",
        )
    if meta_acl == "created_unsatisfied":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} meta-ACL for this created row association is not satisfied",
            confidence="high",
        )
    if meta_acl not in {"anybody", "created_satisfied"} and not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason=f"{event.method} requires Admins authority", confidence="high")
    ace_refs = _canonical_ace_refs(_ace_method_refs(event))
    if not ace_refs:
        if event.method == "SetACL" and _setacl_has_empty_acl_argument(event):
            return ExpectedResponse(
                {SUCCESS},
                expected_return_length=0,
                forbid_return_bool_literal=_raw_tcg_method_event(event),
                reason="Authorized SetACL may replace an AccessControl ACL with an empty ACE list",
                confidence="medium",
            )
        return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason=f"{event.method} requires an ACE reference", confidence="medium")
    missing_refs = {ref for ref in ace_refs if not _ace_ref_exists(ref)}
    if missing_refs:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} references an ACE that does not exist in the ACE table",
            confidence="high",
        )
    if event.method == "AddACE":
        combo_key = _access_control_combo_key_for_state(state, event)
        current_refs = _known_acl_return_refs(state, event)
        dynamic_refs = state.access_control_acl_additions.get(combo_key, set()) if combo_key is not None else set()
        if (current_refs is not None and ace_refs & _canonical_ace_refs(current_refs)) or ace_refs & _canonical_ace_refs(dynamic_refs):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="AddACE fails when the ACE already exists in the target AccessControl ACL",
                confidence="high",
            )
    if event.method == "RemoveACE":
        combo_key = _access_control_combo_key_for_state(state, event)
        current_refs = _known_acl_return_refs(state, event)
        dynamic_refs = state.access_control_acl_additions.get(combo_key, set()) if combo_key is not None else set()
        removed_refs = state.access_control_acl_removals.get(combo_key, set()) if combo_key is not None else set()
        if current_refs is not None and not (ace_refs & _canonical_ace_refs(current_refs)):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="RemoveACE fails when the ACE is not present in the target AccessControl ACL",
                confidence="high",
            )
        if current_refs is None and ace_refs & removed_refs and not (ace_refs & dynamic_refs):
            return ExpectedResponse(
                {INVALID_PARAMETER, FAIL},
                forbidden_statuses={SUCCESS},
                reason="RemoveACE cannot remove an ACE that was already removed from the tracked dynamic AccessControl ACL",
                confidence="high",
            )
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason=f"Authorized {event.method} updates an AccessControl ACL and returns an empty list",
        confidence="medium",
    )


def _expected_delete_method(state: State, event: Event) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires an open session", confidence="high")
    if not state.session.write:
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires a read-write session", confidence="high")
    if event.invoking_symbol not in {"AccessControlTable", "Table_AccessControl", "AccessControl"}:
        return ExpectedResponse({INVALID_PARAMETER, NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="DeleteMethod must be invoked on the AccessControl table", confidence="high")
    (found_invoking, _), (found_method, _) = _access_control_arg_values(event)
    if not found_invoking or not found_method:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="DeleteMethod requires InvokingID and MethodID arguments",
            confidence="high",
        )
    combo_exists = _combo_exists_for_get_acl(state, event)
    if combo_exists is False:
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS, INVALID_PARAMETER, FAIL},
            reason="DeleteMethod references an InvokingID/MethodID combination with no AccessControl row",
            confidence="high",
        )
    meta_acl = _known_meta_acl_authorization(state, event, "DeleteMethod")
    if meta_acl == "empty":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="The association's DeleteMethodACL is empty, so DeleteMethod is not invocable",
            confidence="high",
        )
    if meta_acl == "created_unsatisfied":
        return ExpectedResponse(
            {NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="DeleteMethodACL for this created row association is not satisfied",
            confidence="high",
        )
    if meta_acl not in {"anybody", "created_satisfied"} and not _has_authority(state, "Admins"):
        return ExpectedResponse({NOT_AUTHORIZED}, reason="DeleteMethod requires Admins authority", confidence="high")
    return ExpectedResponse(
        {SUCCESS},
        expected_return_length=0,
        forbid_return_bool_literal=_raw_tcg_method_event(event),
        reason="Authorized DeleteMethod removes an AccessControl association and returns an empty list",
        confidence="medium",
    )


def _host_property_initial_for_expected(name: str) -> Any:
    if name in OPAL_HOST_PROPERTY_INITIALS:
        return OPAL_HOST_PROPERTY_INITIALS[name]
    return HOST_PROPERTY_INITIALS.get(name)


def _coerced_expected_host_property_value(name: str, value: Any) -> Any:
    initial = _host_property_initial_for_expected(name)
    if isinstance(initial, bool):
        return _as_bool(value)
    parsed = _parse_int(value)
    if parsed is None:
        return None
    if initial is None:
        return max(0, parsed)
    return max(int(initial or 0), max(0, parsed))


def _expected_host_properties_after_submission(state: State, event: Event) -> tuple[dict[str, Any], dict[str, Any]]:
    if not _host_properties_parameter_present(event):
        return {}, {}
    required = _opal_host_property_initials()
    current = state.host_properties_by_comid.get(event.comid, {}) if event.comid else state.host_properties
    required.update(current)
    optional: dict[str, Any] = {}
    submitted = _submitted_host_properties(event)
    for name, value in submitted.items():
        coerced = _coerced_expected_host_property_value(name, value)
        if coerced is None:
            continue
        if name in required:
            required[name] = coerced
        elif name in HOST_PROPERTY_INITIALS:
            optional[name] = coerced
    ack_value = required.get("AckNak", optional.get("AckNak", HOST_PROPERTY_INITIALS.get("AckNak")))
    seq_value = required.get("SequenceNumbers", optional.get("SequenceNumbers", HOST_PROPERTY_INITIALS.get("SequenceNumbers")))
    if ack_value is True and seq_value is False:
        for name in ("AckNak", "SequenceNumbers"):
            if name in required:
                required[name] = False
            elif name in HOST_PROPERTY_INITIALS:
                optional[name] = False
    return required, optional


def expected_status(state: State, event: Event) -> ExpectedResponse:
    unsupported = _unsupported_method_response(event)
    if unsupported is not None:
        return unsupported
    wrapper_authas_failure = _wrapper_authas_failure(state, event)
    if wrapper_authas_failure is not None:
        return wrapper_authas_failure
    if event.kind == "host_io":
        return _expected_host_io(state, event)
    if _explicit_session_manager_target(event) and event.method not in CONTROL_SESSION_METHODS:
        return ExpectedResponse(
            {INVALID_PARAMETER, FAIL, NOT_AUTHORIZED},
            forbidden_statuses={SUCCESS},
            reason="The Session Manager control session ignores or discards methods whose MethodID is not a supported control-session method",
            confidence="high",
        )
    if event.method == "Properties":
        if not _is_session_manager_target(event):
            return ExpectedResponse({INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Properties must target the Session Manager", confidence="high")
        expected_properties, optional_properties = _expected_host_properties_after_submission(state, event)
        return ExpectedResponse(
            {SUCCESS},
            expected_return_properties=expected_properties,
            optional_return_properties=optional_properties,
            validate_tper_properties=True,
            reason="Properties is supported by the Session Manager and HostProperties responses reflect current supported host communication properties",
            confidence="high" if expected_properties else "high",
        )
    if event.method == "StartSession":
        return _expected_start_session(state, event)
    if event.method in {"StartTrustedSession", "StartTlsSession"}:
        return _expected_start_trusted_session(state, event)
    if state.session.trusted_startup_pending:
        return ExpectedResponse(
            {NOT_AUTHORIZED, INVALID_PARAMETER, FAIL},
            forbidden_statuses={SUCCESS},
            reason="Regular Session is not open until the trusted startup half completes",
            confidence="high",
        )
    if event.method in CRYPTO_STREAM_METHODS:
        return _expected_crypto_stream_method(state, event)
    if event.method == "XOR":
        return _expected_xor(state, event)
    if event.method == "Verify":
        return _expected_verify(state, event)
    if not _method_supported_in_session(state, event):
        return ExpectedResponse(
            {INVALID_PARAMETER, NOT_AUTHORIZED, FAIL},
            forbidden_statuses={SUCCESS},
            reason=f"{event.method} is not supported in {state.session.sp}",
            confidence="high",
        )
    disabled = _disabled_sp_response(state, event)
    if disabled is not None:
        return disabled
    if _method_combo_deleted(state, event):
        return ExpectedResponse({NOT_AUTHORIZED}, forbidden_statuses={SUCCESS}, reason="AccessControl association for this method was deleted", confidence="high")
    if event.method == "Authenticate":
        return _expected_authenticate(state, event)
    if event.method == "GetACL":
        return _expected_get_acl(state, event)
    if event.method in {"AddACE", "RemoveACE", "SetACL"}:
        return _expected_acl_mutation(state, event)
    if event.method == "DeleteMethod":
        return _expected_delete_method(state, event)
    if event.method == "Get":
        return _expected_get(state, event)
    if event.method == "Set":
        return _expected_set(state, event)
    if event.method == "CreateRow":
        return _expected_create_row(state, event)
    if event.method == "DeleteRow":
        return _expected_delete_row(state, event)
    if event.method == "Delete":
        return _expected_delete(state, event)
    if event.method == "DeleteSP":
        return _expected_delete_sp(state, event)
    if event.method == "CreateTable":
        return _expected_create_table(state, event)
    if event.method == "Activate":
        return _expected_activate(state, event)
    if event.method == "GenKey":
        return _expected_genkey(state, event)
    if event.method == "GetPackage":
        return _expected_get_package(state, event)
    if event.method == "SetPackage":
        return _expected_set_package(state, event)
    if event.method == "Erase":
        return _expected_erase(state, event)
    if event.method == "Sign":
        return _expected_sign(state, event)
    if event.method == "FirmwareAttestation":
        return _expected_firmware_attestation(state, event)
    if event.method in {"Revert", "RevertSP"}:
        return _expected_revert(state, event)
    if event.method in {"SyncSession", "SyncTrustedSession", "SyncTlsSession"}:
        return _expected_sync_session(state, event)
    if event.method in {"EndSession", "CloseSession"}:
        return _expected_end_session(state, event)
    if event.method == "Next":
        return _expected_next(state, event)
    if event.method == "AddLog":
        return _expected_add_log(state, event)
    if event.method == "CreateLog":
        return _expected_create_log(state, event)
    if event.method in {"ClearLog", "FlushLog"}:
        return _expected_log_maintenance(state, event)
    if event.method == "GetFreeSpace":
        return _expected_get_free_space(state, event)
    if event.method == "GetFreeRows":
        return _expected_table_query(state, event)
    if event.method == "Random":
        return _expected_random(state, event)
    return ExpectedResponse({NOT_AUTHORIZED, INVALID_PARAMETER, FAIL}, forbidden_statuses={SUCCESS}, reason="Method is outside the implemented Opal MethodID universe", confidence="medium")


def _expected_host_io(state: State, event: Event) -> ExpectedResponse:
    reset_type = _reset_event_type(event.method)
    if reset_type is not None:
        if reset_type == 3 and not state.programmatic_reset_enabled:
            return ExpectedResponse(
                {FAIL, INVALID_PARAMETER, NOT_AUTHORIZED},
                forbidden_statuses={SUCCESS, None, "PASS"},
                reason="TPER_RESET is disabled unless TPerInfo.ProgrammaticResetEnable is true",
                confidence="high",
            )
        return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Reset events are valid host-side state transitions", confidence="medium")

    normalized_method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if normalized_method == "haslockedrange":
        locked = _locking_feature_locked(state)
        if locked:
            return ExpectedResponse(
                {SUCCESS},
                forbidden_statuses={FAIL, None},
                expected_return_bool=True,
                reason="TCGstorageAPI hasLockedRange reflects the Locking Feature Locked state",
                confidence="high",
            )
        return ExpectedResponse(
            {FAIL},
            forbidden_statuses={SUCCESS, None},
            reason="TCGstorageAPI hasLockedRange returns false when no enabled range is locked",
            confidence="high",
        )

    tper_feature = _expected_level0_tper_feature(state, event)
    if tper_feature is not None:
        return tper_feature

    locking_feature = _expected_level0_locking_feature(state, event)
    if locking_feature is not None:
        return locking_feature

    data_removal_feature = _expected_level0_data_removal_feature(state, event)
    if data_removal_feature is not None:
        return data_removal_feature

    geometry_feature = _expected_level0_geometry_feature(state, event)
    if geometry_feature is not None:
        return geometry_feature

    opal_ssc_v2_feature = _expected_level0_opal_ssc_v2_feature(state, event)
    if opal_ssc_v2_feature is not None:
        return opal_ssc_v2_feature

    crossing_error_allowed = _range_crossing_error_allowed(state, event.lba)
    mbr_relation = _mbr_shadow_relation(state, event.lba)
    if event.method == "Write":
        if mbr_relation in {"within", "partial"}:
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, reason="MBR shadowing blocks host writes to the MBR address range", confidence="high")
        if _any_write_locked(state, event.lba):
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, reason="Write targets a write-locked range", confidence="high")
        if crossing_error_allowed:
            if state.range_crossing_behavior == 1:
                return ExpectedResponse({FAIL, INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, reason="Opal Range Crossing Behavior 1 terminates unlocked writes spanning multiple Locking ranges", confidence="high")
            if state.range_crossing_behavior == 0:
                return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Opal Range Crossing Behavior 0 processes unlocked writes spanning multiple Locking ranges", confidence="high")
            return ExpectedResponse({SUCCESS, None, "PASS", INVALID_PARAMETER, FAIL}, reason="Unlocked range-crossing writes may succeed or be rejected by Range Crossing Behavior", confidence="medium")
        return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Write is allowed by current locking state", confidence="medium")

    if event.method == "Read":
        if mbr_relation == "partial":
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, forbid_read_result_presence=True, reason="A host read spanning the MBR shadow boundary is a data-protection error", confidence="high")
        if mbr_relation == "within":
            expected_mbr_positions = _mbr_shadow_read_expected_byte_positions(state, event)
            if expected_mbr_positions:
                return ExpectedResponse(
                    {SUCCESS, None, "PASS"},
                    expected_read_byte_positions=expected_mbr_positions,
                    reason="MBR shadowing maps the requested LBA window to MBR byte-table offsets and returns the tracked bytes for that window",
                    confidence="high",
                )
            if state.mbr_table_pattern is not None:
                return ExpectedResponse(
                    {SUCCESS, None, "PASS"},
                    expected_read_result=state.mbr_table_pattern,
                    reason="MBR shadowing returns the tracked MBR table data",
                    confidence="high",
                )
            remembered = _remembered_pattern_for_lba(state, event.lba)
            old_pattern = remembered[0] if remembered is not None else None
            return ExpectedResponse({SUCCESS, None, "PASS"}, forbidden_read_result=old_pattern, reason="MBR shadowing returns MBR table data instead of user media data", confidence="high")
        if _any_read_locked(state, event.lba):
            if mbr_relation == "outside" and crossing_error_allowed:
                return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, forbid_read_result_presence=True, reason="Read crosses mixed locking ranges while MBR shadowing is active", confidence="high")
            if mbr_relation == "outside":
                return ExpectedResponse({SUCCESS, None, "PASS"}, expected_zero_read_result=True, reason="MBR shadowing active with outside read-locked range returns zeroes", confidence="high")
            return ExpectedResponse({INVALID_PARAMETER}, forbidden_statuses={SUCCESS, None, "PASS"}, forbid_read_result_presence=True, reason="Read targets a read-locked range", confidence="high")
        if crossing_error_allowed:
            if state.range_crossing_behavior == 1:
                return ExpectedResponse(
                    {INVALID_PARAMETER},
                    forbidden_statuses={SUCCESS, None, "PASS"},
                    forbid_read_result_presence=True,
                    reason="Opal Range Crossing Behavior 1 terminates unlocked reads spanning multiple Locking ranges",
                    confidence="high",
                )
            if state.range_crossing_behavior == 0:
                pass
            else:
                return ExpectedResponse({SUCCESS, None, "PASS", INVALID_PARAMETER, FAIL}, reason="Unlocked range-crossing reads may succeed or be rejected by Range Crossing Behavior", confidence="medium")
        remembered_analysis = _remembered_pattern_analysis_for_lba(state, event.lba)
        if remembered_analysis is None:
            return ExpectedResponse({SUCCESS, None, "PASS"}, reason="No prior write pattern is known for this LBA", confidence="low")
        old_pattern = remembered_analysis.get("pattern")
        if old_pattern is not None and remembered_analysis.get("stale"):
            return ExpectedResponse({SUCCESS, None, "PASS"}, forbidden_read_result=old_pattern, reason="GenKey changed the media key for at least one remembered segment after this pattern was written", confidence="high")
        if old_pattern is not None and remembered_analysis.get("complete"):
            return ExpectedResponse({SUCCESS, None, "PASS"}, expected_read_result=old_pattern, reason="Prior write pattern should still be readable", confidence="high")
        return ExpectedResponse({SUCCESS, None, "PASS"}, reason="Prior writes only partially cover this LBA range", confidence="low")

    return ExpectedResponse({SUCCESS, None, "PASS", FAIL, NOT_AUTHORIZED, INVALID_PARAMETER}, reason="Unknown host I/O fallback", confidence="low")


def _locking_feature_enabled(state: State) -> bool:
    observed = state.observed_sp_lifecycle.get("LockingSP")
    active = _sp_lifecycle_active(observed) if observed is not None else None
    if active is not None:
        return active
    return state.locking_sp_activated


def _locking_feature_locked(state: State) -> bool:
    if not _locking_feature_enabled(state):
        return False
    return any(
        _read_locked(range_state) or _write_locked(range_state)
        for range_state in state.ranges.values()
        if range_state.range_id == 0 or range_state.range_length > 0 or not range_state.range_length_known
    )


def _level0_arg(event: Event, *names: str) -> Any:
    raw = event.raw
    inp = _input_section(raw)
    args = _mapping_section(inp, "args", "Args", "arguments", "Arguments")
    if not args:
        args = _mapping_section(raw, "args", "Args", "arguments", "Arguments")
    for source in (args, inp, raw):
        found, value = _dict_lookup(source, *names)
        if found:
            return value
    return None


def _is_locking_feature_discovery(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    feature_code = _parse_int(_level0_arg(event, "FeatureCode", "featureCode", "feature_code", "code", "Code"))
    feature_name = re.sub(r"[^A-Za-z0-9]", "", _as_text(_level0_arg(event, "Feature", "feature", "Name", "name") or "")).lower()
    return feature_code == 0x0002 or feature_name in {"locking", "lockingfeature"}


def _is_tper_feature_discovery(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    feature_code = _parse_int(_level0_arg(event, "FeatureCode", "featureCode", "feature_code", "code", "Code"))
    feature_name = re.sub(r"[^A-Za-z0-9]", "", _as_text(_level0_arg(event, "Feature", "feature", "Name", "name") or "")).lower()
    return feature_code == 0x0001 or feature_name in {"tper", "tperfeature"}


def _is_data_removal_feature_discovery(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    feature_code = _parse_int(_level0_arg(event, "FeatureCode", "featureCode", "feature_code", "code", "Code"))
    feature_name = re.sub(r"[^A-Za-z0-9]", "", _as_text(_level0_arg(event, "Feature", "feature", "Name", "name") or "")).lower()
    return feature_code == 0x0404 or feature_name in {
        "dataremoval",
        "dataremovalfeature",
        "supporteddataremovalmechanism",
        "supporteddataremovalmechanismfeature",
    }


def _is_geometry_feature_discovery(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    feature_code = _parse_int(_level0_arg(event, "FeatureCode", "featureCode", "feature_code", "code", "Code"))
    feature_name = re.sub(r"[^A-Za-z0-9]", "", _as_text(_level0_arg(event, "Feature", "feature", "Name", "name") or "")).lower()
    return feature_code == 0x0003 or feature_name in {
        "geometry",
        "geometryreporting",
        "geometryreportingfeature",
    }


def _is_opal_ssc_v2_feature_discovery(event: Event) -> bool:
    method = re.sub(r"[^A-Za-z0-9]", "", _as_text(event.method or "")).lower()
    if method not in {"level0discovery", "discovery", "featuredescriptor", "getfeaturedescriptor"}:
        return False
    feature_code = _parse_int(_level0_arg(event, "FeatureCode", "featureCode", "feature_code", "code", "Code"))
    feature_name = re.sub(r"[^A-Za-z0-9]", "", _as_text(_level0_arg(event, "Feature", "feature", "Name", "name") or "")).lower()
    return feature_code == 0x0203 or feature_name in {
        "opalsscv2",
        "opalv2",
        "opalsscv2feature",
    }


def _expected_level0_tper_feature(state: State, event: Event) -> ExpectedResponse | None:
    if not _is_tper_feature_discovery(event):
        return None

    exact_values: dict[Any, int] = {
        ("FeatureCode", "Feature Code", "feature_code", "Code"): 0x0001,
        ("Length", "DescriptorLength", "length"): 0x0C,
        ("StreamingSupported", "Streaming Supported", "Streaming"): 1,
        ("SyncSupported", "Sync Supported", "Synchronous", "SynchronousSupported"): 1,
    }
    minimum_values: dict[Any, int] = {
        ("FeatureDescriptorVersion", "DescriptorVersion", "Version", "Feature Descriptor Version Number"): 0x01,
    }
    return ExpectedResponse(
        {SUCCESS, None, "PASS"},
        expected_return_min_values={**exact_values, **minimum_values},
        expected_return_max_values=exact_values,
        reason="Opal TPer Level 0 descriptor has fixed feature code/length and mandatory Streaming and Sync support",
        confidence="high",
    )


def _expected_level0_locking_feature(state: State, event: Event) -> ExpectedResponse | None:
    if not _is_locking_feature_discovery(event):
        return None

    locking_enabled = _locking_feature_enabled(state)
    locked = _locking_feature_locked(state)
    mbr_enabled = locking_enabled and _as_bool(state.mbr.get("Enabled"))
    mbr_done = mbr_enabled and _as_bool(state.mbr.get("Done"))
    expected_bits = {
        ("LockingEnabled", "Locking Enabled", "locking_enabled"): int(locking_enabled),
        ("Locked", "LockingLocked", "Locking Feature Locked"): int(locked),
        ("MBREnabled", "MBR Enabled", "mbr_enabled"): int(mbr_enabled),
        ("MBRDone", "MBR Done", "mbr_done"): int(mbr_done),
    }
    return ExpectedResponse(
        {SUCCESS, None, "PASS"},
        expected_return_min_values=expected_bits,
        expected_return_max_values=expected_bits,
        reason="Level 0 Locking Feature descriptor bits reflect the current Locking/MBR state",
        confidence="high",
    )


def _expected_level0_data_removal_feature(state: State, event: Event) -> ExpectedResponse | None:
    if not _is_data_removal_feature_discovery(event):
        return None

    fixed_values = {
        ("FeatureCode", "Feature Code", "feature_code", "Code"): 0x0404,
        ("Version", "DescriptorVersion", "version"): 0x02,
        ("Length", "DescriptorLength", "length"): 0x20,
        ("DataRemovalOperationProcessing", "OperationProcessing", "Processing"): 0,
    }
    if _return_payload_has_any_name(
        _output_return_values(event.raw),
        "DataRemovalOperationInterrupted",
        "OperationInterrupted",
        "Interrupted",
    ):
        fixed_values[("DataRemovalOperationInterrupted", "OperationInterrupted", "Interrupted")] = 0
    return ExpectedResponse(
        {SUCCESS, None, "PASS"},
        expected_return_min_values=fixed_values,
        expected_return_max_values=fixed_values,
        expected_return_bit_masks={
            (
                "SupportedDataRemovalMechanism",
                "Supported Data Removal Mechanism",
                "DataRemovalMechanism",
                "Mechanism",
            ): (0x04, 0xD8),
        },
        reason="Opal Supported Data Removal Mechanism Feature has fixed descriptor fields, no processing/interrupted bit after completed operations, mandatory crypto-erase support, and reserved mechanism bits clear",
        confidence="high",
    )


def _expected_level0_geometry_feature(state: State, event: Event) -> ExpectedResponse | None:
    if not _is_geometry_feature_discovery(event):
        return None

    fixed_values: dict[Any, int] = {
        ("FeatureCode", "Feature Code", "feature_code", "Code"): 0x0003,
        ("Version", "DescriptorVersion", "FeatureDescriptorVersion", "Feature Descriptor Version Number"): 0x01,
        ("Length", "DescriptorLength", "length"): 0x1C,
    }
    if "AlignmentRequired" in state.locking_info:
        fixed_values[("ALIGN", "Align", "AlignmentRequired", "Alignment Required")] = int(
            _as_bool(state.locking_info.get("AlignmentRequired"))
        )
    geometry_cells = {
        "LogicalBlockSize": (
            "LogicalBlockSize",
            "Logical Block Size",
            "logical_block_size",
        ),
        "AlignmentGranularity": (
            "AlignmentGranularity",
            "Alignment Granularity",
            "alignment_granularity",
        ),
        "LowestAlignedLBA": (
            "LowestAlignedLBA",
            "Lowest Aligned LBA",
            "lowest_aligned_lba",
        ),
    }
    for key, selector in geometry_cells.items():
        value = _parse_int(state.locking_info.get(key))
        if value is not None:
            fixed_values[selector] = value
    return ExpectedResponse(
        {SUCCESS, None, "PASS"},
        expected_return_min_values=fixed_values,
        expected_return_max_values=fixed_values,
        reason="Opal Geometry Reporting Level 0 descriptor mirrors LockingInfo alignment and geometry fields",
        confidence="high",
    )


def _expected_level0_opal_ssc_v2_feature(state: State, event: Event) -> ExpectedResponse | None:
    if not _is_opal_ssc_v2_feature_discovery(event):
        return None

    exact_values: dict[Any, int] = {
        ("FeatureCode", "Feature Code", "feature_code", "Code"): 0x0203,
        ("Length", "DescriptorLength", "length"): 0x10,
    }
    minimum_values: dict[Any, int] = {
        ("FeatureDescriptorVersion", "DescriptorVersion", "Version", "Feature Descriptor Version Number"): 0x02,
        ("NumberOfComIDs", "Number of ComIDs", "NumComIDs", "ComIDs"): 1,
        (
            "NumberOfLockingSPAdminAuthorities",
            "Number of Locking SP Admin Authorities",
            "LockingSPAdminAuthorities",
        ): 4,
        (
            "NumberOfLockingSPUserAuthorities",
            "Number of Locking SP User Authorities",
            "LockingSPUserAuthorities",
        ): 8,
    }
    allowed_values: dict[Any, set[int]] = {
        ("SSCMinorVersion", "SSC Minor Version Number", "MinorVersion", "SSCMinor"): {0, 1, 2, 3},
        ("RangeCrossingBehavior", "Range Crossing Behavior", "RangeCrossing"): {0, 1},
        ("InitialCPINSIDPINIndicator", "Initial C_PIN_SID PIN Indicator", "InitialSIDPINIndicator"): {0x00, 0xFF},
        (
            "BehaviorOfCPINSIDPINUponTPerRevert",
            "Behavior of C_PIN_SID PIN upon TPer Revert",
            "SIDPINRevertBehavior",
        ): {0x00, 0xFF},
    }
    return ExpectedResponse(
        {SUCCESS, None, "PASS"},
        expected_return_min_values={**exact_values, **minimum_values},
        expected_return_max_values=exact_values,
        expected_return_allowed_values=allowed_values,
        reason="Opal SSC V2 Level 0 descriptor has fixed length, supported minor-version and C_PIN_SID indicator enums, and mandatory minimum ComID/Admin/User counts",
        confidence="high",
    )


def _return_payload_has_any_name(value: Any, *names: str) -> bool:
    wanted = {re.sub(r"[^A-Za-z0-9]", "", name).upper() for name in names}
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(key)).upper() in wanted:
                return True
            if _return_payload_has_any_name(item, *names):
                return True
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and not isinstance(value[0], (dict, list, tuple, set)):
            if re.sub(r"[^A-Za-z0-9]", "", _as_text(value[0])).upper() in wanted:
                return True
        return any(_return_payload_has_any_name(item, *names) for item in value)
    return False


def _return_payload_has_object_ref(value: Any) -> bool:
    if isinstance(value, dict):
        symbol, uid = _object_ref_from_value(value)
        if uid or (symbol and _known_opal_object_symbol(symbol)):
            return True
        return any(_return_payload_has_object_ref(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_return_payload_has_object_ref(item) for item in value)
    symbol, uid = _object_ref_from_value(value)
    return bool(uid or (symbol and _known_opal_object_symbol(symbol)))


def _hex_payload_length(text: str) -> int | None:
    stripped = re.sub(r"[\s:_-]", "", text.strip())
    if stripped.lower().startswith("0x"):
        stripped = stripped[2:]
    stripped = re.sub(r"[^0-9A-Fa-f]", "", stripped)
    if stripped and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", stripped):
        return len(stripped) // 2
    return None


def _return_payload_length(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, bytearray):
        return len(value)
    if isinstance(value, str):
        if re.sub(r"[^A-Za-z_]", "", value).upper() in {
            "SUCCESS",
            "PASS",
            "FAIL",
            "NOTAUTHORIZED",
            "INVALIDPARAMETER",
            "INSUFFICIENTSPACE",
            "INSUFFICIENTROWS",
        }:
            return None
        stripped_value = value.strip()
        if re.fullmatch(r"[bB][rR]?(?:'[^']*'|\"[^\"]*\")", stripped_value) or re.fullmatch(r"[rR]?[bB](?:'[^']*'|\"[^\"]*\")", stripped_value):
            try:
                parsed = ast.literal_eval(stripped_value)
            except (SyntaxError, ValueError):
                parsed = None
            if isinstance(parsed, (bytes, bytearray)):
                return len(parsed)
        hex_length = _hex_payload_length(value)
        return hex_length if hex_length is not None else len(value.encode("utf-8"))
    if isinstance(value, dict):
        for key in (
            "Result",
            "result",
            "return",
            "Return",
            "return_values",
            "ReturnValues",
            "returnValues",
            "values",
            "Values",
            "payload",
            "Payload",
            "BufferOut",
            "Data",
            "data",
            "bytes",
            "Bytes",
        ):
            found, item = _dict_lookup(value, key)
            if found:
                length = _return_payload_length(item)
                if length is not None:
                    return length
        if len(value) == 1:
            length = _return_payload_length(next(iter(value.values())))
            return length if length is not None else 1
        return len(value)
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            return 0
        if len(value) == 1:
            length = _return_payload_length(value[0])
            return length if length is not None else 1
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return len(value)
        return len(value)
    return None



__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
