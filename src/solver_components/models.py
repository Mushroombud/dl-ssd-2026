"""Canonical event and reconstructed verifier state models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import *


@dataclass
class Event:
    raw: dict[str, Any]
    kind: str
    method: str
    invoking_name: str = ""
    invoking_uid: str = ""
    invoking_symbol: str = ""
    status: str | None = None
    required: dict[str, Any] = field(default_factory=dict)
    optional: dict[str, Any] = field(default_factory=dict)
    values: dict[int, Any] = field(default_factory=dict)
    columns: set[int] = field(default_factory=set)
    sp: str | None = None
    authority: str | None = None
    challenge: str | None = None
    write_session: bool = False
    lba: tuple[int, int] | None = None
    pattern: str | None = None
    read_result: str | None = None
    implicit_session: bool = False
    comid: str = ""

    @property
    def is_success(self) -> bool:
        if self.kind == "host_io":
            return self.status in {None, SUCCESS, "PASS"}
        return self.status == SUCCESS


@dataclass
class ExpectedResponse:
    allowed_statuses: set[str | None] = field(default_factory=set)
    forbidden_statuses: set[str | None] = field(default_factory=set)
    expected_read_result: str | None = None
    forbidden_read_result: str | None = None
    expected_return_length: int | None = None
    expected_return_uinteger_count: int | None = None
    expected_return_cells: dict[int, Any] = field(default_factory=dict)
    optional_return_cells: dict[int, Any] = field(default_factory=dict)
    expected_return_min_cells: dict[int, int] = field(default_factory=dict)
    expected_return_max_cells: dict[int, int] = field(default_factory=dict)
    expected_return_cell_lte: tuple[tuple[int, int], ...] = field(default_factory=tuple)
    expected_return_min_values: dict[Any, int] = field(default_factory=dict)
    expected_return_max_values: dict[Any, int] = field(default_factory=dict)
    optional_return_min_values: dict[Any, int] = field(default_factory=dict)
    optional_return_max_values: dict[Any, int] = field(default_factory=dict)
    expected_return_allowed_values: dict[Any, set[int]] = field(default_factory=dict)
    expected_return_bit_masks: dict[Any, tuple[int, int]] = field(default_factory=dict)
    required_return_names: set[str] = field(default_factory=set)
    required_any_return_names: set[str] = field(default_factory=set)
    forbidden_return_names: set[str] = field(default_factory=set)
    expected_return_values: dict[str, Any] = field(default_factory=dict)
    expected_return_properties: dict[str, Any] = field(default_factory=dict)
    optional_return_properties: dict[str, Any] = field(default_factory=dict)
    forbidden_return_properties: set[str] = field(default_factory=set)
    validate_tper_properties: bool = False
    required_return_columns: set[int] = field(default_factory=set)
    forbidden_return_columns: set[int] = field(default_factory=set)
    expected_return_column_types: dict[int, str] = field(default_factory=dict)
    require_typed_return_columns: bool = False
    expected_return_bool: bool | None = None
    require_return_bool: bool = False
    forbidden_return_bool: bool | None = None
    forbid_return_bool_literal: bool = False
    forbid_return_bool_payload: bool = False
    forbid_return_status_bool_payload: bool = False
    forbid_bare_status_return_payload: bool = False
    require_non_empty_return_payload: bool = False
    require_return_byte_payload: bool = False
    expected_return_uid_list: bool = False
    expected_return_uid_list_length: int | None = None
    expected_return_uid_list_min_length: int | None = None
    expected_return_uid_refs: set[str] = field(default_factory=set)
    required_return_uid_refs: set[str] = field(default_factory=set)
    forbidden_return_uid_refs: set[str] = field(default_factory=set)
    forbidden_return_uid_ref_prefixes: set[str] = field(default_factory=set)
    expected_return_pattern: str | None = None
    expected_return_byte_positions: dict[int, str] = field(default_factory=dict)
    expected_read_byte_positions: dict[int, str] = field(default_factory=dict)
    expected_return_min_length: int | None = None
    forbid_read_result_presence: bool = False
    reason: str = ""
    confidence: str = "medium"
    expected_zero_read_result: bool = False


@dataclass
class Session:
    open: bool = False
    sp: str | None = None
    write: bool = False
    authenticated: set[str] = field(default_factory=set)
    host_session_id: str | None = None
    sp_session_id: str | None = None
    startup_host_challenge: bool = False
    startup_sp_challenge: bool = False
    trusted_startup_pending: bool = False
    comid: str = ""


@dataclass
class RangeState:
    range_id: int
    range_start: int = 0
    range_length: int = 0
    range_length_known: bool = False
    read_lock_enabled: bool = False
    write_lock_enabled: bool = False
    read_locked: bool = False
    write_locked: bool = False
    lock_on_reset: bool = False
    active_key: str | None = None
    next_key: str | None = None
    active_key_known: bool = False
    next_key_known: bool = False
    reencrypt_state: int = 1
    reencrypt_request: int | None = None
    adv_key_mode: int | None = None
    verify_mode: int | None = None
    cont_on_reset: Any = None
    last_reencrypt_lba: int | None = None
    last_reenc_stat: Any = None
    general_status: Any = None
    media_generation: int = 0
    lock_on_reset_types: set[int] = field(default_factory=set)


@dataclass
class AceExpression:
    authorities: set[str] = field(default_factory=set)
    operator: str = "or"
    tokens: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class State:
    session: Session = field(default_factory=Session)
    crypto_streams: dict[tuple[str, str], bool] = field(default_factory=dict)
    crypto_stream_bufferout: set[tuple[str, str]] = field(default_factory=set)
    crypto_stream_bufferout_value: dict[tuple[str, str], Any] = field(default_factory=dict)
    pins: dict[str, str] = field(default_factory=dict)
    invalidated_pin_values: dict[str, set[str]] = field(default_factory=dict)
    pin_min_lengths: dict[str, int] = field(default_factory=dict)
    pin_try_limits: dict[str, int] = field(default_factory=dict)
    pin_tries: dict[str, int] = field(default_factory=dict)
    pin_persistence: dict[str, bool] = field(default_factory=dict)
    authority_enabled: dict[str, bool] = field(default_factory=dict)
    authority_secure: dict[str, int] = field(default_factory=dict)
    authority_hash_and_sign: dict[str, bool] = field(default_factory=dict)
    authority_credential_present: dict[str, bool] = field(default_factory=dict)
    authority_credential_symbol: dict[str, str | None] = field(default_factory=dict)
    authority_response_sign: dict[str, str | None] = field(default_factory=dict)
    authority_response_exchange: dict[str, str | None] = field(default_factory=dict)
    authority_limits: dict[str, int] = field(default_factory=dict)
    authority_uses: dict[str, int] = field(default_factory=dict)
    locking_sp_activated: bool = False
    observed_sp_lifecycle: dict[str, int] = field(default_factory=dict)
    sp_failed: set[str] = field(default_factory=set)
    sp_enabled: dict[str, bool] = field(default_factory=dict)
    sp_frozen: dict[str, bool] = field(default_factory=dict)
    sp_session_timeouts: dict[str, int] = field(default_factory=dict)
    tper_def_session_timeout: int | None = None
    tper_max_sessions: int | None = None
    tper_max_session_timeout: int | None = None
    tper_min_session_timeout: int | None = None
    tper_def_trans_timeout: int | None = None
    tper_max_trans_timeout: int | None = None
    tper_min_trans_timeout: int | None = None
    host_properties: dict[str, Any] = field(default_factory=dict)
    host_properties_by_comid: dict[str, dict[str, Any]] = field(default_factory=dict)
    deleted_sps: set[str] = field(default_factory=set)
    pending_deleted_sp: str | None = None
    created_table_names: set[tuple[str, str, str]] = field(default_factory=set)
    created_table_name_by_uid: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    created_tables: dict[str, tuple[str, str]] = field(default_factory=dict)
    created_table_columns: dict[str, set[int]] = field(default_factory=dict)
    created_table_unique_columns: dict[str, tuple[int, ...]] = field(default_factory=dict)
    created_table_rows: dict[str, list[dict[int, Any]]] = field(default_factory=dict)
    created_table_row_values_by_uid: dict[str, tuple[str, dict[int, Any]]] = field(default_factory=dict)
    created_table_row_meta_acl_authorities: dict[str, set[str]] = field(default_factory=dict)
    created_row_side_effect_ace_by_uid: dict[str, str] = field(default_factory=dict)
    created_table_descriptor_uids: dict[str, str] = field(default_factory=dict)
    created_table_min_sizes: dict[str, int] = field(default_factory=dict)
    created_table_max_sizes: dict[str, int] = field(default_factory=dict)
    created_table_allocated_rows: dict[str, int] = field(default_factory=dict)
    created_table_getset_acls: dict[str, set[str]] = field(default_factory=dict)
    programmatic_reset_enabled: bool = False
    locking_info: dict[str, Any] = field(default_factory=dict)
    locking_sp_user_authority_count: int | None = None
    range_crossing_behavior: int | None = None
    loglist_rows: dict[str, dict[int, Any]] = field(default_factory=dict)
    ranges: dict[int, RangeState] = field(default_factory=dict)
    created_locking_ranges: set[int] = field(default_factory=set)
    range_read_lock_users: dict[int, set[str]] = field(default_factory=dict)
    range_write_lock_users: dict[int, set[str]] = field(default_factory=dict)
    datastore_read_users: set[str] = field(default_factory=set)
    datastore_write_users: set[str] = field(default_factory=set)
    ace_expressions: dict[tuple[str, str], AceExpression] = field(default_factory=dict)
    access_control_acl_additions: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    access_control_acl_removals: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    access_control_acl_replacements: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    deleted_method_associations: set[tuple[str, str]] = field(default_factory=set)
    mbr: dict[str, Any] = field(default_factory=dict)
    mbr_table_pattern: str | None = None
    mbr_table_bytes: dict[int, str] = field(default_factory=dict)
    data_removal_mechanism: Any = None
    datastore_pattern: str | None = None
    datastore_bytes: dict[int, str] = field(default_factory=dict)
    expected_datastore_rows: int | None = None
    caes_modes: dict[str, int] = field(default_factory=dict)
    port_values: dict[str, dict[int, Any]] = field(default_factory=dict)
    psk_values: dict[str, dict[int, Any]] = field(default_factory=dict)
    byte_table_rows: dict[str, int] = field(default_factory=dict)
    byte_table_mandatory_granularity: dict[str, int] = field(default_factory=dict)
    byte_table_recommended_granularity: dict[str, int] = field(default_factory=dict)
    lba_patterns: dict[tuple[int, int], tuple[str, int, int]] = field(default_factory=dict)
    wwn: Any = None
    sid_ever_authenticated: bool = False
    sid_pin_revert_behavior: int = 0


__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]
