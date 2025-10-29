%% @doc Common record definitions for Cryptic CA modules
%% @author Cryptic Development Team
%% @since October 2025

-record(invite, {
    invite_id :: binary(),
    inviter_fp :: binary(),
    issued_at :: non_neg_integer(),
    expires_at :: non_neg_integer(),
    consumed :: 0 | 1,
    consumed_at :: non_neg_integer() | undefined,
    consumed_by_fp :: binary() | undefined,
    meta :: binary() | undefined
}).

-record(gpg_identity, {
    gpg_fp :: binary(),
    gpg_pub_armor :: binary(),
    % 'verified_via_invite' | 'verified_bootstrap' | 'pending' | 'revoked'
    status :: binary(),
    inviter_fp :: binary() | undefined,
    registered_at :: non_neg_integer(),
    last_seen :: non_neg_integer(),
    invite_id :: binary() | undefined
}).

-record(audit_log, {
    timestamp :: non_neg_integer(),
    event_type :: binary(),
    gpg_fp :: binary() | undefined,
    invite_id :: binary() | undefined,
    details :: binary() | undefined,
    ip_address :: binary() | undefined
}).
