%% @doc Common record definitions for Cryptic CA modules
%% @author Cryptic Development Team
%% @since October 2025

%% @doc Invite record with state machine
%% State transitions: active → registered → consumed
%% Also: expired (automatic), revoked (manual)
-record(invite, {
    invite_id :: binary(),                     % Token: "inv_<base64url>"
    inviter_fp :: binary(),                    % GPG fingerprint of creator
    issued_at :: non_neg_integer(),            % Unix timestamp
    expires_at :: non_neg_integer(),           % Unix timestamp
    
    %% State machine: 'active' | 'registered' | 'consumed' | 'expired' | 'revoked'
    status = <<"active">> :: binary(),
    
    %% GPG registration (active → registered)
    registered_at :: non_neg_integer() | undefined,
    registered_by_fp :: binary() | undefined,
    
    %% Production cert request (registered → consumed)
    consumed_at :: non_neg_integer() | undefined,
    consumed_cert_serial :: binary() | undefined,
    
    %% Manual revocation
    revoked_at :: non_neg_integer() | undefined,
    revoked_by :: binary() | undefined,
    revoked_reason :: binary() | undefined,
    
    %% Optional metadata (JSON)
    meta :: binary() | undefined
}).

-record(gpg_identity, {
    gpg_fp :: binary(),
    gpg_pub_armor :: binary(),
    % 'active' | 'suspended' | 'revoked'
    status :: binary(),
    registered_by :: binary() | undefined,  % GPG fingerprint of admin who registered this user
    registered_at :: non_neg_integer(),
    last_seen :: non_neg_integer(),
    metadata :: binary() | undefined  % JSON: {name, team, notes, etc.}
}).

-record(audit_log, {
    timestamp :: non_neg_integer(),
    event_type :: binary(),
    gpg_fp :: binary() | undefined,
    invite_id :: binary() | undefined,
    details :: binary() | undefined,
    ip_address :: binary() | undefined
}).

-record(certificate, {
    serial :: binary(),                        % Certificate serial number (unique)
    gpg_fp :: binary(),                        % GPG fingerprint of certificate owner
    issued_at :: non_neg_integer(),            % Unix timestamp
    expires_at :: non_neg_integer(),           % Unix timestamp
    
    %% Status: 'active' | 'expired' | 'revoked'
    status = <<"active">> :: binary(),
    
    %% Revocation (if applicable)
    revoked_at :: non_neg_integer() | undefined,
    revoked_by :: binary() | undefined,        % GPG fingerprint of admin who revoked
    revoked_reason :: binary() | undefined,
    
    %% Certificate data
    cert_pem :: binary()                       % PEM-encoded certificate
}).
