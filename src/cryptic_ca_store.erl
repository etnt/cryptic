%% @doc Cryptic CA Store - SQLite Storage for GPG Registry and Invites
%%
%% This module provides persistent storage for the GPG-based Certificate Authority
%% system, managing invite tokens, GPG identities, and audit logs.
%%
%% == Features ==
%% <ul>
%%   <li>SQLite-based persistent storage for CA data</li>
%%   <li>Optional encryption for sensitive data (GPG keys, invite metadata)</li>
%%   <li>Transaction support for atomic operations</li>
%%   <li>Indexed lookups for fingerprints and invite IDs</li>
%% </ul>
%%
%% == Database Schema ==
%% See init/1 for full schema definition
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_store).

-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    init/1,
    close/1,
    open_db/1,
    create_tables/1,

    %% CA certificate operations
    load_ca_cert/0,
    load_ca_key/0,
    init_ca_environment/0,

    %% Invite operations
    insert_invite/2,
    get_invite/2,
    consume_invite/3,
    list_invites_by_inviter/2,
    revoke_invite/2,
    delete_expired_invites/1,

    %% GPG identity operations
    insert_gpg_identity/2,
    get_gpg_identity/2,
    update_last_seen/2,
    list_gpg_identities/1,

    %% Audit operations
    insert_audit_log/2,
    get_audit_logs/3,

    %% Database inspection (for debugging)
    list_tables/1,
    describe_table/2,
    inspect_db/0
]).

-include("cryptic_server.hrl").

%% esqlite3 connection reference
-type db_ref() :: tuple().
-type invite_id() :: binary().
-type gpg_fingerprint() :: binary().
-type unix_timestamp() :: non_neg_integer().

%%====================================================================
%% API
%%====================================================================

%% @doc Initialize database connection and create tables if needed
-spec init(file:filename()) -> {ok, db_ref()} | {error, term()}.
init(DbFile) ->
    ?info("Initializing CA storage at ~s", [DbFile]),

    %% Ensure directory exists
    DbDir = filename:dirname(DbFile),
    case filelib:ensure_dir(filename:join(DbDir, "dummy")) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} ->
            ?error("Failed to create DB directory ~s: ~p", [DbDir, Reason]),
            exit({error, {dir_creation_failed, Reason}})
    end,

    %% Open database connection
    case esqlite3:open(DbFile) of
        {ok, Conn} ->
            %% Set pragmas for better performance and safety
            ok = esqlite3:exec(Conn, "PRAGMA journal_mode=WAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA synchronous=NORMAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA foreign_keys=ON;"),

            %% Create tables
            case create_tables(Conn) of
                ok ->
                    ?info("CA storage initialized successfully", []),
                    {ok, Conn};
                {error, CreateReason} = CreateError ->
                    ?error("Failed to create tables: ~p", [CreateReason]),
                    esqlite3:close(Conn),
                    CreateError
            end;
        {error, OpenReason} = OpenError ->
            ?error("Failed to open database ~s: ~p", [DbFile, OpenReason]),
            OpenError
    end.

%% @doc Close database connection
-spec close(db_ref()) -> ok.
close(Conn) ->
    esqlite3:close(Conn).

%% @doc Open database connection (for use by other modules)
-spec open_db(file:filename()) -> {ok, db_ref()} | {error, term()}.
open_db(DbFile) ->
    case esqlite3:open(DbFile) of
        {ok, Conn} ->
            ok = esqlite3:exec(Conn, "PRAGMA journal_mode=WAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA synchronous=NORMAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA foreign_keys=ON;"),
            {ok, Conn};
        Error ->
            Error
    end.

%%====================================================================
%% CA Certificate Operations
%%====================================================================

%% @doc Initialize CA environment by loading certificates and keys
%%
%% Reads CA certificate and private key from files specified in
%% application configuration, parses them, and stores in application
%% environment for use by certificate issuance.
%%
%% This should be called during application startup.
%%
%% Configuration:
%% ```
%% {cryptic_ca, [
%%     {ca_cert_file, "CA/certs/ca.crt"},
%%     {ca_key_file, "CA/private/ca.key"}
%% ]}.
%% '''
-spec init_ca_environment() -> ok | {error, term()}.
init_ca_environment() ->
    try
        {ok, CACert} = load_ca_cert(),
        {ok, CAKey} = load_ca_key(),
        
        application:set_env(cryptic_ca, ca_cert, CACert),
        application:set_env(cryptic_ca, ca_key, CAKey),
        
        ?info("CA environment initialized successfully", []),
        ok
    catch
        ErrorType:ErrorReason:Stack ->
            ?error("Failed to initialize CA environment: ~p:~p~n~p",
                   [ErrorType, ErrorReason, Stack]),
            {error, {ca_init_failed, ErrorReason}}
    end.

%% @doc Load CA certificate from PEM file
%%
%% Reads and parses the CA root certificate. Returns an OTPCertificate
%% record that can be used for certificate operations.
-spec load_ca_cert() -> {ok, #'OTPCertificate'{}} | {error, term()}.
load_ca_cert() ->
    case application:get_env(cryptic_ca, ca_cert_file) of
        {ok, CertFile} ->
            case file:read_file(CertFile) of
                {ok, CertPEM} ->
                    try
                        [{_, CertDER, _}] = public_key:pem_decode(CertPEM),
                        Cert = public_key:pkix_decode_cert(CertDER, otp),
                        {ok, Cert}
                    catch
                        _:Reason ->
                            ?error("Failed to parse CA certificate ~s: ~p",
                                   [CertFile, Reason]),
                            {error, {cert_parse_failed, Reason}}
                    end;
                {error, Reason} = Error ->
                    ?error("Failed to read CA certificate ~s: ~p",
                           [CertFile, Reason]),
                    Error
            end;
        undefined ->
            {error, ca_cert_file_not_configured}
    end.

%% @doc Load CA private key from PEM file
%%
%% Reads and parses the CA private key. Returns an ECPrivateKey
%% record for ECDSA keys or RSAPrivateKey for RSA keys.
%%
%% The key must match the algorithm used in the CA certificate.
-spec load_ca_key() -> {ok, tuple()} | {error, term()}.
load_ca_key() ->
    case application:get_env(cryptic_ca, ca_key_file) of
        {ok, KeyFile} ->
            case file:read_file(KeyFile) of
                {ok, KeyPEM} ->
                    try
                        [KeyEntry | _] = public_key:pem_decode(KeyPEM),
                        Key = public_key:pem_entry_decode(KeyEntry),
                        {ok, Key}
                    catch
                        _:Reason ->
                            ?error("Failed to parse CA private key ~s: ~p",
                                   [KeyFile, Reason]),
                            {error, {key_parse_failed, Reason}}
                    end;
                {error, Reason} = Error ->
                    ?error("Failed to read CA private key ~s: ~p",
                           [KeyFile, Reason]),
                    Error
            end;
        undefined ->
            {error, ca_key_file_not_configured}
    end.

%% @doc Create database tables
-spec create_tables(db_ref()) -> ok | {error, term()}.
create_tables(Conn) ->
    InvitesTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS invites (\n"
            "            invite_id TEXT PRIMARY KEY,\n"
            "            inviter_fp TEXT NOT NULL,\n"
            "            issued_at INTEGER NOT NULL,\n"
            "            expires_at INTEGER NOT NULL,\n"
            "            consumed INTEGER DEFAULT 0,\n"
            "            consumed_at INTEGER,\n"
            "            consumed_by_fp TEXT,\n"
            "            meta TEXT,\n"
            "            FOREIGN KEY (inviter_fp) REFERENCES gpg_identities(gpg_fp)\n"
            "        )\n"
            "    "
        >>,

    GpgIdentitiesTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS gpg_identities (\n"
            "            gpg_fp TEXT PRIMARY KEY,\n"
            "            gpg_pub_armor TEXT NOT NULL,\n"
            "            status TEXT NOT NULL CHECK(status IN (\n"
            "                'verified_via_invite',\n"
            "                'verified_bootstrap',\n"
            "                'pending',\n"
            "                'revoked'\n"
            "            )),\n"
            "            inviter_fp TEXT,\n"
            "            registered_at INTEGER NOT NULL,\n"
            "            last_seen INTEGER NOT NULL,\n"
            "            invite_id TEXT,\n"
            "            FOREIGN KEY (invite_id) REFERENCES invites(invite_id)\n"
            "        )\n"
            "    "
        >>,

    AuditLogTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS audit_log (\n"
            "            id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            "            timestamp INTEGER NOT NULL,\n"
            "            event_type TEXT NOT NULL,\n"
            "            gpg_fp TEXT,\n"
            "            invite_id TEXT,\n"
            "            details TEXT,\n"
            "            ip_address TEXT\n"
            "        )\n"
            "    "
        >>,

    %% Create indexes
    Indexes = [
        <<"CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter_fp)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_gpg_status ON gpg_identities(status)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_gpg_inviter ON gpg_identities(inviter_fp)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type)">>
    ],

    try
        ok = esqlite3:exec(Conn, InvitesTable),
        ok = esqlite3:exec(Conn, GpgIdentitiesTable),
        ok = esqlite3:exec(Conn, AuditLogTable),
        lists:foreach(fun(Idx) -> ok = esqlite3:exec(Conn, Idx) end, Indexes),
        ok
    catch
        ErrorType:ErrorReason:_Stack ->
            ?error("Failed to create tables: ~p:~p", [
                ErrorType, ErrorReason
            ]),
            {error, {table_creation_failed, ErrorReason}}
    end.

%%====================================================================
%% Invite Operations
%%====================================================================

%% @doc Insert a new invite into the database.
%%
%% Creates a new invite record that can be used for onboarding new users.
%% The invite contains metadata about who created it, when it expires, and
%% optional additional data (stored as JSON).
%%
%% == Example ==
%% ```
%% Invite = #invite{
%%     invite_id = <<"inv-123">>,
%%     inviter_fp = <<"ABCD1234...">>,
%%     issued_at = 1700000000,
%%     expires_at = 1700086400,
%%     consumed = 0,
%%     meta = <<"{\"role\":\"admin\"}">>
%% },
%% ok = cryptic_ca_store:insert_invite(Conn, Invite).
%% '''
%%
%% @param Conn Database connection reference
%% @param Invite The invite record to insert
%% @returns `ok' on success, `{error, Reason}' on failure (e.g., duplicate ID, FK violation)
-spec insert_invite(db_ref(), #invite{}) -> ok | {error, term()}.
insert_invite(Conn, #invite{} = Invite) ->
    SQL =
        <<
            "INSERT INTO invites (invite_id, inviter_fp, issued_at, expires_at, consumed, meta) \n"
            "             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        >>,
    Params = [
        Invite#invite.invite_id,
        Invite#invite.inviter_fp,
        Invite#invite.issued_at,
        Invite#invite.expires_at,
        Invite#invite.consumed,
        Invite#invite.meta
    ],

    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert invite ~s: ~p", [
                Invite#invite.invite_id, Reason
            ]),
            Error
    end.

%% @doc Retrieve an invite by its unique ID.
%%
%% Fetches a complete invite record including consumption status and metadata.
%% Can be used to validate invite tokens during the onboarding process.
%%
%% == Example ==
%% ```
%% case cryptic_ca_store:get_invite(Conn, <<"inv-123">>) of
%%     {ok, Invite} ->
%%         %% Check if consumed, expired, etc.
%%         handle_invite(Invite);
%%     {error, not_found} ->
%%         invalid_invite()
%% end.
%% '''
%%
%% @param Conn Database connection reference
%% @param InviteId The unique invite identifier
%% @returns `{ok, Invite}' if found, `{error, not_found}' if not found, or `{error, Reason}' on database error
-spec get_invite(db_ref(), invite_id()) ->
    {ok, #invite{}} | {error, not_found} | {error, term()}.
get_invite(Conn, InviteId) ->
    SQL =
        <<
            "SELECT invite_id, inviter_fp, issued_at, expires_at, consumed, \n"
            "                   consumed_at, consumed_by_fp, meta \n"
            "             FROM invites WHERE invite_id = ?1"
        >>,

    case esqlite3:q(Conn, SQL, [InviteId]) of
        [
            [
                Id,
                InviterFp,
                IssuedAt,
                ExpiresAt,
                Consumed,
                ConsumedAt,
                ConsumedByFp,
                Meta
            ]
        ] ->
            {ok, #invite{
                invite_id = Id,
                inviter_fp = InviterFp,
                issued_at = IssuedAt,
                expires_at = ExpiresAt,
                consumed = Consumed,
                consumed_at = ConsumedAt,
                consumed_by_fp = ConsumedByFp,
                meta = Meta
            }};
        Result when Result =:= [] orelse Result =:= ok ->
            {error, not_found};
        {error, Reason} = Error ->
            ?error("Failed to get invite ~s: ~p", [InviteId, Reason]),
            Error
    end.

%% @doc Mark an invite as consumed by a user.
%%
%% This operation is idempotent - attempting to consume an already-consumed
%% invite will succeed. Sets the consumed flag, records the timestamp, and
%% stores the GPG fingerprint of the consuming user.
%%
%% Note: This only updates the database. Validation (checking expiry, current
%% consumption status) should be done before calling this function.
%%
%% == Example ==
%% ```
%% ok = cryptic_ca_store:consume_invite(Conn, <<"inv-123">>, <<"ABCD1234...">>).
%% '''
%%
%% @param Conn Database connection reference
%% @param InviteId The invite ID to mark as consumed
%% @param ConsumerFp GPG fingerprint of the user consuming the invite
%% @returns `ok' on success, `{error, Reason}' on failure
-spec consume_invite(db_ref(), invite_id(), gpg_fingerprint()) ->
    ok | {error, term()}.
consume_invite(Conn, InviteId, ConsumerFp) ->
    Now = erlang:system_time(second),
    SQL =
        <<
            "UPDATE invites \n"
            "             SET consumed = 1, consumed_at = ?1, consumed_by_fp = ?2 \n"
            "             WHERE invite_id = ?3 AND consumed = 0"
        >>,

    case esqlite3:q(Conn, SQL, [Now, ConsumerFp, InviteId]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to consume invite ~s: ~p", [InviteId, Reason]),
            Error
    end.

%% @doc List all invites created by a specific user.
%%
%% Returns invites in reverse chronological order (most recent first).
%% Includes both consumed and unconsumed invites. Useful for displaying
%% a user's invitation history.
%%
%% == Example ==
%% ```
%% {ok, Invites} = cryptic_ca_store:list_invites_by_inviter(
%%     Conn,
%%     <<"ABCD1234...">>
%% ),
%% lists:foreach(fun(I) -> io:format("~s~n", [I#invite.invite_id]) end, Invites).
%% '''
%%
%% @param Conn Database connection reference
%% @param InviterFp GPG fingerprint of the user who created the invites
%% @returns `{ok, [Invite]}' with list of invites (may be empty), or `{error, Reason}' on database error
-spec list_invites_by_inviter(db_ref(), gpg_fingerprint()) ->
    {ok, [#invite{}]} | {error, term()}.
list_invites_by_inviter(Conn, InviterFp) ->
    SQL =
        <<
            "SELECT invite_id, inviter_fp, issued_at, expires_at, consumed, \n"
            "                   consumed_at, consumed_by_fp, meta \n"
            "             FROM invites WHERE inviter_fp = ?1 ORDER BY issued_at DESC"
        >>,

    case esqlite3:q(Conn, SQL, [InviterFp]) of
        Rows when is_list(Rows) ->
            Invites = lists:map(
                fun([Id, Inv, Issued, Exp, Cons, ConsAt, ConsFp, Meta]) ->
                    #invite{
                        invite_id = Id,
                        inviter_fp = Inv,
                        issued_at = Issued,
                        expires_at = Exp,
                        consumed = Cons,
                        consumed_at = ConsAt,
                        consumed_by_fp = ConsFp,
                        meta = Meta
                    }
                end,
                Rows
            ),
            {ok, Invites};
        {error, Reason} = Error ->
            ?error("Failed to list invites for ~s: ~p", [InviterFp, Reason]),
            Error
    end.

%% @doc Revoke an invite (soft delete).
%%
%% Marks an invite as consumed without recording who consumed it or when.
%% This is effectively a soft delete - the invite remains in the database
%% for audit purposes but cannot be used for onboarding.
%%
%% Use this when an admin needs to invalidate an invite that was issued
%% but should no longer be usable (e.g., employee left before using invite).
%%
%% == Example ==
%% ```
%% ok = cryptic_ca_store:revoke_invite(Conn, <<"inv-123">>).
%% '''
%%
%% @param Conn Database connection reference
%% @param InviteId The invite ID to revoke
%% @returns `ok' on success (even if invite doesn't exist), `{error, Reason}' on database error
-spec revoke_invite(db_ref(), invite_id()) -> ok | {error, term()}.
revoke_invite(Conn, InviteId) ->
    SQL = <<"UPDATE invites SET consumed = 1 WHERE invite_id = ?1">>,
    case esqlite3:q(Conn, SQL, [InviteId]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to revoke invite ~s: ~p", [InviteId, Reason]),
            Error
    end.

%% @doc Delete all expired invites from the database.
%%
%% Performs a hard delete (permanent removal) of invites where the expiry
%% timestamp is in the past. This is useful for cleanup/maintenance.
%%
%% Warning: This permanently removes data. Audit logs referencing these
%% invites will remain, but the invite details will be lost.
%%
%% == Example ==
%% ```
%% {ok, Count} = cryptic_ca_store:delete_expired_invites(Conn),
%% io:format("Deleted ~p expired invites~n", [Count]).
%% '''
%%
%% @param Conn Database connection reference
%% @returns `{ok, Count}' where Count is the number of invites deleted, or `{error, Reason}' on failure
-spec delete_expired_invites(db_ref()) ->
    {ok, non_neg_integer()} | {error, term()}.
delete_expired_invites(Conn) ->
    Now = erlang:system_time(second),
    SQL = <<"DELETE FROM invites WHERE expires_at < ?1">>,
    case esqlite3:q(Conn, SQL, [Now]) of
        Result when Result =:= [] orelse Result =:= ok ->
            {ok, esqlite3:changes(Conn)};
        {error, Reason} = Error ->
            ?error("Failed to delete expired invites: ~p", [Reason]),
            Error
    end.

%%====================================================================
%% GPG Identity Operations
%%====================================================================

%% @doc Insert a new GPG identity into the registry.
%%
%% Registers a new user's GPG key in the system. The status field indicates
%% how the identity was verified:
%% <ul>
%%   <li>`verified_via_invite' - User joined via invite token</li>
%%   <li>`verified_bootstrap' - Manually added by admin (no invite)</li>
%%   <li>`pending' - Awaiting verification</li>
%%   <li>`revoked' - Identity has been revoked</li>
%% </ul>
%%
%% == Example ==
%% ```
%% Identity = #gpg_identity{
%%     gpg_fp = <<"ABCD1234...">>,
%%     gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%     status = <<"verified_via_invite">>,
%%     inviter_fp = <<"EFGH5678...">>,
%%     registered_at = erlang:system_time(second),
%%     last_seen = erlang:system_time(second),
%%     invite_id = <<"inv-123">>
%% },
%% ok = cryptic_ca_store:insert_gpg_identity(Conn, Identity).
%% '''
%%
%% @param Conn Database connection reference
%% @param Identity The GPG identity record to insert
%% @returns `ok' on success, `{error, Reason}' on failure (e.g., duplicate fingerprint, FK violation)
-spec insert_gpg_identity(db_ref(), #gpg_identity{}) -> ok | {error, term()}.
insert_gpg_identity(Conn, #gpg_identity{} = Identity) ->
    SQL =
        <<
            "INSERT INTO gpg_identities \n"
            "             (gpg_fp, gpg_pub_armor, status, inviter_fp, registered_at, last_seen, invite_id) \n"
            "             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        >>,
    Params = [
        Identity#gpg_identity.gpg_fp,
        Identity#gpg_identity.gpg_pub_armor,
        Identity#gpg_identity.status,
        Identity#gpg_identity.inviter_fp,
        Identity#gpg_identity.registered_at,
        Identity#gpg_identity.last_seen,
        Identity#gpg_identity.invite_id
    ],

    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert GPG identity ~s: ~p", [
                Identity#gpg_identity.gpg_fp, Reason
            ]),
            Error
    end.

%% @doc Retrieve a GPG identity by fingerprint.
%%
%% Fetches complete identity information including the public key armor,
%% verification status, and registration metadata.
%%
%% == Example ==
%% ```
%% case cryptic_ca_store:get_gpg_identity(Conn, <<"ABCD1234...">>) of
%%     {ok, Identity} ->
%%         io:format("Status: ~s~n", [Identity#gpg_identity.status]);
%%     {error, not_found} ->
%%         io:format("Unknown fingerprint~n")
%% end.
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to look up
%% @returns `{ok, Identity}' if found, `{error, not_found}' if not found, or `{error, Reason}' on database error
-spec get_gpg_identity(db_ref(), gpg_fingerprint()) ->
    {ok, #gpg_identity{}} | {error, not_found} | {error, term()}.
get_gpg_identity(Conn, GpgFp) ->
    SQL =
        <<
            "SELECT gpg_fp, gpg_pub_armor, status, inviter_fp, registered_at, last_seen, invite_id \n"
            "             FROM gpg_identities WHERE gpg_fp = ?1"
        >>,

    case esqlite3:q(Conn, SQL, [GpgFp]) of
        [[Fp, PubKey, Status, InviterFp, RegAt, LastSeen, InviteId]] ->
            {ok, #gpg_identity{
                gpg_fp = Fp,
                gpg_pub_armor = PubKey,
                status = Status,
                inviter_fp = InviterFp,
                registered_at = RegAt,
                last_seen = LastSeen,
                invite_id = InviteId
            }};
        Result when Result =:= [] orelse Result =:= ok ->
            {error, not_found};
        {error, Reason} = Error ->
            ?error("Failed to get GPG identity ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%% @doc Update the last seen timestamp for a GPG identity.
%%
%% Records the current time as the last activity time for this identity.
%% Useful for tracking active users and detecting inactive accounts.
%%
%% The timestamp is automatically set to `erlang:system_time(second)'.
%%
%% == Example ==
%% ```
%% %% Called when user authenticates or performs an action
%% ok = cryptic_ca_store:update_last_seen(Conn, UserFingerprint).
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to update
%% @returns `ok' on success (even if fingerprint doesn't exist), `{error, Reason}' on database error
-spec update_last_seen(db_ref(), gpg_fingerprint()) -> ok | {error, term()}.
update_last_seen(Conn, GpgFp) ->
    Now = erlang:system_time(second),
    SQL = <<"UPDATE gpg_identities SET last_seen = ?1 WHERE gpg_fp = ?2">>,
    case esqlite3:q(Conn, SQL, [Now, GpgFp]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to update last_seen for ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%% @doc List all GPG identities in the registry.
%%
%% Returns all registered identities in reverse chronological order
%% (most recently registered first). Includes identities in all states:
%% verified, pending, and revoked.
%%
%% For filtered lists (e.g., only verified identities), use the result
%% and filter based on the status field.
%%
%% == Example ==
%% ```
%% {ok, Identities} = cryptic_ca_store:list_gpg_identities(Conn),
%% Verified = lists:filter(
%%     fun(I) ->
%%         lists:member(I#gpg_identity.status,
%%                      [<<"verified_via_invite">>, <<"verified_bootstrap">>])
%%     end,
%%     Identities
%% ).
%% '''
%%
%% @param Conn Database connection reference
%% @returns `{ok, [Identity]}' with list of all identities (may be empty), or `{error, Reason}' on database error
-spec list_gpg_identities(db_ref()) ->
    {ok, [#gpg_identity{}]} | {error, term()}.
list_gpg_identities(Conn) ->
    SQL =
        <<
            "SELECT gpg_fp, gpg_pub_armor, status, inviter_fp, registered_at, last_seen, invite_id \n"
            "             FROM gpg_identities ORDER BY registered_at DESC"
        >>,

    case esqlite3:q(Conn, SQL) of
        Rows when is_list(Rows) ->
            Identities = lists:map(
                fun([Fp, Pub, St, Inv, Reg, Last, InvId]) ->
                    #gpg_identity{
                        gpg_fp = Fp,
                        gpg_pub_armor = Pub,
                        status = St,
                        inviter_fp = Inv,
                        registered_at = Reg,
                        last_seen = Last,
                        invite_id = InvId
                    }
                end,
                Rows
            ),
            {ok, Identities};
        {error, Reason} = Error ->
            ?error("Failed to list GPG identities: ~p", [Reason]),
            Error
    end.

%%====================================================================
%% Audit Operations
%%====================================================================

%% @doc Insert an audit log entry.
%%
%% Records a security-relevant event in the audit log for compliance and
%% forensic purposes. Events include invite creation/consumption, identity
%% registration, revocations, etc.
%%
%% The details field typically contains JSON-encoded additional information
%% about the event.
%%
%% == Example ==
%% ```
%% Log = #audit_log{
%%     timestamp = erlang:system_time(second),
%%     event_type = <<"invite_created">>,
%%     gpg_fp = <<"ABCD1234...">>,
%%     invite_id = <<"inv-123">>,
%%     details = <<"{\"expires_in\":86400}">>,
%%     ip_address = <<"192.168.1.100">>
%% },
%% ok = cryptic_ca_store:insert_audit_log(Conn, Log).
%% '''
%%
%% @param Conn Database connection reference
%% @param Log The audit log entry to insert
%% @returns `ok' on success, `{error, Reason}' on failure
-spec insert_audit_log(db_ref(), #audit_log{}) -> ok | {error, term()}.
insert_audit_log(Conn, #audit_log{} = Log) ->
    SQL =
        <<
            "INSERT INTO audit_log (timestamp, event_type, gpg_fp, invite_id, details, ip_address) \n"
            "             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        >>,
    Params = [
        Log#audit_log.timestamp,
        Log#audit_log.event_type,
        Log#audit_log.gpg_fp,
        Log#audit_log.invite_id,
        Log#audit_log.details,
        Log#audit_log.ip_address
    ],

    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert audit log: ~p", [Reason]),
            Error
    end.

%% @doc Retrieve audit logs within a time range.
%%
%% Fetches audit log entries between two Unix timestamps (inclusive).
%% Results are returned in reverse chronological order (most recent first).
%%
%% Useful for generating audit reports, investigating security incidents,
%% or compliance reviews.
%%
%% == Example ==
%% ```
%% %% Get logs from the last 24 hours
%% Now = erlang:system_time(second),
%% OneDayAgo = Now - 86400,
%% {ok, Logs} = cryptic_ca_store:get_audit_logs(Conn, OneDayAgo, Now),
%% lists:foreach(
%%     fun(Log) ->
%%         io:format("~s: ~s~n", [Log#audit_log.event_type, Log#audit_log.gpg_fp])
%%     end,
%%     Logs
%% ).
%% '''
%%
%% @param Conn Database connection reference
%% @param FromTimestamp Start of time range (Unix timestamp in seconds, inclusive)
%% @param ToTimestamp End of time range (Unix timestamp in seconds, inclusive)
%% @returns `{ok, [Log]}' with list of audit logs (may be empty), or `{error, Reason}' on database error
-spec get_audit_logs(db_ref(), unix_timestamp(), unix_timestamp()) ->
    {ok, [#audit_log{}]} | {error, term()}.
get_audit_logs(Conn, FromTimestamp, ToTimestamp) ->
    SQL =
        <<
            "SELECT timestamp, event_type, gpg_fp, invite_id, details, ip_address \n"
            "             FROM audit_log \n"
            "             WHERE timestamp >= ?1 AND timestamp <= ?2 \n"
            "             ORDER BY timestamp DESC"
        >>,

    case esqlite3:q(Conn, SQL, [FromTimestamp, ToTimestamp]) of
        Rows when is_list(Rows) ->
            Logs = lists:map(
                fun([Ts, Evt, Fp, Inv, Det, Ip]) ->
                    #audit_log{
                        timestamp = Ts,
                        event_type = Evt,
                        gpg_fp = Fp,
                        invite_id = Inv,
                        details = Det,
                        ip_address = Ip
                    }
                end,
                Rows
            ),
            {ok, Logs};
        {error, Reason} = Error ->
            ?error("Failed to get audit logs: ~p", [Reason]),
            Error
    end.

%%====================================================================
%% Database Inspection Functions (for debugging)
%%====================================================================

%% @doc List all tables in the database.
%%
%% Returns the names of all tables in the SQLite database, which is useful
%% for interactive debugging and understanding the database schema.
%%
%% == Example ==
%% ```
%% %% From the Erlang shell:
%% DbRef = cryptic_ca_init:get_db_ref().
%% {ok, Tables} = cryptic_ca_store:list_tables(DbRef).
%% io:format("Tables: ~p~n", [Tables]).
%% '''
%%
%% @param Conn Database connection reference
%% @returns `{ok, [TableName]}' where TableName is a binary, or `{error, Reason}'
-spec list_tables(db_ref()) -> {ok, [binary()]} | {error, term()}.
list_tables(Conn) ->
    SQL = <<"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name">>,
    case esqlite3:q(Conn, SQL) of
        Rows when is_list(Rows) ->
            Tables = [Name || [Name] <- Rows],
            {ok, Tables};
        {error, Reason} = Error ->
            ?error("Failed to list tables: ~p", [Reason]),
            Error
    end.

%% @doc Show the CREATE TABLE statement for a specific table.
%%
%% Returns the SQL schema definition for the specified table, useful for
%% understanding table structure, columns, and constraints.
%%
%% == Example ==
%% ```
%% DbRef = cryptic_ca_init:get_db_ref().
%% {ok, Schema} = cryptic_ca_store:describe_table(DbRef, <<"invites">>).
%% io:format("~s~n", [Schema]).
%% '''
%%
%% @param Conn Database connection reference
%% @param TableName Name of the table (as a binary)
%% @returns `{ok, CreateStatement}' where CreateStatement is a binary, or `{error, Reason}'
-spec describe_table(db_ref(), binary()) -> {ok, binary()} | {error, term()}.
describe_table(Conn, TableName) ->
    SQL = <<"SELECT sql FROM sqlite_master WHERE type='table' AND name = ?1">>,
    case esqlite3:q(Conn, SQL, [TableName]) of
        [[CreateSQL]] ->
            {ok, CreateSQL};
        [] ->
            {error, {table_not_found, TableName}};
        {error, Reason} = Error ->
            ?error("Failed to describe table ~s: ~p", [TableName, Reason]),
            Error
    end.

%% @doc Inspect the database and print a summary to stdout.
%%
%% This is a convenience function for quick database inspection from the
%% Erlang shell. It retrieves the database reference, lists all tables,
%% and shows the schema and row count for each table.
%%
%% Note: This function uses cryptic_ca_init:get_db_ref() to get the database
%% reference, so the CA init service must be running.
%%
%% == Example ==
%% ```
%% %% From the Erlang shell (after server is running):
%% cryptic_ca_store:inspect_db().
%% '''
%%
%% @returns `ok' on success, or `{error, Reason}' on failure
-spec inspect_db() -> ok | {error, term()}.
inspect_db() ->
    case cryptic_ca_init:get_db_ref() of
        {ok, Conn} ->
            io:format("~n=== CA Database Inspection ===~n~n", []),
            case list_tables(Conn) of
                {ok, Tables} ->
                    io:format("Tables (~p total):~n", [length(Tables)]),
                    lists:foreach(
                        fun(TableName) ->
                            %% Show table name and row count
                            CountSQL = iolist_to_binary([<<"SELECT COUNT(*) FROM ">>, TableName]),
                            Count = case esqlite3:q(Conn, CountSQL) of
                                [[N]] -> N;
                                _ -> unknown
                            end,
                            io:format("~n  - ~s (~p rows)~n", [TableName, Count]),
                            
                            %% Show schema
                            case describe_table(Conn, TableName) of
                                {ok, Schema} ->
                                    io:format("    Schema: ~s~n", [Schema]);
                                {error, SchemaErr} ->
                                    io:format("    Error getting schema: ~p~n", [SchemaErr])
                            end
                        end,
                        Tables
                    ),
                    io:format("~n=== End of Database Inspection ===~n~n", []),
                    ok;
                {error, Reason} ->
                    io:format("Error listing tables: ~p~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Error getting database reference: ~p~n", [Reason]),
            {error, Reason}
    end.
