%% @doc Cryptic Invite Manager - Invite Token Lifecycle Management
%%
%% This module manages the lifecycle of invite tokens, including creation,
%% validation, consumption, and expiration.
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_invite_mgr).

-include("cryptic_ca.hrl").

-export([
    generate_invite_id/0,
    create_invite/4,
    validate_invite/2,
    consume_invite/3,
    register_gpg_for_invite/3,
    list_user_invites/2,
    revoke_invite/2,
    cleanup_expired_invites/1
]).

-include("cryptic_server.hrl").

-type db_ref() :: pid().
-type invite_id() :: binary().
-type gpg_fingerprint() :: binary().
-type invite_metadata() :: #{binary() => term()}.

%%====================================================================
%% API
%%====================================================================

%% @doc Generate a unique invite ID.
%%
%% Creates a cryptographically unique invite identifier using UUID v4.
%% The ID is prefixed with "inv-" for easy identification in logs and
%% user interfaces.
%%
%% == Format ==
%% The generated ID follows the pattern: `<<"inv-", UUID>>'
%% where UUID is a standard RFC 4122 UUID v4 in string format.
%%
%% == Example ==
%% ```
%% InviteId = cryptic_invite_mgr:generate_invite_id(),
%% %% Returns: <<"inv-550e8400-e29b-41d4-a716-446655440000">>
%% '''
%%
%% @returns A unique binary invite ID
-spec generate_invite_id() -> invite_id().
generate_invite_id() ->
    %% Generate a unique invite ID using UUID
    Uuid = uuid:get_v4(),
    UuidStr = uuid:uuid_to_string(Uuid, binary_standard),
    <<"inv-", UuidStr/binary>>.

%% @doc Create a new invite token for user onboarding.
%%
%% Generates a new invite that can be shared with prospective users to allow
%% them to join the system. The invite includes an expiration time and optional
%% metadata (e.g., intended role, department, permissions).
%%
%% This function performs three operations atomically:
%% <ol>
%%   <li>Generates a unique invite ID</li>
%%   <li>Stores the invite in the database</li>
%%   <li>Creates an audit log entry</li>
%% </ol>
%%
%% == Expiry Time ==
%% The `ExpiryHours' parameter specifies how many hours from now the invite
%% will remain valid. After expiration, the invite cannot be used for onboarding.
%%
%% == Metadata ==
%% The metadata map can contain any additional information needed for the
%% onboarding process. It will be JSON-encoded and stored with the invite.
%% Common use cases:
%% <ul>
%%   <li>`#{<<"role">> => <<"admin">>}' - Assign a specific role</li>
%%   <li>`#{<<"department">> => <<"engineering">>}' - Track org structure</li>
%%   <li>`#{<<"max_uses">> => 1}' - Future: limit invite reuse</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% Create an invite valid for 24 hours with role metadata
%% {ok, InviteId} = cryptic_invite_mgr:create_invite(
%%     DbRef,
%%     <<"ABCD1234...">>,  % Inviter's GPG fingerprint
%%     24,                 % Valid for 24 hours
%%     #{<<"role">> => <<"user">>, <<"team">> => <<"backend">>}
%% ),
%% io:format("Share this invite: ~s~n", [InviteId]).
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviterFp GPG fingerprint of the user creating the invite
%% @param ExpiryHours Number of hours until the invite expires (must be positive)
%% @param Meta Optional metadata map (use `#{}' for no metadata)
%% @returns `{ok, InviteId}' with the new invite ID, or `{error, Reason}' on failure
-spec create_invite(
    db_ref(), gpg_fingerprint(), pos_integer(), invite_metadata()
) ->
    {ok, invite_id()} | {error, term()}.
create_invite(DbRef, InviterFp, ExpiryHours, Meta) ->
    InviteId = generate_invite_id(),
    Now = erlang:system_time(second),
    ExpiresAt = Now + (ExpiryHours * 3600),

    %% Encode metadata as JSON if provided
    MetaJson =
        case maps:size(Meta) of
            0 -> undefined;
            _ -> jsx:encode(Meta)
        end,

    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = InviterFp,
        issued_at = Now,
        expires_at = ExpiresAt,
        status = <<"active">>,
        meta = MetaJson
    },

    case cryptic_ca_store:insert_invite(DbRef, Invite) of
        ok ->
            ?info(
                "Created invite ~s by ~s, expires at ~p",
                [InviteId, InviterFp, ExpiresAt]
            ),

            %% Audit log
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"invite_created">>,
                gpg_fp = InviterFp,
                invite_id = InviteId,
                details = MetaJson,
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            {ok, InviteId};
        {error, Reason} = Error ->
            ?error("Failed to create invite: ~p", [Reason]),
            Error
    end.

%% @doc Validate an invite token for onboarding.
%%
%% Checks whether an invite is valid and can be used for user registration.
%% Validation includes checking:
%% <ul>
%%   <li>The invite exists in the database</li>
%%   <li>The invite has not already been consumed</li>
%%   <li>The invite has not expired</li>
%% </ul>
%%
%% This function does NOT consume the invite - it only validates it. To actually
%% use the invite, call {@link consume_invite/3} after validation succeeds.
%%
%% == Return Value ==
%% On success, returns the GPG fingerprint of the user who created the invite.
%% This can be useful for establishing trust chains or attribution.
%%
%% == Example ==
%% ```
%% case cryptic_invite_mgr:validate_invite(DbRef, InviteId) of
%%     {ok, InviterFp} ->
%%         %% Invite is valid, proceed with onboarding
%%         io:format("Valid invite created by: ~s~n", [InviterFp]),
%%         register_new_user(DbRef, InviteId, NewUserFp);
%%     {error, already_consumed} ->
%%         {error, "This invite has already been used"};
%%     {error, expired} ->
%%         {error, "This invite has expired"};
%%     {error, not_found} ->
%%         {error, "Invalid invite code"}
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviteId The invite ID to validate
%% @returns `{ok, InviterFp}' where InviterFp is the creator's fingerprint, or
%%          `{error, already_consumed}' if consumed,
%%          `{error, expired}' if expired,
%%          `{error, not_found}' if the invite doesn't exist,
%%          or `{error, Reason}' for other database errors
-spec validate_invite(db_ref(), invite_id()) ->
    {ok, gpg_fingerprint()} | {error, term()}.
validate_invite(DbRef, InviteId) ->
    case cryptic_ca_store:get_invite(DbRef, InviteId) of
        {ok, Invite} ->
            Now = erlang:system_time(second),

            %% Check if already consumed or revoked
            if
                Invite#invite.status =:= <<"consumed">> ->
                    ?warning("Invite ~s already consumed", [InviteId]),
                    {error, already_consumed};
                Invite#invite.status =:= <<"revoked">> ->
                    ?warning("Invite ~s has been revoked", [InviteId]),
                    {error, revoked};
                Invite#invite.status =:= <<"expired">> ->
                    ?warning("Invite ~s has expired", [InviteId]),
                    {error, expired};
                %% Check if expired
                Invite#invite.expires_at < Now ->
                    ?warning(
                        "Invite ~s expired at ~p",
                        [InviteId, Invite#invite.expires_at]
                    ),
                    {error, expired};
                %% Valid invite
                true ->
                    {ok, Invite#invite.inviter_fp}
            end;
        {error, not_found} ->
            ?warning("Invite ~s not found", [InviteId]),
            {error, not_found};
        {error, Reason} = Error ->
            ?error("Failed to validate invite ~s: ~p", [InviteId, Reason]),
            Error
    end.

%% @doc Register a GPG key for an invite (active → registered transition).
%%
%% This is the first step in the invite lifecycle after creation. When a user
%% registers their GPG key using an invite token, the invite transitions from
%% 'active' to 'registered' state.
%%
%% == State Transition ==
%% <ul>
%%   <li>Initial state: `active'</li>
%%   <li>Final state: `registered'</li>
%%   <li>Records: GPG fingerprint and timestamp</li>
%% </ul>
%%
%% == Validation ==
%% The invite must be:
%% <ul>
%%   <li>In `active' state (not already registered)</li>
%%   <li>Not expired</li>
%%   <li>Not revoked</li>
%% </ul>
%%
%% == Example ==
%% ```
%% case cryptic_invite_mgr:register_gpg_for_invite(DbRef, InviteId, GpgFp) of
%%     ok -> {ok, "GPG registered, proceed to CSR"};
%%     {error, already_registered} -> {error, "This invite already has a GPG key"}
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviteId The invite ID
%% @param GpgFp GPG fingerprint being registered
%% @returns `ok' on success, or `{error, Reason}' on failure
-spec register_gpg_for_invite(db_ref(), invite_id(), gpg_fingerprint()) ->
    ok | {error, term()}.
register_gpg_for_invite(DbRef, InviteId, GpgFp) ->
    case validate_invite(DbRef, InviteId) of
        {ok, _InviterFp} ->
            Metadata = #{gpg_fp => GpgFp, event => <<"gpg_registration">>},
            case cryptic_ca_store:update_invite_status(DbRef, InviteId, register_gpg, Metadata) of
                ok ->
                    ?info("GPG ~s registered for invite ~s (active→registered)", [GpgFp, InviteId]),
                    AuditLog = #audit_log{
                        timestamp = erlang:system_time(second),
                        event_type = <<"invite_gpg_registered">>,
                        gpg_fp = GpgFp,
                        invite_id = InviteId,
                        details = undefined,
                        ip_address = undefined
                    },
                    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
                    ok;
                {error, Reason} = Error ->
                    ?error("Failed to register GPG for invite ~s: ~p", [InviteId, Reason]),
                    Error
            end;
        {error, _Reason} = Error ->
            Error
    end.

%% @doc Consume an invite token during user onboarding.
%%
%% Marks an invite as used and records who consumed it. This function performs
%% validation before consumption, so you don't need to call {@link validate_invite/2}
%% separately.
%%
%% The operation is atomic and creates an audit log entry for compliance tracking.
%%
%% == Validation ==
%% The function automatically validates the invite before consuming it, checking:
%% <ul>
%%   <li>Invite exists</li>
%%   <li>Not already consumed</li>
%%   <li>Not expired</li>
%% </ul>
%%
%% == Audit Trail ==
%% Creates an `invite_consumed' audit log entry recording:
%% <ul>
%%   <li>Timestamp of consumption</li>
%%   <li>GPG fingerprint of the consumer</li>
%%   <li>Invite ID that was consumed</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% During user registration flow
%% case cryptic_invite_mgr:consume_invite(DbRef, InviteId, NewUserFp) of
%%     ok ->
%%         %% Invite consumed successfully, continue registration
%%         register_user_gpg_key(DbRef, NewUserFp, PubKey);
%%     {error, already_consumed} ->
%%         {error, "This invite has already been used"};
%%     {error, expired} ->
%%         {error, "This invite has expired"};
%%     {error, not_found} ->
%%         {error, "Invalid invite code"}
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviteId The invite ID to consume
%% @param ConsumerFp GPG fingerprint of the user consuming the invite
%% @returns `ok' on successful consumption, or `{error, Reason}' on validation/database failure
-spec consume_invite(db_ref(), invite_id(), gpg_fingerprint()) ->
    ok | {error, term()}.
consume_invite(DbRef, InviteId, ConsumerFpOrSerial) ->
    %% First validate the invite
    case validate_invite(DbRef, InviteId) of
        {ok, _InviterFp} ->
            %% For now, treat ConsumerFpOrSerial as cert_serial
            Metadata = #{cert_serial => ConsumerFpOrSerial, event => <<"cert_issued">>},
            case cryptic_ca_store:update_invite_status(DbRef, InviteId, csr, Metadata) of
                ok ->
                    ?info("Invite ~s consumed with cert serial ~s (registered→consumed)", [InviteId, ConsumerFpOrSerial]),

                    %% Audit log
                    AuditLog = #audit_log{
                        timestamp = erlang:system_time(second),
                        event_type = <<"invite_consumed">>,
                        gpg_fp = undefined,
                        invite_id = InviteId,
                        details = jsx:encode(#{cert_serial => ConsumerFpOrSerial}),
                        ip_address = undefined
                    },
                    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
                    ok;
                {error, ConsumeReason} = ConsumeError ->
                    ?error("Failed to consume invite ~s: ~p", [
                        InviteId, ConsumeReason
                    ]),
                    ConsumeError
            end;
        {error, _Reason} = Error ->
            Error
    end.

%% @doc List all invites created by a specific user.
%%
%% Retrieves a user's invitation history with enriched metadata for display
%% in user interfaces. Each invite includes computed fields for convenience:
%% <ul>
%%   <li>`consumed' - Boolean indicating if the invite was used</li>
%%   <li>`expired' - Boolean indicating if the invite has expired</li>
%%   <li>`meta' - Decoded JSON metadata as an Erlang map</li>
%% </ul>
%%
%% The list is sorted in reverse chronological order (most recent first).
%%
%% == Return Format ==
%% Each invite is returned as a map with the following keys:
%% ```
%% #{
%%     invite_id => binary(),
%%     issued_at => unix_timestamp(),
%%     expires_at => unix_timestamp(),
%%     consumed => boolean(),
%%     consumed_at => unix_timestamp() | undefined,
%%     consumed_by_fp => binary() | undefined,
%%     expired => boolean(),
%%     meta => map()
%% }
%% '''
%%
%% == Example ==
%% ```
%% {ok, Invites} = cryptic_invite_mgr:list_user_invites(DbRef, UserFp),
%% lists:foreach(
%%     fun(Invite) ->
%%         Status = if
%%             maps:get(consumed, Invite) -> "used";
%%             maps:get(expired, Invite) -> "expired";
%%             true -> "active"
%%         end,
%%         io:format("~s: ~s~n", [maps:get(invite_id, Invite), Status])
%%     end,
%%     Invites
%% ).
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviterFp GPG fingerprint of the user who created the invites
%% @returns `{ok, [InviteInfo]}' with list of invite maps (may be empty), or `{error, Reason}' on database error
-spec list_user_invites(db_ref(), gpg_fingerprint()) ->
    {ok, [map()]} | {error, term()}.
list_user_invites(DbRef, InviterFp) ->
    case cryptic_ca_store:list_invites_by_inviter(DbRef, InviterFp) of
        {ok, Invites} ->
            Now = erlang:system_time(second),
            InviteInfos = lists:map(
                fun(Invite) ->
                    #{
                        invite_id => Invite#invite.invite_id,
                        issued_at => Invite#invite.issued_at,
                        expires_at => Invite#invite.expires_at,
                        status => Invite#invite.status,
                        registered_at => Invite#invite.registered_at,
                        registered_by_fp => Invite#invite.registered_by_fp,
                        consumed_at => Invite#invite.consumed_at,
                        consumed_cert_serial => Invite#invite.consumed_cert_serial,
                        expired => Invite#invite.expires_at < Now,
                        meta =>
                            case Invite#invite.meta of
                                undefined -> #{};
                                JsonBin -> jsx:decode(JsonBin, [return_maps])
                            end
                    }
                end,
                Invites
            ),
            {ok, InviteInfos};
        {error, _Reason} = Error ->
            Error
    end.

%% @doc Revoke an invite to prevent it from being used.
%%
%% Invalidates an invite by marking it as consumed without recording a consumer.
%% This is a soft delete operation - the invite remains in the database for
%% audit purposes but cannot be used for onboarding.
%%
%% Creates an audit log entry recording the revocation.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Canceling an invite sent to the wrong person</li>
%%   <li>Invalidating an invite after a candidate declined the offer</li>
%%   <li>Security incident requiring invite invalidation</li>
%%   <li>Admin action to clean up unused invites</li>
%% </ul>
%%
%% == Idempotency ==
%% This operation is idempotent - revoking an already-revoked or already-consumed
%% invite will succeed without error.
%%
%% == Example ==
%% ```
%% %% Revoke an unused invite
%% case cryptic_invite_mgr:revoke_invite(DbRef, InviteId) of
%%     ok ->
%%         io:format("Invite ~s has been revoked~n", [InviteId]);
%%     {error, Reason} ->
%%         io:format("Failed to revoke: ~p~n", [Reason])
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param InviteId The invite ID to revoke
%% @returns `ok' on success (even if already revoked/consumed), or `{error, Reason}' on database error
-spec revoke_invite(db_ref(), invite_id()) -> ok | {error, term()}.
revoke_invite(DbRef, InviteId) ->
    revoke_invite(DbRef, InviteId, <<"Admin revoked">>).

%% @doc Revoke an invite with a specific reason.
%%
%% @param DbRef Database connection reference
%% @param InviteId The invite ID to revoke
%% @param Reason Human-readable reason for revocation
%% @returns `ok' on success, or `{error, Reason}' on database error
-spec revoke_invite(db_ref(), invite_id(), binary()) -> ok | {error, term()}.
revoke_invite(DbRef, InviteId, Reason) ->
    Metadata = #{reason => Reason, revoked_by => undefined},
    case cryptic_ca_store:update_invite_status(DbRef, InviteId, revoke, Metadata) of
        ok ->
            ?info("Invite ~s revoked: ~s", [InviteId, Reason]),

            %% Audit log
            AuditLog = #audit_log{
                timestamp = erlang:system_time(second),
                event_type = <<"invite_revoked">>,
                gpg_fp = undefined,
                invite_id = InviteId,
                details = jsx:encode(#{reason => Reason}),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
            ok;
        {error, Reason} = Error ->
            ?error("Failed to revoke invite ~s: ~p", [InviteId, Reason]),
            Error
    end.

%% @doc Clean up expired invites from the database.
%%
%% Permanently deletes all invites that have passed their expiration time.
%% This is a maintenance operation typically run periodically (e.g., daily cron job).
%%
%% == Important Notes ==
%% <ul>
%%   <li>This is a HARD DELETE - data is permanently removed</li>
%%   <li>Audit log entries referencing deleted invites will remain</li>
%%   <li>Consumed invites are NOT deleted, only expired unconsumed ones</li>
%% </ul>
%%
%% == Recommended Schedule ==
%% Run this cleanup operation daily or weekly depending on invite volume:
%% <ul>
%%   <li>Low volume (less than 100 invites/week): Weekly cleanup</li>
%%   <li>Medium volume (100-1000/week): Daily cleanup</li>
%%   <li>High volume (more than 1000/week): Multiple times daily</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% Scheduled cleanup task
%% cleanup_expired_invites() ->
%%     {ok, DbRef} = cryptic_ca_store:init("data/ca.db"),
%%     case cryptic_invite_mgr:cleanup_expired_invites(DbRef) of
%%         {ok, Count} ->
%%             logger:info("Cleaned up ~p expired invites", [Count]),
%%             cryptic_ca_store:close(DbRef),
%%             {ok, Count};
%%         {error, Reason} ->
%%             logger:error("Cleanup failed: ~p", [Reason]),
%%             cryptic_ca_store:close(DbRef),
%%             {error, Reason}
%%     end.
%% '''
%%
%% @param DbRef Database connection reference
%% @returns `{ok, Count}' where Count is the number of invites deleted, or `{error, Reason}' on failure
-spec cleanup_expired_invites(db_ref()) ->
    {ok, non_neg_integer()} | {error, term()}.
cleanup_expired_invites(DbRef) ->
    case cryptic_ca_store:delete_expired_invites(DbRef) of
        {ok, Count} ->
            ?info("Deleted ~p expired invites", [Count]),
            {ok, Count};
        {error, CleanupReason} = CleanupError ->
            ?error("Failed to cleanup expired invites: ~p", [CleanupReason]),
            CleanupError
    end.

%%====================================================================
%% Internal functions
%%====================================================================
