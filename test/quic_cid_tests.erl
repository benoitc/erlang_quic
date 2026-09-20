%%% -*- erlang -*-
%%%
%%% The connection ID pools (RFC 9000 Section 5.1).
%%%
%%% Sequence 0 is the handshake CID on both sides and counts against the
%%% active_connection_id_limit, so the token-storage cases here start from a
%%% pool that already holds it: a reset token must never be what creates it.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cid_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(OUR_SCID, <<"own-cid0">>).
-define(PEER_SCID, <<1, 2, 3, 4, 5, 6, 7, 8>>).

%%====================================================================
%% The peer's reset token
%%====================================================================

%% The token fills in the sequence-0 entry the peer's Initial installed.
records_token_against_sequence_zero_test() ->
    Token = crypto:strong_rand_bytes(16),
    Pool = quic_cid:record_initial_reset_token(peer_pool(), Token),
    ?assertMatch(
        [
            #cid_entry{
                seq_num = 0, cid = ?PEER_SCID, stateless_reset_token = Token, status = active
            }
        ],
        quic_cid:peer_entries(Pool)
    ).

%% No token leaves the pool untouched.
absent_token_leaves_the_pool_test() ->
    Pool = peer_pool(),
    ?assertEqual(
        quic_cid:peer_entries(Pool),
        quic_cid:peer_entries(quic_cid:record_initial_reset_token(Pool, undefined))
    ).

%% A token alone never creates sequence 0: that entry comes from the peer's
%% Initial, so limit accounting cannot depend on a token the peer may not
%% send. A client never sends one (RFC 9000 Section 18.2).
token_alone_does_not_create_sequence_zero_test() ->
    Empty = quic_cid:new(?OUR_SCID, 2),
    Pool = quic_cid:record_initial_reset_token(Empty, crypto:strong_rand_bytes(16)),
    ?assertEqual([], quic_cid:peer_entries(Pool)).

%% An entry that already carries a token keeps it.
existing_token_is_kept_test() ->
    Pool0 = quic_cid:record_initial_reset_token(peer_pool(), <<9:128>>),
    Pool1 = quic_cid:record_initial_reset_token(Pool0, crypto:strong_rand_bytes(16)),
    ?assertMatch(
        [#cid_entry{seq_num = 0, stateless_reset_token = <<9:128>>}],
        quic_cid:peer_entries(Pool1)
    ).

%%====================================================================
%% Taking the peer's CIDs
%%====================================================================

%% The same sequence with the same CID and token is idempotent, not an
%% error (RFC 9000 Section 19.15).
duplicate_is_idempotent_test() ->
    Token = crypto:strong_rand_bytes(16),
    {ok, Pool1, []} = quic_cid:add_peer_cid(peer_pool(), 1, 0, <<1:64>>, Token),
    ?assertMatch({duplicate, Pool1}, quic_cid:add_peer_cid(Pool1, 1, 0, <<1:64>>, Token)).

%% The same sequence carrying a different CID is a protocol violation.
sequence_reuse_is_reported_test() ->
    {ok, Pool1, []} = quic_cid:add_peer_cid(peer_pool(), 1, 0, <<1:64>>, undefined),
    ?assertEqual(
        {error, {reuse, 1}}, quic_cid:add_peer_cid(Pool1, 1, 0, <<9:64>>, undefined)
    ).

%% The limit counts sequence 0, so a limit of 2 leaves room for one more.
limit_counts_the_handshake_cid_test() ->
    {ok, Pool1, []} = quic_cid:add_peer_cid(peer_pool(), 1, 0, <<1:64>>, undefined),
    ?assertEqual(2, quic_cid:peer_active_count(Pool1)),
    ?assertEqual(
        {error, limit_exceeded}, quic_cid:add_peer_cid(Pool1, 2, 0, <<2:64>>, undefined)
    ).

%% retire_prior_to reports what it retires, and the entries stay until
%% pruned so a retired DCID can still be replaced first.
retirement_reports_sequences_then_prunes_test() ->
    {ok, Pool1, []} = quic_cid:add_peer_cid(peer_pool(), 1, 0, <<1:64>>, undefined),
    {ok, Pool2, ToRetire} = quic_cid:add_peer_cid(Pool1, 2, 2, <<2:64>>, undefined),
    ?assertEqual([0, 1], lists:sort(ToRetire)),
    ?assertEqual(3, length(quic_cid:peer_entries(Pool2))),
    ?assertEqual(
        [2], [
            S
         || #cid_entry{seq_num = S} <- quic_cid:peer_entries(quic_cid:prune_retired_peer(Pool2))
        ]
    ).

%% A retired current DCID is replaced by an active one; an unretired DCID is
%% kept.
replacement_only_for_a_retired_dcid_test() ->
    {ok, Pool1, []} = quic_cid:add_peer_cid(peer_pool(), 1, 0, <<1:64>>, undefined),
    ?assertEqual(keep, quic_cid:replacement_for_retired_dcid(Pool1, <<1:64>>)),
    {ok, Pool2, _} = quic_cid:add_peer_cid(Pool1, 2, 2, <<2:64>>, undefined),
    ?assertEqual({ok, <<2:64>>}, quic_cid:replacement_for_retired_dcid(Pool2, ?PEER_SCID)).

%%====================================================================
%% Issuing our own CIDs
%%====================================================================

%% We issue up to the peer's limit, counting our own sequence 0, and each
%% CID comes back with the sequence number and token to advertise.
issue_fills_the_peer_limit_test() ->
    Pool0 = quic_cid:set_peer_active_limit(quic_cid:new(?OUR_SCID, 2), 3),
    ?assertEqual(2, quic_cid:replenish_needed(Pool0)),
    {Pool1, Issued} = quic_cid:issue(Pool0, quic_cid:replenish_needed(Pool0), undefined),
    ?assertEqual([1, 2], [Seq || {Seq, _CID, _Token} <- Issued]),
    ?assertEqual(3, quic_cid:local_active_count(Pool1)),
    ?assertEqual(0, quic_cid:replenish_needed(Pool1)).

%% Retiring a sequence we never issued is a protocol violation, not a
%% silent no-op (RFC 9000 Section 19.16).
retiring_an_unissued_sequence_is_reported_test() ->
    ?assertEqual({error, unissued}, quic_cid:retire_local(quic_cid:new(?OUR_SCID, 2), 7)).

%% Retirement hands back the CID so the caller can drop it from the
%% listener's routing table.
retire_local_returns_the_cid_test() ->
    {Pool1, [{Seq, CID, _Token}]} = quic_cid:issue(
        quic_cid:set_peer_active_limit(quic_cid:new(?OUR_SCID, 2), 2), 1, undefined
    ),
    ?assertEqual({ok, retired_pool(Pool1, Seq), CID}, quic_cid:retire_local(Pool1, Seq)).

%%====================================================================
%% Reset tokens
%%====================================================================

%% With a secret the token is derived, so a restarted listener holding the
%% same secret recomputes it. Without one it is random.
derived_token_matches_the_listener_test() ->
    Secret = crypto:strong_rand_bytes(32),
    CID = <<10, 11, 12, 13, 14, 15, 16, 17>>,
    ?assertEqual(
        quic_listener:compute_stateless_reset_token(Secret, CID),
        quic_cid:generate_reset_token(CID, Secret)
    ),
    ?assertNotEqual(
        quic_cid:generate_reset_token(CID, undefined),
        quic_cid:generate_reset_token(CID, undefined)
    ).

%% A token we hold matches its CID; an unknown one does not.
reset_token_lookup_test() ->
    Token = crypto:strong_rand_bytes(16),
    Pool = quic_cid:record_initial_reset_token(peer_pool(), Token),
    ?assertEqual({ok, ?PEER_SCID}, quic_cid:find_reset_token_match(Pool, Token)),
    ?assertEqual(
        not_found, quic_cid:find_reset_token_match(Pool, crypto:strong_rand_bytes(16))
    ).

%% An entry without a token is skipped rather than crashing the comparison.
tokenless_entry_is_skipped_test() ->
    ?assertEqual(
        not_found, quic_cid:find_reset_token_match(peer_pool(), crypto:strong_rand_bytes(16))
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% A pool holding both handshake CIDs, as the init paths and adopting the
%% peer's Initial build it.
peer_pool() ->
    quic_cid:set_initial_peer_cid(quic_cid:new(?OUR_SCID, 2), ?PEER_SCID, undefined).

retired_pool(Pool, Seq) ->
    {ok, Retired, _CID} = quic_cid:retire_local(Pool, Seq),
    Retired.
