%%% -*- erlang -*-
%%%
%%% active_connection_id_limit enforcement (RFC 9000 Section 5.1.1).
%%%
%%% These drive quic_connection itself. An earlier version of this module
%%% kept its own #test_state{} and a copy of the NEW_CONNECTION_ID
%%% handler, so it asserted that the copy behaved, and passed throughout
%%% a period when connection-id rotation did not work at all. The copy
%%% also returned `{error, {connection_id_limit_error, _, _}}', an answer
%%% the real code never gives: it closes the connection with
%%% CONNECTION_ID_LIMIT_ERROR.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_cid_limit_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Accepting peer CIDs
%%====================================================================

%% Sequence 0 is the CID the peer used for the handshake and counts
%% against the limit, so a limit of 3 leaves room for two more.
new_cid_within_limit_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(2, 0, <<2:64>>, S1),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    ?assertEqual(3, active_count(S2)).

%% One CID past the limit is a connection error, not a rejected frame.
new_cid_exceeds_limit_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(2),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(2, 0, <<2:64>>, S1),
    ?assertMatch(
        {transport, ?QUIC_CONNECTION_ID_LIMIT_ERROR, _},
        quic_connection_test_support:close_reason(S2)
    ).

%% retire_prior_to frees room in the same frame that fills it.
new_cid_with_retirement_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(2),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    %% Sequence 2 retires everything below 2, so 0 and 1 go and 2 stays.
    S2 = new_cid(2, 2, <<2:64>>, S1),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    ?assertEqual(1, active_count(S2)),
    %% Retired entries are pruned, not kept with a retired status.
    ?assertEqual(1, length(quic_connection_test_support:peer_cids(S2))).

%% A repeated sequence number with the same CID and token is ignored.
duplicate_seq_ignored_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    CID = <<1:64>>,
    Token = crypto:strong_rand_bytes(16),
    S1 = quic_connection:process_frame(
        app, {new_connection_id, 1, 0, CID, Token}, S0
    ),
    S2 = quic_connection:process_frame(
        app, {new_connection_id, 1, 0, CID, Token}, S1
    ),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    ?assertEqual(2, active_count(S2)).

%% Same sequence number carrying a different CID is a protocol violation
%% (RFC 9000 Section 19.15), distinct from the duplicate case above.
duplicate_seq_different_cid_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(1, 0, <<9:64>>, S1),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection_test_support:close_reason(S2)
    ).

%% The limit is whatever we advertised, not a constant.
higher_limit_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(8),
    Filled = lists:foldl(
        fun(Seq, Acc) -> new_cid(Seq, 0, <<Seq:64>>, Acc) end,
        S0,
        lists:seq(1, 7)
    ),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(Filled)),
    ?assertEqual(8, active_count(Filled)),
    Over = new_cid(8, 0, <<8:64>>, Filled),
    ?assertMatch(
        {transport, ?QUIC_CONNECTION_ID_LIMIT_ERROR, _},
        quic_connection_test_support:close_reason(Over)
    ).

%% A limit of 1 means the handshake CID and nothing else.
minimum_limit_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(1),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    ?assertMatch(
        {transport, ?QUIC_CONNECTION_ID_LIMIT_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%%====================================================================
%% The peer's handshake CID (RFC 9000 Section 18.2)
%%
%% active_connection_id_limit includes the CID the peer used during the
%% handshake. These start from an empty peer pool, as the init paths
%% leave it, so sequence 0 has to come from adopting the peer's Initial.
%%====================================================================

%% Server: a limit of 2 is the client's handshake CID plus one more.
server_counts_peer_handshake_cid_test() ->
    S0 = quic_connection_test_support:state_before_initial(server, 2),
    S1 = quic_connection:adopt_peer_scid(<<"client-scid">>, S0),
    S2 = new_cid(1, 0, <<1:64>>, S1),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    S3 = new_cid(2, 0, <<2:64>>, S2),
    ?assertMatch(
        {transport, ?QUIC_CONNECTION_ID_LIMIT_ERROR, _},
        quic_connection_test_support:close_reason(S3)
    ).

%% Client: the same, with the server's handshake CID.
client_counts_peer_handshake_cid_test() ->
    S0 = quic_connection_test_support:state_before_initial(client, 2),
    S1 = quic_connection:adopt_peer_scid(<<"server-scid">>, S0),
    S2 = new_cid(1, 0, <<1:64>>, S1),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    S3 = new_cid(2, 0, <<2:64>>, S2),
    ?assertMatch(
        {transport, ?QUIC_CONNECTION_ID_LIMIT_ERROR, _},
        quic_connection_test_support:close_reason(S3)
    ).

%% Adopting the peer's Initial records it as sequence 0 and switches to it.
adopting_initial_installs_sequence_zero_test() ->
    S0 = quic_connection_test_support:state_before_initial(client, 2),
    S1 = quic_connection:adopt_peer_scid(<<"server-scid">>, S0),
    ?assertEqual(<<"server-scid">>, quic_connection_test_support:state_get(S1, dcid)),
    ?assertMatch(
        [#cid_entry{seq_num = 0, cid = <<"server-scid">>, status = active}],
        quic_connection_test_support:peer_cids(S1)
    ).

%% After a Retry the DCID is the Retry SCID, which has no sequence number.
%% Sequence 0 is the SCID of the server Initial that follows, and it is
%% the only entry.
retry_scid_is_not_sequence_zero_test() ->
    S0 = quic_connection_test_support:state_before_initial(client, 2),
    S1 = quic_connection_test_support:state_set(S0, dcid, <<"retry-scid">>),
    AfterRetry = quic_connection_test_support:state_set(S1, retry_scid, <<"retry-scid">>),
    ?assertEqual([], quic_connection_test_support:peer_cids(AfterRetry)),
    S2 = quic_connection:adopt_peer_scid(<<"server-scid">>, AfterRetry),
    ?assertMatch(
        [#cid_entry{seq_num = 0, cid = <<"server-scid">>}],
        quic_connection_test_support:peer_cids(S2)
    ).

%% Later Initials do not re-adopt or duplicate sequence 0.
adoption_happens_once_test() ->
    S0 = quic_connection_test_support:state_before_initial(client, 2),
    S1 = quic_connection:adopt_peer_scid(<<"server-scid">>, S0),
    S2 = quic_connection:adopt_peer_scid(<<"other-scid">>, S1),
    ?assertEqual(<<"server-scid">>, quic_connection_test_support:state_get(S2, dcid)),
    ?assertEqual(1, length(quic_connection_test_support:peer_cids(S2))).

%%====================================================================
%% Retiring peer CIDs (RFC 9000 Section 19.16)
%%====================================================================

%% retire_prior_to must be answered with RETIRE_CONNECTION_ID for every
%% sequence it retires, or the peer keeps counting them against the
%% limit it advertised.
retire_prior_to_sends_retire_frames_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(2, 2, <<2:64>>, S1),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)),
    ?assertEqual([0, 1], retired_seqs(S2)).

%% Only sequences below retire_prior_to go; the frame's own CID stays.
retire_frames_only_for_retired_seqs_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(4),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(2, 0, <<2:64>>, S1),
    S3 = new_cid(3, 2, <<3:64>>, S2),
    ?assertEqual([0, 1], retired_seqs(S3)),
    ?assertEqual(
        [2, 3],
        lists:sort([S || #cid_entry{seq_num = S} <- quic_connection_test_support:peer_cids(S3)])
    ).

%% A frame retiring nothing sends nothing.
no_retirement_sends_nothing_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    ?assertEqual([], retired_seqs(S1)).

%% When the CID we send with is retired, we switch to a live one before
%% announcing the retirement: a packet still carrying the retired DCID
%% would be unroutable at the peer.
retiring_current_dcid_switches_it_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    ?assertEqual(<<"peer-cid">>, quic_connection_test_support:state_get(S0, dcid)),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = new_cid(2, 2, <<2:64>>, S1),
    ?assertEqual(<<2:64>>, quic_connection_test_support:state_get(S2, dcid)),
    ?assertEqual([0, 1], retired_seqs(S2)).

%%====================================================================
%% Issuing our own CIDs
%%====================================================================

%% We issue up to the peer's limit, counting our sequence 0.
issue_respects_peer_limit_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(2),
    S1 = quic_connection_test_support:state_set(S0, peer_active_cid_limit, 3),
    S2 = quic_connection:issue_new_connection_ids(S1),
    ?assertEqual(3, length(quic_connection_test_support:local_cids(S2))).

%% Already at the peer's limit: nothing new goes out.
issue_at_peer_limit_is_noop_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(2),
    S1 = quic_connection_test_support:state_set(S0, peer_active_cid_limit, 1),
    S2 = quic_connection:issue_new_connection_ids(S1),
    ?assertEqual(
        length(quic_connection_test_support:local_cids(S1)),
        length(quic_connection_test_support:local_cids(S2))
    ).

%%====================================================================
%% Migrating to a new path (RFC 9000 Section 9.5)
%%====================================================================

%% Moving to a new path retires the CID the old path used, or it keeps
%% counting against the limit we advertised and is never pruned.
migration_retires_the_abandoned_cid_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = quic_connection:migrate_to({{127, 0, 0, 1}, 4433}, S1),
    ?assertEqual([0], retired_seqs(S2)),
    ?assertEqual(
        [1], [S || #cid_entry{seq_num = S} <- quic_connection_test_support:peer_cids(S2)]
    ).

%% The new path's CID is in use from its first packet, not adopted later:
%% a PATH_CHALLENGE still carrying the old CID is exactly the linkage
%% Section 9.5 exists to prevent.
migration_switches_the_dcid_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    ?assertEqual(<<"peer-cid">>, quic_connection_test_support:state_get(S1, dcid)),
    S2 = quic_connection:migrate_to({{127, 0, 0, 1}, 4433}, S1),
    ?assertEqual(<<1:64>>, quic_connection_test_support:state_get(S2, dcid)).

%% A CID spent on one path is never offered to another, so a second
%% migration with nothing left does not fall back to reuse.
second_migration_finds_no_cid_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = new_cid(1, 0, <<1:64>>, S0),
    S2 = quic_connection:migrate_to({{127, 0, 0, 1}, 4433}, S1),
    ?assertEqual(false, quic_connection:has_unused_cid(S2)),
    S3 = quic_connection:migrate_to({{127, 0, 0, 1}, 4434}, S2),
    ?assertEqual(<<1:64>>, quic_connection_test_support:state_get(S3, dcid)).

%% With only the handshake CID there is nothing to migrate onto.
migration_without_a_spare_cid_is_refused_test() ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    ?assertEqual(false, quic_connection:has_unused_cid(S0)),
    S1 = quic_connection:migrate_to({{127, 0, 0, 1}, 4433}, S0),
    ?assertEqual(<<"peer-cid">>, quic_connection_test_support:state_get(S1, dcid)),
    ?assertEqual([], retired_seqs(S1)).

%%====================================================================
%% Helpers
%%====================================================================

new_cid(SeqNum, RetirePrior, CID, State) ->
    Token = crypto:strong_rand_bytes(16),
    quic_connection:process_frame(
        app, {new_connection_id, SeqNum, RetirePrior, CID, Token}, State
    ).

%% Sequence numbers of the RETIRE_CONNECTION_ID frames queued to send.
retired_seqs(State) ->
    [
        Seq
     || {retire_connection_id, Seq} <- quic_connection_test_support:pending_frames(State)
    ].

active_count(State) ->
    length([
        E
     || #cid_entry{status = active} = E <- quic_connection_test_support:peer_cids(State)
    ]).
