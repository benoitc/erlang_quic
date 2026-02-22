%%% -*- erlang -*-
%%%
%%% QUIC Connection ID Limit Tests
%%% RFC 9000 Section 5.1.1 - Issuing Connection IDs
%%%
%%% This module tests active_connection_id_limit enforcement.
%%%

-module(quic_cid_limit_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% Test-only state record (mirrors relevant fields from quic_connection)
-record(test_state, {
    peer_cid_pool = [] :: [#cid_entry{}],
    local_active_cid_limit = 2 :: non_neg_integer(),
    peer_active_cid_limit = 2 :: non_neg_integer(),
    transport_params = #{} :: map()
}).

%%====================================================================
%% NEW_CONNECTION_ID Limit Enforcement (RFC 9000 Section 5.1.1)
%%====================================================================

%% Test accepting CIDs up to limit
new_cid_within_limit_test() ->
    State = mock_state(2),

    %% First CID should be accepted
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token1 = crypto:strong_rand_bytes(16),
    {ok, State1} = handle_new_connection_id(0, 0, CID1, Token1, State),

    %% Second CID should also be accepted
    CID2 = <<2, 3, 4, 5, 6, 7, 8, 9>>,
    Token2 = crypto:strong_rand_bytes(16),
    {ok, State2} = handle_new_connection_id(1, 0, CID2, Token2, State1),

    %% Verify both CIDs are stored
    Pool = State2#test_state.peer_cid_pool,
    ?assertEqual(2, length(Pool)),
    ?assert(lists:keymember(CID1, #cid_entry.cid, Pool)),
    ?assert(lists:keymember(CID2, #cid_entry.cid, Pool)).

%% Test rejecting CIDs that exceed limit
new_cid_exceeds_limit_test() ->
    State = mock_state(2),

    %% Add two CIDs (at limit)
    CID1 = <<1, 1, 1, 1, 1, 1, 1, 1>>,
    CID2 = <<2, 2, 2, 2, 2, 2, 2, 2>>,
    Token1 = crypto:strong_rand_bytes(16),
    Token2 = crypto:strong_rand_bytes(16),

    {ok, State1} = handle_new_connection_id(0, 0, CID1, Token1, State),
    {ok, State2} = handle_new_connection_id(1, 0, CID2, Token2, State1),

    %% Third CID should exceed limit
    CID3 = <<3, 3, 3, 3, 3, 3, 3, 3>>,
    Token3 = crypto:strong_rand_bytes(16),
    Result = handle_new_connection_id(2, 0, CID3, Token3, State2),

    ?assertEqual({error, {connection_id_limit_error, 3, 2}}, Result).

%% Test limit with retirement (should allow new CID if old ones retired)
new_cid_with_retirement_test() ->
    State = mock_state(2),

    %% Add two CIDs
    CID1 = <<1, 1, 1, 1, 1, 1, 1, 1>>,
    CID2 = <<2, 2, 2, 2, 2, 2, 2, 2>>,
    Token1 = crypto:strong_rand_bytes(16),
    Token2 = crypto:strong_rand_bytes(16),

    {ok, State1} = handle_new_connection_id(0, 0, CID1, Token1, State),
    {ok, State2} = handle_new_connection_id(1, 0, CID2, Token2, State1),

    %% Add third CID with RetirePrior=1 (retires seq 0)
    CID3 = <<3, 3, 3, 3, 3, 3, 3, 3>>,
    Token3 = crypto:strong_rand_bytes(16),
    Result = handle_new_connection_id(2, 1, CID3, Token3, State2),

    %% Should succeed because CID1 is retired
    ?assertMatch({ok, _}, Result),
    {ok, State3} = Result,

    %% Check pool state
    Pool = State3#test_state.peer_cid_pool,
    ActiveCIDs = [E || #cid_entry{status = active} = E <- Pool],
    ?assertEqual(2, length(ActiveCIDs)).

%% Test duplicate sequence number is ignored
duplicate_seq_ignored_test() ->
    State = mock_state(2),

    CID1 = <<1, 1, 1, 1, 1, 1, 1, 1>>,
    Token1 = crypto:strong_rand_bytes(16),
    {ok, State1} = handle_new_connection_id(0, 0, CID1, Token1, State),

    %% Same seq num with different CID should be ignored
    CID2 = <<9, 9, 9, 9, 9, 9, 9, 9>>,
    Token2 = crypto:strong_rand_bytes(16),
    {ok, State2} = handle_new_connection_id(0, 0, CID2, Token2, State1),

    %% Pool should still have only CID1
    Pool = State2#test_state.peer_cid_pool,
    ?assertEqual(1, length(Pool)),
    [Entry] = Pool,
    ?assertEqual(CID1, Entry#cid_entry.cid).

%% Test higher limits
higher_limit_test() ->
    State = mock_state(8),

    %% Add 8 CIDs
    {ok, FinalState} = lists:foldl(
        fun(Seq, {ok, AccState}) ->
            CID = <<Seq, Seq, Seq, Seq, Seq, Seq, Seq, Seq>>,
            Token = crypto:strong_rand_bytes(16),
            handle_new_connection_id(Seq, 0, CID, Token, AccState)
        end,
        {ok, State},
        lists:seq(0, 7)
    ),

    ?assertEqual(8, length(FinalState#test_state.peer_cid_pool)),

    %% 9th CID should fail
    CID9 = <<9, 9, 9, 9, 9, 9, 9, 9>>,
    Token9 = crypto:strong_rand_bytes(16),
    Result = handle_new_connection_id(8, 0, CID9, Token9, FinalState),
    ?assertEqual({error, {connection_id_limit_error, 9, 8}}, Result).

%% Test limit of 1 (minimum practical limit)
minimum_limit_test() ->
    State = mock_state(1),

    CID1 = <<1, 1, 1, 1, 1, 1, 1, 1>>,
    Token1 = crypto:strong_rand_bytes(16),
    {ok, State1} = handle_new_connection_id(0, 0, CID1, Token1, State),

    %% Second CID should fail
    CID2 = <<2, 2, 2, 2, 2, 2, 2, 2>>,
    Token2 = crypto:strong_rand_bytes(16),
    Result = handle_new_connection_id(1, 0, CID2, Token2, State1),
    ?assertEqual({error, {connection_id_limit_error, 2, 1}}, Result).

%%====================================================================
%% Transport Parameter Application
%%====================================================================

%% Test peer limit is extracted from transport params
apply_transport_params_test() ->
    State = #test_state{
        transport_params = #{},
        peer_active_cid_limit = 2
    },

    %% Apply transport params with limit of 5
    TP = #{active_connection_id_limit => 5},
    NewState = apply_peer_transport_params(TP, State),

    ?assertEqual(5, NewState#test_state.peer_active_cid_limit),
    ?assertEqual(TP, NewState#test_state.transport_params).

%% Test default limit when not specified
apply_transport_params_default_test() ->
    State = #test_state{
        transport_params = #{},
        peer_active_cid_limit = 10
    },

    %% Apply transport params without limit (should default to 2)
    TP = #{initial_max_data => 1000000},
    NewState = apply_peer_transport_params(TP, State),

    ?assertEqual(2, NewState#test_state.peer_active_cid_limit).

%%====================================================================
%% Retire Prior To Handling
%%====================================================================

%% Test retiring multiple CIDs frees space
retire_prior_to_test() ->
    State = mock_state(3),

    %% Add 3 CIDs
    {ok, S1} = handle_new_connection_id(0, 0, <<0:64>>, crypto:strong_rand_bytes(16), State),
    {ok, S2} = handle_new_connection_id(1, 0, <<1:64>>, crypto:strong_rand_bytes(16), S1),
    {ok, S3} = handle_new_connection_id(2, 0, <<2:64>>, crypto:strong_rand_bytes(16), S2),

    %% Adding 4th without retirement should fail
    R1 = handle_new_connection_id(3, 0, <<3:64>>, crypto:strong_rand_bytes(16), S3),
    ?assertMatch({error, _}, R1),

    %% Adding 4th with retire_prior_to=2 should succeed (retires seq 0 and 1)
    {ok, S4} = handle_new_connection_id(3, 2, <<3:64>>, crypto:strong_rand_bytes(16), S3),
    ActiveCount = length([E || #cid_entry{status = active} = E <- S4#test_state.peer_cid_pool]),
    ?assertEqual(2, ActiveCount).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Create a mock state with given limit
mock_state(Limit) ->
    #test_state{
        peer_cid_pool = [],
        local_active_cid_limit = Limit
    }.

%% Test version of handle_new_connection_id (same algorithm as quic_connection)
handle_new_connection_id(SeqNum, RetirePrior, CID, ResetToken, State) ->
    #test_state{peer_cid_pool = Pool, local_active_cid_limit = Limit} = State,

    %% Retire CIDs with seq < RetirePrior
    RetiredPool = lists:map(
        fun
            (#cid_entry{seq_num = S} = Entry) when S < RetirePrior ->
                Entry#cid_entry{status = retired};
            (Entry) ->
                Entry
        end,
        Pool
    ),

    %% Add new CID entry
    NewEntry = #cid_entry{
        seq_num = SeqNum,
        cid = CID,
        stateless_reset_token = ResetToken,
        status = active
    },

    case lists:keyfind(SeqNum, #cid_entry.seq_num, RetiredPool) of
        false ->
            NewPool = [NewEntry | RetiredPool],
            ActiveCount = length([E || #cid_entry{status = active} = E <- NewPool]),
            case ActiveCount > Limit of
                true ->
                    {error, {connection_id_limit_error, ActiveCount, Limit}};
                false ->
                    {ok, State#test_state{peer_cid_pool = NewPool}}
            end;
        _ ->
            {ok, State#test_state{peer_cid_pool = RetiredPool}}
    end.

%% Test version of apply_peer_transport_params
apply_peer_transport_params(TransportParams, State) ->
    PeerLimit = maps:get(active_connection_id_limit, TransportParams, 2),
    State#test_state{
        transport_params = TransportParams,
        peer_active_cid_limit = PeerLimit
    }.
