%%% -*- erlang -*-
%%%
%%% A PATH_RESPONSE to any challenge still outstanding validates the
%%% path (RFC 9000 Section 8.2.3), and validation is abandoned only
%%% after three times the larger of the current PTO and the new path's
%%% PTO from kInitialRtt (Section 8.2.4).

-module(quic_path_validation_timer_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(NEW, {{127, 0, 0, 1}, 40001}).

response_to_an_earlier_challenge_validates_test() ->
    S1 = quic_connection:maybe_handle_address_change(?NEW, 1200, state()),
    #path_state{challenge_data = First} = quic_connection_test_support:pending_peer_path(S1),
    {keep_state, S2} = quic_connection:handle_path_validation_timeout(S1),
    ?assertNotEqual(
        First, (quic_connection_test_support:pending_peer_path(S2))#path_state.challenge_data
    ),
    S3 = quic_connection:handle_path_response(First, S2),
    ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S3)),
    ?assertEqual(idle, (S3#state.mig)#mig.migration_state),
    ?assertEqual(?NEW, S3#state.remote_addr).

fast_path_is_not_abandoned_early_test() ->
    S1 = quic_connection:maybe_handle_address_change(?NEW, 1200, state()),
    S2 = timeouts(3, S1),
    ?assertMatch(
        #path_state{status = validating}, quic_connection_test_support:pending_peer_path(S2)
    ),
    ?assertEqual(validating_peer, (S2#state.mig)#mig.migration_state).

timeouts(0, S) ->
    S;
timeouts(N, S0) ->
    {keep_state, S} = quic_connection:handle_path_validation_timeout(S0),
    timeouts(N - 1, S).

state() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    LS = lists:foldl(
        fun(_, L) -> quic_loss:update_rtt(L, 2, 0) end, S0#state.loss_state, lists:seq(1, 20)
    ),
    S0#state{
        remote_addr = ?OLD, owner = owner(), pmtu_state = quic_pmtu:new(), loss_state = LS
    }.

%% Takes the path_changed notices, which would otherwise reach later tests.
owner() ->
    spawn(fun() ->
        receive
        after 10000 -> ok
        end
    end).
