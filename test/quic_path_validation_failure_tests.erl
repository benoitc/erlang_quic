%%% -*- erlang -*-
%%%
%%% A server follows a client's new address at once and validates it in
%%% the background. When that validation fails it goes back to the last
%%% validated address (RFC 9000 Section 9.3.2).

-module(quic_path_validation_failure_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(SPOOFED, {{127, 0, 0, 1}, 40001}).

reverts_to_the_validated_address_test() ->
    S1 = quic_connection:maybe_handle_address_change(?SPOOFED, 100, state()),
    ?assertEqual(?SPOOFED, S1#state.remote_addr),
    S2 = give_up(S1),
    ?assertEqual(?OLD, S2#state.remote_addr),
    ?assertEqual(idle, (S2#state.mig)#mig.migration_state).

give_up(#state{mig = Mig} = S) ->
    Pending = Mig#mig.pending_peer_validation,
    S1 = S#state{mig = Mig#mig{pending_peer_validation = Pending#path_state{challenge_count = 3}}},
    {keep_state, S2} = quic_connection:handle_path_validation_timeout(S1),
    S2.

state() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    S0#state{remote_addr = ?OLD, owner = self(), pmtu_state = quic_pmtu:new()}.
