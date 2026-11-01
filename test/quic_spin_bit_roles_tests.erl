%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 17.4: the server reflects the spin bit it receives,
%%% the client inverts it, and at least one connection in 16 runs with
%%% the spin bit disabled.

-module(quic_spin_bit_roles_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SPIN_SET, (16#40 bor 2#00100000)).

server_reflects_test() ->
    ?assertEqual(1, outgoing_after(server)).

client_inverts_test() ->
    ?assertEqual(0, outgoing_after(client)).

client_inverts_in_a_contiguous_run_test() ->
    #state{cfg = Cfg} =
        S1 = quic_connection_test_support:with_keys_and_socket(
            quic_connection_test_support:state_for_role(client)
        ),
    S0 = quic_connection_test_support:state_with_pn_app(
        S1#state{cfg = Cfg#conn_cfg{spin_bit_enabled = true}}, 5
    ),
    S = quic_connection:fold_opened([{6, ?SPIN_SET, [ping]}, {7, ?SPIN_SET, [ping]}], S0),
    ?assertEqual(0, S#state.spin_outgoing).

disabled_on_some_connections_test() ->
    Disabled = length([
        E
     || E <- [quic_connection:spin_bit_enabled(#{}) || _ <- lists:seq(1, 1600)], not E
    ]),
    ?assert(Disabled >= 40 andalso Disabled =< 200).

disabled_by_option_test() ->
    ?assertNot(
        lists:any(
            fun(_) -> quic_connection:spin_bit_enabled(#{spin_bit => false}) end, lists:seq(1, 100)
        )
    ).

outgoing_after(Role) ->
    S = quic_connection:record_app_recv(
        ?SPIN_SET, 1, quic_connection_test_support:app_recv_state(Role, true), 0
    ),
    S#state.spin_outgoing.
