%%% -*- erlang -*-
%%%
%%% A client probes the server's preferred address once the handshake is
%%% confirmed (RFC 9000 §9.6.1), in the family of its current path, and
%%% sends an unanswered PATH_CHALLENGE again (§8.2.1).

-module(quic_preferred_address_probe_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

-define(PA_ADDR, {{127, 0, 0, 1}, 9}).

no_probe_before_confirmation_test() ->
    S0 = quic_connection_test_support:client_with_preferred_address(false),
    S1 = quic_connection:maybe_probe_preferred_address(S0),
    ?assertEqual([], quic_connection_test_support:alt_paths(S1)).

probe_on_confirmation_test() ->
    S0 = quic_connection_test_support:client_with_preferred_address(true),
    S1 = quic_connection:maybe_probe_preferred_address(S0),
    ?assertMatch(
        [#path_state{remote_addr = ?PA_ADDR, status = validating, challenge_count = 1}],
        quic_connection_test_support:alt_paths(S1)
    ),
    ?assertEqual(S1, quic_connection:maybe_probe_preferred_address(S1)).

probe_uses_current_family_test() ->
    PA = #preferred_address{
        ipv4_addr = {10, 0, 0, 1},
        ipv4_port = 443,
        ipv6_addr = {16#fd00, 0, 0, 0, 0, 0, 0, 1},
        ipv6_port = 443
    },
    ?assertEqual(
        {{10, 0, 0, 1}, 443}, quic_connection:select_preferred_addr(PA, {{10, 0, 0, 2}, 4433})
    ),
    ?assertEqual(
        {{16#fd00, 0, 0, 0, 0, 0, 0, 1}, 443},
        quic_connection:select_preferred_addr(PA, {{16#fd00, 0, 0, 0, 0, 0, 0, 2}, 4433})
    ),
    ?assertEqual(
        undefined,
        quic_connection:select_preferred_addr(
            PA#preferred_address{ipv4_addr = undefined}, {{10, 0, 0, 2}, 4433}
        )
    ).

unanswered_probe_is_resent_then_abandoned_test() ->
    S0 = quic_connection_test_support:client_with_preferred_address(true),
    S1 = quic_connection:maybe_probe_preferred_address(S0),
    S2 = timeout(S1),
    ?assertMatch(
        [#path_state{challenge_count = 2}], quic_connection_test_support:alt_paths(S2)
    ),
    S3 = timeout(timeout(S2)),
    ?assertEqual([], quic_connection_test_support:alt_paths(S3)).

stale_probe_timeout_is_ignored_test() ->
    S0 = quic_connection_test_support:client_with_preferred_address(true),
    S1 = quic_connection:maybe_probe_preferred_address(S0),
    ?assertEqual(S1, quic_connection:handle_path_probe_timeout(?PA_ADDR, <<"stale!!!">>, S1)).

timeout(State) ->
    [#path_state{remote_addr = Addr, challenge_data = Data}] =
        quic_connection_test_support:alt_paths(State),
    ok =
        receive
            {path_probe_timeout, Addr, Data} -> ok
        after 5000 -> no_probe_timer
        end,
    quic_connection:handle_path_probe_timeout(Addr, Data, State).

response_on_probed_path_uses_its_cid_test() ->
    S0 = quic_connection_test_support:client_with_preferred_address(true),
    S1 = quic_connection:maybe_probe_preferred_address(S0),
    [#path_state{dcid = PathDCID}] = quic_connection_test_support:alt_paths(S1),
    ?assertEqual(<<"pref-cid">>, PathDCID),
    ?assertEqual(PathDCID, quic_connection:addr_dcid(?PA_ADDR, S1)),
    ?assertEqual(
        quic_connection_test_support:state_get(S1, dcid),
        quic_connection:addr_dcid({{127, 0, 0, 3}, 9}, S1)
    ).
