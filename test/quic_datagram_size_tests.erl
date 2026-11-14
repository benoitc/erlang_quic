%%% -*- erlang -*-
%%%
%%% DATAGRAM sizes: a DATAGRAM goes out only in a packet that fits the
%%% confirmed path MTU (RFC 8899 Section 3).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_datagram_size_tests).

-include_lib("eunit/include/eunit.hrl").

%% Short header with the 8-byte test DCID, a 4-byte packet number and
%% the AEAD tag.
-define(HEADER, (1 + 8 + 4 + 16)).
%% The DATAGRAM type byte and a 2-byte length.
-define(FRAME_2, (1 + 2)).

%%====================================================================
%% Path MTU (RFC 8899 Section 3)
%%====================================================================

%% The confirmed MTU bounds the payload, not the probing ceiling.
send_checks_the_confirmed_mtu_test() ->
    PMTU = quic_pmtu:on_connection_established(1500, quic_pmtu:new(#{})),
    ?assertEqual(1200, quic_pmtu:current_mtu(PMTU)),
    S0 = sender(65535, PMTU),
    Fit = 1200 - ?HEADER - ?FRAME_2,
    {ok, S1} = quic_connection:do_send_datagram(payload(Fit), S0),
    [{Size, [{datagram_with_length, _}]}] = quic_connection_test_support:app_packets_sent(S1),
    ?assert(Size =< 1200),
    ?assertEqual(
        {error, datagram_too_large_for_path},
        quic_connection:do_send_datagram(payload(Fit + 1), S0)
    ).

%% The budget grows when a probe is acknowledged and falls back when a
%% black hole is detected.
budget_follows_the_confirmed_mtu_test() ->
    Raised = probed(quic_pmtu:on_connection_established(1500, quic_pmtu:new(#{}))),
    Mtu = quic_pmtu:current_mtu(Raised),
    ?assert(Mtu > 1200),
    assert_fits(Mtu - ?HEADER - ?FRAME_2, sender(65535, Raised)),
    Fallen = black_holed(Raised),
    ?assertEqual(1200, quic_pmtu:current_mtu(Fallen)),
    assert_fits(1200 - ?HEADER - ?FRAME_2, sender(65535, Fallen)).

%%====================================================================
%% Helpers
%%====================================================================

sender(PeerMax, PMTU) ->
    quic_connection_test_support:state_for_datagram(PeerMax, PMTU).

payload(N) ->
    binary:copy(<<"d">>, N).

%% Fit bytes are sent, one more is refused for the path.
assert_fits(Fit, S0) ->
    ?assertMatch({ok, _}, quic_connection:do_send_datagram(payload(Fit), S0)),
    ?assertEqual(
        {error, datagram_too_large_for_path},
        quic_connection:do_send_datagram(payload(Fit + 1), S0)
    ).

%% Acknowledge probes until the search completes.
probed(PMTU) ->
    probed(PMTU, 0).

probed(PMTU, PN) when PN < 32 ->
    case quic_pmtu:get_state(PMTU) of
        search_complete ->
            PMTU;
        _ ->
            {Gen, Sent} = quic_pmtu:on_probe_sent(PN, PMTU),
            probed(quic_pmtu:on_probe_acked(PN, Gen, Sent), PN + 1)
    end.

%% Lose full-size packets until black-hole detection drops the MTU.
black_holed(PMTU) ->
    Mtu = quic_pmtu:current_mtu(PMTU),
    Fallen = lists:foldl(
        fun(_, P) -> quic_pmtu:on_loss_event([Mtu], P) end, PMTU, lists:seq(1, 6)
    ),
    ?assertEqual(error, quic_pmtu:get_state(Fallen)),
    Fallen.
