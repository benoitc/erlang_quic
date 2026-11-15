%%% -*- erlang -*-
%%%
%%% DATAGRAM sizes: max_datagram_frame_size bounds the whole frame, type
%%% and length included (RFC 9221 Section 3), and a DATAGRAM goes out
%%% only in a packet that fits the confirmed path MTU (RFC 8899 Section 3).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_datagram_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

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

%% With a 4-byte packet number the packet fills the MTU exactly. The
%% length takes 2 bytes up to 16383 and 4 above.
path_budget_counts_the_length_size_test_() ->
    [
        {"2-byte length", fun() -> assert_fills_the_mtu(1500, 1500 - ?HEADER - 1 - 2) end},
        {"4-byte length", fun() -> assert_fills_the_mtu(20000, 20000 - ?HEADER - 1 - 4) end}
    ].

%% IMMEDIATE_ACK is left out of a packet it would push past the MTU,
%% and still rides in one with room for it.
immediate_ack_only_when_it_fits_test() ->
    S0 = quic_connection_test_support:state_set(
        quic_connection_test_support:state_set(
            long_pn(sender(65535, undefined)), transport_params, #{min_ack_delay => 1000}
        ),
        hs_probe,
        true
    ),
    Full = 1200 - ?HEADER - ?FRAME_2,
    {ok, S1} = quic_connection:do_send_datagram(payload(Full), S0),
    ?assertMatch(
        [{1200, [{datagram_with_length, _}]}], quic_connection_test_support:app_packets_sent(S1)
    ),
    {ok, S2} = quic_connection:do_send_datagram(payload(Full - 1), S0),
    ?assertMatch(
        [{1200, [{datagram_with_length, _}, immediate_ack]}],
        quic_connection_test_support:app_packets_sent(S2)
    ).

%%====================================================================
%% Peer's max_datagram_frame_size (RFC 9221 Section 3)
%%====================================================================

%% The largest payload whose frame fits the peer's maximum is sent; one
%% more byte is refused. Past 65 the length takes 2 bytes, so 66 leaves
%% a byte unused.
send_checks_the_whole_frame_test_() ->
    [
        {integer_to_list(PeerMax), fun() -> assert_peer_limit(PeerMax, Fit) end}
     || {PeerMax, Fit} <- [{2, 0}, {65, 63}, {66, 63}, {67, 64}, {100, 97}, {1000, 997}]
    ].

%% A peer limit too small for any frame refuses even an empty datagram.
send_refuses_when_no_frame_fits_test() ->
    ?assertEqual(
        {error, datagram_too_large},
        quic_connection:do_send_datagram(<<>>, sender(1, undefined))
    ).

%% A received frame, type and length included, at our maximum is
%% delivered; one byte more closes with PROTOCOL_VIOLATION. A length
%% encoded on 2 bytes where 1 would do counts as sent.
receive_checks_the_whole_frame_test_() ->
    Cases = [
        {"0x30 at max", 100, <<16#30, (payload(99))/binary>>, delivered},
        {"0x30 above max", 100, <<16#30, (payload(100))/binary>>, closed},
        {"0x31 at max", 100, quic_frame:encode({datagram_with_length, payload(97)}), delivered},
        {"0x31 above max", 100, quic_frame:encode({datagram_with_length, payload(98)}), closed},
        {"0x31 long length at max", 65, <<16#31, 16#40, 62, (payload(62))/binary>>, delivered},
        {"0x31 long length above max", 65, <<16#31, 16#40, 63, (payload(63))/binary>>, closed}
    ],
    [
        {Name, fun() -> assert_received(Max, Frame, Want) end}
     || {Name, Max, Frame, Want} <- Cases
    ].

%% Fence: without our support any DATAGRAM is unexpected, whatever its size.
receive_without_support_is_unexpected_test() ->
    S0 = quic_connection_test_support:state_receiving_datagrams(0),
    Frame = quic_frame:encode({datagram_with_length, payload(10)}),
    {ok, S1, _} = quic_connection:decode_and_process_streaming(app, Frame, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, <<"unexpected DATAGRAM frame">>},
        quic_connection_test_support:close_reason(S1)
    ).

%%====================================================================
%% datagram_max_size/1
%%====================================================================

%% The size reported is the one send_datagram enforces: the smaller of
%% the peer's frame limit and the path budget, 0 without peer support.
max_size_is_what_send_accepts_test_() ->
    Path = {error, datagram_too_large_for_path},
    Peer = {error, datagram_too_large},
    None = {error, datagrams_not_supported},
    Cases = [
        {"path bound", 65535, 1200 - ?HEADER - ?FRAME_2, ok, Path},
        {"peer bound", 100, 97, ok, Peer},
        {"nothing fits", 1, 0, Peer, Peer},
        {"no support", 0, 0, None, None}
    ],
    [
        {Name, fun() -> assert_max_size(PeerMax, Want, AtMax, AboveMax) end}
     || {Name, PeerMax, Want, AtMax, AboveMax} <- Cases
    ].

%% Before the handshake completes, a client sending 0-RTT answers from the
%% parameters remembered with the ticket (RFC 9221 Section 3), so HTTP/3
%% can advertise its datagram setting in 0-RTT.
queries_answer_during_the_handshake_test_() ->
    TP = #{max_datagram_frame_size => 65535},
    S = quic_connection_test_support:state_set(sender(65535, undefined), transport_params, TP),
    From = {self(), make_ref()},
    [
        {atom_to_list(StateName), fun() ->
            ?assertMatch(
                {keep_state, _, [{reply, From, {ok, TP}}]},
                quic_connection:StateName({call, From}, get_peer_transport_params, S)
            ),
            ?assertMatch(
                {keep_state, _, [{reply, From, Max}]} when Max =:= 1200 - ?HEADER - ?FRAME_2,
                quic_connection:StateName({call, From}, datagram_max_size, S)
            )
        end}
     || StateName <- [idle, handshaking]
    ].

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

assert_peer_limit(PeerMax, Fit) ->
    S0 = sender(PeerMax, undefined),
    {ok, S1} = quic_connection:do_send_datagram(payload(Fit), S0),
    [{_, [Frame]}] = quic_connection_test_support:app_packets_sent(S1),
    ?assert(byte_size(quic_frame:encode(Frame)) =< PeerMax),
    ?assert(byte_size(quic_frame:encode({datagram_with_length, payload(Fit + 1)})) > PeerMax),
    ?assertEqual(
        {error, datagram_too_large},
        quic_connection:do_send_datagram(payload(Fit + 1), S0)
    ).

assert_received(LocalMax, Frame, Want) ->
    S0 = quic_connection_test_support:state_receiving_datagrams(LocalMax),
    {ok, S1, _} = quic_connection:decode_and_process_streaming(app, Frame, S0),
    Delivered = maps:get(delivered, quic_connection:datagram_stats_snapshot(S1)),
    Reason = quic_connection_test_support:close_reason(S1),
    case Want of
        delivered ->
            ?assertEqual(undefined, Reason),
            ?assertEqual(1, Delivered);
        closed ->
            ?assertMatch(
                {transport, ?QUIC_PROTOCOL_VIOLATION, <<"DATAGRAM frame too large">>}, Reason
            ),
            ?assertEqual(0, Delivered)
    end,
    flush_datagrams().

flush_datagrams() ->
    receive
        {quic, _, {datagram, _}} -> flush_datagrams()
    after 0 -> ok
    end.

assert_fills_the_mtu(Mtu, Fit) ->
    PMTU = #pmtu_state{
        state = search_complete, current_mtu = Mtu, max_mtu = Mtu, search_min = Mtu
    },
    Window = quic_cc:new(#{algorithm => newreno, initial_window => 4 * Mtu}),
    S0 = quic_connection_test_support:state_set(
        long_pn(sender(65535, PMTU)), cc_state, Window
    ),
    {ok, S1} = quic_connection:do_send_datagram(payload(Fit), S0),
    ?assertMatch([{Mtu, _}], quic_connection_test_support:app_packets_sent(S1)),
    ?assertEqual(
        {error, datagram_too_large_for_path},
        quic_connection:do_send_datagram(payload(Fit + 1), S0)
    ).

%% The next packet number takes 4 bytes.
long_pn(S) ->
    quic_connection_test_support:state_set(S, app_next_pn, 16#1000000).

assert_max_size(PeerMax, Want, AtMax, AboveMax) ->
    S = sender(PeerMax, undefined),
    From = {self(), make_ref()},
    {keep_state, S, [{reply, From, Max}]} =
        quic_connection:connected({call, From}, datagram_max_size, S),
    ?assertEqual(Want, Max),
    ?assertEqual(AtMax, sent(quic_connection:do_send_datagram(payload(Max), S))),
    ?assertEqual(AboveMax, sent(quic_connection:do_send_datagram(payload(Max + 1), S))).

sent({ok, _}) -> ok;
sent(Error) -> Error.
