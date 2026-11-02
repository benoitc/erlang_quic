%%% -*- erlang -*-
%%%
%%% Datagrams carrying PATH_CHALLENGE or PATH_RESPONSE are at least 1200
%%% bytes (RFC 9000 Section 8.2.1), whatever the packet number length.

-module(quic_path_validation_padding_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(DATA, <<1, 2, 3, 4, 5, 6, 7, 8>>).

challenge_test_() ->
    [?_assert(sent_size(fun send_challenge/2, PN) >= 1200) || PN <- [0, 300, 70000]].

response_test_() ->
    [?_assert(sent_size(fun send_response/2, PN) >= 1200) || PN <- [0, 300, 70000]].

send_challenge(Addr, S) ->
    quic_connection:send_path_challenge(Addr, ?DATA, S).

send_response(Addr, S) ->
    quic_connection:send_path_response_to_addr(Addr, ?DATA, S).

sent_size(Send, PN) ->
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Peer),
        S0 = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_keys(client)
        ),
        PNSpace = (S0#state.hs)#hs.pn_handshake,
        S1 = S0#state{pn_app = PNSpace#pn_space{next_pn = PN}},
        S = Send({{127, 0, 0, 1}, Port}, S1),
        _ = quic_connection:flush_socket_batch(S),
        {ok, {_, _, Datagram}} = gen_udp:recv(Peer, 0, 1000),
        byte_size(Datagram)
    after
        gen_udp:close(Peer)
    end.
