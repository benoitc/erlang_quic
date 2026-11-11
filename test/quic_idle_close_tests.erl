%%% -*- erlang -*-
%%%
%%% An idle timeout closes the connection silently, after the handshake
%%% as during it (RFC 9000 Section 10.1).

-module(quic_idle_close_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

idle_timeout_sends_nothing_test() ->
    ?assertEqual(0, datagrams_on_close(idle_timeout)).

other_closes_send_a_close_test() ->
    ?assertEqual(1, datagrams_on_close(normal)).

datagrams_on_close(Reason) ->
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Peer),
        S0 = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_pn_app(
                quic_connection_test_support:state_with_keys(server), 10
            )
        ),
        S = quic_connection:initiate_close(Reason, S0#state{
            coalesce = false, remote_addr = {{127, 0, 0, 1}, Port}
        }),
        _ = quic_connection:flush_socket_batch(S),
        count(Peer)
    after
        gen_udp:close(Peer)
    end.

count(Socket) ->
    case gen_udp:recv(Socket, 0, 200) of
        {ok, _} -> 1 + count(Socket);
        {error, timeout} -> 0
    end.
