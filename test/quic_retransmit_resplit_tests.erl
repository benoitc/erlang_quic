%%% -*- erlang -*-
%%%
%%% Lost data is retransmitted in packets that fit the current path MTU,
%%% even when it was first sent in larger packets before the MTU went
%%% down (RFC 9000 Section 14.2).

-module(quic_retransmit_resplit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).
-define(MTU, 1200).

fits_the_current_mtu_test() ->
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Peer),
        Data = crypto:strong_rand_bytes(1400),
        Lost = #sent_packet{
            pn = 0,
            time_sent = 0,
            size = 1450,
            ack_eliciting = true,
            in_flight = true,
            frames = [{stream, ?STREAM, 0, Data, false}]
        },
        S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 1400, false),
        S = quic_connection:retransmit_lost_packets([Lost], S0#state{
            coalesce = false, remote_addr = {{127, 0, 0, 1}, Port}
        }),
        _ = quic_connection:flush_socket_batch(S),
        Sizes = datagram_sizes(Peer),
        ?assertMatch([_, _ | _], Sizes),
        ?assertEqual([], [Size || Size <- Sizes, Size > ?MTU])
    after
        gen_udp:close(Peer)
    end.

datagram_sizes(Socket) ->
    case gen_udp:recv(Socket, 0, 200) of
        {ok, {_, _, Packet}} -> [byte_size(Packet) | datagram_sizes(Socket)];
        {error, timeout} -> []
    end.
