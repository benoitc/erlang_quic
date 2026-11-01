%%% -*- erlang -*-
%%%
%%% Closing before 1-RTT keys exist still tells the peer (RFC 9000
%%% Section 10.2.3): a CONNECTION_CLOSE of type 0x1c with
%%% APPLICATION_ERROR goes out in Handshake packets, and from a server
%%% in Initial packets too.

-module(quic_close_during_handshake_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

client_sends_a_close_test() ->
    ?assertEqual([handshake], close_packet_types(client)).

server_sends_it_at_both_levels_test() ->
    ?assertEqual([handshake, initial], lists:sort(close_packet_types(server))).

close_packet_types(Role) ->
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Peer),
        #state{hs = HS} =
            S0 = quic_connection_test_support:state_sending(
                quic_connection_test_support:state_with_keys(Role)
            ),
        S1 = S0#state{
            app_keys = undefined,
            coalesce = false,
            remote_addr = {{127, 0, 0, 1}, Port},
            hs = HS#hs{pn_initial = HS#hs.pn_handshake, address_validated = true}
        },
        S = quic_connection:initiate_close(normal, S1),
        _ = quic_connection:flush_socket_batch(S),
        ?assertEqual(normal, S#state.close_reason),
        packet_types(Peer)
    after
        gen_udp:close(Peer)
    end.

packet_types(Socket) ->
    case gen_udp:recv(Socket, 0, 200) of
        {ok, {_, _, <<1:1, 1:1, Type:2, _:4, _/binary>>}} ->
            [type(Type) | packet_types(Socket)];
        {error, timeout} ->
            []
    end.

type(0) -> initial;
type(2) -> handshake.
