%%% -*- erlang -*-
%%%
%%% After closing, an endpoint answers the peer's packets with its
%%% CONNECTION_CLOSE, at a falling rate, so a lost close does not leave
%%% the peer retransmitting until its idle timeout (RFC 9000 Section
%%% 10.2.1). A peer's close or an idle timeout is not answered.

-module(quic_closing_reply_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

answers_the_1st_2nd_and_4th_packet_test() ->
    with_peer(fun(Peer, Sock) ->
        S0 = sent(quic_connection:initiate_close(normal, state(Peer))),
        _ = count(Sock),
        S = lists:foldl(fun(_, S) -> quic_connection:closing_reply(Peer, S) end, S0, [1, 2, 3, 4]),
        ?assertEqual(3, count(Sock)),
        ?assertEqual(4, S#state.closing_recv)
    end).

a_batch_counts_each_packet_test() ->
    with_peer(fun(Peer, Sock) ->
        S0 = sent(quic_connection:initiate_close(normal, state(Peer))),
        _ = count(Sock),
        _ = quic_connection:closing_reply(Peer, 3, S0),
        ?assertEqual(1, count(Sock))
    end).

other_addresses_are_not_answered_test() ->
    with_peer(fun(Peer, Sock) ->
        S0 = sent(quic_connection:initiate_close(normal, state(Peer))),
        _ = count(Sock),
        _ = quic_connection:closing_reply({{127, 0, 0, 1}, 9}, S0),
        ?assertEqual(0, count(Sock))
    end).

idle_timeout_is_not_answered_test() ->
    with_peer(fun(Peer, Sock) ->
        S0 = quic_connection:initiate_close(idle_timeout, state(Peer)),
        _ = quic_connection:closing_reply(Peer, S0),
        ?assertEqual(0, count(Sock))
    end).

%% RFC 9000 Section 10.2.2: an error found after the peer's close may
%% be sent once, and is not resent.
an_error_after_the_peers_close_is_not_resent_test() ->
    with_peer(fun(Peer, Sock) ->
        Close = quic_frame:encode({connection_close, application, 0, undefined, <<>>}),
        {ok, S0, _} = quic_connection:decode_and_process_streaming(
            app, <<Close/binary, 16#21>>, state(Peer)
        ),
        ?assertMatch({transport, ?QUIC_FRAME_ENCODING_ERROR, _}, S0#state.close_reason),
        _ = quic_connection:flush_socket_batch(S0),
        ?assertEqual(1, count(Sock)),
        ?assertEqual(undefined, S0#state.closing_frame),
        _ = lists:foldl(fun(_, S) -> draining_packet(Peer, S) end, S0, [1, 2, 3, 4]),
        ?assertEqual(0, count(Sock))
    end).

draining_packet({quic_packet, _, _} = Msg, State) ->
    {keep_state, S} = quic_connection:draining(info, Msg, State),
    S;
draining_packet(Peer, State) ->
    draining_packet({quic_packet, <<>>, Peer}, State).

sent(State) ->
    quic_connection:flush_socket_batch(State).

state(Peer) ->
    S0 = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_pn_app(
            quic_connection_test_support:state_with_keys(server), 10
        )
    ),
    S0#state{coalesce = false, remote_addr = Peer}.

with_peer(Fun) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    try
        Fun({{127, 0, 0, 1}, Port}, Sock)
    after
        gen_udp:close(Sock)
    end.

count(Socket) ->
    case gen_udp:recv(Socket, 0, 200) of
        {ok, _} -> 1 + count(Socket);
        {error, timeout} -> 0
    end.
