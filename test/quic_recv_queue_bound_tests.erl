%% The socket-backend receive paths (listener and client receiver)
%% emulate a bounded kernel receive buffer: a train is forwarded in
%% chunks so the mailbox bound caps queued packets, not just messages,
%% and once the connection's mailbox is over the bound the train is
%% tail-dropped. The listener keeps the head packet so the peer still
%% gets a timely (dup-)ACK carrying the loss signal.
-module(quic_recv_queue_bound_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(ADDR, {{127, 0, 0, 1}, 4433}).

packets(N) ->
    [<<I:16, 0:(1000 * 8)>> || I <- lists:seq(1, N)].

%% A process that never reads its mailbox, optionally pre-filled.
sink(Backlog) ->
    Pid = spawn_link(fun() ->
        receive
            stop -> ok
        end
    end),
    [Pid ! {noise, I} || I <- lists:seq(1, Backlog)],
    Pid.

drain(Pid, Tag) ->
    {messages, Msgs} = process_info(Pid, messages),
    [M || M <- Msgs, element(1, M) =:= Tag].

listener_forwards_single_packet_as_is_test() ->
    Pid = sink(0),
    [P] = packets(1),
    ok = quic_listener:send_packets_to_connection(Pid, [P], ?ADDR),
    ?assertEqual([{quic_packet, P, ?ADDR}], drain(Pid, quic_packet)),
    ?assertEqual([], drain(Pid, quic_packets)).

listener_chunks_a_train_test() ->
    Pid = sink(0),
    Ps = packets(2 * ?MAX_PACKETS_PER_CONN_MSG + 3),
    ok = quic_listener:send_packets_to_connection(Pid, Ps, ?ADDR),
    Msgs = drain(Pid, quic_packets),
    Sizes = [length(Chunk) || {quic_packets, Chunk, _} <- Msgs],
    ?assertEqual([?MAX_PACKETS_PER_CONN_MSG, ?MAX_PACKETS_PER_CONN_MSG, 3], Sizes),
    %% Order and content survive the split.
    ?assertEqual(Ps, lists:append([Chunk || {quic_packets, Chunk, _} <- Msgs])).

listener_tail_drops_over_the_bound_test() ->
    Pid = sink(?MAX_CONN_RECV_QUEUE_MSGS + 1),
    Ps = packets(5),
    Before = quic_listener:recv_drops(),
    ok = quic_listener:send_packets_to_connection(Pid, Ps, ?ADDR),
    ?assertEqual([{quic_packet, hd(Ps), ?ADDR}], drain(Pid, quic_packet)),
    ?assertEqual([], drain(Pid, quic_packets)),
    ?assertEqual(Before + 4, quic_listener:recv_drops()).

listener_at_the_bound_still_forwards_test() ->
    Pid = sink(?MAX_CONN_RECV_QUEUE_MSGS),
    Ps = packets(3),
    Before = quic_listener:recv_drops(),
    ok = quic_listener:send_packets_to_connection(Pid, Ps, ?ADDR),
    ?assertEqual([{quic_packets, Ps, ?ADDR}], drain(Pid, quic_packets)),
    ?assertEqual(Before, quic_listener:recv_drops()).

client_forwards_a_train_as_one_message_test() ->
    Pid = sink(0),
    Ps = packets(4),
    ok = quic_socket:forward_to_owner(Pid, sock, {127, 0, 0, 1}, 4433, Ps),
    ?assertEqual([{udp_batch, sock, {127, 0, 0, 1}, 4433, Ps}], drain(Pid, udp_batch)),
    [P] = packets(1),
    ok = quic_socket:forward_to_owner(Pid, sock, {127, 0, 0, 1}, 4433, [P]),
    ?assertEqual([{udp, sock, {127, 0, 0, 1}, 4433, P}], drain(Pid, udp)).

client_tail_drops_over_the_bound_test() ->
    Pid = sink(?MAX_CONN_RECV_QUEUE_MSGS + 1),
    Ps = packets(6),
    Before = quic_socket:client_recv_drops(),
    ok = quic_socket:forward_to_owner(Pid, sock, {127, 0, 0, 1}, 4433, Ps),
    ?assertEqual([], drain(Pid, udp_batch)),
    ?assertEqual([], drain(Pid, udp)),
    ?assertEqual(Before + 6, quic_socket:client_recv_drops()).
