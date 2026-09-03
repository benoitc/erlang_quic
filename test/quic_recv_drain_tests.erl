%% drain_recv_msgs/2 pulls datagram messages already queued in the
%% connection's mailbox into the current receive pass, so the ACK,
%% socket-batch and timer flushes at the end of the pass amortize over
%% the whole train. These tests pin its contract: only datagram
%% messages are taken, in order, up to the cap, and never once a close
%% has been initiated.
-module(quic_recv_drain_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ADDR, {{127, 0, 0, 1}, 4433}).

%% An undecryptable short-header packet: parsed and discarded by the
%% receive path without touching the (absent) keys.
garbage(I) ->
    <<1:1, 0:1, 0:6, I:8, 0:(40 * 8)>>.

server_state() ->
    quic_connection:test_state_for_server(?ADDR, undefined, <<>>).

client_state() ->
    quic_connection:test_state_for_client(?ADDR).

flush_mailbox() ->
    receive
        _ -> flush_mailbox()
    after 0 -> ok
    end.

mailbox() ->
    {messages, Msgs} = process_info(self(), messages),
    Msgs.

drains_queued_server_datagrams_test() ->
    flush_mailbox(),
    self() ! {quic_packet, garbage(1), ?ADDR},
    self() ! {quic_packets, [garbage(2), garbage(3)], ?ADDR},
    self() ! {other, event},
    self() ! {quic_packet, garbage(4), ?ADDR},
    _ = quic_connection:drain_recv_msgs(server_state(), 64),
    ?assertEqual([{other, event}], mailbox()).

drains_queued_client_datagrams_test() ->
    flush_mailbox(),
    %% The drain matches on the state's socket, and the client path
    %% re-arms {active, N} on it after each datagram.
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    S = quic_connection:test_state_with_socket(client_state(), Sock),
    self() ! {udp, Sock, {127, 0, 0, 1}, 4433, garbage(1)},
    self() ! {udp_batch, Sock, {127, 0, 0, 1}, 4433, [garbage(2), garbage(3)]},
    self() ! {timeout, ref, idle},
    _ = quic_connection:drain_recv_msgs(S, 64),
    gen_udp:close(Sock),
    ?assertEqual([{timeout, ref, idle}], mailbox()).

stops_at_the_cap_test() ->
    flush_mailbox(),
    [self() ! {quic_packet, garbage(I), ?ADDR} || I <- lists:seq(1, 10)],
    _ = quic_connection:drain_recv_msgs(server_state(), 4),
    Left = mailbox(),
    ?assertEqual(6, length(Left)),
    %% Oldest first: the cap leaves the tail of the queue.
    ?assertEqual({quic_packet, garbage(5), ?ADDR}, hd(Left)).

zero_cap_takes_nothing_test() ->
    flush_mailbox(),
    self() ! {quic_packet, garbage(1), ?ADDR},
    _ = quic_connection:drain_recv_msgs(server_state(), 0),
    ?assertEqual(1, length(mailbox())).

leaves_the_mailbox_alone_once_closing_test() ->
    flush_mailbox(),
    self() ! {quic_packet, garbage(1), ?ADDR},
    S0 = server_state(),
    S = quic_connection:test_state_closing(S0, {application, 0, <<"bye">>}),
    ?assertEqual(S, quic_connection:drain_recv_msgs(S, 64)),
    ?assertEqual(1, length(mailbox())).

%% The same-source collection must keep mailbox order across both
%% message shapes: a single datagram queued behind a GRO train belongs
%% after it, not in front of it. Taking one shape at a time would
%% reorder the wire.
client_collect_keeps_mailbox_order_test() ->
    flush_mailbox(),
    Sock = sock,
    self() ! {udp_batch, Sock, {127, 0, 0, 1}, 4433, [garbage(2), garbage(3)]},
    self() ! {udp, Sock, {127, 0, 0, 1}, 4433, garbage(4)},
    self() ! {udp_batch, Sock, {127, 0, 0, 1}, 4433, [garbage(5)]},
    self() ! {other, event},
    {Datagrams, Left} = quic_connection:collect_client_udp(Sock, {127, 0, 0, 1}, 4433, 64, [
        garbage(1)
    ]),
    ?assertEqual([garbage(I) || I <- lists:seq(1, 5)], Datagrams),
    ?assertEqual(61, Left),
    ?assertEqual([{other, event}], mailbox()).
