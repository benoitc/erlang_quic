%% Server connections on the socket backend hand their finished send
%% batches to one shared sender process that performs the sendmsg
%% calls serially: concurrent sendmsg on one socket handle burns most
%% of its CPU in NIF-level contention. The connection keeps its batch
%% buffer, GSO grouping and counters; only the syscall moves.
-module(quic_shared_sender_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ADDR, {127, 0, 0, 1}).

conn_sender(SenderPid) ->
    {ok, SS} = quic_socket:new_sender(fake_socket, #{
        backend => socket, sender_pid => SenderPid, batching => #{max_packets => 64}
    }),
    SS.

flush_hands_the_batch_over_test() ->
    SS0 = conn_sender(self()),
    {ok, SS1} = quic_socket:send(SS0, ?ADDR, 4433, <<"p1">>),
    {ok, SS2} = quic_socket:send(SS1, ?ADDR, 4433, <<"p2">>),
    {ok, SS3} = quic_socket:send(SS2, ?ADDR, 4433, <<"p3">>),
    {ok, SS4} = quic_socket:flush(SS3),
    receive
        {send_batch, {?ADDR, 4433}, Buffer, 3} ->
            ?assertEqual([<<"p1">>, <<"p2">>, <<"p3">>], lists:reverse(Buffer))
    after 100 ->
        ?assert(false)
    end,
    Info = quic_socket:info(SS4),
    ?assertMatch(#{batch_pending := 0, batch_flushes := 1, packets_coalesced := 3}, Info).

empty_batch_is_not_handed_over_test() ->
    SS0 = conn_sender(self()),
    {ok, _} = quic_socket:flush(SS0),
    receive
        {send_batch, _, _, _} -> ?assert(false)
    after 20 ->
        ok
    end.

%% A dead sender turns the connection back into a direct sender for
%% good; the packets still go out (here: nowhere, on a closed socket,
%% which is what the error path covers) rather than into a dead mailbox.
dead_sender_falls_back_to_direct_test() ->
    Dead = spawn(fun() -> ok end),
    timer:sleep(10),
    {ok, Sock} = gen_udp:open(0, [binary]),
    {ok, SS0} = quic_socket:new_sender(Sock, #{backend => gen_udp, sender_pid => Dead}),
    {ok, SS1} = quic_socket:send(SS0, ?ADDR, 4433, <<"p1">>),
    {ok, SS2} = quic_socket:flush(SS1),
    ?assertMatch(#{batch_pending := 0, batch_flushes := 1}, quic_socket:info(SS2)),
    %% The next batch goes direct without consulting the dead pid.
    {ok, SS3} = quic_socket:send(SS2, ?ADDR, 4433, <<"p2">>),
    {ok, SS4} = quic_socket:flush(SS3),
    ?assertMatch(#{batch_flushes := 2}, quic_socket:info(SS4)),
    gen_udp:close(Sock).

%% End to end on a real socket-backend socket: batches handed to the
%% shared sender reach the wire, in order.
shared_sender_sends_on_the_wire_test() ->
    case quic_socket:open(0, #{}) of
        {ok, SS} ->
            case quic_socket:info(SS) of
                #{backend := socket} -> wire_roundtrip(SS);
                _ -> quic_socket:close(SS)
            end;
        _ ->
            ok
    end.

wire_roundtrip(ListenerSS) ->
    {ok, Recv} = gen_udp:open(0, [binary, {active, true}]),
    {ok, RecvPort} = inet:port(Recv),
    {Sender, Counter} = quic_socket:start_shared_sender(ListenerSS),
    {ok, {_, _}} = quic_socket:sockname(ListenerSS),
    {ok, Conn0} = quic_socket:new_sender(quic_socket:test_socket(ListenerSS), #{
        backend => socket, sender_pid => Sender, gso_counter => Counter
    }),
    {ok, Conn1} = quic_socket:send(Conn0, ?ADDR, RecvPort, <<"one">>),
    {ok, Conn2} = quic_socket:send(Conn1, ?ADDR, RecvPort, <<"two">>),
    {ok, _} = quic_socket:flush(Conn2),
    Got = [
        receive
            {udp, Recv, _, _, D} -> D
        after 1000 -> timeout
        end
     || _ <- [1, 2]
    ],
    ?assertEqual([<<"one">>, <<"two">>], Got),
    Sender ! stop,
    gen_udp:close(Recv),
    quic_socket:close(ListenerSS).
