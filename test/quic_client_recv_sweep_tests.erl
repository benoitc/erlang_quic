%% The client receiver sweeps what the socket already holds before it
%% wakes the connection, so datagrams that arrived while the connection
%% was busy reach it as one train instead of one message each. Driven
%% through the real receiver process on loopback sockets, with the test
%% process as the owner: a burst arrives as one train in order, the
%% sweep budget splits a larger burst into full trains, and a datagram
%% from another source is forwarded on its own after the train.
-module(quic_client_recv_sweep_tests).
-include_lib("eunit/include/eunit.hrl").

%% The client receiver exists only on the socket backend (OTP 27+ on
%% Linux); elsewhere there is nothing to test.
with_socket_backend(Fun) ->
    case maps:get(backend, quic_socket:detect_capabilities()) of
        socket -> Fun();
        _ -> ok
    end.

receiver() ->
    {ok, S} = quic_socket:open(0, #{backend => socket, batching => #{enabled => false}}),
    {ok, #{port := Port}} = socket:sockname(quic_socket:test_socket(S)),
    {S, Port}.

sender() ->
    {ok, S} = socket:open(inet, dgram, udp),
    ok = socket:bind(S, #{family => inet, addr => {127, 0, 0, 1}, port => 0}),
    {ok, #{port := Port}} = socket:sockname(S),
    {S, Port}.

send_all(S, Port, Payloads) ->
    [
        ok = socket:sendto(S, P, #{family => inet, addr => {127, 0, 0, 1}, port => Port})
     || P <- Payloads
    ],
    ok.

payloads(N) ->
    [<<I:16, 0:(200 * 8)>> || I <- lists:seq(1, N)].

%% Collect forwarded trains until Expected packets have arrived.
collect(Expected, Acc) ->
    case length(lists:append(Acc)) >= Expected of
        true -> lists:reverse(Acc);
        false -> collect_more(Expected, Acc)
    end.

collect_more(Expected, Acc) ->
    receive
        {udp, _, _, _, P} -> collect(Expected, [[P] | Acc]);
        {udp_batch, _, _, _, Ps} -> collect(Expected, [Ps | Acc])
    after 2000 ->
        error({timeout, lists:reverse(Acc)})
    end.

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

burst_arrives_as_one_train_test() ->
    with_socket_backend(fun() ->
        flush(),
        {R, RPort} = receiver(),
        {S, _} = sender(),
        Ps = payloads(10),
        %% Queue the burst before the receiver starts so the first read
        %% finds the rest already on the socket.
        send_all(S, RPort, Ps),
        timer:sleep(20),
        {ok, Pid} = quic_socket:start_client_receiver(R, self(), 512),
        Trains = collect(10, []),
        ?assertEqual([Ps], Trains),
        ok = quic_socket:stop_client_receiver(Pid),
        socket:close(S),
        quic_socket:close(R)
    end).

budget_splits_a_large_burst_test() ->
    with_socket_backend(fun() ->
        flush(),
        {R, RPort} = receiver(),
        {S, _} = sender(),
        Ps = payloads(150),
        send_all(S, RPort, Ps),
        timer:sleep(50),
        {ok, Pid} = quic_socket:start_client_receiver(R, self(), 512),
        Trains = collect(150, []),
        ?assertEqual(Ps, lists:append(Trains)),
        ?assert(lists:all(fun(T) -> length(T) =< 64 end, Trains)),
        ?assert(length(Trains) < 150 div 8),
        ok = quic_socket:stop_client_receiver(Pid),
        socket:close(S),
        quic_socket:close(R)
    end).

other_source_ends_the_train_test() ->
    with_socket_backend(fun() ->
        flush(),
        {R, RPort} = receiver(),
        {S1, P1} = sender(),
        {S2, P2} = sender(),
        [A, B, C] = payloads(3),
        send_all(S1, RPort, [A, B]),
        timer:sleep(10),
        send_all(S2, RPort, [C]),
        timer:sleep(20),
        {ok, Pid} = quic_socket:start_client_receiver(R, self(), 512),
        Msgs = collect_raw(2, []),
        ?assertMatch(
            [{udp_batch, _, {127, 0, 0, 1}, P1, [A, B]}, {udp, _, {127, 0, 0, 1}, P2, C}], Msgs
        ),
        ok = quic_socket:stop_client_receiver(Pid),
        socket:close(S1),
        socket:close(S2),
        quic_socket:close(R)
    end).

collect_raw(0, Acc) ->
    lists:reverse(Acc);
collect_raw(N, Acc) ->
    receive
        {udp, _, _, _, _} = M -> collect_raw(N - 1, [M | Acc]);
        {udp_batch, _, _, _, _} = M -> collect_raw(N - 1, [M | Acc])
    after 2000 ->
        error({timeout, lists:reverse(Acc)})
    end.
