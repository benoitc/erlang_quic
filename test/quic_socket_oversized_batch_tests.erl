%%% -*- erlang -*-
%%%
%%% A datagram the kernel refuses as too large (EMSGSIZE) is lost on its
%%% own; the packets batched after it still go out. With DF set, a DPLPMTUD
%%% probe above the interface MTU fails this way (RFC 9000 §14.4, RFC 8899),
%%% and the packets behind it are already tracked as sent.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_socket_oversized_batch_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LOCALHOST, {127, 0, 0, 1}).
-define(TOO_LARGE, 65600).

gen_udp_batch_continues_past_oversized_datagram_test() ->
    batch_continues(gen_udp).

socket_batch_continues_past_oversized_datagram_test() ->
    batch_continues(socket).

gso_test_() ->
    case os:type() of
        {unix, linux} ->
            [
                fun gso_runs_continue_past_oversized_datagram/0,
                fun gso_run_refused_as_too_large_is_sent_per_segment/0
            ];
        _ ->
            []
    end.

gso_runs_continue_past_oversized_datagram() ->
    Before = [packet(N, 1200) || N <- [1, 2]],
    After = [packet(N, 1200) || N <- [3, 4]],
    Runs = [{gso, 1200, Before}, {single, packet(0, ?TOO_LARGE)}, {gso, 1200, After}],
    ?assertEqual(Before ++ After, send_runs(Runs)).

gso_run_refused_as_too_large_is_sent_per_segment() ->
    Small = [packet(N, 1200) || N <- [1, 2]],
    Large = [packet(N, 32768) || N <- [3, 4, 5]],
    ?assertEqual(Small ++ Large, send_runs([{gso, 1200, Small}, {gso, 32768, Large}])).

send_runs(Runs) ->
    with_receiver(fun(Recv, Port) ->
        {ok, S} = socket:open(inet, dgram, udp),
        try
            Dest = #{family => inet, addr => ?LOCALHOST, port => Port},
            ?assertEqual(ok, quic_socket:send_runs(S, Dest, Runs)),
            recv_all(Recv)
        after
            socket:close(S)
        end
    end).

batch_continues(Backend) ->
    with_receiver(fun(Recv, Port) ->
        {ok, S0} = quic_socket:open_for_send(?LOCALHOST, #{
            backend => Backend,
            gso => false,
            batching => #{enabled => true, max_packets => 64}
        }),
        Before = [packet(N, 1200) || N <- [1, 2]],
        After = [packet(N, 1200) || N <- [3, 4]],
        Batch = Before ++ [packet(0, ?TOO_LARGE)] ++ After,
        S1 = lists:foldl(
            fun(P, S) ->
                {ok, S1} = quic_socket:send(S, ?LOCALHOST, Port, P),
                S1
            end,
            S0,
            Batch
        ),
        try
            ?assertMatch({ok, _}, quic_socket:flush(S1)),
            ?assertEqual(Before ++ After, recv_all(Recv))
        after
            quic_socket:close(S1)
        end
    end).

packet(N, Size) ->
    <<N, (binary:copy(<<0>>, Size - 1))/binary>>.

with_receiver(F) ->
    {ok, Recv} = gen_udp:open(0, [binary, {active, false}, {ip, ?LOCALHOST}, {recbuf, 1 bsl 20}]),
    {ok, Port} = inet:port(Recv),
    try
        F(Recv, Port)
    after
        gen_udp:close(Recv)
    end.

recv_all(Recv) ->
    case gen_udp:recv(Recv, 0, 200) of
        {ok, {_, _, Data}} -> [Data | recv_all(Recv)];
        {error, timeout} -> []
    end.
