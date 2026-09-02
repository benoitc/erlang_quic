%%% -*- erlang -*-
%%%
%%% Bulk stream sends go out as chunk runs: many full-size packets
%%% sealed and handed to the socket in one loop with one bookkeeping
%%% pass. The wire must not notice: every byte arrives, in order, on
%%% both socket backends, with pacing on and off.
-module(quic_bulk_run_send_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    gen_udp_paced/1,
    gen_udp_unpaced/1,
    socket_paced/1,
    socket_unpaced/1
]).

-define(SIZE, 3 * 1024 * 1024).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [gen_udp_paced, gen_udp_unpaced, socket_paced, socket_unpaced].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

gen_udp_paced(_) -> round_trip(gen_udp, true).
gen_udp_unpaced(_) -> round_trip(gen_udp, false).
socket_paced(_) -> round_trip(socket, true).
socket_unpaced(_) -> round_trip(socket, false).

%% One stream, one send of ?SIZE random bytes with FIN, echoed back.
round_trip(Backend, Pacing) ->
    {ok, Server} = quic_test_echo_server:start(#{
        socket_backend => Backend,
        max_data => 64 * 1024 * 1024
    }),
    Port = maps:get(port, Server),
    try
        {ok, Conn} = quic:connect(
            <<"127.0.0.1">>,
            Port,
            #{
                verify => false,
                alpn => [<<"echo">>],
                socket_backend => Backend,
                pacing_enabled => Pacing,
                max_data => 64 * 1024 * 1024,
                max_stream_data_bidi_local => 8 * 1024 * 1024,
                max_stream_data_bidi_remote => 8 * 1024 * 1024
            },
            self()
        ),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ct:fail(connect_timeout)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        Data = crypto:strong_rand_bytes(?SIZE),
        T0 = erlang:monotonic_time(millisecond),
        ok = quic:send_data(Conn, StreamId, Data, true),
        Echo = collect(Conn, StreamId, <<>>),
        T1 = erlang:monotonic_time(millisecond),
        ct:pal("~p pacing=~p: ~p bytes round trip in ~p ms", [
            Backend, Pacing, byte_size(Echo), T1 - T0
        ]),
        ?assertEqual(?SIZE, byte_size(Echo)),
        ?assertEqual(Data, Echo),
        ok = quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

collect(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Chunk, Fin}} ->
            Acc1 = <<Acc/binary, Chunk/binary>>,
            case Fin orelse byte_size(Acc1) >= ?SIZE of
                true -> Acc1;
                false -> collect(Conn, StreamId, Acc1)
            end;
        {quic, Conn, {closed, Reason}} ->
            ct:fail({closed_before_fin, Reason, byte_size(Acc)})
    after 30000 ->
        ct:fail({echo_timeout, byte_size(Acc)})
    end.
