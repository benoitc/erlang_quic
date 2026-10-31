%%% -*- erlang -*-
%%%
%%% The interop server answers a batch of requests in shared packets.
%%%
%%% Answering one request at a time with a synchronous send puts every
%%% response in a datagram of its own. In the runner's zerortt test that
%%% is a burst of some 40 small packets, more than the simulated link's
%%% 25-packet queue holds.

-module(quic_interop_server_batch_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([responses_share_packets/1]).

-define(FILES, 40).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [responses_share_packets].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

responses_share_packets(Config) ->
    Www = filename:join(?config(priv_dir, Config), "www"),
    ok = filelib:ensure_path(Www),
    Names = [lists:flatten(io_lib:format("file~2..0B", [N])) || N <- lists:seq(1, ?FILES)],
    [ok = file:write_file(filename:join(Www, N), <<"0123456789abcdef">>) || N <- Names],
    {ok, Server} = quic_test_echo_server:start(#{
        alpn => [<<"hq-interop">>],
        connection_handler => fun(Conn, DCID) ->
            quic_interop_server:spawn_handler(Conn, DCID, Www, "transfer")
        end
    }),
    try
        Counter = counters:new(1, []),
        Conn = connect_counting(maps:get(port, Server), Counter),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 15000 -> ct:fail("connect timeout")
        end,
        timer:sleep(500),
        Before = counters:get(Counter, 1),
        Sids = [element(2, {ok, _} = quic:open_stream(Conn)) || _ <- Names],
        ok = sys:suspend(Conn),
        [
            ok = quic:send_data_async(
                Conn, Sid, <<"GET /", (list_to_binary(N))/binary, "\r\n">>, true
            )
         || {Sid, N} <- lists:zip(Sids, Names)
        ],
        ok = sys:resume(Conn),
        ok = await_fins(Conn, Sids),
        Datagrams = counters:get(Counter, 1) - Before,
        ct:pal("~p responses in ~p datagrams", [?FILES, Datagrams]),
        ?assert(Datagrams < ?FILES div 2),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

await_fins(_Conn, []) ->
    ok;
await_fins(Conn, Pending) ->
    receive
        {quic, Conn, {stream_data, Sid, _Data, true}} ->
            await_fins(Conn, lists:delete(Sid, Pending));
        {quic, Conn, _Other} ->
            await_fins(Conn, Pending)
    after 10000 ->
        ct:fail({responses_missing, Pending})
    end.

connect_counting(Port, Counter) ->
    SocketRef = make_ref(),
    Bridge = quic_test_bridge:start(#{
        server => {{127, 0, 0, 1}, Port},
        socket_ref => SocketRef,
        drop_in => fun(_Pkt, _N) ->
            counters:add(Counter, 1, 1),
            false
        end
    }),
    Adapter = #{
        send_fun => fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },
    Opts = #{
        verify => false,
        alpn => [<<"hq-interop">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ok = quic_test_bridge:set_conn(Bridge, Conn),
    Conn.
