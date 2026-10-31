%%% -*- erlang -*-
%%%
%%% A NAT rebinding during the handshake.
%%%
%%% The client's port changes after its first datagram, before the
%%% server's reply gets back, so the old port is dead from the start.
%%% The client retransmits from the new port; a server that keeps
%%% sending its flight to the old port never completes the handshake.

-module(quic_handshake_rebind_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([control_plain_handshake/1, completes_after_a_rebind_before_the_first_reply/1]).

-define(CONNECT_MS, 15000).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [control_plain_handshake, completes_after_a_rebind_before_the_first_reply].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

control_plain_handshake(_Config) ->
    with_server(fun(Port) ->
        Conn = connect_through_bridge(Port, #{}),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

completes_after_a_rebind_before_the_first_reply(_Config) ->
    with_server(fun(Port) ->
        Conn = connect_through_bridge(Port, #{rebind_at => 2}),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

%%====================================================================
%% Harness
%%====================================================================

with_server(Fun) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Fun(maps:get(port, Server))
    after
        quic_test_echo_server:stop(Server)
    end.

connected_within(Conn, Budget) ->
    receive
        {quic, Conn, {connected, _}} -> ok;
        {quic, Conn, {closed, Reason}} -> ct:fail({closed_during_handshake, Reason})
    after Budget -> ct:fail("connect timeout")
    end.

echo_roundtrip(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = <<"rebind check">>,
    ok = quic:send_data(Conn, StreamId, Payload, true),
    ?assertEqual(Payload, collect_echo(Conn, StreamId, 5000, <<>>)).

collect_echo(Conn, StreamId, Budget, Acc) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Acc1 = <<Acc/binary, Data/binary>>,
            case Fin of
                true -> Acc1;
                false -> collect_echo(Conn, StreamId, Budget - spent(Start), Acc1)
            end;
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc)
    after max(0, Budget) -> Acc
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

connect_through_bridge(Port, BridgeOpts) ->
    SocketRef = make_ref(),
    Bridge = quic_test_bridge:start(BridgeOpts#{
        server => {{127, 0, 0, 1}, Port},
        socket_ref => SocketRef
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
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ok = quic_test_bridge:set_conn(Bridge, Conn),
    Conn.
