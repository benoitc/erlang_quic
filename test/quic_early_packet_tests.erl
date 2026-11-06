%%% -*- erlang -*-
%%%
%%% Datagrams that arrive before the keys to read them (RFC 9001 Section
%%% 5.7): the client keeps them and reads them once the keys arrive, so a
%%% reordered server flight does not wait for a retransmission.

-module(quic_early_packet_tests).

-include_lib("eunit/include/eunit.hrl").

%% The server's first flight is three datagrams: its Initial (with the
%% ServerHello) and two Handshake ones. The Initial is delivered after the
%% first Handshake datagram, and nothing more from the server gets through
%% until the client is connected. Read once its keys arrive, the early
%% Handshake datagram is enough; dropped, the client could only connect
%% from a retransmission, which never arrives.
reordered_server_flight_test_() ->
    {timeout, 30, fun reordered_server_flight/0}.

reordered_server_flight() ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Port = maps:get(port, Server),
        SocketRef = make_ref(),
        Connected = counters:new(1, []),
        Bridge = quic_test_bridge:start(#{
            server => {{127, 0, 0, 1}, Port},
            socket_ref => SocketRef,
            hold_in => fun(_Pkt, N) -> N =:= 1 end,
            drop_in => fun(_Pkt, N) -> N > 3 andalso counters:get(Connected, 1) =:= 0 end
        }),
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            socket_backend => adapter,
            socket_adapter => #{
                send_fun => fun(IP, P, Pkt) ->
                    Bridge ! {send, IP, P, Pkt},
                    ok
                end,
                close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
                local => {{127, 0, 0, 1}, 0},
                socket_ref => SocketRef
            }
        },
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        ok = quic_test_bridge:set_conn(Bridge, Conn),
        Result =
            receive
                {quic, Conn, {connected, _}} -> connected
            after 3000 -> timeout
            end,
        counters:put(Connected, 1, 1),
        ?assertEqual(connected, Result),
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"ping">>, true),
        ?assertEqual(<<"ping">>, await_echo(Conn, StreamId)),
        _ = quic:safe_close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

await_echo(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} -> Data;
        {quic, Conn, _Other} -> await_echo(Conn, StreamId)
    after 5000 -> timeout
    end.
