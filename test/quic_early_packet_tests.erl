%%% -*- erlang -*-
%%%
%%% Datagrams that arrive before the keys to read them (RFC 9001 Section
%%% 5.7): the client keeps them and reads them once the keys arrive, so a
%%% reordered server flight does not wait for a retransmission.

-module(quic_early_packet_tests).

-include_lib("eunit/include/eunit.hrl").

%% The server's first datagram (its Initial, carrying the ServerHello) is
%% delivered after the second, so the client sees Handshake data first.
%% Kept and read once the keys arrive, it needs no retransmission: the
%% server sends as many datagrams as when nothing is reordered.
reordered_server_flight_test_() ->
    {timeout, 30, fun reordered_server_flight/0}.

reordered_server_flight() ->
    InOrder = handshake(fun(_Pkt, _N) -> false end),
    Reordered = handshake(fun(_Pkt, N) -> N =:= 1 end),
    ?assertEqual(InOrder, Reordered).

%% Connect through the relay, echo once, and return how many datagrams
%% the server sent.
handshake(Hold) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Port = maps:get(port, Server),
        SocketRef = make_ref(),
        Bridge = quic_test_bridge:start(#{
            server => {{127, 0, 0, 1}, Port},
            socket_ref => SocketRef,
            hold_in => Hold
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
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ?assert(false)
        end,
        Sent = quic_test_bridge:delivered_in(Bridge),
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"ping">>, true),
        ?assertEqual(<<"ping">>, await_echo(Conn, StreamId)),
        _ = quic:safe_close(Conn, normal),
        Sent
    after
        quic_test_echo_server:stop(Server)
    end.

await_echo(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} -> Data;
        {quic, Conn, _Other} -> await_echo(Conn, StreamId)
    after 5000 -> timeout
    end.
