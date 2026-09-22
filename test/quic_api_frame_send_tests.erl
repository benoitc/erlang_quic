%%% -*- erlang -*-
%%%
%%% A frame queued through the API has to leave straight away.
%%%
%%% quic:reset_stream/3, quic:reset_stream_at/4, quic:stop_sending/3
%%% and quic:send_ping/1 queue a frame on the connection. Like any other API call that queues
%%% a frame, the call has to send it before returning, or it waits for
%%% whatever traffic next flushes the connection, which on a quiet
%%% connection may never come.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_api_frame_send_tests).

-include_lib("eunit/include/eunit.hrl").

%% Well under eunit's 5 s per-test limit, so a frame that never leaves
%% fails on its assertion rather than as a timeout.
-define(WAIT_MS, 2000).

-define(CODE, 16#0107).

reset_stream_reaches_the_peer_test() ->
    with_quiet_stream(#{}, fun(Tag, Conn, StreamId) ->
        ok = quic:reset_stream(Conn, StreamId, ?CODE),
        ?assertEqual({stream_reset, StreamId, ?CODE}, await_server(Tag, stream_reset))
    end).

reset_stream_at_reaches_the_peer_test() ->
    with_quiet_stream(#{reset_stream_at => true}, fun(Tag, Conn, StreamId) ->
        ok = quic:reset_stream_at(Conn, StreamId, ?CODE, 0),
        ?assertEqual({stream_reset, StreamId, ?CODE}, await_server(Tag, stream_reset))
    end).

stop_sending_reaches_the_peer_test() ->
    with_quiet_stream(#{}, fun(Tag, Conn, StreamId) ->
        ok = quic:stop_sending(Conn, StreamId, ?CODE),
        ?assertEqual({stop_sending, StreamId, ?CODE}, await_server(Tag, stop_sending))
    end).

send_ping_reaches_the_peer_test() ->
    with_quiet_stream(#{}, fun(Tag, Conn, _StreamId) ->
        Before = server_packets(Tag),
        ok = quic:send_ping(Conn),
        ?assertEqual(received, await_server_packet(Tag, Before))
    end).

%% The fence: with nothing asked for, the server hears nothing, so what
%% it hears above is what the call sent.
quiet_stream_stays_quiet_test() ->
    with_quiet_stream(#{}, fun(Tag, _Conn, _StreamId) ->
        Before = server_packets(Tag),
        ?assertEqual(timeout, await_server(Tag, stream_reset)),
        ?assertEqual(Before, server_packets(Tag))
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% A connected client with one open stream whose first write the server
%% has received, and nothing left in flight on either side.
with_quiet_stream(Extra, F) ->
    Test = self(),
    Tag = make_ref(),
    {ok, Server} = quic_test_echo_server:start(Extra#{
        connection_handler => fun(ConnPid, _ConnRef) ->
            Test ! {server_conn, Tag, ConnPid},
            Relay = spawn(fun() -> relay(Test, Tag) end),
            ok = quic:set_owner_sync(ConnPid, Relay),
            {ok, Relay}
        end
    }),
    try
        Port = maps:get(port, Server),
        Opts = maps:merge(quic_test_echo_server:client_opts(), Extra#{alpn => [<<"echo">>]}),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?WAIT_MS -> error(connect_timeout)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"ping">>, false),
        {stream_data, StreamId, <<"ping">>, false} = await_server(Tag, stream_data),
        %% Let the ACKs for the write settle so nothing else flushes the
        %% client's send batch.
        timer:sleep(200),
        try
            F(Tag, Conn, StreamId)
        after
            _ = quic:close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Server)
    end.

relay(Test, Tag) ->
    receive
        {quic, _Conn, Event} -> Test ! {server, Tag, Event};
        _ -> ok
    end,
    relay(Test, Tag).

server_packets(Tag) ->
    receive
        {server_conn, Tag, ServerConn} = Msg ->
            self() ! Msg,
            {ok, #{packets_received := N}} = quic:get_stats(ServerConn),
            N
    after 0 -> error(no_server_conn)
    end.

%% Polls the server's receive count until it moves past Before.
await_server_packet(Tag, Before) ->
    Deadline = erlang:monotonic_time(millisecond) + ?WAIT_MS,
    await_server_packet(Tag, Before, Deadline).

await_server_packet(Tag, Before, Deadline) ->
    case server_packets(Tag) > Before of
        true ->
            received;
        false ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    timer:sleep(20),
                    await_server_packet(Tag, Before, Deadline);
                false ->
                    timeout
            end
    end.

await_server(Tag, Type) ->
    receive
        {server, Tag, Event} when element(1, Event) =:= Type -> Event
    after ?WAIT_MS -> timeout
    end.
