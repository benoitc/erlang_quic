%%% -*- erlang -*-
%%%
%%% End-to-end smoke test for the opt-in `socket_backend => socket'
%%% client path. Verifies a 64 KB echo round-trip works with the OTP
%%% socket NIF + dedicated receiver process instead of gen_udp + active
%%% mode.

-module(quic_client_socket_backend_tests).

-include_lib("eunit/include/eunit.hrl").

client_socket_backend_roundtrip_test_() ->
    {timeout, 30, fun client_socket_backend_roundtrip/0}.

client_socket_backend_migrate_test_() ->
    {timeout, 30, fun client_socket_backend_migrate/0}.

client_socket_backend_roundtrip() ->
    {ok, Srv} = quic_test_echo_server:start(#{
        max_data => 16 * 1024 * 1024,
        max_stream_data_bidi_local => 8 * 1024 * 1024,
        max_stream_data_bidi_remote => 8 * 1024 * 1024,
        max_stream_data_uni => 8 * 1024 * 1024
    }),
    try
        #{port := Port} = Srv,
        ClientOpts = maps:merge(quic_test_echo_server:client_opts(), #{
            socket_backend => socket,
            max_data => 16 * 1024 * 1024,
            max_stream_data_bidi_local => 8 * 1024 * 1024,
            max_stream_data_bidi_remote => 8 * 1024 * 1024,
            max_stream_data_uni => 8 * 1024 * 1024
        }),
        {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                ?assert(false)
            end,
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = crypto:strong_rand_bytes(64 * 1024),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            Received = collect_echo(Conn, StreamId, <<>>, 10000),
            ?assertEqual(Payload, Received)
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

%% Migration on the socket backend must rebind the OTP socket + its
%% receiver process and still exchange traffic on the new path.
client_socket_backend_migrate() ->
    {ok, Srv} = quic_test_echo_server:start(#{
        max_data => 16 * 1024 * 1024,
        max_stream_data_bidi_local => 8 * 1024 * 1024,
        max_stream_data_bidi_remote => 8 * 1024 * 1024,
        max_stream_data_uni => 8 * 1024 * 1024
    }),
    try
        #{port := Port} = Srv,
        ClientOpts = maps:merge(quic_test_echo_server:client_opts(), #{
            socket_backend => socket,
            max_data => 16 * 1024 * 1024,
            max_stream_data_bidi_local => 8 * 1024 * 1024,
            max_stream_data_bidi_remote => 8 * 1024 * 1024,
            max_stream_data_uni => 8 * 1024 * 1024
        }),
        {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                ?assert(false)
            end,
            ?assertEqual(ok, quic:migrate(Conn)),
            %% After migration the stream should still echo.
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = crypto:strong_rand_bytes(4096),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            Received = collect_echo(Conn, StreamId, <<>>, 10000),
            ?assertEqual(Payload, Received)
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

client_pre_opened_socket_rejects_socket_backend_test_() ->
    {timeout, 10, fun client_pre_opened_socket_rejects_socket_backend/0}.

%% A caller that passes a pre-opened gen_udp socket via the `socket'
%% option *and* requests `socket_backend => socket' asks for two
%% incompatible things: the pre-opened handle is a gen_udp port, not
%% an OTP socket NIF handle. `quic:connect/4' must reject the
%% combination with an error, not crash inside init.
client_pre_opened_socket_rejects_socket_backend() ->
    {ok, Srv} = quic_test_echo_server:start(#{}),
    try
        #{port := Port} = Srv,
        {ok, UdpSocket} = gen_udp:open(0, [binary, {active, false}]),
        try
            Opts = maps:merge(quic_test_echo_server:client_opts(), #{
                socket => UdpSocket,
                socket_backend => socket
            }),
            Result = quic:connect("127.0.0.1", Port, Opts, self()),
            ?assertMatch({error, {incompatible_options, _}}, Result)
        after
            catch gen_udp:close(UdpSocket)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

client_receiver_crash_closes_connection_test_() ->
    {timeout, 15, fun client_receiver_crash_closes_connection/0}.

%% If the dedicated receiver process dies, the connection has no way
%% to receive datagrams and must close promptly rather than sit idle
%% until max_idle_timeout fires.
client_receiver_crash_closes_connection() ->
    process_flag(trap_exit, true),
    {ok, Srv} = quic_test_echo_server:start(#{}),
    try
        #{port := Port} = Srv,
        ClientOpts = maps:merge(quic_test_echo_server:client_opts(), #{
            socket_backend => socket
        }),
        {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                ?assert(false)
            end,
            Receiver = find_receiver(Conn),
            ?assertNotEqual(undefined, Receiver),
            exit(Receiver, kill),
            receive
                {quic, Conn, {closed, {receiver_exit, _}}} ->
                    ok;
                {quic, Conn, {closed, _Other}} ->
                    ?assert(false)
            after 3000 ->
                error(no_close_event)
            end
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

%% Locate the client's recv-loop process by scanning links of the
%% connection and matching on `quic_socket:client_recv_loop' anywhere
%% in the process's current stacktrace.
find_receiver(Conn) ->
    {links, Links} = process_info(Conn, links),
    Candidates = [P || P <- Links, is_pid(P), is_client_recv_loop(P)],
    case Candidates of
        [Pid | _] -> Pid;
        [] -> undefined
    end.

is_client_recv_loop(Pid) ->
    case process_info(Pid, current_stacktrace) of
        {current_stacktrace, Stack} ->
            lists:any(
                fun
                    ({quic_socket, client_recv_loop, _, _}) -> true;
                    (_) -> false
                end,
                Stack
            );
        _ ->
            false
    end.

collect_echo(Conn, StreamId, Acc, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_echo(Conn, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic, Conn, {stream_closed, StreamId, _}} ->
            Acc;
        {quic, Conn, {closed, _}} ->
            Acc;
        %% Ignore unrelated events (e.g. session_ticket) that may show
        %% up in the owner mailbox before the echoed stream data does.
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Acc, Timeout)
    after Timeout ->
        error({collect_timeout, byte_size(Acc)})
    end.
