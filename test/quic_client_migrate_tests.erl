%%% -*- erlang -*-
%%%
%%% Regression test for the default gen_udp client migration path.
%%% Mirrors the socket-backend migrate test so the shared
%%% `rebind_client_socket/1' dispatcher has coverage on both backends.

-module(quic_client_migrate_tests).

-include_lib("eunit/include/eunit.hrl").

client_gen_udp_migrate_test_() ->
    {timeout, 30, fun client_gen_udp_migrate/0}.

client_gen_udp_migrate() ->
    do_migrate(#{}, "127.0.0.1").

%% Regression for the IPv6 client path: migration rebind must reopen an
%% IPv6 socket, not silently fall back to inet.
client_gen_udp_migrate_ipv6_test_() ->
    {timeout, 30, fun client_gen_udp_migrate_ipv6/0}.

client_gen_udp_migrate_ipv6() ->
    case ipv6_available() of
        false ->
            ok;
        true ->
            do_migrate(#{extra_socket_opts => [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]}, "::1")
    end.

do_migrate(ServerExtra, Host) ->
    {ok, Srv} = quic_test_echo_server:start(
        maps:merge(
            #{
                max_data => 16 * 1024 * 1024,
                max_stream_data_bidi_local => 8 * 1024 * 1024,
                max_stream_data_bidi_remote => 8 * 1024 * 1024,
                max_stream_data_uni => 8 * 1024 * 1024
            },
            ServerExtra
        )
    ),
    try
        #{port := Port} = Srv,
        ClientOpts = maps:merge(quic_test_echo_server:client_opts(), #{
            max_data => 16 * 1024 * 1024,
            max_stream_data_bidi_local => 8 * 1024 * 1024,
            max_stream_data_bidi_remote => 8 * 1024 * 1024,
            max_stream_data_uni => 8 * 1024 * 1024
        }),
        {ok, Conn} = quic:connect(Host, Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                ?assert(false)
            end,
            ?assertEqual(ok, quic:migrate(Conn)),
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = crypto:strong_rand_bytes(4096),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            Received = collect_echo(Conn, StreamId, <<>>, 10000),
            ?assertEqual(Payload, Received)
        after
            quic:safe_close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

ipv6_available() ->
    case gen_udp:open(0, [binary, inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}]) of
        {ok, S} ->
            gen_udp:close(S),
            true;
        {error, _} ->
            false
    end.

collect_echo(Conn, StreamId, Acc, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_echo(Conn, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic, Conn, {closed, _}} ->
            Acc;
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Acc, Timeout)
    after Timeout ->
        error({collect_timeout, byte_size(Acc)})
    end.
