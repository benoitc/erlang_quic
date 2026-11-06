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
            %% A new path needs a CID not used on the old one
            %% (RFC 9000 Section 9.5), and the peer's arrives just
            %% after `connected'.
            ?assert(quic_connection_test_support:await_spare_cid(Conn, 5000)),
            {ok, {_, OldPort}} = quic:sockname(Conn),
            ?assertEqual(ok, quic:migrate(Conn)),
            %% sockname follows the rebound socket.
            {ok, {_, NewPort}} = quic:sockname(Conn),
            ?assertNotEqual(OldPort, NewPort),
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

%% A move made while there is no network at all: every datagram is lost
%% until the network comes back just before the disconnect timeout, then
%% data has to flow again on the path the client moved to. Probe backoff
%% puts the next probe after the deadline, so the connection lives only
%% if it probes once more before giving up. The relay plays a NAT (one
%% upstream socket per client source) so the server sees a new address.
migrate_without_network_test_() ->
    {timeout, 60, fun migrate_without_network/0}.

migrate_without_network() ->
    {ok, Srv} = quic_test_echo_server:start(#{}),
    #{port := SrvPort} = Srv,
    {Relay, RelayPort} = start_relay(SrvPort),
    try
        {ok, Conn} = quic:connect(
            "127.0.0.1",
            RelayPort,
            (quic_test_echo_server:client_opts())#{disconnect_timeout => 5000},
            self()
        ),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> ?assert(false)
            end,
            {ok, S1} = quic:open_stream(Conn),
            ok = quic:send_data(Conn, S1, <<"before">>, true),
            ?assertEqual(<<"before">>, collect_echo(Conn, S1, <<>>, 5000)),
            ?assert(quic_connection_test_support:await_spare_cid(Conn, 5000)),
            Relay ! {up, false},
            ?assertEqual(ok, quic:migrate(Conn)),
            {ok, S2} = quic:open_stream(Conn),
            ok = quic:send_data(Conn, S2, <<"during">>, true),
            timer:sleep(4700),
            Relay ! {up, true},
            ?assertEqual(<<"during">>, collect_echo(Conn, S2, <<>>, 15000)),
            {ok, S3} = quic:open_stream(Conn),
            ok = quic:send_data(Conn, S3, <<"after">>, true),
            ?assertEqual(<<"after">>, collect_echo(Conn, S3, <<>>, 10000)),
            %% The move reached the server as a second NAT mapping.
            Relay ! {mappings, self()},
            receive
                {mappings, N} -> ?assertEqual(2, N)
            after 1000 -> ?assert(false)
            end
        after
            quic:safe_close(Conn)
        end
    after
        exit(Relay, kill),
        quic_test_echo_server:stop(Srv)
    end.

start_relay(SrvPort) ->
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, Front} = gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
        {ok, Port} = inet:port(Front),
        Parent ! {relay_port, self(), Port},
        relay(Front, SrvPort, true, #{})
    end),
    receive
        {relay_port, Pid, Port} -> {Pid, Port}
    end.

relay(Front, SrvPort, Up, Nat) ->
    receive
        {up, Up1} ->
            relay(Front, SrvPort, Up1, Nat);
        {mappings, From} ->
            From ! {mappings, map_size(Nat)},
            relay(Front, SrvPort, Up, Nat);
        {udp, Front, IP, Port, Data} ->
            {Back, Nat1} = nat_entry({IP, Port}, Nat),
            Up andalso gen_udp:send(Back, {127, 0, 0, 1}, SrvPort, Data),
            relay(Front, SrvPort, Up, Nat1);
        {udp, Back, _IP, _Port, Data} ->
            case [Client || {Client, B} <- maps:to_list(Nat), B =:= Back] of
                [{CIP, CPort}] when Up -> gen_udp:send(Front, CIP, CPort, Data);
                _ -> ok
            end,
            relay(Front, SrvPort, Up, Nat)
    end.

nat_entry(Client, Nat) ->
    case Nat of
        #{Client := Back} ->
            {Back, Nat};
        _ ->
            {ok, Back} = gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
            {Back, Nat#{Client => Back}}
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
