%%% -*- erlang -*-
%%%
%%% Unit tests for QUIC multi-pool server API
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_server_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Test Helpers
%%====================================================================

%% A certificate and the key that signs for it. start_server/3 refuses a
%% pair that could not complete a handshake, so placeholder bytes will
%% not do even though these cases never connect.
generate_test_cert() ->
    quic_test_echo_server:cert_and_key().

%% Create base server options with required cert/key
base_opts() ->
    {Cert, PrivKey} = generate_test_cert(),
    #{cert => Cert, key => PrivKey, alpn => [<<"h3">>]}.

%%====================================================================
%% Test setup/teardown
%%====================================================================

setup() ->
    %% Start the application (it will be shared across tests)
    case whereis(quic_sup) of
        undefined ->
            {ok, _} = application:ensure_all_started(quic);
        _ ->
            ok
    end,
    ok.

cleanup(_) ->
    %% Clean up servers but keep the application running
    Servers =
        try
            quic:which_servers()
        catch
            _:_ -> []
        end,
    lists:foreach(
        fun(Name) ->
            _ = quic:stop_server(Name),
            _ =
                (try
                    quic_server_registry:unregister(Name)
                catch
                    _:_ -> ok
                end)
        end,
        Servers
    ),
    %% Wait for cleanup
    timer:sleep(50),
    ok.

%%====================================================================
%% Test generators
%%====================================================================

server_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"Start and stop server", fun start_stop_server_test/0},
        {"Multiple servers", fun multiple_servers_test/0},
        {"Duplicate name error", fun duplicate_name_test/0},
        {"Get server info", fun get_server_info_test/0},
        {"Server not found", fun server_not_found_test/0},
        {"Pool size option", fun pool_size_test/0},
        {"One listener by default", fun default_pool_size_test/0},
        {"A single listener does not share its port", fun single_listener_port_test/0},
        {"Pool connections are listed once", fun pool_connections_listed_once_test/0},
        {"Which servers", fun which_servers_test/0},
        {"Get server port", fun get_server_port_test/0},
        {"Get server sockname", fun get_server_sockname_test/0},
        {"Badarg tests", fun badarg_test/0}
    ]}.

%%====================================================================
%% Test cases
%%====================================================================

start_stop_server_test() ->
    %% Start server with required cert/key options
    Result = quic:start_server(test_server, 0, base_opts()),
    ?assertMatch({ok, _Pid}, Result),
    {ok, Pid} = Result,
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),

    %% Verify it's registered
    ?assertEqual([test_server], quic:which_servers()),

    %% Stop server
    ?assertEqual(ok, quic:stop_server(test_server)),

    %% Brief delay for cleanup
    timer:sleep(50),

    %% Verify it's gone
    ?assertEqual([], quic:which_servers()).

multiple_servers_test() ->
    %% Start multiple servers on different ports
    {ok, Pid1} = quic:start_server(server1, 0, base_opts()),
    {ok, Pid2} = quic:start_server(server2, 0, base_opts()),
    {ok, Pid3} = quic:start_server(server3, 0, base_opts()),

    ?assert(is_pid(Pid1)),
    ?assert(is_pid(Pid2)),
    ?assert(is_pid(Pid3)),

    %% All different PIDs
    ?assertNotEqual(Pid1, Pid2),
    ?assertNotEqual(Pid2, Pid3),
    ?assertNotEqual(Pid1, Pid3),

    %% All registered
    Servers = quic:which_servers(),
    ?assertEqual(3, length(Servers)),
    ?assert(lists:member(server1, Servers)),
    ?assert(lists:member(server2, Servers)),
    ?assert(lists:member(server3, Servers)),

    %% Stop one
    quic:stop_server(server2),
    timer:sleep(50),

    Servers2 = quic:which_servers(),
    ?assertEqual(2, length(Servers2)),
    ?assertNot(lists:member(server2, Servers2)).

duplicate_name_test() ->
    {ok, _} = quic:start_server(dup_server, 0, base_opts()),

    %% Try to start another with same name
    Result = quic:start_server(dup_server, 0, base_opts()),
    ?assertMatch({error, {already_started, dup_server}}, Result).

get_server_info_test() ->
    {ok, Pid} = quic:start_server(info_server, 0, base_opts()),

    %% Get info
    {ok, Info} = quic:get_server_info(info_server),

    ?assertEqual(Pid, maps:get(pid, Info)),
    ?assert(is_integer(maps:get(port, Info))),
    %% Port 0 means ephemeral
    ?assert(maps:get(port, Info) >= 0),
    ?assert(is_integer(maps:get(started_at, Info))),

    %% Opts should contain the name added by start_server
    StoredOpts = maps:get(opts, Info),
    ?assertEqual([<<"h3">>], maps:get(alpn, StoredOpts)).

server_not_found_test() ->
    ?assertEqual({error, not_found}, quic:get_server_info(nonexistent)),
    ?assertEqual({error, not_found}, quic:get_server_port(nonexistent)),
    ?assertEqual({error, not_found}, quic:get_server_sockname(nonexistent)),
    ?assertEqual({error, not_found}, quic:get_server_connections(nonexistent)).

pool_size_test() ->
    %% Start server with pool_size
    Opts = maps:merge(base_opts(), #{pool_size => 4}),
    {ok, _} = quic:start_server(pool_server, 0, Opts),

    %% Get info and verify opts
    {ok, Info} = quic:get_server_info(pool_server),
    StoredOpts = maps:get(opts, Info),
    ?assertEqual(4, maps:get(pool_size, StoredOpts)),
    ?assertEqual(4, length(quic_listener_sup:get_listeners(maps:get(pid, Info)))).

default_pool_size_test() ->
    {ok, Sup} = quic:start_server(default_pool_server, 0, base_opts()),
    ?assertMatch([_], quic_listener_sup:get_listeners(Sup)).

%% SO_REUSEPORT is for the listeners of a pool. On a lone listener it
%% would let any other socket that sets it bind the port and take a
%% share of the datagrams.
single_listener_port_test() ->
    {ok, _} = quic:start_server(single_listener_server, 0, base_opts()),
    {ok, Port} = quic:get_server_port(single_listener_server),
    Result = gen_udp:open(Port, [binary, {reuseport, true}]),
    case Result of
        {ok, Socket} -> gen_udp:close(Socket);
        _ -> ok
    end,
    ?assertEqual({error, eaddrinuse}, Result).

pool_connections_listed_once_test() ->
    Test = self(),
    Opts = maps:merge(base_opts(), #{
        pool_size => 2,
        connection_handler => fun(ConnPid) ->
            Test ! {conn, ConnPid},
            {ok, Test}
        end
    }),
    {ok, Sup} = quic:start_server(listed_once_server, 0, Opts),
    [Listener | _] = quic_listener_sup:get_listeners(Sup),
    {ok, Sock} = gen_udp:open(0, [binary]),
    %% Only the header is parsed to route it; padded to the 1200 bytes a
    %% client Initial datagram has.
    Header = <<16#C0, 1:32, 8, 1:64, 4, 2:32>>,
    Initial = <<Header/binary, 0:((1200 - byte_size(Header)) * 8)>>,
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, quic_listener:get_port(Listener), Initial),
    gen_udp:close(Sock),
    receive
        {conn, ConnPid} ->
            ?assertEqual({ok, [ConnPid]}, quic:get_server_connections(listed_once_server))
    after 5000 -> error(no_connection)
    end.

which_servers_test() ->
    %% Clean up any leftover servers from previous tests
    lists:foreach(
        fun(N) ->
            _ = quic:stop_server(N),
            _ =
                (try
                    quic_server_registry:unregister(N)
                catch
                    _:_ -> ok
                end)
        end,
        quic:which_servers()
    ),
    timer:sleep(100),

    %% Now should be empty
    ?assertEqual([], quic:which_servers()),

    %% Add servers
    {ok, _} = quic:start_server(ws1, 0, base_opts()),
    ?assertEqual([ws1], quic:which_servers()),

    {ok, _} = quic:start_server(ws2, 0, base_opts()),
    Servers = quic:which_servers(),
    ?assertEqual(2, length(Servers)),
    ?assert(lists:member(ws1, Servers)),
    ?assert(lists:member(ws2, Servers)).

get_server_port_test() ->
    {ok, _} = quic:start_server(port_server, 0, base_opts()),

    %% Port 0 means ephemeral - should return actual OS-assigned port (> 0)
    {ok, Port} = quic:get_server_port(port_server),
    ?assert(is_integer(Port)),
    %% Ephemeral ports are never 0
    ?assert(Port > 0),
    ?assert(Port < 65536),

    %% Second call should also return the same port (cached in registry)
    {ok, Port2} = quic:get_server_port(port_server),
    ?assertEqual(Port, Port2).

get_server_sockname_test() ->
    {ok, _} = quic:start_server(sockname_server, 0, base_opts()),

    %% Resolved live from the socket; port matches get_server_port/1.
    {ok, {IP, Port}} = quic:get_server_sockname(sockname_server),
    ?assert(is_tuple(IP)),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    ?assert(Port < 65536),
    {ok, PortViaPort} = quic:get_server_port(sockname_server),
    ?assertEqual(PortViaPort, Port).

badarg_test() ->
    %% Invalid name
    ?assertEqual({error, badarg}, quic:start_server("not_atom", 0, #{})),
    ?assertEqual({error, badarg}, quic:stop_server("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_info("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_port("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_sockname("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_connections("not_atom")),

    %% Invalid port
    ?assertEqual({error, badarg}, quic:start_server(test, -1, #{})),
    ?assertEqual({error, badarg}, quic:start_server(test, 70000, #{})),

    %% Invalid opts
    ?assertEqual({error, badarg}, quic:start_server(test, 0, not_a_map)).
