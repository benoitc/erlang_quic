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

%% Generate dummy test certificate and key (same as listener tests)
generate_test_cert() ->
    Cert = <<"test_certificate_data">>,
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

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
            _ = (catch quic_server_registry:unregister(Name))
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
        {"Which servers", fun which_servers_test/0},
        {"Get server port", fun get_server_port_test/0},
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
    ?assertEqual({error, not_found}, quic:get_server_connections(nonexistent)).

pool_size_test() ->
    %% Start server with pool_size
    Opts = maps:merge(base_opts(), #{pool_size => 4}),
    {ok, _} = quic:start_server(pool_server, 0, Opts),

    %% Get info and verify opts
    {ok, Info} = quic:get_server_info(pool_server),
    StoredOpts = maps:get(opts, Info),
    ?assertEqual(4, maps:get(pool_size, StoredOpts)).

which_servers_test() ->
    %% Clean up any leftover servers from previous tests
    lists:foreach(
        fun(N) ->
            _ = quic:stop_server(N),
            _ = (catch quic_server_registry:unregister(N))
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

badarg_test() ->
    %% Invalid name
    ?assertEqual({error, badarg}, quic:start_server("not_atom", 0, #{})),
    ?assertEqual({error, badarg}, quic:stop_server("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_info("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_port("not_atom")),
    ?assertEqual({error, badarg}, quic:get_server_connections("not_atom")),

    %% Invalid port
    ?assertEqual({error, badarg}, quic:start_server(test, -1, #{})),
    ?assertEqual({error, badarg}, quic:start_server(test, 70000, #{})),

    %% Invalid opts
    ?assertEqual({error, badarg}, quic:start_server(test, 0, not_a_map)).
