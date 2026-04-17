%%% -*- erlang -*-
%%%
%%% Tests for QUIC Listener
%%% RFC 9000 Section 5 - Connections
%%%

-module(quic_listener_tests).

%% Logger handler callback for the send_packet error-visibility tests.
%% Referenced via `?MODULE' in logger:add_handler/3.
-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

%% Generate a test certificate and key for server
generate_test_cert() ->
    %% For tests, use dummy data - real certs would be loaded from files
    Cert = <<"test_certificate_data">>,
    % Simplified for tests
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

%%====================================================================
%% Listener Lifecycle Tests
%%====================================================================

start_stop_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener),
    timer:sleep(10),
    ?assertNot(is_process_alive(Listener)).

get_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Port = quic_listener:get_port(Listener),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    ok = quic_listener:stop(Listener).

specific_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    %% Use a random high port
    TestPort = 40000 + rand:uniform(10000),
    {ok, Listener} = quic_listener:start_link(TestPort, Opts),
    ActualPort = quic_listener:get_port(Listener),
    ?assertEqual(TestPort, ActualPort),
    ok = quic_listener:stop(Listener).

get_connections_empty_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Connections = quic_listener:get_connections(Listener),
    ?assertEqual([], Connections),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Multiple Listener Tests
%%====================================================================

multiple_listeners_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener1} = quic_listener:start_link(0, Opts),
    {ok, Listener2} = quic_listener:start_link(0, Opts),
    Port1 = quic_listener:get_port(Listener1),
    Port2 = quic_listener:get_port(Listener2),
    ?assertNotEqual(Port1, Port2),
    ok = quic_listener:stop(Listener1),
    ok = quic_listener:stop(Listener2).

%%====================================================================
%% ALPN Configuration Tests
%%====================================================================

alpn_list_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>, <<"hq-29">>, <<"hq-28">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

default_alpn_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Certificate Chain Tests
%%====================================================================

cert_chain_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    IntermediateCert = <<"intermediate_cert">>,
    RootCert = <<"root_cert">>,
    Opts = #{
        cert => Cert,
        cert_chain => [IntermediateCert, RootCert],
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Connection Handler Callback Tests
%%====================================================================

connection_handler_registration_test() ->
    %% Test that connection_handler option is accepted
    {Cert, PrivKey} = generate_test_cert(),
    TestPid = self(),
    Handler = fun(ConnPid, ConnRef) ->
        %% Notify test that handler was invoked
        TestPid ! {handler_invoked, ConnPid, ConnRef},
        HandlerPid = spawn(fun() ->
            receive
                stop -> ok
            after 5000 -> ok
            end
        end),
        {ok, HandlerPid}
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

connection_handler_error_handling_test() ->
    %% Test that connection_handler errors are handled gracefully
    {Cert, PrivKey} = generate_test_cert(),
    %% Handler that returns an error
    Handler = fun(_ConnPid, _ConnRef) ->
        {error, test_error}
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

connection_handler_invalid_return_test() ->
    %% Test that invalid connection_handler return values are handled
    {Cert, PrivKey} = generate_test_cert(),
    %% Handler that returns unexpected value
    Handler = fun(_ConnPid, _ConnRef) ->
        invalid_return
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Connection Cleanup Tests
%%====================================================================

%% Test that cleanup_connection properly removes CID entries for dead processes
%% This tests the fix for the bug where literal atom '_' was used instead of
%% the match spec variable '$1', causing entries to never be cleaned up
cleanup_connection_removes_entries_test() ->
    %% Create an ETS table like the listener uses
    Conns = ets:new(test_conns, [set, public]),

    %% Create fake connection PIDs
    Pid1 = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Pid2 = spawn(fun() ->
        receive
            stop -> ok
        end
    end),

    %% Insert CID entries for both connections (mimics create_connection)
    CID1a = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID1b = <<10, 20, 30, 40, 50, 60, 70, 80>>,
    CID2a = <<11, 12, 13, 14, 15, 16, 17, 18>>,
    CID2b = <<21, 22, 23, 24, 25, 26, 27, 28>>,

    ets:insert(Conns, {CID1a, Pid1}),
    ets:insert(Conns, {CID1b, Pid1}),
    ets:insert(Conns, {CID2a, Pid2}),
    ets:insert(Conns, {CID2b, Pid2}),

    %% Verify all 4 entries exist
    ?assertEqual(4, ets:info(Conns, size)),

    %% Simulate cleanup for Pid1 using the same logic as quic_listener
    Pattern = {{'$1', Pid1}, [], [true]},
    ets:select_delete(Conns, [Pattern]),

    %% Verify Pid1's entries are removed, Pid2's remain
    ?assertEqual(2, ets:info(Conns, size)),
    ?assertEqual([], ets:lookup(Conns, CID1a)),
    ?assertEqual([], ets:lookup(Conns, CID1b)),
    ?assertEqual([{CID2a, Pid2}], ets:lookup(Conns, CID2a)),
    ?assertEqual([{CID2b, Pid2}], ets:lookup(Conns, CID2b)),

    %% Cleanup
    Pid1 ! stop,
    Pid2 ! stop,
    ets:delete(Conns).

%% Test both '_' and '$1' work as wildcards in match specs
cleanup_connection_match_spec_variants_test() ->
    %% Both '_' and '$1' work as wildcards in ETS match specs
    Conns = ets:new(test_conns, [set, public]),

    Pid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID2 = <<9, 10, 11, 12, 13, 14, 15, 16>>,

    %% Test with '_' wildcard
    ets:insert(Conns, {CID1, Pid}),
    ?assertEqual(1, ets:info(Conns, size)),

    Pattern1 = {{'_', Pid}, [], [true]},
    Deleted1 = ets:select_delete(Conns, [Pattern1]),
    ?assertEqual(1, Deleted1),
    ?assertEqual(0, ets:info(Conns, size)),

    %% Test with '$1' match variable
    ets:insert(Conns, {CID2, Pid}),
    ?assertEqual(1, ets:info(Conns, size)),

    Pattern2 = {{'$1', Pid}, [], [true]},
    Deleted2 = ets:select_delete(Conns, [Pattern2]),
    ?assertEqual(1, Deleted2),
    ?assertEqual(0, ets:info(Conns, size)),

    %% Cleanup
    Pid ! stop,
    ets:delete(Conns).

%%====================================================================
%% send_packet/6 error handling + logger visibility
%%====================================================================

%% Minimal logger handler that forwards only the listener_send_failed
%% report to the configured pid. Any other log event is silently
%% ignored so the test process mailbox is not polluted by unrelated
%% warnings from concurrent eunit tests.
log(
    #{level := warning, msg := {report, #{what := listener_send_failed} = R}},
    #{config := #{pid := Pid}}
) ->
    Pid ! {listener_send_failed, R};
log(_Event, _Config) ->
    ok.

install_capture() ->
    Id = list_to_atom(
        "quic_listener_capture_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    ok = logger:add_handler(Id, ?MODULE, #{
        level => warning,
        config => #{pid => self()}
    }),
    Id.

remove_capture(Id) ->
    logger:remove_handler(Id).

wait_for_listener_warning(Timeout) ->
    receive
        {listener_send_failed, R} -> {ok, R}
    after Timeout ->
        timeout
    end.

send_packet_gen_udp_surfaces_and_logs_error_test() ->
    Id = install_capture(),
    try
        {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
        ok = gen_udp:close(Sock),
        Result = quic_listener:send_packet(
            Sock, undefined, gen_udp, {127, 0, 0, 1}, 65535, <<"x">>
        ),
        ?assertMatch({error, _}, Result),
        ?assertMatch({ok, #{backend := gen_udp}}, wait_for_listener_warning(1000))
    after
        remove_capture(Id)
    end.

send_packet_socket_backend_surfaces_and_logs_error_test() ->
    Id = install_capture(),
    try
        {ok, Raw} = socket:open(inet, dgram, udp),
        {ok, State} = quic_socket:new_sender(Raw, #{backend => socket}),
        ok = socket:close(Raw),
        Result = quic_listener:send_packet(
            undefined, State, socket, {127, 0, 0, 1}, 65535, <<"x">>
        ),
        ?assertMatch({error, _}, Result),
        ?assertMatch({ok, #{backend := socket}}, wait_for_listener_warning(1000))
    after
        remove_capture(Id)
    end.
