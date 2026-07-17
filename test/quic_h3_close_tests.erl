%%% -*- erlang -*-
%%%
%%% Tests for how quic_h3_connection reacts to the underlying QUIC
%%% connection process going DOWN: a clean QUIC exit (normal,
%%% shutdown, {shutdown, _}) must stop the H3 process with `normal'
%%% (no crash report, no abnormal link-EXIT to the owner), while an
%%% abnormal QUIC exit stops it with {quic_closed, Reason}. In both
%%% cases the owner receives {quic_h3, Conn, closed}.

-module(quic_h3_close_tests).

-include_lib("eunit/include/eunit.hrl").

%% logger handler callback
-export([log/2]).

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    ok.

teardown(_) ->
    meck:unload(quic),
    ok.

quic_down_normal_is_graceful_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        Capture = install_capture(),
        {FakeQuicConn, H3Conn, Mon} = start_client(),
        FakeQuicConn ! {exit_with, normal},
        expect_closed(H3Conn),
        expect_down(Mon, normal),
        assert_no_error_log(H3Conn),
        remove_capture(Capture)
    end}.

quic_down_shutdown_is_graceful_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        Capture = install_capture(),
        {FakeQuicConn, H3Conn, Mon} = start_client(),
        FakeQuicConn ! {exit_with, {shutdown, drained}},
        expect_closed(H3Conn),
        expect_down(Mon, normal),
        assert_no_error_log(H3Conn),
        remove_capture(Capture)
    end}.

quic_down_abnormal_propagates_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        Capture = install_capture(),
        {FakeQuicConn, H3Conn, Mon} = start_client(),
        FakeQuicConn ! {exit_with, boom},
        expect_closed(H3Conn),
        expect_down(Mon, {quic_closed, boom}),
        expect_error_log(H3Conn),
        remove_capture(Capture)
    end}.

server_quic_down_normal_is_graceful_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        Capture = install_capture(),
        FakeQuicConn = spawn(fun fake_quic_loop/0),
        {ok, H3Conn} = gen_statem:start_link(
            quic_h3_connection, {server, FakeQuicConn, #{}, self()}, []
        ),
        unlink(H3Conn),
        Mon = monitor(process, H3Conn),
        ?assertEqual(awaiting_quic, current_state(H3Conn)),
        FakeQuicConn ! {exit_with, normal},
        expect_closed(H3Conn),
        expect_down(Mon, normal),
        assert_no_error_log(H3Conn),
        remove_capture(Capture)
    end}.

%%====================================================================
%% Helpers
%%====================================================================

start_client() ->
    FakeQuicConn = spawn(fun fake_quic_loop/0),
    {ok, H3Conn} = quic_h3_connection:start_link(FakeQuicConn, <<"example.com">>, 443, #{}),
    unlink(H3Conn),
    Mon = monitor(process, H3Conn),
    ?assertEqual(bootstrapping, current_state(H3Conn)),
    {FakeQuicConn, H3Conn, Mon}.

fake_quic_loop() ->
    receive
        {exit_with, Reason} -> exit(Reason);
        _ -> fake_quic_loop()
    end.

current_state(Pid) ->
    {StateName, _StateData} = sys:get_state(Pid, 1000),
    StateName.

expect_closed(H3Conn) ->
    receive
        {quic_h3, H3Conn, closed} -> ok
    after 1000 ->
        error(no_closed_message)
    end.

expect_down(Mon, ExpectedReason) ->
    receive
        {'DOWN', Mon, process, _, Reason} ->
            ?assertEqual(ExpectedReason, Reason)
    after 1000 ->
        error(no_down)
    end.

%%====================================================================
%% Logger capture: forward every error-level event's origin pid so a
%% test can assert whether the H3 process emitted a crash report.
%%====================================================================

log(#{level := error, meta := Meta}, #{config := #{pid := Pid}}) ->
    Pid ! {error_log, maps:get(pid, Meta, undefined)};
log(_Event, _Config) ->
    ok.

install_capture() ->
    Id = list_to_atom(
        "quic_h3_close_capture_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    ok = logger:add_handler(Id, ?MODULE, #{
        level => error,
        config => #{pid => self()}
    }),
    Id.

remove_capture(Id) ->
    logger:remove_handler(Id).

assert_no_error_log(Pid) ->
    receive
        {error_log, Pid} -> error({unexpected_crash_report, Pid})
    after 200 ->
        ok
    end.

expect_error_log(Pid) ->
    receive
        {error_log, Pid} -> ok
    after 1000 ->
        error(no_crash_report)
    end.
