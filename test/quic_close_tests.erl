%%% -*- erlang -*-
%%%
%%% Tests for QUIC connection close handling
%%% Issue #19: Crashes in draining state when owner exits
%%%

-module(quic_close_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Issue #19: Owner exit during draining
%%====================================================================

%% The connection is linked to its owner and traps exits, so it stops
%% with the owner's exit reason. Anything else means it crashed on its own.
owner_exit_after_close_test() ->
    {Owner, Conn, Mon} = with_owner(fun(Pid) ->
        quic_connection:close(Pid, normal),
        exit(normal)
    end),
    ?assertEqual(normal, await_down(Conn, Mon)),
    ?assertNot(is_process_alive(Owner)).

owner_crash_after_close_test() ->
    {Owner, Conn, Mon} = with_owner(fun(Pid) ->
        quic_connection:close(Pid, normal),
        exit(crash_test)
    end),
    ?assertEqual(crash_test, await_down(Conn, Mon)),
    ?assertNot(is_process_alive(Owner)).

%% Owner returns before the connection has processed the close.
owner_exit_before_close_processed_test() ->
    {Owner, Conn, Mon} = with_owner(fun(Pid) ->
        quic_connection:close(Pid, normal)
    end),
    ?assertEqual(normal, await_down(Conn, Mon)),
    ?assertNot(is_process_alive(Owner)).

%% Owner exits once the connection is draining.
draining_handles_owner_exit_test() ->
    {Owner, Conn, Mon} = with_owner(fun(Pid) ->
        quic_connection:close(Pid, normal),
        receive
            {quic, Pid, {closed, normal}} -> ok
        after 1000 ->
            exit(no_closed_event)
        end
    end),
    ?assertEqual(normal, await_down(Conn, Mon)),
    ?assertNot(is_process_alive(Owner)).

%% Start a connection owned by a new process and monitor it before the
%% owner runs Fun, so the exit reason is observed however fast it dies.
with_owner(Fun) ->
    TestPid = self(),
    Owner = spawn(fun() ->
        {ok, Pid} = quic_connection:start_link(
            "127.0.0.1", quic_test_silent_peer:port(), #{}, self()
        ),
        TestPid ! {conn_pid, self(), Pid},
        receive
            go -> Fun(Pid)
        end
    end),
    Conn =
        receive
            {conn_pid, Owner, P} -> P
        after 1000 ->
            error(timeout_waiting_for_conn_pid)
        end,
    Mon = erlang:monitor(process, Conn),
    Owner ! go,
    {Owner, Conn, Mon}.

await_down(Conn, Mon) ->
    receive
        {'DOWN', Mon, process, Conn, Reason} -> Reason
    after 5000 ->
        error(connection_still_running)
    end.

%%====================================================================
%% Synchronous close tests
%%====================================================================

%% Test that close triggers draining state and sends closed message
close_sends_closed_message_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Close the connection (doesn't need to be connected to test close behavior)
    quic_connection:close(Pid, normal),

    %% Wait for the closed message - should be sent when entering draining
    receive
        {quic, Pid, {closed, normal}} -> ok
    after 1000 ->
        error(no_closed_event)
    end,

    %% Wait for connection to finish
    timer:sleep(100).

%%====================================================================
%% Application Error Code Tests (Issue #31)
%%====================================================================

%% Test close/3 with custom error code and reason phrase
close_with_app_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Close with custom application error code
    ErrorCode = 16#0100,
    ReasonPhrase = <<"custom error reason">>,
    quic_connection:close(Pid, {app_error, ErrorCode, ReasonPhrase}),

    %% Wait for the closed message with the app_error reason
    receive
        {quic, Pid, {closed, {app_error, ErrorCode, ReasonPhrase}}} -> ok
    after 1000 ->
        error(no_closed_event)
    end,

    timer:sleep(100).

%% Test close/3 API with zero error code (QUIC_NO_ERROR equivalent)
close_with_zero_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Close with error code 0 (no error)
    quic_connection:close(Pid, {app_error, 0, <<>>}),

    receive
        {quic, Pid, {closed, {app_error, 0, <<>>}}} -> ok
    after 1000 ->
        error(no_closed_event)
    end,

    timer:sleep(100).

%% Test close/3 API with maximum valid 62-bit error code
close_with_max_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Close with maximum 62-bit error code
    MaxErrorCode = (1 bsl 62) - 1,
    quic_connection:close(Pid, {app_error, MaxErrorCode, <<"max code">>}),

    receive
        {quic, Pid, {closed, {app_error, MaxErrorCode, <<"max code">>}}} -> ok
    after 1000 ->
        error(no_closed_event)
    end,

    timer:sleep(100).

%% Test quic:close/3 public API
quic_close_3_api_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Use the public API
    ErrorCode = 42,
    ReasonPhrase = <<"test reason">>,
    ok = quic:close(Pid, ErrorCode, ReasonPhrase),

    timer:sleep(100).

%% Test that close/2 with legacy {error, application_error} still works
close_legacy_application_error_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", quic_test_silent_peer:port(), #{}, self()),

    %% Close with legacy pattern (used in E2E tests)
    quic_connection:close(Pid, {error, application_error}),

    receive
        {quic, Pid, {closed, {error, application_error}}} -> ok
    after 1000 ->
        error(no_closed_event)
    end,

    timer:sleep(100).

%%====================================================================
%% close_reason_to_code Tests
%%====================================================================

%% Test close_reason_to_code for new app_error pattern
close_reason_to_code_app_error_test() ->
    %% app_error with code should return the code
    ?assertEqual(256, quic_connection:close_reason_to_code({app_error, 256, <<"reason">>})),
    ?assertEqual(0, quic_connection:close_reason_to_code({app_error, 0, <<>>})),
    ?assertEqual(65535, quic_connection:close_reason_to_code({app_error, 65535, <<"test">>})).

%% Test close_reason_to_code for peer_closed patterns
close_reason_to_code_peer_closed_test() ->
    %% Application close from peer
    ?assertEqual(
        100, quic_connection:close_reason_to_code({peer_closed, application, 100, <<"reason">>})
    ),
    %% Transport close from peer
    ?assertEqual(
        200, quic_connection:close_reason_to_code({peer_closed, transport, 200, 0, <<"reason">>})
    ).

%% Test close_reason_to_code for legacy patterns
close_reason_to_code_legacy_test() ->
    ?assertEqual(0, quic_connection:close_reason_to_code(connection_closed)),
    ?assertEqual(0, quic_connection:close_reason_to_code(normal)),
    ?assertEqual(stateless_reset, quic_connection:close_reason_to_code(stateless_reset)),
    ?assertEqual(idle_timeout, quic_connection:close_reason_to_code(idle_timeout)),
    ?assertEqual(42, quic_connection:close_reason_to_code({error, 42})),
    ?assertEqual(
        ?QUIC_APPLICATION_ERROR, quic_connection:close_reason_to_code({error, application_error})
    ),
    %% Atoms are returned as-is (for qlog compatibility)
    ?assertEqual(some_atom_reason, quic_connection:close_reason_to_code(some_atom_reason)),
    %% Non-atoms/non-matching patterns return 'unknown'
    ?assertEqual(unknown, quic_connection:close_reason_to_code({some, tuple})).
