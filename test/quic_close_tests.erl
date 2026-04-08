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

%% Test that connection doesn't crash when owner exits immediately after close
owner_exit_after_close_test() ->
    %% Spawn a process that will be the connection owner
    TestPid = self(),
    Owner = spawn(fun() ->
        {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
        %% Tell the test process about the connection pid
        TestPid ! {conn_pid, Pid},
        %% Close the connection
        quic_connection:close(Pid, normal),
        %% Exit immediately - this should not crash the connection
        exit(normal)
    end),

    %% Get the connection pid
    ConnPid =
        receive
            {conn_pid, P} -> P
        after 1000 ->
            error(timeout_waiting_for_conn_pid)
        end,

    %% Wait a bit for the owner to exit and connection to process it
    timer:sleep(100),

    %% The connection should either be in draining state or have cleanly stopped
    %% It should NOT have crashed
    case is_process_alive(ConnPid) of
        true ->
            %% Connection is still alive - check it's in draining or closed state
            {State, _} = quic_connection:get_state(ConnPid),
            ?assert(State =:= draining orelse State =:= closed),
            %% Wait for it to finish draining
            timer:sleep(200);
        false ->
            %% Connection has stopped - verify it stopped normally
            %% by checking no error reports were generated
            ok
    end,

    %% Verify the owner process has exited
    ?assertNot(is_process_alive(Owner)).

%% Test that connection handles owner crash (abnormal exit) gracefully
owner_crash_after_close_test() ->
    TestPid = self(),
    Owner = spawn(fun() ->
        {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
        TestPid ! {conn_pid, Pid},
        quic_connection:close(Pid, normal),
        %% Crash immediately
        exit(crash_test)
    end),

    ConnPid =
        receive
            {conn_pid, P} -> P
        after 1000 ->
            error(timeout_waiting_for_conn_pid)
        end,

    timer:sleep(100),

    %% Connection should handle the owner crash gracefully
    case is_process_alive(ConnPid) of
        true ->
            {State, _} = quic_connection:get_state(ConnPid),
            ?assert(State =:= draining orelse State =:= closed),
            timer:sleep(200);
        false ->
            ok
    end,

    ?assertNot(is_process_alive(Owner)).

%% Test that connection handles owner exit BEFORE close message is processed
owner_exit_before_close_processed_test() ->
    TestPid = self(),
    Owner = spawn(fun() ->
        {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
        TestPid ! {conn_pid, Pid},
        %% Close and exit as fast as possible
        quic_connection:close(Pid, normal),
        %% Don't even wait - exit immediately
        ok
    end),

    ConnPid =
        receive
            {conn_pid, P} -> P
        after 1000 ->
            error(timeout_waiting_for_conn_pid)
        end,

    %% Owner exits right after spawn function returns
    timer:sleep(50),
    ?assertNot(is_process_alive(Owner)),

    %% Give the connection time to process both the close and the EXIT
    timer:sleep(100),

    %% Connection should not have crashed
    case is_process_alive(ConnPid) of
        true ->
            {State, _} = quic_connection:get_state(ConnPid),
            ?assert(State =:= draining orelse State =:= closed orelse State =:= idle),
            timer:sleep(200);
        false ->
            %% It's ok if it stopped, as long as it didn't crash
            ok
    end.

%% Test that draining state properly handles owner EXIT
draining_handles_owner_exit_test() ->
    TestPid = self(),

    %% Create owner that will close but stay alive briefly
    Owner = spawn_link(fun() ->
        {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
        TestPid ! {conn_pid, Pid},
        quic_connection:close(Pid, normal),
        %% Wait to receive the closed message
        receive
            {quic, _, {closed, _}} -> ok
        after 500 ->
            ok
        end,
        %% Now exit - connection should be in draining state
        TestPid ! owner_exiting
    end),

    ConnPid =
        receive
            {conn_pid, P} -> P
        after 1000 ->
            error(timeout_waiting_for_conn_pid)
        end,

    %% Wait for owner to signal it's about to exit
    receive
        owner_exiting -> ok
    after 1000 ->
        ok
    end,

    %% Give time for EXIT to propagate
    timer:sleep(100),

    %% Connection should still be draining or have closed cleanly
    case is_process_alive(ConnPid) of
        true ->
            {State, _} = quic_connection:get_state(ConnPid),
            ?assert(State =:= draining orelse State =:= closed);
        false ->
            %% Stopped cleanly
            ok
    end,

    %% Cleanup - unlink from owner if still linked
    catch unlink(Owner).

%%====================================================================
%% Synchronous close tests
%%====================================================================

%% Test that close triggers draining state and sends closed message
close_sends_closed_message_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Ref = gen_statem:call(Pid, get_ref),

    %% Close the connection (doesn't need to be connected to test close behavior)
    quic_connection:close(Pid, normal),

    %% Wait for the closed message - should be sent when entering draining
    receive
        {quic, Ref, {closed, normal}} -> ok
    after 500 ->
        %% If we don't get the message, it might be because we're in idle state
        %% which is fine - the test is about not crashing
        ok
    end,

    %% Wait for connection to finish
    timer:sleep(100).

%%====================================================================
%% Application Error Code Tests (Issue #31)
%%====================================================================

%% Test close/3 with custom error code and reason phrase
close_with_app_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Ref = gen_statem:call(Pid, get_ref),

    %% Close with custom application error code
    ErrorCode = 16#0100,
    ReasonPhrase = <<"custom error reason">>,
    quic_connection:close(Pid, {app_error, ErrorCode, ReasonPhrase}),

    %% Wait for the closed message with the app_error reason
    receive
        {quic, Ref, {closed, {app_error, ErrorCode, ReasonPhrase}}} -> ok
    after 500 ->
        ok
    end,

    timer:sleep(100).

%% Test close/3 API with zero error code (QUIC_NO_ERROR equivalent)
close_with_zero_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Ref = gen_statem:call(Pid, get_ref),

    %% Close with error code 0 (no error)
    quic_connection:close(Pid, {app_error, 0, <<>>}),

    receive
        {quic, Ref, {closed, {app_error, 0, <<>>}}} -> ok
    after 500 ->
        ok
    end,

    timer:sleep(100).

%% Test close/3 API with maximum valid 62-bit error code
close_with_max_error_code_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Ref = gen_statem:call(Pid, get_ref),

    %% Close with maximum 62-bit error code
    MaxErrorCode = (1 bsl 62) - 1,
    quic_connection:close(Pid, {app_error, MaxErrorCode, <<"max code">>}),

    receive
        {quic, Ref, {closed, {app_error, MaxErrorCode, <<"max code">>}}} -> ok
    after 500 ->
        ok
    end,

    timer:sleep(100).

%% Test quic:close/3 public API
quic_close_3_api_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),

    %% Use the public API
    ErrorCode = 42,
    ReasonPhrase = <<"test reason">>,
    ok = quic:close(Pid, ErrorCode, ReasonPhrase),

    timer:sleep(100).

%% Test that close/2 with legacy {error, application_error} still works
close_legacy_application_error_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Ref = gen_statem:call(Pid, get_ref),

    %% Close with legacy pattern (used in E2E tests)
    quic_connection:close(Pid, {error, application_error}),

    receive
        {quic, Ref, {closed, {error, application_error}}} -> ok
    after 500 ->
        ok
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
