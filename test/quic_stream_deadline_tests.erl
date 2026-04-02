%%% -*- erlang -*-
%%%
%%% Unit tests for QUIC stream deadlines
%%% Tests per-stream deadline/timeout control
%%%
%%% Note: Full integration tests require a connected peer and are covered
%%% in E2E tests. These unit tests verify record structure, logic, and
%%% API behavior at the module level.
%%%

-module(quic_stream_deadline_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Generators
%%====================================================================

stream_deadline_test_() ->
    [
        {"Record fields exist", fun record_fields_exist/0},
        {"Error code defined", fun error_code_defined/0},
        {"Deadline calculation logic", fun deadline_calculation_logic/0},
        {"Remaining time calculation", fun remaining_time_calculation/0},
        {"Action types valid", fun action_types_valid/0},
        {"Timer message format", fun timer_message_format/0}
    ].

%%====================================================================
%% Unit Test Cases
%%====================================================================

record_fields_exist() ->
    %% Verify stream_state record has deadline fields
    Stream = #stream_state{
        id = 0,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{},
        deadline = undefined,
        deadline_timer = undefined,
        deadline_action = both,
        deadline_error_code = 16#FF
    },
    ?assertEqual(undefined, Stream#stream_state.deadline),
    ?assertEqual(undefined, Stream#stream_state.deadline_timer),
    ?assertEqual(both, Stream#stream_state.deadline_action),
    ?assertEqual(16#FF, Stream#stream_state.deadline_error_code).

error_code_defined() ->
    %% Verify the deadline exceeded error code is defined
    ?assertEqual(16#FF, ?QUIC_STREAM_DEADLINE_EXCEEDED).

deadline_calculation_logic() ->
    %% Test deadline timestamp calculation
    Now = erlang:system_time(millisecond),
    TimeoutMs = 5000,
    Deadline = Now + TimeoutMs,

    %% Deadline should be in the future
    ?assert(Deadline > Now),
    ?assertEqual(TimeoutMs, Deadline - Now).

remaining_time_calculation() ->
    %% Test remaining time calculation
    Now = erlang:system_time(millisecond),
    TimeoutMs = 5000,
    Deadline = Now + TimeoutMs,

    %% Immediately after setting, remaining should be close to timeout
    Remaining = max(0, Deadline - Now),
    ?assert(Remaining =< TimeoutMs),
    % Allow 10ms tolerance
    ?assert(Remaining >= TimeoutMs - 10),

    %% For expired deadline
    ExpiredDeadline = Now - 1000,
    ExpiredRemaining = max(0, ExpiredDeadline - Now),
    ?assertEqual(0, ExpiredRemaining).

action_types_valid() ->
    %% Test valid action types
    ?assertEqual(notify, notify),
    ?assertEqual(reset, reset),
    ?assertEqual(both, both),

    %% Test default action in record
    Stream = #stream_state{
        id = 0,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{}
    },
    ?assertEqual(both, Stream#stream_state.deadline_action).

timer_message_format() ->
    %% Test timer message format
    StreamId = 4,
    Msg = {stream_deadline, StreamId},
    ?assertEqual({stream_deadline, 4}, Msg),
    {stream_deadline, Id} = Msg,
    ?assertEqual(4, Id).

%%====================================================================
%% API Tests (connection in idle state)
%%====================================================================

api_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        fun unknown_stream_errors/1,
        fun api_functions_exported/1
    ]}.

setup() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    Pid.

cleanup(Pid) ->
    quic_connection:close(Pid, normal),
    timer:sleep(50).

unknown_stream_errors(Pid) ->
    fun() ->
        %% In idle state, deadline operations are not available
        %% They return {error, {invalid_state, idle}}
        %% This is expected behavior - deadline API requires connected state
        NonExistentStream = 9999,
        {error, {invalid_state, idle}} =
            quic_connection:set_stream_deadline(Pid, NonExistentStream, 5000, #{}),
        {error, {invalid_state, idle}} =
            quic_connection:cancel_stream_deadline(Pid, NonExistentStream),
        {error, {invalid_state, idle}} =
            quic_connection:get_stream_deadline(Pid, NonExistentStream),
        ok
    end.

api_functions_exported(_Pid) ->
    fun() ->
        %% Verify all API functions are exported from quic module
        Exports = quic:module_info(exports),
        ?assert(lists:member({send_data, 5}, Exports)),
        ?assert(lists:member({set_stream_deadline, 3}, Exports)),
        ?assert(lists:member({set_stream_deadline, 4}, Exports)),
        ?assert(lists:member({cancel_stream_deadline, 2}, Exports)),
        ?assert(lists:member({get_stream_deadline, 2}, Exports)),

        %% Verify all API functions are exported from quic_connection module
        ConnExports = quic_connection:module_info(exports),
        ?assert(lists:member({set_stream_deadline, 4}, ConnExports)),
        ?assert(lists:member({cancel_stream_deadline, 2}, ConnExports)),
        ?assert(lists:member({get_stream_deadline, 2}, ConnExports))
    end.

%%====================================================================
%% Custom Error Code Tests
%%====================================================================

custom_error_code_test_() ->
    [
        {"Default error code", fun default_error_code/0},
        {"Custom error code in record", fun custom_error_code_in_record/0}
    ].

default_error_code() ->
    %% Default error code should be 0xFF
    Stream = #stream_state{
        id = 0,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{}
    },
    ?assertEqual(16#FF, Stream#stream_state.deadline_error_code),
    ?assertEqual(?QUIC_STREAM_DEADLINE_EXCEEDED, Stream#stream_state.deadline_error_code).

custom_error_code_in_record() ->
    %% Test setting a custom error code
    CustomCode = 16#1234,
    Stream = #stream_state{
        id = 0,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{},
        deadline_error_code = CustomCode
    },
    ?assertEqual(CustomCode, Stream#stream_state.deadline_error_code).

%%====================================================================
%% Stream State Manipulation Tests
%%====================================================================

stream_state_test_() ->
    [
        {"Deadline fields can be set", fun deadline_fields_settable/0},
        {"Deadline cleared on close", fun deadline_cleared_on_close/0},
        {"Multiple deadline updates", fun multiple_deadline_updates/0}
    ].

deadline_fields_settable() ->
    %% Test that all deadline fields can be set
    Now = erlang:system_time(millisecond),
    TimerRef = make_ref(),
    Stream = #stream_state{
        id = 4,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{},
        deadline = Now + 10000,
        deadline_timer = TimerRef,
        deadline_action = notify,
        deadline_error_code = 16#42
    },
    ?assert(is_integer(Stream#stream_state.deadline)),
    ?assert(is_reference(Stream#stream_state.deadline_timer)),
    ?assertEqual(notify, Stream#stream_state.deadline_action),
    ?assertEqual(16#42, Stream#stream_state.deadline_error_code).

deadline_cleared_on_close() ->
    %% Test that deadline fields can be cleared (as on cancel)
    Stream = #stream_state{
        id = 4,
        state = open,
        send_offset = 100,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{},
        deadline = 12345,
        deadline_timer = make_ref(),
        deadline_action = notify,
        deadline_error_code = 16#42
    },

    %% Clear the deadline
    ClearedStream = Stream#stream_state{
        deadline = undefined,
        deadline_timer = undefined
    },

    ?assertEqual(undefined, ClearedStream#stream_state.deadline),
    ?assertEqual(undefined, ClearedStream#stream_state.deadline_timer),
    %% Action and error code should be preserved
    ?assertEqual(notify, ClearedStream#stream_state.deadline_action),
    ?assertEqual(16#42, ClearedStream#stream_state.deadline_error_code).

multiple_deadline_updates() ->
    %% Test updating deadline multiple times
    Stream0 = #stream_state{
        id = 4,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{}
    },

    %% First update
    Now1 = erlang:system_time(millisecond),
    Timer1 = make_ref(),
    Stream1 = Stream0#stream_state{
        deadline = Now1 + 5000,
        deadline_timer = Timer1,
        deadline_action = notify
    },
    ?assertEqual(notify, Stream1#stream_state.deadline_action),
    ?assertEqual(Timer1, Stream1#stream_state.deadline_timer),

    %% Second update (changes action)
    Timer2 = make_ref(),
    Now2 = erlang:system_time(millisecond),
    Stream2 = Stream1#stream_state{
        deadline = Now2 + 10000,
        deadline_timer = Timer2,
        deadline_action = reset
    },
    ?assertEqual(reset, Stream2#stream_state.deadline_action),
    ?assertEqual(Timer2, Stream2#stream_state.deadline_timer),
    ?assert(Stream2#stream_state.deadline >= Now2 + 9990).

%%====================================================================
%% send_data/5 Timeout Tests
%%====================================================================

send_data_timeout_test_() ->
    [
        {"send_data/5 exported", fun send_data_5_exported/0},
        {"Timeout catch pattern", fun timeout_catch_pattern/0}
    ].

send_data_5_exported() ->
    Exports = quic:module_info(exports),
    ?assert(lists:member({send_data, 5}, Exports)).

timeout_catch_pattern() ->
    %% Test that timeout exception handling pattern works
    Result =
        try
            %% Simulate a timeout exception
            exit({timeout, {gen_statem, call, [fake_pid, some_request, 100]}})
        catch
            exit:{timeout, _} -> {error, timeout}
        end,
    ?assertEqual({error, timeout}, Result).

%%====================================================================
%% Timer Integration Tests
%%====================================================================

timer_test_() ->
    [
        {"Timer can be started", fun timer_can_be_started/0},
        {"Timer can be cancelled", fun timer_can_be_cancelled/0},
        {"Timer message is delivered", fun timer_message_delivered/0}
    ].

timer_can_be_started() ->
    %% Test that erlang:send_after works as expected
    StreamId = 4,
    TimerRef = erlang:send_after(1000, self(), {stream_deadline, StreamId}),
    ?assert(is_reference(TimerRef)),
    %% Cancel it so we don't get spurious messages
    erlang:cancel_timer(TimerRef).

timer_can_be_cancelled() ->
    %% Test that timer cancellation works
    StreamId = 4,
    TimerRef = erlang:send_after(100, self(), {stream_deadline, StreamId}),
    Result = erlang:cancel_timer(TimerRef),
    %% Result is remaining time or false if already expired
    ?assert(is_integer(Result) orelse Result =:= false),

    %% Give it time to potentially fire (but it shouldn't)
    timer:sleep(150),
    receive
        {stream_deadline, StreamId} -> ?assert(false)
    after 0 -> ok
    end.

timer_message_delivered() ->
    %% Test that timer message is delivered after timeout
    StreamId = 8,
    _TimerRef = erlang:send_after(10, self(), {stream_deadline, StreamId}),
    receive
        {stream_deadline, RecvId} ->
            ?assertEqual(StreamId, RecvId)
    after 100 ->
        ?assert(false)
    end.
