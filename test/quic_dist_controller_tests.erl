%%% -*- erlang -*-
%%%
%%% QUIC Distribution Controller Unit Tests
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_controller_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_dist.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

%% Note: These are unit tests that don't require a running QUIC connection.
%% Integration tests are in the CT suites.

%%====================================================================
%% State Machine Tests
%%====================================================================

callback_mode_test() ->
    %% Verify the callback mode is state_functions with state_enter
    Result = quic_dist_controller:callback_mode(),
    ?assertEqual([state_functions, state_enter], Result).

%%====================================================================
%% Module Attribute Tests
%%====================================================================

%% Test that the module exports expected functions
exports_test() ->
    Exports = quic_dist_controller:module_info(exports),
    %% Check key API functions are exported
    ?assert(lists:member({start_link, 2}, Exports)),
    ?assert(lists:member({start_link, 3}, Exports)),
    ?assert(lists:member({send, 2}, Exports)),
    ?assert(lists:member({recv, 3}, Exports)),
    ?assert(lists:member({tick, 1}, Exports)),
    ?assert(lists:member({getstat, 1}, Exports)),
    ?assert(lists:member({get_address, 2}, Exports)),
    ?assert(lists:member({set_supervisor, 2}, Exports)).

%%====================================================================
%% API Tests (mocking connection)
%%====================================================================

%% These tests use meck to mock the quic_connection module.
%% They verify the controller's API works correctly.

-ifdef(MECK_TESTS).

setup_meck() ->
    meck:new(quic_connection, [passthrough]),
    meck:new(quic, [passthrough]),
    ok.

cleanup_meck(_) ->
    meck:unload(quic_connection),
    meck:unload(quic),
    ok.

controller_start_link_test_() ->
    {setup, fun setup_meck/0, fun cleanup_meck/1, fun(_) ->
        ConnRef = make_ref(),
        ConnPid = self(),

        %% Mock lookup to return our pid
        meck:expect(quic_connection, lookup, fun(Ref) when Ref =:= ConnRef ->
            {ok, ConnPid}
        end),

        %% Mock open_stream
        meck:expect(quic, open_stream, fun(_) -> {ok, 0} end),
        meck:expect(quic, set_stream_priority, fun(_, _, _, _) -> ok end),

        %% Start controller
        {ok, Pid} = quic_dist_controller:start_link(ConnRef, client),
        ?assert(is_pid(Pid)),

        %% Clean up
        gen_statem:stop(Pid),

        ok
    end}.

-endif.

%%====================================================================
%% Helper Function Tests
%%====================================================================

%% Test round-robin stream selection
stream_round_robin_test() ->
    Streams = [4, 8, 12, 16],

    %% Index 0 -> stream 4
    ?assertEqual(4, lists:nth((0 rem length(Streams)) + 1, Streams)),
    %% Index 1 -> stream 8
    ?assertEqual(8, lists:nth((1 rem length(Streams)) + 1, Streams)),
    %% Index 2 -> stream 12
    ?assertEqual(12, lists:nth((2 rem length(Streams)) + 1, Streams)),
    %% Index 3 -> stream 16
    ?assertEqual(16, lists:nth((3 rem length(Streams)) + 1, Streams)),
    %% Index 4 -> back to stream 4
    ?assertEqual(4, lists:nth((4 rem length(Streams)) + 1, Streams)).

%% Test message framing
message_framing_test() ->
    Data = <<"hello">>,

    %% Handshake framing (2-byte length prefix)
    Len2 = byte_size(Data),
    Frame2 = <<Len2:16/big, Data/binary>>,
    ?assertEqual(7, byte_size(Frame2)),

    %% Post-handshake framing (4-byte length prefix)
    Len4 = byte_size(Data),
    Frame4 = <<Len4:32/big, Data/binary>>,
    ?assertEqual(9, byte_size(Frame4)).

%% Test buffer operations
buffer_operations_test() ->
    Buffer = <<>>,
    Data1 = <<"hello">>,
    Data2 = <<" world">>,

    %% Append data
    Buffer1 = <<Buffer/binary, Data1/binary>>,
    ?assertEqual(<<"hello">>, Buffer1),

    Buffer2 = <<Buffer1/binary, Data2/binary>>,
    ?assertEqual(<<"hello world">>, Buffer2),

    %% Extract data
    Length = 5,
    <<Extracted:Length/binary, Rest/binary>> = Buffer2,
    ?assertEqual(<<"hello">>, Extracted),
    ?assertEqual(<<" world">>, Rest).
