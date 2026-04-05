%%% -*- erlang -*-
%%%
%%% Tests for quic_socket module
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_socket_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Platform Detection Tests
%%====================================================================

detect_capabilities_test() ->
    Caps = quic_socket:detect_capabilities(),
    ?assert(is_map(Caps)),
    ?assert(maps:is_key(gso, Caps)),
    ?assert(maps:is_key(gro, Caps)),
    ?assert(maps:is_key(backend, Caps)),
    %% Backend should be either socket or gen_udp
    Backend = maps:get(backend, Caps),
    ?assert(Backend =:= socket orelse Backend =:= gen_udp).

platform_specific_capabilities_test() ->
    Caps = quic_socket:detect_capabilities(),
    case os:type() of
        {unix, linux} ->
            %% On Linux with OTP 27+, might have GSO/GRO support
            %% (depends on kernel version and OTP version)
            ok;
        _ ->
            %% On non-Linux, GSO/GRO should be false
            ?assertEqual(false, maps:get(gso, Caps)),
            ?assertEqual(false, maps:get(gro, Caps)),
            ?assertEqual(gen_udp, maps:get(backend, Caps))
    end.

%%====================================================================
%% Socket Open/Close Tests
%%====================================================================

open_close_test() ->
    {ok, State} = quic_socket:open(0, #{}),
    ?assertMatch({ok, {_, _}}, quic_socket:sockname(State)),
    ?assertEqual(ok, quic_socket:close(State)).

open_with_batching_disabled_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => false}}),
    ?assertMatch({ok, {_, _}}, quic_socket:sockname(State)),
    ok = quic_socket:close(State).

open_with_custom_batch_config_test() ->
    {ok, State} = quic_socket:open(0, #{
        batching => #{
            enabled => true,
            max_packets => 32
        }
    }),
    ?assertMatch({ok, {_, _}}, quic_socket:sockname(State)),
    ok = quic_socket:close(State).

%%====================================================================
%% Wrap Existing Socket Tests
%%====================================================================

wrap_genudp_socket_test() ->
    {ok, UdpSock} = gen_udp:open(0, [binary, inet]),
    {ok, State} = quic_socket:wrap(UdpSock, #{}),
    ?assertMatch({ok, {_, _}}, quic_socket:sockname(State)),
    gen_udp:close(UdpSock).

wrap_with_batching_config_test() ->
    {ok, UdpSock} = gen_udp:open(0, [binary, inet]),
    {ok, State} = quic_socket:wrap(UdpSock, #{
        batching => #{
            enabled => true,
            max_packets => 16
        }
    }),
    ?assertMatch({ok, {_, _}}, quic_socket:sockname(State)),
    gen_udp:close(UdpSock).

%%====================================================================
%% Batch Accumulation Tests
%%====================================================================

batch_accumulation_test() ->
    {ok, State} = quic_socket:open(0, #{
        batching => #{enabled => true, max_packets => 64}
    }),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send a packet to localhost - should be batched
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, <<"test1">>),

    %% Flush the batch
    {ok, State2} = quic_socket:flush(State1),

    %% Clean up
    ok = quic_socket:close(State2).

multiple_packets_batch_test() ->
    {ok, State} = quic_socket:open(0, #{
        batching => #{enabled => true, max_packets => 64}
    }),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send multiple packets to the same destination (localhost)
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, <<"packet1">>),
    {ok, State2} = quic_socket:send(State1, {127, 0, 0, 1}, LocalPort, <<"packet2">>),
    {ok, State3} = quic_socket:send(State2, {127, 0, 0, 1}, LocalPort, <<"packet3">>),

    %% Flush all batched packets
    {ok, State4} = quic_socket:flush(State3),

    ok = quic_socket:close(State4).

%%====================================================================
%% Flush Trigger Tests
%%====================================================================

flush_on_destination_change_test() ->
    {ok, State} = quic_socket:open(0, #{
        batching => #{enabled => true, max_packets => 64}
    }),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send to first destination (localhost)
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, <<"to_addr1">>),

    %% Send to different destination - should trigger flush of first batch
    %% (Using different port to simulate different destination)
    DifferentPort = LocalPort + 1,
    {ok, State2} = quic_socket:send(State1, {127, 0, 0, 1}, DifferentPort, <<"to_addr2">>),

    %% Clean up
    {ok, State3} = quic_socket:flush(State2),
    ok = quic_socket:close(State3).

flush_empty_batch_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true}}),

    %% Flushing an empty batch should succeed
    {ok, State1} = quic_socket:flush(State),

    ok = quic_socket:close(State1).

%%====================================================================
%% Batching Disabled Tests (Direct Send)
%%====================================================================

direct_send_when_batching_disabled_test() ->
    {ok, State} = quic_socket:open(0, #{
        batching => #{enabled => false}
    }),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send should go directly without batching (to localhost)
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, <<"direct">>),

    ok = quic_socket:close(State1).

%%====================================================================
%% Socket Options Tests
%%====================================================================

setopts_test() ->
    {ok, State} = quic_socket:open(0, #{}),

    %% Set socket options
    ?assertEqual(ok, quic_socket:setopts(State, [{active, 100}])),

    ok = quic_socket:close(State).

controlling_process_test() ->
    {ok, State} = quic_socket:open(0, #{}),

    %% Set controlling process to self
    ?assertEqual(ok, quic_socket:controlling_process(State, self())),

    ok = quic_socket:close(State).

%%====================================================================
%% End-to-End Send/Receive Test
%%====================================================================

send_receive_test() ->
    %% Flush any stale messages from previous tests
    flush_mailbox(),

    %% Create sender and receiver sockets
    {ok, Sender} = quic_socket:open(0, #{batching => #{enabled => true}}),
    {ok, Receiver} = quic_socket:open(0, #{batching => #{enabled => false}}),

    {ok, {_SenderIP, _SenderPort}} = quic_socket:sockname(Sender),
    {ok, {_RecvIP, RecvPort}} = quic_socket:sockname(Receiver),

    %% Set receiver to active mode for gen_udp backend
    quic_socket:setopts(Receiver, [{active, true}]),

    %% Small delay to ensure setopts takes effect
    timer:sleep(10),

    %% Send a packet to localhost
    TestData = <<"hello quic_socket">>,
    {ok, Sender1} = quic_socket:send(Sender, {127, 0, 0, 1}, RecvPort, TestData),

    %% Flush to actually send
    {ok, Sender2} = quic_socket:flush(Sender1),

    %% Wait for the packet with longer timeout for CI environments
    Result =
        receive
            {udp, _, _, _, ReceivedData} ->
                {ok, ReceivedData}
        after 5000 ->
            timeout
        end,

    ok = quic_socket:close(Sender2),
    ok = quic_socket:close(Receiver),

    %% Assert after cleanup to avoid resource leaks on failure
    case Result of
        {ok, Data} -> ?assertEqual(TestData, Data);
        timeout -> ?assert(false)
    end.

%% Helper to flush stale messages from mailbox
flush_mailbox() ->
    receive
        _ -> flush_mailbox()
    after 0 ->
        ok
    end.

%%====================================================================
%% Batch Full Auto-Flush Test
%%====================================================================

batch_full_auto_flush_test() ->
    %% Create socket with very small batch size
    {ok, State} = quic_socket:open(0, #{
        batching => #{enabled => true, max_packets => 2}
    }),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send first packet - should be batched
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, <<"p1">>),

    %% Send second packet - should trigger auto-flush (batch full)
    {ok, State2} = quic_socket:send(State1, {127, 0, 0, 1}, LocalPort, <<"p2">>),

    ok = quic_socket:close(State2).

%%====================================================================
%% Edge Cases Tests
%%====================================================================

large_packet_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true}}),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send a larger packet (just under typical MTU) to localhost
    LargeData = binary:copy(<<"x">>, 1200),
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, LargeData),
    {ok, State2} = quic_socket:flush(State1),

    ok = quic_socket:close(State2).

iolist_send_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true}}),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    %% Send iolist instead of binary to localhost
    IoList = [<<"part1">>, [<<"part2">>, <<"part3">>]],
    {ok, State1} = quic_socket:send(State, {127, 0, 0, 1}, LocalPort, IoList),
    {ok, State2} = quic_socket:flush(State1),

    ok = quic_socket:close(State2).
