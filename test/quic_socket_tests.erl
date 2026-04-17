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

    %% Use gen_udp directly for this test since socket backend
    %% doesn't support active mode message delivery
    {ok, Sender} = gen_udp:open(0, [binary, inet]),
    {ok, Receiver} = gen_udp:open(0, [binary, inet, {active, true}]),

    {ok, {_RecvIP, RecvPort}} = inet:sockname(Receiver),

    %% Send a packet to localhost
    TestData = <<"hello quic_socket">>,
    ok = gen_udp:send(Sender, {127, 0, 0, 1}, RecvPort, TestData),

    %% Wait for the packet
    Result =
        receive
            {udp, _, _, _, ReceivedData} ->
                {ok, ReceivedData}
        after 5000 ->
            timeout
        end,

    gen_udp:close(Sender),
    gen_udp:close(Receiver),

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

%%====================================================================
%% info/1 and observability tests
%%====================================================================

info_reports_config_and_counters_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true, max_packets => 16}}),
    Info = quic_socket:info(State),

    ?assert(is_map(Info)),
    %% Config keys
    ?assert(maps:is_key(backend, Info)),
    ?assert(maps:is_key(gso_supported, Info)),
    ?assert(maps:is_key(gso_size, Info)),
    ?assert(maps:is_key(batching_enabled, Info)),
    ?assert(maps:is_key(max_batch_packets, Info)),
    %% Counters start at zero
    ?assertEqual(0, maps:get(batch_flushes, Info)),
    ?assertEqual(0, maps:get(packets_coalesced, Info)),
    ?assertEqual(true, maps:get(batching_enabled, Info)),
    ?assertEqual(16, maps:get(max_batch_packets, Info)),

    ok = quic_socket:close(State).

info_batching_disabled_test() ->
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => false}}),
    Info = quic_socket:info(State),
    ?assertEqual(false, maps:get(batching_enabled, Info)),
    ok = quic_socket:close(State).

info_wrap_reports_gen_udp_no_gso_test() ->
    %% wrap/2 wraps an existing gen_udp socket - never enables GSO.
    {ok, RawSocket} = gen_udp:open(0, [binary, {active, false}]),
    {ok, State} = quic_socket:wrap(RawSocket, #{}),
    Info = quic_socket:info(State),
    ?assertEqual(gen_udp, maps:get(backend, Info)),
    ?assertEqual(false, maps:get(gso_supported, Info)),
    ok = quic_socket:close(State),
    ok = gen_udp:close(RawSocket).

batch_counters_advance_on_flush_test() ->
    %% Send three packets via the batch, flush once, assert one flush
    %% and three coalesced packets counted.
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true, max_packets => 64}}),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    Dest = {127, 0, 0, 1},
    {ok, S1} = quic_socket:send(State, Dest, LocalPort, <<"one">>),
    {ok, S2} = quic_socket:send(S1, Dest, LocalPort, <<"two">>),
    {ok, S3} = quic_socket:send(S2, Dest, LocalPort, <<"three">>),
    {ok, S4} = quic_socket:flush(S3),

    Info = quic_socket:info(S4),
    ?assertEqual(1, maps:get(batch_flushes, Info)),
    ?assertEqual(3, maps:get(packets_coalesced, Info)),

    ok = quic_socket:close(S4).

batch_counters_zero_with_batching_disabled_test() ->
    %% With batching disabled, packets go out via do_send_immediate and
    %% must NOT count as coalesced.
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => false}}),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    Dest = {127, 0, 0, 1},
    {ok, S1} = quic_socket:send(State, Dest, LocalPort, <<"a">>),
    {ok, S2} = quic_socket:send(S1, Dest, LocalPort, <<"b">>),

    Info = quic_socket:info(S2),
    ?assertEqual(0, maps:get(batch_flushes, Info)),
    ?assertEqual(0, maps:get(packets_coalesced, Info)),

    ok = quic_socket:close(S2).

send_immediate_bypasses_batch_test() ->
    %% send_immediate/4 must send directly regardless of batching state
    %% and must NOT bump packets_coalesced.
    {ok, State} = quic_socket:open(0, #{batching => #{enabled => true}}),
    {ok, {_LocalIP, LocalPort}} = quic_socket:sockname(State),

    Dest = {127, 0, 0, 1},
    {ok, S1} = quic_socket:send_immediate(State, Dest, LocalPort, <<"direct">>),

    Info = quic_socket:info(S1),
    ?assertEqual(0, maps:get(batch_flushes, Info)),
    ?assertEqual(0, maps:get(packets_coalesced, Info)),

    ok = quic_socket:close(S1).
