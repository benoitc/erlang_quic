%%% -*- erlang -*-
%%%
%%% When the server rejects 0-RTT, the recovery state of the 0-RTT
%%% packets in flight is discarded (RFC 9002 Section 6.4), and the
%%% rejected streams' queued data goes with them.

-module(quic_0rtt_reject_recovery_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

discards_in_flight_0rtt_packets_test() ->
    S = quic_connection:finalize_zero_rtt_state(rejected()),
    ?assertEqual(0, quic_loss:bytes_in_flight(S#state.loss_state)),
    ?assertEqual(#{}, quic_loss:sent_packets(app, S#state.loss_state)),
    ?assertEqual(0, quic_cc:bytes_in_flight(S#state.cc_state)).

drops_queued_0rtt_data_test() ->
    S = quic_connection:finalize_zero_rtt_state(rejected()),
    ?assertEqual(0, S#state.send_queue_bytes).

rejected() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 200, false),
    Now = erlang:monotonic_time(millisecond),
    Frames = fun(Off) -> [{stream, ?STREAM, Off, binary:copy(<<0>>, 100), false}] end,
    LS1 = quic_loss:on_packet_sent(app, S0#state.loss_state, 0, 1200, true, Frames(0), Now),
    LS2 = quic_loss:on_packet_sent(app, LS1, 1, 1200, true, Frames(100), Now),
    CC = quic_cc:on_packet_sent(quic_cc:on_packet_sent(S0#state.cc_state, 1200), 1200),
    {ok, S1} = quic_connection:queue_blocked_send(
        ?STREAM, 200, binary:copy(<<0>>, 300), false, 300, S0#state{
            loss_state = LS2, cc_state = CC
        }
    ),
    #state{hs = HS} = S1,
    S1#state{
        owner = self(),
        hs = HS#hs{
            early_data_accepted = false,
            zero_rtt_stream_ids = sets:from_list([?STREAM], [{version, 2}])
        }
    }.
