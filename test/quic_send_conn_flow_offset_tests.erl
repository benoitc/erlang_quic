%%% -*- erlang -*-
%%%
%%% Connection flow control counts the largest offset sent on each stream
%%% (RFC 9000 Section 4.1), as the receiver does. A write that goes out
%%% ahead of data still queued on the same stream uses credit for the gap,
%%% and the queued data costs nothing when it follows.

-module(quic_send_conn_flow_offset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SID, 0).

%% 1000 bytes counted, the peer allows 2000.
a_write_ahead_of_the_limit_waits_test() ->
    ?assertEqual(
        {blocked, connection},
        quic_connection:check_send_queue_flow_control(?SID, 3000, 500, state(1000, 1000, 2000))
    ).

data_below_the_highest_offset_is_already_counted_test() ->
    S = state(3500, 3500, 3500),
    ?assertEqual(ok, quic_connection:check_send_queue_flow_control(?SID, 1000, 2000, S)),
    S1 = quic_connection:count_sent(?SID, 3000, S),
    ?assertEqual(3500, S1#state.data_sent).

a_jump_counts_the_gap_test() ->
    S = quic_connection:count_sent(?SID, 3000, state(1000, 1000, 10000)),
    ?assertEqual(3000, S#state.data_sent),
    #{?SID := #stream_state{send_highest = Highest}} = S#state.streams,
    ?assertEqual(3000, Highest).

%% The window offers up to MaxData minus what is counted, from the
%% stream's highest offset.
allowance_is_measured_from_the_highest_offset_test() ->
    S = state(1000, 1000, 2000),
    #{?SID := Stream} = S#state.streams,
    ?assertEqual(1000, quic_connection:conn_allowance(Stream, 1000, 2000, 1000)),
    ?assertEqual(-1000, quic_connection:conn_allowance(Stream, 3000, 2000, 1000)).

state(Highest, DataSent, MaxData) ->
    S = quic_connection_test_support:state_for_role(client),
    S#state{
        streams = #{
            ?SID => #stream_state{
                id = ?SID, send_offset = 4000, send_max_data = 1 bsl 30, send_highest = Highest
            }
        },
        data_sent = DataSent,
        max_data_remote = MaxData
    }.
