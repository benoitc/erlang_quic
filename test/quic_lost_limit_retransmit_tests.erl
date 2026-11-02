%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 13.3: a lost MAX_DATA, MAX_STREAM_DATA or MAX_STREAMS
%%% is resent only when it still carries the latest value.

-module(quic_lost_limit_retransmit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

stale_max_data_is_dropped_test() ->
    ?assertEqual([], resent({max_data, 500})).

current_max_data_is_resent_test() ->
    ?assertEqual([{max_data, 1000}], resent({max_data, 1000})).

stale_max_streams_is_dropped_test() ->
    ?assertEqual([], resent({max_streams, bidi, 50})),
    ?assertEqual([], resent({max_streams, uni, 50})).

current_max_streams_is_resent_test() ->
    ?assertEqual([{max_streams, bidi, 100}], resent({max_streams, bidi, 100})).

stale_max_stream_data_is_dropped_test() ->
    ?assertEqual([], resent({max_stream_data, 0, 100})).

current_max_stream_data_is_resent_test() ->
    ?assertEqual([{max_stream_data, 0, 200}], resent({max_stream_data, 0, 200})).

max_stream_data_after_final_size_is_dropped_test() ->
    ?assertEqual([], resent({max_stream_data, 4, 200})).

max_stream_data_for_gone_stream_is_dropped_test() ->
    ?assertEqual([], resent({max_stream_data, 8, 200})).

resent(Frame) ->
    Lost = #sent_packet{
        pn = 0, time_sent = 0, ack_eliciting = true, in_flight = true, size = 50, frames = [Frame]
    },
    S = quic_connection:retransmit_lost_packets([Lost], state()),
    lists:append([Fs || #sent_packet{frames = Fs} <- maps:values(sent(S))]).

sent(State) ->
    quic_loss:sent_packets(app, ?S:loss_state(State)).

state() ->
    S0 = ?S:with_keys_and_socket(?S:state_for_role(client)),
    S0#state{
        max_data_local = 1000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        streams = #{
            0 => #stream_state{id = 0, recv_max_data = 200},
            4 => #stream_state{id = 4, recv_max_data = 200, final_size = 150}
        }
    }.
