%%% -*- erlang -*-
%%%
%%% A stream the peer resets counts its final size against connection
%%% flow control (RFC 9000 Section 4.5), and gives back the receive
%%% buffer its out-of-order data held.

-module(quic_reset_stream_accounting_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

counts_the_unreceived_tail_test() ->
    S = reset(1000, server(100)),
    ?assertEqual(1000, S#state.data_received).

counts_a_stream_reset_before_any_data_test() ->
    S0 = server(100),
    S = quic_connection:process_frame(app, {reset_stream, 4, 0, 1000}, S0),
    ?assertEqual(1100, S#state.data_received).

releases_buffered_data_test() ->
    S0 = quic_connection:process_frame(
        app, {stream, ?STREAM, 500, binary:copy(<<0>>, 100), false}, server(100)
    ),
    ?assertEqual(100, S0#state.recv_buffer_bytes),
    S = reset(1000, S0),
    ?assertEqual(0, S#state.recv_buffer_bytes),
    ?assertEqual(1000, S#state.data_received).

%% Data that arrives after the reset is not counted, or delivered, again.
late_data_is_not_counted_again_test() ->
    S0 = reset(1000, server(100)),
    S = quic_connection:process_frame(
        app, {stream, ?STREAM, 100, binary:copy(<<0>>, 900), false}, S0
    ),
    ?assertEqual(1000, S#state.data_received),
    ?assertEqual(0, S#state.recv_buffer_bytes).

%% Our send side is still open, so the stream outlives the reset.
repeated_reset_is_counted_once_test() ->
    _ = resets_notified(),
    S = reset(1000, reset(1000, server(100))),
    ?assertEqual(1000, S#state.data_received),
    ?assertEqual(1, length(resets_notified())).

%% The bytes below the reliable size still arrive, and are not counted
%% again (draft-ietf-quic-reliable-stream-reset-07).
reset_stream_at_counts_the_final_size_test() ->
    S0 = reset_at(1000, 500, server_reset_at(100)),
    ?assertEqual(1000, S0#state.data_received),
    S = quic_connection:process_frame(
        app, {stream, ?STREAM, 100, binary:copy(<<0>>, 400), false}, S0
    ),
    ?assertEqual(1000, S#state.data_received).

reset_stream_at_before_any_data_test() ->
    S = quic_connection:process_frame(
        app, {reset_stream_at, 4, 0, 1000, 0}, server_reset_at(100)
    ),
    ?assertEqual(1100, S#state.data_received).

reset(FinalSize, S) ->
    quic_connection:process_frame(app, {reset_stream, ?STREAM, 0, FinalSize}, S).

server(Received) ->
    S = quic_connection_test_support:recv_stream_state(?STREAM, Received, 100000, 100000),
    quic_connection_test_support:with_keys_and_socket(S#state{
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{}
    }).

reset_at(FinalSize, ReliableSize, S) ->
    quic_connection:process_frame(
        app, {reset_stream_at, ?STREAM, 0, FinalSize, ReliableSize}, S
    ).

server_reset_at(Received) ->
    #state{cfg = Cfg} = S = server(Received),
    S#state{cfg = Cfg#conn_cfg{reset_stream_at_enabled = true}}.

resets_notified() ->
    receive
        {quic, _, {stream_reset, ?STREAM, _}} = M -> [M | resets_notified()]
    after 0 -> []
    end.
