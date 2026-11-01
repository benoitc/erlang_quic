%%% -*- erlang -*-
%%%
%%% A peer stream opened by STREAM_DATA_BLOCKED, STOP_SENDING or
%%% RESET_STREAM before its first STREAM frame (RFC 9000 Section 3.2)
%%% is the same stream a STREAM frame would have opened.

-module(quic_peer_stream_open_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(BIDI, 0).
-define(UNI, 2).
-define(BIDI_LIMIT, 1000).
-define(UNI_LIMIT, 5000).

stream_data_blocked_opens_a_peer_uni_stream_test() ->
    S = frames([{stream_data_blocked, ?UNI, 0}]),
    ?assertEqual(?UNI_LIMIT, recv_max_data(?UNI, S)).

data_after_stream_data_blocked_test() ->
    S = frames([{stream_data_blocked, ?BIDI, 0}, {stream, ?BIDI, 0, <<"abc">>, false}]),
    ?assertEqual(3, recv_offset(?BIDI, S)).

data_after_stop_sending_test() ->
    S = frames([{stop_sending, ?BIDI, 0}, {stream, ?BIDI, 0, <<"abc">>, false}]),
    ?assertEqual(3, recv_offset(?BIDI, S)).

peer_uni_stream_gets_the_uni_limit_test() ->
    Data = binary:copy(<<0>>, ?BIDI_LIMIT * 3),
    S = frames([{stream, ?UNI, 0, Data, false}]),
    ?assertEqual(byte_size(Data), recv_offset(?UNI, S)).

frames(Frames) ->
    lists:foldl(fun(F, S) -> quic_connection:process_frame(app, F, S) end, server(), Frames).

server() ->
    #state{cfg = Cfg} = S = quic_connection_test_support:recv_stream_state(?BIDI, 0, 0, 100000),
    quic_connection_test_support:with_keys_and_socket(S#state{
        streams = #{},
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{},
        cfg = Cfg#conn_cfg{
            max_stream_data_bidi_local = ?BIDI_LIMIT,
            max_stream_data_bidi_remote = ?BIDI_LIMIT,
            max_stream_data_uni = ?UNI_LIMIT
        }
    }).

recv_offset(Id, #state{streams = Streams}) ->
    (maps:get(Id, Streams))#stream_state.recv_offset.

recv_max_data(Id, #state{streams = Streams}) ->
    (maps:get(Id, Streams))#stream_state.recv_max_data.
