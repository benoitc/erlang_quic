%%% -*- erlang -*-
%%%
%%% A peer stream opened by STREAM_DATA_BLOCKED, STOP_SENDING,
%%% RESET_STREAM or MAX_STREAM_DATA before its first STREAM frame
%%% (RFC 9000 Section 3.2) is the same stream a STREAM frame would have
%%% opened.

-module(quic_peer_stream_open_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(BIDI, 0).
-define(UNI, 2).
-define(BIDI_LIMIT, 1000).
-define(UNI_LIMIT, 5000).
%% Above the limit a peer that sent no transport parameter starts with.
-define(CREDIT, 4000000).

stream_data_blocked_opens_a_peer_uni_stream_test() ->
    S = frames([{stream_data_blocked, ?UNI, 0}]),
    ?assertEqual(?UNI_LIMIT, recv_max_data(?UNI, S)).

data_after_stream_data_blocked_test() ->
    S = frames([{stream_data_blocked, ?BIDI, 0}, {stream, ?BIDI, 0, <<"abc">>, false}]),
    ?assertEqual(3, recv_offset(?BIDI, S)).

data_after_stop_sending_test() ->
    S = frames([{stop_sending, ?BIDI, 0}, {stream, ?BIDI, 0, <<"abc">>, false}]),
    ?assertEqual(3, recv_offset(?BIDI, S)).

%% MAX_STREAM_DATA ahead of the stream's first data opens it with the
%% credit it grants, and the STREAM frame that follows lands on it.
max_stream_data_opens_a_peer_bidi_stream_test() ->
    _ = opened(),
    S = frames([{max_stream_data, ?BIDI, ?CREDIT}, {stream, ?BIDI, 0, <<"abc">>, false}]),
    ?assertEqual(?CREDIT, send_max_data(?BIDI, S)),
    ?assertEqual(3, recv_offset(?BIDI, S)),
    ?assertEqual([?BIDI], opened()).

%% Credit below the initial limit does not lower it.
max_stream_data_below_the_initial_limit_test() ->
    Initial = send_max_data(?BIDI, frames([{stream, ?BIDI, 0, <<"abc">>, false}])),
    _ = opened(),
    S = frames([{max_stream_data, ?BIDI, 0}]),
    ?assertEqual(Initial, send_max_data(?BIDI, S)).

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

send_max_data(Id, #state{streams = Streams}) ->
    (maps:get(Id, Streams))#stream_state.send_max_data.

opened() ->
    receive
        {quic, _, {stream_opened, Id}} -> [Id | opened()]
    after 0 -> []
    end.
