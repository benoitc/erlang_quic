%%% -*- erlang -*-
%%%
%%% With stream_reset_final_size the owner's notice of a peer's reset
%%% carries the stream's final size (RFC 9000 Section 4.5): the final size
%%% of the RESET_STREAM, or of the RESET_STREAM_AT rather than its
%%% reliable size. Without it the notice is unchanged.

-module(quic_reset_final_size_notice_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

reset_stream_carries_final_size_test() ->
    _ = quic_connection:process_frame(app, {reset_stream, ?STREAM, 7, 1000}, server(true)),
    ?assertEqual({stream_reset, ?STREAM, 7, 1000}, notice()).

reset_stream_unchanged_without_the_option_test() ->
    _ = quic_connection:process_frame(app, {reset_stream, ?STREAM, 7, 1000}, server(false)),
    ?assertEqual({stream_reset, ?STREAM, 7}, notice()).

%% A reset that opens a stream not seen yet.
reset_of_an_unseen_stream_carries_final_size_test() ->
    _ = quic_connection:process_frame(app, {reset_stream, 4, 7, 300}, server(true)),
    ?assertEqual({stream_reset, 4, 7, 300}, notice()).

reset_stream_at_carries_final_size_not_reliable_size_test() ->
    _ = quic_connection:process_frame(
        app, {reset_stream_at, ?STREAM, 7, 1000, 200}, reset_at(server(true))
    ),
    ?assertEqual({stream_reset, ?STREAM, 7, 1000}, notice()).

reset_stream_at_unchanged_without_the_option_test() ->
    _ = quic_connection:process_frame(
        app, {reset_stream_at, ?STREAM, 7, 1000, 200}, reset_at(server(false))
    ),
    ?assertEqual({stream_reset, ?STREAM, 7}, notice()).

%%====================================================================
%% Helpers
%%====================================================================

%% A server that received 600 bytes of stream 0, with this test process
%% as owner.
server(FinalSizeOpt) ->
    flush(),
    S = quic_connection_test_support:recv_stream_state(?STREAM, 600, 100000, 100000),
    S1 = quic_connection_test_support:with_keys_and_socket(S#state{
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{},
        owner = self()
    }),
    Cfg = S1#state.cfg,
    S1#state{cfg = Cfg#conn_cfg{stream_reset_final_size = FinalSizeOpt}}.

reset_at(#state{cfg = Cfg} = S) ->
    S#state{cfg = Cfg#conn_cfg{reset_stream_at_enabled = true}}.

%% The reset notice the owner was sent; other events are skipped.
notice() ->
    receive
        {quic, _, {stream_reset, _, _} = N} -> N;
        {quic, _, {stream_reset, _, _, _} = N} -> N;
        {quic, _, _} -> notice()
    after 100 -> no_notice
    end.

flush() ->
    receive
        {quic, _, _} -> flush()
    after 0 -> ok
    end.
