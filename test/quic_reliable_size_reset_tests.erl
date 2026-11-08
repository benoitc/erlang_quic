%%% -*- erlang -*-
%%%
%%% A stream given a reliable size (quic:set_stream_reliable_size/3) is
%%% reset with RESET_STREAM_AT when quic resets it on its own, so its first
%%% bytes, such as a WebTransport stream header, stay reliable
%%% (draft-ietf-webtrans-http3-17 Section 4.4). Without the setting, or
%%% with a peer that did not advertise reset_stream_at, it is a
%%% RESET_STREAM as before.

-module(quic_reliable_size_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

stop_sending_is_answered_with_reset_stream_at_test() ->
    ?assertEqual(
        [{reset_stream_at, ?STREAM, 9, 1000, 3}], resets(stop_sending(stream(3, true)))
    ).

reliable_size_is_capped_at_what_was_sent_test() ->
    ?assertEqual(
        [{reset_stream_at, ?STREAM, 9, 1000, 1000}], resets(stop_sending(stream(5000, true)))
    ).

no_reliable_size_keeps_reset_stream_test() ->
    ?assertEqual([{reset_stream, ?STREAM, 9, 1000}], resets(stop_sending(stream(undefined, true)))).

peer_without_reset_stream_at_gets_reset_stream_test() ->
    ?assertEqual([{reset_stream, ?STREAM, 9, 1000}], resets(stop_sending(stream(3, false)))).

deadline_reset_keeps_the_reliable_size_test() ->
    #state{streams = #{?STREAM := Stream}} = S0 = stream(3, true),
    S1 = S0#state{
        streams = #{
            ?STREAM => Stream#stream_state{deadline_action = reset, deadline_error_code = 9}
        }
    },
    {ok, S} = quic_connection:handle_stream_deadline_expired(?STREAM, S1),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 1000, 3}], resets(S)).

%%====================================================================
%% Helpers
%%====================================================================

%% 1000 bytes written on a stream we send on, with this reliable size,
%% to a peer that did or did not advertise reset_stream_at.
stream(ReliableSize, PeerResetAt) ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 1000, false),
    #state{streams = #{?STREAM := Stream}} = S0,
    S0#state{
        owner = self(),
        transport_params = #{reset_stream_at => PeerResetAt},
        streams = #{?STREAM => Stream#stream_state{reliable_size = ReliableSize}}
    }.

stop_sending(S) ->
    quic_connection:process_frame(app, {stop_sending, ?STREAM, 9}, S).

resets(#state{pend_frames = Frames}) ->
    [F || F <- Frames, element(1, F) =:= reset_stream orelse element(1, F) =:= reset_stream_at].
