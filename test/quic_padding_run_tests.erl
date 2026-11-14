%%% -*- erlang -*-
%%%
%%% A run of PADDING frames (RFC 9000 Section 19.1), one byte each and
%%% without meaning, is processed as a single frame.

-module(quic_padding_run_tests).

-include_lib("eunit/include/eunit.hrl").

padded_packet_test() ->
    ?assertEqual([ping, padding], frames(<<1, 0:(1100 * 8)>>)).

padding_between_frames_test() ->
    ?assertEqual([padding, ping, padding, ping], frames(<<0, 0, 0, 1, 0, 0, 1>>)).

padding_only_test() ->
    ?assertEqual([padding], frames(<<0>>)),
    ?assertEqual([padding], frames(<<0:(1200 * 8)>>)).

frames(Payload) ->
    State = quic_connection_test_support:state_for_role(server),
    {ok, _, Frames} = quic_connection:decode_and_process_streaming(initial, Payload, State),
    Frames.
