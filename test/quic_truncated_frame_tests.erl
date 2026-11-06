%%% -*- erlang -*-
%%%
%%% A frame cut short inside an authenticated packet is a
%%% FRAME_ENCODING_ERROR (RFC 9000 Section 12.4), whether the packet came
%%% through the generic decoder or the NIF's raw fallback.

-module(quic_truncated_frame_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

truncated_frames_test_() ->
    [
        {Name, fun() -> ?assertMatch({transport, ?QUIC_FRAME_ENCODING_ERROR, _}, close(Plain)) end}
     || {Name, Plain} <- [
            {"RESET_STREAM without final size", <<16#04, 0, 0>>},
            {"CRYPTO longer than the packet", <<16#06, 0, 10, 1, 2>>},
            {"STREAM longer than the packet", <<16#0a, 0, 10, 1, 2>>},
            {"ACK without ranges", <<16#02, 5>>}
        ]
    ].

raw_fallback_test() ->
    {ok, S, _} = quic_connection:opened_frames(
        {raw, <<16#04, 0, 0>>}, quic_connection_test_support:state_for_role(server)
    ),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _}, quic_connection_test_support:close_reason(S)
    ).

close(Plain) ->
    {ok, S, _} = quic_connection:decode_and_process_streaming(
        app, Plain, quic_connection_test_support:state_for_role(server)
    ),
    quic_connection_test_support:close_reason(S).
