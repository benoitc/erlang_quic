%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 4.6: a sender that wishes to open a stream but is
%%% at the peer's limit SHOULD send STREAMS_BLOCKED.

-module(quic_streams_blocked_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

bidi_limit_sends_streams_blocked_test() ->
    S0 = blocked_state(),
    {keep_state, S1, [{reply, _, Reply}]} = open(open_stream, S0#state{
        next_stream_id_bidi = 0, max_streams_bidi_remote = 0
    }),
    ?assertEqual({error, stream_limit}, Reply),
    ?assert(lists:member({streams_blocked, bidi, 0}, sent_frames(S1))).

uni_limit_sends_streams_blocked_test() ->
    S0 = blocked_state(),
    {keep_state, S1, [{reply, _, Reply}]} =
        open(open_unidirectional_stream, S0#state{
            next_stream_id_uni = 2, max_streams_uni_remote = 0
        }),
    ?assertEqual({error, stream_limit}, Reply),
    ?assert(lists:member({streams_blocked, uni, 0}, sent_frames(S1))).

blocked_state() ->
    ?S:with_keys_and_socket(?S:state_for_role(client)).

open(Request, State) ->
    quic_connection:connected({call, {self(), make_ref()}}, Request, State).

sent_frames(State) ->
    Sent = quic_loss:sent_packets(app, ?S:loss_state(State)),
    lists:append([Frames || #sent_packet{frames = Frames} <- maps:values(Sent)]).
