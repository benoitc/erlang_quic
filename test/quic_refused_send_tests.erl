%%% -*- erlang -*-
%%%
%%% A 1-RTT datagram the kernel refuses is tracked as sent, so loss
%%% detection declares it lost and its frames are sent again
%%% (RFC 9002 Section 6).

-module(quic_refused_send_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).
-define(FRAME, {stream, 0, 0, <<"request">>, false}).

refused_packet_is_tracked_and_resent_test() ->
    S0 = refusing(open_stream(?S:state_owing_ack(0, false))),
    S1 = quic_connection:send_app_packet_internal(quic_frame:encode(?FRAME), [?FRAME], S0),
    ?assertEqual([[?FRAME]], sent_frames(S1)),
    ?assert(quic_loss:bytes_in_flight(?S:loss_state(S1)) > 0),
    S2 = quic_connection:handle_pto_timeout(?S:state_set(S1, pto_space, app)),
    ?assertMatch([_, _], sent_frames(S2)),
    ?assertMatch([{ack, _, _, _}, ?FRAME], lists:last(sent_frames(S2))).

refused_run_packet_is_tracked_test() ->
    S = refusing(?S:state_owing_ack(0, false)),
    Frames = [{stream, 0, 0, <<"a">>, false}, {stream, 0, 1, <<"b">>, false}],
    {_SS, Tracked} = quic_connection:send_run_packets(
        [<<"p1">>, <<"p2">>], Frames, 10, S, undefined, []
    ),
    ?assertEqual([{11, 2, lists:nth(2, Frames)}, {10, 2, hd(Frames)}], Tracked).

refusing(#state{socket = Socket} = State) ->
    ok = gen_udp:close(Socket),
    State#state{socket_state = undefined}.

open_stream(State) ->
    State#state{streams = #{0 => #stream_state{id = 0, send_offset = 7}}}.

sent_frames(State) ->
    Sent = quic_loss:sent_packets(app, ?S:loss_state(State)),
    [Frames || {_, #sent_packet{frames = Frames}} <- lists:keysort(1, maps:to_list(Sent))].
