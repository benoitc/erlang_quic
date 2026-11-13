%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 13.3: what a lost packet's frames send again, frame
%%% type by frame type.

-module(quic_lost_frame_repair_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

%%====================================================================
%% PING
%%====================================================================

lost_ping_is_not_resent_test() ->
    ?assertEqual([], resent([ping], state())).

lost_ping_beside_a_limit_resends_only_the_limit_test() ->
    ?assertEqual([{max_data, 1000}], resent([ping, {max_data, 1000}], state())).

%% The PTO still probes with a PING when the oldest packet held only one.
probe_after_lost_ping_is_a_ping_test() ->
    S0 = state(),
    LS = quic_loss:on_packet_sent(app, ?S:loss_state(S0), 0, 30, true, [ping], 0),
    S1 = quic_connection:send_probe_packet(app, S0#state{loss_state = LS}),
    ?assertEqual([[ping]], new_packets(S1, 0)).

ping_only_packet_is_acknowledged_without_delay_test() ->
    ?assertNot(quic_connection:should_delay_ack([ping])),
    ?assertNot(quic_connection:should_delay_ack([ping, padding])).

%%====================================================================
%% DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED
%%====================================================================

data_blocked_at_the_current_limit_is_resent_test() ->
    ?assertEqual([{data_blocked, 5000}], resent([{data_blocked, 5000}], blocked())).

data_blocked_after_the_limit_rose_is_dropped_test() ->
    S = blocked(),
    ?assertEqual([], resent([{data_blocked, 5000}], S#state{max_data_remote = 9000})).

stream_data_blocked_at_the_current_limit_is_resent_test() ->
    ?assertEqual(
        [{stream_data_blocked, 0, 300}], resent([{stream_data_blocked, 0, 300}], blocked())
    ).

stream_data_blocked_after_the_limit_rose_is_dropped_test() ->
    S = with_stream(0, fun(St) -> St#stream_state{send_max_data = 600} end, blocked()),
    ?assertEqual([], resent([{stream_data_blocked, 0, 300}], S)).

stream_data_blocked_after_reset_is_dropped_test() ->
    S = with_stream(0, fun(St) -> St#stream_state{send_done = true} end, blocked()),
    ?assertEqual([], resent([{stream_data_blocked, 0, 300}], S)),
    S1 = with_stream(0, fun(St) -> St#stream_state{send_reset_at = 100} end, blocked()),
    ?assertEqual([], resent([{stream_data_blocked, 0, 300}], S1)).

stream_data_blocked_for_a_gone_stream_is_dropped_test() ->
    S = blocked(),
    ?assertEqual([], resent([{stream_data_blocked, 0, 300}], S#state{streams = #{}})).

streams_blocked_at_the_current_limit_is_resent_test() ->
    ?assertEqual([{streams_blocked, bidi, 10}], resent([{streams_blocked, bidi, 10}], blocked())),
    ?assertEqual([{streams_blocked, uni, 3}], resent([{streams_blocked, uni, 3}], blocked())).

streams_blocked_after_the_limit_rose_is_dropped_test() ->
    S = (blocked())#state{max_streams_bidi_remote = 20, max_streams_uni_remote = 5},
    ?assertEqual([], resent([{streams_blocked, bidi, 10}], S)),
    ?assertEqual([], resent([{streams_blocked, uni, 3}], S)).

%%====================================================================
%% STOP_SENDING
%%====================================================================

stop_sending_while_receiving_is_resent_test() ->
    ?assertEqual([{stop_sending, 0, 7}], resent([{stop_sending, 0, 7}], blocked())).

stop_sending_after_all_data_arrived_is_dropped_test() ->
    S0 = blocked(),
    S1 = quic_connection:process_frame(app, {stream, 0, 0, <<"done">>, true}, S0),
    ?assertMatch(#{0 := #stream_state{recv_done = true}}, S1#state.streams),
    ?assertEqual([], resent([{stop_sending, 0, 7}], S1)).

stop_sending_after_the_peer_reset_is_dropped_test() ->
    S0 = blocked(),
    S1 = quic_connection:process_frame(app, {reset_stream, 0, 9, 0}, S0),
    ?assertMatch(#{0 := #stream_state{recv_done = true}}, S1#state.streams),
    ?assertEqual([], resent([{stop_sending, 0, 7}], S1)).

stop_sending_for_a_gone_stream_is_dropped_test() ->
    S = blocked(),
    ?assertEqual([], resent([{stop_sending, 0, 7}], S#state{streams = #{}})).

%%====================================================================
%% RESET_STREAM_AT
%%====================================================================

reset_stream_at_with_the_current_reliable_size_is_resent_test() ->
    {Frame, S} = reset_at(),
    ?assertEqual([Frame], resent([Frame], S)).

reset_stream_at_after_a_lower_reliable_size_is_dropped_test() ->
    {Frame, S0} = reset_at(),
    {ok, S1} = quic_connection:do_reset_stream_at(0, 9, 450, S0),
    ?assertEqual([], resent([Frame], S1)).

reset_stream_at_after_reset_stream_is_dropped_test() ->
    {Frame, S0} = reset_at(),
    {ok, S1} = quic_connection:do_close_stream(0, 9, S0),
    ?assertEqual([], resent([Frame], S1)).

reset_stream_at_for_a_reclaimed_stream_is_resent_test() ->
    {Frame, S} = reset_at(),
    ?assertEqual([Frame], resent([Frame], S#state{streams = #{}})).

%%====================================================================
%% NEW_CONNECTION_ID
%%====================================================================

new_connection_id_still_issued_is_resent_test() ->
    {Frame, S} = issued_cid(),
    ?assertEqual([Frame], resent([Frame], S)).

new_connection_id_the_peer_retired_is_dropped_test() ->
    {{new_connection_id, Seq, _, _, _} = Frame, S0} = issued_cid(),
    S1 = quic_connection:process_frame(app, {retire_connection_id, Seq}, S0),
    ?assertNot(
        lists:keymember(Seq, #cid_entry.seq_num, quic_cid:local_entries(S1#state.cid_pool_state))
    ),
    ?assertEqual([], resent([Frame], S1)).

%%====================================================================
%% PATH_CHALLENGE, PATH_RESPONSE
%%====================================================================

lost_path_response_is_not_resent_test() ->
    ?assertEqual([], resent([{path_response, <<1, 2, 3, 4, 5, 6, 7, 8>>}], state())).

lost_path_challenge_is_not_resent_test() ->
    ?assertEqual([], resent([{path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>}], state())).

%% The response sent through the ordinary send path when the challenge's
%% source address is unknown is not resent either.
lost_fallback_path_response_is_not_resent_test() ->
    Data = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    S0 = (state())#state{current_packet_source = undefined},
    S1 = quic_connection:process_frame(app, {path_challenge, Data}, S0),
    [Lost] = maps:values(quic_loss:sent_packets(app, ?S:loss_state(S1))),
    ?assertEqual([{path_response, Data}], Lost#sent_packet.frames),
    S2 = quic_connection:retransmit_lost_packets([Lost], S1),
    ?assertEqual([], new_packets(S2, ?S:next_app_pn(S1))),
    ?assertEqual([], held(S2)).

%%====================================================================
%% Helpers
%%====================================================================

%% The frames sent again after a packet carrying Frames is lost.
resent(Frames, State) ->
    Lost = #sent_packet{
        pn = 0, time_sent = 0, ack_eliciting = true, in_flight = true, size = 50, frames = Frames
    },
    S = quic_connection:retransmit_lost_packets([Lost], State),
    lists:append(new_packets(S, ?S:next_app_pn(State))) ++ held(S) -- held(State).

%% Frames of the packets sent at or after packet number From.
new_packets(State, From) ->
    [Fs || {PN, Fs} <- sent(State), PN >= From].

sent(State) ->
    lists:sort([
        {PN, Fs}
     || {PN, #sent_packet{frames = Fs}} <- maps:to_list(
            quic_loss:sent_packets(app, ?S:loss_state(State))
        )
    ]).

held(#state{ctrl_queue = {_, Q}}) ->
    queue:to_list(Q).

%% Blocked on every limit: 5000 bytes on the connection, 300 on stream 0,
%% 10 bidirectional and 3 unidirectional streams. Stream 0 also receives.
blocked() ->
    S = state(),
    S#state{
        max_data_remote = 5000,
        data_sent = 5000,
        max_streams_bidi_remote = 10,
        max_streams_uni_remote = 3,
        streams = #{
            0 => #stream_state{
                id = 0,
                state = open,
                send_offset = 400,
                send_max_data = 300,
                send_highest = 300,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = 1000,
                recv_fin = false,
                recv_buffer = gb_trees:empty()
            }
        }
    }.

%% A stream reset with RESET_STREAM_AT, code 9 and Reliable Size 500,
%% with 400 bytes sent and 600 queued; returns the frame sent.
reset_at() ->
    S0 = ?S:state_with_send_stream(0, 400, false),
    {ok, S1} = quic_connection:queue_blocked_send(0, 400, binary:copy(<<0>>, 600), false, 600, S0),
    S2 = S1#state{owner = self(), coalesce = false, transport_params = #{reset_stream_at => true}},
    {ok, S} = quic_connection:do_reset_stream_at(0, 9, 500, S2),
    [Frame] = [F || {_, Fs} <- sent(S), {reset_stream_at, _, _, _, _} = F <- Fs],
    {Frame, S}.

%% One connection ID issued as sequence 1 beside the handshake one, and
%% the NEW_CONNECTION_ID that carried it.
issued_cid() ->
    {Pool, [{Seq, CID, Token}]} = quic_cid:issue(quic_cid:new(<<"own-cid0">>, 2), 1, undefined),
    {{new_connection_id, Seq, 0, CID, Token}, (state())#state{cid_pool_state = Pool}}.

with_stream(StreamId, Fun, #state{streams = Streams} = State) ->
    State#state{streams = maps:update_with(StreamId, Fun, Streams)}.

state() ->
    S0 = ?S:with_keys_and_socket(?S:state_for_role(client)),
    S0#state{
        owner = self(),
        cfg = (S0#state.cfg)#conn_cfg{fc_max_receive_window = 1000},
        max_data_local = 1000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100
    }.
