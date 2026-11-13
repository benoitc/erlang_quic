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
%% Helpers
%%====================================================================

%% The frames sent again after a packet carrying Frames is lost.
resent(Frames, State) ->
    Lost = #sent_packet{
        pn = 0, time_sent = 0, ack_eliciting = true, in_flight = true, size = 50, frames = Frames
    },
    S = quic_connection:retransmit_lost_packets([Lost], State),
    lists:append([Fs || {_PN, Fs} <- sent(S)]) ++ held(S).

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

state() ->
    S0 = ?S:with_keys_and_socket(?S:state_for_role(client)),
    S0#state{
        max_data_local = 1000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100
    }.
