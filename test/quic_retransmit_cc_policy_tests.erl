%%% -*- erlang -*-
%%%
%%% Congestion policy for retransmitted frames (RFC 9002 §7).
%%%
%%% "An endpoint MUST NOT send a packet if it would cause bytes_in_flight
%%% to be larger than the congestion window, unless the packet is sent on
%%% a PTO timer expiration or when entering recovery." That is two rules:
%%% a PTO probe is exempt from the congestion window outright, and an
%%% ordinary loss retransmission stays bound by it.
%%%
%%% Gating probes deadlocks a full window: bytes_in_flight sits at or
%%% just above cwnd, every probe is denied, no probe means no ACK, and
%%% loss detection never runs. Exempting loss retransmissions instead
%%% would burst a full sent_q past the window during recovery.

-module(quic_retransmit_cc_policy_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(PACKET, 1200).
-define(FRAME, {max_streams, bidi, 1000}).

probe_is_exempt_above_cwnd_test() ->
    S0 = probing(state(full_window())),
    S1 = quic_connection:send_retransmit_frames_cc([?FRAME], S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual({0, []}, held(S1)).

loss_retransmission_is_refused_above_cwnd_test() ->
    S0 = state(full_window()),
    S1 = quic_connection:send_retransmit_frames_cc([?FRAME], S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual({1, [?FRAME]}, held(S1)).

loss_retransmission_passes_an_open_window_test() ->
    S0 = state(quic_cc:new()),
    S1 = quic_connection:send_retransmit_frames_cc([?FRAME], S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual({0, []}, held(S1)).

%% A congestion state with no room: keep charging full packets until
%% even one more no longer fits under cwnd.
full_window() ->
    fill(quic_cc:new()).

fill(CC) ->
    case quic_cc:can_send(CC, ?PACKET) of
        true -> fill(quic_cc:on_packet_sent(CC, ?PACKET));
        false -> CC
    end.

state(CC) ->
    S = quic_connection_test_support:state_for_admission(0, 0, 1000000, 1000000),
    S#state{cc_state = CC}.

probing(#state{hs = HS} = S) ->
    S#state{hs = HS#hs{hs_probe = true}}.

next_pn(#state{pn_app = #pn_space{next_pn = PN}}) -> PN.

held(#state{ctrl_queue = {N, Q}}) -> {N, queue:to_list(Q)}.
