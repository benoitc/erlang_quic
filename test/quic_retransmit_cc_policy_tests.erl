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
%%%
%%% These tests pin the policy at the retransmit_cc_allowed/3 decision
%%% point for both modes, over both a full and an open window.

-module(quic_retransmit_cc_policy_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PACKET, 1200).

%% A congestion state with no room: keep charging full packets until
%% even one more no longer fits under cwnd.
full_window() ->
    fill(quic_cc:new()).

fill(CC) ->
    case quic_cc:can_send(CC, ?PACKET) of
        true -> fill(quic_cc:on_packet_sent(CC, ?PACKET));
        false -> CC
    end.

probe_is_exempt_above_cwnd_test() ->
    CC = full_window(),
    ?assertNot(quic_cc:can_send(CC, ?PACKET)),
    ?assert(quic_connection:retransmit_cc_allowed(probe, CC, ?PACKET)).

loss_retransmission_is_refused_above_cwnd_test() ->
    CC = full_window(),
    ?assertNot(quic_connection:retransmit_cc_allowed(normal, CC, ?PACKET)).

loss_retransmission_passes_an_open_window_test() ->
    CC = quic_cc:new(),
    ?assert(quic_connection:retransmit_cc_allowed(normal, CC, ?PACKET)).

%% The loss gate is the congestion window proper, not the more lenient
%% control allowance: a state the control gate would wave through is
%% still refused once cwnd is spent.
loss_gate_is_cwnd_not_the_control_allowance_test() ->
    CC = full_window(),
    case quic_cc:can_send_control(CC, ?PACKET) of
        true -> ?assertNot(quic_connection:retransmit_cc_allowed(normal, CC, ?PACKET));
        false -> ok
    end.
