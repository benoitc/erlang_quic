%%% -*- erlang -*-
%%%
%%% The peer's ACK timing parameters in loss detection (RFC 9002 Sections
%%% 5.3 and 6.2.1).
%%%
%%% ack_delay_exponent decodes the peer's ACK Delay field; max_ack_delay
%%% caps it in RTT samples and is part of the PTO. Both only apply fully
%%% after handshake confirmation: before it the delay is not capped and
%%% the PTO leaves max_ack_delay out.
%%%
%%% Values are deliberately not the defaults (exponent 3, 25 ms), so a
%%% loss state that ignores the peer's parameters fails these.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_loss_ack_params_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% RTT samples
%%====================================================================

%% The ACK Delay field is shifted by the peer's exponent, not by 3.
%% 2000 << 5 is 64 ms; read with exponent 3 it would be 16 ms.
peer_exponent_decodes_ack_delay_test() ->
    S0 = primed(quic_loss:set_peer_ack_params(quic_loss:new(), 5, 100)),
    S1 = acked(sent(S0, 1, 1000), 1, 2000, 1200),
    %% latest 200, delay 64: adjusted 136, smoothed (7*100 + 136) div 8
    ?assertEqual(104, quic_loss:smoothed_rtt(S1)).

%% Before confirmation the delay is subtracted in full, even beyond the
%% peer's max_ack_delay.
unconfirmed_ack_delay_is_not_capped_test() ->
    S0 = primed(quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10)),
    S1 = acked(sent(S0, 1, 1000), 1, delay(50, 3), 1200),
    %% latest 200, delay 50: adjusted 150, smoothed (700 + 150) div 8
    ?assertEqual(106, quic_loss:smoothed_rtt(S1)).

%% After confirmation the delay is capped at the peer's max_ack_delay.
confirmed_ack_delay_is_capped_at_peer_value_test() ->
    S0 = primed(confirmed(quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10))),
    S1 = acked(sent(S0, 1, 1000), 1, delay(50, 3), 1200),
    %% latest 200, delay capped to 10: adjusted 190, smoothed (700 + 190) div 8
    ?assertEqual(111, quic_loss:smoothed_rtt(S1)).

%%====================================================================
%% PTO
%%====================================================================

%% Initial and Handshake PTO use 0 for max_ack_delay: smoothed 100,
%% 4 * rttvar 200.
unconfirmed_pto_excludes_max_ack_delay_test() ->
    S = quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10),
    ?assertEqual(300, quic_loss:get_pto(S)).

%% Once confirmed, the peer's max_ack_delay is added, not the default 25.
confirmed_pto_includes_peer_max_ack_delay_test() ->
    S = confirmed(quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10)),
    ?assertEqual(310, quic_loss:get_pto(S)).

%% The persistent congestion window includes max_ack_delay whatever the
%% packet number space (RFC 9002 Section 7.6.1), so confirmation does
%% not change it.
persistent_congestion_includes_max_ack_delay_test() ->
    S = quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10),
    ?assertEqual(310, quic_loss:persistent_congestion_pto(S)),
    ?assertEqual(310, quic_loss:persistent_congestion_pto(confirmed(S))).

%% A path change resets the RTT estimate, not what the peer negotiated or
%% whether the handshake is confirmed.
path_reset_keeps_peer_params_test() ->
    S = confirmed(quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10)),
    R = quic_loss:reset_for_new_path(S),
    ?assertEqual(310, quic_loss:get_pto(R)).

%%====================================================================
%% Through the connection
%%====================================================================

%% Applying the peer's transport parameters hands both values to loss
%% detection.
transport_params_reach_loss_state_test() ->
    S0 = quic_connection_test_support:state_before_initial(server, 2),
    S1 = quic_connection:adopt_peer_scid(<<"client-scid">>, S0),
    S2 = quic_connection_test_support:state_set(S1, loss_state, quic_loss:new()),
    S3 = quic_connection:apply_peer_transport_params(
        #{initial_scid => <<"client-scid">>, ack_delay_exponent => 5, max_ack_delay => 10},
        S2
    ),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S3)),
    L = quic_connection_test_support:loss_state(S3),
    ?assertEqual(310, quic_loss:persistent_congestion_pto(L)),
    ?assertEqual(300, quic_loss:get_pto(L)),
    L1 = acked(sent(primed(L), 1, 1000), 1, 2000, 1200),
    ?assertEqual(104, quic_loss:smoothed_rtt(L1)).

%% A client's handshake is confirmed by HANDSHAKE_DONE (RFC 9001 Section
%% 4.1.2).
handshake_done_confirms_client_test() ->
    S0 = quic_connection_test_support:state_before_initial(client, 2),
    S1 = quic_connection_test_support:state_set(
        S0, loss_state, quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10)
    ),
    ?assertEqual(300, quic_loss:get_pto(quic_connection_test_support:loss_state(S1))),
    S2 = quic_connection:process_frame(app, handshake_done, S1),
    ?assertEqual(310, quic_loss:get_pto(quic_connection_test_support:loss_state(S2))).

%% Both confirmation points are reached on a real handshake: once
%% confirmed, the PTO carries max_ack_delay just as the persistent
%% congestion PTO always does. The client learns it from HANDSHAKE_DONE,
%% which can land just after `connected'.
both_sides_confirm_after_handshake_test_() ->
    {timeout, 30, fun both_sides_confirm/0}.

both_sides_confirm() ->
    {ok, Srv} = quic_test_echo_server:start(),
    try
        #{port := Port, name := Name} = Srv,
        {ok, Conn} = quic:connect(
            "127.0.0.1", Port, quic_test_echo_server:client_opts(), self()
        ),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            {ok, [ServerConn | _]} = quic:get_server_connections(Name),
            ?assert(confirmed_within(Conn, 2000)),
            ?assert(confirmed_within(ServerConn, 2000))
        after
            quic:safe_close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

confirmed_within(Pid, Budget) when Budget =< 0 ->
    is_confirmed(Pid);
confirmed_within(Pid, Budget) ->
    case is_confirmed(Pid) of
        true ->
            true;
        false ->
            timer:sleep(20),
            confirmed_within(Pid, Budget - 20)
    end.

is_confirmed(Pid) ->
    {_StateName, Data} = sys:get_state(Pid),
    L = quic_connection_test_support:loss_state(Data),
    quic_loss:get_pto(L) =:= quic_loss:persistent_congestion_pto(L).

%%====================================================================
%% Helpers
%%====================================================================

confirmed(S) -> quic_loss:on_handshake_confirmed(S).

sent(S, PN, Now) -> quic_loss:on_packet_sent(S, PN, 1200, true, [ping], Now).

acked(S, PN, EncodedDelay, Now) ->
    {S1, _Acked, _Lost, _Info} = quic_loss:on_ack_received(
        S, {ack, PN, EncodedDelay, 0, []}, Now
    ),
    S1.

%% A first sample of 100 ms; the first sample ignores ACK delay, so any
%% delay assertion needs a second one.
primed(S) ->
    S1 = acked(sent(S, 0, 0), 0, 0, 100),
    100 = quic_loss:smoothed_rtt(S1),
    S1.

%% Encode Ms milliseconds of ACK delay for exponent Exp.
delay(Ms, Exp) -> (Ms * 1000) bsr Exp.
