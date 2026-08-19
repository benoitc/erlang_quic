%% Inside a connected-state receive pass, count-based ACK decimation
%% only counts; finish_recv_pass/1 then emits one ACK for the whole
%% train. Without this a 64-packet drain pass emitted an ACK every
%% ack_packet_tolerance packets, and the ACK machinery on both ends
%% ate a large share of the CPU on bulk flows.
-module(quic_recv_pass_ack_tests).

-include_lib("eunit/include/eunit.hrl").

in_pass(S) -> quic_connection:test_state_in_recv_pass(S).

steps(S, 0) ->
    S;
steps(S, N) ->
    {S1, _} = quic_connection:test_decimate_step(S),
    steps(S1, N - 1).

no_flush_inside_a_pass_test() ->
    S0 = in_pass(quic_connection:test_decimate_initial_state()),
    %% Well past the tolerance (2): still counting, timer armed.
    {_S, Info} = quic_connection:test_decimate_step(steps(S0, 7)),
    ?assertMatch(#{ack_elicited_count := 8, ack_timer_armed := true}, Info).

one_ack_at_pass_end_test() ->
    S0 = in_pass(quic_connection:test_decimate_initial_state()),
    S1 = steps(S0, 8),
    {_S2, Info} = quic_connection:test_finish_recv_pass(S1),
    ?assertMatch(
        #{ack_elicited_count := 0, ack_timer_armed := false, recv_pass := false}, Info
    ).

below_tolerance_keeps_the_timer_test() ->
    S0 = in_pass(quic_connection:test_decimate_initial_state()),
    S1 = steps(S0, 1),
    {_S2, Info} = quic_connection:test_finish_recv_pass(S1),
    ?assertMatch(
        #{ack_elicited_count := 1, ack_timer_armed := true, recv_pass := false}, Info
    ).

no_ack_when_the_pass_started_a_close_test() ->
    S0 = in_pass(quic_connection:test_decimate_initial_state()),
    S1 = quic_connection:test_state_closing(steps(S0, 4), {application, 0, <<>>}),
    {_S2, Info} = quic_connection:test_finish_recv_pass(S1),
    ?assertMatch(#{ack_elicited_count := 4, recv_pass := false}, Info).

decimation_resumes_after_the_pass_test() ->
    S0 = in_pass(quic_connection:test_decimate_initial_state()),
    {S1, _} = quic_connection:test_finish_recv_pass(steps(S0, 3)),
    %% Outside a pass the tolerance applies again: two packets flush.
    {S2, _} = quic_connection:test_decimate_step(S1),
    {_S3, Info} = quic_connection:test_decimate_step(S2),
    ?assertMatch(#{ack_elicited_count := 0, ack_timer_armed := false}, Info).
