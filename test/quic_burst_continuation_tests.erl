%% A burst continuation must reach the connection's mailbox directly.
%% erlang:send_after(0, ...) goes through the timer wheel, whose ~1 ms
%% service tick clocked every 64-packet burst continuation and capped
%% bulk streams at ~85 MB/s regardless of the paced rate.
-module(quic_burst_continuation_tests).

-include_lib("eunit/include/eunit.hrl").

continuation_is_in_the_mailbox_immediately_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    S1 = quic_connection:arm_burst_continuation(S0),
    Ref = quic_connection:test_pacing_timer(S1),
    ?assert(is_reference(Ref)),
    receive
        {pacing_timeout, Ref} -> ok
    after 0 ->
        ?assert(false)
    end.

armed_continuation_is_not_duplicated_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    S1 = quic_connection:arm_burst_continuation(S0),
    S2 = quic_connection:arm_burst_continuation(S1),
    ?assertEqual(quic_connection:test_pacing_timer(S1), quic_connection:test_pacing_timer(S2)),
    receive
        {pacing_timeout, _} -> ok
    after 0 ->
        ?assert(false)
    end,
    receive
        {pacing_timeout, _} -> ?assert(false)
    after 0 ->
        ok
    end.
