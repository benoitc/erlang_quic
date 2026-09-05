%% record_app_recv/4 fuses the three per-packet receive updates of the
%% 1-RTT hot path (PN space, spin bit, activity stamp) into one state
%% rebuild. It must stay observably identical to running the three
%% helpers in sequence, which these tests check over random packet
%% sequences for every role and spin-bit setting.
-module(quic_record_app_recv_tests).

-include_lib("eunit/include/eunit.hrl").

reference(FirstByte, PN, State, Now) ->
    S1 = quic_connection:record_received_pn(app, PN, State, Now),
    S2 = quic_connection:update_spin_from_recv(FirstByte, PN, S1),
    quic_connection:update_last_activity(S2, Now).

%% Short-header first byte with the spin bit set or clear.
first_byte(Spin) -> 16#40 bor (Spin bsl 5).

run(Role, SpinEnabled, Seed) ->
    rand:seed(exsplus, {Seed, Seed * 3 + 1, Seed * 5 + 2}),
    S0 = quic_connection:test_app_recv_state(Role, SpinEnabled),
    lists:foldl(
        fun(I, {Fused, Ref}) ->
            %% Mostly sequential with occasional reordering and duplicates.
            PN =
                case rand:uniform(10) of
                    1 -> max(0, I - rand:uniform(4));
                    2 -> I + rand:uniform(3);
                    _ -> I
                end,
            FB = first_byte(rand:uniform(2) - 1),
            Now = 1000 + I,
            NewFused = quic_connection:record_app_recv(FB, PN, Fused, Now),
            NewRef = reference(FB, PN, Ref, Now),
            ?assertEqual(NewRef, NewFused),
            {NewFused, NewRef}
        end,
        {S0, S0},
        lists:seq(0, 200)
    ).

fused_matches_reference_test_() ->
    [
        {lists:flatten(io_lib:format("~p spin=~p seed=~p", [Role, Spin, Seed])), fun() ->
            run(Role, Spin, Seed)
        end}
     || Role <- [client, server], Spin <- [true, false], Seed <- lists:seq(1, 5)
    ].
