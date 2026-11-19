%%% -*- erlang -*-
%%%
%%% "Endpoints SHOULD wait three times the PTO before initiating a key
%%% update after receiving an acknowledgment that confirms that the
%%% previous key update was received" (RFC 9001 Section 6.5). The
%%% previous keys are held for that long, so an update asked for while
%%% they are still there is refused.

-module(quic_key_update_spacing_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

refused_while_previous_keys_are_held_test() ->
    S = confirmed_after_update(),
    {Reply, S1} = key_update(S),
    ?assertEqual({error, key_update_too_soon}, Reply),
    ?assertEqual(
        quic_connection_test_support:key_phase(S), quic_connection_test_support:key_phase(S1)
    ).

accepted_once_previous_keys_are_retired_test() ->
    S = quic_connection:retire_prev_keys(confirmed_after_update()),
    {Reply, S1} = key_update(S),
    ?assertEqual(ok, Reply),
    ?assertNotEqual(
        quic_connection_test_support:key_phase(S), quic_connection_test_support:key_phase(S1)
    ).

%% The confidentiality limit is a MUST (Section 6.6) and does not wait.
confidentiality_limit_does_not_wait_test() ->
    #state{key_state = KS} = S = confirmed_after_update(),
    S1 = quic_connection:maybe_force_key_update(
        S#state{key_state = KS#key_update_state{send_count = 16#800000 - 1}}, 1
    ),
    ?assertNotEqual(
        quic_connection_test_support:key_phase(S), quic_connection_test_support:key_phase(S1)
    ).

confirmed_after_update() ->
    S = quic_connection_test_support:after_own_key_update(100),
    S#state{loss_state = quic_loss:on_handshake_confirmed(quic_loss:new())}.

key_update(S) ->
    From = {self(), make_ref()},
    {keep_state, S1, [{reply, From, Reply}]} = quic_connection:connected(
        {call, From}, key_update, S
    ),
    {Reply, S1}.
