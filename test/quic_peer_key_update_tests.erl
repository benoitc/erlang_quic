%%% -*- erlang -*-
%%%
%%% After a key update of our own, the previous keys are kept for late
%%% packets, yet the peer may already start its next update. RFC 9001
%%% Section 6.5 tells them apart by packet number.

-module(quic_peer_key_update_tests).

-include_lib("eunit/include/eunit.hrl").

late_old_phase_packet_uses_previous_keys_test() ->
    S0 = quic_connection_test_support:after_own_key_update(100),
    {Keys, S1} = quic_connection:select_decrypt_keys(0, 90, S0),
    ?assertEqual(quic_connection_test_support:state_get(S0, prev_app_keys), Keys),
    ?assertEqual(1, quic_connection_test_support:key_phase(S1)).

newer_other_phase_packet_is_a_peer_update_test() ->
    S0 = quic_connection_test_support:after_own_key_update(100),
    {Keys, S1} = quic_connection:select_decrypt_keys(0, 101, S0),
    ?assertEqual(0, quic_connection_test_support:key_phase(S1)),
    ?assertNotEqual(quic_connection_test_support:state_get(S0, prev_app_keys), Keys),
    ?assertNotEqual(quic_connection_test_support:state_get(S0, app_keys), Keys).
