%%% -*- erlang -*-
%%%
%%% A peer with a zero-length CID issues no CIDs to migrate onto, yet it
%%% may still move to a new address (RFC 9000 Section 9.5).

-module(quic_zero_length_cid_migration_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

-define(NEW_ADDR, {{127, 0, 0, 2}, 9}).

zero_length_cid_peer_is_validated_on_new_address_test() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<>>),
    S1 = quic_connection:maybe_handle_address_change(?NEW_ADDR, 1200, S0),
    ?assertMatch(
        #path_state{remote_addr = ?NEW_ADDR, status = validating, dcid = <<>>},
        quic_connection_test_support:pending_peer_path(S1)
    ).

peer_without_spare_cid_is_not_followed_test() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    S1 = quic_connection:maybe_handle_address_change(?NEW_ADDR, 1200, S0),
    ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S1)).
