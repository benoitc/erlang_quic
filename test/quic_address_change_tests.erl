%%% -*- erlang -*-
%%%
%%% A peer the network moves to a new IP address keeps sending with the
%%% same CID. Following it under a fresh CID of the peer's is right when
%%% there is one; kwik issues none, and a server that insists on one
%%% stays on a path that no longer reaches the client. RFC 9000 Section
%%% 9.5 lets the current CID stay when the peer's did.

-module(quic_address_change_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(NEW, {{127, 0, 0, 2}, 40000}).

follows_a_peer_that_kept_its_cid_test() ->
    S = quic_connection:maybe_handle_address_change(?NEW, 100, state(<<"own-cid0">>)),
    ?assertEqual(?NEW, S#state.remote_addr),
    ?assertEqual(<<"peer-cid">>, S#state.dcid).

stays_for_a_migration_it_cannot_probe_test() ->
    S = quic_connection:maybe_handle_address_change(?NEW, 100, state(<<"own-cid1">>)),
    ?assertEqual(?OLD, S#state.remote_addr).

pass_dcid_is_the_first_short_header_dcid_test() ->
    S = state(undefined),
    ?assertEqual(
        <<"own-cid0">>,
        quic_connection:pass_dcid([<<16#c0, "long">>, <<16#41, "own-cid0", "rest">>], S)
    ),
    ?assertEqual(undefined, quic_connection:pass_dcid([<<16#c0, "long">>], S)).

state(PassDCID) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    Pool = quic_cid:set_initial_peer_cid(
        quic_cid:new(<<"own-cid0">>, 2), <<"peer-cid">>, undefined
    ),
    S0#state{
        remote_addr = ?OLD,
        cid_pool_state = Pool,
        mig = #mig{peer_dcid = <<"own-cid0">>, pass_dcid = PassDCID}
    }.
