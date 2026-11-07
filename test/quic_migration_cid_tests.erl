%%% -*- erlang -*-
%%%
%%% The server keeps its CID for a new address only when the client
%%% kept its own, which is what a NAT does (RFC 9000 Section 9.5). A
%%% client that changed its CID moved on purpose, port change or not,
%%% and is followed under a fresh one, which data uses as soon as the
%%% server follows.

-module(quic_migration_cid_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(PORT_MOVE, {{127, 0, 0, 1}, 40001}).
-define(IP_MOVE, {{127, 0, 0, 2}, 40000}).

nat_rebinding_keeps_the_cid_test() ->
    S = quic_connection:maybe_handle_address_change(?PORT_MOVE, 1200, state(<<"own-cid0">>)),
    ?assertEqual(?PORT_MOVE, S#state.remote_addr),
    ?assertEqual(<<"peer-cid">>, S#state.dcid).

port_move_with_a_new_cid_takes_a_fresh_one_test() ->
    S = quic_connection:maybe_handle_address_change(?PORT_MOVE, 1200, state(<<"own-cid1">>)),
    ?assertEqual(?PORT_MOVE, S#state.remote_addr),
    ?assertEqual(<<"spare-ci">>, S#state.dcid).

data_to_a_new_ip_uses_its_cid_test() ->
    S = quic_connection:maybe_handle_address_change(?IP_MOVE, 1200, state(<<"own-cid1">>)),
    ?assertEqual(?IP_MOVE, S#state.remote_addr),
    ?assertEqual(<<"spare-ci">>, S#state.dcid).

failed_validation_restores_the_old_cid_test() ->
    S1 = quic_connection:maybe_handle_address_change(?IP_MOVE, 1200, state(<<"own-cid1">>)),
    Pending = quic_connection_test_support:pending_peer_path(S1),
    Expired = Pending#path_state{deadline = erlang:monotonic_time(millisecond) - 1},
    S2 = S1#state{mig = (S1#state.mig)#mig{pending_peer_validation = Expired}},
    {keep_state, S3} = quic_connection:handle_path_validation_timeout(S2),
    ?assertEqual(?OLD, S3#state.remote_addr),
    ?assertEqual(<<"peer-cid">>, S3#state.dcid).

validation_retires_the_old_cid_test() ->
    S1 = quic_connection:maybe_handle_address_change(?IP_MOVE, 1200, state(<<"own-cid1">>)),
    #path_state{challenge_data = Data} = quic_connection_test_support:pending_peer_path(S1),
    S2 = quic_connection:handle_path_response(Data, S1),
    ?assertEqual(<<"spare-ci">>, S2#state.dcid),
    ?assertNotEqual(not_found, quic_cid:retire_peer(S1#state.cid_pool_state, <<"peer-cid">>)),
    ?assertEqual(not_found, quic_cid:retire_peer(S2#state.cid_pool_state, <<"peer-cid">>)).

state(PassDCID) ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    {ok, Pool, _} = quic_cid:add_peer_cid(
        S0#state.cid_pool_state, 1, 0, <<"spare-ci">>, binary:copy(<<1>>, 16)
    ),
    S0#state{
        remote_addr = ?OLD,
        cid_pool_state = Pool,
        owner = owner(),
        pmtu_state = quic_pmtu:new(),
        mig = #mig{peer_dcid = <<"own-cid0">>, pass_dcid = PassDCID}
    }.

%% Takes the path_changed notices, which would otherwise reach later tests.
owner() ->
    spawn(fun() ->
        receive
        after 10000 -> ok
        end
    end).
