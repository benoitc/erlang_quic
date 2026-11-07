%%% -*- erlang -*-
%%%
%%% Only a client migrates (RFC 9000 Section 9). A server connection
%%% sends from the listener's socket, which quic:migrate/1 must leave
%%% alone.

-module(quic_server_migrate_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

server_refuses_to_migrate_test() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    {ok, Pool} = add_spare(S0#state.cid_pool_state),
    S1 = S0#state{
        cid_pool_state = Pool,
        loss_state = quic_loss:on_handshake_confirmed(S0#state.loss_state)
    },
    Listener = S1#state.socket,
    From = {self(), make_ref()},
    {keep_state, S2, [{reply, From, Reply}]} =
        quic_connection:connected({call, From}, migrate, S1),
    ?assertEqual({error, not_supported_on_server}, Reply),
    ?assertEqual(Listener, S2#state.socket),
    ?assertMatch({ok, _}, inet:port(Listener)),
    {keep_state, _, [{reply, From, Reply2}]} =
        quic_connection:connected({call, From}, {migrate, #{}}, S1),
    ?assertEqual({error, not_supported_on_server}, Reply2).

add_spare(Pool0) ->
    case quic_cid:add_peer_cid(Pool0, 1, 0, <<"spare-ci">>, binary:copy(<<1>>, 16)) of
        {ok, Pool, _} -> {ok, Pool};
        Other -> Other
    end.
