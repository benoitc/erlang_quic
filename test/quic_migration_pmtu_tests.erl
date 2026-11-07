%%% -*- erlang -*-
%%%
%%% A path change resets PMTU to the base size (RFC 8899), and the
%%% server then searches again on the new path instead of staying at
%%% 1200 bytes for the rest of the connection.

-module(quic_migration_pmtu_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 2}, 40000}).

probes_the_new_path_after_migration_test() ->
    {ok, Sock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Peer = {{127, 0, 0, 1}, Port},
    try
        S1 = quic_connection:maybe_handle_address_change(Peer, 1200, state()),
        #path_state{challenge_data = Data} = quic_connection_test_support:pending_peer_path(S1),
        _ = recv_all(Sock),
        S2 = quic_connection:handle_path_response(Data, S1),
        ?assertEqual(Peer, S2#state.remote_addr),
        ?assert(lists:any(fun(D) -> byte_size(D) > 1200 end, recv_all(Sock)))
    after
        gen_udp:close(Sock)
    end.

recv_all(Sock) ->
    receive
        {udp, Sock, _, _, D} -> [D | recv_all(Sock)]
    after 100 -> []
    end.

state() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    {ok, Pool, _} = quic_cid:add_peer_cid(
        S0#state.cid_pool_state, 1, 0, <<"spare-ci">>, binary:copy(<<1>>, 16)
    ),
    S0#state{
        remote_addr = ?OLD,
        cid_pool_state = Pool,
        owner = spawn(fun() ->
            receive
            after 10000 -> ok
            end
        end),
        pmtu_state = quic_pmtu:on_connection_established(1500, quic_pmtu:new()),
        coalesce = false
    }.
