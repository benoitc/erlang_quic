%%% -*- erlang -*-
%%%
%%% With QUIC-LB configured (draft-ietf-quic-load-balancers-22), the CIDs offered in
%%% NEW_CONNECTION_ID carry the server ID like the handshake CID, so the
%%% load balancer still routes a peer that switches to one.

-module(quic_lb_new_connection_id_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SERVER_ID, <<1, 2, 3, 4>>).

issued_cids_encode_the_server_id_test() ->
    {ok, LB} = quic_lb:new_config(#{
        server_id => ?SERVER_ID, algorithm => plaintext, nonce_len => 6
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LB}),
    S0 = quic_connection_test_support:state_for_cid_limit(2),
    #state{cfg = Cfg} = S1 = quic_connection_test_support:state_set(S0, peer_active_cid_limit, 3),
    S = quic_connection:issue_new_connection_ids(S1#state{
        cfg = Cfg#conn_cfg{cid_config = CIDConfig}
    }),
    Issued = [
        CID
     || #cid_entry{seq_num = Seq, cid = CID} <- quic_connection_test_support:local_cids(S), Seq > 0
    ],
    ?assertEqual(2, length(Issued)),
    [
        ?assertEqual({ok, ?SERVER_ID}, quic_lb:decode_server_id(CID, LB))
     || CID <- Issued
    ],
    [?assertEqual(quic_lb:expected_cid_len(LB), byte_size(CID)) || CID <- Issued].
