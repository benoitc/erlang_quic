%%% -*- erlang -*-
%%%
%%% "After the client has received and processed an Initial or Retry
%%% packet from the server, it MUST discard any subsequent Retry
%%% packets" (RFC 9000 Section 17.2.5.2).

-module(quic_late_retry_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(ODCID, <<"orig-dci">>).
-define(SCID, <<"own-cid0">>).

discarded_after_a_server_initial_test() ->
    S0 = client(),
    #state{hs = HS} = S0,
    S1 = S0#state{
        hs = HS#hs{pn_initial = (HS#hs.pn_initial)#pn_space{largest_recv = 0}},
        dcid = <<"server-c">>
    },
    ?assertEqual({error, late_retry}, quic_connection:decode_and_decrypt_packet(retry(), S1)).

client() ->
    #state{cfg = Cfg, hs = HS} = S = quic_connection_test_support:state_with_keys(client),
    S#state{
        dcid = ?ODCID,
        version = ?QUIC_VERSION_1,
        cfg = Cfg#conn_cfg{original_dcid = ?ODCID, scid = ?SCID},
        hs = HS#hs{
            pn_initial = #pn_space{
                next_pn = 1,
                largest_recv = undefined,
                recv_time = undefined,
                ack_ranges = [],
                ack_eliciting_in_flight = 0
            }
        }
    }.

retry() ->
    quic_packet:encode_retry(?ODCID, ?SCID, <<"retry-sc">>, <<"token">>, ?QUIC_VERSION_1).
