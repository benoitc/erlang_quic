%%% -*- erlang -*-
%%%
%%% After quic:migrate/1 the client sends from a new local address, on a
%%% new path. Once that path is validated its congestion controller, RTT
%%% estimator and PMTU start over, as the server's do for a client that
%%% moved (RFC 9000 Section 9.4).

-module(quic_client_migration_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SERVER, {{127, 0, 0, 1}, 9}).
-define(CHALLENGE, <<"challeng">>).

validated_migration_starts_the_path_over_test() ->
    S0 = migrated(),
    ?assert(quic_rtt:has_sample(quic_loss:rtt(S0#state.loss_state))),
    S = quic_connection:handle_path_response(?CHALLENGE, S0),
    ?assertNot(quic_rtt:has_sample(quic_loss:rtt(S#state.loss_state))),
    ?assertEqual(
        quic_cc:cwnd(quic_cc:new(#{})), quic_cc:cwnd(S#state.cc_state)
    ),
    ?assertMatch([#path_state{status = validated}], quic_connection_test_support:alt_paths(S)).

server_keeps_its_path_when_a_probe_is_answered_test() ->
    S0 = migrated(server),
    S = quic_connection:handle_path_response(?CHALLENGE, S0),
    ?assert(quic_rtt:has_sample(quic_loss:rtt(S#state.loss_state))),
    ?assertEqual(quic_cc:cwnd(S0#state.cc_state), quic_cc:cwnd(S#state.cc_state)).

migrated() ->
    migrated(client).

%% A client that has migrated: sending under the new path's CID, which
%% it is still validating, with estimates from the old path.
migrated(Role) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(Role)
    ),
    Path = #path_state{
        remote_addr = ?SERVER,
        status = validating,
        challenge_data = ?CHALLENGE,
        challenge_count = 1,
        dcid = <<"spare-ci">>,
        dcid_seq = 1
    },
    CC0 = quic_cc:on_packet_sent(quic_cc:new(#{}), 12000),
    S0#state{
        remote_addr = ?SERVER,
        dcid = <<"spare-ci">>,
        loss_state = quic_loss:update_rtt(S0#state.loss_state, 40, 0),
        cc_state = quic_cc:on_packets_acked(CC0, 12000, 0),
        pmtu_state = quic_pmtu:on_connection_established(1500, quic_pmtu:new()),
        mig = #mig{alt_paths = [Path]}
    }.
