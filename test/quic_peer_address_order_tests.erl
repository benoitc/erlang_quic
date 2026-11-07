%%% -*- erlang -*-
%%%
%%% A server changes the address it sends to only for the
%%% highest-numbered non-probing packet (RFC 9000 Section 9.3), and a
%%% newer packet from another address while a validation runs moves it
%%% on, which also abandons a spurious migration (Section 9.3.2).

-module(quic_peer_address_order_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(A, {{127, 0, 0, 1}, 40001}).
-define(B, {{127, 0, 0, 1}, 40002}).

reordered_packet_does_not_move_back_test() ->
    S1 = recv(7, ?A, (state())#state{remote_addr = ?A}),
    S2 = recv(6, ?OLD, S1),
    ?assertEqual(?A, S2#state.remote_addr),
    ?assertEqual(idle, (S2#state.mig)#mig.migration_state).

newer_packet_from_the_old_address_ends_a_spurious_migration_test() ->
    S1 = recv(5, ?OLD, state()),
    S2 = recv(6, ?A, S1),
    ?assertEqual(?A, S2#state.remote_addr),
    S3 = recv(7, ?OLD, S2),
    ?assertEqual(?OLD, S3#state.remote_addr),
    ?assertEqual(idle, (S3#state.mig)#mig.migration_state),
    ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S3)).

second_rebinding_during_validation_is_followed_test() ->
    S1 = recv(5, ?OLD, state()),
    S2 = recv(6, ?A, S1),
    S3 = recv(7, ?B, S2),
    ?assertEqual(?B, S3#state.remote_addr),
    ?assertMatch(
        #path_state{remote_addr = ?B}, quic_connection_test_support:pending_peer_path(S3)
    ),
    S4 = give_up(S3),
    ?assertEqual(?OLD, S4#state.remote_addr).

recv(PN, From, State) ->
    quic_connection:server_recv_pass([packet(PN, State)], From, undefined, State).

give_up(#state{mig = Mig} = S) ->
    Pending = Mig#mig.pending_peer_validation,
    Expired = Pending#path_state{deadline = erlang:monotonic_time(millisecond) - 1},
    S1 = S#state{mig = Mig#mig{pending_peer_validation = Expired}},
    {keep_state, S2} = quic_connection:handle_path_validation_timeout(S1),
    S2.

packet(PN, #state{app_keys = {ClientKeys, _}, cfg = #conn_cfg{scid = SCID}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Payload = quic_connection:pad_for_header_protection(quic_frame:encode(ping)),
    FirstByte = 16#40 bor (quic_packet:pn_length(PN) - 1),
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, FirstByte, SCID, Payload).

state() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    S0#state{
        remote_addr = ?OLD,
        owner = self(),
        pmtu_state = quic_pmtu:new(),
        hs = (S0#state.hs)#hs{
            tls_state = handshake_complete, pn_initial = (S0#state.hs)#hs.pn_handshake
        }
    }.
