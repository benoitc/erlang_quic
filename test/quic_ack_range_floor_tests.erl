%%% -*- erlang -*-
%%%
%%% A packet number below the ACK ranges dropped by the range cap is
%%% discarded as a duplicate (RFC 9000 Sections 12.3 and 13.2.3).

-module(quic_ack_range_floor_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

replay_below_dropped_range_test() ->
    S0 = client(),
    S1 = quic_connection:handle_packet_loop(app_packet(1128, 1000, S0), S0),
    ?assertEqual(1000, S1#state.max_data_remote),
    S = quic_connection:handle_packet_loop(app_packet(1000, 2000, S1), S1),
    ?assertEqual(1000, S#state.max_data_remote).

replay_below_dropped_range_in_a_batch_test() ->
    S1 = quic_connection:fold_opened([{1128, 16#41, [{max_data, 1000}]}], client()),
    ?assertEqual(1000, S1#state.max_data_remote),
    S = quic_connection:fold_opened([{1000, 16#41, [{max_data, 2000}]}], S1),
    ?assertEqual(1000, S#state.max_data_remote).

client() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    S1 = quic_connection_test_support:state_with_pn_app(S0, 1126),
    Ranges = [{PN, PN} || PN <- lists:seq(1126, 1000, -2)],
    64 = length(Ranges),
    S1#state{
        max_data_remote = 100,
        pn_app = (S1#state.pn_app)#pn_space{ack_ranges = Ranges}
    }.

app_packet(PN, MaxData, #state{app_keys = {_, ServerKeys}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = quic_frame:encode({max_data, MaxData}),
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, 16#41, <<"own-cid0">>, [
        Payload, <<0, 0, 0>>
    ]).
