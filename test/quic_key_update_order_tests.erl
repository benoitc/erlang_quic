%%% -*- erlang -*-
%%%
%%% Packets with higher numbers are protected with the same or newer
%%% keys. One that opens with the old keys above a packet that used the
%%% new ones is a KEY_UPDATE_ERROR (RFC 9001 Section 6.4).

-module(quic_key_update_order_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

old_keys_above_a_new_key_packet_close_test() ->
    S0 = updated(),
    S1 = recv(new, 101, S0),
    S2 = recv(new, 110, S1),
    S = recv(old, 105, S2),
    ?assertMatch({transport, ?QUIC_KEY_UPDATE_ERROR, _}, S#state.close_reason).

old_keys_below_the_new_ones_are_late_packets_test() ->
    S0 = updated(),
    S1 = recv(new, 101, S0),
    S2 = recv(new, 110, S1),
    S = recv(old, 90, S2),
    ?assertEqual(undefined, S#state.close_reason).

%% A server that has just updated its keys, having received packets 95
%% to 100.
updated() ->
    S0 = quic_connection_test_support:state_sending(
        quic_connection_test_support:after_own_key_update(100)
    ),
    S0#state{
        key_state = (S0#state.key_state)#key_update_state{update_state = initiated},
        pn_app = (S0#state.pn_app)#pn_space{ack_ranges = [{95, 100}]},
        hs = (S0#state.hs)#hs{tls_state = handshake_complete}
    }.

recv(Which, PN, #state{key_state = KS, cfg = #conn_cfg{scid = SCID}} = State) ->
    {Phase, {ClientKeys, _}} =
        case Which of
            new -> {KS#key_update_state.current_phase, KS#key_update_state.current_keys};
            old -> {1 - KS#key_update_state.current_phase, KS#key_update_state.prev_keys}
        end,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Payload = <<(quic_frame:encode(ping))/binary, 0:(8 * 20)>>,
    Packet = quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, PN, 16#40 bor (Phase bsl 2), SCID, Payload
    ),
    {ok, app, _, <<>>, NewState, processed} =
        quic_connection:decode_short_header_packet(Packet, State),
    NewState.
