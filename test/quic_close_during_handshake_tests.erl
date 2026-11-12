%%% -*- erlang -*-
%%%
%%% Closing before the handshake is confirmed still tells the peer (RFC
%%% 9000 Section 10.2.3): the CONNECTION_CLOSE goes out in Handshake
%%% packets, from a server in Initial packets too, and in 1-RTT packets
%%% once there are keys. An application close becomes a 0x1c
%%% APPLICATION_ERROR with no reason below 1-RTT.

-module(quic_close_during_handshake_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

client_sends_a_close_test() ->
    ?assertEqual([handshake], close_packet_types(client)).

server_sends_it_at_both_levels_test() ->
    ?assertEqual([handshake, initial], close_packet_types(server)).

%% RFC 9000 Section 10.1: an idle timeout closes silently.
idle_timeout_sends_nothing_test() ->
    ?assertEqual([], close_packet_types(server, idle_timeout)).

%% With 1-RTT keys but the handshake not yet confirmed, the peer may not
%% read 1-RTT packets, so the close goes out at the lower levels too.
server_with_1rtt_keys_sends_it_at_every_level_test() ->
    ?assertEqual([app, handshake, initial], close_packet_types(server, normal, unconfirmed)).

client_with_1rtt_keys_sends_it_in_handshake_too_test() ->
    ?assertEqual([app, handshake], close_packet_types(client, normal, unconfirmed)).

confirmed_sends_it_in_1rtt_only_test() ->
    ?assertEqual([app], close_packet_types(server, normal, confirmed)).

%% Every close path, not only a local close, goes out at each level.
transport_error_goes_out_at_every_level_test() ->
    Frame = {connection_close, transport, ?QUIC_PROTOCOL_VIOLATION, 0, <<"bad frame">>},
    ?assertEqual(
        [{app, Frame}, {handshake, Frame}, {initial, Frame}],
        closes(server, unconfirmed, fun(S) ->
            quic_connection:close_with_transport_error(?QUIC_PROTOCOL_VIOLATION, <<"bad frame">>, S)
        end)
    ).

tls_alert_goes_out_at_every_level_test() ->
    Code = ?QUIC_CRYPTO_ERROR_BASE + ?TLS_ALERT_HANDSHAKE_FAILURE,
    Frame = {connection_close, transport, Code, 0, <<"handshake failure">>},
    ?assertEqual(
        [{app, Frame}, {handshake, Frame}, {initial, Frame}],
        closes(server, unconfirmed, fun(S) ->
            quic_connection:send_tls_alert(?TLS_ALERT_HANDSHAKE_FAILURE, S)
        end)
    ).

%% An application close keeps its code in 1-RTT only; at the Handshake
%% level it is a 0x1c APPLICATION_ERROR with no reason.
terminate_close_goes_out_in_handshake_too_test() ->
    ?assertMatch(
        [
            {app, {connection_close, application, 16#42, _, <<"bye">>}},
            {handshake, {connection_close, transport, ?QUIC_APPLICATION_ERROR, 0, <<>>}}
        ],
        closes(client, unconfirmed, fun(S) ->
            quic_connection:send_connection_close({app_error, 16#42, <<"bye">>}, S)
        end)
    ).

confirmed_transport_error_goes_out_in_1rtt_only_test() ->
    Frame = {connection_close, transport, ?QUIC_PROTOCOL_VIOLATION, 0, <<"bad frame">>},
    ?assertEqual(
        [{app, Frame}],
        closes(server, confirmed, fun(S) ->
            quic_connection:close_with_transport_error(?QUIC_PROTOCOL_VIOLATION, <<"bad frame">>, S)
        end)
    ).

close_packet_types(Role) ->
    close_packet_types(Role, normal).

close_packet_types(Role, Reason) ->
    close_packet_types(Role, Reason, no_1rtt_keys).

close_packet_types(Role, Reason, Keys) ->
    Closes = closes(Role, Keys, fun(S0) ->
        S = quic_connection:initiate_close(Reason, S0),
        ?assertEqual(Reason, S#state.close_reason),
        S
    end),
    [Level || {Level, _} <- Closes].

%% The CONNECTION_CLOSE frames Close sent, by level, from a Role whose
%% handshake is at the given point.
closes(Role, Keys, Close) ->
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Peer),
        #state{hs = HS, loss_state = LS, app_keys = {ClientKeys, ServerKeys}} =
            S0 = quic_connection_test_support:with_keys_and_socket(
                quic_connection_test_support:state_for_role(Role)
            ),
        S1 = S0#state{
            app_keys =
                case Keys of
                    no_1rtt_keys -> undefined;
                    _ -> S0#state.app_keys
                end,
            loss_state =
                case Keys of
                    confirmed -> quic_loss:on_handshake_confirmed(LS);
                    _ -> LS
                end,
            coalesce = false,
            remote_addr = {{127, 0, 0, 1}, Port},
            hs = HS#hs{address_validated = true}
        },
        _ = quic_connection:flush_socket_batch(Close(S1)),
        SendKeys =
            case Role of
                server -> ServerKeys;
                client -> ClientKeys
            end,
        lists:sort(received(Peer, SendKeys, S0#state.dcid))
    after
        gen_udp:close(Peer)
    end.

%% The fixture uses one set of keys at every level.
received(Socket, Keys, DCID) ->
    case gen_udp:recv(Socket, 0, 200) of
        {ok, {_, _, Datagram}} -> packets(Datagram, Keys, DCID) ++ received(Socket, Keys, DCID);
        {error, timeout} -> []
    end.

packets(<<1:1, 1:1, Type:2, _:4, _:32, DL, _:DL/binary, SL, _:SL/binary, R0/binary>> = D, K, DCID) ->
    {TokenLen, R1} =
        case Type of
            0 -> quic_varint:decode(R0);
            _ -> {0, R0}
        end,
    <<_:TokenLen/binary, R2/binary>> = R1,
    {Len, R3} = quic_varint:decode(R2),
    <<Encrypted:Len/binary, Next/binary>> = R3,
    Header = binary:part(D, 0, byte_size(D) - byte_size(R3)),
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = K,
    {ok, _, _, Plain} =
        quic_aead:unprotect_long_packet(Cipher, Key, IV, HP, Header, Encrypted, undefined),
    close_frames(type(Type), Plain) ++ packets(Next, K, DCID);
packets(<<0:1, 1:1, _:6, _/binary>> = D, K, DCID) ->
    HeaderLen = 1 + byte_size(DCID),
    <<Header:HeaderLen/binary, Encrypted/binary>> = D,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = K,
    {ok, _, _, Plain} =
        quic_aead:unprotect_short_packet(Cipher, Key, IV, HP, Header, Encrypted, undefined),
    close_frames(app, Plain);
packets(_, _K, _DCID) ->
    [].

close_frames(Level, Plain) ->
    {ok, Frames} = quic_frame:decode_all(Plain),
    [{Level, F} || {connection_close, _, _, _, _} = F <- Frames].

type(0) -> initial;
type(2) -> handshake.
