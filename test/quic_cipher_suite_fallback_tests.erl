%%% -*- erlang -*-
%%%
%%% A cipher suite is only used when both sides allow it (RFC 9846
%%% Section 4.2.1), never taken as a default when they do not.

-module(quic_cipher_suite_fallback_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

no_common_suite_test() ->
    ?assertEqual(
        none, quic_tls_negotiation:select_cipher([?TLS_AES_256_GCM_SHA384], [aes_128_gcm])
    ).

server_without_a_common_suite_aborts_test() ->
    {CH, _, _} = quic_tls:build_client_hello(#{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        ciphers => [aes_256_gcm],
        transport_params => #{}
    }),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S = quic_connection:process_tls_messages(initial, CH, S0#state{
        cfg = Cfg#conn_cfg{
            cipher_preference = [aes_128_gcm], tls_groups = [x25519], alpn_list = [<<"h3">>]
        },
        hs = HS#hs{tls_state = awaiting_client_hello, tls_transcript = <<>>}
    }),
    ?assertEqual({tls_alert, ?TLS_ALERT_HANDSHAKE_FAILURE}, S#state.close_reason).

%% RFC 9846 Section 4.2.4: a HelloRetryRequest is checked like a
%% ServerHello, before its suite is used for the transcript.
hello_retry_request_with_a_suite_not_offered_test() ->
    HRR = quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_256_GCM_SHA384, x25519),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    {_, Priv} = quic_crypto:generate_key_pair(x25519),
    S = quic_connection:process_tls_messages(initial, HRR, S0#state{
        cfg = Cfg#conn_cfg{cipher_preference = [aes_128_gcm], tls_groups = [x25519]},
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_server_hello,
            tls_group = x25519,
            tls_private_key = Priv,
            tls_transcript = <<>>,
            tls_ch1_opts = #{}
        }
    }),
    ?assertEqual({tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER}, S#state.close_reason).

%% An external PSK is SHA-256 (RFC 9846 Section 4.3.11), so it goes with a
%% suite of that hash and not with the one the binder was checked by.
external_psk_needs_a_sha256_suite_test() ->
    {CH, _, _} = quic_tls:build_client_hello(#{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        external_psk => {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>}
    }),
    <<_:8, _:24, Body/binary>> = CH,
    {ok, CHMap} = quic_tls:parse_client_hello(Body),
    Config = #{psks => #{<<"id">> => <<"this-is-a-32-byte-test-secret!!!">>}},
    Known = quic_tls_negotiation:known_external_psk(CHMap, Config),
    ?assertMatch({ok, _}, quic_tls:select_psk(CHMap, CH, Known, [psk_dhe_ke], aes_128_gcm)),
    ?assertEqual(none, quic_tls:select_psk(CHMap, CH, Known, [psk_dhe_ke], aes_256_gcm)).

%% RFC 9846 Section 4.2.4: the ServerHello names the suite of the
%% HelloRetryRequest before it.
server_hello_after_retry_keeps_the_retry_suite_test() ->
    S = retried_client(aes_128_gcm),
    ?assertEqual(
        awaiting_encrypted_extensions,
        (server_hello(aes_128_gcm, #{}, S))#state.hs#hs.tls_state
    ),
    ?assertExit({tls_alert, illegal_parameter}, server_hello(chacha20_poly1305, #{}, S)).

retried_client(HrrCipher) ->
    S0 = client_awaiting_server_hello(#{}),
    HRR = quic_tls:build_hello_retry_request(
        <<>>, quic_tls_negotiation:cipher_atom_to_code(HrrCipher), x25519
    ),
    S = quic_connection:process_tls_messages(initial, HRR, S0),
    ?assertMatch(#hs{hrr_sent = true, tls_group = x25519}, S#state.hs),
    S.

%% A client that offered all three suites, with its first key share in
%% secp256r1, waiting for the ServerHello.
client_awaiting_server_hello(ExtraOpts) ->
    Ciphers = [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
    Groups = [secp256r1, x25519],
    Opts = ExtraOpts#{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        groups => Groups,
        ciphers => Ciphers
    },
    {CH1, Priv, Random} = quic_tls:build_client_hello(Opts),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S0#state{
        cfg = Cfg#conn_cfg{
            cipher_preference = Ciphers,
            tls_groups = Groups,
            external_psk = maps:get(external_psk, ExtraOpts, undefined)
        },
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_server_hello,
            tls_group = secp256r1,
            tls_private_key = Priv,
            tls_transcript = CH1,
            tls_ch1_random = Random,
            tls_ch1_opts = Opts
        }
    }.

server_hello(Cipher, Extra, #state{hs = #hs{tls_group = Group}} = S) ->
    {Msg, _} = quic_tls:build_server_hello(Extra#{
        cipher_suite => quic_tls_negotiation:cipher_atom_to_code(Cipher),
        key_pair => quic_crypto:generate_key_pair(Group),
        key_share_group => Group
    }),
    quic_connection:process_tls_messages(initial, Msg, S).

%% RFC 9846 Section 4.3.11: a server accepting an external PSK, which is
%% SHA-256, selects a SHA-256 suite.
external_psk_accepted_with_a_suite_of_its_hash_test() ->
    Psk = {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>},
    S = client_awaiting_server_hello(#{external_psk => Psk}),
    Accepted = #{selected_psk_identity => 0},
    ?assertMatch(
        #hs{tls_state = awaiting_encrypted_extensions, selected_psk = #{}},
        (server_hello(aes_128_gcm, Accepted, S))#state.hs
    ),
    ?assertExit({tls_alert, illegal_parameter}, server_hello(aes_256_gcm, Accepted, S)).

%% The same for a resumption ticket, which carries the hash of the suite
%% it was issued under, here one that allows 0-RTT.
ticket_accepted_with_a_suite_of_its_hash_test() ->
    Ticket = #session_ticket{
        server_name = <<"localhost">>,
        ticket = <<"ticket">>,
        lifetime = 3600,
        age_add = 0,
        nonce = <<0>>,
        resumption_secret = <<0:256>>,
        max_early_data = 16#FFFFFFFF,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>,
        transport_params = #{}
    },
    S0 = client_awaiting_server_hello(#{session_ticket => Ticket}),
    S = S0#state{
        hs = (S0#state.hs)#hs{
            server_name = <<"localhost">>,
            ticket_store = quic_ticket:store_ticket(
                <<"localhost">>, Ticket, quic_ticket:new_store()
            )
        }
    },
    Accepted = #{selected_psk_identity => 0},
    ?assertMatch(
        #hs{tls_state = awaiting_encrypted_extensions, selected_psk = #{}},
        (server_hello(chacha20_poly1305, Accepted, S))#state.hs
    ),
    ?assertExit({tls_alert, illegal_parameter}, server_hello(aes_256_gcm, Accepted, S)).

%% RFC 9846 Section 4.3.11: a known external PSK steers the server to a
%% suite of its hash when both sides allow one.
psk_hash_steers_suite_selection_test() ->
    Client = [?TLS_AES_256_GCM_SHA384, ?TLS_AES_128_GCM_SHA256],
    Server = [aes_256_gcm, aes_128_gcm],
    ?assertEqual(aes_128_gcm, quic_tls_negotiation:select_cipher(Client, Server, sha256)),
    ?assertEqual(aes_256_gcm, quic_tls_negotiation:select_cipher(Client, Server, undefined)),
    ?assertEqual(
        aes_256_gcm, quic_tls_negotiation:select_cipher(Client, [aes_256_gcm], sha256)
    ),
    ?assertEqual(none, quic_tls_negotiation:select_cipher(Client, [chacha20_poly1305], sha256)).

known_external_psk_needs_a_known_identity_test() ->
    {CH, _, _} = quic_tls:build_client_hello(#{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        external_psk => {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>}
    }),
    <<_:8, _:24, Body/binary>> = CH,
    {ok, CHMap} = quic_tls:parse_client_hello(Body),
    Known = #{psks => #{<<"id">> => <<"this-is-a-32-byte-test-secret!!!">>}},
    ?assertMatch(
        {ok, #{identity_idx := 0, identity := <<"id">>}},
        quic_tls_negotiation:known_external_psk(CHMap, Known)
    ),
    ?assertEqual(none, quic_tls_negotiation:known_external_psk(CHMap, #{psks => #{}})),
    ?assertEqual(none, quic_tls_negotiation:known_external_psk(CHMap, undefined)).
