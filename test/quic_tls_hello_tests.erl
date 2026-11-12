%%% -*- erlang -*-
%%%
%%% A handshake message that breaks a rule of RFC 9846 Sections 4.2 to
%%% 4.7 ends the handshake with the alert the RFC names for it.

-module(quic_tls_hello_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% supported_versions (RFC 9846 Section 4.3.1)
%%====================================================================

server_hello_naming_tls13_test() ->
    ?assertEqual(undefined, client_close(server_hello())).

server_hello_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        client_close(without_ext(?EXT_SUPPORTED_VERSIONS, server_hello()))
    ).

server_hello_selecting_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(set_ext(?EXT_SUPPORTED_VERSIONS, <<?TLS_VERSION_1_2:16>>, server_hello()))
    ).

hello_retry_request_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        client_close(without_ext(?EXT_SUPPORTED_VERSIONS, hello_retry_request()))
    ).

hello_retry_request_selecting_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(
            set_ext(?EXT_SUPPORTED_VERSIONS, <<?TLS_VERSION_1_2:16>>, hello_retry_request())
        )
    ).

client_hello_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        server_close(without_ext(?EXT_SUPPORTED_VERSIONS, client_hello()))
    ).

client_hello_offering_only_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        server_close(set_ext(?EXT_SUPPORTED_VERSIONS, <<2, ?TLS_VERSION_1_2:16>>, client_hello()))
    ).

%%====================================================================
%% ClientHello legacy fields (RFC 9846 Section 4.2.2)
%%====================================================================

client_hello_legacy_version_test_() ->
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
            server_close(with_legacy_version(V, client_hello()))
        )
     || V <- [16#0301, ?TLS_VERSION_1_3, 16#7f1c]
    ].

client_hello_compression_test_() ->
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
            server_close(with_compression(M, client_hello()))
        )
     || M <- [<<1>>, <<1, 0>>, <<0, 1>>]
    ].

%%====================================================================
%% ServerHello legacy fields (RFC 9846 Sections 4.2.3 and 4.2.4)
%%====================================================================

server_hello_legacy_version_test_() ->
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
            client_close(with_legacy_version(V, Msg))
        )
     || V <- [16#0301, ?TLS_VERSION_1_3], Msg <- [server_hello(), hello_retry_request()]
    ].

server_hello_compression_test_() ->
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
            client_close(with_server_compression(1, Msg))
        )
     || Msg <- [server_hello(), hello_retry_request()]
    ].

server_hello_session_id_echo_test_() ->
    [
        ?_assertEqual({tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER}, client_close(Msg))
     || Msg <- [
            server_hello(#{session_id => <<1, 2, 3, 4>>}),
            quic_tls:build_hello_retry_request(<<1, 2, 3, 4>>, ?TLS_AES_128_GCM_SHA256, secp256r1)
        ]
    ].

%%====================================================================
%% HelloRetryRequest (RFC 9846 Section 4.2.4)
%%====================================================================

hello_retry_request_for_another_group_test() ->
    S = client_after(hello_retry_request()),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertMatch(#{key_share := [{?GROUP_SECP256R1, _}]}, retried_client_hello(S)).

hello_retry_request_for_the_group_already_sent_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, x25519))
    ).

hello_retry_request_changing_nothing_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(without_ext(?EXT_KEY_SHARE, hello_retry_request()))
    ).

%% The cookie is the change: it goes back, with the same key share.
hello_retry_request_with_only_a_cookie_test() ->
    HRR = add_ext(
        ?EXT_COOKIE, <<5:16, "token">>, without_ext(?EXT_KEY_SHARE, hello_retry_request())
    ),
    S = client_after(HRR),
    ?assertEqual(undefined, S#state.close_reason),
    CH2 = retried_client_hello(S),
    ?assertEqual(<<5:16, "token">>, maps:get(?EXT_COOKIE, maps:get(extensions, CH2))),
    ?assertEqual(
        maps:get(?EXT_KEY_SHARE, maps:get(extensions, first_client_hello())),
        maps:get(?EXT_KEY_SHARE, maps:get(extensions, CH2))
    ).

hello_retry_request_with_a_cookie_for_the_group_already_sent_test() ->
    HRR = add_ext(
        ?EXT_COOKIE,
        <<5:16, "token">>,
        quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, x25519)
    ),
    S = client_after(HRR),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertMatch(#{extensions := #{?EXT_COOKIE := <<5:16, "token">>}}, retried_client_hello(S)).

%%====================================================================
%% PSK key exchange modes (RFC 9846 Sections 4.3.9 and 4.3.11)
%%====================================================================

psk_without_modes_test_() ->
    Offers = [
        {external_psk, {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>}},
        {session_ticket, ticket()}
    ],
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_MISSING_EXTENSION},
            server_close(without_ext(?EXT_PSK_KEY_EXCHANGE_MODES, client_hello(#{Key => Offer})))
        )
     || {Key, Offer} <- Offers
    ].

ticket_resumes_in_psk_dhe_ke_test() ->
    ?assertMatch({true, #{source := ticket}}, resume_with_modes(<<?PSK_KE_MODE_DHE_KE>>)).

ticket_not_resumed_without_psk_dhe_ke_test() ->
    ?assertEqual({false, undefined}, resume_with_modes(<<?PSK_KE_MODE_KE>>)).

ticket_selected_without_key_share_test() ->
    SH = server_hello(#{selected_psk_identity => 0, selected_psk_mode => psk_ke}),
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        (client_after(SH, #{session_ticket => ticket()}))#state.close_reason
    ).

ticket_selected_at_another_index_test() ->
    SH = server_hello(#{selected_psk_identity => 1}),
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        (client_after(SH, #{session_ticket => ticket()}))#state.close_reason
    ).

external_psk_mode_follows_the_key_share_test() ->
    Psk = {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>, [psk_dhe_ke, psk_ke]},
    SH = server_hello(#{selected_psk_identity => 0, selected_psk_mode => psk_ke}),
    S = client_after(SH, #{external_psk => Psk}),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertMatch(#{mode := psk_ke}, (S#state.hs)#hs.selected_psk).

external_psk_mode_not_offered_test() ->
    Psk = {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>, [psk_ke]},
    SH = server_hello(#{selected_psk_identity => 0}),
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        (client_after(SH, #{external_psk => Psk}))#state.close_reason
    ).

%% Whether a server resumed a ticket from a ClientHello offering Modes,
%% and the PSK it selected.
resume_with_modes(Modes) ->
    Ticket = ticket(),
    Tab = ets:new(issued, [set, public]),
    try
        quic_ticket:store_issued(Tab, Ticket),
        CH = set_ext(
            ?EXT_PSK_KEY_EXCHANGE_MODES,
            <<(byte_size(Modes)), Modes/binary>>,
            client_hello(#{session_ticket => Ticket})
        ),
        S = server_after(rebind(CH, Ticket), Tab),
        {
            quic_ticket:lookup_issued(Tab, Ticket#session_ticket.ticket) =:= error,
            (S#state.hs)#hs.selected_psk
        }
    after
        ets:delete(Tab)
    end.

ticket() ->
    T = quic_ticket:create_ticket(<<"localhost">>, <<7:256>>, 0, aes_128_gcm, <<"h3">>),
    T#session_ticket{transport_params = #{}}.

%% CH with its resumption binder computed again over what it now holds.
rebind(CH, Ticket) ->
    Cipher = Ticket#session_ticket.cipher,
    PSK = quic_ticket:derive_psk(Ticket#session_ticket.resumption_secret, Ticket),
    Truncated = binary:part(CH, 0, byte_size(CH) - 35),
    Binder = quic_crypto:compute_psk_binder(
        Cipher,
        quic_crypto:derive_early_secret(Cipher, PSK),
        quic_crypto:transcript_hash(Cipher, Truncated),
        resumption
    ),
    <<Truncated/binary, 33:16, 32, Binder/binary>>.

%%====================================================================
%% Extension data and message structure (RFC 9846 Sections 4.3 and 6.2)
%%====================================================================

client_hello_extension_with_trailing_data_test_() ->
    Psk = {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>},
    Exts = [
        {?EXT_KEY_SHARE, #{}},
        {?EXT_SERVER_NAME, #{}},
        {?EXT_ALPN, #{}},
        {?EXT_SUPPORTED_GROUPS, #{}},
        {?EXT_SIGNATURE_ALGORITHMS, #{}},
        {?EXT_PSK_KEY_EXCHANGE_MODES, #{}},
        {?EXT_SUPPORTED_VERSIONS, #{}},
        {?EXT_PRE_SHARED_KEY, #{external_psk => Psk}}
    ],
    [
        {
            integer_to_list(Type),
            ?_assertEqual(
                {tls_alert, ?TLS_ALERT_DECODE_ERROR},
                server_close(append_to_ext(Type, <<0>>, client_hello(Extra)))
            )
        }
     || {Type, Extra} <- Exts
    ].

client_hello_malformed_extension_test_() ->
    Malformed = [
        {?EXT_SUPPORTED_GROUPS, <<3:16, 0, 29, 0>>},
        {?EXT_SIGNATURE_ALGORITHMS, <<1:16, 4>>},
        {?EXT_SUPPORTED_GROUPS, <<0:16>>},
        {?EXT_KEY_SHARE, <<6:16, 0, 29, 0, 32, 1, 2>>},
        {?EXT_ALPN, <<3:16, 0, 1, $h>>},
        {?EXT_SERVER_NAME, <<0:16>>},
        {?EXT_PSK_KEY_EXCHANGE_MODES, <<0>>}
    ],
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_DECODE_ERROR},
            server_close(set_ext(Type, Data, client_hello()))
        )
     || {Type, Data} <- Malformed
    ].

client_hello_early_data_with_data_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR},
        server_close(add_ext(?EXT_EARLY_DATA, <<0>>, client_hello()))
    ).

client_hello_odd_cipher_suites_test() ->
    ?assertEqual({tls_alert, ?TLS_ALERT_DECODE_ERROR}, server_close(with_suites(<<19, 1, 19>>))).

client_hello_long_session_id_test() ->
    <<T, _:24, V:16, R:32/binary, 0, Rest/binary>> = client_hello(),
    Body = <<V:16, R/binary, 33, 0:264, Rest/binary>>,
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR},
        server_close(<<T, (byte_size(Body)):24, Body/binary>>)
    ).

client_hello_trailing_data_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR}, server_close(with_trailing_byte(client_hello()))
    ).

client_hello_duplicate_extension_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        server_close(map_exts(fun([E | Rest]) -> [E, E | Rest] end, client_hello()))
    ).

client_hello_pre_shared_key_not_last_test() ->
    CH = client_hello(#{external_psk => {<<"id">>, <<"this-is-a-32-byte-test-secret!!!">>}}),
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        server_close(map_exts(fun(Exts) -> [lists:last(Exts) | lists:droplast(Exts)] end, CH))
    ).

server_hello_malformed_extension_test_() ->
    Malformed = [
        {server_hello(), fun(M) -> append_to_ext(?EXT_KEY_SHARE, <<0>>, M) end},
        {server_hello(), fun(M) -> add_ext(?EXT_PRE_SHARED_KEY, <<0, 0, 0>>, M) end},
        {server_hello(), fun(M) -> append_to_ext(?EXT_SUPPORTED_VERSIONS, <<0>>, M) end},
        {server_hello(), fun with_trailing_byte/1},
        {hello_retry_request(), fun(M) -> append_to_ext(?EXT_KEY_SHARE, <<0>>, M) end},
        {hello_retry_request(), fun(M) -> add_ext(?EXT_COOKIE, <<0:16>>, M) end},
        {hello_retry_request(), fun with_trailing_byte/1}
    ],
    [
        ?_assertEqual({tls_alert, ?TLS_ALERT_DECODE_ERROR}, client_close(F(Msg)))
     || {Msg, F} <- Malformed
    ].

encrypted_extensions_test() ->
    ?assertNotMatch({tls_alert, _}, in_handshake(client, awaiting_encrypted_extensions, ee(#{}))).

encrypted_extensions_malformed_test_() ->
    Malformed = [
        set_ext(?EXT_ALPN, <<6:16, 2, "h3", 2, "h2">>, ee(#{})),
        append_to_ext(?EXT_ALPN, <<0>>, ee(#{})),
        add_ext(?EXT_EARLY_DATA, <<0>>, ee(#{})),
        add_ext(?EXT_SERVER_NAME, <<0>>, ee(#{})),
        add_ext(?EXT_SUPPORTED_GROUPS, <<1:16, 0>>, ee(#{})),
        with_trailing_byte(ee(#{}))
    ],
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_DECODE_ERROR},
            in_handshake(client, awaiting_encrypted_extensions, Msg)
        )
     || Msg <- Malformed
    ].

certificate_malformed_test_() ->
    Cert = <<"not checked here">>,
    Entry = <<(byte_size(Cert)):24, Cert/binary>>,
    Malformed = [
        %% a byte after the certificate_list
        <<0, (byte_size(Entry) + 2):24, Entry/binary, 0:16, 0>>,
        %% an entry's extensions cut short
        <<0, (byte_size(Entry) + 3):24, Entry/binary, 1:16, 0>>,
        %% an empty cert_data
        <<0, 5:24, 0:24, 0:16>>,
        %% a list too short for an entry
        <<0, 2:24, 0:16>>
    ],
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_DECODE_ERROR},
            in_handshake(Role, TlsState, handshake_msg(?TLS_CERTIFICATE, Body))
        )
     || Body <- Malformed,
        {Role, TlsState} <- [{client, awaiting_certificate}, {server, awaiting_client_cert}]
    ].

certificate_verify_with_trailing_data_test_() ->
    Body = <<16#0403:16, 2:16, 0, 0, 0>>,
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_DECODE_ERROR},
            in_handshake(Role, TlsState, handshake_msg(?TLS_CERTIFICATE_VERIFY, Body))
        )
     || {Role, TlsState} <- [
            {client, awaiting_certificate_verify}, {server, awaiting_client_cert_verify}
        ]
    ].

certificate_request_test_() ->
    CR = quic_tls:build_certificate_request(<<>>),
    [
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_MISSING_EXTENSION},
            in_handshake(client, awaiting_certificate, without_ext(?EXT_SIGNATURE_ALGORITHMS, CR))
        ),
        ?_assertEqual(
            {tls_alert, ?TLS_ALERT_DECODE_ERROR},
            in_handshake(
                client, awaiting_certificate, append_to_ext(?EXT_SIGNATURE_ALGORITHMS, <<0>>, CR)
            )
        )
    ].

ee(Extra) ->
    quic_tls:build_encrypted_extensions(Extra#{alpn => <<"h3">>, transport_params => #{}}).

handshake_msg(Type, Body) ->
    <<Type, (byte_size(Body)):24, Body/binary>>.

with_trailing_byte(<<Type, Len:24, Body:Len/binary>>) ->
    <<Type, (Len + 1):24, Body/binary, 0>>.

with_suites(Suites) ->
    <<T, _:24, V:16, R:32/binary, SL, S:SL/binary, CL:16, _:CL/binary, Rest/binary>> =
        client_hello(),
    Body = <<V:16, R/binary, SL, S/binary, (byte_size(Suites)):16, Suites/binary, Rest/binary>>,
    <<T, (byte_size(Body)):24, Body/binary>>.

append_to_ext(Type, Extra, Msg) ->
    map_exts(
        fun(Exts) ->
            {Type, Data} = lists:keyfind(Type, 1, Exts),
            lists:keyreplace(Type, 1, Exts, {Type, <<Data/binary, Extra/binary>>})
        end,
        Msg
    ).

%%====================================================================
%% Messages
%%====================================================================

server_hello() ->
    server_hello(#{}).

server_hello(Extra) ->
    {Msg, _} = quic_tls:build_server_hello(Extra#{
        cipher_suite => ?TLS_AES_128_GCM_SHA256,
        key_pair => quic_crypto:generate_key_pair(x25519),
        key_share_group => x25519
    }),
    Msg.

hello_retry_request() ->
    quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, secp256r1).

client_hello() ->
    client_hello(#{}).

client_hello(Extra) ->
    {CH, _, _} = quic_tls:build_client_hello(maps:merge(client_hello_opts(), Extra)),
    CH.

client_hello_opts() ->
    #{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        groups => [x25519, secp256r1],
        ciphers => [aes_128_gcm],
        key_pair => key_pair()
    }.

key_pair() ->
    {<<9:256>>, <<1:256>>}.

first_client_hello() ->
    {CH1, _, _} = quic_tls:build_client_hello(client_hello_opts()),
    parsed_client_hello(CH1).

parsed_client_hello(<<?TLS_CLIENT_HELLO, Len:24, Body:Len/binary>>) ->
    {ok, CH} = quic_tls:parse_client_hello(Body),
    CH.

%% The ClientHello a client sent after a HelloRetryRequest: its
%% transcript is message_hash(CH1), the HRR, then that ClientHello.
retried_client_hello(#state{hs = #hs{tls_transcript = Transcript}}) ->
    <<254, 32:24, _:32/binary, ?TLS_SERVER_HELLO, Len:24, _:Len/binary, CH2/binary>> = Transcript,
    parsed_client_hello(CH2).

with_legacy_version(V, <<Type, Len:24, _:16, Rest/binary>>) ->
    <<Type, Len:24, V:16, Rest/binary>>.

with_compression(M, <<?TLS_CLIENT_HELLO, _:24, Body/binary>>) ->
    <<V:16, R:32/binary, SL, S:SL/binary, CL:16, C:CL/binary, ML, _:ML/binary, Exts/binary>> =
        Body,
    New = <<V:16, R/binary, SL, S/binary, CL:16, C/binary, (byte_size(M)), M/binary, Exts/binary>>,
    <<?TLS_CLIENT_HELLO, (byte_size(New)):24, New/binary>>.

with_server_compression(M, <<?TLS_SERVER_HELLO, Len:24, Body/binary>>) ->
    <<V:16, R:32/binary, SL, S:SL/binary, Suite:16, _, Exts/binary>> = Body,
    <<?TLS_SERVER_HELLO, Len:24, V:16, R/binary, SL, S/binary, Suite:16, M, Exts/binary>>.

add_ext(Type, Data, Msg) ->
    map_exts(fun(Exts) -> Exts ++ [{Type, Data}] end, Msg).

without_ext(Type, Msg) ->
    map_exts(fun(Exts) -> lists:keydelete(Type, 1, Exts) end, Msg).

set_ext(Type, Data, Msg) ->
    map_exts(fun(Exts) -> lists:keyreplace(Type, 1, Exts, {Type, Data}) end, Msg).

%% Msg with its extension list passed through F.
map_exts(F, <<Type, _Len:24, Body/binary>>) ->
    {Head, Exts} = split_exts(Type, Body),
    {ok, Ordered} = quic_tls:parse_extensions_ordered(Exts),
    NewExts = iolist_to_binary([
        <<T:16, (byte_size(D)):16, D/binary>>
     || {T, D} <- F([{T, D} || {T, D, _, _} <- Ordered])
    ]),
    NewBody = <<Head/binary, (byte_size(NewExts)):16, NewExts/binary>>,
    <<Type, (byte_size(NewBody)):24, NewBody/binary>>.

split_exts(
    ?TLS_CLIENT_HELLO,
    <<V:16, R:32/binary, SL, S:SL/binary, CL:16, C:CL/binary, ML, M:ML/binary, EL:16, E:EL/binary>>
) ->
    {<<V:16, R/binary, SL, S/binary, CL:16, C/binary, ML, M/binary>>, E};
split_exts(?TLS_ENCRYPTED_EXTENSIONS, <<EL:16, E:EL/binary>>) ->
    {<<>>, E};
split_exts(?TLS_CERTIFICATE_REQUEST, <<CL, C:CL/binary, EL:16, E:EL/binary>>) ->
    {<<CL, C/binary>>, E};
split_exts(
    ?TLS_SERVER_HELLO,
    <<V:16, R:32/binary, SL, S:SL/binary, Suite:16, M, EL:16, E:EL/binary>>
) ->
    {<<V:16, R/binary, SL, S/binary, Suite:16, M>>, E}.

%%====================================================================
%% Connections
%%====================================================================

%% How a client that sent client_hello/0 closes on Msg.
client_close(Msg) ->
    (client_after(Msg))#state.close_reason.

client_after(Msg) ->
    client_after(Msg, #{}).

%% A client whose ClientHello carried Extra, after Msg.
client_after(Msg, Extra) ->
    Opts = maps:merge(client_hello_opts(), Extra),
    {CH1, Priv, Random} = quic_tls:build_client_hello(Opts),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    Tickets =
        case maps:find(session_ticket, Extra) of
            {ok, T} -> quic_ticket:store_ticket(<<"localhost">>, T, quic_ticket:new_store());
            error -> quic_ticket:new_store()
        end,
    quic_connection:process_tls_messages(initial, Msg, S0#state{
        cfg = Cfg#conn_cfg{
            cipher_preference = [aes_128_gcm],
            tls_groups = [x25519, secp256r1],
            external_psk = maps:get(external_psk, Extra, undefined)
        },
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_server_hello,
            tls_group = x25519,
            tls_private_key = Priv,
            tls_transcript = CH1,
            tls_ch1_random = Random,
            tls_ch1_opts = Opts,
            server_name = <<"localhost">>,
            ticket_store = Tickets
        }
    }).

%% How a Role in TlsState, holding handshake keys, closes on the
%% Handshake-level Msg.
in_handshake(Role, TlsState, Msg) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(Role)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S = quic_connection:process_tls_messages(handshake, Msg, S0#state{
        last_activity = erlang:monotonic_time(millisecond),
        cfg = Cfg#conn_cfg{alpn_list = [<<"h3">>], verify = false, idle_timeout = 30000},
        hs = HS#hs{tls_state = TlsState, tls_transcript = <<>>, peer_cert = <<"cert">>}
    }),
    S#state.close_reason.

%% How a server waiting for a ClientHello closes on Msg.
server_close(Msg) ->
    (server_after(Msg, undefined))#state.close_reason.

%% A server issuing tickets into Tab, after Msg.
server_after(Msg, Tab) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    quic_connection:process_tls_messages(initial, Msg, S0#state{
        last_activity = erlang:monotonic_time(millisecond),
        cfg = Cfg#conn_cfg{
            cipher_preference = [aes_128_gcm],
            tls_groups = [x25519],
            alpn_list = [<<"h3">>],
            ticket_table = Tab,
            idle_timeout = 30000
        },
        hs = HS#hs{tls_state = awaiting_client_hello, tls_transcript = <<>>}
    }).
