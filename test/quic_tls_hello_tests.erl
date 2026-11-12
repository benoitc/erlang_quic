%%% -*- erlang -*-
%%%
%%% A ClientHello, ServerHello or HelloRetryRequest that breaks a rule of
%%% RFC 9846 Sections 4.2 and 4.3 ends the handshake with the alert the
%%% RFC names for it.

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
