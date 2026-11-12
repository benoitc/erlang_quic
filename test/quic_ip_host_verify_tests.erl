%%% -*- erlang -*-
%%%
%%% A client that dials an IP address checks that address against the
%%% server certificate's iPAddress subjectAltName entries (RFC 9525
%%% Section 6.4) and does not send it as SNI (RFC 6066 Section 3).

-module(quic_ip_host_verify_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(TIMEOUT, 5000).
-define(LOOPBACK_IP_SAN, {iPAddress, [127, 0, 0, 1]}).
-define(LOOPBACK6, {0, 0, 0, 0, 0, 0, 0, 1}).
-define(LOOPBACK6_IP_SAN, {iPAddress, lists:duplicate(15, 0) ++ [1]}).
-define(BRACKETED, [<<"[::1]">>, "[::1]"]).
-define(DNS_SANS, [{dNSName, "[::1]"}, {dNSName, "::1"}]).
-define(MISMATCH6, {error, {certificate_invalid, {hostname_mismatch, <<"::1">>}}}).

%%====================================================================
%% Address host, verify on
%%====================================================================

ip_tuple_host_without_ip_san_refused_test() ->
    with_server([{dNSName, "localhost"}], fun(Port, Ca, _Sni) ->
        ?assertEqual(
            {error, {certificate_invalid, {hostname_mismatch, <<"127.0.0.1">>}}},
            connect({127, 0, 0, 1}, Port, verify_opts(Ca))
        )
    end).

ip_string_host_without_ip_san_refused_test() ->
    with_server([{dNSName, "localhost"}], fun(Port, Ca, _Sni) ->
        ?assertEqual(
            {error, {certificate_invalid, {hostname_mismatch, <<"127.0.0.1">>}}},
            connect("127.0.0.1", Port, verify_opts(Ca))
        )
    end).

ip_host_other_ip_san_refused_test() ->
    with_server([{iPAddress, [127, 0, 0, 2]}], fun(Port, Ca, _Sni) ->
        ?assertEqual(
            {error, {certificate_invalid, {hostname_mismatch, <<"127.0.0.1">>}}},
            connect(<<"127.0.0.1">>, Port, verify_opts(Ca))
        )
    end).

ip_tuple_host_with_ip_san_accepted_test() ->
    with_server([?LOOPBACK_IP_SAN], fun(Port, Ca, Sni) ->
        ?assertEqual(connected, connect({127, 0, 0, 1}, Port, verify_opts(Ca))),
        ?assertEqual(undefined, Sni())
    end).

ip_string_host_with_ip_san_accepted_test() ->
    with_server([?LOOPBACK_IP_SAN], fun(Port, Ca, Sni) ->
        ?assertEqual(connected, connect("127.0.0.1", Port, verify_opts(Ca))),
        ?assertEqual(undefined, Sni())
    end).

%%====================================================================
%% server_name set by the caller
%%====================================================================

%% An address given as server_name is checked the same way and kept
%% out of SNI.
ip_server_name_not_sent_as_sni_test() ->
    with_server([?LOOPBACK_IP_SAN], fun(Port, Ca, Sni) ->
        Opts = (verify_opts(Ca))#{server_name => <<"127.0.0.1">>},
        ?assertEqual(connected, connect({127, 0, 0, 1}, Port, Opts)),
        ?assertEqual(undefined, Sni())
    end).

hostname_server_name_on_ip_host_unchanged_test() ->
    with_server([{dNSName, "localhost"}], fun(Port, Ca, Sni) ->
        Opts = (verify_opts(Ca))#{server_name => <<"localhost">>},
        ?assertEqual(connected, connect({127, 0, 0, 1}, Port, Opts)),
        ?assertEqual(<<"localhost">>, Sni())
    end).

%%====================================================================
%% Hostname host and verify off: unchanged
%%====================================================================

resolved_hostname_unchanged_test() ->
    with_server([{dNSName, "localhost"}], fun(Port, Ca, Sni) ->
        Opts = (verify_opts(Ca))#{family => inet, happy_eyeballs => false},
        ?assertEqual(connected, connect("localhost", Port, Opts)),
        ?assertEqual(<<"localhost">>, Sni())
    end).

resolved_hostname_mismatch_unchanged_test() ->
    with_server([?LOOPBACK_IP_SAN], fun(Port, Ca, _Sni) ->
        Opts = (verify_opts(Ca))#{family => inet, happy_eyeballs => false},
        ?assertEqual(
            {error, {certificate_invalid, {hostname_mismatch, <<"localhost">>}}},
            connect("localhost", Port, Opts)
        )
    end).

ip_host_verify_off_unchanged_test() ->
    with_server([{dNSName, "localhost"}], fun(Port, _Ca, Sni) ->
        ?assertEqual(
            connected,
            connect({127, 0, 0, 1}, Port, #{alpn => [<<"h3">>], verify => false})
        ),
        ?assertEqual(undefined, Sni())
    end).

%%====================================================================
%% IPv6 addresses and the ClientHello
%%====================================================================

ipv6_host_is_the_checked_name_test_() ->
    Ca = ca(),
    Loopback6 = {0, 0, 0, 0, 0, 0, 0, 1},
    Name = quic_connection:client_server_name(Loopback6, #{}),
    WithIp = leaf(Ca, [{iPAddress, lists:duplicate(15, 0) ++ [1]}]),
    WithDns = leaf(Ca, [{dNSName, "localhost"}]),
    [
        ?_assertEqual(<<"::1">>, Name),
        ?_assertEqual(ok, validate(Ca, WithIp, Name)),
        ?_assertEqual({error, {hostname_mismatch, <<"::1">>}}, validate(Ca, WithDns, Name)),
        ?_assertEqual({literal, Loopback6}, quic_happy:parse_host("::1")),
        ?_assertEqual({literal, Loopback6}, quic_happy:parse_host("[::1]"))
    ].

client_hello_sni_test_() ->
    [
        ?_assertEqual(undefined, hello_sni(<<"127.0.0.1">>)),
        ?_assertEqual(undefined, hello_sni(<<"::1">>)),
        ?_assertEqual(<<"example.com">>, hello_sni(<<"example.com">>))
    ].

%%====================================================================
%% Bracketed IPv6 literal, as host or as server_name
%%====================================================================

%% `[::1]' names the address ::1: it is checked against iPAddress
%% entries only, so a DNS entry spelling it does not match.
bracketed_server_name_dns_san_refused_test_() ->
    {timeout, 60, [
        ?_test(
            with_server6([San], fun(Port, Ca, _Sni) ->
                Opts = (verify_opts(Ca))#{server_name => SN},
                ?assertEqual(?MISMATCH6, connect(?LOOPBACK6, Port, Opts))
            end)
        )
     || San <- ?DNS_SANS, SN <- ?BRACKETED
    ]}.

bracketed_server_name_ip_san_accepted_test_() ->
    {timeout, 60, [
        ?_test(
            with_server6([?LOOPBACK6_IP_SAN], fun(Port, Ca, Sni) ->
                Opts = (verify_opts(Ca))#{server_name => SN},
                ?assertEqual(connected, connect(?LOOPBACK6, Port, Opts)),
                ?assertEqual(undefined, Sni())
            end)
        )
     || SN <- ?BRACKETED
    ]}.

bracketed_host_dns_san_refused_test_() ->
    {timeout, 60, [
        ?_test(
            with_server6([San], fun(Port, Ca, _Sni) ->
                ?assertEqual(?MISMATCH6, Dial(Host, Port, verify_opts(Ca)))
            end)
        )
     || San <- ?DNS_SANS, Host <- ?BRACKETED, Dial <- dialers()
    ]}.

bracketed_host_ip_san_accepted_test_() ->
    {timeout, 60, [
        ?_test(
            with_server6([?LOOPBACK6_IP_SAN], fun(Port, Ca, Sni) ->
                ?assertEqual(connected, Dial(Host, Port, verify_opts(Ca))),
                ?assertEqual(undefined, Sni())
            end)
        )
     || Host <- ?BRACKETED, Dial <- dialers()
    ]}.

%% A zone ID is not part of the address the certificate names.
zoned_host_ip_san_accepted_test_() ->
    {timeout, 60, [
        ?_test(
            with_server6([?LOOPBACK6_IP_SAN], fun(Port, Ca, Sni) ->
                ?assertEqual(connected, connect(Host, Port, verify_opts(Ca))),
                ?assertEqual(undefined, Sni())
            end)
        )
     || Host <- [<<"[::1%lo0]">>, "::1%lo0"]
    ]}.

%% quic_h3 sets server_name to the host it is given.
h3_bracketed_host_dns_san_refused_test_() ->
    {timeout, 30, [
        ?_test(
            with_h3_server6([San], fun(Port, Ca, _Sni) ->
                ?assertEqual(?MISMATCH6, h3_connect(Port, Ca))
            end)
        )
     || San <- ?DNS_SANS
    ]}.

h3_bracketed_host_ip_san_accepted_test_() ->
    {timeout, 30, fun() ->
        with_h3_server6([?LOOPBACK6_IP_SAN], fun(Port, Ca, Sni) ->
            ?assertEqual(connected, h3_connect(Port, Ca)),
            ?assertEqual(undefined, Sni())
        end)
    end}.

address_literal_forms_test_() ->
    [
        ?_assertEqual({ok, ?LOOPBACK6}, quic_cert:host_address(H))
     || H <- [<<"::1">>, "::1", <<"[::1]">>, "[::1]", <<"[::1%lo0]">>, "::1%2", <<"[::1%25eth0]">>]
    ] ++
        [
            ?_assertEqual(
                {ok, {65152, 0, 0, 0, 0, 0, 0, 1}}, quic_cert:host_address(<<"[fe80::1%en0]">>)
            ),
            ?_assertEqual({ok, {127, 0, 0, 1}}, quic_cert:host_address(<<"127.0.0.1">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"[::1">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"::1]">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"[::1%]">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"[localhost]">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"example.com">>)),
            ?_assertEqual(error, quic_cert:host_address(<<"127.0.0.1%lo0">>))
        ].

bracketed_name_is_the_address_test_() ->
    Ca = ca(),
    WithIp = leaf(Ca, [?LOOPBACK6_IP_SAN]),
    [
        ?_assertEqual(<<"::1">>, quic_connection:client_server_name(<<"[::1]">>, #{})),
        ?_assertEqual(<<"::1">>, quic_connection:client_server_name("[::1%lo0]", #{})),
        ?_assertEqual(
            <<"::1">>, quic_connection:client_server_name(?LOOPBACK6, #{server_name => "[::1]"})
        ),
        ?_assertEqual(ok, validate(Ca, WithIp, <<"[::1]">>)),
        ?_assertEqual(
            {error, {hostname_mismatch, <<"[::1]">>}},
            validate(Ca, leaf(Ca, [{dNSName, "[::1]"}]), <<"[::1]">>)
        ),
        ?_assertEqual(undefined, hello_sni(<<"[::1]">>)),
        ?_assertEqual(undefined, hello_sni(<<"[fe80::1%en0]">>)),
        ?_assertEqual({literal, ?LOOPBACK6}, quic_happy:parse_host("[::1%lo0]")),
        ?_assertEqual({name, "localhost"}, quic_happy:parse_host("[localhost]"))
    ].

%%====================================================================
%% Helpers
%%====================================================================

%% quic:connect/4, and a connection process started with the host as
%% given, as quic_h3 and quic_dist reach it.
dialers() ->
    [fun connect/3, fun connect_direct/3].

connect_direct(Host, Port, Opts) ->
    {ok, Pid} = quic_connection:start_link(Host, Port, Opts, self()),
    await(Pid, Pid).

h3_connect(Port, #{der := CaDer}) ->
    case
        quic_h3:connect(<<"[::1]">>, Port, #{
            sync => true, connect_timeout => ?TIMEOUT, verify => true, cacerts => [CaDer]
        })
    of
        {ok, Conn} ->
            ok = quic_h3:close(Conn),
            connected;
        {error, _} = Error ->
            Error
    end.

hello_sni(ServerName) ->
    {Msg, _, _} = quic_tls:build_client_hello(#{
        server_name => ServerName, alpn => [<<"h3">>], transport_params => #{}
    }),
    <<1, _Len:24, Body/binary>> = Msg,
    {ok, Info} = quic_tls:parse_client_hello(Body),
    maps:get(server_name, Info, undefined).

verify_opts(#{der := CaDer}) ->
    #{alpn => [<<"h3">>], verify => true, cacerts => [CaDer]}.

%% Start a server presenting a leaf with `San', run F with its port, the
%% CA and a fun returning the SNI the server saw on the last handshake.
with_server(San, F) ->
    with_server(San, #{}, F).

with_server6(San, F) ->
    with_server(San, #{extra_socket_opts => [{ip, ?LOOPBACK6}]}, F).

with_server(San, Extra, F) ->
    with_server(San, Extra, fun quic:start_server/3, F).

with_h3_server6(San, F) ->
    Start = fun(Name, Port, Opts) ->
        quic_h3:start_server(Name, Port, #{
            cert => maps:get(cert, Opts), key => maps:get(key, Opts), quic_opts => Opts
        })
    end,
    with_server(San, #{extra_socket_opts => [{ip, ?LOOPBACK6}]}, Start, F).

with_server(San, Extra, Start, F) ->
    {ok, _} = application:ensure_all_started(quic),
    Ca = ca(),
    {Leaf, Key} = leaf_and_key(Ca, San),
    Self = self(),
    Tag = make_ref(),
    SniCb = fun(Sni) ->
        Self ! {Tag, Sni},
        {ok, #{cert => Leaf, key => Key}}
    end,
    Name = list_to_atom("quic_ip_host_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Opts = Extra#{alpn => [<<"h3">>], sni_callback => SniCb, cert => Leaf, key => Key},
    {ok, _} = Start(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    Sni = fun() ->
        receive
            {Tag, S} -> S
        after ?TIMEOUT -> error(no_client_hello)
        end
    end,
    try
        F(Port, Ca, Sni)
    after
        quic:stop_server(Name)
    end.

connect(Host, Port, Opts) ->
    {ok, Conn} = quic:connect(Host, Port, Opts, self()),
    await(Conn, Conn).

await(Conn, Close) ->
    Result =
        receive
            {quic, Conn, {connected, _}} -> connected;
            {quic, Conn, {error, Reason}} -> {error, Reason};
            {quic, Conn, {closed, Reason}} -> {closed, Reason}
        after ?TIMEOUT -> timeout
        end,
    _ = quic:safe_close(Close),
    Result.

validate(#{der := CaDer}, Leaf, Name) ->
    quic_cert:validate_server(Leaf, [], [CaDer], Name).

ca() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Exts = [
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = true}
        },
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [keyCertSign, cRLSign, digitalSignature]
        }
    ],
    #{key => Key, der => mint("IP Host Test CA", "IP Host Test CA", Key, Key, Exts)}.

leaf(Ca, San) ->
    {Der, _Key} = leaf_and_key(Ca, San),
    Der.

leaf_and_key(#{key := CaKey}, San) ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Exts = [
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = false}
        },
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [digitalSignature]
        },
        #'Extension'{extnID = ?'id-ce-subjectAltName', critical = false, extnValue = San}
    ],
    {mint("server", "IP Host Test CA", Key, CaKey, Exts), Key}.

mint(Subject, Issuer, #'ECPrivateKey'{publicKey = Pub, parameters = Params}, SignKey, Exts) ->
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = erlang:unique_integer([positive, monotonic]),
        signature = #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'},
        issuer = name(Issuer),
        validity = #'Validity'{
            notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "350101000000Z"}
        },
        subject = name(Subject),
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
            subjectPublicKey = #'ECPoint'{point = Pub}
        },
        extensions = Exts
    },
    public_key:pkix_sign(TBS, SignKey).

name(CN) ->
    {rdnSequence, [
        [
            #'AttributeTypeAndValue'{
                type = ?'id-at-commonName', value = {utf8String, list_to_binary(CN)}
            }
        ]
    ]}.
