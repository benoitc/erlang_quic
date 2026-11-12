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
%% Helpers
%%====================================================================

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
    {ok, _} = quic:start_server(Name, 0, #{alpn => [<<"h3">>], sni_callback => SniCb}),
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
    Result =
        receive
            {quic, Conn, {connected, _}} -> connected;
            {quic, Conn, {error, Reason}} -> {error, Reason};
            {quic, Conn, {closed, Reason}} -> {closed, Reason}
        after ?TIMEOUT -> timeout
        end,
    _ = quic:safe_close(Conn),
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
