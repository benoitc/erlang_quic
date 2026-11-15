%%% -*- erlang -*-
%%%
%%% What a peer certificate may be used for. When present, its Key Usage
%%% must allow signatures (RFC 9846 Section 4.5.1.2) and its Extended Key
%%% Usage the role it authenticates (RFC 5280 Section 4.2.1.12). A leaf
%%% listed among the trust anchors is taken as configured.

-module(quic_cert_usage_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(NAME, <<"localhost">>).
-define(CONNECT_TIMEOUT, 3000).

%%====================================================================
%% Server certificates
%%====================================================================

server_usage_test_() ->
    {Root, RootKey} = root(),
    Server = fun(Usage) ->
        {Leaf, _} = leaf(Usage, Root, RootKey),
        quic_cert:validate_server(Leaf, [], [Root], ?NAME)
    end,
    [
        {"no usage extension", ?_assertEqual(ok, Server(#{}))},
        {"digitalSignature", ?_assertEqual(ok, Server(#{ku => [digitalSignature]}))},
        {"serverAuth", ?_assertEqual(ok, Server(#{eku => [?'id-kp-serverAuth']}))},
        {"anyExtendedKeyUsage", ?_assertEqual(ok, Server(#{eku => [?'anyExtendedKeyUsage']}))},
        {"server and client auth",
            ?_assertEqual(ok, Server(#{eku => [?'id-kp-serverAuth', ?'id-kp-clientAuth']}))},
        {"keyEncipherment only",
            ?_assertEqual({error, {bad_cert, key_usage}}, Server(#{ku => [keyEncipherment]}))},
        {"code signing only",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, server_auth}}},
                Server(#{eku => [?'id-kp-codeSigning']})
            )},
        {"client auth only",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, server_auth}}},
                Server(#{eku => [?'id-kp-clientAuth']})
            )},
        {"a purpose of its own only",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, server_auth}}},
                Server(#{eku => [{1, 3, 6, 1, 4, 1, 99999, 1}]})
            )},
        {"signing allowed but the purpose wrong",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, server_auth}}},
                Server(#{ku => [digitalSignature], eku => [?'id-kp-codeSigning']})
            )}
    ].

%%====================================================================
%% Client certificates
%%====================================================================

client_usage_test_() ->
    {Root, RootKey} = root(),
    Client = fun(Usage) ->
        {Leaf, _} = leaf(Usage, Root, RootKey),
        quic_cert:validate_client(Leaf, [], [Root])
    end,
    [
        {"no usage extension", ?_assertEqual(ok, Client(#{}))},
        {"clientAuth", ?_assertEqual(ok, Client(#{eku => [?'id-kp-clientAuth']}))},
        {"anyExtendedKeyUsage", ?_assertEqual(ok, Client(#{eku => [?'anyExtendedKeyUsage']}))},
        {"keyEncipherment only",
            ?_assertEqual({error, {bad_cert, key_usage}}, Client(#{ku => [keyEncipherment]}))},
        {"server auth only",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, client_auth}}},
                Client(#{eku => [?'id-kp-serverAuth']})
            )},
        {"code signing only",
            ?_assertEqual(
                {error, {bad_cert, {extended_key_usage, client_auth}}},
                Client(#{eku => [?'id-kp-codeSigning']})
            )}
    ].

%%====================================================================
%% Both roles and pinned certificates
%%====================================================================

%% A certificate used both to accept and to connect, as a distribution
%% node uses its own, works both ways only when it allows both purposes.
both_roles_test_() ->
    {Root, RootKey} = root(),
    {Both, _} = leaf(#{eku => [?'id-kp-serverAuth', ?'id-kp-clientAuth']}, Root, RootKey),
    {ServerOnly, _} = leaf(#{eku => [?'id-kp-serverAuth']}, Root, RootKey),
    [
        ?_assertEqual(ok, quic_cert:validate_server(Both, [], [Root], ?NAME)),
        ?_assertEqual(ok, quic_cert:validate_client(Both, [], [Root])),
        ?_assertEqual(ok, quic_cert:validate_server(ServerOnly, [], [Root], ?NAME)),
        ?_assertEqual(
            {error, {bad_cert, {extended_key_usage, client_auth}}},
            quic_cert:validate_client(ServerOnly, [], [Root])
        )
    ].

%% A self-signed certificate listed in cacerts was trusted as it is, even
%% with key usage made for a CA and a purpose that is not TLS; a CA-issued
%% leaf with that purpose is refused.
pinned_leaf_is_taken_as_configured_test_() ->
    {Root, RootKey} = root(),
    {Pinned, _} = self_signed(#{ku => [keyCertSign, cRLSign], eku => [?'id-kp-codeSigning']}),
    {Issued, _} = leaf(#{eku => [?'id-kp-codeSigning']}, Root, RootKey),
    [
        ?_assertEqual(ok, quic_cert:validate_server(Pinned, [], [Pinned], ?NAME)),
        ?_assertEqual(ok, quic_cert:validate_client(Pinned, [], [Pinned])),
        ?_assertEqual(
            {error, {bad_cert, {extended_key_usage, server_auth}}},
            quic_cert:validate_server(Issued, [], [Root], ?NAME)
        )
    ].

%% The hostname is still checked on a pinned certificate.
pinned_leaf_still_checks_the_name_test() ->
    {Pinned, _} = self_signed(#{}),
    ?assertMatch(
        {error, {hostname_mismatch, _}},
        quic_cert:validate_server(Pinned, [], [Pinned], <<"other.example">>)
    ).

%%====================================================================
%% End to end
%%====================================================================

%% A client refuses a server whose certificate is for code signing.
client_refuses_a_code_signing_server_test_() ->
    {timeout, 30, fun() ->
        {ok, _} = application:ensure_all_started(quic),
        {Root, RootKey} = root(),
        Verify = #{verify => true, cacerts => [Root], server_name => ?NAME},
        {Good, GoodKey} = leaf(#{eku => [?'id-kp-serverAuth']}, Root, RootKey),
        {Bad, BadKey} = leaf(#{eku => [?'id-kp-codeSigning']}, Root, RootKey),
        ?assertEqual(connected, with_server(#{cert => Good, key => GoodKey}, Verify)),
        ?assertNotEqual(connected, with_server(#{cert => Bad, key => BadKey}, Verify))
    end}.

%% A server that requires a client certificate refuses one for servers.
server_refuses_a_server_only_client_certificate_test_() ->
    {timeout, 30, fun() ->
        {ok, _} = application:ensure_all_started(quic),
        {Root, RootKey} = root(),
        {ServerCert, ServerKey} = leaf(#{}, Root, RootKey),
        ServerOpts = #{
            cert => ServerCert, key => ServerKey, require_client_cert => true, cacerts => [Root]
        },
        {Good, GoodKey} = leaf(#{eku => [?'id-kp-clientAuth']}, Root, RootKey),
        {Bad, BadKey} = leaf(#{eku => [?'id-kp-serverAuth']}, Root, RootKey),
        Client = fun(Cert, Key) ->
            #{verify => false, cert => Cert, key => Key}
        end,
        ?assertEqual(connected, with_server(ServerOpts, Client(Good, GoodKey))),
        ?assertNotEqual(connected, with_server(ServerOpts, Client(Bad, BadKey)))
    end}.

with_server(ServerOpts, ClientOpts) ->
    {ok, #{port := Port} = Server} = quic_test_echo_server:start(ServerOpts),
    try
        connect(Port, ClientOpts)
    after
        quic_test_echo_server:stop(Server)
    end.

%% One owner per attempt, so a late event from one attempt never reaches
%% the next.
connect(Port, Opts) ->
    Parent = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts#{alpn => [<<"echo">>]}, self()),
        Result =
            receive
                {quic, _, {connected, _}} -> still_connected();
                {quic, _, {closed, Reason}} -> {closed, Reason};
                {quic, _, {error, Reason}} -> {error, Reason}
            after ?CONNECT_TIMEOUT -> timeout
            end,
        quic:safe_close(Conn),
        Parent ! {result, self(), Result}
    end),
    receive
        {result, Pid, Result} ->
            erlang:demonitor(MRef, [flush]),
            Result;
        {'DOWN', MRef, process, Pid, Reason} ->
            {crashed, Reason}
    after ?CONNECT_TIMEOUT + 3000 ->
        erlang:demonitor(MRef, [flush]),
        exit(Pid, kill),
        timeout
    end.

%% A client is connected once it sends its Finished, before the server
%% has checked its certificate: a refusal closes the connection right
%% after.
still_connected() ->
    receive
        {quic, _, {closed, Reason}} -> {closed, Reason}
    after 1000 -> connected
    end.

%%====================================================================
%% Certificates
%%====================================================================

root() ->
    Key = key(),
    {mint(<<"Usage Root">>, <<"Usage Root">>, Key, Key, ca_extensions()), Key}.

%% A leaf for localhost signed by Root, with the usage extensions given.
leaf(Usage, Root, RootKey) ->
    Key = key(),
    Issuer = subject_cn(Root),
    {mint(?NAME, Issuer, Key, RootKey, leaf_extensions(Usage)), Key}.

self_signed(Usage) ->
    Key = key(),
    {mint(?NAME, ?NAME, Key, Key, leaf_extensions(Usage)), Key}.

key() ->
    public_key:generate_key({rsa, 2048, 65537}).

mint(Subject, Issuer, Key, SignKey, Extensions) ->
    #'RSAPrivateKey'{modulus = M, publicExponent = E} = Key,
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = erlang:unique_integer([positive, monotonic]) + 1,
        signature = #'SignatureAlgorithm'{algorithm = ?'sha256WithRSAEncryption'},
        issuer = name(Issuer),
        validity = #'Validity'{
            notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "350101000000Z"}
        },
        subject = name(Subject),
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{algorithm = ?'rsaEncryption', parameters = 'NULL'},
            subjectPublicKey = #'RSAPublicKey'{modulus = M, publicExponent = E}
        },
        extensions = Extensions
    },
    public_key:pkix_sign(TBS, SignKey).

name(CN) ->
    {rdnSequence, [
        [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, CN}}]
    ]}.

subject_cn(Der) ->
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{subject = {rdnSequence, RDNs}}} =
        public_key:pkix_decode_cert(Der, otp),
    [CN] = [
        V
     || [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, V}}] <- RDNs
    ],
    CN.

ca_extensions() ->
    [
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
    ].

leaf_extensions(Usage) ->
    [
        #'Extension'{
            extnID = ?'id-ce-subjectAltName',
            critical = false,
            extnValue = [{dNSName, binary_to_list(?NAME)}]
        }
    ] ++
        [
            #'Extension'{extnID = ?'id-ce-keyUsage', critical = true, extnValue = KU}
         || KU <- [maps:get(ku, Usage, none)], KU =/= none
        ] ++
        [
            #'Extension'{extnID = ?'id-ce-extKeyUsage', critical = false, extnValue = EKU}
         || EKU <- [maps:get(eku, Usage, none)], EKU =/= none
        ].
