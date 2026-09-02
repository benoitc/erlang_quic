%%% -*- erlang -*-
%%%
%%% Cipher suites on the wire. The `ciphers' option has to reach the
%%% ClientHello in the order given: a client that always offered the
%%% built-in list could not be restricted to one suite, and the order
%%% is what a server's preference selects against.

-module(quic_cipher_offer_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% The suites offered are the ones configured, in that order.
configured_ciphers_reach_the_hello_test() ->
    ?assertEqual(
        [?TLS_CHACHA20_POLY1305_SHA256, ?TLS_AES_128_GCM_SHA256],
        offered(#{ciphers => [chacha20_poly1305, aes_128_gcm]})
    ).

%% A single configured suite is the whole offer, which is what pins a
%% deployment to one cipher.
a_single_cipher_is_offered_alone_test() ->
    ?assertEqual([?TLS_AES_256_GCM_SHA384], offered(#{ciphers => [aes_256_gcm]})).

%% Without the option the built-in list is offered, so existing callers
%% see no change.
the_default_offer_is_unchanged_test() ->
    ?assertEqual(
        [
            ?TLS_AES_128_GCM_SHA256,
            ?TLS_AES_256_GCM_SHA384,
            ?TLS_CHACHA20_POLY1305_SHA256
        ],
        offered(#{})
    ).

%% Parse the cipher_suites vector back out of a built ClientHello.
offered(Opts) ->
    Base = #{server_name => <<"localhost">>, alpn => [<<"h3">>], transport_params => #{}},
    {Msg, _Priv, _Random} = quic_tls:build_client_hello(maps:merge(Base, Opts)),
    <<_MsgType:8, _Len:24, Body/binary>> = Msg,
    <<_Version:16, _CHRandom:32/binary, SessLen:8, Rest/binary>> = Body,
    <<_Sess:SessLen/binary, SuitesLen:16, Suites:SuitesLen/binary, _/binary>> = Rest,
    [Code || <<Code:16>> <= Suites].
