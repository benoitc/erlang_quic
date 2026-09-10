%%% -*- erlang -*-
%%%
%%% Cipher preference: AES hardware detection and the server's choice
%%% when a client asks for ChaCha20-Poly1305 first.
%%%

-module(quic_cipher_preference_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

x86_with_aes_test() ->
    Info = <<"processor\t: 0\nflags\t\t: fpu vme sse2 aes avx2 sha_ni\n">>,
    ?assert(quic_crypto:aes_accelerated(Info)).

x86_without_aes_test() ->
    Info = <<"processor\t: 0\nflags\t\t: fpu vme sse2 avx2\n">>,
    ?assertNot(quic_crypto:aes_accelerated(Info)).

arm64_with_aes_test() ->
    Info = <<"processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n">>,
    ?assert(quic_crypto:aes_accelerated(Info)).

arm64_without_aes_test() ->
    %% Raspberry Pi 4: Cortex-A72 without the crypto extension.
    Info = <<"processor\t: 0\nFeatures\t: fp asimd evtstrm crc32 cpuid\n">>,
    ?assertNot(quic_crypto:aes_accelerated(Info)).

aes_substring_is_not_a_flag_test() ->
    Info = <<"flags\t\t: vaes_lookalike aesni_no\n">>,
    ?assertNot(quic_crypto:aes_accelerated(Info)).

unknown_cpuinfo_counts_as_accelerated_test() ->
    ?assert(quic_crypto:aes_accelerated(<<"model name\t: Something\n">>)).

default_preference_follows_hardware_test() ->
    Pref = quic_crypto:default_cipher_preference(),
    ?assertEqual(lists:sort([aes_128_gcm, aes_256_gcm, chacha20_poly1305]), lists:sort(Pref)),
    case quic_crypto:aes_accelerated() of
        true -> ?assertEqual(aes_128_gcm, hd(Pref));
        false -> ?assertEqual(chacha20_poly1305, hd(Pref))
    end.

server_prefers_own_order_by_default_test() ->
    Client = [?TLS_AES_128_GCM_SHA256, ?TLS_CHACHA20_POLY1305_SHA256],
    Server = [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
    ?assertEqual(aes_128_gcm, quic_connection:select_cipher(Client, Server)).

server_honours_chacha_first_client_test() ->
    Client = [?TLS_CHACHA20_POLY1305_SHA256, ?TLS_AES_128_GCM_SHA256],
    Server = [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
    ?assertEqual(chacha20_poly1305, quic_connection:select_cipher(Client, Server)).

server_without_chacha_keeps_its_order_test() ->
    Client = [?TLS_CHACHA20_POLY1305_SHA256, ?TLS_AES_128_GCM_SHA256, ?TLS_AES_256_GCM_SHA384],
    Server = [aes_256_gcm, aes_128_gcm],
    ?assertEqual(aes_256_gcm, quic_connection:select_cipher(Client, Server)).

chacha_first_server_wins_over_aes_first_client_test() ->
    Client = [?TLS_AES_128_GCM_SHA256, ?TLS_CHACHA20_POLY1305_SHA256],
    Server = [chacha20_poly1305, aes_128_gcm, aes_256_gcm],
    ?assertEqual(chacha20_poly1305, quic_connection:select_cipher(Client, Server)).
