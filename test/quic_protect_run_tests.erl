%% protect_run/8 seals a run of short-header packets in one NIF call.
%% Its output must be byte-identical to sealing each packet with
%% quic_aead:protect_short_packet/8, across ciphers and across the
%% packet-number length boundaries inside a run; ChaCha and a missing
%% NIF report `fallback' so the caller takes the per-packet path.
-module(quic_protect_run_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID, <<1, 2, 3, 4, 5, 6, 7, 8>>).
%% Short header base: fixed bit set, key phase 0, PN-length bits clear.
-define(FIRST_BYTE_BASE, 16#40).

keys(aes_128_gcm) ->
    {crypto:strong_rand_bytes(16), crypto:strong_rand_bytes(12), crypto:strong_rand_bytes(16)};
keys(aes_256_gcm) ->
    {crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(12), crypto:strong_rand_bytes(32)};
keys(chacha20_poly1305) ->
    {crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(12), crypto:strong_rand_bytes(32)}.

payloads(K) ->
    [crypto:strong_rand_bytes(100 + I) || I <- lists:seq(1, K)].

reference(Cipher, Key, IV, HP, PN0, Payloads) ->
    {Ps, _} = lists:mapfoldl(
        fun(Payload, PN) ->
            FirstByte = ?FIRST_BYTE_BASE bor (quic_packet:pn_length(PN) - 1),
            {
                quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, FirstByte, ?DCID, Payload),
                PN + 1
            }
        end,
        PN0,
        Payloads
    ),
    Ps.

run_matches_reference(Cipher, PN0, K) ->
    {Key, IV, HP} = keys(Cipher),
    Payloads = payloads(K),
    case quic_aead_ctx:protect_run(Cipher, Key, IV, HP, PN0, ?FIRST_BYTE_BASE, ?DCID, Payloads) of
        {ok, Packets} ->
            ?assertEqual(reference(Cipher, Key, IV, HP, PN0, Payloads), Packets);
        fallback ->
            %% No NIF on this host (or disabled): nothing to compare, the
            %% caller seals per packet with the reference itself.
            ok
    end.

aes_128_run_test_() ->
    [
        {lists:flatten(io_lib:format("aes128 pn0=~p k=~p", [PN0, K])), fun() ->
            run_matches_reference(aes_128_gcm, PN0, K)
        end}
     || {PN0, K} <- [{0, 8}, {250, 12}, {65530, 12}, {16777210, 12}, {4294967290, 12}, {7, 1}]
    ].

aes_256_run_test() ->
    run_matches_reference(aes_256_gcm, 65530, 16).

chacha_is_fallback_test() ->
    {Key, IV, HP} = keys(chacha20_poly1305),
    ?assertEqual(
        fallback,
        quic_aead_ctx:protect_run(
            chacha20_poly1305, Key, IV, HP, 0, ?FIRST_BYTE_BASE, ?DCID, payloads(3)
        )
    ).

empty_run_test() ->
    {Key, IV, HP} = keys(aes_128_gcm),
    case quic_aead_ctx:protect_run(aes_128_gcm, Key, IV, HP, 0, ?FIRST_BYTE_BASE, ?DCID, []) of
        {ok, []} -> ok;
        fallback -> ok
    end.
