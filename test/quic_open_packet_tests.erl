%% open_packet/8 fuses header unprotection, packet-number reconstruction
%% and AEAD open for one short-header packet. It must open what
%% protect_run sealed, byte for byte, across packet-number length
%% boundaries, hand a key-phase mismatch back to the generic path
%% untouched, and reject a corrupted tag.
-module(quic_open_packet_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID, <<9, 8, 7, 6>>).
-define(BASE, 16#40).

keys() ->
    {crypto:strong_rand_bytes(16), crypto:strong_rand_bytes(12), crypto:strong_rand_bytes(16)}.

%% Split a wire packet into the header the receiver has parsed (first
%% byte + DCID) and the rest, as decrypt_app_packet sees it.
split(Packet) ->
    HLen = 1 + byte_size(?DCID),
    <<Header:HLen/binary, Rest/binary>> = Packet,
    {Header, Rest}.

roundtrip(PN0, K) ->
    {Key, IV, HP} = keys(),
    Payloads = [crypto:strong_rand_bytes(60 + I) || I <- lists:seq(1, K)],
    case quic_aead_ctx:protect_run(aes_128_gcm, Key, IV, HP, PN0, ?BASE, ?DCID, Payloads) of
        fallback ->
            ok;
        {ok, Packets} ->
            lists:foldl(
                fun({Packet, Payload}, Largest) ->
                    {Header, Rest} = split(Packet),
                    {ok, PN, FirstByte, Plain} =
                        quic_aead_ctx:open_packet(
                            aes_128_gcm, Key, IV, HP, Largest, 0, Header, Rest
                        ),
                    ?assertEqual(Payload, Plain),
                    %% Fixed bit set, key phase 0, PN length as encoded.
                    ?assertEqual(?BASE bor (quic_packet:pn_length(PN) - 1), FirstByte),
                    PN
                end,
                undefined,
                lists:zip(Packets, Payloads)
            ),
            ok
    end.

roundtrip_test_() ->
    [
        {lists:flatten(io_lib:format("pn0=~p k=~p", [PN0, K])), fun() -> roundtrip(PN0, K) end}
     || {PN0, K} <- [{0, 6}, {250, 10}, {65530, 10}, {16777210, 10}]
    ].

%% The receiver tracks largest_recv as packets arrive; a packet whose
%% PN is reconstructed against a stale (lower) largest still decodes
%% while within the window.
reconstruction_with_stale_largest_test() ->
    {Key, IV, HP} = keys(),
    case quic_aead_ctx:protect_run(aes_128_gcm, Key, IV, HP, 300, ?BASE, ?DCID, [<<0:(80 * 8)>>]) of
        fallback ->
            ok;
        {ok, [Packet]} ->
            {Header, Rest} = split(Packet),
            ?assertMatch(
                {ok, 300, _, _},
                quic_aead_ctx:open_packet(aes_128_gcm, Key, IV, HP, 250, 0, Header, Rest)
            )
    end.

key_phase_mismatch_is_fallback_test() ->
    {Key, IV, HP} = keys(),
    case quic_aead_ctx:protect_run(aes_128_gcm, Key, IV, HP, 5, ?BASE, ?DCID, [<<1:(80 * 8)>>]) of
        fallback ->
            ok;
        {ok, [Packet]} ->
            {Header, Rest} = split(Packet),
            %% Sealed with phase 0; the receiver expects phase 1.
            ?assertEqual(
                fallback, quic_aead_ctx:open_packet(aes_128_gcm, Key, IV, HP, 4, 1, Header, Rest)
            )
    end.

corrupted_tag_is_an_error_test() ->
    {Key, IV, HP} = keys(),
    case quic_aead_ctx:protect_run(aes_128_gcm, Key, IV, HP, 5, ?BASE, ?DCID, [<<2:(80 * 8)>>]) of
        fallback ->
            ok;
        {ok, [Packet]} ->
            {Header, Rest0} = split(Packet),
            Sz = byte_size(Rest0),
            <<Keep:(Sz - 1)/binary, Last>> = Rest0,
            Rest = <<Keep/binary, (Last bxor 16#ff)>>,
            ?assertEqual(
                error, quic_aead_ctx:open_packet(aes_128_gcm, Key, IV, HP, 4, 0, Header, Rest)
            )
    end.

chacha_is_fallback_test() ->
    ?assertEqual(
        fallback,
        quic_aead_ctx:open_packet(
            chacha20_poly1305,
            crypto:strong_rand_bytes(32),
            crypto:strong_rand_bytes(12),
            crypto:strong_rand_bytes(32),
            undefined,
            0,
            <<16#40, 1, 2, 3, 4>>,
            <<0:(64 * 8)>>
        )
    ).
