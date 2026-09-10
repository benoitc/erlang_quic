%%% Fuzz harness for the in-NIF frame parser. Not part of the normal
%%% eunit run: intended to be driven under AddressSanitizer or valgrind,
%%% where the point is to crash the NIF, not to assert on output.
%%%
%%%   erlc -o ebin test/quic_nif_fuzz.erl
%%%   LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
%%%     erl -noshell -pa ebin -eval 'quic_nif_fuzz:run(200000), halt().'
-module(quic_nif_fuzz).

-export([run/1, run/2, run/3]).

-define(KEY, <<0:128>>).
-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).
-define(HP, <<16#aa:8, 0:120>>).
-define(DCID, <<9, 8, 7, 6>>).
-define(FB_BASE, 16#40).

run(N) ->
    run(N, 1).

run(N, Seed) ->
    run(N, Seed, aes_128_gcm).

%% Cipher is a parameter because the fused paths take a different route
%% for ChaCha20-Poly1305: its header protection is a ChaCha20 keystream
%% rather than an ECB block, so fuzzing only AES leaves that C path
%% unexercised.
run(N, Seed, Cipher) ->
    case quic_crypto_nif:is_loaded() of
        false ->
            io:format("NIF not loaded, nothing to fuzz~n");
        true ->
            rand:seed(exsplus, {Seed, Seed * 7 + 1, Seed * 13 + 3}),
            {Parsed, Raw, Rejected} = loop(N, Cipher, 0, 0, 0),
            io:format(
                "fuzzed ~b packets (~s): parsed=~b raw=~b rejected=~b~n",
                [N, Cipher, Parsed, Raw, Rejected]
            ),
            %% Everything rejected means the cipher never reached the
            %% fused path, so nothing was fuzzed. Report it rather than
            %% let a caller read the run as coverage.
            case Parsed + Raw of
                0 -> {error, nothing_exercised};
                _ -> ok
            end
    end.

loop(0, _Cipher, P, R, X) ->
    {P, R, X};
loop(N, Cipher, P, R, X) ->
    Plain = payload(),
    case protect(Cipher, Plain) of
        {ok, Packet} ->
            case
                catch quic_aead_ctx:open_run(
                    Cipher, key(Cipher), ?IV, hp(Cipher), 0, 0, byte_size(?DCID), [Packet]
                )
            of
                {ok, [{_PN, _FB, {raw, _}}]} -> loop(N - 1, Cipher, P, R + 1, X);
                {ok, [{_PN, _FB, L}]} when is_list(L) -> loop(N - 1, Cipher, P + 1, R, X);
                _ -> loop(N - 1, Cipher, P, R, X + 1)
            end;
        skip ->
            loop(N - 1, Cipher, P, R, X + 1)
    end.

protect(Cipher, Plain) ->
    case
        catch quic_aead_ctx:protect_run(
            Cipher, key(Cipher), ?IV, hp(Cipher), 7, ?FB_BASE, ?DCID, [Plain]
        )
    of
        {ok, [Packet]} -> {ok, Packet};
        _ -> skip
    end.

key(aes_128_gcm) -> ?KEY;
key(aes_256_gcm) -> <<0:256>>;
key(chacha20_poly1305) -> <<0:256>>.

%% Header-protection key: 16 bytes for AES-128 ECB, 32 for AES-256 and
%% for the ChaCha20 keystream.
hp(aes_128_gcm) -> ?HP;
hp(aes_256_gcm) -> <<16#aa:8, 0:248>>;
hp(chacha20_poly1305) -> <<16#aa:8, 0:248>>.

%% A mix of shapes: pure noise, valid frames with corrupted tails,
%% truncations, and deeply nested length fields.
payload() ->
    Base =
        case rand:uniform(5) of
            1 -> noise(rand:uniform(1200));
            2 -> frames(rand:uniform(8));
            3 -> truncate(frames(rand:uniform(6)));
            4 -> corrupt(frames(rand:uniform(6)));
            5 -> many_frames(rand:uniform(96))
        end,
    %% keep protect_run happy (needs sampling room)
    <<0:(64 * 8), Base/binary>>.

noise(Len) ->
    list_to_binary([rand:uniform(256) - 1 || _ <- lists:seq(1, Len)]).

frames(N) ->
    iolist_to_binary([quic_frame:encode(frame()) || _ <- lists:seq(1, N)]).

%% Single-byte frames only, so the count crosses the parser's
%% PF_MAX_FRAMES cap (64) without the packet growing out of proportion.
%% The other shapes top out at 8 frames and never reach the array bound,
%% which left the one fixed-size buffer in the parser unexercised.
many_frames(N) ->
    iolist_to_binary([quic_frame:encode(small_frame()) || _ <- lists:seq(1, N)]).

small_frame() ->
    case rand:uniform(3) of
        1 -> ping;
        2 -> handshake_done;
        3 -> {max_data, rand:uniform(1000000)}
    end.

frame() ->
    case rand:uniform(9) of
        1 -> ping;
        2 -> {ack, [{rand:uniform(1000), rand:uniform(50)}], rand:uniform(100), undefined};
        3 -> {ack, [{rand:uniform(1000), rand:uniform(50)}], 1, {1, 2, 3}};
        4 -> {crypto, rand:uniform(100000), noise(rand:uniform(400))};
        5 -> {stream, rand:uniform(64), rand:uniform(100000), noise(rand:uniform(400)), false};
        6 -> {stream, rand:uniform(64), 0, noise(rand:uniform(200)), true};
        7 -> {max_data, rand:uniform(1000000)};
        8 -> {max_stream_data, rand:uniform(64), rand:uniform(1000000)};
        9 -> handshake_done
    end.

truncate(Bin) when byte_size(Bin) > 1 ->
    binary:part(Bin, 0, rand:uniform(byte_size(Bin)));
truncate(Bin) ->
    Bin.

corrupt(Bin) when byte_size(Bin) > 2 ->
    Pos = rand:uniform(byte_size(Bin)) - 1,
    <<A:Pos/binary, B, Rest/binary>> = Bin,
    <<A/binary, (B bxor (rand:uniform(255))), Rest/binary>>;
corrupt(Bin) ->
    Bin.
