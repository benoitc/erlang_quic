%%% Fuzz harness for the in-NIF frame parser. Not part of the normal
%%% eunit run: intended to be driven under AddressSanitizer or valgrind,
%%% where the point is to crash the NIF, not to assert on output.
%%%
%%%   erlc -o ebin test/quic_nif_fuzz.erl
%%%   LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
%%%     erl -noshell -pa ebin -eval 'quic_nif_fuzz:run(200000), halt().'
-module(quic_nif_fuzz).

-export([run/1, run/2]).

-define(KEY, <<0:128>>).
-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).
-define(HP, <<16#aa:8, 0:120>>).
-define(DCID, <<9, 8, 7, 6>>).
-define(FB_BASE, 16#40).

run(N) ->
    run(N, 1).

run(N, Seed) ->
    case quic_crypto_nif:is_loaded() of
        false ->
            io:format("NIF not loaded, nothing to fuzz~n");
        true ->
            rand:seed(exsplus, {Seed, Seed * 7 + 1, Seed * 13 + 3}),
            {Parsed, Raw, Rejected} = loop(N, 0, 0, 0),
            io:format(
                "fuzzed ~b packets: parsed=~b raw=~b rejected=~b~n",
                [N, Parsed, Raw, Rejected]
            )
    end.

loop(0, P, R, X) ->
    {P, R, X};
loop(N, P, R, X) ->
    Plain = payload(),
    case protect(Plain) of
        {ok, Packet} ->
            case
                catch quic_aead_ctx:open_run(
                    aes_128_gcm, ?KEY, ?IV, ?HP, 0, 0, byte_size(?DCID), [Packet]
                )
            of
                {ok, [{_PN, _FB, {raw, _}}]} -> loop(N - 1, P, R + 1, X);
                {ok, [{_PN, _FB, L}]} when is_list(L) -> loop(N - 1, P + 1, R, X);
                _ -> loop(N - 1, P, R, X + 1)
            end;
        skip ->
            loop(N - 1, P, R, X + 1)
    end.

protect(Plain) ->
    case
        catch quic_aead_ctx:protect_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, 7, ?FB_BASE, ?DCID, [Plain]
        )
    of
        {ok, [Packet]} -> {ok, Packet};
        _ -> skip
    end.

%% A mix of shapes: pure noise, valid frames with corrupted tails,
%% truncations, and deeply nested length fields.
payload() ->
    Base =
        case rand:uniform(4) of
            1 -> noise(rand:uniform(1200));
            2 -> frames(rand:uniform(8));
            3 -> truncate(frames(rand:uniform(6)));
            4 -> corrupt(frames(rand:uniform(6)))
        end,
    %% keep protect_run happy (needs sampling room)
    <<0:(64 * 8), Base/binary>>.

noise(Len) ->
    list_to_binary([rand:uniform(256) - 1 || _ <- lists:seq(1, Len)]).

frames(N) ->
    iolist_to_binary([quic_frame:encode(frame()) || _ <- lists:seq(1, N)]).

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
