%%% Differential tests for the in-NIF frame parser (open_run/8) against
%%% quic_frame:decode/1.
%%%
%%% The contract under test: the NIF may always decline a packet by
%%% returning {raw, Plaintext} (the Erlang decoder then owns it,
%%% including all error semantics), but whenever it does return a frame
%%% list, that list must equal what quic_frame:decode/1 produces, minus
%%% PADDING frames (which carry no semantics: neither ack-eliciting nor
%%% non-probing).
-module(quic_nif_frame_parse_tests).

-include_lib("eunit/include/eunit.hrl").

-define(KEY, <<0:128>>).
-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).
-define(HP, <<16#aa:8, 0:120>>).
-define(DCID, <<9, 8, 7, 6>>).
-define(FB_BASE, 16#40).
%% protect_run needs enough plaintext for header-protection sampling;
%% pad with leading PADDING frames so no trailing length-less STREAM
%% frame can swallow the padding.
-define(PAD, 64).

with_nif(Fun) ->
    case quic_crypto_nif:is_loaded() of
        true -> Fun();
        false -> ok
    end.

pad(Plain) ->
    <<0:(?PAD * 8), Plain/binary>>.

%% Decode the way decode_and_process_streaming/4 does, but surfacing
%% failures (including decoder crashes on truncated input) as errors.
erl_decode(Data) ->
    try
        erl_decode(Data, [])
    catch
        _:_ -> error
    end.

erl_decode(<<>>, Acc) ->
    lists:reverse(Acc);
erl_decode(Data, Acc) ->
    case quic_frame:decode(Data) of
        {error, _} -> error;
        {Frame, Rest} -> erl_decode(Rest, [Frame | Acc])
    end.

strip_padding(error) -> error;
strip_padding(Frames) -> [F || F <- Frames, F =/= padding].

%% Encrypt one packet carrying Plain and run it back through open_run.
open_one(Plain) ->
    {ok, [Packet]} = quic_aead_ctx:protect_run(
        aes_128_gcm, ?KEY, ?IV, ?HP, 7, ?FB_BASE, ?DCID, [Plain]
    ),
    {ok, [{_PN, _FB, Third}]} = quic_aead_ctx:open_run(
        aes_128_gcm, ?KEY, ?IV, ?HP, 6, 0, byte_size(?DCID), [Packet]
    ),
    Third.

%% Core invariant: parsed output equals the Erlang decoder's, and the
%% raw fallback preserves the plaintext exactly.
check(Plain0) ->
    Plain = pad(Plain0),
    case open_one(Plain) of
        {raw, Got} ->
            ?assertEqual(Plain, Got),
            raw;
        Parsed ->
            ?assertEqual(strip_padding(erl_decode(Plain)), Parsed),
            parsed
    end.

%% Frames the NIF is expected to parse itself.
fast_path_frames() ->
    [
        ping,
        {ack, [{100, 3}], 42, undefined},
        {ack, [{100, 3}, {2, 5}, {1, 1}], 7, undefined},
        {ack, [{500, 10}], 1, {1, 2, 3}},
        {crypto, 0, <<"hello crypto">>},
        {crypto, 1000, binary:copy(<<$c>>, 300)},
        {stream, 4, 0, <<"payload">>, false},
        {stream, 8, 1234, <<"more">>, true},
        {stream, 16383, 16384, binary:copy(<<$s>>, 500), false},
        {max_data, 1048576},
        {max_stream_data, 12, 65536},
        {max_streams, bidi, 100},
        {max_streams, uni, 3},
        handshake_done
    ].

%% Frames outside the fast path: must take the raw fallback.
fallback_frames() ->
    [
        {reset_stream, 4, 7, 100},
        {stop_sending, 8, 2},
        {new_token, <<"token">>},
        {data_blocked, 500},
        {stream_data_blocked, 4, 100},
        {streams_blocked, bidi, 7},
        {new_connection_id, 1, 0, <<1, 2, 3, 4, 5, 6, 7, 8>>, <<0:128>>},
        {retire_connection_id, 3},
        {path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>},
        {path_response, <<8, 7, 6, 5, 4, 3, 2, 1>>},
        {connection_close, transport, 0, 0, <<"bye">>}
    ].

enc(Frames) ->
    iolist_to_binary([quic_frame:encode(F) || F <- Frames]).

each_fast_path_frame_is_parsed_test() ->
    with_nif(fun() ->
        lists:foreach(
            fun(Frame) ->
                ?assertEqual({Frame, parsed}, {Frame, check(enc([Frame]))})
            end,
            fast_path_frames()
        )
    end).

mixed_fast_path_packet_is_parsed_test() ->
    with_nif(fun() ->
        ?assertEqual(parsed, check(enc(fast_path_frames())))
    end).

padding_between_frames_is_skipped_test() ->
    with_nif(fun() ->
        Frames = [{stream, 4, 0, <<"data">>, false}, ping],
        Plain = <<
            (quic_frame:encode(hd(Frames)))/binary,
            0:(100 * 8),
            (quic_frame:encode(lists:last(Frames)))/binary
        >>,
        ?assertEqual(parsed, check(Plain)),
        ?assertEqual(Frames, open_one(pad(Plain)))
    end).

padding_only_packet_falls_back_test() ->
    with_nif(fun() ->
        %% No frames at all: the Erlang decoder owns the
        %% PROTOCOL_VIOLATION for a frameless packet.
        ?assertEqual(raw, check(<<0:(200 * 8)>>))
    end).

unknown_frame_types_fall_back_test() ->
    with_nif(fun() ->
        lists:foreach(
            fun(Frame) ->
                ?assertEqual({Frame, raw}, {Frame, check(enc([Frame]))})
            end,
            fallback_frames()
        )
    end).

%% A fast-path frame followed by a fallback frame must not be split:
%% the whole packet takes the raw path.
partial_fast_path_falls_back_test() ->
    with_nif(fun() ->
        Plain = enc([{stream, 4, 0, <<"x">>, false}, {stop_sending, 8, 2}]),
        ?assertEqual(raw, check(Plain))
    end).

%% Truncated input must never yield a frame list that disagrees with
%% the Erlang decoder (check/1 asserts the invariant either way).
truncated_frames_test() ->
    with_nif(fun() ->
        Full = enc([{crypto, 1000, binary:copy(<<$c>>, 300)}]),
        lists:foreach(
            fun(Len) ->
                <<Prefix:Len/binary, _/binary>> = Full,
                check(Prefix)
            end,
            [1, 2, 3, 5, 8, 40, byte_size(Full) - 1]
        )
    end).

%% Randomised differential run over the fast-path forms.
random_mixes_match_erlang_test() ->
    with_nif(fun() ->
        All = fast_path_frames(),
        lists:foreach(
            fun(Seed) ->
                rand:seed(exsplus, {Seed, Seed * 7, Seed * 13}),
                N = rand:uniform(6),
                Frames = [lists:nth(rand:uniform(length(All)), All) || _ <- lists:seq(1, N)],
                ?assertEqual({Seed, parsed}, {Seed, check(enc(Frames))})
            end,
            lists:seq(1, 200)
        )
    end).

%% Random byte soup: the NIF must either decline or agree exactly.
random_garbage_never_disagrees_test() ->
    with_nif(fun() ->
        lists:foreach(
            fun(Seed) ->
                rand:seed(exsplus, {Seed, Seed * 3, Seed * 11}),
                Len = rand:uniform(120),
                Plain = list_to_binary([rand:uniform(256) - 1 || _ <- lists:seq(1, Len)]),
                check(Plain)
            end,
            lists:seq(1, 500)
        )
    end).
