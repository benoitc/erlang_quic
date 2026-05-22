%%% -*- erlang -*-
%%%
%%% Unit tests for quic_connection:chunk_crypto/3, the pure splitter
%%% that segments a handshake CRYPTO payload into sized, contiguous
%%% pieces (issue #134).

-module(quic_crypto_chunk_tests).

-include_lib("eunit/include/eunit.hrl").

empty_payload_test() ->
    ?assertEqual([], quic_connection:chunk_crypto(<<>>, 0, 1144)).

fits_in_one_chunk_test() ->
    Payload = <<"short handshake">>,
    ?assertEqual(
        [{0, Payload}],
        quic_connection:chunk_crypto(Payload, 0, 1144)
    ).

exact_multiple_test() ->
    %% 6 bytes, Max 2 -> three 2-byte chunks at 0, 2, 4.
    ?assertEqual(
        [{0, <<"ab">>}, {2, <<"cd">>}, {4, <<"ef">>}],
        quic_connection:chunk_crypto(<<"abcdef">>, 0, 2)
    ).

remainder_chunk_test() ->
    %% 7 bytes, Max 3 -> 3,3,1.
    ?assertEqual(
        [{0, <<"abc">>}, {3, <<"def">>}, {6, <<"g">>}],
        quic_connection:chunk_crypto(<<"abcdefg">>, 0, 3)
    ).

offset_preserved_from_start_test() ->
    %% Starting offset is honoured and stays contiguous.
    ?assertEqual(
        [{10, <<"abc">>}, {13, <<"de">>}],
        quic_connection:chunk_crypto(<<"abcde">>, 10, 3)
    ).

%% A realistic ~4 KB flight at the 1144-byte budget: every chunk is
%% within budget, offsets are contiguous, and reassembly is lossless.
large_flight_invariants_test() ->
    Max = 1144,
    Payload = crypto:strong_rand_bytes(4000),
    Chunks = quic_connection:chunk_crypto(Payload, 0, Max),
    %% 4000 / 1144 -> 4 chunks (1144, 1144, 1144, 568)
    ?assertEqual(4, length(Chunks)),
    %% every chunk within budget
    [?assert(byte_size(C) =< Max) || {_, C} <- Chunks],
    %% offsets contiguous starting at 0
    ?assertEqual([0, 1144, 2288, 3432], [Off || {Off, _} <- Chunks]),
    %% each offset equals the running byte count
    lists:foldl(
        fun({Off, C}, Acc) ->
            ?assertEqual(Acc, Off),
            Acc + byte_size(C)
        end,
        0,
        Chunks
    ),
    %% lossless reassembly
    ?assertEqual(Payload, iolist_to_binary([C || {_, C} <- Chunks])).
