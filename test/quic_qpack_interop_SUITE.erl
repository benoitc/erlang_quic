%%% -*- erlang -*-
%%%
%%% QPACK Interoperability Test Suite
%%%
%%% Tests decoding of encoded files from the qifs repository.
%%% https://github.com/qpackers/qifs
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_qpack_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    decode_nghttp3_netbsd_static/1,
    decode_nghttp3_fb_req_static/1,
    decode_nghttp3_fb_resp_static/1,
    decode_ls_qpack_netbsd_static/1,
    roundtrip_netbsd_qif/1,
    roundtrip_fb_req_qif/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        decode_nghttp3_netbsd_static,
        decode_nghttp3_fb_req_static,
        decode_nghttp3_fb_resp_static,
        decode_ls_qpack_netbsd_static,
        roundtrip_netbsd_qif,
        roundtrip_fb_req_qif
    ].

init_per_suite(Config) ->
    %% Find qifs directory in project test/
    DataDir = ?config(data_dir, Config),
    %% DataDir is typically _build/test/lib/quic/test/quic_qpack_interop_SUITE_data
    %% We need to go up to project root and then to test/qifs
    ProjectRoot = find_project_root(DataDir),
    QifsDir = filename:join([ProjectRoot, "test", "qifs"]),
    case filelib:is_dir(QifsDir) of
        true ->
            [{qifs_dir, QifsDir} | Config];
        false ->
            ct:log("qifs dir not found at ~s", [QifsDir]),
            {skip, "qifs directory not found - run: git submodule add https://github.com/qpackers/qifs test/qifs"}
    end.

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> Dir; %% Reached root
                _ -> find_project_root(Parent)
            end
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Test Cases - Decode from other implementations
%%====================================================================

%% Test decoding nghttp3-encoded netbsd.qif with static table only (0.0.0)
decode_nghttp3_netbsd_static(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    EncodedFile = filename:join([QifsDir, "encoded", "qpack-06", "nghttp3", "netbsd.out.0.0.0"]),
    QifFile = filename:join([QifsDir, "qifs", "netbsd.qif"]),
    decode_and_compare(EncodedFile, QifFile).

%% Test decoding nghttp3-encoded fb-req.qif with static table only
decode_nghttp3_fb_req_static(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    EncodedFile = filename:join([QifsDir, "encoded", "qpack-06", "nghttp3", "fb-req.out.0.0.0"]),
    QifFile = filename:join([QifsDir, "qifs", "fb-req.qif"]),
    decode_and_compare(EncodedFile, QifFile).

%% Test decoding nghttp3-encoded fb-resp.qif with static table only
decode_nghttp3_fb_resp_static(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    EncodedFile = filename:join([QifsDir, "encoded", "qpack-06", "nghttp3", "fb-resp.out.0.0.0"]),
    QifFile = filename:join([QifsDir, "qifs", "fb-resp.qif"]),
    decode_and_compare(EncodedFile, QifFile).

%% Test decoding ls-qpack encoded netbsd.qif with static table only
decode_ls_qpack_netbsd_static(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    EncodedFile = filename:join([QifsDir, "encoded", "qpack-06", "ls-qpack", "netbsd.out.0.0.0"]),
    QifFile = filename:join([QifsDir, "qifs", "netbsd.qif"]),
    case filelib:is_file(EncodedFile) of
        true -> decode_and_compare(EncodedFile, QifFile);
        false -> {skip, "ls-qpack encoded file not found"}
    end.

%%====================================================================
%% Test Cases - Round-trip our own encoding
%%====================================================================

%% Test encoding and decoding netbsd.qif
roundtrip_netbsd_qif(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    QifFile = filename:join([QifsDir, "qifs", "netbsd.qif"]),
    roundtrip_qif(QifFile).

%% Test encoding and decoding fb-req.qif
roundtrip_fb_req_qif(Config) ->
    QifsDir = ?config(qifs_dir, Config),
    QifFile = filename:join([QifsDir, "qifs", "fb-req.qif"]),
    roundtrip_qif(QifFile).

%%====================================================================
%% Internal Functions
%%====================================================================

%% Decode encoded file and compare with original QIF
decode_and_compare(EncodedFile, QifFile) ->
    %% Read and parse both files
    {ok, EncodedBin} = file:read_file(EncodedFile),
    {ok, QifBin} = file:read_file(QifFile),

    %% Parse QIF to get expected headers
    ExpectedBlocks = parse_qif(QifBin),

    %% Parse encoded file and decode blocks
    DecodedBlocks = decode_encoded_file(EncodedBin),

    %% Compare
    ?assertEqual(length(ExpectedBlocks), length(DecodedBlocks)),
    compare_blocks(ExpectedBlocks, DecodedBlocks, 1),
    ok.

%% Parse QIF file into list of header blocks
parse_qif(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_qif_lines(Lines, [], []).

parse_qif_lines([], [], Acc) ->
    lists:reverse(Acc);
parse_qif_lines([], Current, Acc) ->
    lists:reverse([lists:reverse(Current) | Acc]);
parse_qif_lines([<<>> | Rest], [], Acc) ->
    %% Empty line, skip if no current block
    parse_qif_lines(Rest, [], Acc);
parse_qif_lines([<<>> | Rest], Current, Acc) ->
    %% Empty line ends current block
    parse_qif_lines(Rest, [], [lists:reverse(Current) | Acc]);
parse_qif_lines([<<"#", _/binary>> | Rest], Current, Acc) ->
    %% Comment, skip
    parse_qif_lines(Rest, Current, Acc);
parse_qif_lines([Line | Rest], Current, Acc) ->
    %% Parse header line: name\tvalue
    case binary:split(Line, <<"\t">>) of
        [Name, Value] ->
            parse_qif_lines(Rest, [{Name, Value} | Current], Acc);
        [Name] when Name =/= <<>> ->
            %% Name only, empty value
            parse_qif_lines(Rest, [{Name, <<>>} | Current], Acc);
        _ ->
            parse_qif_lines(Rest, Current, Acc)
    end.

%% Parse encoded file format:
%% For each block:
%%   8 bytes: stream ID (big-endian)
%%   4 bytes: block length (big-endian)
%%   N bytes: encoded block
decode_encoded_file(Bin) ->
    decode_encoded_blocks(Bin, quic_qpack:new(), []).

decode_encoded_blocks(<<>>, _State, Acc) ->
    lists:reverse(Acc);
decode_encoded_blocks(<<_StreamId:64/big, Length:32/big, Rest/binary>>, State, Acc) ->
    <<EncodedBlock:Length/binary, Rest2/binary>> = Rest,
    case quic_qpack:decode(EncodedBlock, State) of
        {{ok, Headers}, NewState} ->
            decode_encoded_blocks(Rest2, NewState, [Headers | Acc]);
        {{error, Reason}, _} ->
            ct:fail({decode_error, Reason, byte_size(EncodedBlock)})
    end;
decode_encoded_blocks(Bin, _State, _Acc) ->
    ct:fail({invalid_encoded_format, byte_size(Bin)}).

%% Compare two lists of header blocks
compare_blocks([], [], _N) ->
    ok;
compare_blocks([Expected | RestE], [Decoded | RestD], N) ->
    %% Sort both for comparison (order may differ)
    SortedExpected = lists:sort(Expected),
    SortedDecoded = lists:sort(Decoded),
    case SortedExpected =:= SortedDecoded of
        true ->
            compare_blocks(RestE, RestD, N + 1);
        false ->
            ct:log("Block ~p mismatch:~nExpected: ~p~nDecoded: ~p",
                   [N, SortedExpected, SortedDecoded]),
            %% Find differences
            Missing = SortedExpected -- SortedDecoded,
            Extra = SortedDecoded -- SortedExpected,
            ct:fail({block_mismatch, N,
                     {missing, Missing},
                     {extra, Extra}})
    end.

%% Round-trip test: parse QIF, encode, decode, compare
roundtrip_qif(QifFile) ->
    {ok, QifBin} = file:read_file(QifFile),
    ExpectedBlocks = parse_qif(QifBin),

    State0 = quic_qpack:new(),
    roundtrip_blocks(ExpectedBlocks, State0, 1).

roundtrip_blocks([], _State, _N) ->
    ok;
roundtrip_blocks([Headers | Rest], State, N) ->
    %% Encode
    {Encoded, State1} = quic_qpack:encode(Headers, State),

    %% Decode
    case quic_qpack:decode(Encoded, State1) of
        {{ok, Decoded}, State2} ->
            %% Compare (preserve order for round-trip)
            case Headers =:= Decoded of
                true ->
                    roundtrip_blocks(Rest, State2, N + 1);
                false ->
                    ct:log("Round-trip block ~p mismatch:~nOriginal: ~p~nDecoded: ~p",
                           [N, Headers, Decoded]),
                    ct:fail({roundtrip_mismatch, N})
            end;
        {{error, Reason}, _} ->
            ct:fail({roundtrip_decode_error, N, Reason})
    end.
