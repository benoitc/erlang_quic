%%% -*- erlang -*-
%%%
%%% Property-based tests for QPACK encoding/decoding
%%% Inspired by quiche qpack_decode fuzz target
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_qpack_prop_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Property Tests
%%====================================================================

qpack_prop_test_() ->
    {timeout, 120, [
        {"Header roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_header_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"Multiple headers roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_multiple_headers_roundtrip(), [{numtests, 50}, {to_file, user}]))
        end},
        {"Decode arbitrary bytes no crash", fun() ->
            ?assert(proper:quickcheck(prop_decode_no_crash(), [{numtests, 500}, {to_file, user}]))
        end},
        {"Static table entries roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_static_table_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"Huffman roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_huffman_roundtrip(), [{numtests, 200}, {to_file, user}]))
        end},
        {"Header names preserved", fun() ->
            ?assert(proper:quickcheck(prop_header_name_preserved(), [{numtests, 100}, {to_file, user}]))
        end}
    ]}.

%%====================================================================
%% Properties
%%====================================================================

%% Single header encode/decode roundtrip
prop_header_roundtrip() ->
    ?FORALL({Name, Value}, {http_header_name(), http_header_value()},
        begin
            State0 = quic_qpack:new(),
            Headers = [{Name, Value}],
            {Encoded, State1} = quic_qpack:encode(Headers, State0),
            case quic_qpack:decode(Encoded, State1) of
                {{ok, Decoded}, _State2} ->
                    %% Names are lowercased
                    LowerName = string:lowercase(Name),
                    [{DecodedName, DecodedValue}] = Decoded,
                    DecodedName =:= LowerName andalso DecodedValue =:= Value;
                {{error, _Reason}, _} ->
                    false
            end
        end).

%% Multiple headers encode/decode roundtrip
prop_multiple_headers_roundtrip() ->
    ?FORALL(Headers, non_empty(list({http_header_name(), http_header_value()})),
        begin
            State0 = quic_qpack:new(),
            {Encoded, State1} = quic_qpack:encode(Headers, State0),
            case quic_qpack:decode(Encoded, State1) of
                {{ok, Decoded}, _State2} ->
                    %% Check same number of headers
                    length(Decoded) =:= length(Headers) andalso
                    %% Check each header matches (with lowercased name)
                    lists:all(fun({{N1, V1}, {N2, V2}}) ->
                        string:lowercase(N1) =:= N2 andalso V1 =:= V2
                    end, lists:zip(Headers, Decoded));
                {{error, _Reason}, _} ->
                    false
            end
        end).

%% Decoding arbitrary bytes should not crash (fuzzing target)
%% Note: quic_qpack uses throw for incomplete data, which is expected
prop_decode_no_crash() ->
    ?FORALL(Bytes, binary(),
        begin
            State = quic_qpack:new(),
            try
                case quic_qpack:decode(Bytes, State) of
                    {{ok, _}, _} -> true;
                    {{blocked, _}, _} -> true;
                    {{error, _}, _} -> true
                end
            catch
                %% throw:incomplete is expected for malformed data
                throw:incomplete -> true;
                %% Other throws are also acceptable error handling
                throw:_ -> true;
                %% Errors that indicate malformed input are acceptable
                error:badarg -> true;
                error:function_clause -> true;
                error:{badmatch, _} -> true;
                %% Any other crash is a real bug
                Class:Reason ->
                    io:format("Unexpected crash: ~p:~p~n", [Class, Reason]),
                    false
            end
        end).

%% Static table entries should encode efficiently and roundtrip
prop_static_table_roundtrip() ->
    ?FORALL(Headers, static_table_headers(),
        begin
            State0 = quic_qpack:new(),
            {Encoded, State1} = quic_qpack:encode(Headers, State0),
            case quic_qpack:decode(Encoded, State1) of
                {{ok, Decoded}, _State2} ->
                    Decoded =:= Headers;
                {{error, _Reason}, _} ->
                    false
            end
        end).

%% Huffman encoding/decoding roundtrip
prop_huffman_roundtrip() ->
    ?FORALL(Str, printable_binary(),
        begin
            Encoded = quic_qpack_huffman:encode(Str),
            Decoded = quic_qpack_huffman:decode(Encoded),
            Decoded =:= Str
        end).

%% Header names should be preserved exactly (QPACK doesn't lowercase)
prop_header_name_preserved() ->
    ?FORALL({Name, Value}, {http_header_name(), http_header_value()},
        begin
            State0 = quic_qpack:new(),
            Headers = [{Name, Value}],
            {Encoded, State1} = quic_qpack:encode(Headers, State0),
            case quic_qpack:decode(Encoded, State1) of
                {{ok, [{DecodedName, _}]}, _} ->
                    DecodedName =:= Name;
                _ ->
                    false
            end
        end).

%%====================================================================
%% Generators
%%====================================================================

%% Generate valid HTTP header names (lowercase, no special chars)
http_header_name() ->
    ?LET(Name, non_empty(list(oneof([
        range($a, $z),
        range($0, $9),
        $-
    ]))),
        list_to_binary(Name)).

%% Generate HTTP header values (printable ASCII)
http_header_value() ->
    ?LET(Value, list(range(32, 126)),
        list_to_binary(Value)).

%% Generate printable binary strings
printable_binary() ->
    ?LET(Chars, list(range(32, 126)),
        list_to_binary(Chars)).

%% Generate headers from static table
static_table_headers() ->
    ?LET(N, range(1, 5),
        [static_table_header() || _ <- lists:seq(1, N)]).

static_table_header() ->
    oneof([
        {<<":authority">>, <<>>},
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"http">>},
        {<<":scheme">>, <<"https">>},
        {<<":status">>, <<"200">>},
        {<<":status">>, <<"204">>},
        {<<":status">>, <<"206">>},
        {<<":status">>, <<"304">>},
        {<<":status">>, <<"400">>},
        {<<":status">>, <<"404">>},
        {<<":status">>, <<"500">>},
        {<<"accept">>, <<"*/*">>},
        {<<"accept-encoding">>, <<"gzip, deflate, br">>},
        {<<"accept-language">>, <<>>},
        {<<"cache-control">>, <<"max-age=0">>},
        {<<"content-encoding">>, <<"gzip">>},
        {<<"content-type">>, <<"text/html; charset=utf-8">>},
        {<<"content-type">>, <<"application/json">>},
        {<<"host">>, <<>>},
        {<<"user-agent">>, <<>>}
    ]).
