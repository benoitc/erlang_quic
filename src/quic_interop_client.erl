%%% -*- erlang -*-
%%%
%%% QUIC Interop Runner Client
%%% https://github.com/quic-interop/quic-interop-runner
%%%
%%% Copyright (c) 2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Interop runner client for QUIC compliance testing.
%%%
%%% Environment variables:
%%%   REQUESTS - Space-separated URLs to download
%%%   TESTCASE - Test case name (handshake, transfer, retry, etc.)
%%%   DOWNLOADS - Directory to save downloaded files
%%%   SSLKEYLOGFILE - Optional file for TLS key logging

-module(quic_interop_client).

-export([main/1]).

-define(EXIT_SUCCESS, 0).
-define(EXIT_FAILURE, 1).
-define(EXIT_UNSUPPORTED, 127).

%% Supported test cases
-define(SUPPORTED_TESTS, [
    "handshake",
    "transfer",
    "retry",
    "keyupdate",
    "chacha20",
    "multiconnect",
    "v2"
    %% "resumption" - not fully implemented yet
    %% "zerortt" - not fully implemented yet
]).

main(_Args) ->
    %% Start required applications
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    %% Get environment variables
    TestCase = os:getenv("TESTCASE", "handshake"),
    RequestsStr = os:getenv("REQUESTS", ""),
    DownloadsDir = os:getenv("DOWNLOADS", "/downloads"),

    io:format("QUIC Interop Client~n"),
    io:format("  Test case: ~s~n", [TestCase]),
    io:format("  Requests: ~s~n", [RequestsStr]),
    io:format("  Downloads: ~s~n", [DownloadsDir]),

    %% Check if test case is supported
    case lists:member(TestCase, ?SUPPORTED_TESTS) of
        false ->
            io:format("Test case ~s not supported~n", [TestCase]),
            halt(?EXIT_UNSUPPORTED);
        true ->
            run_test(TestCase, RequestsStr, DownloadsDir)
    end.

run_test(TestCase, RequestsStr, DownloadsDir) ->
    %% Parse URLs
    Requests = string:tokens(RequestsStr, " "),

    case Requests of
        [] ->
            io:format("No requests specified~n"),
            halt(?EXIT_FAILURE);
        _ ->
            %% Run downloads
            Results = lists:map(
                fun(Url) -> download_file(TestCase, Url, DownloadsDir) end,
                Requests
            ),

            %% Check results
            case lists:all(fun(R) -> R =:= ok end, Results) of
                true ->
                    io:format("All downloads successful~n"),
                    halt(?EXIT_SUCCESS);
                false ->
                    io:format("Some downloads failed~n"),
                    halt(?EXIT_FAILURE)
            end
    end.

download_file(TestCase, Url, DownloadsDir) ->
    io:format("Downloading: ~s~n", [Url]),

    %% Parse URL
    case parse_url(Url) of
        {ok, Host, Port, Path} ->
            %% Build connection options based on test case
            Opts = build_opts(TestCase),

            %% Connect
            case quic:connect(Host, Port, Opts, self()) of
                {ok, ConnRef} ->
                    Result = wait_for_connection_and_download(ConnRef, Path, DownloadsDir, TestCase),
                    quic:close(ConnRef, normal),
                    Result;
                {error, Reason} ->
                    io:format("Connection failed: ~p~n", [Reason]),
                    error
            end;
        error ->
            io:format("Invalid URL: ~s~n", [Url]),
            error
    end.

build_opts("chacha20") ->
    %% Force ChaCha20-Poly1305 cipher
    #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>],
        ciphers => [chacha20_poly1305]
    };
build_opts("keyupdate") ->
    %% Request key update after initial data
    #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>],
        force_key_update => true
    };
build_opts("v2") ->
    %% Use QUIC v2
    #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>],
        version => 16#6b3343cf  % QUIC v2
    };
build_opts(_) ->
    %% Default options
    #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>]
    }.

wait_for_connection_and_download(ConnRef, Path, DownloadsDir, TestCase) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("Connected~n"),

            %% Handle key update test case
            case TestCase of
                "keyupdate" ->
                    %% Initiate key update before request
                    case quic_connection:lookup(ConnRef) of
                        {ok, Pid} -> quic_connection:key_update(Pid);
                        _ -> ok
                    end;
                _ ->
                    ok
            end,

            %% Open stream and send request
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    %% Send HTTP/0.9 style request (for hq-interop)
                    Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
                    ok = quic:send_data(ConnRef, StreamId, Request, true),
                    receive_and_save(ConnRef, StreamId, Path, DownloadsDir);
                {error, StreamErr} ->
                    io:format("Failed to open stream: ~p~n", [StreamErr]),
                    error
            end;

        {quic, ConnRef, {closed, Reason}} ->
            io:format("Connection closed: ~p~n", [Reason]),
            error;

        {quic, ConnRef, {transport_error, Code, Msg}} ->
            io:format("Transport error: ~p ~p~n", [Code, Msg]),
            error

    after 30000 ->
        io:format("Connection timeout~n"),
        error
    end.

receive_and_save(ConnRef, StreamId, Path, DownloadsDir) ->
    Data = receive_stream_data(ConnRef, StreamId, <<>>, 60000),

    case Data of
        {ok, Content} ->
            %% Extract filename from path
            Filename = filename:basename(Path),
            FilePath = filename:join(DownloadsDir, Filename),

            %% Save file
            case file:write_file(FilePath, Content) of
                ok ->
                    io:format("Saved: ~s (~p bytes)~n", [FilePath, byte_size(Content)]),
                    ok;
                {error, WriteErr} ->
                    io:format("Failed to write file: ~p~n", [WriteErr]),
                    error
            end;
        error ->
            error
    end.

receive_stream_data(ConnRef, StreamId, Acc, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            {ok, <<Acc/binary, Data/binary>>};

        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            receive_stream_data(ConnRef, StreamId, <<Acc/binary, Data/binary>>, Timeout);

        {quic, ConnRef, {stream_reset, StreamId, _Code}} ->
            io:format("Stream reset~n"),
            error;

        {quic, ConnRef, {closed, _Reason}} ->
            %% Connection closed, return what we have
            case Acc of
                <<>> -> error;
                _ -> {ok, Acc}
            end

    after Timeout ->
        io:format("Stream timeout~n"),
        case Acc of
            <<>> -> error;
            _ -> {ok, Acc}
        end
    end.

parse_url(Url) ->
    %% Simple URL parser for https://host:port/path
    case string:prefix(Url, "https://") of
        nomatch ->
            error;
        HostPortPath ->
            case string:split(HostPortPath, "/") of
                [HostPort | PathParts] ->
                    Path = "/" ++ string:join(PathParts, "/"),
                    case string:split(HostPort, ":") of
                        [Host, PortStr] ->
                            Port = list_to_integer(PortStr),
                            {ok, Host, Port, Path};
                        [Host] ->
                            {ok, Host, 443, Path}
                    end;
                _ ->
                    error
            end
    end.
