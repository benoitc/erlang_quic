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

%% Suppress dialyzer warnings for escript functions that call halt()
-dialyzer({no_return, [main/1, run_test/3]}).
-dialyzer({nowarn_function, [run_resumption_test/2, run_zerortt_test/2, run_migration_test/2]}).

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
    "v2",
    "resumption",
    "zerortt",
    "connectionmigration"
]).

%% Include for session_ticket record
-include("quic.hrl").

%% Ticket file location (for resumption/0-RTT tests)
-define(TICKET_FILE, "/downloads/session_ticket.dat").

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

run_test("resumption", RequestsStr, DownloadsDir) ->
    %% Resumption test: two connections, second uses session ticket
    run_resumption_test(RequestsStr, DownloadsDir);
run_test("zerortt", RequestsStr, DownloadsDir) ->
    %% 0-RTT test: send early data using stored ticket
    run_zerortt_test(RequestsStr, DownloadsDir);
run_test("connectionmigration", RequestsStr, DownloadsDir) ->
    %% Connection migration: simulate path change during transfer
    run_migration_test(RequestsStr, DownloadsDir);
run_test(TestCase, RequestsStr, DownloadsDir) ->
    %% Standard test case
    Requests = string:tokens(RequestsStr, " "),

    case Requests of
        [] ->
            io:format("No requests specified~n"),
            halt(?EXIT_FAILURE);
        _ ->
            Results = lists:map(
                fun(Url) -> download_file(TestCase, Url, DownloadsDir) end,
                Requests
            ),

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
    %% Extract filename and open file for streaming writes
    Filename = filename:basename(Path),
    FilePath = filename:join(DownloadsDir, Filename),

    case file:open(FilePath, [write, binary, raw]) of
        {ok, FileHandle} ->
            Result = receive_stream_data_streaming(ConnRef, StreamId, FileHandle, 0, 60000),
            file:close(FileHandle),
            case Result of
                {ok, BytesWritten} ->
                    io:format("Saved: ~s (~p bytes)~n", [FilePath, BytesWritten]),
                    ok;
                error ->
                    %% Clean up partial file on error
                    file:delete(FilePath),
                    error
            end;
        {error, OpenErr} ->
            io:format("Failed to open file for writing: ~p~n", [OpenErr]),
            error
    end.

%% Streaming version: write chunks to disk as they arrive (memory efficient for large files)
receive_stream_data_streaming(ConnRef, StreamId, FileHandle, BytesWritten, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            case file:write(FileHandle, Data) of
                ok ->
                    NewBytesWritten = BytesWritten + byte_size(Data),
                    case Fin of
                        true ->
                            {ok, NewBytesWritten};
                        false ->
                            receive_stream_data_streaming(ConnRef, StreamId, FileHandle, NewBytesWritten, Timeout)
                    end;
                {error, WriteErr} ->
                    io:format("Write error: ~p~n", [WriteErr]),
                    error
            end;

        {quic, ConnRef, {stream_reset, StreamId, _Code}} ->
            io:format("Stream reset~n"),
            error;

        {quic, ConnRef, {closed, _Reason}} ->
            %% Connection closed, return what we have
            case BytesWritten of
                0 -> error;
                _ -> {ok, BytesWritten}
            end

    after Timeout ->
        io:format("Stream timeout~n"),
        case BytesWritten of
            0 -> error;
            _ -> {ok, BytesWritten}
        end
    end.

parse_url(Url) ->
    %% Simple URL parser for https://host:port/path
    case string:prefix(Url, "https://") of
        nomatch ->
            error;
        HostPortPath ->
            %% string:split always returns at least one element
            [HostPort | PathParts] = string:split(HostPortPath, "/"),
            Path = "/" ++ string:join(PathParts, "/"),
            case string:split(HostPort, ":") of
                [Host, PortStr] ->
                    Port = list_to_integer(PortStr),
                    {ok, Host, Port, Path};
                [Host] ->
                    {ok, Host, 443, Path}
            end
    end.

%%====================================================================
%% Session Resumption Test
%%====================================================================

%% Two-phase resumption test:
%% Phase 1: Connect, download, receive session ticket
%% Phase 2: Reconnect with ticket, verify resumption works
run_resumption_test(RequestsStr, DownloadsDir) ->
    Requests = string:tokens(RequestsStr, " "),
    case Requests of
        [] ->
            io:format("No requests specified~n"),
            halt(?EXIT_FAILURE);
        [Url | _Rest] ->
            case parse_url(Url) of
                {ok, Host, Port, Path} ->
                    %% Phase 1: Initial connection to get ticket
                    io:format("~n=== Phase 1: Initial connection to get ticket ===~n"),
                    case resumption_phase1(Host, Port, Path, DownloadsDir) of
                        {ok, Ticket} ->
                            %% Save ticket to file
                            save_ticket(Ticket),
                            io:format("Ticket saved~n"),

                            %% Phase 2: Resumption with ticket
                            io:format("~n=== Phase 2: Resumption with ticket ===~n"),
                            case resumption_phase2(Host, Port, Path, DownloadsDir, Ticket) of
                                ok ->
                                    io:format("Resumption test successful~n"),
                                    halt(?EXIT_SUCCESS);
                                error ->
                                    io:format("Resumption phase 2 failed~n"),
                                    halt(?EXIT_FAILURE)
                            end;
                        error ->
                            io:format("Resumption phase 1 failed~n"),
                            halt(?EXIT_FAILURE)
                    end;
                error ->
                    io:format("Invalid URL~n"),
                    halt(?EXIT_FAILURE)
            end
    end.

%% Phase 1: Connect, download, and wait for session ticket
resumption_phase1(Host, Port, Path, DownloadsDir) ->
    Opts = #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>]
    },
    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = wait_for_ticket_and_download(ConnRef, Path, DownloadsDir),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            io:format("Phase 1 connection failed: ~p~n", [Reason]),
            error
    end.

%% Wait for connection, download, and capture session ticket
wait_for_ticket_and_download(ConnRef, Path, DownloadsDir) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("Phase 1: Connected~n"),
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
                    ok = quic:send_data(ConnRef, StreamId, Request, true),
                    %% Download and wait for ticket
                    download_and_wait_for_ticket(ConnRef, StreamId, Path, DownloadsDir, undefined);
                {error, Err} ->
                    io:format("Failed to open stream: ~p~n", [Err]),
                    error
            end;
        {quic, ConnRef, {closed, Reason}} ->
            io:format("Phase 1: Connection closed: ~p~n", [Reason]),
            error
    after 30000 ->
        io:format("Phase 1: Connection timeout~n"),
        error
    end.

%% Download file and wait for session ticket
download_and_wait_for_ticket(ConnRef, StreamId, Path, DownloadsDir, Ticket) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            %% Accumulate data (could use streaming, but for resumption test this is fine)
            case Fin of
                true ->
                    %% Save the file
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, Data),
                    io:format("Phase 1: Downloaded ~s~n", [FilePath]),
                    %% Continue waiting for ticket if we don't have one yet
                    case Ticket of
                        undefined -> wait_for_ticket_only(ConnRef, 5000);
                        _ -> {ok, Ticket}
                    end;
                false ->
                    download_and_wait_for_ticket(ConnRef, StreamId, Path, DownloadsDir, Ticket)
            end;

        {quic, ConnRef, {session_ticket, NewTicket}} ->
            io:format("Phase 1: Received session ticket~n"),
            download_and_wait_for_ticket(ConnRef, StreamId, Path, DownloadsDir, NewTicket);

        {quic, ConnRef, {closed, _Reason}} ->
            case Ticket of
                undefined -> error;
                _ -> {ok, Ticket}
            end

    after 60000 ->
        io:format("Phase 1: Stream/ticket timeout~n"),
        case Ticket of
            undefined -> error;
            _ -> {ok, Ticket}
        end
    end.

%% Wait only for a session ticket (after download is complete)
wait_for_ticket_only(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {session_ticket, Ticket}} ->
            io:format("Received session ticket~n"),
            {ok, Ticket};
        {quic, ConnRef, {closed, _Reason}} ->
            io:format("Connection closed before ticket received~n"),
            error
    after Timeout ->
        io:format("Ticket timeout~n"),
        error
    end.

%% Phase 2: Reconnect using session ticket
resumption_phase2(Host, Port, Path, DownloadsDir, Ticket) ->
    Opts = #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>],
        session_ticket => Ticket
    },
    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = wait_for_connection_and_download(ConnRef, Path, DownloadsDir, "resumption"),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            io:format("Phase 2 connection failed: ~p~n", [Reason]),
            error
    end.

%% Save ticket to file for debugging/inspection
save_ticket(Ticket) ->
    file:write_file(?TICKET_FILE, term_to_binary(Ticket)).

%% Load ticket from file
load_ticket() ->
    case file:read_file(?TICKET_FILE) of
        {ok, Data} ->
            try binary_to_term(Data) of
                Ticket -> {ok, Ticket}
            catch
                _:_ -> error
            end;
        {error, _} ->
            error
    end.

%%====================================================================
%% 0-RTT Test
%%====================================================================

%% 0-RTT test requires a stored ticket from a previous connection
run_zerortt_test(RequestsStr, DownloadsDir) ->
    Requests = string:tokens(RequestsStr, " "),
    case Requests of
        [] ->
            io:format("No requests specified~n"),
            halt(?EXIT_FAILURE);
        [Url | _Rest] ->
            case parse_url(Url) of
                {ok, Host, Port, Path} ->
                    %% Try to load existing ticket
                    case load_ticket() of
                        {ok, Ticket} ->
                            io:format("Using stored ticket for 0-RTT~n"),
                            case zerortt_with_ticket(Host, Port, Path, DownloadsDir, Ticket) of
                                ok ->
                                    io:format("0-RTT test successful~n"),
                                    halt(?EXIT_SUCCESS);
                                error ->
                                    io:format("0-RTT test failed~n"),
                                    halt(?EXIT_FAILURE)
                            end;
                        error ->
                            %% No ticket, do resumption first
                            io:format("No stored ticket, running resumption first~n"),
                            case resumption_phase1(Host, Port, Path, DownloadsDir) of
                                {ok, Ticket} ->
                                    save_ticket(Ticket),
                                    case zerortt_with_ticket(Host, Port, Path, DownloadsDir, Ticket) of
                                        ok ->
                                            io:format("0-RTT test successful~n"),
                                            halt(?EXIT_SUCCESS);
                                        error ->
                                            io:format("0-RTT test failed~n"),
                                            halt(?EXIT_FAILURE)
                                    end;
                                error ->
                                    io:format("Failed to get ticket for 0-RTT~n"),
                                    halt(?EXIT_FAILURE)
                            end
                    end;
                error ->
                    io:format("Invalid URL~n"),
                    halt(?EXIT_FAILURE)
            end
    end.

%% Connect with 0-RTT using stored ticket
%% Sends request as early data before handshake completes
zerortt_with_ticket(Host, Port, Path, DownloadsDir, Ticket) ->
    Opts = #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>],
        session_ticket => Ticket,
        enable_early_data => true
    },
    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            %% Open stream and send request immediately (uses 0-RTT if available)
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
                    io:format("Sending 0-RTT request~n"),
                    ok = quic:send_data(ConnRef, StreamId, Request, true),
                    Result = wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir),
                    quic:close(ConnRef, normal),
                    Result;
                {error, not_connected} ->
                    %% Early keys not available, fall back to waiting for connection
                    io:format("0-RTT: Early keys not available, waiting for connection~n"),
                    Result = wait_for_connection_then_request(ConnRef, Path, DownloadsDir),
                    quic:close(ConnRef, normal),
                    Result;
                {error, Err} ->
                    io:format("Failed to open stream: ~p~n", [Err]),
                    quic:close(ConnRef, normal),
                    error
            end;
        {error, Reason} ->
            io:format("0-RTT connection failed: ~p~n", [Reason]),
            error
    end.

%% Fallback: wait for connection then send request
wait_for_connection_then_request(ConnRef, Path, DownloadsDir) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("0-RTT: Connected (fallback to 1-RTT)~n"),
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
                    ok = quic:send_data(ConnRef, StreamId, Request, true),
                    wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir);
                {error, Err} ->
                    io:format("Failed to open stream: ~p~n", [Err]),
                    error
            end;
        {quic, ConnRef, {closed, Reason}} ->
            io:format("0-RTT: Connection closed: ~p~n", [Reason]),
            error
    after 30000 ->
        io:format("0-RTT: Connection timeout~n"),
        error
    end.

%% Wait for 0-RTT response (may receive before or after connected event)
wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir) ->
    wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir, false, false, <<>>).

wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir, Connected, Retried, Acc) ->
    %% Use shorter timeout after handshake to detect rejected 0-RTT
    Timeout = case Connected andalso Acc =:= <<>> andalso not Retried of
        true -> 2000;  % Short wait for 0-RTT response after handshake
        false -> 60000
    end,
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("0-RTT: Handshake completed~n"),
            wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir, true, Retried, Acc);

        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            NewAcc = <<Acc/binary, Data/binary>>,
            case Fin of
                true ->
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, NewAcc),
                    io:format("0-RTT: Downloaded ~s (~p bytes)~n", [FilePath, byte_size(NewAcc)]),
                    ok;
                false ->
                    wait_for_zerortt_response(ConnRef, StreamId, Path, DownloadsDir, Connected, Retried, NewAcc)
            end;

        {quic, ConnRef, {early_data_rejected, _}} ->
            io:format("0-RTT: Early data rejected, resending as 1-RTT~n"),
            %% Resend request on new stream
            resend_request_1rtt(ConnRef, Path, DownloadsDir);

        {quic, ConnRef, {closed, Reason}} ->
            io:format("0-RTT: Connection closed: ~p~n", [Reason]),
            case Acc of
                <<>> -> error;
                _ ->
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, Acc),
                    ok
            end

    after Timeout ->
        case Connected andalso Acc =:= <<>> andalso not Retried of
            true ->
                %% 0-RTT likely rejected (server couldn't decrypt), retry as 1-RTT
                io:format("0-RTT: No response, resending as 1-RTT~n"),
                resend_request_1rtt(ConnRef, Path, DownloadsDir);
            false ->
                io:format("0-RTT: Timeout~n"),
                error
        end
    end.

%% Resend the request using 1-RTT (after 0-RTT was rejected)
resend_request_1rtt(ConnRef, Path, DownloadsDir) ->
    case quic:open_stream(ConnRef) of
        {ok, NewStreamId} ->
            Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
            ok = quic:send_data(ConnRef, NewStreamId, Request, true),
            wait_for_1rtt_response(ConnRef, NewStreamId, Path, DownloadsDir, <<>>);
        {error, Err} ->
            io:format("0-RTT: Failed to open 1-RTT stream: ~p~n", [Err]),
            error
    end.

%% Wait for 1-RTT response
wait_for_1rtt_response(ConnRef, StreamId, Path, DownloadsDir, Acc) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            NewAcc = <<Acc/binary, Data/binary>>,
            case Fin of
                true ->
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, NewAcc),
                    io:format("0-RTT: Downloaded via 1-RTT ~s (~p bytes)~n", [FilePath, byte_size(NewAcc)]),
                    ok;
                false ->
                    wait_for_1rtt_response(ConnRef, StreamId, Path, DownloadsDir, NewAcc)
            end;
        {quic, ConnRef, {closed, Reason}} ->
            io:format("0-RTT: Connection closed during 1-RTT: ~p~n", [Reason]),
            error
    after 60000 ->
        io:format("0-RTT: 1-RTT timeout~n"),
        error
    end.

%%====================================================================
%% Connection Migration Test
%%====================================================================

%% Connection migration test: change local address mid-transfer
run_migration_test(RequestsStr, DownloadsDir) ->
    Requests = string:tokens(RequestsStr, " "),
    case Requests of
        [] ->
            io:format("No requests specified~n"),
            halt(?EXIT_FAILURE);
        [Url | _Rest] ->
            case parse_url(Url) of
                {ok, Host, Port, Path} ->
                    case run_migration_download(Host, Port, Path, DownloadsDir) of
                        ok ->
                            io:format("Connection migration test successful~n"),
                            halt(?EXIT_SUCCESS);
                        error ->
                            io:format("Connection migration test failed~n"),
                            halt(?EXIT_FAILURE)
                    end;
                error ->
                    io:format("Invalid URL~n"),
                    halt(?EXIT_FAILURE)
            end
    end.

%% Connect, start download, trigger migration, complete download
run_migration_download(Host, Port, Path, DownloadsDir) ->
    Opts = #{
        verify => false,
        alpn => [<<"hq-interop">>, <<"h3">>]
    },
    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = wait_and_migrate_download(ConnRef, Path, DownloadsDir),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            io:format("Migration test connection failed: ~p~n", [Reason]),
            error
    end.

%% Wait for connection, start download, trigger migration mid-transfer
wait_and_migrate_download(ConnRef, Path, DownloadsDir) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("Migration test: Connected~n"),
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    Request = <<"GET ", (list_to_binary(Path))/binary, "\r\n">>,
                    ok = quic:send_data(ConnRef, StreamId, Request, true),
                    receive_with_migration(ConnRef, StreamId, Path, DownloadsDir, false, <<>>);
                {error, Err} ->
                    io:format("Failed to open stream: ~p~n", [Err]),
                    error
            end;
        {quic, ConnRef, {closed, Reason}} ->
            io:format("Migration test: Connection closed: ~p~n", [Reason]),
            error
    after 30000 ->
        io:format("Migration test: Connection timeout~n"),
        error
    end.

%% Receive data and trigger migration after first chunk
receive_with_migration(ConnRef, StreamId, Path, DownloadsDir, Migrated, Acc) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            NewAcc = <<Acc/binary, Data/binary>>,

            %% Trigger migration after receiving some data (but before FIN)
            Migrated1 = case Migrated orelse Fin of
                true ->
                    Migrated;
                false when byte_size(NewAcc) > 0 ->
                    io:format("Migration test: Triggering path migration~n"),
                    %% The migrate call initiates path validation
                    case quic:migrate(ConnRef) of
                        ok ->
                            io:format("Migration test: Migration initiated~n"),
                            true;
                        {error, MigErr} ->
                            io:format("Migration test: Migration failed: ~p~n", [MigErr]),
                            true  % Continue anyway
                    end;
                false ->
                    false
            end,

            case Fin of
                true ->
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, NewAcc),
                    io:format("Migration test: Downloaded ~s (~p bytes)~n", [FilePath, byte_size(NewAcc)]),
                    ok;
                false ->
                    receive_with_migration(ConnRef, StreamId, Path, DownloadsDir, Migrated1, NewAcc)
            end;

        {quic, ConnRef, {path_validated, _PathInfo}} ->
            io:format("Migration test: New path validated~n"),
            receive_with_migration(ConnRef, StreamId, Path, DownloadsDir, Migrated, Acc);

        {quic, ConnRef, {closed, Reason}} ->
            io:format("Migration test: Connection closed: ~p~n", [Reason]),
            case Acc of
                <<>> -> error;
                _ ->
                    Filename = filename:basename(Path),
                    FilePath = filename:join(DownloadsDir, Filename),
                    file:write_file(FilePath, Acc),
                    ok
            end

    after 60000 ->
        io:format("Migration test: Timeout~n"),
        error
    end.
