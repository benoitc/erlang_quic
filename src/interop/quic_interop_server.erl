%%% -*- erlang -*-
%%%
%%% QUIC Interop Runner Server
%%% https://github.com/quic-interop/quic-interop-runner
%%%
%%% Copyright (c) 2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Interop runner server for QUIC compliance testing.
%%%
%%% Environment variables:
%%%   TESTCASE - Test case name (handshake, transfer, retry, etc.)
%%%   SSLKEYLOGFILE - Optional file for TLS key logging
%%%
%%% The server serves files from /www directory and uses certificates
%%% from /certs directory (cert.pem, priv.key).

-module(quic_interop_server).

-export([main/1]).

%% Suppress dialyzer warnings for escript functions that call halt()
-dialyzer({nowarn_function, [main/1, run_server/4]}).

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

main(_Args) ->
    %% Start required applications
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    %% Get environment variables
    TestCase = os:getenv("TESTCASE", "handshake"),
    CertsDir = os:getenv("CERTS", "/certs"),
    WwwDir = os:getenv("WWW", "/www"),
    Port = list_to_integer(os:getenv("PORT", "443")),

    io:format("QUIC Interop Server~n"),
    io:format("  Test case: ~s~n", [TestCase]),
    io:format("  Port: ~p~n", [Port]),
    io:format("  Certs: ~s~n", [CertsDir]),
    io:format("  WWW: ~s~n", [WwwDir]),

    %% Check if test case is supported
    case lists:member(TestCase, ?SUPPORTED_TESTS) of
        false ->
            io:format("Test case ~s not supported~n", [TestCase]),
            halt(?EXIT_UNSUPPORTED);
        true ->
            run_server(TestCase, Port, CertsDir, WwwDir)
    end.

run_server(TestCase, Port, CertsDir, WwwDir) ->
    %% Load certificates
    CertFile = filename:join(CertsDir, "cert.pem"),
    KeyFile = filename:join(CertsDir, "priv.key"),

    case {file:read_file(CertFile), file:read_file(KeyFile)} of
        {{ok, CertPem}, {ok, KeyPem}} ->
            %% Decode PEM to DER
            [{_, CertDer, _}] = public_key:pem_decode(CertPem),
            PrivateKey = decode_private_key(KeyPem),

            %% Build server options
            Opts = build_server_opts(TestCase, CertDer, PrivateKey, WwwDir),

            %% Start listener
            case quic_listener:start_link(Port, Opts) of
                {ok, Listener} ->
                    io:format("Server listening on port ~p~n", [Port]),

                    %% Wait forever (or until killed)
                    receive
                        stop ->
                            quic_listener:stop(Listener),
                            halt(?EXIT_SUCCESS)
                    end;
                {error, Reason} ->
                    io:format("Failed to start listener: ~p~n", [Reason]),
                    halt(?EXIT_FAILURE)
            end;
        _ ->
            io:format("Failed to read certificates~n"),
            halt(?EXIT_FAILURE)
    end.

build_server_opts(TestCase, Cert, Key, WwwDir) ->
    BaseOpts = #{
        cert => Cert,
        key => Key,
        alpn => [<<"hq-interop">>, <<"h3">>],
        connection_handler => fun(ConnPid, ConnRef) ->
            spawn_handler(ConnPid, ConnRef, WwwDir, TestCase)
        end
    },

    %% Test case specific options
    case TestCase of
        "retry" ->
            BaseOpts#{retry => true};
        "chacha20" ->
            BaseOpts#{ciphers => [chacha20_poly1305]};
        "v2" ->
            BaseOpts#{versions => [16#6b3343cf, 16#00000001]};
        _ ->
            BaseOpts
    end.

%% Decode PEM-encoded private key to internal format
decode_private_key(PemData) ->
    case public_key:pem_decode(PemData) of
        [{Type, Der, not_encrypted}] ->
            decode_key_entry(Type, Der);
        [{Type, Der, _Cipher}] ->
            %% Encrypted key - not supported yet
            decode_key_entry(Type, Der);
        _ ->
            error(invalid_private_key)
    end.

decode_key_entry('RSAPrivateKey', Der) ->
    public_key:der_decode('RSAPrivateKey', Der);
decode_key_entry('ECPrivateKey', Der) ->
    public_key:der_decode('ECPrivateKey', Der);
decode_key_entry('PrivateKeyInfo', Der) ->
    %% PKCS#8 format - public_key:der_decode handles extraction automatically
    public_key:der_decode('PrivateKeyInfo', Der);
decode_key_entry(Type, _Der) ->
    error({unsupported_key_type, Type}).

spawn_handler(ConnPid, ConnRef, WwwDir, TestCase) ->
    HandlerPid = spawn(fun() ->
        connection_handler(ConnPid, ConnRef, WwwDir, TestCase)
    end),
    {ok, HandlerPid}.

connection_handler(ConnPid, ConnRef, WwwDir, TestCase) ->
    io:format("Handler started, waiting for messages...~n"),
    %% Wait for stream data
    receive
        {quic, ConnRef, {connected, Info}} ->
            io:format("Handler got connected: ~p~n", [Info]),
            connection_handler(ConnPid, ConnRef, WwwDir, TestCase);
        {quic, ConnRef, {stream_opened, StreamId}} ->
            io:format("Handler got stream_opened: ~p~n", [StreamId]),
            handle_stream(ConnPid, ConnRef, StreamId, WwwDir, TestCase);
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            io:format(
                "Handler got stream_data: stream=~p size=~p fin=~p~n",
                [StreamId, byte_size(Data), Fin]
            ),
            %% Handle request
            handle_request(ConnPid, ConnRef, StreamId, Data, WwwDir, TestCase);
        {quic, ConnRef, {closed, Reason}} ->
            io:format("Handler got closed: ~p~n", [Reason]),
            ok;
        Other ->
            io:format("Handler got unexpected: ~p~n", [Other]),
            connection_handler(ConnPid, ConnRef, WwwDir, TestCase)
    after 60000 ->
        io:format("Handler timeout~n"),
        ok
    end.

handle_stream(_ConnPid, ConnRef, StreamId, WwwDir, TestCase) ->
    %% Wait for request on this stream
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, _Fin}} ->
            handle_request(undefined, ConnRef, StreamId, Data, WwwDir, TestCase)
    after 30000 ->
        ok
    end.

handle_request(_ConnPid, ConnRef, StreamId, Data, WwwDir, TestCase) ->
    io:format("handle_request: stream=~p data=~p~n", [StreamId, Data]),
    %% Parse simple HTTP/0.9 request: "GET /path\r\n"
    case parse_request(Data) of
        {ok, Path} ->
            io:format("Parsed request path: ~p~n", [Path]),
            %% Handle key update test
            case TestCase of
                "keyupdate" ->
                    case quic_connection:lookup(ConnRef) of
                        {ok, Pid} -> quic_connection:key_update(Pid);
                        _ -> ok
                    end;
                _ ->
                    ok
            end,

            %% Serve file
            FilePath = filename:join(WwwDir, Path),
            io:format("Reading file: ~p~n", [FilePath]),
            case file:read_file(FilePath) of
                {ok, Content} ->
                    io:format("Sending ~p bytes on stream ~p~n", [byte_size(Content), StreamId]),
                    Result = quic:send_data(ConnRef, StreamId, Content, true),
                    io:format("send_data result: ~p~n", [Result]),
                    Result;
                {error, ReadErr} ->
                    io:format("File read error: ~p, sending 404~n", [ReadErr]),
                    quic:send_data(ConnRef, StreamId, <<"404 Not Found">>, true)
            end;
        error ->
            io:format("Parse error, sending 400~n"),
            quic:send_data(ConnRef, StreamId, <<"400 Bad Request">>, true)
    end.

parse_request(Data) ->
    case binary:split(Data, <<"\r\n">>) of
        [RequestLine | _] ->
            case binary:split(RequestLine, <<" ">>, [global]) of
                [<<"GET">>, Path | _] ->
                    %% Remove leading slash for file path
                    CleanPath =
                        case Path of
                            <<"/">> -> <<"index.html">>;
                            <<"/", Rest/binary>> -> Rest;
                            _ -> Path
                        end,
                    {ok, binary_to_list(CleanPath)};
                _ ->
                    error
            end;
        _ ->
            error
    end.
