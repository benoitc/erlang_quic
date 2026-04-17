%%% -*- erlang -*-
%%%
%%% Example: QLOG Tracing
%%%
%%% Demonstrates enabling QLOG for debugging QUIC connections.
%%%
%%% Usage:
%%%   1. Start server with QLOG: qlog_example:start_server(4433).
%%%   2. Run client with QLOG: qlog_example:run_client("localhost", 4433).
%%%   3. View logs: ls /tmp/qlog/*.qlog
%%%   4. Analyze: qlog_example:analyze("/tmp/qlog/somefile.qlog").
%%%

-module(qlog_example).

-export([start_server/1, stop_server/0]).
-export([run_client/2]).
-export([analyze/1, list_qlogs/0, list_qlogs/1]).
-export([handle_connection/2]).

-define(QLOG_DIR, "/tmp/qlog").

%% @doc Start a server with QLOG enabled.
-spec start_server(inet:port_number()) -> {ok, pid()} | {error, term()}.
start_server(Port) ->
    application:ensure_all_started(quic),

    %% Ensure QLOG directory exists
    ok = filelib:ensure_dir(?QLOG_DIR ++ "/"),

    case load_certs() of
        {ok, Cert, Key} ->
            Opts = #{
                cert => Cert,
                key => Key,
                alpn => [<<"echo">>],
                connection_handler => fun ?MODULE:handle_connection/2,
                %% Enable QLOG
                qlog => #{
                    enabled => true,
                    dir => ?QLOG_DIR,
                    events => all
                }
            },
            case quic:start_server(qlog_server, Port, Opts) of
                {ok, Pid} ->
                    {ok, ActualPort} = quic:get_server_port(qlog_server),
                    io:format("QLOG server started on port ~p~n", [ActualPort]),
                    io:format("QLOG files will be written to: ~s~n", [?QLOG_DIR]),
                    {ok, Pid};
                Error ->
                    Error
            end;
        {error, Reason} ->
            {error, {cert_load_failed, Reason}}
    end.

%% @doc Stop the QLOG server.
-spec stop_server() -> ok.
stop_server() ->
    quic:stop_server(qlog_server),
    io:format("Server stopped. Check QLOG files in: ~s~n", [?QLOG_DIR]),
    ok.

%% @doc Connect to server with QLOG enabled.
-spec run_client(string() | binary(), inet:port_number()) -> ok | {error, term()}.
run_client(Host, Port) ->
    application:ensure_all_started(quic),

    %% Ensure QLOG directory exists
    ok = filelib:ensure_dir(?QLOG_DIR ++ "/"),

    Opts = #{
        alpn => [<<"echo">>],
        verify => false,
        %% Enable QLOG with selective events
        qlog => #{
            enabled => true,
            dir => ?QLOG_DIR,
            events => [packet_sent, packet_received, packet_lost, metrics_updated]
        }
    },

    io:format("Connecting to ~s:~p with QLOG enabled~n", [Host, Port]),

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            run_client_session(ConnRef);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List all QLOG files in the default directory.
-spec list_qlogs() -> [string()].
list_qlogs() ->
    list_qlogs(?QLOG_DIR).

%% @doc List all QLOG files in specified directory.
-spec list_qlogs(string()) -> [string()].
list_qlogs(Dir) ->
    Pattern = filename:join(Dir, "*.qlog"),
    Files = filelib:wildcard(Pattern),
    lists:foreach(
        fun(F) ->
            {ok, Info} = file:read_file_info(F),
            Size = element(2, Info),
            io:format("~s (~p bytes)~n", [F, Size])
        end,
        Files
    ),
    Files.

%% @doc Analyze a QLOG file and print summary.
-spec analyze(string()) -> map().
analyze(Filename) ->
    {ok, Data} = file:read_file(Filename),
    Lines = binary:split(Data, <<"\n">>, [global, trim]),

    %% Parse each line as JSON (simple parsing)
    Events = lists:filtermap(
        fun(Line) ->
            case Line of
                <<>> ->
                    false;
                _ ->
                    case parse_json_line(Line) of
                        {ok, Map} -> {true, Map};
                        error -> false
                    end
            end
        end,
        Lines
    ),

    %% Count events by type
    Counts = lists:foldl(
        fun(Event, Acc) ->
            Name = maps:get(<<"name">>, Event, <<"unknown">>),
            maps:update_with(Name, fun(V) -> V + 1 end, 1, Acc)
        end,
        #{},
        Events
    ),

    %% Find lost packets
    LostCount = maps:get(<<"quic:packet_lost">>, Counts, 0),

    %% Extract RTT samples
    RTTs = lists:filtermap(
        fun(Event) ->
            case maps:get(<<"name">>, Event, undefined) of
                <<"quic:metrics_updated">> ->
                    Data1 = maps:get(<<"data">>, Event, #{}),
                    case maps:get(<<"smoothed_rtt">>, Data1, undefined) of
                        undefined -> false;
                        RTT when is_number(RTT) -> {true, RTT};
                        _ -> false
                    end;
                _ ->
                    false
            end
        end,
        Events
    ),

    AvgRTT =
        case RTTs of
            [] -> undefined;
            _ -> lists:sum(RTTs) / length(RTTs)
        end,

    %% Print summary
    io:format("~nQLOG Analysis: ~s~n", [Filename]),
    io:format("=====================================~n"),
    io:format("Total events: ~p~n", [length(Events)]),
    io:format("~nEvent counts:~n"),
    lists:foreach(
        fun({Name, Count}) ->
            io:format("  ~s: ~p~n", [Name, Count])
        end,
        lists:sort(maps:to_list(Counts))
    ),
    io:format("~nPackets lost: ~p~n", [LostCount]),
    case AvgRTT of
        undefined -> ok;
        _ -> io:format("Average RTT: ~.2f ms~n", [AvgRTT])
    end,

    #{
        total_events => length(Events),
        event_counts => Counts,
        packets_lost => LostCount,
        average_rtt => AvgRTT
    }.

%% @doc Server-side handler: echoes stream data back to the peer.
handle_connection(ConnPid, _DCID) ->
    HandlerPid = spawn(fun() -> echo_loop(ConnPid) end),
    {ok, HandlerPid}.

%%====================================================================
%% Internal Functions
%%====================================================================

echo_loop(ConnPid) ->
    receive
        {quic, _, {stream_data, StreamId, Data, Fin}} ->
            quic:send_data(ConnPid, StreamId, Data, Fin),
            echo_loop(ConnPid);
        {quic, _, {closed, _}} ->
            ok;
        _Other ->
            echo_loop(ConnPid)
    end.

run_client_session(ConnRef) ->
    %% Wait for connection
    receive
        {quic, ConnRef, {connected, _Info}} ->
            io:format("Connected!~n")
    after 5000 ->
        quic:close(ConnRef, timeout),
        exit(connection_timeout)
    end,

    %% Open stream and send some data
    {ok, StreamId} = quic:open_stream(ConnRef),
    TestData = <<"QLOG test data - Hello World!">>,
    ok = quic:send_data(ConnRef, StreamId, TestData, true),
    io:format("Sent: ~p~n", [TestData]),

    %% Wait for echo
    receive
        {quic, ConnRef, {stream_data, StreamId, Response, _}} ->
            io:format("Received: ~p~n", [Response])
    after 5000 ->
        io:format("Timeout waiting for response~n")
    end,

    %% Close connection and wait for the connection process to terminate
    %% so the QLOG writer flushes before we return.
    MRef = erlang:monitor(process, ConnRef),
    quic:close(ConnRef, normal),
    receive
        {'DOWN', MRef, process, ConnRef, _} -> ok
    after 2000 ->
        erlang:demonitor(MRef, [flush]),
        ok
    end,
    io:format("~nConnection closed. QLOG file written to: ~s~n", [?QLOG_DIR]),
    io:format("Run qlog_example:list_qlogs() to see files~n"),
    io:format("Run qlog_example:analyze(\"<filename>\") to analyze~n"),
    ok.

parse_json_line(Line) ->
    %% Very simple JSON object parser for QLOG events
    %% Just extracts "name" and "data" fields
    try
        %% Find "name" field
        case binary:match(Line, <<"\"name\"">>) of
            {Pos, _} ->
                %% Extract name value
                Rest = binary:part(Line, Pos, byte_size(Line) - Pos),
                case re:run(Rest, <<"\"name\":\"([^\"]+)\"">>, [{capture, [1], binary}]) of
                    {match, [Name]} ->
                        {ok, #{<<"name">> => Name, <<"raw">> => Line}};
                    _ ->
                        {ok, #{<<"raw">> => Line}}
                end;
            nomatch ->
                %% Might be header
                {ok, #{<<"header">> => true, <<"raw">> => Line}}
        end
    catch
        _:_ -> error
    end.

load_certs() ->
    Locations = [
        {"certs/cert.pem", "certs/priv.key"},
        {"../certs/cert.pem", "../certs/priv.key"}
    ],
    load_certs_from_locations(Locations).

load_certs_from_locations([]) ->
    {error, no_certs_found};
load_certs_from_locations([{CertFile, KeyFile} | Rest]) ->
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            try
                {ok, CertPem} = file:read_file(CertFile),
                {ok, KeyPem} = file:read_file(KeyFile),
                [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
                KeyDer = decode_key(KeyPem),
                {ok, CertDer, KeyDer}
            catch
                _:_ -> load_certs_from_locations(Rest)
            end;
        _ ->
            load_certs_from_locations(Rest)
    end.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] ->
            public_key:der_decode('PrivateKeyInfo', Der);
        [{_, Der, not_encrypted}] ->
            Der
    end.
