%%% -*- erlang -*-
%%%
%%% QUIC Benchmark Server
%%%
%%% Simple QUIC server for benchmark targets with three modes:
%%% - Echo mode: Return received data
%%% - Sink mode: Discard received data (for throughput tests)
%%% - Stats mode: Report received bytes/streams
%%%

-module(quic_bench_server).

-behaviour(gen_server).

-export([
    start/1,
    start/2,
    stop/1,
    get_stats/1,
    reset_stats/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-record(state, {
    server_name :: atom(),
    mode :: echo | sink | stats,
    port :: inet:port_number(),
    stats = #{
        bytes_received => 0,
        bytes_sent => 0,
        streams_opened => 0,
        connections => 0
    } :: map()
}).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Start benchmark server on specified port with default mode (sink)
-spec start(inet:port_number()) -> {ok, pid()} | {error, term()}.
start(Port) ->
    start(Port, sink).

%% @doc Start benchmark server on specified port with specified mode
-spec start(inet:port_number(), echo | sink | stats) -> {ok, pid()} | {error, term()}.
start(Port, Mode) when Mode =:= echo; Mode =:= sink; Mode =:= stats ->
    gen_server:start(?MODULE, [Port, Mode], []).

%% @doc Stop the benchmark server
-spec stop(pid()) -> ok.
stop(Server) ->
    gen_server:stop(Server).

%% @doc Get current statistics
-spec get_stats(pid()) -> map().
get_stats(Server) ->
    gen_server:call(Server, get_stats).

%% @doc Reset statistics
-spec reset_stats(pid()) -> ok.
reset_stats(Server) ->
    gen_server:call(Server, reset_stats).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([Port, Mode]) ->
    process_flag(trap_exit, true),

    %% Generate a unique server name
    ServerName = list_to_atom("bench_server_" ++ integer_to_list(Port)),

    %% Get test certificates from project root certs/ directory
    %% code:priv_dir returns _build/test/lib/quic/priv, so we go up to find certs/
    PrivDir = code:priv_dir(quic),
    %% Go up: priv -> quic -> lib -> test -> _build -> project_root
    ProjectRoot = filename:dirname(
        filename:dirname(filename:dirname(filename:dirname(filename:dirname(PrivDir))))
    ),
    CertDir = filename:join(ProjectRoot, "certs"),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "priv.key"),

    %% Read cert and key
    case {file:read_file(CertFile), file:read_file(KeyFile)} of
        {{ok, CertPem}, {ok, KeyPem}} ->
            %% Parse PEM to DER
            [{_, CertDer, _}] = public_key:pem_decode(CertPem),
            [KeyEntry] = public_key:pem_decode(KeyPem),
            KeyTerm = public_key:pem_entry_decode(KeyEntry),

            Self = self(),

            %% Start QUIC server with connection handler
            Opts = #{
                cert => CertDer,
                key => KeyTerm,
                alpn => [<<"bench">>, <<"h3">>],
                connection_handler => fun(ConnPid, ConnRef) ->
                    spawn_handler(Self, ConnPid, ConnRef, Mode)
                end
            },

            case quic:start_server(ServerName, Port, Opts) of
                {ok, _ServerPid} ->
                    io:format(
                        "Benchmark server '~p' started on port ~p (mode: ~p)~n",
                        [ServerName, Port, Mode]
                    ),
                    {ok, #state{
                        server_name = ServerName,
                        mode = Mode,
                        port = Port
                    }};
                {error, Reason} ->
                    {stop, Reason}
            end;
        {{error, CertErr}, _} ->
            io:format("Failed to read cert: ~p~n", [CertErr]),
            {stop, {cert_error, CertErr}};
        {_, {error, KeyErr}} ->
            io:format("Failed to read key: ~p~n", [KeyErr]),
            {stop, {key_error, KeyErr}}
    end.

handle_call(get_stats, _From, #state{stats = Stats} = State) ->
    {reply, Stats, State};
handle_call(reset_stats, _From, State) ->
    NewStats = #{
        bytes_received => 0,
        bytes_sent => 0,
        streams_opened => 0,
        connections => 0
    },
    {reply, ok, State#state{stats = NewStats}};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({stats_update, BytesReceived, BytesSent, StreamsOpened}, #state{stats = Stats} = State) ->
    NewStats = Stats#{
        bytes_received => maps:get(bytes_received, Stats, 0) + BytesReceived,
        bytes_sent => maps:get(bytes_sent, Stats, 0) + BytesSent,
        streams_opened => maps:get(streams_opened, Stats, 0) + StreamsOpened,
        connections => maps:get(connections, Stats, 0) + 1
    },
    {noreply, State#state{stats = NewStats}};
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', _Pid, Reason}, State) ->
    io:format("Connection handler exited: ~p~n", [Reason]),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{server_name = ServerName}) ->
    quic:stop_server(ServerName),
    ok.

%%====================================================================
%% Connection Handler
%%====================================================================

spawn_handler(StatsServer, ConnPid, ConnRef, Mode) ->
    HandlerPid = spawn_link(fun() ->
        connection_handler(StatsServer, ConnPid, ConnRef, Mode)
    end),
    {ok, HandlerPid}.

connection_handler(StatsServer, ConnPid, ConnRef, Mode) ->
    %% Wait for connection to be established
    receive
        {quic, ConnRef, {connected, _Info}} ->
            connection_loop(
                StatsServer,
                ConnPid,
                ConnRef,
                Mode,
                #{bytes_recv => 0, bytes_sent => 0, streams => 0}
            )
    after 5000 ->
        io:format("Connection timeout~n"),
        ok
    end.

connection_loop(StatsServer, ConnPid, ConnRef, Mode, Acc) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
            BytesRecv = byte_size(Data),
            NewAcc0 = Acc#{bytes_recv => maps:get(bytes_recv, Acc, 0) + BytesRecv},

            %% Handle based on mode
            NewAcc =
                case Mode of
                    echo ->
                        %% Echo the data back
                        case quic_connection:send_data(ConnPid, StreamId, Data, Fin) of
                            ok ->
                                NewAcc0#{
                                    bytes_sent => maps:get(bytes_sent, NewAcc0, 0) + BytesRecv
                                };
                            _ ->
                                NewAcc0
                        end;
                    sink ->
                        %% Just discard
                        NewAcc0;
                    stats ->
                        %% Track and discard
                        NewAcc0
                end,

            connection_loop(StatsServer, ConnPid, ConnRef, Mode, NewAcc);
        {quic, ConnRef, {stream_opened, _StreamId}} ->
            NewAcc = Acc#{streams => maps:get(streams, Acc, 0) + 1},
            connection_loop(StatsServer, ConnPid, ConnRef, Mode, NewAcc);
        {quic, ConnRef, {closed, _Reason}} ->
            %% Connection closed, report stats
            StatsServer !
                {stats_update, maps:get(bytes_recv, Acc, 0), maps:get(bytes_sent, Acc, 0),
                    maps:get(streams, Acc, 0)},
            ok;
        _Other ->
            connection_loop(StatsServer, ConnPid, ConnRef, Mode, Acc)
    after 30000 ->
        %% Idle timeout
        quic_connection:close(ConnPid, normal),
        StatsServer !
            {stats_update, maps:get(bytes_recv, Acc, 0), maps:get(bytes_sent, Acc, 0),
                maps:get(streams, Acc, 0)},
        ok
    end.
