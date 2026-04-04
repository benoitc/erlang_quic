%%% -*- erlang -*-
%%%
%%% Example: Simple Echo Server
%%%
%%% Usage:
%%%   1. Generate certificates: cd certs && ./generate_certs.sh
%%%   2. Start: echo_server:start(4433).
%%%   3. Test with: echo_client:run("localhost", 4433, <<"Hello!">>).
%%%   4. Stop: echo_server:stop().
%%%

-module(echo_server).

-export([start/1, start/2, stop/0]).
-export([handle_connection/2]).

%% @doc Start echo server on specified port.
-spec start(inet:port_number()) -> {ok, pid()} | {error, term()}.
start(Port) ->
    start(Port, #{}).

%% @doc Start echo server with custom options.
-spec start(inet:port_number(), map()) -> {ok, pid()} | {error, term()}.
start(Port, ExtraOpts) ->
    application:ensure_all_started(quic),

    %% Load certificates
    case load_certs() of
        {ok, Cert, Key} ->
            Opts = maps:merge(
                #{
                    cert => Cert,
                    key => Key,
                    alpn => [<<"echo">>],
                    connection_handler => fun ?MODULE:handle_connection/2,
                    %% Enable datagrams for echo
                    max_datagram_frame_size => 65535
                },
                ExtraOpts
            ),
            case quic:start_server(echo_server, Port, Opts) of
                {ok, Pid} ->
                    {ok, ActualPort} = quic:get_server_port(echo_server),
                    io:format("Echo server started on port ~p~n", [ActualPort]),
                    {ok, Pid};
                Error ->
                    Error
            end;
        {error, Reason} ->
            {error, {cert_load_failed, Reason}}
    end.

%% @doc Stop the echo server.
-spec stop() -> ok.
stop() ->
    quic:stop_server(echo_server),
    io:format("Echo server stopped~n"),
    ok.

%% @doc Handle new connections.
handle_connection(ConnPid, Info) ->
    PeerAddr = maps:get(peer_address, Info, unknown),
    io:format("New connection from ~p~n", [PeerAddr]),
    spawn(fun() -> echo_loop(ConnPid) end).

%%====================================================================
%% Internal Functions
%%====================================================================

echo_loop(ConnPid) ->
    receive
        {quic, _, {stream_data, StreamId, Data, Fin}} ->
            %% Echo the data back
            io:format("Echoing ~p bytes on stream ~p~n", [byte_size(Data), StreamId]),
            quic:send_data(ConnPid, StreamId, Data, Fin),
            echo_loop(ConnPid);

        {quic, _, {datagram, Data}} ->
            %% Echo datagrams too
            io:format("Echoing datagram: ~p bytes~n", [byte_size(Data)]),
            quic:send_datagram(ConnPid, Data),
            echo_loop(ConnPid);

        {quic, _, {stream_opened, StreamId}} ->
            io:format("Stream ~p opened by peer~n", [StreamId]),
            echo_loop(ConnPid);

        {quic, _, {closed, Reason}} ->
            io:format("Connection closed: ~p~n", [Reason]),
            ok;

        Other ->
            io:format("Unhandled message: ~p~n", [Other]),
            echo_loop(ConnPid)
    end.

load_certs() ->
    %% Try multiple certificate locations
    Locations = [
        {"certs/cert.pem", "certs/priv.key"},
        {"../certs/cert.pem", "../certs/priv.key"},
        {code:priv_dir(quic) ++ "/../certs/cert.pem",
         code:priv_dir(quic) ++ "/../certs/priv.key"}
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
                _:Reason ->
                    io:format("Failed to load certs from ~s: ~p~n", [CertFile, Reason]),
                    load_certs_from_locations(Rest)
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
        [{Type, Der, not_encrypted}] ->
            io:format("Unknown key type: ~p~n", [Type]),
            Der
    end.
