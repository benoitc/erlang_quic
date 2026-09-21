%%% -*- erlang -*-
%%%
%%% Peer nodes that speak QUIC distribution, for the dist suites.
%%%
%%% Four things have to be right for a peer to come up and be usable, and
%%% each copy of this code that drifted got at least one of them wrong:
%%%
%%% - Distribution starts while the node boots, before anything can be
%%%   set from outside, so the certificate and key go on the command line.
%%%   Set afterwards they are too late and the node exits with
%%%   {credentials, no_credentials}.
%%% - The host is an address, which only longnames accept.
%%% - peer:start/1, not start_link/1: a Common Test group init runs in a
%%%   process that exits when it returns, and takes linked peers with it.
%%% - The peers are not connected to the test node, which would need the
%%%   test node to speak QUIC distribution as well. They are driven with
%%%   peer:call/4,5 over standard_io, so a case collects its result on a
%%%   peer and reads it back, rather than waiting in the test process.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_dist_peer).

-export([
    generate_certs/1,
    start/3,
    start/4,
    restart/3,
    stop/1,
    stop_one/1
]).

-export_type([peer/0, certs/0]).

-type peer() :: #{
    peer := pid(), node := node(), port := inet:port_number(), args := [string()]
}.
-type certs() :: #{cert := file:filename(), key := file:filename()}.

-define(HOST, "127.0.0.1").
-define(HOST_IP, {127, 0, 0, 1}).

%% @doc A self-signed certificate and key under Dir.
-spec generate_certs(file:filename()) -> {ok, certs()} | {error, term()}.
generate_certs(Dir) ->
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Cert = filename:join(Dir, "cert.pem"),
    Key = filename:join(Dir, "key.pem"),
    _ = os:cmd(
        lists:flatten(
            io_lib:format(
                "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
                "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
                [Key, Cert]
            )
        )
    ),
    case filelib:is_file(Cert) andalso filelib:is_file(Key) of
        true -> {ok, #{cert => Cert, key => Key}};
        false -> {error, cert_generation_failed}
    end.

%% @doc Start Count nodes that know one another, with the quic application
%% running and static discovery holding the whole table on every node.
%% Nothing is connected yet; a case connects the pairs it needs.
-spec start(string(), pos_integer(), certs()) -> {ok, [peer()]} | {error, term()}.
start(Prefix, Count, Certs) ->
    start(Prefix, Count, Certs, []).

%% @doc As start/3, with extra emulator arguments for every node; a node
%% brought back with restart/3 gets the same ones.
-spec start(string(), pos_integer(), certs(), [string()]) -> {ok, [peer()]} | {error, term()}.
start(Prefix, Count, Certs, Args) ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    Specs = [
        {Prefix ++ "_" ++ integer_to_list(N) ++ "_" ++ Unique, free_port()}
     || N <- lists:seq(1, Count)
    ],
    start_specs(Specs, Certs, Args, []).

start_specs([], Certs, _Args, Acc) ->
    Peers = lists:reverse(Acc),
    try
        lists:foreach(fun(P) -> configure(P, Peers, Certs) end, Peers),
        {ok, Peers}
    catch
        Class:Reason ->
            stop(Peers),
            {error, {Class, Reason}}
    end;
start_specs([{Name, Port} | Rest], Certs, Args, Acc) ->
    case boot(Name, Port, Certs, Args) of
        {ok, Peer} ->
            start_specs(Rest, Certs, Args, [Peer | Acc]);
        {error, _} = Error ->
            stop(Acc),
            Error
    end.

%% @doc Start a node that has gone down again, under its old name and
%% port, so the others still reach it through the table they hold.
-spec restart(peer(), [peer()], certs()) -> {ok, peer()} | {error, term()}.
restart(#{node := Node, port := Port, args := Args}, All, Certs) ->
    [Name, _Host] = string:split(atom_to_list(Node), "@"),
    case boot(Name, Port, Certs, Args) of
        {ok, Peer} ->
            Table = [
                case P of
                    #{node := Node} -> Peer;
                    _ -> P
                end
             || P <- All
            ],
            try configure(Peer, Table, Certs) of
                ok -> {ok, Peer}
            catch
                Class:Reason ->
                    stop_one(Peer),
                    {error, {Class, Reason}}
            end;
        {error, _} = Error ->
            Error
    end.

-spec stop([peer()]) -> ok.
stop(Peers) ->
    lists:foreach(fun stop_one/1, Peers).

-spec stop_one(peer()) -> ok.
stop_one(#{peer := Pid}) ->
    try
        peer:stop(Pid)
    catch
        _:_ -> ok
    end,
    ok.

%%====================================================================
%% Internal
%%====================================================================

boot(Name, Port, #{cert := Cert, key := Key}, Extra) ->
    Opts = #{
        name => list_to_atom(Name),
        host => ?HOST,
        longnames => true,
        connection => standard_io,
        args =>
            [
                "-proto_dist",
                "quic",
                "-epmd_module",
                "quic_epmd",
                "-start_epmd",
                "false",
                "-quic_dist_port",
                integer_to_list(Port),
                "-quic_dist_cert",
                Cert,
                "-quic_dist_key",
                Key,
                "-setcookie",
                atom_to_list(erlang:get_cookie())
            ] ++ Extra ++ lists:append([["-pa", P] || P <- code:get_path()])
    },
    try peer:start(Opts) of
        {ok, Pid, Node} -> {ok, #{peer => Pid, node => Node, port => Port, args => Extra}};
        {error, _} = Error -> Error
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

configure(#{peer := Pid}, Peers, #{cert := Cert, key := Key}) ->
    Table = [{N, {?HOST, Port}} || #{node := N, port := Port} <- Peers],
    DistConfig = [
        {cert_file, Cert},
        {key_file, Key},
        {verify, verify_none},
        {discovery_module, quic_discovery_static},
        {nodes, Table}
    ],
    ok = peer:call(Pid, application, set_env, [quic, dist, DistConfig]),
    {ok, _} = peer:call(Pid, application, ensure_all_started, [quic]),
    {ok, _} = peer:call(Pid, quic_discovery_static, init, [[{nodes, Table}]]),
    ok.

%% A port nothing holds right now. Something else could take it before
%% the peer binds, but on loopback in a test run that is rare, and far
%% better than fixed ports that collide across suites.
free_port() ->
    {ok, Socket} = gen_udp:open(0, [{ip, ?HOST_IP}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_udp:close(Socket),
    Port.
