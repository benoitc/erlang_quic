%%% -*- erlang -*-
%%%
%%% GOAWAY from both endpoints, against aioquic, quic-go and quiche.
%%%
%%% RFC 9114 Section 5.2 lets either endpoint send GOAWAY, and lets the
%%% other answer with its own. The identifiers differ in kind: a server
%%% names a client request stream, a client names a push. Other stacks
%%% validate what they receive (quic-go and quiche close on a stream ID
%%% that is not a multiple of four or that increases), so the in-process
%%% tests cannot show that what we send is acceptable, nor that what they
%%% send is handled. These cases run our server against each stack's
%%% client and our client against each stack's server.
%%%
%%% Needs Docker: the peers come from docker/docker-compose.yml. The
%%% servers must already be up (docker compose up -d); the client images
%%% are built here under the `tools' profile. On macOS the client
%%% containers reach our server through host.docker.internal, see
%%% client_host/0.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_goaway_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).
-export([
    aioquic_client_answers_goaway/1,
    quic_go_client_drains_after_goaway/1,
    quiche_client_answers_goaway/1,
    goaway_from_aioquic_server/1,
    goaway_from_quic_go_server/1,
    goaway_from_quiche_server/1
]).

%% Our server for the external clients.
-define(SERVER_PORT, 4439).
%% The body every /goaway path sends, in two parts around the GOAWAY.
-define(BODY, <<"partial and done">>).
%% Long enough for a loopback exchange plus the half-second body hold.
-define(WAIT_MS, 5000).

suite() ->
    [{timetrap, {minutes, 15}}].

all() ->
    [{group, external_clients}, {group, external_servers}].

groups() ->
    [
        {external_clients, [sequence], [
            aioquic_client_answers_goaway,
            quic_go_client_drains_after_goaway,
            quiche_client_answers_goaway
        ]},
        {external_servers, [sequence], [
            goaway_from_aioquic_server,
            goaway_from_quic_go_server,
            goaway_from_quiche_server
        ]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    case os:find_executable("docker") of
        false ->
            {skip, docker_not_available};
        _ ->
            build_client_images(),
            Config
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(external_clients, Config) ->
    {Cert, Key} = read_certs(),
    %% Not linked: this process ends with the group's init, the relay
    %% must outlive it as the owner of every server-side connection.
    Relay = spawn(fun() -> relay(undefined) end),
    {ok, _} = quic_h3:start_server(h3_goaway_interop, ?SERVER_PORT, #{
        cert => Cert,
        key => Key,
        handler => fun handle/5,
        connection_handler => fun(_Conn) -> #{owner => Relay} end
    }),
    [{relay, Relay} | Config];
init_per_group(external_servers, Config) ->
    Config.

end_per_group(external_clients, Config) ->
    quic_h3:stop_server(h3_goaway_interop),
    exit(?config(relay, Config), kill),
    ok;
end_per_group(external_servers, _Config) ->
    ok.

%% Each case hears the server-side events raised while it runs.
init_per_testcase(_Case, Config) ->
    case ?config(relay, Config) of
        undefined -> ok;
        Relay -> Relay ! {attach, self()}
    end,
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

%%====================================================================
%% Our server, their client
%%====================================================================

%% aioquic answers the GOAWAY with its own, by hand, and reads the rest
%% of the response. Our server reports both GOAWAYs and stays up for it.
aioquic_client_answers_goaway(_Config) ->
    OutDir = output_dir(),
    {Code, Output} = run_client(
        "aioquic-h3-client",
        io_lib:format("-v ~s:/tmp/output", [OutDir]),
        io_lib:format("--insecure --goaway --output-dir /tmp/output ~s", [url("/goaway")])
    ),
    log_run("aioquic", Code, Output),
    ?assertEqual(0, Code),
    ?assert(contains(Output, "GOAWAY sent")),
    ?assertEqual({ok, ?BODY}, file:read_file(filename:join(OutDir, "goaway"))),
    ?assertMatch({goaway_sent, 4}, await_server(goaway_sent)),
    ?assertEqual({goaway, 0}, await_server(goaway)),
    ?assertEqual({closed, normal}, await_server(closed)).

%% quic-go validates our GOAWAY identifier, finishes the request in
%% flight and sends no more requests on that connection: the second one
%% arrives on a new connection, which our server reports as a second
%% `connected'. quic-go never sends a GOAWAY of its own.
quic_go_client_drains_after_goaway(_Config) ->
    {Code, Output} = run_client(
        "quic-go-h3-client", "", io_lib:format("~s ~s", [url("/goaway"), url("/second")])
    ),
    log_run("quic-go", Code, Output),
    ?assertEqual(0, Code),
    ?assert(contains(Output, "url=1 status=200 body=partial and done")),
    ?assert(contains(Output, "url=2 status=200 body=ok")),
    ?assertEqual(connected, await_server(connected)),
    ?assertMatch({goaway_sent, 4}, await_server(goaway_sent)),
    ?assertEqual({closed, normal}, await_server(closed)),
    ?assertEqual(connected, await_server(connected)).

%% quiche validates our GOAWAY identifier and answers with its own.
%%
%% Not run under Docker Desktop for macOS: its host-network emulation
%% can change the source address it presents for our packets part way
%% through a connection, and quiche drops a server packet from a new
%% address as a forbidden migration. The same client against the same
%% server completes every run when either side is outside Docker.
quiche_client_answers_goaway(_Config) ->
    case os:type() of
        {unix, darwin} ->
            {skip, "Docker Desktop host networking rewrites our source address mid-connection"};
        _ ->
            quiche_client_run()
    end.

quiche_client_run() ->
    {Code, Output} = run_client("quiche-h3-client", "", url("/goaway")),
    log_run("quiche", Code, Output),
    ?assertEqual(0, Code),
    ?assert(contains(Output, "GOAWAY id=4")),
    ?assert(contains(Output, "GOAWAY sent")),
    ?assert(contains(Output, "status=200")),
    ?assert(contains(Output, "body=partial and done")),
    ?assertMatch({goaway_sent, 4}, await_server(goaway_sent)),
    ?assertEqual({goaway, 0}, await_server(goaway)),
    ?assertEqual({closed, normal}, await_server(closed)).

%%====================================================================
%% Their server, our client
%%====================================================================

goaway_from_aioquic_server(_Config) ->
    with_peer(
        os:getenv("QUIC_AIOQUIC_HOST", "127.0.0.1"),
        list_to_integer(os:getenv("QUIC_AIOQUIC_H3_PORT", "4435")),
        fun(Host, Port) -> goaway_exchange(Host, Port, <<"/goaway">>) end
    ).

goaway_from_quic_go_server(_Config) ->
    with_peer(
        os:getenv("QUIC_QUICGO_HOST", "127.0.0.1"),
        list_to_integer(os:getenv("QUIC_QUICGO_H3_GOAWAY_PORT", "4440")),
        fun(Host, Port) -> goaway_exchange(Host, Port, <<"/goaway">>) end
    ).

goaway_from_quiche_server(_Config) ->
    with_peer(
        os:getenv("QUIC_QUICHE_HOST", "127.0.0.1"),
        list_to_integer(os:getenv("QUIC_QUICHE_H3_GOAWAY_PORT", "4441")),
        fun(Host, Port) -> goaway_exchange(Host, Port, <<"/">>) end
    ).

%% The server sends GOAWAY while our request is in flight. We answer with
%% our own, the response still completes, a new request is refused, and
%% the connection closes normally once drained: no ID error either way.
goaway_exchange(Host, Port, Path) ->
    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false, sync => true}),
    {ok, StreamId} = quic_h3:request(Conn, [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, Path},
        {<<":authority">>, list_to_binary(Host)}
    ]),
    {Before, GoawayId} = until_goaway(Conn, []),
    %% A server names a client request stream beyond the one in flight.
    ?assertEqual(0, GoawayId rem 4),
    ?assert(GoawayId > StreamId),
    ok = quic_h3:goaway(Conn),
    ?assertEqual({error, goaway_received}, quic_h3:request(Conn, [{<<":method">>, <<"GET">>}])),
    After = until_closed(Conn, []),
    Events = Before ++ After,
    ct:pal("events: ~p", [Events]),
    ?assertEqual([{goaway_sent, 0}], [E || {goaway_sent, _} = E <- Events]),
    ?assertMatch([{response, StreamId, 200, _}], [E || {response, _, _, _} = E <- Events]),
    ?assertEqual(
        ?BODY, iolist_to_binary([D || {data, S, D, _} <- Events, S =:= StreamId])
    ),
    ?assertEqual([true], [Fin || {data, S, _, Fin} <- Events, S =:= StreamId, Fin]),
    ?assertEqual([], [E || {error, _, _} = E <- Events]),
    ?assertEqual({closed, normal}, lists:last(Events)).

until_goaway(Conn, Acc) ->
    case next(Conn) of
        {goaway, Id} -> {lists:reverse(Acc), Id};
        timeout -> ct:fail({no_goaway, lists:reverse(Acc)});
        {closed, _} = Closed -> ct:fail({closed_before_goaway, lists:reverse([Closed | Acc])});
        Event -> until_goaway(Conn, [Event | Acc])
    end.

until_closed(Conn, Acc) ->
    case next(Conn) of
        {closed, _} = Closed -> lists:reverse([Closed | Acc]);
        timeout -> ct:fail({not_closed, lists:reverse(Acc)});
        Event -> until_closed(Conn, [Event | Acc])
    end.

next(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> next(Conn);
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> timeout
    end.

with_peer(Host, Port, F) ->
    case quic_test_peer:reachable(Host, Port) of
        true -> F(Host, Port);
        false -> {skip, io_lib:format("no server at ~s:~p", [Host, Port])}
    end.

%%====================================================================
%% Our server's handler and owner relay
%%====================================================================

%% GOAWAY, then a response whose body ends half a second later, so the
%% client holds the GOAWAY while its request is still in flight.
handle(Conn, StreamId, <<"GET">>, <<"/goaway">>, _Headers) ->
    ok = quic_h3:goaway(Conn),
    ok = quic_h3:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
    ok = quic_h3:send_data(Conn, StreamId, <<"partial">>, false),
    timer:sleep(500),
    Result = quic_h3:send_data(Conn, StreamId, <<" and done">>, true),
    ct:pal("server handler: final send_data on stream ~p -> ~p", [StreamId, Result]),
    Result;
handle(Conn, StreamId, _Method, _Path, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<"ok">>, true).

%% Owner of every server-side connection; forwards their events to the
%% attached test case and drops what arrives between cases.
relay(Target) ->
    receive
        {attach, Pid} -> relay(Pid);
        {quic_h3, _Conn, Event} when is_pid(Target) -> Target ! {server_owner, Event};
        _ -> ok
    end,
    relay(Target).

%% The client's exit code and output, with what our server reported so
%% far, so a failed run can be read from the log.
log_run(Client, Code, Output) ->
    timer:sleep(200),
    ct:pal("~s client exit ~p:~n~s~nserver events so far: ~p", [
        Client, Code, Output, peek_server_events()
    ]).

peek_server_events() ->
    {messages, Messages} = process_info(self(), messages),
    [Event || {server_owner, Event} <- Messages].

%% The next server-side event of the given kind, skipping the others.
await_server(Tag) ->
    receive
        {server_owner, Tag} -> Tag;
        {server_owner, Event} when is_tuple(Event), element(1, Event) =:= Tag -> Event
    after ?WAIT_MS -> {Tag, timeout}
    end.

%%====================================================================
%% Docker
%%====================================================================

build_client_images() ->
    Cmd = io_lib:format(
        "cd ~s && docker compose --profile tools build "
        "aioquic-h3-client quic-go-h3-client quiche-h3-client 2>&1",
        [docker_dir()]
    ),
    case exec_cmd(Cmd, 900000) of
        {0, _} -> ok;
        {Status, Output} -> ct:fail({client_image_build_failed, Status, Output})
    end.

%% Runs one client container against our server and returns its exit
%% code and output.
run_client(Service, RunArgs, ClientArgs) ->
    Cmd = io_lib:format(
        "cd ~s && docker compose run --rm ~s ~s ~s 2>&1",
        [docker_dir(), RunArgs, Service, ClientArgs]
    ),
    ct:pal("Running: ~s", [Cmd]),
    exec_cmd(Cmd, 60000).

url(Path) ->
    io_lib:format("https://~s:~p~s", [client_host(), ?SERVER_PORT, Path]).

%% Where a client container finds our server. Docker Desktop for macOS
%% emulates host networking and rewrites the source address of replies
%% from 127.0.0.1, which quiche drops as coming from an unknown address;
%% the host's own name gives a stable address.
client_host() ->
    case os:type() of
        {unix, darwin} -> "host.docker.internal";
        _ -> "127.0.0.1"
    end.

contains(Output, Needle) ->
    string:find(Output, Needle) =/= nomatch.

%% A new directory per run, never reused: on Docker Desktop for macOS a
%% container cannot create a file at a path the host just deleted.
output_dir() ->
    Dir = filename:join(
        "/tmp",
        "quic_h3_goaway_interop_" ++ integer_to_list(erlang:system_time(microsecond))
    ),
    ok = file:make_dir(Dir),
    Dir.

read_certs() ->
    Dir = filename:join(project_root(), "certs"),
    {ok, CertPem} = file:read_file(filename:join(Dir, "cert.pem")),
    {ok, KeyPem} = file:read_file(filename:join(Dir, "priv.key")),
    [{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(CertPem),
    [KeyEntry] = public_key:pem_decode(KeyPem),
    {Cert, public_key:pem_entry_decode(KeyEntry)}.

docker_dir() ->
    filename:join(project_root(), "docker").

project_root() ->
    filename:dirname(filename:dirname(filename:absname(?FILE))).

%% Through sh -c rather than {spawn, Cmd}: the command starts with cd, a
%% shell builtin that dash will not exec.
exec_cmd(Cmd, Timeout) ->
    Port = open_port(
        {spawn_executable, "/bin/sh"},
        [{args, ["-c", lists:flatten(Cmd)]}, exit_status, binary, stderr_to_stdout, {line, 4096}]
    ),
    exec_cmd_loop(Port, [], Timeout).

exec_cmd_loop(Port, Acc, Timeout) ->
    receive
        {Port, {data, {_Eol, Line}}} ->
            exec_cmd_loop(Port, [Line | Acc], Timeout);
        {Port, {exit_status, Status}} ->
            {Status, binary_to_list(iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Acc))))}
    after Timeout ->
        try
            port_close(Port)
        catch
            _:_ -> ok
        end,
        {timeout, binary_to_list(iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Acc))))}
    end.
