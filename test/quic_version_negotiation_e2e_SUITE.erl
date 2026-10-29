%%% -*- erlang -*-
%%%
%%% RFC 9368 compatible version negotiation end to end: a client that
%%% starts in v1 and also accepts v2 ends up in v2 when the server
%%% prefers it, and stays in v1 otherwise.

-module(quic_version_negotiation_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    client_offering_v2_switches/1,
    client_without_versions_stays_v1/1,
    server_without_v2_stays_v1/1
]).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        client_offering_v2_switches,
        client_without_versions_stays_v1,
        server_without_v2_stays_v1
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

client_offering_v2_switches(_Config) ->
    ?assertEqual(
        ?QUIC_VERSION_2,
        negotiated(
            #{versions => [?QUIC_VERSION_2, ?QUIC_VERSION_1]},
            #{versions => [?QUIC_VERSION_2, ?QUIC_VERSION_1]}
        )
    ).

client_without_versions_stays_v1(_Config) ->
    ?assertEqual(
        ?QUIC_VERSION_1,
        negotiated(#{versions => [?QUIC_VERSION_2, ?QUIC_VERSION_1]}, #{})
    ).

server_without_v2_stays_v1(_Config) ->
    ?assertEqual(
        ?QUIC_VERSION_1,
        negotiated(
            #{versions => [?QUIC_VERSION_1]},
            #{versions => [?QUIC_VERSION_2, ?QUIC_VERSION_1]}
        )
    ).

negotiated(ServerOpts, ClientOpts) ->
    {ok, #{port := Port} = Server} = quic_test_echo_server:start(ServerOpts),
    try
        Opts = maps:merge(#{verify => false, alpn => [<<"echo">>]}, ClientOpts),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 ->
            quic:safe_close(Conn, timeout),
            ct:fail("connection timeout")
        end,
        ok = echo(Conn, <<"version negotiation">>),
        {connected, #{version := Version}} = quic_connection:get_state(Conn),
        quic:close(Conn, normal),
        Version
    after
        quic_test_echo_server:stop(Server)
    end.

echo(Conn, Payload) ->
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, Payload, true),
    receive
        {quic, Conn, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 10000 ->
        ct:fail("echo timeout")
    end.
