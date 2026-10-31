%%% -*- erlang -*-
%%%
%%% A client moving to the server's preferred address.
%%%
%%% The preferred address is on a port of its own, as the Interop
%%% Runner's connectionmigration case has it. The listener has to
%%% receive there, route the preferred CID to the connection and answer
%%% from that port, or the client's probe goes unanswered and it stays
%%% on the address it connected to.

-module(quic_preferred_address_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([client_moves_to_the_preferred_address/1]).

-define(CONNECT_MS, 10000).
-define(MIGRATE_MS, 10000).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [client_moves_to_the_preferred_address].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

client_moves_to_the_preferred_address(_Config) ->
    Preferred = {{127, 0, 0, 1}, free_port()},
    {ok, Server} = quic_test_echo_server:start(#{preferred_ipv4 => Preferred}),
    try
        Port = maps:get(port, Server),
        {ok, Conn} = quic:connect(
            <<"127.0.0.1">>,
            Port,
            maps:merge(quic_test_echo_server:client_opts(), #{verify => false, alpn => [<<"echo">>]}),
            self()
        ),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout")
        end,
        ?assertEqual({ok, Preferred}, wait_for_peer(Conn, Preferred, ?MIGRATE_MS)),
        echo_roundtrip(Conn),
        %% The client takes packets from the old address as well, so only
        %% the server shows it followed: it sends from the preferred socket.
        {ok, [ServerConn | _]} = quic:get_server_connections(maps:get(name, Server)),
        {connected, #state{mig = #mig{main_sock = MainSock}}} = sys:get_state(ServerConn),
        ?assertNotEqual(undefined, MainSock),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

free_port() ->
    {ok, S} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(S),
    gen_udp:close(S),
    Port.

wait_for_peer(Conn, Want, Budget) when Budget > 0 ->
    case quic:peername(Conn) of
        {ok, Want} ->
            {ok, Want};
        _ ->
            timer:sleep(50),
            wait_for_peer(Conn, Want, Budget - 50)
    end;
wait_for_peer(Conn, _Want, _Budget) ->
    quic:peername(Conn).

echo_roundtrip(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = <<"preferred path">>,
    ok = quic:send_data(Conn, StreamId, Payload, true),
    ?assertEqual(Payload, collect_echo(Conn, StreamId, <<>>)).

collect_echo(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_echo(Conn, StreamId, <<Acc/binary, Data/binary>>);
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Acc)
    after 5000 -> Acc
    end.
