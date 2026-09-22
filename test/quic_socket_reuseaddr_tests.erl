%%% -*- erlang -*-
%%%
%%% SO_REUSEADDR belongs to a listener on a fixed port, nowhere else.
%%%
%%% With the option set, the kernel treats a port held by another
%%% SO_REUSEADDR socket as free when it autobinds, so two sockets can end
%%% up on one port and every datagram for it goes to one of them. The
%%% other connection then sends its ClientHello and its probes into
%%% silence. Client sockets are always ephemeral, so they must never set
%%% it, and a listener on port 0 gains nothing from it either.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_socket_reuseaddr_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Option lists
%%====================================================================

listener_opts_set_reuseaddr_on_a_fixed_port_test() ->
    ?assertEqual(true, reuseaddr_opt(quic_socket:build_genudp_opts(4433, #{}))),
    ?assertEqual(false, reuseaddr_opt(quic_socket:build_genudp_opts(0, #{}))).

client_opts_never_set_reuseaddr_test() ->
    ?assertEqual(undefined, reuseaddr_opt(quic_socket:build_send_genudp_opts(inet, #{}))).

%%====================================================================
%% Client sockets
%%====================================================================

client_gen_udp_socket_has_no_reuseaddr_test() ->
    with_client(gen_udp, fun(State) ->
        ?assertEqual(false, reuseaddr_of(quic_socket:get_socket(State)))
    end).

client_socket_backend_has_no_reuseaddr_test() ->
    with_client(socket, fun(State) ->
        ?assertEqual(false, reuseaddr_of(quic_socket:get_socket(State)))
    end).

%% Nothing else can take the port a client is using, which is what the
%% kernel guarantees for a socket that did not ask to share.
client_port_is_exclusive_test() ->
    with_client(gen_udp, fun(State) ->
        {ok, {_Addr, Port}} = quic_socket:sockname(State),
        ?assert(Port > 0),
        ?assertEqual(
            {error, eaddrinuse},
            gen_udp:open(Port, [binary, {active, false}, {reuseaddr, true}])
        )
    end).

%% The property that broke: every client gets a port of its own.
client_ports_are_distinct_test() ->
    States = [open_client(gen_udp) || _ <- lists:seq(1, 64)],
    try
        Ports = [Port || State <- States, {ok, {_Addr, Port}} <- [quic_socket:sockname(State)]],
        ?assertEqual(64, length(lists:usort(Ports)))
    after
        [quic_socket:close(State) || State <- States]
    end.

%%====================================================================
%% Listener sockets
%%====================================================================

listener_on_an_ephemeral_port_has_no_reuseaddr_test() ->
    with_listener(0, fun(Listener) ->
        ?assertEqual(false, reuseaddr_of(listener_socket(Listener)))
    end).

listener_on_a_fixed_port_keeps_reuseaddr_test() ->
    with_listener(free_port(), fun(Listener) ->
        ?assertEqual(true, reuseaddr_of(listener_socket(Listener)))
    end).

listener_ephemeral_ports_are_distinct_test() ->
    with_listener(0, fun(First) ->
        with_listener(0, fun(Second) ->
            ?assertNotEqual(quic_listener:get_port(First), quic_listener:get_port(Second))
        end)
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% The socket backend binds only when a source address is given, so its
%% port is assigned by the kernel on the first send. gen_udp binds at
%% open; sending anyway keeps both backends on one path.
with_client(Backend, F) ->
    State = open_client(Backend),
    try
        F(State)
    after
        quic_socket:close(State)
    end.

open_client(Backend) ->
    {ok, State} = quic_socket:open_for_send({127, 0, 0, 1}, #{
        backend => Backend, batching => #{enabled => false}
    }),
    %% Discard port (RFC 863), so nothing answers.
    {ok, Sent} = quic_socket:send(State, {127, 0, 0, 1}, 9, <<0>>),
    Sent.

with_listener(Port, F) ->
    {ok, Listener} = quic_listener:start_link(Port, listener_opts()),
    try
        F(Listener)
    after
        quic_listener:stop(Listener)
    end.

listener_opts() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    #{cert => Cert, key => Key, alpn => [<<"h3">>]}.

listener_socket(Listener) ->
    #{socket := Socket} = gen_server:call(Listener, get_socket_info),
    Socket.

%% A port no one holds right now. The listener takes it straight after.
free_port() ->
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_udp:close(Socket),
    Port.

reuseaddr_of({'$socket', _} = Socket) ->
    {ok, Value} = socket:getopt(Socket, {socket, reuseaddr}),
    Value;
reuseaddr_of(Socket) when is_port(Socket) ->
    {ok, [{reuseaddr, Value}]} = inet:getopts(Socket, [reuseaddr]),
    Value.

reuseaddr_opt(Opts) ->
    proplists:get_value(reuseaddr, Opts, undefined).
