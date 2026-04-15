%%% -*- erlang -*-
%%%
%%% Regression + coverage for the H3 server owner wiring.
%%%
%%% `quic_h3:start_server/3' used to capture `self()' as the default
%%% owner pid for H3 connections. When the caller was a transient
%%% process (spawned helper, init_per_suite), the owner pid would be
%%% dead by the time a client arrived, tripping the
%%% `monitor(process, Owner)' in `quic_h3_connection:init/1' and
%%% transitioning the server's H3 fsm to `closing' before SETTINGS
%%% could flow. Clients saw `connect_timeout'.
%%%
%%% Two cases:
%%%   1. Transient caller + `h3_datagram_enabled => true' — verifies a
%%%      dead start_server caller no longer wedges client handshakes.
%%%   2. Per-conn `connection_handler' hook supplying `owner => Pid' —
%%%      verifies datagrams route to the explicit owner.

-module(quic_h3_owner_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    transient_caller_with_datagram_flag/1,
    custom_owner_receives_datagram/1
]).

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [transient_caller_with_datagram_flag, custom_owner_receives_datagram].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = load_certs(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Test cases
%%====================================================================

%% A process that called start_server and exited must not kill the
%% server's ability to accept new connections when the H3 datagram
%% extension is enabled.
transient_caller_with_datagram_flag(Config) ->
    Cert = ?config(cert, Config),
    Key = ?config(key, Config),
    Name = unique_name("h3_owner_transient"),

    Parent = self(),
    Spawner = spawn(fun() ->
        {ok, _} = quic_h3:start_server(Name, 0, #{
            cert => Cert,
            key => Key,
            handler => fun handle_hello/5,
            h3_datagram_enabled => true
        }),
        {ok, P} = quic:get_server_port(Name),
        Parent ! {port, P}
    end),
    Ref = monitor(process, Spawner),
    Port =
        receive
            {port, P} -> P
        after 5000 -> ct:fail(start_server_timeout)
        end,
    receive
        {'DOWN', Ref, process, Spawner, _} -> ok
    after 2000 -> ct:fail(spawner_did_not_exit)
    end,
    false = is_process_alive(Spawner),

    try
        {200, <<"hello">>} = do_get(Port)
    after
        catch quic_h3:stop_server(Name)
    end,
    ok.

%% With `connection_handler => fun(_) -> #{owner => Parent} end', an
%% H3 datagram sent by the client must reach Parent as
%% `{quic_h3, _, {datagram, StreamId, Payload}}'.
custom_owner_receives_datagram(Config) ->
    Cert = ?config(cert, Config),
    Key = ?config(key, Config),
    Name = unique_name("h3_owner_explicit"),

    Parent = self(),
    Hook = fun(_ConnPid) -> #{owner => Parent} end,
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        handler => fun handle_hello/5,
        h3_datagram_enabled => true,
        connection_handler => Hook
    }),
    {ok, Port} = quic:get_server_port(Name),

    try
        {ok, Conn} = quic_h3:connect("localhost", Port, #{
            verify => false,
            sync => true,
            h3_datagram_enabled => true
        }),
        Headers = [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/">>},
            {<<":authority">>, <<"localhost">>}
        ],
        {ok, StreamId} = quic_h3:request(Conn, Headers),
        {200, <<"hello">>} = recv_response(Conn, StreamId, 5000),

        Payload = <<"ping-payload">>,
        ok = quic_h3:send_datagram(Conn, StreamId, Payload),

        receive
            {quic_h3, _H3Conn, {datagram, StreamId, Payload}} -> ok
        after 3000 ->
            ct:fail(datagram_not_received_by_explicit_owner)
        end,

        quic_h3:close(Conn)
    after
        catch quic_h3:stop_server(Name)
    end,
    ok.

%%====================================================================
%% Helpers
%%====================================================================

handle_hello(Conn, StreamId, _Method, _Path, _Headers) ->
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"text/plain">>}
    ]),
    quic_h3:send_data(Conn, StreamId, <<"hello">>, true).

do_get(Port) ->
    {ok, Conn} = quic_h3:connect("localhost", Port, #{verify => false, sync => true}),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    Result = recv_response(Conn, StreamId, 5000),
    quic_h3:close(Conn),
    Result.

recv_response(Conn, StreamId, Timeout) ->
    recv_response(Conn, StreamId, Timeout, undefined, <<>>).

recv_response(Conn, StreamId, Timeout, Status, Acc) ->
    receive
        {quic_h3, Conn, {response, StreamId, S, _}} ->
            recv_response(Conn, StreamId, Timeout, S, Acc);
        {quic_h3, Conn, {headers, StreamId, S, _}} ->
            recv_response(Conn, StreamId, Timeout, S, Acc);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {Status, <<Acc/binary, Data/binary>>};
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            recv_response(Conn, StreamId, Timeout, Status, <<Acc/binary, Data/binary>>);
        {quic_h3, Conn, {stream_end, StreamId}} ->
            {Status, Acc}
    after Timeout ->
        ct:fail({response_timeout, StreamId, Status, byte_size(Acc)})
    end.

unique_name(Base) ->
    list_to_atom(Base ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))).

load_certs() ->
    {ok, Cwd} = file:get_cwd(),
    Root = find_root(Cwd),
    CertFile = filename:join([Root, "certs", "cert.pem"]),
    KeyFile = filename:join([Root, "certs", "priv.key"]),
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    [{Type, KeyDer, not_encrypted} | _] = public_key:pem_decode(KeyPem),
    {CertDer, public_key:der_decode(Type, KeyDer)}.

find_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true ->
            Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> error(no_project_root);
                _ -> find_root(Parent)
            end
    end.
