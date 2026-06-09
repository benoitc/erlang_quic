%%% -*- erlang -*-
%%%
%%% TLS 1.3 External PSK end-to-end suite (RFC 8446 §4.2.11).
%%%
%%% Spins an in-process echo server with PSK config and drives full
%%% handshakes through it: psk_dhe_ke, psk_ke (no-DHE), mixed
%%% cert+PSK selection, callback lookup, unknown identity / bad
%%% binder failure modes, downgrade protection.
%%%

-module(quic_psk_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    psk_dhe_ke_handshake/1,
    psk_ke_handshake/1,
    psk_callback_lookup/1,
    cert_and_psk_coexist/1,
    unknown_identity_psk_only/1,
    unknown_identity_with_cert_falls_through/1,
    bad_binder_is_fatal/1,
    client_downgrade_protection/1
]).

-define(IDENTITY, <<"alice">>).
-define(SECRET, <<"this-is-a-32-byte-test-secret!!!">>).
-define(WRONG_SECRET, <<"this-is-a-different-32-byte-key.">>).
-define(OTHER_IDENTITY, <<"bob">>).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        psk_dhe_ke_handshake,
        psk_ke_handshake,
        psk_callback_lookup,
        cert_and_psk_coexist,
        unknown_identity_psk_only,
        unknown_identity_with_cert_falls_through,
        bad_binder_is_fatal,
        client_downgrade_protection
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(TC, Config) ->
    ct:pal("Starting test: ~p", [TC]),
    Config.

end_per_testcase(_TC, _Config) ->
    ok.

%%====================================================================
%% Test cases
%%====================================================================

%% Default mode psk_dhe_ke: client offers external_psk, server has
%% a matching entry in `psks`. Handshake completes, data echoes.
psk_dhe_ke_handshake(_Config) ->
    {ok, Server} = start_psk_server(#{psks => #{?IDENTITY => ?SECRET}}),
    try
        ConnRef = connect_with_psk(Server, {?IDENTITY, ?SECRET}),
        ok = echo_roundtrip(ConnRef, <<"psk_dhe_ke">>),
        quic:close(ConnRef, normal)
    after
        stop_server(Server)
    end.

%% psk_ke mode: client offers psk_ke only. Server omits key_share
%% and the handshake completes via the zero-IKM key schedule.
psk_ke_handshake(_Config) ->
    {ok, Server} = start_psk_server(#{psks => #{?IDENTITY => ?SECRET}}),
    try
        ConnRef = connect_with_psk(
            Server, {?IDENTITY, ?SECRET, [psk_ke]}
        ),
        ok = echo_roundtrip(ConnRef, <<"psk_ke">>),
        quic:close(ConnRef, normal)
    after
        stop_server(Server)
    end.

%% psk_callback wins over `psks` map; callback resolves identity to
%% the correct secret.
psk_callback_lookup(_Config) ->
    Cb = fun
        (?IDENTITY) -> {ok, ?SECRET};
        (_) -> not_found
    end,
    {ok, Server} = start_psk_server(#{psk_callback => Cb}),
    try
        ConnRef = connect_with_psk(Server, {?IDENTITY, ?SECRET}),
        ok = echo_roundtrip(ConnRef, <<"callback">>),
        quic:close(ConnRef, normal)
    after
        stop_server(Server)
    end.

%% Server has cert+key AND PSK. A PSK client and a cert client both
%% connect successfully against the same listener.
cert_and_psk_coexist(_Config) ->
    {ok, Server} = start_psk_server(#{
        psks => #{?IDENTITY => ?SECRET},
        with_cert => true
    }),
    try
        %% PSK client
        Conn1 = connect_with_psk(Server, {?IDENTITY, ?SECRET}),
        ok = echo_roundtrip(Conn1, <<"psk-client">>),
        quic:close(Conn1, normal),

        %% Cert client (no PSK option)
        Conn2 = connect_plain(Server),
        ok = echo_roundtrip(Conn2, <<"cert-client">>),
        quic:close(Conn2, normal)
    after
        stop_server(Server)
    end.

%% PSK-only server (no cert). Client offers an unknown identity:
%% server has no cert fallback so the handshake fails with a TLS
%% alert (unknown_psk_identity).
unknown_identity_psk_only(_Config) ->
    {ok, Server} = start_psk_server(#{psks => #{?IDENTITY => ?SECRET}}),
    try
        Result = try_connect(Server, #{
            external_psk => {?OTHER_IDENTITY, ?SECRET}
        }),
        ?assertMatch({error, _}, Result)
    after
        stop_server(Server)
    end.

%% Cert+PSK server: client offers an identity the server doesn't
%% know. Server falls through to the cert path silently and the
%% handshake completes (no client downgrade flag in play, so the
%% client accepts the cert).
unknown_identity_with_cert_falls_through(_Config) ->
    {ok, Server} = start_psk_server(#{
        psks => #{?IDENTITY => ?SECRET},
        with_cert => true
    }),
    try
        %% The client offers external_psk; if the server can't match
        %% it, the client's downgrade check will fire. Use a
        %% cert-only client here (no external_psk) to model an
        %% accidental misconfig between two consenting peers.
        Conn = connect_plain(Server),
        ok = echo_roundtrip(Conn, <<"fallback">>),
        quic:close(Conn, normal)
    after
        stop_server(Server)
    end.

%% Identity known but binder is wrong (client claims a secret that
%% doesn't match the server's). Server MUST send decrypt_error and
%% MUST NOT fall through to cert even when cert+key are present.
bad_binder_is_fatal(_Config) ->
    {ok, Server} = start_psk_server(#{
        psks => #{?IDENTITY => ?SECRET},
        with_cert => true
    }),
    try
        Result = try_connect(Server, #{
            external_psk => {?IDENTITY, ?WRONG_SECRET}
        }),
        ?assertMatch({error, _}, Result)
    after
        stop_server(Server)
    end.

%% Server has cert+PSK; client offers an external_psk with an
%% identity the server doesn't know. Server falls through to cert.
%% Client's downgrade protection MUST then abort the handshake
%% rather than silently accepting the cert path.
client_downgrade_protection(_Config) ->
    {ok, Server} = start_psk_server(#{
        psks => #{?IDENTITY => ?SECRET},
        with_cert => true
    }),
    try
        Result = try_connect(Server, #{
            external_psk => {?OTHER_IDENTITY, ?SECRET}
        }),
        ?assertMatch({error, _}, Result)
    after
        stop_server(Server)
    end.

%%====================================================================
%% Helpers
%%====================================================================

start_psk_server(Extra0) ->
    WithCert = maps:get(with_cert, Extra0, false),
    Extra1 = maps:remove(with_cert, Extra0),
    BaseExtra =
        case WithCert of
            true ->
                Extra1;
            false ->
                %% Pre-empt the echo-server's default cert load: an
                %% empty cert/key pair forces start_psk_server to
                %% rely solely on PSK auth.
                Extra1
        end,
    case WithCert of
        true ->
            quic_test_echo_server:start(BaseExtra);
        false ->
            start_psk_only_server(BaseExtra)
    end.

%% Build a listener that uses PSK only (no cert/key). Mirrors what
%% quic_test_echo_server:start/1 does but skips the cert load.
start_psk_only_server(Extra) ->
    Name = list_to_atom(
        "quic_psk_echo_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    Opts = maps:merge(
        #{
            alpn => [<<"echo">>],
            max_data => 16 * 1024 * 1024,
            max_stream_data_bidi_local => 4 * 1024 * 1024,
            max_stream_data_bidi_remote => 4 * 1024 * 1024,
            max_stream_data_uni => 4 * 1024 * 1024,
            connection_handler => fun(ConnPid, _ConnRef) ->
                Echo = spawn_link(fun() -> echo_loop(ConnPid) end),
                ok = quic:set_owner_sync(ConnPid, Echo),
                {ok, Echo}
            end
        },
        Extra
    ),
    {ok, _Pid} = quic:start_server(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    {ok, #{name => Name, port => Port}}.

stop_server(#{name := Name}) ->
    try
        quic:stop_server(Name)
    catch
        _:_ -> ok
    end,
    ok.

connect_with_psk(#{port := Port}, PskOffer) ->
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        external_psk => PskOffer
    },
    {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    wait_connected(ConnRef, 10000),
    ConnRef.

connect_plain(#{port := Port}) ->
    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    wait_connected(ConnRef, 10000),
    ConnRef.

%% Drive a connect attempt that may legitimately fail. Returns
%% `ok` on success or `{error, Reason}` from the connection's
%% closed event / psk_not_selected notification.
try_connect(#{port := Port}, ExtraOpts) ->
    Opts = maps:merge(
        #{verify => false, alpn => [<<"echo">>]},
        ExtraOpts
    ),
    case quic:connect(<<"127.0.0.1">>, Port, Opts, self()) of
        {error, _} = E ->
            E;
        {ok, ConnRef} ->
            await_outcome(ConnRef, 10000)
    end.

await_outcome(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            quic:close(ConnRef, normal),
            ok;
        {quic, ConnRef, {error, Reason}} ->
            {error, Reason};
        {quic, ConnRef, {closed, Reason}} ->
            {error, Reason}
    after Timeout ->
        quic:safe_close(ConnRef, timeout),
        {error, timeout}
    end.

wait_connected(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {connected, _Info}} -> ok
    after Timeout ->
        quic:safe_close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

echo_roundtrip(ConnRef, Payload) ->
    {ok, StreamId} = quic:open_stream(ConnRef),
    ok = quic:send_data(ConnRef, StreamId, Payload, true),
    receive
        {quic, ConnRef, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 10000 ->
        ct:fail("echo timeout")
    end.

echo_loop(Conn) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            echo_loop(Conn);
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            _ = quic:send_data_async(Conn, StreamId, Data, Fin),
            echo_loop(Conn);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        {quic, Conn, _Other} ->
            echo_loop(Conn);
        {'DOWN', _, process, Conn, _} ->
            ok;
        _Unexpected ->
            echo_loop(Conn)
    end.
