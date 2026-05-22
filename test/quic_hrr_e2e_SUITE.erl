%%% -*- erlang -*-
%%%
%%% HelloRetryRequest end-to-end suite (RFC 8446 §4.1.4).
%%%
%%% Drives full handshakes where the server's preferred key-exchange
%%% group differs from the group the client sent a key_share for,
%%% forcing an HRR + CH2 retry. Also covers the failure modes.

-module(quic_hrr_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    hrr_secp256r1/1,
    no_common_group/1,
    psk_plus_hrr_aborts/1
]).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [hrr_secp256r1, no_common_group, psk_plus_hrr_aborts].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Tests
%%====================================================================

%% Server prefers secp256r1 only; client offers [x25519, secp256r1]
%% with a key_share for x25519. Server must HRR, client retries with
%% secp256r1, handshake completes and data echoes.
hrr_secp256r1(_Config) ->
    {ok, Server} = start_echo(#{groups => [secp256r1]}),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => [x25519, secp256r1]
        },
        ConnRef = connect(Server, Opts),
        Info = wait_connected(ConnRef),
        ?assertEqual(secp256r1, maps:get(negotiated_group, Info)),
        ok = echo(ConnRef, <<"hrr works">>),
        quic:close(ConnRef, normal)
    after
        stop_echo(Server)
    end.

%% Server only supports secp384r1; client offers only x25519. No
%% group intersection at all → handshake fails.
no_common_group(_Config) ->
    {ok, Server} = start_echo(#{groups => [secp384r1]}),
    try
        Opts = #{verify => false, alpn => [<<"echo">>], groups => [x25519]},
        ?assertMatch({error, _}, try_connect(Server, Opts))
    after
        stop_echo(Server)
    end.

%% Client offers external_psk AND a group set that forces HRR. Per
%% the v1 rule the client aborts when HRR follows a PSK ClientHello.
psk_plus_hrr_aborts(_Config) ->
    Identity = <<"id">>,
    Secret = <<"this-is-a-32-byte-test-secret!!!">>,
    {ok, Server} = start_echo(#{
        groups => [secp256r1],
        psks => #{Identity => Secret},
        with_cert => true
    }),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => [x25519, secp256r1],
            external_psk => {Identity, Secret}
        },
        ?assertMatch({error, _}, try_connect(Server, Opts))
    after
        stop_echo(Server)
    end.

%%====================================================================
%% Helpers
%%====================================================================

start_echo(Extra0) ->
    WithCert = maps:get(with_cert, Extra0, true),
    Extra = maps:remove(with_cert, Extra0),
    case WithCert of
        true -> quic_test_echo_server:start(Extra);
        false -> quic_test_echo_server:start(Extra)
    end.

stop_echo(Server) ->
    quic_test_echo_server:stop(Server).

connect(#{port := Port}, Opts) ->
    {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ConnRef.

wait_connected(ConnRef) ->
    receive
        {quic, ConnRef, {connected, Info}} -> Info
    after 10000 ->
        catch quic:close(ConnRef, timeout),
        ct:fail("connection timeout")
    end.

try_connect(#{port := Port}, Opts) ->
    case quic:connect(<<"127.0.0.1">>, Port, Opts, self()) of
        {error, _} = E ->
            E;
        {ok, ConnRef} ->
            receive
                {quic, ConnRef, {connected, _}} ->
                    quic:close(ConnRef, normal),
                    ok;
                {quic, ConnRef, {error, R}} ->
                    {error, R};
                {quic, ConnRef, {closed, R}} ->
                    {error, R}
            after 10000 ->
                catch quic:close(ConnRef, timeout),
                {error, timeout}
            end
    end.

echo(ConnRef, Payload) ->
    {ok, StreamId} = quic:open_stream(ConnRef),
    ok = quic:send_data(ConnRef, StreamId, Payload, true),
    receive
        {quic, ConnRef, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 10000 ->
        ct:fail("echo timeout")
    end.
