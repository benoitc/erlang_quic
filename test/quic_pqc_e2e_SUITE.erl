%%% -*- erlang -*-
%%%
%%% Post-quantum hybrid key exchange end-to-end suite
%%% (X25519MLKEM768, draft-ietf-tls-ecdhe-mlkem).
%%%
%%% Drives full handshakes negotiating the hybrid group directly and
%%% through a HelloRetryRequest, plus mixed peers where one side is
%%% classical-only, to prove interop is unaffected.
%%%
%%% The whole suite is skipped when the crypto library has no
%%% ML-KEM-768 support (OTP < 28.1 or restricted crypto builds).

-module(quic_pqc_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    hybrid_direct/1,
    classical_client_interop/1,
    hybrid_via_hrr/1,
    hybrid_share_sizes/1,
    unsupported_group_rejected/1
]).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        hybrid_direct,
        classical_client_interop,
        hybrid_via_hrr,
        hybrid_share_sizes,
        unsupported_group_rejected
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    case quic_crypto:group_supported(x25519mlkem768) of
        true ->
            {ok, _} = application:ensure_all_started(quic),
            Config;
        false ->
            {skip, "crypto library has no ML-KEM-768 support"}
    end.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Tests
%%====================================================================

%% Both sides prefer the hybrid group and the client sends its
%% key_share for it: direct negotiation, no HRR, data echoes.
hybrid_direct(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{groups => [x25519mlkem768, x25519]}),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => [x25519mlkem768, x25519]
        },
        ConnRef = connect(Server, Opts),
        Info = wait_connected(ConnRef),
        ?assertEqual(x25519mlkem768, maps:get(negotiated_group, Info)),
        ok = echo(ConnRef, <<"post-quantum echo">>),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

%% A classical-only client against a hybrid-preferring server must
%% keep working: the server uses the client's x25519 share directly.
classical_client_interop(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{groups => [x25519mlkem768, x25519]}),
    try
        Opts = #{verify => false, alpn => [<<"echo">>], groups => [x25519]},
        ConnRef = connect(Server, Opts),
        Info = wait_connected(ConnRef),
        ?assertEqual(x25519, maps:get(negotiated_group, Info)),
        ok = echo(ConnRef, <<"classical still fine">>),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

%% Hybrid-only server, client key_share for x25519 but hybrid in its
%% supported_groups: server sends an HRR for the hybrid group, the
%% client retries with a hybrid share, handshake completes.
hybrid_via_hrr(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{groups => [x25519mlkem768]}),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => [x25519, x25519mlkem768]
        },
        ConnRef = connect(Server, Opts),
        Info = wait_connected(ConnRef),
        ?assertEqual(x25519mlkem768, maps:get(negotiated_group, Info)),
        ok = echo(ConnRef, <<"hybrid after hrr">>),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

%% Wire-format invariants of the hybrid exchange
%% (draft-ietf-tls-ecdhe-mlkem): client share 1216 bytes (ML-KEM
%% encapsulation key || X25519 public), server share 1120 bytes
%% (ciphertext || X25519 public), shared secret 64 bytes (ML-KEM
%% secret || X25519 secret), and both sides derive the same secret.
hybrid_share_sizes(_Config) ->
    {ClientShare, ClientPriv} = quic_crypto:generate_key_pair(x25519mlkem768),
    ?assertEqual(1216, byte_size(ClientShare)),
    {ServerShare, undefined, ServerSecret} =
        quic_crypto:server_key_exchange(x25519mlkem768, ClientShare),
    ?assertEqual(1120, byte_size(ServerShare)),
    ?assertEqual(64, byte_size(ServerSecret)),
    ClientSecret = quic_crypto:compute_shared_secret(
        x25519mlkem768, ClientPriv, ServerShare
    ),
    ?assertEqual(ServerSecret, ClientSecret),
    ok.

%% A group the runtime cannot perform is rejected up front with a
%% clean error from both connect/4 and start_server/3, rather than
%% crashing inside crypto during the handshake. `unknown_group_xyz'
%% stands in for a group unsupported on any release (the same path an
%% older OTP node hits for x25519mlkem768).
unsupported_group_rejected(_Config) ->
    ?assertEqual(
        {error, {unsupported_group, unknown_group_xyz}},
        quic:connect(<<"127.0.0.1">>, 12345, #{groups => [unknown_group_xyz]}, self())
    ),
    ?assertEqual(
        {error, {unsupported_group, unknown_group_xyz}},
        quic:start_server(pqc_bad_group_srv, 0, #{groups => [unknown_group_xyz]})
    ),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

connect(#{port := Port}, Opts) ->
    {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ConnRef.

wait_connected(ConnRef) ->
    receive
        {quic, ConnRef, {connected, Info}} -> Info
    after 10000 ->
        quic:safe_close(ConnRef, timeout),
        ct:fail("connection timeout")
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
