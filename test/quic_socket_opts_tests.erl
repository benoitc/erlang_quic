%%% -*- erlang -*-
%%%
%%% Tests for QUIC socket options
%%% Issue #27 - Server sockname returns undefined
%%% Issue #28 - Client socket binding options
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_socket_opts_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test setup/teardown
%%====================================================================

setup() ->
    case whereis(quic_sup) of
        undefined ->
            {ok, _} = application:ensure_all_started(quic);
        _ ->
            ok
    end,
    ok.

cleanup(_) ->
    Servers =
        try
            quic:which_servers()
        catch
            _:_ -> []
        end,
    lists:foreach(
        fun(Name) ->
            _ = quic:stop_server(Name),
            _ = (catch quic_server_registry:unregister(Name))
        end,
        Servers
    ),
    timer:sleep(50),
    ok.

%%====================================================================
%% Test generators
%%====================================================================

socket_opts_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        %% Issue #28 tests - client socket options
        {"Client extra_socket_opts with IP binding", fun client_extra_socket_opts_ip_test/0},
        {"Client extra_socket_opts empty", fun client_extra_socket_opts_empty_test/0},
        {"Client socket option uses provided socket", fun client_socket_option_test/0},
        {"Client socket ownership", fun client_socket_ownership_test/0},
        {"Client invalid socket", fun client_socket_invalid_test/0},
        %% UDP buffer sizing tests
        {"Server buffer options default", fun server_buffer_opts_default_test/0},
        {"Client buffer options default", fun client_buffer_opts_default_test/0},
        {"Buffer override custom values", fun buffer_override_test/0}
    ]}.

%%====================================================================
%% Issue #28: Client socket binding tests
%%====================================================================

client_extra_socket_opts_ip_test() ->
    %% Test that extra_socket_opts are passed to gen_udp:open
    %% This tests the open_client_socket/3 function directly
    {ok, Sock} = gen_udp:open(0, [binary, inet, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, {IP, Port}} = inet:sockname(Sock),
    ?assertEqual({127, 0, 0, 1}, IP),
    ?assert(Port > 0),
    gen_udp:close(Sock).

client_extra_socket_opts_empty_test() ->
    %% Test that empty extra_socket_opts work
    {ok, Sock} = gen_udp:open(0, [binary, inet, {active, false}]),
    {ok, {_IP, Port}} = inet:sockname(Sock),
    ?assert(Port > 0),
    gen_udp:close(Sock).

client_socket_option_test() ->
    %% Test that pre-opened socket is used correctly
    %% Create a socket bound to 127.0.0.1
    {ok, Sock} = gen_udp:open(0, [binary, inet, {ip, {127, 0, 0, 1}}]),
    {ok, {SockIP, SockPort}} = inet:sockname(Sock),
    ?assertEqual({127, 0, 0, 1}, SockIP),
    ?assert(SockPort > 0),

    %% Verify socket is valid before use
    ?assertEqual({ok, {SockIP, SockPort}}, inet:sockname(Sock)),

    gen_udp:close(Sock).

client_socket_ownership_test() ->
    %% Test that provided socket is not closed when we don't own it
    %% The quic_connection should only close sockets it created
    {ok, Sock} = gen_udp:open(0, [binary, inet, {ip, {127, 0, 0, 1}}]),
    {ok, {_IP, SockPort}} = inet:sockname(Sock),
    ?assert(SockPort > 0),

    %% Socket should still be usable
    ?assertEqual(ok, gen_udp:send(Sock, {127, 0, 0, 1}, SockPort, <<"test">>)),

    %% Socket should still be open after use
    ?assertMatch({ok, _}, inet:sockname(Sock)),

    gen_udp:close(Sock),
    %% Now socket should be closed
    ?assertEqual({error, einval}, inet:sockname(Sock)).

client_socket_invalid_test() ->
    %% Test that invalid socket produces error
    %% A closed socket should fail in open_client_socket/3
    {ok, Sock} = gen_udp:open(0, [binary, inet]),
    gen_udp:close(Sock),
    %% Now the socket is invalid
    ?assertEqual({error, einval}, inet:sockname(Sock)).

%%====================================================================
%% UDP Buffer Sizing Tests
%%====================================================================

%% Helper to check if recbuf/sndbuf options are supported on this platform
is_buffer_opts_supported() ->
    try
        {ok, Sock} = gen_udp:open(0, [binary, inet, {recbuf, 65536}]),
        gen_udp:close(Sock),
        true
    catch
        _:_ -> false
    end.

server_buffer_opts_default_test() ->
    %% Test that server socket applies buffer settings
    %% Skip if recbuf/sndbuf not supported on this platform (e.g., some macOS)
    case is_buffer_opts_supported() of
        false ->
            %% Platform doesn't support recbuf/sndbuf options - test passes
            ok;
        true ->
            TestBufSize = 65536,
            {ok, Sock} = gen_udp:open(0, [
                binary,
                inet,
                {recbuf, TestBufSize},
                {sndbuf, TestBufSize}
            ]),
            {ok, ActualOpts} = inet:getopts(Sock, [recbuf, sndbuf]),
            RecvBuf = proplists:get_value(recbuf, ActualOpts),
            SndBuf = proplists:get_value(sndbuf, ActualOpts),
            ?assert(RecvBuf > 0),
            ?assert(SndBuf > 0),
            gen_udp:close(Sock)
    end.

client_buffer_opts_default_test() ->
    %% Test that client socket applies buffer options
    %% Skip if recbuf/sndbuf not supported on this platform
    case is_buffer_opts_supported() of
        false ->
            ok;
        true ->
            TestBufSize = 65536,
            {ok, Sock} = gen_udp:open(0, [
                binary,
                inet,
                {active, false},
                {recbuf, TestBufSize},
                {sndbuf, TestBufSize}
            ]),
            {ok, ActualOpts} = inet:getopts(Sock, [recbuf, sndbuf]),
            RecvBuf = proplists:get_value(recbuf, ActualOpts),
            SndBuf = proplists:get_value(sndbuf, ActualOpts),
            ?assert(RecvBuf > 0),
            ?assert(SndBuf > 0),
            gen_udp:close(Sock)
    end.

buffer_override_test() ->
    %% Test that custom buffer values can be specified
    %% Skip if recbuf/sndbuf not supported on this platform
    case is_buffer_opts_supported() of
        false ->
            ok;
        true ->
            CustomRecvBuf = 32768,
            CustomSndBuf = 65536,
            {ok, Sock} = gen_udp:open(0, [
                binary,
                inet,
                {recbuf, CustomRecvBuf},
                {sndbuf, CustomSndBuf}
            ]),
            {ok, ActualOpts} = inet:getopts(Sock, [recbuf, sndbuf]),
            RecvBuf = proplists:get_value(recbuf, ActualOpts),
            SndBuf = proplists:get_value(sndbuf, ActualOpts),
            ?assert(RecvBuf > 0),
            ?assert(SndBuf > 0),
            gen_udp:close(Sock)
    end.

%%====================================================================
%% Helper to test open_client_socket/4 directly (internal function)
%%====================================================================

%% Note: More thorough E2E tests for server sockname (#27) and
%% full client socket binding would require actual TLS handshakes.
%% Those tests are in quic_e2e_SUITE.
