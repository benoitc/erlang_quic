%%% -*- erlang -*-
%%%
%%% Both ends of a connection write their handshake secrets to
%%% SSLKEYLOGFILE, not only the application ones: the QUIC Interop Runner
%%% rejects a key log without SERVER_HANDSHAKE_TRAFFIC_SECRET, and
%%% Wireshark cannot decrypt the Handshake packets without them.

-module(quic_keylog_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([both_ends_log_handshake_secrets/1]).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [both_ends_log_handshake_secrets].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

both_ends_log_handshake_secrets(Config) ->
    Path = filename:join(?config(priv_dir, Config), "keys.log"),
    os:putenv("SSLKEYLOGFILE", Path),
    try
        {ok, #{port := Port} = Server} = quic_test_echo_server:start(#{}),
        {ok, Conn} = quic:connect(
            <<"127.0.0.1">>, Port, #{verify => false, alpn => [<<"echo">>]}, self()
        ),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ct:fail("connection timeout")
        end,
        timer:sleep(200),
        quic:close(Conn, normal),
        quic_test_echo_server:stop(Server),
        {ok, Bin} = file:read_file(Path),
        Labels = [hd(string:lexemes(L, " ")) || L <- string:lexemes(binary_to_list(Bin), "\n")],
        Count = fun(Label) -> length([L || L <- Labels, L =:= Label]) end,
        ?assertEqual(2, Count("CLIENT_TRAFFIC_SECRET_0")),
        ?assertEqual(2, Count("CLIENT_HANDSHAKE_TRAFFIC_SECRET")),
        ?assertEqual(2, Count("SERVER_HANDSHAKE_TRAFFIC_SECRET"))
    after
        os:unsetenv("SSLKEYLOGFILE")
    end.
