%%% -*- erlang -*-
%%%
%%% SSLKEYLOGFILE output. The format is what Wireshark reads, so the
%%% label, the client random and the secret have to appear in that order,
%%% lowercase hex, one line per secret.

-module(quic_keylog_tests).

-include_lib("eunit/include/eunit.hrl").

keylog_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        fun writes_a_wireshark_line/1,
        fun appends_rather_than_truncating/1,
        fun skips_a_secret_it_cannot_match/1
    ]}.

setup() ->
    Path = filename:join(
        "/tmp",
        "quic_keylog_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Old = os:getenv("SSLKEYLOGFILE"),
    os:putenv("SSLKEYLOGFILE", Path),
    {Path, Old}.

cleanup({Path, Old}) ->
    file:delete(Path),
    case Old of
        false -> os:unsetenv("SSLKEYLOGFILE");
        _ -> os:putenv("SSLKEYLOGFILE", Old)
    end,
    ok.

writes_a_wireshark_line({Path, _}) ->
    fun() ->
        ?assert(quic_keylog:enabled()),
        Random = binary:copy(<<16#ab>>, 32),
        Secret = binary:copy(<<16#cd>>, 32),
        ok = quic_keylog:log(client_handshake, Random, Secret),
        {ok, Bin} = file:read_file(Path),
        [Label, RandomHex, SecretHex] = string:lexemes(string:trim(binary_to_list(Bin)), " "),
        ?assertEqual("CLIENT_HANDSHAKE_TRAFFIC_SECRET", Label),
        ?assertEqual(string:copies("ab", 32), RandomHex),
        ?assertEqual(string:copies("cd", 32), SecretHex)
    end.

%% A connection writes four secrets; truncating would leave only the last
%% and make the capture undecryptable.
appends_rather_than_truncating({Path, _}) ->
    fun() ->
        Random = binary:copy(<<1>>, 32),
        [
            ok = quic_keylog:log(L, Random, binary:copy(<<2>>, 32))
         || L <- [client_handshake, server_handshake, client_application, server_application]
        ],
        {ok, Bin} = file:read_file(Path),
        ?assertEqual(4, length(string:lexemes(binary_to_list(Bin), "\n")))
    end.

%% Without the client random the line matches no connection, so it is
%% dropped rather than written misleadingly.
skips_a_secret_it_cannot_match({Path, _}) ->
    fun() ->
        ok = quic_keylog:log(client_handshake, undefined, binary:copy(<<3>>, 32)),
        ok = quic_keylog:log(client_handshake, binary:copy(<<3>>, 32), <<>>),
        ?assertEqual({error, enoent}, file:read_file(Path))
    end.
