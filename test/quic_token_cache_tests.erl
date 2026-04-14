%%% -*- erlang -*-
%%%
%%% Unit tests for the client-side NEW_TOKEN cache (RFC 9000 §8.1.3).

-module(quic_token_cache_tests).

-include_lib("eunit/include/eunit.hrl").

with_cache_test_() ->
    {foreach,
        fun() ->
            application:ensure_all_started(quic),
            ok = quic_token_cache:clear()
        end,
        fun(_) -> ok end, [
            fun put_then_take_returns_token/0,
            fun take_without_put_returns_empty/0,
            fun second_take_returns_empty/0,
            fun overwrite_replaces_token/0,
            fun different_endpoints_are_isolated/0
        ]}.

put_then_take_returns_token() ->
    Endpoint = {{127, 0, 0, 1}, 4433},
    ok = quic_token_cache:put(Endpoint, <<"opaque">>),
    ?assertEqual({ok, <<"opaque">>}, quic_token_cache:take(Endpoint)).

take_without_put_returns_empty() ->
    ?assertEqual(empty, quic_token_cache:take({{127, 0, 0, 1}, 9999})).

second_take_returns_empty() ->
    E = {{127, 0, 0, 1}, 4433},
    ok = quic_token_cache:put(E, <<"tok">>),
    {ok, _} = quic_token_cache:take(E),
    ?assertEqual(empty, quic_token_cache:take(E)).

overwrite_replaces_token() ->
    E = {{127, 0, 0, 1}, 4433},
    ok = quic_token_cache:put(E, <<"first">>),
    ok = quic_token_cache:put(E, <<"second">>),
    ?assertEqual({ok, <<"second">>}, quic_token_cache:take(E)).

different_endpoints_are_isolated() ->
    ok = quic_token_cache:put({{127, 0, 0, 1}, 4433}, <<"a">>),
    ok = quic_token_cache:put({{127, 0, 0, 1}, 4434}, <<"b">>),
    ?assertEqual({ok, <<"a">>}, quic_token_cache:take({{127, 0, 0, 1}, 4433})),
    ?assertEqual({ok, <<"b">>}, quic_token_cache:take({{127, 0, 0, 1}, 4434})).
