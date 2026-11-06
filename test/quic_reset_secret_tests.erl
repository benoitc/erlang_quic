%%% -*- erlang -*-
%%%
%%% Reset tokens are derived with HMAC-SHA256 over a secret of at least
%%% 32 bytes; a shorter `reset_secret' is refused when a listener starts.

-module(quic_reset_secret_tests).

-include_lib("eunit/include/eunit.hrl").

short_secret_refused_test() ->
    ?assertEqual({error, {invalid_reset_secret, 16}}, start(crypto:strong_rand_bytes(16))).

non_binary_secret_refused_test() ->
    ?assertEqual({error, {invalid_reset_secret, secret}}, start(secret)).

%% A listener started on its own refuses it too, as quic_dist and the
%% interop server start it.
listener_refuses_short_secret_test() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    ?assertEqual(
        {error, {invalid_reset_secret, 16}},
        quic_listener:start(0, #{
            cert => Cert, key => Key, alpn => [<<"h3">>], reset_secret => binary:copy(<<1>>, 16)
        })
    ).

start(Secret) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("reset_secret_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Result = quic:start_server(Name, 0, #{
        cert => Cert, key => Key, alpn => [<<"h3">>], reset_secret => Secret
    }),
    case Result of
        {ok, _} -> quic:stop_server(Name);
        _ -> ok
    end,
    Result.
