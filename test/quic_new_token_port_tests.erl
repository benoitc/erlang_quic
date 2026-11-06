%%% -*- erlang -*-
%%%
%%% A NEW_TOKEN token is for a later connection (RFC 9000 Section
%%% 8.1.3), which comes from a new ephemeral port: it is bound to the
%%% client's IP address only. A Retry token answers one Initial and
%%% stays bound to the address and port.

-module(quic_new_token_port_tests).

-include_lib("eunit/include/eunit.hrl").

-define(SECRET, <<0:256>>).
-define(IP, {192, 0, 2, 1}).
-define(MAX_AGE, 600000).

new_token_from_another_port_test() ->
    Token = quic_address_token:encode_new_token(?SECRET, {?IP, 50000}, now_ms()),
    ?assertMatch({ok, _}, validate(Token, {?IP, 50001})).

new_token_from_another_ip_test() ->
    Token = quic_address_token:encode_new_token(?SECRET, {?IP, 50000}, now_ms()),
    ?assertEqual({error, address_mismatch}, validate(Token, {{192, 0, 2, 2}, 50000})).

retry_token_from_another_port_test() ->
    Token = quic_address_token:encode_retry(?SECRET, {?IP, 50000}, <<"odcid">>, now_ms()),
    ?assertEqual({error, address_mismatch}, validate(Token, {?IP, 50001})).

validate(Token, Addr) ->
    quic_listener:validate_initial_token(?SECRET, Token, Addr, ?MAX_AGE).

now_ms() ->
    erlang:system_time(millisecond).
