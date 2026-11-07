%%% -*- erlang -*-
%%%
%%% A client echoes a Retry token at once, so a server accepts one only
%%% for a short time (RFC 9000 Section 8.1.3). NEW_TOKEN tokens keep the
%%% configured lifetime.

-module(quic_retry_token_age_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

-define(SECRET, binary:copy(<<7>>, 32)).
-define(ADDR, {{127, 0, 0, 1}, 40000}).
-define(MAX_AGE, 600000).

fresh_retry_token_accepted_test() ->
    Token = quic_address_token:encode_retry(?SECRET, ?ADDR, <<"odcid123">>, now_ms() - 1000),
    ?assertMatch({spawn_validated, <<"odcid123">>, _}, decide(Token)).

old_retry_token_refused_test() ->
    Token = quic_address_token:encode_retry(?SECRET, ?ADDR, <<"odcid123">>, now_ms() - 60000),
    ?assertMatch({send_retry, _, _}, decide(Token)).

decide(Token) ->
    quic_listener:decide_address_validation(
        initial(Token), ?QUIC_VERSION_1, ?ADDR, ?SECRET, always, ?MAX_AGE
    ).

initial(Token) ->
    DCID = <<"retried1">>,
    SCID = <<"client01">>,
    TokenLen = quic_varint:encode(byte_size(Token)),
    <<16#C0, ?QUIC_VERSION_1:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary,
        TokenLen/binary, Token/binary, 0, 0>>.

now_ms() ->
    erlang:system_time(millisecond).
