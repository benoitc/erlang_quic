%%% -*- erlang -*-
%%%
%%% A server sends no Content-Length in a 2xx response to CONNECT
%%% (RFC 9110 Section 8.6). One the application supplied is left out;
%%% other responses keep theirs.

-module(quic_h3_connect_content_length_tests).

-include_lib("eunit/include/eunit.hrl").

-define(HEADERS, [{<<"content-length">>, <<"5">>}, {<<"server">>, <<"t">>}]).

successful_connect_drops_content_length_test_() ->
    [
        ?_assertEqual([{<<"server">>, <<"t">>}], headers(Status, <<"CONNECT">>))
     || Status <- [200, 204, 299]
    ].

other_responses_keep_content_length_test_() ->
    [
        ?_assertEqual(?HEADERS, headers(Status, Method))
     || {Status, Method} <- [
            {200, <<"GET">>}, {200, <<"HEAD">>}, {403, <<"CONNECT">>}, {502, <<"CONNECT">>}
        ]
    ].

headers(Status, Method) ->
    quic_h3_connection:outbound_response_headers(Status, Method, ?HEADERS).
