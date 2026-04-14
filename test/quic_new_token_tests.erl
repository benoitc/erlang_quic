%%% -*- erlang -*-
%%%
%%% RFC 9000 §8.1.3: servers MUST treat NEW_TOKEN as PROTOCOL_VIOLATION;
%%% clients accept and (for now) discard.

-module(quic_new_token_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

server_rejects_new_token_with_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, {new_token, <<"opaque">>}, S0),
    %% No app keys in this minimal state, so send_protocol_violation
    %% sets close_reason directly rather than writing a CLOSE frame.
    ?assertMatch(
        {protocol_violation, <<"NEW_TOKEN received by server">>},
        quic_connection:test_close_reason(S1)
    ).

client_caches_new_token_keyed_by_remote_addr_test() ->
    application:ensure_all_started(quic),
    ok = quic_token_cache:clear(),
    Addr = {{127, 0, 0, 1}, 4433},
    S0 = quic_connection:test_state_for_client(Addr),
    S1 = quic_connection:process_frame(app, {new_token, <<"tok">>}, S0),
    ?assertEqual(S0, S1),
    ?assertEqual({ok, <<"tok">>}, quic_token_cache:take(Addr)).
