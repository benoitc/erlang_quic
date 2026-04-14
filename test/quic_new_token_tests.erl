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

%%====================================================================
%% Server-side Initial-token validation
%%====================================================================

secret() -> <<"another-32-byte-secret-for-tests">>.

server_accepts_valid_new_token_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token = quic_address_token:encode_new_token(
        secret(), Addr, erlang:system_time(millisecond)
    ),
    S = quic_connection:test_state_for_server(Addr, secret(), ODCID),
    ?assertEqual(validated, quic_connection:maybe_validate_initial_token(Token, S)).

server_accepts_valid_retry_token_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token = quic_address_token:encode_retry(
        secret(), Addr, ODCID, erlang:system_time(millisecond)
    ),
    S = quic_connection:test_state_for_server(Addr, secret(), ODCID),
    ?assertEqual(validated, quic_connection:maybe_validate_initial_token(Token, S)).

server_rejects_token_from_wrong_address_test() ->
    ClientAddr = {{10, 0, 0, 1}, 51234},
    AttackerAddr = {{192, 168, 1, 99}, 51234},
    Token = quic_address_token:encode_new_token(
        secret(), ClientAddr, erlang:system_time(millisecond)
    ),
    S = quic_connection:test_state_for_server(AttackerAddr, secret(), <<>>),
    ?assertMatch(
        {error, address_mismatch, _},
        quic_connection:maybe_validate_initial_token(Token, S)
    ).

server_rejects_expired_retry_token_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    ODCID = <<1, 2, 3, 4>>,
    Long = erlang:system_time(millisecond) - 60 * 60 * 1000,
    Token = quic_address_token:encode_retry(secret(), Addr, ODCID, Long),
    S = quic_connection:test_state_for_server(Addr, secret(), ODCID),
    ?assertEqual(
        {error, token_expired},
        quic_connection:maybe_validate_initial_token(Token, S)
    ).

server_rejects_retry_with_mismatched_odcid_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    Token = quic_address_token:encode_retry(
        secret(), Addr, <<1, 2, 3>>, erlang:system_time(millisecond)
    ),
    S = quic_connection:test_state_for_server(Addr, secret(), <<9, 9, 9>>),
    ?assertEqual(
        {error, odcid_mismatch},
        quic_connection:maybe_validate_initial_token(Token, S)
    ).

server_without_secret_skips_validation_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    S = quic_connection:test_state_for_server(Addr, undefined, <<>>),
    ?assertEqual(
        no_token, quic_connection:maybe_validate_initial_token(<<"anything">>, S)
    ).

empty_token_returns_no_token_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    S = quic_connection:test_state_for_server(Addr, secret(), <<>>),
    ?assertEqual(no_token, quic_connection:maybe_validate_initial_token(<<>>, S)).
