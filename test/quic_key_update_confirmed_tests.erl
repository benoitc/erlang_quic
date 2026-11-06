%%% -*- erlang -*-
%%%
%%% "An endpoint MUST NOT initiate a key update prior to having confirmed
%%% the handshake" (RFC 9001 Section 6.1).

-module(quic_key_update_confirmed_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

before_confirmation_test() ->
    ?assertEqual({error, handshake_not_confirmed}, key_update(quic_loss:new())).

after_confirmation_test() ->
    ?assertEqual(ok, key_update(quic_loss:on_handshake_confirmed(quic_loss:new()))).

key_update(LossState) ->
    #state{app_keys = Keys} =
        S = quic_connection_test_support:state_with_keys(client),
    From = {self(), make_ref()},
    {keep_state, _, [{reply, From, Reply}]} = quic_connection:connected(
        {call, From}, key_update, S#state{
            loss_state = LossState,
            key_state = #key_update_state{
                current_keys = Keys,
                client_app_secret = binary:copy(<<1>>, 32),
                server_app_secret = binary:copy(<<2>>, 32)
            }
        }
    ),
    Reply.
