%%% -*- erlang -*-
%%%
%%% An endpoint must not migrate before the handshake is confirmed
%%% (RFC 9000 Section 9).

-module(quic_migrate_before_confirmation_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

migrate_test_() ->
    [
        ?_assertEqual({error, handshake_not_confirmed}, reply(Request))
     || Request <- [migrate, {migrate, #{}}]
    ].

reply(Request) ->
    S0 = quic_connection_test_support:state_for_cid_limit(3),
    S1 = quic_connection:process_frame(
        app, {new_connection_id, 1, 0, <<1:64>>, crypto:strong_rand_bytes(16)}, S0
    ),
    S = S1#state{loss_state = quic_loss:new(), remote_addr = {{127, 0, 0, 1}, 4433}},
    From = {self(), make_ref()},
    {keep_state, _, [{reply, From, Reply}]} = quic_connection:connected({call, From}, Request, S),
    Reply.
