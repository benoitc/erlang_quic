%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 19.19: a 0x1d CONNECTION_CLOSE carries an
%%% application error code. A local close without one is the transport
%%% code APPLICATION_ERROR, which belongs in a 0x1c frame.

-module(quic_close_frame_type_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

close_without_app_code_is_a_transport_close_test() ->
    ?assertMatch(
        [{connection_close, transport, ?QUIC_APPLICATION_ERROR, 0, _}],
        close_frames(fun() -> quic_connection:initiate_close(owner_gone, state()) end)
    ).

terminate_without_app_code_is_a_transport_close_test() ->
    ?assertMatch(
        [{connection_close, transport, ?QUIC_APPLICATION_ERROR, 0, _}],
        close_frames(fun() -> quic_connection:send_connection_close({badmatch, x}, state()) end)
    ).

app_code_stays_an_application_close_test() ->
    ?assertMatch(
        [{connection_close, application, 16#42, _, <<"bye">>}],
        close_frames(fun() ->
            quic_connection:initiate_close({app_error, 16#42, <<"bye">>}, state())
        end)
    ).

normal_stays_an_application_close_test() ->
    ?assertMatch(
        [{connection_close, application, 0, _, _}],
        close_frames(fun() -> quic_connection:initiate_close(normal, state()) end)
    ),
    ?assertMatch(
        [{connection_close, application, 0, _, _}],
        close_frames(fun() -> quic_connection:send_connection_close(shutdown, state()) end)
    ).

%% Confirmed, so the close goes out in 1-RTT packets only.
state() ->
    S = ?S:with_keys_and_socket(?S:state_for_role(client)),
    ?S:state_set(S, loss_state, quic_loss:on_handshake_confirmed(?S:loss_state(S))).

%% The CONNECTION_CLOSE frames handed to the encoder while Fun ran.
close_frames(Fun) ->
    ok = meck:new(quic_frame, [passthrough]),
    try
        _ = Fun(),
        [
            F
         || {_, {quic_frame, encode, [{connection_close, _, _, _, _} = F]}, _} <-
                meck:history(quic_frame)
        ]
    after
        meck:unload(quic_frame)
    end.
