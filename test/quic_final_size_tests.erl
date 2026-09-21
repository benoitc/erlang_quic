%%% -*- erlang -*-
%%%
%%% A stream's final size, from both ends (RFC 9000 Section 4.5).
%%%
%%% Once a FIN has fixed a stream's final size nothing may lie beyond it.
%%% A sender that writes past it produces data the peer has to reject,
%%% and a receiver that accepts it hands the application bytes the peer
%%% declared did not exist. Both used to happen whenever the other side
%%% had not closed its own half: a fully closed stream is removed, which
%%% hid it everywhere else.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_final_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(SID, 4).
-define(WIN, ?DEFAULT_MAX_RECEIVE_WINDOW).

%%====================================================================
%% Receiving
%%====================================================================

%% Data past a known final size is a connection error, not more data.
data_beyond_the_final_size_is_rejected_test() ->
    S1 = fin_received(<<"first">>),
    S2 = receive_frame(S1, 5, <<"after fin">>, false),
    ?assertEqual(final_size_error, quic_connection_test_support:close_reason(S2)),
    %% And it never reaches the application.
    ?assertEqual([], [D || {quic, _, {stream_data, ?SID, D, _}} <- messages()]).

%% The existing rule, kept: a second FIN may not move the final size.
a_second_fin_that_moves_the_final_size_is_rejected_test() ->
    S2 = receive_frame(fin_received(<<"first">>), 0, <<"first and more">>, true),
    ?assertEqual(final_size_error, quic_connection_test_support:close_reason(S2)).

%% The fence: a retransmission that stays within the final size is
%% ordinary, so the cases above are about the boundary and not about
%% any frame after a FIN.
a_retransmission_within_the_final_size_is_fine_test() ->
    S2 = receive_frame(fin_received(<<"first">>), 0, <<"first">>, true),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S2)).

%% The lean path only runs while the final size is unknown, so a frame
%% after a FIN always reaches the checks; hold it to that.
the_lean_path_defers_once_the_final_size_is_known_test() ->
    S1 = fin_received(<<"first">>),
    S2 = quic_connection:do_process_stream_data_buffered(?SID, 5, <<"after fin">>, false, S1),
    ?assertEqual(final_size_error, quic_connection_test_support:close_reason(S2)).

%%====================================================================
%% Sending
%%====================================================================

%% After our FIN the send side is closed: a write is refused and
%% nothing is queued or sent.
a_write_after_our_fin_is_refused_test() ->
    S0 = quic_connection_test_support:state_with_send_stream(?SID, 5, true),
    ?assertMatch({error, _}, quic_connection:do_send_data(?SID, <<"after fin">>, false, S0)).

%% The fence: before the FIN the same write goes through.
a_write_before_our_fin_is_accepted_test() ->
    S0 = quic_connection_test_support:state_with_send_stream(?SID, 5, false),
    ?assertMatch({ok, _}, quic_connection:do_send_data(?SID, <<"more">>, false, S0)).

%%====================================================================
%% Helpers
%%====================================================================

%% A peer-initiated stream whose FIN has arrived with Data, so its final
%% size is byte_size(Data). Keys and a socket, so a close can be sent.
fin_received(Data) ->
    flush(),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:recv_stream_state(?SID, 0, ?WIN, 2 * ?WIN)
    ),
    S1 = receive_frame(S0, 0, Data, true),
    undefined = quic_connection_test_support:close_reason(S1),
    flush(),
    S1.

receive_frame(State, Offset, Data, Fin) ->
    quic_connection:do_process_stream_data_slow(?SID, Offset, Data, Fin, State).

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

messages() ->
    {messages, Msgs} = process_info(self(), messages),
    Msgs.
