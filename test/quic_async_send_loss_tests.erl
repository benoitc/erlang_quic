%%% A send that the peer's flow-control window has no room for must be
%%% queued, not turned into an error.
%%%
%%% send_data_async is fire-and-forget, so an error return is silently
%%% lost, and the loss is invisible to both ends: the bytes never reach
%%% the wire, so the peer cannot detect a gap, and the next send on the
%%% stream continues from a later offset. The application stream is then
%%% missing a chunk with nothing reported anywhere.
-module(quic_async_send_loss_tests).

-include_lib("eunit/include/eunit.hrl").

queue(StreamId, Offset, Data, Fin, SendOffset) ->
    quic_connection:test_queue_blocked_send(StreamId, Offset, Data, Fin, SendOffset).

%% The regression: this used to return {error, {flow_control_blocked, _}}
%% and drop the payload.
blocked_send_is_queued_test() ->
    ?assertMatch({ok, _, 1}, queue(4, 0, <<"payload">>, false, 0)).

%% The offset has to advance at queue time, so a later send on the same
%% stream orders behind this entry rather than overwriting its range.
blocked_send_advances_offset_test() ->
    {ok, NewOffset, _} = queue(4, 100, binary:copy(<<$x>>, 250), false, 100),
    ?assertEqual(350, NewOffset).

fin_is_preserved_test() ->
    ?assertMatch({ok, _, 1}, queue(8, 0, <<"last">>, true, 0)).

%% An empty payload still has to queue rather than error: a FIN-only send
%% carries stream-closing intent.
empty_payload_is_queued_test() ->
    {ok, NewOffset, Count} = queue(4, 40, <<>>, true, 40),
    ?assertEqual(40, NewOffset),
    ?assertEqual(1, Count).

iodata_is_accepted_test() ->
    {ok, NewOffset, _} = queue(4, 0, [<<"ab">>, [<<"cd">>, <<"ef">>]], false, 0),
    ?assertEqual(6, NewOffset).
