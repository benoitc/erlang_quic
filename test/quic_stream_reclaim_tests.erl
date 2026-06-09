%%% -*- erlang -*-
%%%
%%% Regression for #152: fully-closed streams must be reclaimed from the
%%% connection's stream map, not accumulate for the life of the connection.

-module(quic_stream_reclaim_tests).

-include_lib("eunit/include/eunit.hrl").

%% After a graceful FIN-close on both directions, the connection's stream
%% map returns to ~empty instead of growing one entry per stream.
reclaim_after_fin_test_() ->
    {timeout, 60, fun reclaim_after_fin/0}.

reclaim_after_fin() ->
    {ok, Srv} = quic_test_echo_server:start(#{
        max_data => 64 * 1024 * 1024,
        max_streams_bidi => 200
    }),
    try
        #{port := Port} = Srv,
        {ok, Conn} = quic:connect("127.0.0.1", Port, quic_test_echo_server:client_opts(), self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> ?assert(false)
        end,
        N = 50,
        Sids = [open_and_finish(Conn) || _ <- lists:seq(1, N)],
        %% Each stream echoes the payload back with FIN; drain those so the
        %% client's receive side also reaches its terminal state.
        ok = drain_fins(Conn, lists:sort(Sids), 30000),
        %% Both directions are now terminal on the client, so the stream map
        %% must have been reclaimed back down (not stuck at N).
        ?assert(wait_streams_below(Conn, 5, 10000)),
        quic:safe_close(Conn)
    after
        quic_test_echo_server:stop(Srv)
    end.

open_and_finish(Conn) ->
    {ok, Sid} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, Sid, <<"hello-152">>, true),
    Sid.

drain_fins(_Conn, [], _Timeout) ->
    ok;
drain_fins(Conn, Pending, Timeout) ->
    receive
        {quic, Conn, {stream_data, Sid, _Data, true}} ->
            drain_fins(Conn, lists:delete(Sid, Pending), Timeout);
        {quic, Conn, _Other} ->
            drain_fins(Conn, Pending, Timeout)
    after Timeout ->
        error({fins_not_received, Pending})
    end.

wait_streams_below(Conn, Threshold, Timeout) when Timeout =< 0 ->
    stream_count(Conn) =< Threshold;
wait_streams_below(Conn, Threshold, Timeout) ->
    case stream_count(Conn) =< Threshold of
        true ->
            true;
        false ->
            timer:sleep(100),
            wait_streams_below(Conn, Threshold, Timeout - 100)
    end.

stream_count(Conn) ->
    {_StateName, Map} = gen_statem:call(Conn, get_state),
    maps:get(streams, Map).
