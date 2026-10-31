%%% -*- erlang -*-
%%%
%%% Stream credit goes back to the peer in steps of half the initial
%%% limit, not one MAX_STREAMS per closed stream. Each of those is a
%%% packet of its own that the peer acknowledges, which in the interop
%%% runner's zerortt test pushed msquic's 1-RTT bytes over the limit.

-module(quic_stream_credit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

credit_in_half_window_steps_test_() ->
    {timeout, 60, fun credit_in_half_window_steps/0}.

credit_in_half_window_steps() ->
    {ok, Srv} = quic_test_echo_server:start(#{max_streams_bidi => 20}),
    try
        #{port := Port} = Srv,
        {ok, Conn} = quic:connect("127.0.0.1", Port, quic_test_echo_server:client_opts(), self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> ?assert(false)
        end,
        ok = run_streams(Conn, 9),
        timer:sleep(500),
        ?assertEqual(20, peer_limit(Conn)),
        ok = run_streams(Conn, 1),
        ?assert(wait_limit(Conn, 30, 5000)),
        quic:safe_close(Conn)
    after
        quic_test_echo_server:stop(Srv)
    end.

run_streams(Conn, N) ->
    Sids = [
        begin
            {ok, Sid} = quic:open_stream(Conn),
            ok = quic:send_data(Conn, Sid, <<"credit">>, true),
            Sid
        end
     || _ <- lists:seq(1, N)
    ],
    drain_fins(Conn, Sids).

drain_fins(_Conn, []) ->
    ok;
drain_fins(Conn, Pending) ->
    receive
        {quic, Conn, {stream_data, Sid, _Data, true}} ->
            drain_fins(Conn, lists:delete(Sid, Pending));
        {quic, Conn, _Other} ->
            drain_fins(Conn, Pending)
    after 10000 ->
        error({fins_not_received, Pending})
    end.

peer_limit(Conn) ->
    {_StateName, #state{max_streams_bidi_remote = Max}} = sys:get_state(Conn),
    Max.

wait_limit(Conn, Want, Timeout) when Timeout =< 0 ->
    peer_limit(Conn) =:= Want;
wait_limit(Conn, Want, Timeout) ->
    case peer_limit(Conn) of
        Want ->
            true;
        _ ->
            timer:sleep(100),
            wait_limit(Conn, Want, Timeout - 100)
    end.
