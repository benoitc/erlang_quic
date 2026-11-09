%%% -*- erlang -*-
%%%
%%% Synchronous API calls on a connection whose process is gone return
%%% `{error, closed}'. The process stops a few PTOs after any close, so
%%% a caller cannot know it is still there when it calls.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_api_closed_tests).

-include_lib("eunit/include/eunit.hrl").

calls() ->
    [
        {send_data, fun(C) -> quic:send_data(C, 0, <<"x">>, false) end},
        {send_data_timeout, fun(C) -> quic:send_data(C, 0, <<"x">>, false, 1000) end},
        {open_stream, fun quic:open_stream/1},
        {open_unidirectional_stream, fun quic:open_unidirectional_stream/1},
        {set_stream_flow_control, fun(C) -> quic:set_stream_flow_control(C, 0, manual) end},
        {consume, fun(C) -> quic:consume(C, 0, 1) end},
        {reset_stream, fun(C) -> quic:reset_stream(C, 0, 0) end},
        {reset_stream_at, fun(C) -> quic:reset_stream_at(C, 0, 0, 0) end},
        {set_stream_reliable_size, fun(C) -> quic:set_stream_reliable_size(C, 0, 0) end},
        {stop_sending, fun(C) -> quic:stop_sending(C, 0, 0) end},
        {peername, fun quic:peername/1},
        {sockname, fun quic:sockname/1},
        {peercert, fun quic:peercert/1},
        {set_owner_sync, fun(C) -> quic:set_owner_sync(C, self()) end},
        {send_datagram, fun(C) -> quic:send_datagram(C, <<"x">>) end},
        {setopts, fun(C) -> quic:setopts(C, []) end},
        {migrate, fun quic:migrate/1},
        {migrate_timeout, fun(C) -> quic_connection:migrate(C, 1000) end},
        {set_stream_priority, fun(C) -> quic:set_stream_priority(C, 0, 3, false) end},
        {get_stream_priority, fun(C) -> quic:get_stream_priority(C, 0) end},
        {set_congestion_control, fun(C) -> quic:set_congestion_control(C, newreno) end},
        {set_stream_deadline, fun(C) -> quic:set_stream_deadline(C, 0, 1000) end},
        {cancel_stream_deadline, fun(C) -> quic:cancel_stream_deadline(C, 0) end},
        {get_stream_deadline, fun(C) -> quic:get_stream_deadline(C, 0) end},
        {get_send_queue_info, fun quic:get_send_queue_info/1},
        {get_path_stats, fun quic:get_path_stats/1},
        {get_stats, fun quic_connection:get_stats/1},
        {get_peer_transport_params, fun quic_connection:get_peer_transport_params/1},
        {send_ping, fun quic_connection:send_ping/1},
        {get_mtu, fun quic_connection:get_mtu/1},
        {key_update, fun quic_connection:key_update/1},
        {close_stream, fun(C) -> quic_connection:close_stream(C, 0, 0) end}
    ].

%% The process was gone before the call.
call_after_exit_test_() ->
    Gone = gone(),
    [{atom_to_list(Name), ?_assertEqual({error, closed}, Call(Gone))} || {Name, Call} <- calls()].

%% The process stops while the call is waiting for its reply.
exit_during_call_test_() ->
    [
        ?_assertEqual({error, closed}, quic:peername(exits_on_call(Reason)))
     || Reason <- [normal, shutdown, {shutdown, owner_down}]
    ].

%% Fence: a crash of the connection is not reported as a close.
crash_during_call_test() ->
    ?assertExit({boom, _}, quic:peername(exits_on_call(boom))).

%% Fence: a timeout is still a timeout.
timeout_test() ->
    Silent = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ?assertEqual({error, timeout}, quic:send_data(Silent, 0, <<"x">>, false, 50)),
    Silent ! stop.

%% Over a connection: closed locally, then used again after it stopped.
call_after_close_test_() ->
    {timeout, 30, fun call_after_close/0}.

call_after_close() ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        {ok, Conn} = quic:connect(
            <<"127.0.0.1">>,
            maps:get(port, Server),
            #{verify => false, alpn => [<<"echo">>]},
            self()
        ),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        MRef = erlang:monitor(process, Conn),
        ok = quic:close(Conn),
        receive
            {'DOWN', MRef, process, Conn, _} -> ok
        after 10000 -> error(still_alive)
        end,
        ?assertEqual({error, closed}, quic:send_data(Conn, StreamId, <<"x">>, false)),
        ?assertEqual({error, closed}, quic:open_stream(Conn))
    after
        quic_test_echo_server:stop(Server)
    end.

gone() ->
    {Pid, MRef} = spawn_monitor(fun() -> ok end),
    receive
        {'DOWN', MRef, process, Pid, _} -> Pid
    end.

exits_on_call(Reason) ->
    spawn(fun() ->
        receive
            {'$gen_call', _From, _Request} -> exit(Reason)
        end
    end).
