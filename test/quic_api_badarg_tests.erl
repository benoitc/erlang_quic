%%% -*- erlang -*-
%%%
%%% A bad argument to an API call is refused with `{error, Reason}' and
%%% leaves the connection running. Passed on to the connection process it
%%% would crash there, and take every stream and the linked owner along.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_api_badarg_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TOO_BIG, 1 bsl 62).

cases() ->
    [
        {"send_data, data not iodata", badarg, fun(C, S) -> quic:send_data(C, S, data, false) end},
        {"send_data, improper list", badarg, fun(C, S) ->
            quic:send_data(C, S, [<<"a">> | b], false)
        end},
        {"send_data, fin not a boolean", badarg, fun(C, S) ->
            quic:send_data(C, S, <<"x">>, fin)
        end},
        {"send_data/5, data not iodata", badarg, fun(C, S) ->
            quic:send_data(C, S, data, false, 1000)
        end},
        {"send_data_async, data not iodata", badarg, fun(C, S) ->
            quic:send_data_async(C, S, data, false)
        end},
        {"send_data_async, fin not a boolean", badarg, fun(C, S) ->
            quic:send_data_async(C, S, <<"x">>, fin)
        end},
        {"reset_stream, negative code", badarg, fun(C, S) -> quic:reset_stream(C, S, -1) end},
        {"reset_stream, code past 2^62-1", badarg, fun(C, S) ->
            quic:reset_stream(C, S, ?TOO_BIG)
        end},
        {"reset_stream, code not an integer", badarg, fun(C, S) ->
            quic:reset_stream(C, S, oops)
        end},
        {"reset_stream_at, negative size", badarg, fun(C, S) ->
            quic:reset_stream_at(C, S, 0, -1)
        end},
        {"stop_sending, negative code", badarg, fun(C, S) -> quic:stop_sending(C, S, -1) end},
        {"stop_sending, code past 2^62-1", badarg, fun(C, S) ->
            quic:stop_sending(C, S, ?TOO_BIG)
        end},
        {"stop_sending, code not an integer", badarg, fun(C, S) ->
            quic:stop_sending(C, S, oops)
        end},
        {"set_stream_deadline, unknown action", invalid_action, fun(C, S) ->
            R = quic:set_stream_deadline(C, S, 50, #{action => bogus}),
            %% Past the expiry, where the action is used.
            timer:sleep(200),
            R
        end},
        {"set_stream_deadline, code past 2^62-1", invalid_error_code, fun(C, S) ->
            quic:set_stream_deadline(C, S, 50, #{error_code => ?TOO_BIG})
        end},
        {"set_stream_deadline, options not a map", badarg, fun(C, S) ->
            quic:set_stream_deadline(C, S, 50, [])
        end},
        {"set_owner, not a pid", badarg, fun(C, _S) -> quic_connection:set_owner(C, owner) end},
        {"set_owner_sync, not a pid", badarg, fun(C, _S) ->
            quic_connection:set_owner_sync(C, owner)
        end}
    ].

badarg_test_() ->
    {setup,
        fun() ->
            {ok, Server} = quic_test_echo_server:start(),
            Server
        end,
        fun quic_test_echo_server:stop/1, fun(Server) ->
            [
                {Title, {timeout, 30, fun() -> refused(Server, Reason, Call) end}}
             || {Title, Reason, Call} <- cases()
            ]
        end}.

%% The call is refused, and the connection still carries data afterwards.
%% The caller is linked to the connection and does not trap exits.
refused(Server, Reason, Call) ->
    Test = self(),
    {Caller, MRef} = spawn_monitor(fun() -> Test ! {result, self(), call(Server, Call)} end),
    Result =
        receive
            {result, Caller, R} -> R;
            {'DOWN', MRef, process, Caller, Why} -> {caller_died, Why}
        end,
    erlang:demonitor(MRef, [flush]),
    ?assertEqual({{error, Reason}, <<"still here">>}, Result).

call(#{port := Port}, Call) ->
    {ok, Conn} = quic:connect(
        <<"127.0.0.1">>, Port, #{verify => false, alpn => [<<"echo">>]}, self()
    ),
    receive
        {quic, Conn, {connected, _}} -> ok
    after 5000 -> error(not_connected)
    end,
    {ok, StreamId} = quic:open_stream(Conn),
    Result = Call(Conn, StreamId),
    ok = quic:send_data(Conn, StreamId, <<"still here">>, true),
    Echoed = echoed(Conn, StreamId, <<>>),
    quic:close(Conn),
    {Result, Echoed}.

echoed(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            echoed(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 5000 -> error({no_echo, Acc})
    end.
