%%% -*- erlang -*-
%%%
%%% A winning attempt that is already closing when the coordinator hands
%%% it over makes set_owner_sync/2 return an error. The coordinator does
%%% not crash on a try_clause (#399), and the race ends with the reason
%%% the server closed the winner with: its handshake completed, so it won
%%% (RFC 8305 Section 5), and the other attempts are not waited for.

-module(quic_happy_owner_error_tests).

-include_lib("eunit/include/eunit.hrl").

closing_winner_test() ->
    Attempt = spawn(fun closing_connection/0),
    ok = meck:new(quic_conn_sup, [passthrough]),
    ok = meck:expect(quic_conn_sup, start_child, fun(_, _, _, Coord) ->
        Coord ! {quic, Attempt, {connected, #{}}},
        {ok, Attempt}
    end),
    try
        ?assertEqual({error, {invalid_state, draining}}, race())
    after
        Attempt ! stop,
        meck:unload(quic_conn_sup)
    end.

%% Two addresses. The first attempt completes its handshake once the
%% second has started, and the server has closed it by the hand-off. The
%% second never answers.
closed_winner_ends_the_race_test() ->
    Closed = {peer_closed, transport, 16#174, 0, <<"certificate required">>},
    Silent = spawn(fun closing_connection/0),
    ok = meck:new(quic_conn_sup, [passthrough]),
    Count = counters:new(1, []),
    ok = meck:expect(quic_conn_sup, start_child, fun(_, _, _, Coord) ->
        counters:add(Count, 1, 1),
        case counters:get(Count, 1) of
            1 ->
                Winner = spawn(fun() -> closed_connection(Coord, Closed) end),
                {ok, Winner};
            _ ->
                {ok, Silent}
        end
    end),
    try
        {Ms, Result} = timer:tc(fun race/1, [two_addresses], millisecond),
        ?assertEqual({error, Closed}, Result),
        ?assert(Ms < 1500)
    after
        Silent ! stop,
        meck:unload(quic_conn_sup)
    end.

%% Completes its handshake after the second attempt has started, then
%% answers the hand-off as a connection the server closed does: the close
%% to its owner first, then the error.
closed_connection(Coord, Closed) ->
    timer:sleep(400),
    Coord ! {quic, self(), {connected, #{}}},
    receive
        {'$gen_call', From, {set_owner, _}} ->
            Coord ! {quic, self(), {closed, Closed}},
            gen_statem:reply(From, {error, closed})
    after 5000 -> ok
    end.

%% Answers the coordinator's set_owner_sync/2 as a draining connection does.
closing_connection() ->
    receive
        {'$gen_call', From, _} ->
            gen_statem:reply(From, {error, {invalid_state, draining}}),
            closing_connection();
        stop ->
            ok
    end.

%% The coordinator links to its caller, so run it from a process of its
%% own and report what became of it.
race() ->
    race(one_address).

race(Addrs) ->
    Test = self(),
    {Caller, MRef} = spawn_monitor(fun() ->
        {ok, Coord} = quic_happy:start_coordinator(#{
            addrs => addrs(Addrs),
            port => 4433,
            opts => #{},
            owner => self(),
            caller => self(),
            delay => 250,
            timeout => 2000
        }),
        receive
            {quic_happy_result, Coord, Result} -> Test ! {result, self(), Result}
        end
    end),
    receive
        {result, Caller, Result} -> Result;
        {'DOWN', MRef, process, Caller, Reason} -> {crashed, Reason}
    after 3000 -> no_result
    end.

addrs(one_address) -> [{{127, 0, 0, 1}, inet}];
addrs(two_addresses) -> [{{0, 0, 0, 0, 0, 0, 0, 1}, inet6}, {{127, 0, 0, 1}, inet}].
