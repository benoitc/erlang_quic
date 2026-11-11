%% A connection exit costs the listener the same whatever else is in the
%% routing table.
%%
%% The listener routes packets and cleans up after connections in one
%% process. Cleanup used to scan the whole shared connection-ID table on
%% every exit, so a cohort of connections expiring together cost the
%% square of its size and stalled routing for everyone else. It now
%% deletes the exiting connection's IDs by key.
%%
%% What is measured is the listener's own work (reductions) for one
%% exit with a large table, which is deterministic where wall-clock time
%% is not.
-module(quic_listener_cid_cleanup_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID, <<9, 9, 9, 9, 9, 9, 9, 9>>).
-define(SCID, <<1, 2, 3, 4>>).
-define(OTHERS, 200000).

initial(DCID) ->
    %% Padded to the 1200 bytes a client Initial datagram has.
    Packet =
        <<16#C0, 1:32, (byte_size(DCID)), DCID/binary, (byte_size(?SCID)), ?SCID/binary, "body">>,
    <<Packet/binary, 0:((1200 - byte_size(Packet)) * 8)>>.

handler(Test) ->
    fun(ConnPid, _DCID) ->
        Test ! {conn, ConnPid},
        {ok, Test}
    end.

exit_cleanup_does_not_scan_the_routing_table_test_() ->
    {timeout, 60, fun() ->
        {ok, Sup} = quic_listener_sup:start_link(0, #{
            connection_handler => handler(self()),
            psks => #{<<"id">> => <<"secret">>},
            alpn => [<<"h3">>]
        }),
        unlink(Sup),
        [Listener | _] = Listeners = quic_listener_sup:get_listeners(Sup),
        {quic_listener_manager, Manager, _, _} =
            lists:keyfind(quic_listener_manager, 1, supervisor:which_children(Sup)),
        {ok, {Conns, _Tickets}} = quic_listener_manager:get_tables(Manager),
        Other = spawn(fun() ->
            receive
                stop -> ok
            end
        end),
        ets:insert(Conns, [{<<I:64>>, Other} || I <- lists:seq(1, ?OTHERS)]),
        {ok, Sock} = gen_udp:open(0, [binary]),
        try
            ok = gen_udp:send(
                Sock, {127, 0, 0, 1}, quic_listener:get_port(Listener), initial(?DCID)
            ),
            ConnPid =
                receive
                    {conn, P} -> P
                after 5000 -> error(no_connection)
                end,
            ?assertMatch([{_, ConnPid}], ets:lookup(Conns, ?DCID)),
            Before = reductions(Listeners),
            exit(ConnPid, kill),
            ok = wait_removed(Conns, ?DCID, 250),
            After = reductions(Listeners),
            %% A scan of the table costs on the order of its size. Any
            %% listener of the pool may have taken the Initial.
            ?assert(After - Before < ?OTHERS div 20),
            ?assertEqual([], ets:match_object(Conns, {'_', ConnPid})),
            ?assertEqual(?OTHERS, length(ets:match_object(Conns, {'_', Other})))
        after
            gen_udp:close(Sock),
            Other ! stop,
            quic_listener_sup:stop(Sup)
        end
    end}.

%% A pool listener that goes away takes its connections with it, and
%% their IDs must leave the table the pool shares: a packet for one of
%% them is otherwise routed to a dead process instead of drawing a
%% stateless reset, and the rows count against max_connections for good.
%% A listener that is killed runs no terminate, so both ways are checked.
routes_of_a_gone_listener_are_removed_test_() ->
    [
        {"listener stops", {timeout, 30, fun() -> gone_listener(fun quic_listener:stop/1) end}},
        {"listener is killed",
            {timeout, 30, fun() -> gone_listener(fun(L) -> exit(L, kill) end) end}}
    ].

gone_listener(Stop) ->
    Test = self(),
    {ok, Sup} = quic_listener_sup:start_link(0, #{
        connection_handler => handler(Test),
        psks => #{<<"id">> => <<"secret">>},
        alpn => [<<"h3">>]
    }),
    unlink(Sup),
    [Listener | _] = quic_listener_sup:get_listeners(Sup),
    {quic_listener_manager, Manager, _, _} =
        lists:keyfind(quic_listener_manager, 1, supervisor:which_children(Sup)),
    {ok, {Conns, _Tickets}} = quic_listener_manager:get_tables(Manager),
    {ok, Sock} = gen_udp:open(0, [binary]),
    try
        Port = quic_listener:get_port(Listener),
        DCIDs = [<<I:64>> || I <- lists:seq(1, 5)],
        ConnPids = [
            begin
                ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, initial(DCID)),
                receive
                    {conn, P} -> P
                after 5000 -> error(no_connection)
                end
            end
         || DCID <- DCIDs
        ],
        ?assertEqual(ConnPids, [P || DCID <- DCIDs, {_, P} <- ets:lookup(Conns, DCID)]),
        Ref = erlang:monitor(process, Listener),
        Stop(Listener),
        receive
            {'DOWN', Ref, process, Listener, _} -> ok
        after 5000 -> error(listener_still_up)
        end,
        ?assertEqual(ok, wait_no_routes_to(ConnPids, Conns, 250))
    after
        gen_udp:close(Sock),
        quic_listener_sup:stop(Sup)
    end.

wait_no_routes_to(Pids, Conns, Tries) ->
    case [Row || {_, P} = Row <- ets:tab2list(Conns), lists:member(P, Pids)] of
        [] ->
            ok;
        Rows when Tries =:= 0 ->
            {still_routed, Rows};
        _ ->
            timer:sleep(20),
            wait_no_routes_to(Pids, Conns, Tries - 1)
    end.

wait_removed(Conns, Key, 0) ->
    {still_routed, ets:lookup(Conns, Key)};
wait_removed(Conns, Key, Tries) ->
    case ets:lookup(Conns, Key) of
        [] ->
            ok;
        _ ->
            timer:sleep(20),
            wait_removed(Conns, Key, Tries - 1)
    end.

reductions(Pids) ->
    lists:sum([R || P <- Pids, {reductions, R} <- [process_info(P, reductions)]]).
