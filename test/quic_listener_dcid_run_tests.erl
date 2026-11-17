%%% -*- erlang -*-
%%%
%%% A train of 1-RTT packets is grouped by connection with one routing
%%% table lookup per run of packets for the same connection ID.

-module(quic_listener_dcid_run_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID_LEN, 8).

groups_as_packet_by_packet_test() ->
    {A, B} = {self(), spawn(fun() -> ok end)},
    [A1, A2, A3, A4] = [short(<<"conn-aaa">>, N) || N <- [1, 2, 3, 4]],
    [B1, B2] = [short(<<"conn-bbb">>, N) || N <- [1, 2]],
    Unknown = short(<<"unknown!">>, 1),
    Long = <<16#E0, 1:32, 8, "conn-aaa", 8, "client-s", 0:320>>,
    {Groups, _} = group([A1, A2, B1, A3, Unknown, B2, Long, A4], [
        {<<"conn-aaa">>, A}, {<<"conn-bbb">>, B}
    ]),
    ?assertEqual(
        #{{conn, A} => [A4, Long, A3, A2, A1], {conn, B} => [B2, B1], unrouted => [Unknown]},
        Groups
    ).

one_lookup_per_run_test() ->
    Packets =
        [short(<<"conn-aaa">>, N) || N <- lists:seq(1, 20)] ++
            [short(<<"conn-bbb">>, N) || N <- lists:seq(1, 20)],
    {Groups, Lookups} = group(Packets, [{<<"conn-aaa">>, self()}, {<<"conn-bbb">>, self()}]),
    ?assertEqual(#{{conn, self()} => lists:reverse(Packets)}, Groups),
    ?assertEqual(2, Lookups).

short(DCID, N) ->
    <<16#40, DCID/binary, N:32, 0:160>>.

%% The grouping, and how many times it read the routing table.
group(Packets, Routes) ->
    Conns = ets:new(conns, [set, public]),
    true = ets:insert(Conns, Routes),
    Self = self(),
    Tracer = spawn_link(fun() -> count_lookups(Self, 0) end),
    try
        erlang:trace_pattern({ets, lookup, 2}, true, []),
        erlang:trace(Self, true, [call, {tracer, Tracer}]),
        Groups = quic_listener:group_packets_by_conn(Packets, ?DCID_LEN, Conns, #{}),
        erlang:trace(Self, false, [call]),
        Ref = erlang:trace_delivered(Self),
        receive
            {trace_delivered, Self, Ref} -> ok
        end,
        Tracer ! {count, Self},
        receive
            {lookups, N} -> {Groups, N}
        end
    after
        erlang:trace_pattern({ets, lookup, 2}, false, []),
        ets:delete(Conns)
    end.

count_lookups(Traced, N) ->
    receive
        {trace, Traced, call, {ets, lookup, _}} -> count_lookups(Traced, N + 1);
        {count, From} -> From ! {lookups, N}
    end.
