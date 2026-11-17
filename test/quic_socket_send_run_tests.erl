%%% -*- erlang -*-
%%%
%%% quic_socket:send_run/4 sends a run of packets as send/4 would one at
%%% a time, and the connection tracks the ones that went out.

-module(quic_socket_send_run_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LOCAL, {127, 0, 0, 1}).

%% Same datagrams, in the same order, across batch boundaries, and the
%% same batch left pending.
matches_send_test() ->
    {ok, Recv} = gen_udp:open(0, [binary, {active, false}, {ip, ?LOCAL}]),
    {ok, Port} = inet:port(Recv),
    Packets = [<<N, (binary:copy(<<N>>, 100))/binary>> || N <- lists:seq(1, 11)],
    Open = fun() ->
        {ok, State} = quic_socket:open(0, #{batching => #{enabled => true, max_packets => 4}}),
        State
    end,
    {Run, []} = quic_socket:send_run(Open(), ?LOCAL, Port, Packets),
    ?assertEqual({Run, []}, quic_socket:send_run(Run, ?LOCAL, Port, [])),
    ?assertEqual(3, maps:get(batch_pending, quic_socket:info(Run))),
    {ok, Flushed} = quic_socket:flush(Run),
    ?assertEqual(Packets, [recv(Recv) || _ <- Packets]),
    OneByOne = lists:foldl(
        fun(Packet, State) ->
            {ok, State1} = quic_socket:send(State, ?LOCAL, Port, Packet),
            State1
        end,
        Open(),
        Packets
    ),
    ?assertEqual(quic_socket:info(OneByOne), quic_socket:info(Run)),
    {ok, _} = quic_socket:flush(OneByOne),
    ?assertEqual(Packets, [recv(Recv) || _ <- Packets]),
    ok = quic_socket:close(Flushed),
    ok = quic_socket:close(OneByOne),
    gen_udp:close(Recv).

%% A send that fails is reported by its position in the run, and the run
%% goes on.
reports_failed_positions_test() ->
    Sends = fun
        (_IP, _Port, <<2>>) -> {error, eperm};
        (_IP, _Port, _Packet) -> ok
    end,
    {ok, State} = quic_socket:open_adapter(#{send_fun => Sends}),
    ?assertMatch(
        {_, [{1, eperm}]}, quic_socket:send_run(State, ?LOCAL, 4433, [<<1>>, <<2>>, <<3>>])
    ).

tracks_a_refused_packet_too_test() ->
    Packets = [<<1:80>>, <<2:160>>, <<3:240>>],
    Tracked = [{9, 30, c}, {8, 20, b}, {7, 10, a}],
    ?assertEqual(Tracked, quic_connection:track_run(Packets, [a, b, c], 7, [], 0, [])),
    ?assertEqual(Tracked, quic_connection:track_run(Packets, [a, b, c], 7, [{1, eperm}], 0, [])).

recv(Socket) ->
    {ok, {_, _, Datagram}} = gen_udp:recv(Socket, 0, 2000),
    Datagram.
