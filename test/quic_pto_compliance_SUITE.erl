%%% -*- erlang -*-
%%%
%%% Per-space recovery, end to end.
%%%
%%% The unit tests pin the selector and the discard rules on synthetic
%%% state. These cases run real connections and lose real packets, which
%%% is the only way to show that a flight lost in a given packet number
%%% space is actually recovered by that space's probe, now that the three
%%% ad-hoc retransmission timers that used to do it are gone.
%%%
%%% Each loss case has a no-loss fence, so a case that stops losing
%%% anything fails rather than passing on a handshake that was never
%%% disturbed. Every case reports what it dropped.
%%%
%%% The relay sees datagrams, not frames: a 1-RTT payload is encrypted,
%%% so a rule can match the long-header packet type and the datagram's
%%% ordinal and nothing else. Where a case cares which frame was lost it
%%% says so from the qlog afterwards rather than pretending the relay
%%% could have known.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_pto_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0]).
-export([
    control_no_loss/1,
    initial_flight_recovers/1,
    handshake_flight_recovers/1,
    first_app_datagram_recovers/1,
    handshake_spaces_are_discarded/1
]).

-define(CONNECT_MS, 20000).
-define(ECHO_MS, 20000).
-define(ECHO, <<"per-space recovery">>).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [
        control_no_loss,
        initial_flight_recovers,
        handshake_flight_recovers,
        first_app_datagram_recovers,
        handshake_spaces_are_discarded
    ].

%%====================================================================
%% Cases
%%====================================================================

%% Fence: the same harness with nothing dropped. A failure here means
%% the relay itself is broken, not the recovery under test.
control_no_loss(_Config) ->
    {Echo, Dropped} = run(#{}),
    ?assertEqual(?ECHO, Echo),
    ?assertEqual(0, Dropped).

%% RFC 9002 Section 6.2.1: the Initial space has its own probe. Drop the
%% client's first two Initial datagrams, which is its whole ClientHello
%% flight, so the handshake can only start once that probe replays it.
initial_flight_recovers(_Config) ->
    {Echo, Dropped} = run(#{
        drop_out => fun(Pkt, N) ->
            N =< 2 andalso quic_test_bridge:header_level(Pkt) =:= initial
        end
    }),
    ?assertEqual(?ECHO, Echo),
    ?assert(Dropped >= 1).

%% The Handshake space likewise. Dropping what the server sends at that
%% level removes its Finished, which only the Handshake probe can bring
%% back now that the server's retained flight is gone.
handshake_flight_recovers(_Config) ->
    {Echo, Dropped} = run(#{
        drop_in => fun(Pkt, N) ->
            N =< 4 andalso quic_test_bridge:header_level(Pkt) =:= handshake
        end
    }),
    ?assertEqual(?ECHO, Echo),
    ?assert(Dropped >= 1).

%% The first 1-RTT datagram the server sends carries HANDSHAKE_DONE.
%% Dropping it delays the client's confirmation, which is exactly the
%% window in which the application probe must stay unarmed; the
%% connection still has to complete and carry data afterwards.
%%
%% The rule is the datagram's header form and ordinal because that is
%% all the relay can see. Which frame it held is not asserted here.
first_app_datagram_recovers(_Config) ->
    {Echo, Dropped} = run(#{
        drop_in => fun(Pkt, N) ->
            N >= 1 andalso quic_test_bridge:header_level(Pkt) =:= short
        end,
        drop_limit => 1
    }),
    ?assertEqual(?ECHO, Echo),
    ?assert(Dropped >= 1).

%% RFC 9002 Appendix A.11 and RFC 9001 Section 4.9: once the handshake
%% is confirmed neither handshake space holds packets, neither is
%% charged against bytes in flight, and the keys are gone. Left tracked
%% they could never be acknowledged, and would hold the in-flight count
%% above zero for the life of the connection.
handshake_spaces_are_discarded(_Config) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        #{port := Port, name := Name} = Server,
        {ok, Conn} = quic:connect(
            "127.0.0.1", Port, quic_test_echo_server:client_opts(), self()
        ),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after ?CONNECT_MS -> ct:fail("connect timeout")
            end,
            {ok, [ServerConn | _]} = quic:get_server_connections(Name),
            ?assert(confirmed_within(Conn, 5000)),
            ?assert(confirmed_within(ServerConn, 5000)),
            [assert_discarded(Role, Pid) || {Role, Pid} <- [{client, Conn}, {server, ServerConn}]]
        after
            _ = quic:safe_close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Server)
    end.

%%====================================================================
%% Helpers
%%====================================================================

assert_discarded(Role, Pid) ->
    {_StateName, Data} = sys:get_state(Pid),
    Loss = quic_connection_test_support:loss_state(Data),
    ?assertEqual(
        {Role, 0, 0},
        {Role, maps:size(quic_loss:sent_packets(initial, Loss)),
            maps:size(quic_loss:sent_packets(handshake, Loss))}
    ),
    ?assertEqual(
        {Role, undefined, undefined},
        {Role, quic_connection_test_support:state_get(Data, initial_keys),
            quic_connection_test_support:state_get(Data, handshake_keys)}
    ).

confirmed_within(_Pid, Budget) when Budget =< 0 ->
    false;
confirmed_within(Pid, Budget) ->
    {_StateName, Data} = sys:get_state(Pid),
    case quic_loss:handshake_confirmed(quic_connection_test_support:loss_state(Data)) of
        true ->
            true;
        false ->
            timer:sleep(20),
            confirmed_within(Pid, Budget - 20)
    end.

%% Connect through the relay under the given drop rules, echo a payload,
%% and report what came back with how many datagrams were lost.
run(Rules) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Port = maps:get(port, Server),
        SocketRef = make_ref(),
        Bridge = quic_test_bridge:start(bridge_opts(Rules, Port, SocketRef)),
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            socket_backend => adapter,
            socket_adapter => #{
                send_fun => fun(IP, P, Pkt) ->
                    Bridge ! {send, IP, P, Pkt},
                    ok
                end,
                close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
                local => {{127, 0, 0, 1}, 0},
                socket_ref => SocketRef
            }
        },
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        ok = quic_test_bridge:set_conn(Bridge, Conn),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout")
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, ?ECHO, true),
        Echo = await_echo(Conn, StreamId),
        Dropped = quic_test_bridge:dropped(Bridge),
        ct:pal("dropped ~p datagram(s)", [Dropped]),
        _ = quic:safe_close(Conn, normal),
        {Echo, Dropped}
    after
        quic_test_echo_server:stop(Server)
    end.

%% `drop_limit' caps how many datagrams a rule may take, so a rule that
%% would otherwise match every datagram of its shape stops after the few
%% the case is about.
bridge_opts(Rules, Port, SocketRef) ->
    Base = #{server => {{127, 0, 0, 1}, Port}, socket_ref => SocketRef},
    Limit = maps:get(drop_limit, Rules, infinity),
    Counter = counters:new(1, []),
    maps:fold(
        fun
            (drop_limit, _V, Acc) ->
                Acc;
            (Key, Pred, Acc) ->
                Acc#{Key => capped(Pred, Counter, Limit)}
        end,
        Base,
        Rules
    ).

capped(Pred, Counter, Limit) ->
    fun(Pkt, N) ->
        case Pred(Pkt, N) andalso counters:get(Counter, 1) < Limit of
            true ->
                counters:add(Counter, 1, 1),
                true;
            false ->
                false
        end
    end.

await_echo(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} -> Data;
        {quic, Conn, _Other} -> await_echo(Conn, StreamId)
    after ?ECHO_MS -> timeout
    end.
