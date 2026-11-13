%%% -*- erlang -*-
%%%
%%% A credit update held behind a full congestion window.
%%%
%%% Every ack-eliciting packet waits for the congestion window (RFC 9002
%%% Section 7), MAX_DATA included. Here the server's echo is limited by
%%% the client's MAX_DATA, and everything the client sends is dropped for
%%% a while, so its window fills with its own upload and no ACK comes
%%% back to reopen it. The echo that still arrives uses up the credit,
%%% the server stops, and the MAX_DATA the client then owes has to leave
%%% in a PTO probe, which the window does not hold back (Section 7.5).
%%% The transfer completes once the path is back.
%%%
%%% Modelled on quinn's congested_tail_loss and
%%% quic_stranded_window_recovery_SUITE, whose harness this reuses.

-module(quic_credit_deadlock_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([credit_reaches_the_peer_while_the_window_is_full/1]).

%% Several times the receive window, in both directions.
-define(PAYLOAD_BYTES, 1024 * 1024).
%% The client's receive window.
-define(WINDOW, 65536).
%% Long enough for the window to fill and for PTOs to fire.
-define(BLACKHOLE_MS, 1500).
%% Largest datagram the connection sends; a window with less room than
%% this left is full.
-define(MAX_DATAGRAM, 1500).
%% Budget for the whole transfer once the path is back.
-define(RECOVER_MS, 30000).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [credit_reaches_the_peer_while_the_window_is_full].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

credit_reaches_the_peer_while_the_window_is_full(_Config) ->
    with_echo_server(fun(Conn, Bridge) ->
        {ok, StreamId} = quic:open_stream(Conn),
        Payload = payload(),
        ok = quic:send_data_async(Conn, StreamId, Payload, true),
        %% Let the echo start, so the server is waiting on our credit.
        First = collect_echo(Conn, StreamId, 5000, 0, ?WINDOW),
        ?assert(First > 0),
        Bridge ! blackhole,
        timer:sleep(?BLACKHOLE_MS),
        Held = path_stats(Conn),
        ct:pal("at the end of the outage: ~p", [Held]),
        %% The premise: the client's window is full.
        ?assert(maps:get(cwnd, Held) - maps:get(bytes_in_flight, Held) < ?MAX_DATAGRAM),
        Bridge ! heal,
        Echoed = collect_echo(Conn, StreamId, ?RECOVER_MS, First, ?PAYLOAD_BYTES),
        ct:pal("echoed ~p of ~p bytes~nfinal: ~p", [Echoed, ?PAYLOAD_BYTES, path_stats(Conn)]),
        ?assertEqual(?PAYLOAD_BYTES, Echoed)
    end).

%%====================================================================
%% Harness
%%====================================================================

payload() ->
    binary:copy(<<"x">>, ?PAYLOAD_BYTES).

path_stats(Conn) ->
    {ok, Stats} = quic:get_path_stats(Conn),
    Stats.

with_echo_server(Fun) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        {Conn, Bridge} = connect_through_bridge(maps:get(port, Server)),
        Fun(Conn, Bridge),
        _ = quic:safe_close(Conn, normal),
        ok
    after
        quic_test_echo_server:stop(Server)
    end.

%% Accumulate echoed bytes until Target is reached or the budget runs
%% out. The budget covers the transfer as a whole, so a trickle that
%% never finishes still fails.
collect_echo(_Conn, _StreamId, Budget, Acc, _Target) when Budget =< 0 ->
    Acc;
collect_echo(_Conn, _StreamId, _Budget, Acc, Target) when Acc >= Target ->
    Acc;
collect_echo(Conn, StreamId, Budget, Acc, Target) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc + byte_size(Data), Target);
        {quic, Conn, _Other} ->
            %% Session tickets and the like arrive on the same mailbox.
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc, Target)
    after Budget -> Acc
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

connect_through_bridge(Port) ->
    ServerIP = {127, 0, 0, 1},
    SocketRef = make_ref(),
    Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef) end),
    Adapter = #{
        send_fun => fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        close_fun => fun() ->
            Bridge ! stop,
            ok
        end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        %% A small receive window: the server's echo waits on our MAX_DATA.
        max_data => ?WINDOW,
        max_stream_data_bidi_local => ?WINDOW,
        max_stream_data_bidi_remote => ?WINDOW,
        max_receive_window => ?WINDOW,
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},
    receive
        {quic, Conn, {connected, _}} -> {Conn, Bridge}
    after 10000 -> ct:fail("connect timeout")
    end.

%% Relays between the client's socket adapter and a real UDP socket to
%% the server. In blackhole mode client packets are dropped rather than
%% forwarded, so nothing the client sends is acknowledged; `heal' puts
%% the path back. The server direction is never touched: its echo keeps
%% arriving until it runs out of credit.
bridge_init(ServerIP, ServerPort, SocketRef) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        blackhole => false,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        blackhole ->
            bridge_loop(Bridge#{blackhole := true});
        heal ->
            bridge_loop(Bridge#{blackhole := false});
        {send, _IP, _Port, Pkt} ->
            case maps:get(blackhole, Bridge) of
                true -> ok;
                false -> ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt)
            end,
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            case maps:get(conn, Bridge) of
                undefined ->
                    bridge_loop(Bridge#{pending := [Data | maps:get(pending, Bridge)]});
                Conn ->
                    deliver(Bridge, Conn, Data),
                    bridge_loop(Bridge)
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Bridge)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.
