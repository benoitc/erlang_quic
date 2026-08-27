%%% -*- erlang -*-
%%%
%%% A lost client Finished must still get through.
%%%
%%% The client's Certificate(+CertificateVerify)+Finished flight goes out
%%% at the Handshake encryption level. Once the client state machine
%%% leaves `handshaking' nothing retransmits it: handshake-space packets
%%% are not in the 1-RTT loss tracker, and the handshake retransmit timer
%%% only runs in that state.
%%%
%%% So a client whose Finished is dropped considers itself connected and
%%% starts sending 1-RTT data the server cannot act on before the
%%% handshake completes, while the server keeps replaying its own flight
%%% against ACK-only answers. Nothing breaks the tie and the connection
%%% dies on the idle timer with the Finished never acknowledged.
%%%
%%% One dropped datagram is enough, which makes this reachable on any
%%% lossy path rather than an exotic case.
%%%
%%% The bridge here drops the client's first Handshake-level datagrams
%%% and then lets everything through, so recovery depends entirely on the
%%% client resending the flight on its own.

-module(quic_lost_finished_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    control_no_loss/1,
    survives_one_lost_finished/1,
    survives_two_lost_finished/1
]).

-define(ECHO, <<"finished came back">>).
-define(CONNECT_MS, 15000).
-define(ECHO_MS, 20000).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [control_no_loss, survives_one_lost_finished, survives_two_lost_finished].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Fence: the same path with nothing dropped. Separates a real stall
%% from a broken harness.
control_no_loss(_Config) ->
    ?assertEqual(?ECHO, run(0)).

survives_one_lost_finished(_Config) ->
    ?assertEqual(?ECHO, run(1)).

survives_two_lost_finished(_Config) ->
    %% Two consecutive losses, so recovery cannot depend on a single
    %% retransmission happening to land.
    ?assertEqual(?ECHO, run(2)).

%%====================================================================
%% Harness
%%====================================================================

%% Connect with the first Drop client Handshake-level datagrams
%% discarded, then echo a payload. Returns what came back.
run(Drop) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Port = maps:get(port, Server),
        SocketRef = make_ref(),
        Self = self(),
        Bridge = spawn_link(fun() -> bridge_init({127, 0, 0, 1}, Port, SocketRef, Drop, Self) end),
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
            socket_backend => adapter,
            socket_adapter => Adapter
        },
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        Bridge ! {set_conn, Conn},
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout with ~p dropped", [Drop])
        end,
        Bridge ! {report, self()},
        receive
            {dropped, N} -> ct:pal("dropped ~p client Handshake datagram(s)", [N])
        after 2000 -> ok
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, ?ECHO, true),
        Got = await_echo(Conn, StreamId),
        _ = quic:safe_close(Conn, normal),
        Got
    after
        quic_test_echo_server:stop(Server)
    end.

await_echo(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} -> Data;
        {quic, Conn, _Other} -> await_echo(Conn, StreamId)
    after ?ECHO_MS -> timeout
    end.

%%====================================================================
%% Bridge
%%====================================================================

%% Relays between the client's socket adapter and a real UDP socket,
%% discarding the first Drop datagrams the client sends at the Handshake
%% encryption level. The long-header form and type bits sit outside the
%% header-protection mask, so the level is readable without keys.
bridge_init(ServerIP, ServerPort, SocketRef, Drop, Reporter) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        to_drop => Drop,
        dropped => 0,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef,
        reporter => Reporter
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        {report, To} ->
            To ! {dropped, maps:get(dropped, Bridge)},
            bridge_loop(Bridge);
        {send, _IP, _Port, Pkt} ->
            Left = maps:get(to_drop, Bridge),
            case Left > 0 andalso header_level(Pkt) =:= handshake of
                true ->
                    bridge_loop(Bridge#{
                        to_drop := Left - 1,
                        dropped := maps:get(dropped, Bridge) + 1
                    });
                false ->
                    ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
                    bridge_loop(Bridge)
            end;
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

%% QUIC v1 long-header packet types live in bits 4-5 of the first byte:
%% Initial 0x00, 0-RTT 0x10, Handshake 0x20, Retry 0x30.
header_level(Pkt) ->
    <<First:8, _/binary>> = iolist_to_binary(Pkt),
    case First band 16#80 of
        0 ->
            short;
        _ ->
            case First band 16#30 of
                16#00 -> initial;
                16#10 -> zero_rtt;
                16#20 -> handshake;
                _ -> retry
            end
    end.
