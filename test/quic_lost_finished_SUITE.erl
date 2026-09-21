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
    survives_two_lost_finished/1,
    survives_four_lost_finished/1
]).

-define(ECHO, <<"finished came back">>).
-define(CONNECT_MS, 15000).
-define(ECHO_MS, 20000).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [
        control_no_loss,
        survives_one_lost_finished,
        survives_two_lost_finished,
        survives_four_lost_finished
    ].

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

%% Past what the server's own retransmissions can prompt: recovery here
%% needs the client's flight timer to keep firing on its own schedule.
survives_four_lost_finished(_Config) ->
    ?assertEqual(?ECHO, run(4)).

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
        %% Drop the first `Drop' Handshake-level datagrams the client
        %% sends. The long-header form and type bits sit outside the
        %% header-protection mask, so the level is readable without keys.
        Bridge = quic_test_bridge:start(#{
            server => {{127, 0, 0, 1}, Port},
            socket_ref => SocketRef,
            drop_out => fun(Pkt, N) ->
                N =< Drop andalso quic_test_bridge:header_level(Pkt) =:= handshake
            end
        }),
        Adapter = #{
            send_fun => fun(IP, P, Pkt) ->
                Bridge ! {send, IP, P, Pkt},
                ok
            end,
            close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
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
        ok = quic_test_bridge:set_conn(Bridge, Conn),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout with ~p dropped", [Drop])
        end,
        ct:pal("dropped ~p client Handshake datagram(s)", [quic_test_bridge:dropped(Bridge)]),
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
