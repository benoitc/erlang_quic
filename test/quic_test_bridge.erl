%%% -*- erlang -*-
%%%
%%% A UDP relay that can drop selected datagrams.
%%%
%%% Loss tests need to drop a specific packet, not a random one, so they
%%% sit a relay between client and server and decide per datagram. Two
%%% suites grew their own copy of this; a third would have been the point
%%% to stop, so it lives here instead.
%%%
%%% The relay sees datagrams, not frames. A 1-RTT payload is encrypted,
%%% so a rule can match on the long-header packet type and on how many
%%% datagrams have gone that way, and nothing else. Rules phrased in
%%% terms of a frame cannot be expressed here, and a test that needs one
%%% should assert against the qlog after the fact instead.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_test_bridge).

-export([start/1, set_conn/2, dropped/1, stop/1]).
-export([header_level/1]).

-export_type([drop_fun/0]).

%% Called once per datagram in its direction with the datagram and its
%% 1-based ordinal, counting the ones already dropped. True drops it.
-type drop_fun() :: fun((binary(), pos_integer()) -> boolean()).

-type opts() :: #{
    server := {inet:ip_address(), inet:port_number()},
    socket_ref := term(),
    %% Client to server
    drop_out => drop_fun(),
    %% Server to client
    drop_in => drop_fun()
}.

-define(KEEP, fun(_Pkt, _N) -> false end).

%% @doc Start a relay. It listens on an ephemeral port; point the client
%% at that port and give the relay the real server address.
-spec start(opts()) -> pid().
start(#{server := Server, socket_ref := SocketRef} = Opts) ->
    Parent = self(),
    spawn_link(fun() ->
        {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
        {ok, Port} = inet:port(Sock),
        Parent ! {bridge_port, self(), Port},
        loop(#{
            sock => Sock,
            conn => undefined,
            pending => [],
            server => Server,
            socket_ref => SocketRef,
            drop_out => maps:get(drop_out, Opts, ?KEEP),
            drop_in => maps:get(drop_in, Opts, ?KEEP),
            out_seen => 0,
            in_seen => 0,
            dropped => 0
        })
    end).

%% @doc Hand the relay the connection pid once it exists. Datagrams that
%% arrived first are delivered in order.
-spec set_conn(pid(), pid()) -> ok.
set_conn(Bridge, Conn) ->
    Bridge ! {set_conn, Conn},
    ok.

%% @doc How many datagrams the relay has dropped, in both directions.
-spec dropped(pid()) -> non_neg_integer().
dropped(Bridge) ->
    Bridge ! {report, self()},
    receive
        {dropped, N} -> N
    after 1000 -> error(bridge_report_timeout)
    end.

-spec stop(pid()) -> ok.
stop(Bridge) ->
    Bridge ! stop,
    ok.

%%====================================================================
%% Internals
%%====================================================================

loop(#{sock := Sock, server := {ServerIP, ServerPort}} = B) ->
    receive
        {set_conn, Conn} ->
            [deliver(B, Conn, D) || D <- lists:reverse(maps:get(pending, B))],
            loop(B#{conn := Conn, pending := []});
        {report, To} ->
            To ! {dropped, maps:get(dropped, B)},
            loop(B);
        %% The connection sends here as if this were its socket.
        {send, _IP, _Port, Pkt} ->
            Bin = iolist_to_binary(Pkt),
            N = maps:get(out_seen, B) + 1,
            B1 = B#{out_seen := N},
            case (maps:get(drop_out, B))(Bin, N) of
                true ->
                    loop(B1#{dropped := maps:get(dropped, B) + 1});
                false ->
                    ok = gen_udp:send(Sock, ServerIP, ServerPort, Bin),
                    loop(B1)
            end;
        {udp, Sock, _IP, _Port, Data} ->
            N = maps:get(in_seen, B) + 1,
            B1 = B#{in_seen := N},
            case (maps:get(drop_in, B))(Data, N) of
                true ->
                    loop(B1#{dropped := maps:get(dropped, B) + 1});
                false ->
                    case maps:get(conn, B1) of
                        undefined ->
                            loop(B1#{pending := [Data | maps:get(pending, B1)]});
                        Conn ->
                            deliver(B1, Conn, Data),
                            loop(B1)
                    end
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            loop(B)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.

%% @doc The packet type of a datagram's first packet. QUIC v1 long-header
%% types live in bits 4-5 of the first byte: Initial 0x00, 0-RTT 0x10,
%% Handshake 0x20, Retry 0x30. A short header carries no type, so a
%% 1-RTT datagram is only ever `short'.
-spec header_level(iodata()) -> initial | zero_rtt | handshake | retry | short.
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
