%%% -*- erlang -*-
%%%
%%% A port nothing answers on.
%%%
%%% A unit test that starts a connection is about what the connection
%%% process does on its own, so the peer has to stay silent. Port 4433 is
%%% not silent: `docker/docker-compose.yml' publishes the aioquic interop
%%% server there, and 4434 the quic-go one, so with the interop stack up
%%% those tests handshake against a real server and assertions about an
%%% idle connection turn into a race.
%%%
%%% The port comes from a UDP socket this VM opens and holds for the
%%% whole run: nothing on the host can bind it, no server can reply, and
%%% because the socket exists the kernel sends no ICMP unreachable back
%%% either.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_test_silent_peer).

-export([port/0, port/1]).

%% @doc A silent port, the same one for every caller in this run.
-spec port() -> inet:port_number().
port() ->
    port(1).

%% @doc The N-th silent port, for a test that needs two peers that differ.
%% Each index keeps its own port for the rest of the run.
-spec port(pos_integer()) -> inet:port_number().
port(N) when is_integer(N), N > 0 ->
    case persistent_term:get({?MODULE, N}, undefined) of
        undefined -> open(N);
        Port -> Port
    end.

open(N) ->
    Test = self(),
    %% Owned by a process of its own, so the socket outlives the test
    %% that first asked for it.
    spawn(fun() ->
        {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
        {ok, Port} = inet:port(Socket),
        Test ! {silent_port, N, Port},
        receive
            stop -> gen_udp:close(Socket)
        end
    end),
    receive
        {silent_port, N, Port} ->
            persistent_term:put({?MODULE, N}, Port),
            Port
    after 1000 ->
        error({no_silent_port, N})
    end.
