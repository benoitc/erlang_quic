%%% -*- erlang -*-
%%%
%%% Diagnostic probe for the simultaneous-connect deadlock. Runs *inside*
%%% a peer node: arms tracing before the race, snapshots while the dials
%%% are still blocked, and tears everything down afterwards.
%%%
%%% The point is to answer one question with evidence rather than
%%% inference: which transition stalls. Entry traces alone cannot do it,
%%% so the interesting functions carry return traces - both branches of
%%% notify_acceptor/1 return ok, and reaching mark_pending/1 says nothing
%%% about what do_mark_pending/4 decided.

-module(quic_dist_race_probe).

-export([arm/0, snapshot/0, disarm/0]).

-define(COLLECTOR, quic_dist_race_collector).
-define(SYS_TIMEOUT, 1000).
-define(BIG_BINARY, 32).

%%====================================================================
%% Arming
%%====================================================================

arm() ->
    _ = disarm(),
    Collector = spawn(fun() -> collect([]) end),
    true = register(?COLLECTOR, Collector),
    %% new_processes covers the setup and accept workers spawned during
    %% the race, but misses net_kernel calling accept_connection/5 and
    %% the listener running notify_acceptor/1: both predate it.
    Existing = existing_pids(),
    Traced = [P || P <- Existing, trace_pid(P, Collector)],
    _ = safe(fun() -> erlang:trace(new_processes, true, [call, procs, {tracer, Collector}]) end),
    #{traced => Traced, patterns => set_patterns()}.

trace_pid(Pid, Collector) ->
    try
        erlang:trace(Pid, true, [call, procs, {tracer, Collector}]),
        true
    catch
        _:_ -> false
    end.

%% Narrow patterns only: tracing whole modules floods the collector and
%% can perturb the scheduling race being chased.
set_patterns() ->
    Ret = [{'_', [], [{return_trace}]}],
    Specs = [
        {{quic_dist, accept_connection, 5}, Ret},
        {{quic_dist, notify_acceptor, 1}, Ret},
        {{dist_util, handshake_other_started, 1}, Ret},
        {{dist_util, mark_pending, 1}, Ret},
        {{dist_util, do_mark_pending, 4}, Ret},
        {{dist_util, recv_name, 1}, Ret},
        %% Only the acceptor lookup, not every persistent_term read.
        {{persistent_term, get, 2}, [
            {[{quic_dist_acceptor, '_'}, '_'], [], [{return_trace}]}
        ]}
    ],
    [{MFA, safe(fun() -> erlang:trace_pattern(MFA, MS, [local]) end)} || {MFA, MS} <- Specs].

%%====================================================================
%% Snapshot
%%====================================================================

snapshot() ->
    #{
        at => erlang:system_time(millisecond),
        node => node(),
        nodes => nodes(),
        traces => drain(),
        net_kernel => pinfo(whereis(net_kernel)),
        listeners => [pinfo(P) || P <- listener_pids()],
        acceptors => [pinfo(P) || P <- acceptor_pids()],
        controllers => [controller_info(P) || P <- procs_of(quic_dist_controller)],
        connections => [connection_info(P) || P <- procs_of(quic_connection)]
    }.

%% Curated map: no key material, no buffers.
connection_info(Pid) ->
    State =
        try quic_connection:get_state(Pid) of
            {Name, Info} -> #{state => Name, info => Info}
        catch
            _:R -> #{error => R}
        end,
    maps:merge(#{pid => Pid}, maps:merge(State, pinfo_map(Pid))).

%% The controller record is small, but redact anything binary-and-large
%% rather than trusting that it stays that way.
controller_info(Pid) ->
    Sys =
        try sys:get_state(Pid, ?SYS_TIMEOUT) of
            S -> redact(S)
        catch
            _:R -> {error, R}
        end,
    maps:merge(#{pid => Pid, sys_state => Sys}, pinfo_map(Pid)).

redact(B) when is_binary(B), byte_size(B) > ?BIG_BINARY -> {redacted, byte_size(B)};
redact(T) when is_tuple(T) -> list_to_tuple([redact(E) || E <- tuple_to_list(T)]);
redact(L) when is_list(L) -> [redact(E) || E <- L];
redact(M) when is_map(M) -> maps:map(fun(_, V) -> redact(V) end, M);
redact(V) -> V.

pinfo(undefined) ->
    undefined;
pinfo(Pid) ->
    maps:merge(#{pid => Pid}, pinfo_map(Pid)).

pinfo_map(Pid) ->
    case process_info(Pid, [current_function, current_stacktrace, message_queue_len, status]) of
        undefined ->
            #{alive => false};
        Info ->
            maps:from_list(Info)
    end.

%%====================================================================
%% Teardown
%%====================================================================

disarm() ->
    _ = safe(fun() -> erlang:trace(new_processes, false, [call, procs]) end),
    [safe(fun() -> erlang:trace(P, false, [call, procs]) end) || P <- existing_pids()],
    [
        safe(fun() -> erlang:trace_pattern(MFA, false, [local]) end)
     || MFA <- [
            {quic_dist, accept_connection, 5},
            {quic_dist, notify_acceptor, 1},
            {dist_util, handshake_other_started, 1},
            {dist_util, mark_pending, 1},
            {dist_util, do_mark_pending, 4},
            {dist_util, recv_name, 1},
            {persistent_term, get, 2}
        ]
    ],
    case whereis(?COLLECTOR) of
        undefined ->
            ok;
        Pid ->
            unregister(?COLLECTOR),
            exit(Pid, kill),
            ok
    end.

safe(F) ->
    try
        F()
    catch
        _:R -> {error, R}
    end.

%%====================================================================
%% Discovery
%%====================================================================

%% The peers boot distribution before quic_sup exists, so the listener is
%% a standalone one recorded in persistent_term, not in the registry.
%% Match the key shape rather than reconstructing the name.
listener_pids() ->
    [
        Pid
     || {{quic_dist_early_listener, _}, #{pid := Pid}} <- persistent_term:get(),
        is_pid(Pid),
        is_process_alive(Pid)
    ].

acceptor_pids() ->
    [
        Pid
     || {{quic_dist_acceptor, _}, Pid} <- persistent_term:get(),
        is_pid(Pid),
        is_process_alive(Pid)
    ].

existing_pids() ->
    [P || P <- [whereis(net_kernel)], is_pid(P)] ++ listener_pids() ++ acceptor_pids().

procs_of(Mod) ->
    [P || P <- processes(), initial_module(P) =:= Mod].

initial_module(Pid) ->
    case process_info(Pid, dictionary) of
        {dictionary, D} ->
            case lists:keyfind('$initial_call', 1, D) of
                {_, {M, _, _}} -> M;
                _ -> undefined
            end;
        _ ->
            undefined
    end.

%%====================================================================
%% Collector
%%====================================================================

collect(Acc) ->
    receive
        {drain, From} ->
            From ! {traces, lists:reverse(Acc)},
            collect(Acc);
        Trace when element(1, Trace) =:= trace orelse element(1, Trace) =:= trace_ts ->
            collect([summarise(Trace) | Acc]);
        _Other ->
            collect(Acc)
    end.

%% Keep the shape, drop the payloads: arguments can carry key material.
summarise({trace, Pid, call, {M, F, A}}) -> {call, Pid, {M, F, length(A)}};
summarise({trace, Pid, return_from, MFA, Ret}) -> {return, Pid, MFA, redact(Ret)};
summarise({trace, Pid, spawned, By, {M, F, A}}) -> {spawned, Pid, By, {M, F, length(A)}};
summarise({trace, Pid, exit, Reason}) -> {exit, Pid, redact(Reason)};
summarise(Other) -> {other, element(2, Other), element(3, Other)}.

drain() ->
    case whereis(?COLLECTOR) of
        undefined ->
            [];
        Pid ->
            Pid ! {drain, self()},
            receive
                {traces, T} -> T
            after 2000 -> [{error, collector_timeout}]
            end
    end.
