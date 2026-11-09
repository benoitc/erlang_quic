%%% -*- erlang -*-
%%%
%%% QUIC Listener Pool Supervisor
%%% RFC 9000 Section 5 - Connections
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @private

-module(quic_listener_manager).

-behaviour(gen_server).

-export([get_tables/1, cid_index_heir/1, delete_routes/2]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-type state() :: {ets:table(), ets:table()}.

-spec get_tables(pid()) -> {ok, state()}.
get_tables(Pid) ->
    gen_server:call(Pid, get_tables).

%% @doc The `heir' option for a pool listener's CID index. A listener
%% that terminates removes its own rows from the shared routing table;
%% one that is killed cannot, so its index passes to the manager, which
%% removes them.
-spec cid_index_heir(pid()) -> {heir, pid(), cid_index}.
cid_index_heir(Pid) ->
    {heir, Pid, cid_index}.

%% @doc Remove one listener's connection IDs, as listed in its index,
%% from the shared routing table, and drop the index.
-spec delete_routes(ets:table(), ets:table()) -> ok.
delete_routes(Index, ConnTab) ->
    try
        ets:foldl(
            fun({Pid, CID}, ok) ->
                ets:delete_object(ConnTab, {CID, Pid}),
                ok
            end,
            ok,
            Index
        ),
        ets:delete(Index),
        ok
    catch
        error:badarg -> ok
    end.

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link(?MODULE, noargs, [{hibernate_after, 50}]).

-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    Opts = [set, public, {read_concurrency, true}, {write_concurrency, auto}],
    ConnTab = ets:new(quic_pool_connections, Opts),
    TicketTab = ets:new(quic_server_tickets, Opts),
    {ok, {ConnTab, TicketTab}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, {ok, state()} | not_implemented, state()}.
handle_call(get_tables, _From, Tabs) ->
    {reply, {ok, Tabs}, Tabs};
handle_call(_Request, _From, Tabs) ->
    {reply, not_implemented, Tabs}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, Tabs) ->
    {noreply, Tabs}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({'ETS-TRANSFER', Index, _Listener, cid_index}, {ConnTab, _} = Tabs) ->
    delete_routes(Index, ConnTab),
    {noreply, Tabs};
handle_info(_Msg, Tabs) ->
    {noreply, Tabs}.
