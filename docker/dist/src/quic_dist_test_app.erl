%%% -*- erlang -*-
%%%
%%% QUIC Distribution Test Application
%%%

-module(quic_dist_test_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    log_event(app_start, node()),
    quic_dist_test_sup:start_link().

stop(_State) ->
    log_event(app_stop, node()),
    ok.

log_event(Event, Data) ->
    io:format("[DIST_TEST] ~p ~p~n", [Event, Data]).
