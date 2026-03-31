%%% -*- erlang -*-
%%%
%%% QUIC Distribution Test Supervisor
%%%

-module(quic_dist_test_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },
    ChildSpecs = [
        #{
            id => quic_dist_test_server,
            start => {quic_dist_test_server, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [quic_dist_test_server]
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.
