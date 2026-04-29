%%% -*- erlang -*-
%%%
%%% Tests for the per-node connect-options registry exposed by
%%% quic_dist:set_connect_options/2 and friends.
%%%
%%% Behavioural verification only - the actual merge into quic:connect/4
%%% is exercised by the dist e2e suites.

-module(quic_dist_connect_opts_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    set_get_clear/1,
    overwrite_existing/1,
    get_returns_empty_when_unset/1,
    table_created_lazily/1
]).

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [
        set_get_clear,
        overwrite_existing,
        get_returns_empty_when_unset,
        table_created_lazily
    ].

init_per_testcase(_Name, Config) ->
    %% Drop any leftover entry from a previous test.
    catch ets:delete(quic_dist_connect_opts),
    Config.

end_per_testcase(_Name, _Config) ->
    catch ets:delete(quic_dist_connect_opts),
    ok.

%%====================================================================
%% Tests
%%====================================================================

set_get_clear(_Config) ->
    Node = 'peer@localhost',
    Opts = #{socket_backend => adapter, foo => bar},

    ?assertEqual(#{}, quic_dist:get_connect_options(Node)),

    ok = quic_dist:set_connect_options(Node, Opts),
    ?assertEqual(Opts, quic_dist:get_connect_options(Node)),

    ok = quic_dist:clear_connect_options(Node),
    ?assertEqual(#{}, quic_dist:get_connect_options(Node)).

overwrite_existing(_Config) ->
    Node = 'peer@localhost',
    ok = quic_dist:set_connect_options(Node, #{a => 1}),
    ok = quic_dist:set_connect_options(Node, #{a => 2, b => 3}),
    ?assertEqual(#{a => 2, b => 3}, quic_dist:get_connect_options(Node)).

get_returns_empty_when_unset(_Config) ->
    ?assertEqual(#{}, quic_dist:get_connect_options('never-registered@nowhere')).

table_created_lazily(_Config) ->
    %% init_per_testcase already dropped the table; first read should
    %% not crash.
    undefined = ets:info(quic_dist_connect_opts),
    ?assertEqual(#{}, quic_dist:get_connect_options('peer@localhost')),

    ok = quic_dist:clear_connect_options('peer@localhost'),

    %% First write creates the table.
    ok = quic_dist:set_connect_options('peer@localhost', #{x => 1}),
    ?assert(is_list(ets:info(quic_dist_connect_opts))).
