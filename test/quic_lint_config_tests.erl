%%% -*- erlang -*-
%%%
%%% One lint configuration, and it is the one Elvis reads.
%%%
%%% `elvis_core' consults `elvis.config' and falls back to the `elvis' key
%%% in `rebar.config' only when that file is missing or unusable; it never
%%% merges the two. Carrying both means edits to the ignored copy look
%%% applied and are not, which is how the two drifted apart before.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_lint_config_tests).

-include_lib("eunit/include/eunit.hrl").

%% The file Elvis actually reads has to exist and carry rules.
elvis_config_is_present_test() ->
    {ok, [Config]} = file:consult(filename:join(root(), "elvis.config")),
    ?assertMatch([_ | _], Config),
    ?assertNotEqual(undefined, proplists:get_value(config, Config)).

%% And nothing may sit in rebar.config pretending to configure lint.
rebar_config_has_no_elvis_key_test() ->
    {ok, RebarConfig} = file:consult(filename:join(root(), "rebar.config")),
    ?assertEqual(
        undefined,
        proplists:get_value(elvis, RebarConfig),
        "rebar.config carries an elvis key, which rebar3 lint ignores while "
        "elvis.config exists: put the rules in elvis.config instead"
    ).

root() ->
    {ok, Cwd} = file:get_cwd(),
    find_root(Cwd).

find_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true ->
            Dir;
        false ->
            case filename:dirname(Dir) of
                Dir -> error(project_root_not_found);
                Parent -> find_root(Parent)
            end
    end.
