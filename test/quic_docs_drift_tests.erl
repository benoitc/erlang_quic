%%% -*- erlang -*-
%%%
%%% Checks that the documentation still describes this code.
%%%
%%% Docs drift silently: an option is renamed, a function goes away, a
%%% suite is deleted, and the guide keeps saying otherwise until a reader
%%% copies it and loses an afternoon. These checks catch the classes of
%%% drift that can be settled mechanically. Defaults are deliberately not
%%% compared wholesale; the comment above versions_agree_test/0 says why.
%%%
%%% Each check also asserts a floor on how much it inspected, so a parser
%%% that stops matching fails loudly instead of passing vacuously.
-module(quic_docs_drift_tests).

-include_lib("eunit/include/eunit.hrl").

%% Options a doc table names that no accessor in src/ reads. Empty is the
%% goal; an entry here needs a comment saying why it cannot be checked.
-define(OPTION_ALLOWLIST, []).

%% Headings whose bullet lists document option keys.
-define(OPTION_HEADINGS, ["Options", "Extension Hooks"]).

%%====================================================================
%% Checks
%%====================================================================

%% Every option named in a docs table must be read somewhere in src/.
option_names_exist_test() ->
    Root = root(),
    Known = option_keys(Root),
    ?assert(length(Known) > 100),
    {Checked, Problems} = lists:foldl(
        fun({File, Line, Name}, {N, Acc}) ->
            case lists:member(Name, Known) orelse lists:member(Name, ?OPTION_ALLOWLIST) of
                true ->
                    {N + 1, Acc};
                false ->
                    {N + 1, [
                        fmt("~s:~p option `~s` is documented but no accessor in src/ reads it", [
                            File, Line, Name
                        ])
                        | Acc
                    ]}
            end
        end,
        {0, []},
        documented_options(Root)
    ),
    ?debugFmt("option names: checked ~p", [Checked]),
    ?assert(Checked > 130),
    ?assertEqual([], lists:reverse(Problems)).

%% Every `mod:fun/arity' in the docs must be exported by that module.
%% Only modules of this application are checked; `h1_capsule' and friends
%% belong to sibling libraries and are skipped.
referenced_functions_exist_test() ->
    Root = root(),
    AppModules = app_modules(Root),
    {Checked, Problems} = lists:foldl(
        fun({File, Line, Mod, Fun, Arity}, {N, Acc}) ->
            case lists:member(Mod, AppModules) of
                false ->
                    {N, Acc};
                true ->
                    case is_exported(Mod, Fun, Arity) of
                        true ->
                            {N + 1, Acc};
                        false ->
                            {N + 1, [
                                fmt("~s:~p ~s:~s/~p is documented but not exported", [
                                    File, Line, Mod, Fun, Arity
                                ])
                                | Acc
                            ]}
                    end
            end
        end,
        {0, []},
        documented_functions(Root)
    ),
    ?debugFmt("function references: checked ~p", [Checked]),
    ?assert(Checked > 20),
    ?assertEqual([], lists:reverse(Problems)).

%% Every suite the docs tell a reader to run must exist.
referenced_suites_exist_test() ->
    Root = root(),
    {Checked, Problems} = lists:foldl(
        fun({File, Line, Suite}, {N, Acc}) ->
            Path = filename:join([Root, "test", Suite ++ ".erl"]),
            case filelib:is_file(Path) of
                true ->
                    {N + 1, Acc};
                false ->
                    {N + 1, [
                        fmt("~s:~p suite ~s does not exist in test/", [File, Line, Suite]) | Acc
                    ]}
            end
        end,
        {0, []},
        documented_suites(Root)
    ),
    ?debugFmt("suite references: checked ~p", [Checked]),
    ?assert(Checked >= 3),
    ?assertEqual([], lists:reverse(Problems)).

%% src/quic.app.src is the version; everything else must agree with it.
versions_agree_test() ->
    Root = root(),
    Vsn = app_vsn(Root),
    MinorVsn = major_minor(Vsn),
    Problems =
        makefile_version_problem(Root, Vsn) ++
            security_version_problems(Root, MinorVsn) ++
            install_tag_problems(Root, Vsn),
    ?assertEqual([], Problems).

%% Why defaults are not compared here:
%%
%% `verify', `groups' and `alpn' have different client and server defaults
%% in one file, `ciphers' is computed, `reset_secret' is random,
%% `max_udp_payload_size' is a sentinel resolved downstream, and
%% `delivery_coalescing' hides its default inside a helper. Comparing every
%% documented default would report those as failures forever, and a check
%% people learn to ignore is worse than no check.

%%====================================================================
%% Documentation scanning
%%====================================================================

%% Options documented either as table rows or as bullets. Rows come from
%% the first cell of a `| Option | Type | Default | ... |' table; rows whose
%% first cell is not a plain `name' (prose, separators, headers) are
%% skipped. Bullets come from `- `name` - ...' lines under an options
%% heading.
documented_options(Root) ->
    lists:flatmap(
        fun(File) ->
            Rel = rel(Root, File),
            Lines = lines(File),
            {_, Rows} = lists:foldl(
                fun({Line, Text}, {InTable, Acc}) ->
                    scan_option_row(Rel, Line, Text, InTable, Acc)
                end,
                {false, []},
                Lines
            ),
            {_, Bullets} = lists:foldl(
                fun({Line, Text}, {InSection, Acc}) ->
                    scan_option_bullet(Rel, Line, Text, InSection, Acc)
                end,
                {false, []},
                Lines
            ),
            lists:reverse(Rows) ++ lists:reverse(Bullets)
        end,
        doc_files(Root)
    ).

%% Bullets are options only under a heading that says so. The same
%% `- `name` - ...' shape lists modules under other headings, and those
%% are not option keys.
scan_option_bullet(File, Line, Text, InSection, Acc) ->
    case re:run(Text, "^#+\\s+(.*?)\\s*$", [{capture, [1], list}]) of
        {match, [Heading]} ->
            {lists:member(Heading, ?OPTION_HEADINGS), Acc};
        nomatch when InSection ->
            case re:run(Text, "^\\s*-\\s+`([a-z][a-z_0-9]*)`\\s*[-(]", [{capture, [1], list}]) of
                {match, [Name]} -> {true, [{File, Line, Name} | Acc]};
                nomatch -> {true, Acc}
            end;
        nomatch ->
            {false, Acc}
    end.

%% Only rows of a table whose first column is "Option" are options. The
%% same pipe-table shape carries qlog event names, module lists and state
%% record fields, none of which are read as option keys.
scan_option_row(File, Line, Text, InTable, Acc) ->
    case table_first_cell(Text) of
        {ok, "Option"} ->
            {true, Acc};
        {ok, Cell} when InTable ->
            case re:run(Cell, "^`([a-z][a-z_0-9]*)`$", [{capture, [1], list}]) of
                {match, [Name]} -> {true, [{File, Line, Name} | Acc]};
                nomatch -> {true, Acc}
            end;
        {ok, _} ->
            {InTable, Acc};
        none ->
            %% Separator rows sit inside the table; anything else ends it.
            {InTable andalso is_table_line(Text), Acc}
    end.

is_table_line(Text) ->
    case string:trim(Text) of
        "|" ++ _ -> true;
        _ -> false
    end.

documented_functions(Root) ->
    RE = "`([a-z][a-z_0-9]*):([a-z][a-zA-Z_0-9]*)/([0-9]+(?:,[0-9]+)*)`",
    lists:flatmap(
        fun(File) ->
            lists:flatmap(
                fun({Line, Text}) ->
                    case re:run(Text, RE, [global, {capture, all_but_first, list}]) of
                        {match, Matches} ->
                            [
                                {rel(Root, File), Line, list_to_atom(M), list_to_atom(F), A}
                             || [M, F, Arities] <- Matches,
                                A <- [list_to_integer(S) || S <- string:lexemes(Arities, ",")]
                            ];
                        nomatch ->
                            []
                    end
                end,
                lines(File)
            )
        end,
        doc_files(Root)
    ).

documented_suites(Root) ->
    RE = "--suite=([A-Za-z_0-9,\\\\\n ]+)",
    lists:flatmap(
        fun(File) ->
            lists:flatmap(
                fun({Line, Text}) ->
                    case re:run(Text, RE, [global, {capture, all_but_first, list}]) of
                        {match, Matches} ->
                            [
                                {rel(Root, File), Line, Suite}
                             || [Raw] <- Matches,
                                Suite <- string:lexemes(Raw, ",\\ "),
                                Suite =/= []
                            ];
                        nomatch ->
                            []
                    end
                end,
                lines(File)
            )
        end,
        doc_files(Root)
    ).

%% The cell before the first `|' separator, or `none' for a non-table line
%% and for separator rows.
table_first_cell(Text) ->
    case string:trim(Text) of
        "|" ++ Rest ->
            case string:split(Rest, "|") of
                [Cell | _] ->
                    Trimmed = string:trim(Cell),
                    case is_separator(Trimmed) of
                        true -> none;
                        false -> {ok, Trimmed}
                    end;
                _ ->
                    none
            end;
        _ ->
            none
    end.

is_separator([]) -> true;
is_separator(S) -> lists:all(fun(C) -> C =:= $- orelse C =:= $: orelse C =:= $\s end, S).

%%====================================================================
%% Source scanning
%%====================================================================

%% Every atom read as an option key. Covers the map accessors plus the
%% proplist-style helpers dist config uses (`get_opt', `get_init_arg') and
%% the boolean helper, which hides the key in a wrapper.
option_keys(Root) ->
    REs = [
        "maps:get\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "maps:find\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "maps:is_key\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "proplists:get_value\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "proplists:get_bool\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "bool_opt\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "get_opt\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,",
        "get_init_arg\\(\\s*([a-z][a-zA-Z_0-9]*)\\s*,"
    ],
    Keys = lists:flatmap(
        fun(File) ->
            {ok, Bin} = file:read_file(File),
            Text = binary_to_list(Bin),
            lists:flatmap(
                fun(RE) ->
                    case re:run(Text, RE, [global, {capture, all_but_first, list}]) of
                        {match, Matches} -> [K || [K] <- Matches];
                        nomatch -> []
                    end
                end,
                REs
            )
        end,
        src_files(Root)
    ),
    lists:usort(Keys).

app_modules(Root) ->
    [list_to_atom(filename:basename(F, ".erl")) || F <- src_files(Root)].

is_exported(Mod, Fun, Arity) ->
    case code:ensure_loaded(Mod) of
        {module, Mod} -> erlang:function_exported(Mod, Fun, Arity);
        {error, _} -> false
    end.

%%====================================================================
%% Versions
%%====================================================================

app_vsn(Root) ->
    {ok, [{application, quic, Props}]} = file:consult(filename:join([Root, "src", "quic.app.src"])),
    proplists:get_value(vsn, Props).

major_minor(Vsn) ->
    [Major, Minor | _] = string:lexemes(Vsn, "."),
    Major ++ "." ++ Minor.

makefile_version_problem(Root, Vsn) ->
    File = filename:join(Root, "Makefile"),
    Found = [
        string:trim(V)
     || {_, Text} <- lines(File),
        {match, [V]} <- [
            re:run(Text, "^PROJECT_VERSION\\s*=\\s*(.+)$", [{capture, [1], list}])
        ]
    ],
    case Found of
        [Vsn] -> [];
        [] -> [fmt("Makefile has no PROJECT_VERSION", [])];
        [Other | _] -> [fmt("Makefile PROJECT_VERSION is ~s, app.src says ~s", [Other, Vsn])]
    end.

security_version_problems(Root, MinorVsn) ->
    File = filename:join(Root, "SECURITY.md"),
    Supported = [
        V
     || {_, Text} <- lines(File),
        {match, [V]} <- [
            re:run(Text, "^\\|\\s*([0-9]+\\.[0-9]+)\\.x\\s*\\|\\s*yes", [{capture, [1], list}])
        ]
    ],
    case Supported of
        [MinorVsn] ->
            [];
        [] ->
            [fmt("SECURITY.md lists no supported x.y.x line", [])];
        [Other | _] ->
            [fmt("SECURITY.md supports ~s.x, the release is ~s.x", [Other, MinorVsn])]
    end.

install_tag_problems(Root, Vsn) ->
    lists:flatmap(
        fun(File) ->
            [
                fmt("~s:~p install snippet pins tag ~s, the release is ~s", [
                    rel(Root, File), Line, Tag, Vsn
                ])
             || {Line, Text} <- lines(File),
                {match, [Tag]} <- [
                    re:run(Text, "\\{tag,\\s*\"([^\"]+)\"\\}", [{capture, [1], list}])
                ],
                Tag =/= Vsn
            ]
        end,
        doc_files(Root)
    ).

%%====================================================================
%% Files
%%====================================================================

doc_files(Root) ->
    filelib:wildcard(filename:join([Root, "docs", "*.md"])) ++
        [
            filename:join(Root, F)
         || F <- ["README.md", "AGENTS.md", "SECURITY.md", "CONTRIBUTING.md"],
            filelib:is_file(filename:join(Root, F))
        ].

src_files(Root) ->
    filelib:wildcard(filename:join([Root, "src", "**", "*.erl"])) ++
        filelib:wildcard(filename:join([Root, "src", "*.erl"])).

lines(File) ->
    {ok, Bin} = file:read_file(File),
    Texts = string:split(binary_to_list(Bin), "\n", all),
    lists:zip(lists:seq(1, length(Texts)), Texts).

rel(Root, File) ->
    case string:prefix(File, Root ++ "/") of
        nomatch -> File;
        Rest -> Rest
    end.

%% The project root, found the way quic_qpack_interop_SUITE finds it.
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

fmt(Format, Args) ->
    lists:flatten(io_lib:format(Format, Args)).
