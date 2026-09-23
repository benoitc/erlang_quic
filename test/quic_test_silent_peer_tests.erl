%%% -*- erlang -*-
%%%
%%% The silent peer, and the rule it exists to enforce.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_test_silent_peer_tests).

-include_lib("eunit/include/eunit.hrl").

%% Ports the interop stack publishes on the host
%% (`docker/docker-compose.yml'), which is what makes a literal port in a
%% unit test unsafe.
-define(INTEROP_PORTS, [4433, 4434, 4435, 4436]).

%%====================================================================
%% The port
%%====================================================================

the_same_port_every_time_test() ->
    ?assertEqual(quic_test_silent_peer:port(), quic_test_silent_peer:port()).

indexes_get_ports_of_their_own_test() ->
    ?assertNotEqual(quic_test_silent_peer:port(1), quic_test_silent_peer:port(2)).

not_an_interop_port_test() ->
    ?assertNot(lists:member(quic_test_silent_peer:port(), ?INTEROP_PORTS)).

%% Held for the run, so no other test and nothing on the host can take it
%% and start answering.
the_port_is_ours_test() ->
    ?assertEqual(
        {error, eaddrinuse},
        gen_udp:open(quic_test_silent_peer:port(), [binary, {active, false}])
    ).

%% The point of the whole thing: a QUIC packet sent there is not answered.
%% Probed with an unsupported version, which any live QUIC server replies
%% to with Version Negotiation (RFC 9000 Section 6).
nothing_answers_there_test() ->
    ?assertNot(quic_test_peer:reachable("127.0.0.1", quic_test_silent_peer:port())).

%%====================================================================
%% The rule
%%====================================================================

%% A unit test that starts a connection must name a port it controls.
%% With a literal one it can reach whatever happens to be listening,
%% which for 4433 and 4434 is an interop server whenever the stack is up.
%% Common Test suites are exempt: `quic_interop_SUITE' dials those peers
%% on purpose.
unit_tests_dial_a_port_they_control_test() ->
    Offenders = [
        {filename:basename(File), Line, Text}
     || File <- filelib:wildcard(filename:join([root(), "test", "*_tests.erl"])),
        {Line, Text} <- literal_port_dials(File)
    ],
    ?assertEqual([], Offenders).

literal_port_dials(File) ->
    {ok, Bin} = file:read_file(File),
    Lines = string:split(binary_to_list(Bin), "\n", all),
    [
        {Line, Text}
     || {Line, Text} <- lists:enumerate(Lines),
        not is_comment(Text),
        dials_a_literal_port(Text)
    ].

is_comment(Text) ->
    case string:trim(Text, leading) of
        "%" ++ _ -> true;
        _ -> false
    end.

%% A call to start_link or connect whose second argument is an integer
%% literal rather than a port the test asked for.
dials_a_literal_port(Text) ->
    case re:run(Text, "quic_connection:(start_link|connect)\\(.*?,\\s*([0-9]+)\\s*,") of
        {match, _} -> true;
        nomatch -> false
    end.

%% The project root, found the way quic_docs_drift_tests finds it.
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
