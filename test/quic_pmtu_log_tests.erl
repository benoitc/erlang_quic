%%% -*- erlang -*-
%%%
%%% The raise timer starts a new PMTU search every pmtu_raise_interval
%%% while the path stays below max_mtu (RFC 8899 Section 5.1.1), which on
%%% an ordinary Ethernet path is always. A search that ends where it
%%% began is not news: `pmtu_search_complete' is logged at info level
%%% when the MTU changed and at debug level otherwise.

-module(quic_pmtu_log_tests).

-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

%% Largest UDP payload a 1500 byte IPv4 path carries.
-define(ETHERNET, 1472).

log(#{level := Level, msg := {report, #{what := pmtu_search_complete, final_mtu := MTU}}}, #{
    config := #{pid := Pid}
}) ->
    Pid ! {search_complete, Level, MTU};
log(_Event, _Config) ->
    ok.

search_complete_is_news_once_test() ->
    captured(fun() ->
        S0 = quic_pmtu:on_connection_established(1500, quic_pmtu:new()),
        S1 = search(S0, ?ETHERNET),
        MTU = quic_pmtu:current_mtu(S1),
        ?assert(MTU > 1400 andalso MTU =< ?ETHERNET),
        ?assertEqual([{info, MTU}], reported()),
        %% Two raise timers later the path is what it was.
        S2 = search(quic_pmtu:on_raise_timer(S1), ?ETHERNET),
        S3 = search(quic_pmtu:on_raise_timer(S2), ?ETHERNET),
        ?assertEqual(MTU, quic_pmtu:current_mtu(S3)),
        ?assertEqual([{debug, MTU}, {debug, MTU}], reported()),
        %% The path grows: that is reported.
        S4 = search(quic_pmtu:on_raise_timer(S3), 1500),
        Raised = quic_pmtu:current_mtu(S4),
        ?assert(Raised > MTU),
        ?assertEqual([{info, Raised}], reported())
    end).

%% Run the search to its end on a path that carries packets up to Limit.
search(State, Limit) ->
    search(State, Limit, 1).

search(State, Limit, PN) ->
    case quic_pmtu:should_probe(State) of
        false ->
            ?assertEqual(search_complete, quic_pmtu:get_state(State)),
            State;
        true ->
            {Size, _Frames} = quic_pmtu:create_probe_packet(State, 30),
            {Gen, Sent} = quic_pmtu:on_probe_sent(PN, State),
            Next =
                case Size =< Limit of
                    true -> quic_pmtu:on_probe_acked(PN, Gen, Sent);
                    false -> quic_pmtu:on_probe_lost(PN, Gen, Sent)
                end,
            search(Next, Limit, PN + 1)
    end.

reported() ->
    receive
        {search_complete, Level, MTU} -> [{Level, MTU} | reported()]
    after 0 -> []
    end.

captured(Fun) ->
    Id = list_to_atom("quic_pmtu_log_" ++ integer_to_list(erlang:unique_integer([positive]))),
    #{level := Primary} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun()
    after
        logger:remove_handler(Id),
        logger:set_primary_config(level, Primary)
    end.
