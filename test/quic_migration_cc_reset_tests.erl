%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 9.4: a migration starts congestion control over. It
%%% starts over with the controller and options the connection was
%%% configured with, not a default NewReno.

-module(quic_migration_cc_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(WINDOW, 123456).

migration_keeps_the_configured_controller_test() ->
    #state{cc_state = CC} = migrated(cubic),
    ?assertEqual(cubic, quic_cc:algorithm(CC)),
    ?assertEqual(?WINDOW, quic_cc:cwnd(CC)).

%% An algorithm chosen later with set_congestion_control/2 is kept too.
migration_keeps_a_switched_controller_test() ->
    #state{cc_state = CC} = migrated(bbr),
    ?assertEqual(bbr, quic_cc:algorithm(CC)).

switching_keeps_the_configured_options_test() ->
    {ok, #state{cc_state = CC}} =
        quic_connection:do_set_congestion_control(cubic, state(newreno)),
    ?assertEqual(cubic, quic_cc:algorithm(CC)),
    ?assertEqual(?WINDOW, quic_cc:cwnd(CC)).

migrated(Algorithm) ->
    NewPath = #path_state{
        remote_addr = {{127, 0, 0, 2}, 4433}, status = validated, is_nat_rebinding = false
    },
    State = quic_connection:complete_migration(NewPath, state(Algorithm)),
    receive
        {quic, _, {path_changed, _, _}} -> State
    after 1000 -> error(no_path_changed)
    end.

%% A connection configured with ?WINDOW as its initial window, running
%% Algorithm.
state(Algorithm) ->
    Opts = #{initial_window => ?WINDOW},
    #state{cfg = Cfg} = S = quic_connection_test_support:state_for_role(client),
    S#state{
        owner = self(),
        cc_state = quic_cc:new(Algorithm, Opts),
        loss_state = quic_loss:new(),
        pmtu_state = quic_pmtu:new(),
        mig = #mig{alt_paths = []},
        cfg = Cfg#conn_cfg{cc_opts = Opts#{algorithm => newreno}}
    }.
