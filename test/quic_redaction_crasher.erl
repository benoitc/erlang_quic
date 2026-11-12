%%% -*- erlang -*-
%%%
%%% Test helper: a gen_statem holding a connection state that crashes
%%% with function_clause on it, under its own supervisor.

-module(quic_redaction_crasher).

-export([start_sup/1, start_link/1]).
-export([init/1, callback_mode/0, handle_event/4, format_status/1]).

%% The state goes in a closure so the child spec does not print it.
start_sup(State) ->
    supervisor:start_link(?MODULE, {sup, fun() -> State end}).

start_link(StateFun) ->
    gen_statem:start_link(?MODULE, {statem, StateFun}, []).

init({sup, StateFun}) ->
    Child = #{id => crasher, start => {?MODULE, start_link, [StateFun]}, restart => temporary},
    {ok, {#{strategy => one_for_one, intensity => 0, period => 1}, [Child]}};
init({statem, StateFun}) ->
    {ok, running, StateFun()}.

callback_mode() ->
    handle_event_function.

handle_event({call, _From}, crash, _StateName, State) ->
    crash(State).

format_status(Status) ->
    quic_connection:format_status(Status).

crash(not_a_state) ->
    keep_state_and_data.
