%%% -*- erlang -*-
%%%
%%% What a firing keep-alive timer does to the idle timer and to its own
%%% next expiry.

-module(quic_keep_alive_timer_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(IDLE, 20000).
-define(INTERVAL, 8000).

%% The idle timer is moved to the idle deadline itself (RFC 9000 Section
%% 10.1), so it does not fire only to find the connection was kept alive.
moves_the_idle_timer_to_its_deadline_test() ->
    [
        begin
            S0 = quic_connection:set_idle_timer(state(client, 0)),
            Old = S0#state.idle_timer,
            S1 = fire(S0#state{last_activity = erlang:monotonic_time(millisecond) - Idle}),
            ?assertEqual(false, erlang:read_timer(Old)),
            Left = erlang:read_timer(S1#state.idle_timer),
            ?assert(Left =< ?IDLE - Idle),
            ?assert(Left > ?IDLE - Idle - 1000),
            cancel(S1)
        end
     || Idle <- [1000, ?INTERVAL]
    ].

%% The acknowledgement of the last PING arrived a round trip into the
%% interval. The next expiry sends the next PING; it does not wait out
%% that round trip first.
pings_once_idle_for_most_of_the_interval_test() ->
    Sent = fire(state(server, ?INTERVAL - 50)),
    ?assert(next_expiry(Sent) > ?INTERVAL - 1000),
    cancel(Sent),
    Waits = fire(state(server, ?INTERVAL div 2)),
    Left = next_expiry(Waits),
    ?assert(Left =< ?INTERVAL div 2),
    ?assert(Left > ?INTERVAL div 2 - 1000),
    cancel(Waits).

%% Both ends on the same interval: the client's next PING comes before
%% the server's timer, which then finds the connection active.
client_pings_before_the_server_test() ->
    Client = fire(state(client, ?INTERVAL)),
    Server = fire(state(server, ?INTERVAL)),
    ?assert(next_expiry(Client) =< ?INTERVAL - ?INTERVAL div 16),
    ?assert(next_expiry(Server) > ?INTERVAL - ?INTERVAL div 16),
    %% When the server's timer fires the client's PING is at most a
    %% sixteenth of the interval old.
    Quiet = fire(state(server, ?INTERVAL div 16)),
    ?assert(next_expiry(Quiet) > ?INTERVAL - ?INTERVAL div 16 - 1000),
    [cancel(S) || S <- [Client, Server, Quiet]].

next_expiry(#state{keep_alive_timer = Ref}) ->
    erlang:read_timer(Ref).

fire(State) ->
    Ref = make_ref(),
    {keep_state, S} = quic_connection:handle_common_event(
        info, {timeout, Ref, keep_alive_timeout}, connected, State#state{keep_alive_timer = Ref}
    ),
    S.

state(Role, Idle) ->
    #state{cfg = Cfg} = S = quic_connection_test_support:state_for_role(Role),
    S#state{
        loss_state = quic_loss:new(),
        last_activity = erlang:monotonic_time(millisecond) - Idle,
        cfg = Cfg#conn_cfg{idle_timeout = ?IDLE, keep_alive_interval = ?INTERVAL}
    }.

cancel(#state{idle_timer = Idle, keep_alive_timer = KeepAlive}) ->
    erlang:cancel_timer(Idle),
    erlang:cancel_timer(KeepAlive).
