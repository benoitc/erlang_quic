%%% -*- erlang -*-
%%%
%%% Cost of the loss-timer selector (RFC 9002 §6.1.2).
%%%
%%% get_loss_time_and_space/1 runs on every send and every
%%% acknowledgement, so its cost is paid per packet. Its worst case is
%%% the common one: nothing in the space has been overtaken yet, which
%%% is where a scan of the sent queue does the most work and finds
%%% nothing. The queue is oldest first and packet numbers increase with
%%% it, so the head decides the answer on its own and the depth of the
%%% queue must not enter into it.
%%%
%%% Reductions, not wall clock: they are deterministic and do not pick
%%% up load from the rest of the run.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_loss_selector_cost_tests).

-include_lib("eunit/include/eunit.hrl").

%% Enough calls that the selector, not the loop around it, dominates.
-define(CALLS, 200).

-define(SENT_AT, 1000000).

%% Observed over ?CALLS calls: before this was a head peek, 1,000
%% in-flight packets cost 221k reductions and 10,000 cost 2.13M, a
%% ratio of 9.6. With the peek they cost 7.5k and 7.2k, a ratio of
%% 0.96. The ceiling of two is far from either, so drift shows up as a
%% failure and noise does not.
selector_cost_does_not_follow_queue_depth_test_() ->
    {timeout, 120, fun() ->
        Small = measure(1000),
        Large = measure(10000),
        ?assert(Large < Small * 2)
    end}.

%%====================================================================
%% Measurement
%%====================================================================

%% Each depth is measured in its own process so the heap growth and
%% garbage collection from building the previous state cannot land in
%% the next one's reduction count.
measure(Depth) ->
    Parent = self(),
    Ref = make_ref(),
    {_Pid, MRef} = spawn_monitor(fun() ->
        State = with_in_flight(Depth),
        {reductions, Before} = erlang:process_info(self(), reductions),
        ok = select(State, ?CALLS),
        {reductions, After} = erlang:process_info(self(), reductions),
        Parent ! {Ref, After - Before}
    end),
    receive
        {Ref, Reductions} ->
            erlang:demonitor(MRef, [flush]),
            Reductions;
        {'DOWN', MRef, process, _, Reason} ->
            exit({measure_failed, Depth, Reason})
    after 120000 ->
        exit({measure_timeout, Depth})
    end.

select(_State, 0) ->
    ok;
select(State, N) ->
    %% Matching none also pins the scenario: nothing is overtaken, so
    %% the selector cannot stop early on a match.
    none = quic_loss:get_loss_time_and_space(State),
    select(State, N - 1).

%% Depth in-flight ack-eliciting packets, all with packet numbers above
%% largest_acked: a flight sent after the last acknowledgement arrived.
with_in_flight(Depth) ->
    S0 = quic_loss:on_packet_sent(app, quic_loss:new(), 1, 1200, true, [], ?SENT_AT),
    S1 = quic_loss:on_packet_sent(app, S0, 2, 1200, true, [], ?SENT_AT),
    {S2, _Acked, _Lost, _Meta} = quic_loss:on_ack_received(
        app, S1, {ack, 1, 0, 0, []}, ?SENT_AT
    ),
    lists:foldl(
        fun(PN, S) -> quic_loss:on_packet_sent(app, S, PN, 1200, true, [], ?SENT_AT) end,
        S2,
        lists:seq(3, Depth + 1)
    ).
