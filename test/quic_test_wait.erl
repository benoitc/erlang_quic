%%% -*- erlang -*-
%%%
%%% Waiting for a condition with an explicit time budget.
%%%
%%% A fixed sleep followed by an assertion fails whenever a loaded runner
%%% is slower than the sleep assumed. Polling with a budget waits only as
%%% long as needed and fails only when the condition never holds within
%%% the budget.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_test_wait).

-export([until/2, until/3]).

-define(DEFAULT_INTERVAL_MS, 20).

%% @doc Poll Pred until it returns true or BudgetMs has passed. Returns
%% whether it held. Pred is evaluated once more after the budget runs out,
%% so a condition that turns true right at the deadline is still seen. A
%% Pred returning anything but a boolean crashes the caller rather than
%% counting as false.
-spec until(fun(() -> boolean()), non_neg_integer()) -> boolean().
until(Pred, BudgetMs) ->
    until(Pred, BudgetMs, ?DEFAULT_INTERVAL_MS).

-spec until(fun(() -> boolean()), non_neg_integer(), pos_integer()) -> boolean().
until(Pred, BudgetMs, IntervalMs) ->
    poll(Pred, erlang:monotonic_time(millisecond) + BudgetMs, IntervalMs).

poll(Pred, Deadline, IntervalMs) ->
    case Pred() of
        true ->
            true;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    false;
                false ->
                    timer:sleep(IntervalMs),
                    poll(Pred, Deadline, IntervalMs)
            end
    end.
