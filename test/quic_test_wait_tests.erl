%%% -*- erlang -*-
%%%
%%% quic_test_wait: the helper other tests rely on to wait for a
%%% condition, so it has to report a timeout as a timeout.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_test_wait_tests).

-include_lib("eunit/include/eunit.hrl").

holds_immediately_test() ->
    ?assert(quic_test_wait:until(fun() -> true end, 1000)).

%% A condition that never holds is reported false, and only once the
%% budget has actually been spent.
never_holds_test() ->
    T0 = erlang:monotonic_time(millisecond),
    ?assertNot(quic_test_wait:until(fun() -> false end, 100)),
    ?assert(erlang:monotonic_time(millisecond) - T0 >= 100).

%% A condition that turns true partway through is seen.
becomes_true_test() ->
    Ready = erlang:monotonic_time(millisecond) + 60,
    ?assert(
        quic_test_wait:until(fun() -> erlang:monotonic_time(millisecond) >= Ready end, 2000)
    ).

%% A non-boolean result is a bug in the caller's predicate, not a timeout.
non_boolean_crashes_test() ->
    ?assertError(
        {case_clause, not_a_boolean}, quic_test_wait:until(fun() -> not_a_boolean end, 100)
    ).
