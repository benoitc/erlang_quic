%%% -*- erlang -*-
%%%
%%% Windowed Min/Max Filters for Congestion Control
%%%
%%% Implements windowed filters for tracking minimum and maximum values
%%% over a sliding time window. Used by BBR for BtlBw (max filter) and
%%% RTprop (min filter) estimation.
%%%
%%% Based on the windowed min/max algorithm from Kathleen Nichols'
%%% ns2 work and Google's BBR implementation.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_cc_filter).

-export([
    %% Max filter (for bandwidth estimation)
    new_max_filter/1,
    update_max/3,
    get_max/1,
    reset_max/1,

    %% Min filter (for RTT estimation)
    new_min_filter/1,
    update_min/3,
    get_min/1,
    reset_min/1
]).

-export_type([windowed_filter/0]).

%% Windowed filter state
%% Uses a 3-sample sliding window algorithm
-record(windowed_filter, {
    %% Window length in time units (ms for RTprop, round count for BtlBw)
    window_len :: non_neg_integer(),
    %% Filter type: max or min
    type :: max | min,
    %% Best value in window
    best_value :: non_neg_integer() | infinity | undefined,
    best_time :: non_neg_integer() | undefined,
    %% Second best value
    second_value :: non_neg_integer() | infinity | undefined,
    second_time :: non_neg_integer() | undefined,
    %% Third best value
    third_value :: non_neg_integer() | infinity | undefined,
    third_time :: non_neg_integer() | undefined
}).

-opaque windowed_filter() :: #windowed_filter{}.

%%====================================================================
%% Max Filter API (for bandwidth estimation)
%%====================================================================

%% @doc Create a new max filter with given window length.
%% WindowLen is in time units (typically round count for BtlBw).
-spec new_max_filter(WindowLen :: non_neg_integer()) -> windowed_filter().
new_max_filter(WindowLen) ->
    #windowed_filter{
        window_len = WindowLen,
        type = max,
        best_value = 0,
        best_time = undefined,
        second_value = 0,
        second_time = undefined,
        third_value = 0,
        third_time = undefined
    }.

%% @doc Update max filter with a new sample.
%% Returns updated filter. Value is the sample, Time is the current time.
-spec update_max(windowed_filter(), Value :: non_neg_integer(), Time :: non_neg_integer()) ->
    windowed_filter().
update_max(#windowed_filter{type = max} = Filter, Value, Time) ->
    %% First, expire old samples
    Filter1 = expire_max_samples(Filter, Time),
    %% Then update with new value
    do_update_max(Filter1, Value, Time).

%% @doc Get the current maximum value.
-spec get_max(windowed_filter()) -> non_neg_integer().
get_max(#windowed_filter{type = max, best_value = Value}) ->
    Value.

%% @doc Reset the max filter to initial state.
-spec reset_max(windowed_filter()) -> windowed_filter().
reset_max(#windowed_filter{window_len = WL}) ->
    new_max_filter(WL).

%%====================================================================
%% Min Filter API (for RTT estimation)
%%====================================================================

%% @doc Create a new min filter with given window length.
%% WindowLen is in milliseconds (typically 10000ms = 10s for RTprop).
-spec new_min_filter(WindowLen :: non_neg_integer()) -> windowed_filter().
new_min_filter(WindowLen) ->
    #windowed_filter{
        window_len = WindowLen,
        type = min,
        best_value = infinity,
        best_time = undefined,
        second_value = infinity,
        second_time = undefined,
        third_value = infinity,
        third_time = undefined
    }.

%% @doc Update min filter with a new sample.
%% Returns updated filter. Value is the sample, Time is the current time.
-spec update_min(windowed_filter(), Value :: non_neg_integer(), Time :: non_neg_integer()) ->
    windowed_filter().
update_min(#windowed_filter{type = min} = Filter, Value, Time) ->
    %% First, expire old samples
    Filter1 = expire_min_samples(Filter, Time),
    %% Then update with new value
    do_update_min(Filter1, Value, Time).

%% @doc Get the current minimum value.
-spec get_min(windowed_filter()) -> non_neg_integer() | infinity.
get_min(#windowed_filter{type = min, best_value = Value}) ->
    Value.

%% @doc Reset the min filter to initial state.
-spec reset_min(windowed_filter()) -> windowed_filter().
reset_min(#windowed_filter{window_len = WL}) ->
    new_min_filter(WL).

%%====================================================================
%% Internal Functions - Max Filter
%%====================================================================

%% Expire max samples that are outside the window
expire_max_samples(#windowed_filter{window_len = WL, best_time = BT} = Filter, Time) when
    is_integer(BT), Time - BT > WL
->
    %% Best sample expired, promote second to best
    expire_max_samples(
        Filter#windowed_filter{
            best_value = Filter#windowed_filter.second_value,
            best_time = Filter#windowed_filter.second_time,
            second_value = Filter#windowed_filter.third_value,
            second_time = Filter#windowed_filter.third_time,
            third_value = 0,
            third_time = undefined
        },
        Time
    );
expire_max_samples(#windowed_filter{window_len = WL, second_time = ST} = Filter, Time) when
    is_integer(ST), Time - ST > WL
->
    %% Second sample expired, promote third to second
    expire_max_samples(
        Filter#windowed_filter{
            second_value = Filter#windowed_filter.third_value,
            second_time = Filter#windowed_filter.third_time,
            third_value = 0,
            third_time = undefined
        },
        Time
    );
expire_max_samples(#windowed_filter{window_len = WL, third_time = TT} = Filter, Time) when
    is_integer(TT), Time - TT > WL
->
    %% Third sample expired
    Filter#windowed_filter{
        third_value = 0,
        third_time = undefined
    };
expire_max_samples(Filter, _Time) ->
    Filter.

%% Update max filter with new value
do_update_max(#windowed_filter{best_value = BV} = Filter, Value, Time) when Value >= BV ->
    %% New value is the best - reset all samples to this value
    Filter#windowed_filter{
        best_value = Value,
        best_time = Time,
        second_value = Value,
        second_time = Time,
        third_value = Value,
        third_time = Time
    };
do_update_max(
    #windowed_filter{second_value = SV, window_len = WL, best_time = BT} = Filter, Value, Time
) when
    Value >= SV
->
    %% Value is better than second best
    Quarter = max(1, WL div 4),
    case is_integer(BT) andalso Time - BT >= Quarter of
        true ->
            %% More than a quarter passed since best was recorded
            %% This value becomes second best
            Filter#windowed_filter{
                second_value = Value,
                second_time = Time,
                third_value = Value,
                third_time = Time
            };
        false ->
            %% Still in first quarter, update second and third
            Filter#windowed_filter{
                second_value = Value,
                second_time = Time,
                third_value = Value,
                third_time = Time
            }
    end;
do_update_max(
    #windowed_filter{third_value = TV, window_len = WL, second_time = ST} = Filter, Value, Time
) when
    Value >= TV
->
    %% Value is better than third best
    Quarter = max(1, WL div 4),
    case is_integer(ST) andalso Time - ST >= Quarter of
        true ->
            %% More than a quarter passed since second was recorded
            Filter#windowed_filter{
                third_value = Value,
                third_time = Time
            };
        false ->
            Filter#windowed_filter{
                third_value = Value,
                third_time = Time
            }
    end;
do_update_max(Filter, _Value, _Time) ->
    %% Value is less than all tracked samples
    Filter.

%%====================================================================
%% Internal Functions - Min Filter
%%====================================================================

%% Expire min samples that are outside the window
expire_min_samples(#windowed_filter{window_len = WL, best_time = BT} = Filter, Time) when
    is_integer(BT), Time - BT > WL
->
    %% Best sample expired, promote second to best
    expire_min_samples(
        Filter#windowed_filter{
            best_value = Filter#windowed_filter.second_value,
            best_time = Filter#windowed_filter.second_time,
            second_value = Filter#windowed_filter.third_value,
            second_time = Filter#windowed_filter.third_time,
            third_value = infinity,
            third_time = undefined
        },
        Time
    );
expire_min_samples(#windowed_filter{window_len = WL, second_time = ST} = Filter, Time) when
    is_integer(ST), Time - ST > WL
->
    %% Second sample expired, promote third to second
    expire_min_samples(
        Filter#windowed_filter{
            second_value = Filter#windowed_filter.third_value,
            second_time = Filter#windowed_filter.third_time,
            third_value = infinity,
            third_time = undefined
        },
        Time
    );
expire_min_samples(#windowed_filter{window_len = WL, third_time = TT} = Filter, Time) when
    is_integer(TT), Time - TT > WL
->
    %% Third sample expired
    Filter#windowed_filter{
        third_value = infinity,
        third_time = undefined
    };
expire_min_samples(Filter, _Time) ->
    Filter.

%% Update min filter with new value
do_update_min(#windowed_filter{best_value = BV} = Filter, Value, Time) when
    BV =:= infinity orelse Value =< BV
->
    %% New value is the best - reset all samples to this value
    Filter#windowed_filter{
        best_value = Value,
        best_time = Time,
        second_value = Value,
        second_time = Time,
        third_value = Value,
        third_time = Time
    };
do_update_min(
    #windowed_filter{second_value = SV, window_len = WL, best_time = BT} = Filter, Value, Time
) when
    SV =:= infinity orelse Value =< SV
->
    %% Value is better than second best
    Quarter = max(1, WL div 4),
    case is_integer(BT) andalso Time - BT >= Quarter of
        true ->
            Filter#windowed_filter{
                second_value = Value,
                second_time = Time,
                third_value = Value,
                third_time = Time
            };
        false ->
            Filter#windowed_filter{
                second_value = Value,
                second_time = Time,
                third_value = Value,
                third_time = Time
            }
    end;
do_update_min(
    #windowed_filter{third_value = TV, window_len = WL, second_time = ST} = Filter, Value, Time
) when
    TV =:= infinity orelse Value =< TV
->
    %% Value is better than third best
    Quarter = max(1, WL div 4),
    case is_integer(ST) andalso Time - ST >= Quarter of
        true ->
            Filter#windowed_filter{
                third_value = Value,
                third_time = Time
            };
        false ->
            Filter#windowed_filter{
                third_value = Value,
                third_time = Time
            }
    end;
do_update_min(Filter, _Value, _Time) ->
    %% Value is greater than all tracked samples
    Filter.
