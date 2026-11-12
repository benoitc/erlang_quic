%%% -*- erlang -*-
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @private Replace secrets with `redacted' in the terms that crash
%%% reports and `sys:get_status/1' print.
%%%
%%% `term/1' walks a term and redacts, wherever they appear: private
%%% keys, packet protection keys and IVs, traffic secrets, PSKs and
%%% session ticket secrets, QUIC-LB keys, stateless reset secrets and
%%% tokens, and the values of option keys that hold any of these.

-module(quic_redact).

-include("quic.hrl").

-export([term/1, value/1, fields/2, status/2, seal/1, open/1]).
-export([install_log_filter/0, remove_log_filter/0, log_filter/2]).
-export_type([sealed/0]).

%% Options passed as a supervisor child argument: printed as #Fun<...>.
-type sealed() :: fun(() -> map()).

-define(REDACTED, redacted).

%% Option and map keys whose value is a secret, or a fun that may hold one.
-define(SECRET_KEYS, [
    key,
    private_key,
    client_private_key,
    key_pair,
    psks,
    psk_callback,
    external_psk,
    selected_psk,
    secret,
    resumption_secret,
    early_secret,
    reset_secret,
    stateless_reset_secret,
    stateless_reset_token,
    sni_callback
]).

%% @doc Wrap options so that supervisor reports and
%% sys:get_status/1 of the supervisor holding them print none of them.
-spec seal(map() | sealed()) -> sealed().
seal(Sealed) when is_function(Sealed, 0) -> Sealed;
seal(Opts) when is_map(Opts) -> fun() -> Opts end.

%% @doc The options `seal/1' wrapped; a plain map is returned as is.
-spec open(map() | sealed()) -> map().
open(Sealed) when is_function(Sealed, 0) -> Sealed();
open(Opts) when is_map(Opts) -> Opts.

%% @doc `redacted' for a set value; `undefined' is kept to show absence.
-spec value(term()) -> term().
value(undefined) -> undefined;
value(_) -> ?REDACTED.

%% @doc `value/1' applied to the record fields at `Positions'.
-spec fields(tuple(), [pos_integer()]) -> tuple().
fields(Record, Positions) ->
    lists:foldl(fun(I, R) -> setelement(I, R, value(element(I, R))) end, Record, Positions).

%% @doc Apply `term/1' to the values of the status map keys in `Keys'.
-spec status(map(), [atom()]) -> map().
status(Status, Keys) ->
    maps:map(
        fun(K, V) ->
            case lists:member(K, Keys) of
                true -> term(V);
                false -> V
            end
        end,
        Status
    ).

%% @doc Redact every secret found in `T'.
-spec term(term()) -> term().
term(T) when is_tuple(T) ->
    keys(T);
term(M) when is_map(M) ->
    maps:map(fun redact_entry/2, M);
term([H | T]) ->
    [term(H) | term(T)];
term(Other) ->
    Other.

redact_entry(K, V) ->
    case lists:member(K, ?SECRET_KEYS) of
        true -> value(V);
        false -> term(V)
    end.

%% Packet protection keys, traffic secrets and PSKs.
keys(#crypto_keys{} = K) ->
    fields(K, [#crypto_keys.key, #crypto_keys.iv, #crypto_keys.hp]);
keys(#key_update_state{current_keys = Cur, prev_keys = Prev} = S) ->
    fields(
        S#key_update_state{current_keys = term(Cur), prev_keys = term(Prev)},
        [#key_update_state.client_app_secret, #key_update_state.server_app_secret]
    );
keys(#session_ticket{} = T) ->
    fields(T, [#session_ticket.resumption_secret]);
keys(#psk_offer{} = O) ->
    fields(O, [#psk_offer.secret]);
keys(T) ->
    ids(T).

%% QUIC-LB keys, stateless reset secrets and tokens.
ids(#lb_config{} = C) ->
    fields(C, [#lb_config.key]);
ids(#cid_config{lb_config = Lb} = C) ->
    fields(C#cid_config{lb_config = term(Lb)}, [#cid_config.reset_secret]);
ids(#cid_entry{} = E) ->
    fields(E, [#cid_entry.stateless_reset_token]);
ids(#preferred_address{} = A) ->
    fields(A, [#preferred_address.stateless_reset_token]);
ids(T) ->
    tuple(T).

%% A public_key private key record or EdDSA key goes whole.
tuple(T) when tuple_size(T) > 0 ->
    case element(1, T) of
        'ECPrivateKey' -> ?REDACTED;
        'RSAPrivateKey' -> ?REDACTED;
        'DSAPrivateKey' -> ?REDACTED;
        'PrivateKeyInfo' -> ?REDACTED;
        'OneAsymmetricKey' -> ?REDACTED;
        ed_pri -> ?REDACTED;
        _ -> list_to_tuple(term(tuple_to_list(T)))
    end;
tuple(T) ->
    T.

%%====================================================================
%% Crash report filter
%%====================================================================

%% format_status/1 never sees the stack trace of a crash, which holds the
%% arguments of the failing call (often the whole state), nor proc_lib's
%% mailbox and dictionary. This primary logger filter covers them.

%% @doc Add the crash report filter to the logger primary config.
-spec install_log_filter() -> ok.
install_log_filter() ->
    try logger:add_primary_filter(?MODULE, {fun ?MODULE:log_filter/2, []}) of
        _ -> ok
    catch
        _:_ -> ok
    end.

%% @doc Remove the crash report filter.
-spec remove_log_filter() -> ok.
remove_log_filter() ->
    _ = logger:remove_primary_filter(?MODULE),
    ok.

%% @doc In crash, terminate and supervisor reports, drop the arguments of
%% quic stack frames. From a quic process, also drop every frame's
%% arguments and redact its state and secrets anywhere in the report.
-spec log_filter(logger:log_event(), term()) -> logger:log_event().
log_filter(#{msg := {report, #{label := Label} = Report}} = Event, _Extra) ->
    case is_crash_label(Label) of
        true -> Event#{msg := {report, crash_report(Report)}};
        false -> Event
    end;
log_filter(Event, _Extra) ->
    Event.

is_crash_label({gen_statem, terminate}) -> true;
is_crash_label({gen_server, terminate}) -> true;
is_crash_label({proc_lib, crash}) -> true;
is_crash_label({supervisor, _}) -> true;
is_crash_label(_) -> false.

%% The filter runs in the process that logs: the one that crashed, or
%% the supervisor reporting its child.
crash_report(Report) ->
    case get('$initial_call') of
        {Mod, _, _} when is_atom(Mod) ->
            case is_quic_module(Mod) of
                true -> maps:map(fun own_entry/2, frames(all, Report));
                false -> frames(quic, Report)
            end;
        _ ->
            frames(quic, Report)
    end.

is_quic_module(Mod) ->
    case atom_to_binary(Mod) of
        <<"quic", _/binary>> -> true;
        _ -> false
    end.

%% Stack frames {M, F, Args, Location} get the arity instead of Args.
frames(Scope, L) when is_list(L) ->
    case is_stacktrace(L) of
        true -> [frame(Scope, F) || F <- L];
        false -> frames_list(Scope, L)
    end;
frames(Scope, T) when is_tuple(T) ->
    list_to_tuple(frames_list(Scope, tuple_to_list(T)));
frames(Scope, M) when is_map(M) ->
    maps:map(fun(_K, V) -> frames(Scope, V) end, M);
frames(_Scope, T) ->
    T.

frames_list(Scope, [H | T]) -> [frames(Scope, H) | frames_list(Scope, T)];
frames_list(_Scope, []) -> [];
frames_list(Scope, T) -> frames(Scope, T).

is_stacktrace([_ | _] = L) ->
    try
        lists:all(fun is_frame/1, L)
    catch
        _:_ -> false
    end;
is_stacktrace(_) ->
    false.

is_frame({M, F, A, Loc}) when is_atom(M), is_atom(F), is_list(Loc) ->
    is_list(A) orelse is_integer(A);
is_frame(_) ->
    false.

frame(all, {M, F, Args, Loc}) when is_list(Args) ->
    {M, F, length(Args), Loc};
frame(quic, {M, F, Args, Loc} = Frame) when is_list(Args) ->
    case is_quic_module(M) of
        true -> {M, F, length(Args), Loc};
        false -> Frame
    end;
frame(_Scope, Frame) ->
    Frame.

%% The report's `state' was formatted by format_status/1. Any other copy
%% of a process state (a `state' record), in a reason, a message or a
%% child report, is dropped.
own_entry(state, V) -> term(V);
own_entry(_K, V) -> term(states(V)).

states(T) when is_tuple(T), tuple_size(T) > 1, element(1, T) =:= state ->
    ?REDACTED;
states(T) when is_tuple(T) ->
    list_to_tuple(states_list(tuple_to_list(T)));
states(L) when is_list(L) ->
    states_list(L);
states(M) when is_map(M) ->
    maps:map(fun(_K, V) -> states(V) end, M);
states(T) ->
    T.

states_list([H | T]) -> [states(H) | states_list(T)];
states_list([]) -> [];
states_list(T) -> states(T).
