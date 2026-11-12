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

-export([term/1, value/1, fields/2, status/2]).

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
