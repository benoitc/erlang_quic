%%% -*- erlang -*-
%%%
%%% QUIC Distribution Authentication Behaviour
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Optional authentication callback invoked between the QUIC
%%% handshake and the Erlang distribution handshake.
%%%
%%% Configure via the `auth_callback' option (sys.config or
%%% `-quic_dist auth_callback Mod:Fun'):
%%%
%%% ```
%%% {quic, [{dist, [
%%%   {auth_callback, {my_app_auth, authenticate}},
%%%   {auth_handshake_timeout, 10000}
%%% ]}]}.
%%% '''
%%%
%%% The callback runs on both sides. It can refuse the connection by
%%% returning `{error, Reason}'; the connection is then closed and the
%%% dist controller is never started.
%%%
%%% A callback that proves which node is on the other end returns
%%% `{ok, {authenticated_node, Node}}'. quic_dist then refuses the
%%% connection unless the peer's dist node name is `Node': on the
%%% server, the name the peer announces in the dist handshake; on the
%%% client, the node being dialed. A peer asking the server for a
%%% dynamic name is refused too. Any other `{ok, Info}' admits the peer
%%% without that check.
%%%
%%% @end

-module(quic_dist_auth).

%% Implementations validate the freshly-established QUIC connection
%% (peer certificate, ALPN, transport parameters, PSK identity) and
%% return `{ok, Info}' on success or `{error, Reason}' to refuse it.
%% `Info = {authenticated_node, Node}' binds the connection to `Node'.
%% Do not open a stream: stream ids are assigned in open order and both
%% sides assume the control stream is stream 0, so an extra stream
%% opened here shifts every stream after it. `Timeout' is the value
%% configured via `auth_handshake_timeout'; it bounds the wait for the
%% QUIC handshake, not this callback.
-callback authenticate(
    Conn :: pid(),
    Side :: client | server,
    Timeout :: timeout()
) ->
    {ok, Info :: term()} | {error, Reason :: term()}.

-export([run/4, authenticated_node/1, peer_name/1]).

-include_lib("kernel/include/dist.hrl").

%% @doc Invoke a configured callback, turning a crash or a bad return
%% into `{error, _}' so a buggy implementation cannot take down the
%% process running it. Callers must filter out `undefined' first.
-spec run(
    Callback :: quic_dist:auth_callback(),
    Conn :: pid(),
    Side :: client | server,
    Timeout :: timeout()
) ->
    {ok, term()} | {error, term()}.
run({Mod, Fun}, Conn, Side, Timeout) when is_atom(Mod), is_atom(Fun) ->
    safe_call(fun() -> Mod:Fun(Conn, Side, Timeout) end);
run(F, Conn, Side, Timeout) when is_function(F, 3) ->
    safe_call(fun() -> F(Conn, Side, Timeout) end).

%% @doc The node an auth result binds the connection to, if any.
-spec authenticated_node(Info :: term()) -> node() | undefined.
authenticated_node({authenticated_node, Node}) when is_atom(Node) -> Node;
authenticated_node(_) -> undefined.

%% @doc Read the peer's node name from a dist handshake message the way
%% `dist_util' does, so a name check sees the name dist_util will use.
%% The name stays a string: dist_util turns it into an atom with
%% `list_to_atom/1', so it names node `N' exactly when it equals
%% `atom_to_list(N)'.
-spec peer_name(Data :: term()) ->
    {static, string()} | {dynamic, string()} | malformed | not_name.
peer_name([$n, _V1, _V0, _F3, _F2, _F1, _F0 | Name]) ->
    {static, Name};
peer_name([$N, F7, F6, F5, F4, F3, F2, F1, F0, _Cr3, _Cr2, _Cr1, _Cr0, NL1, NL0 | Rest]) ->
    try
        <<Flags:64>> = <<F7, F6, F5, F4, F3, F2, F1, F0>>,
        <<NameLen:16>> = <<NL1, NL0>>,
        {Name, _Residue} = lists:split(NameLen, Rest),
        case Flags band ?DFLAG_NAME_ME of
            0 -> {static, Name};
            _ -> {dynamic, Name}
        end
    catch
        error:_ -> malformed
    end;
peer_name([H | _]) when H =:= $n; H =:= $N ->
    malformed;
peer_name(_) ->
    not_name.

%% @private
safe_call(Thunk) ->
    try Thunk() of
        {ok, {authenticated_node, Node}} = Bad when not is_atom(Node) ->
            {error, {auth_callback_bad_return, Bad}};
        {ok, _} = Ok ->
            Ok;
        {error, _} = Err ->
            Err;
        Other ->
            {error, {auth_callback_bad_return, Other}}
    catch
        Class:Reason:Stack ->
            {error, {auth_callback_crash, Class, Reason, Stack}}
    end.
