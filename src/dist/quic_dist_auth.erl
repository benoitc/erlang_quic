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
%%% @end

-module(quic_dist_auth).

%% Implementations validate the freshly-established QUIC connection
%% (e.g. inspect peer certificates, run a challenge/response on a user
%% stream) and return `{ok, Info}' on success or `{error, Reason}' to
%% refuse it. `Timeout' is the deadline configured via
%% `auth_handshake_timeout'.
-callback authenticate(
    Conn :: pid(),
    Side :: client | server,
    Timeout :: timeout()
) ->
    {ok, Info :: term()} | {error, Reason :: term()}.
