%%% -*- erlang -*-
%%%
%%% Which receive limit a stream gets.
%%%
%%% RFC 9000 Section 18.2: initial_max_stream_data_bidi_local covers the
%%% bidirectional streams opened by the endpoint that sends it, and
%%% bidi_remote those its peer opens. A stream tracking the other value
%%% disagrees with what the peer was told: tracking a larger one, it
%%% never sees its headroom run low and never extends the window.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_receive_window_tests).

-include_lib("eunit/include/eunit.hrl").

-define(S, quic_connection_test_support).
-define(LOCAL, 65536).
-define(REMOTE, 262144).

%% A stream we open receives within our bidi_local limit.
locally_opened_stream_uses_bidi_local_test_() ->
    [?_assertEqual(?LOCAL, opened_locally(Role)) || Role <- [client, server]].

%% A stream the peer opens receives within our bidi_remote limit.
peer_opened_stream_uses_bidi_remote_test_() ->
    [?_assertEqual(?REMOTE, opened_by_peer(Role)) || Role <- [client, server]].

%%====================================================================
%% Helpers
%%====================================================================

opened_locally(Role) ->
    S0 = ?S:state_with_stream_limits(Role, ?LOCAL, ?REMOTE),
    {ok, StreamId, S1} = quic_connection:do_open_stream(S0),
    ?S:recv_max_data(S1, StreamId).

opened_by_peer(Role) ->
    S0 = ?S:state_with_stream_limits(Role, ?LOCAL, ?REMOTE),
    %% The first bidirectional stream the other side opens.
    StreamId =
        case Role of
            client -> 1;
            server -> 0
        end,
    S1 = quic_connection:process_stream_data(StreamId, 0, <<"x">>, false, S0),
    ?S:recv_max_data(S1, StreamId).
