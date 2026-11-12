%%% -*- erlang -*-
%%%
%%% A handshake that has not completed within the idle timeout from its
%%% start, or the disconnect timeout when the idle timeout is off, is
%%% abandoned.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_handshake_timeout_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OPTS, #{idle_timeout => 0, disconnect_timeout => 1000}).
-define(IDLE_OPTS, #{idle_timeout => 5000, disconnect_timeout => 1000}).

%% One Initial the server cannot decrypt creates a connection that never
%% sends anything, so nothing is in flight to time out on.
server_abandons_unreadable_initial_test_() ->
    {timeout, 30, fun server_abandons_unreadable_initial/0}.

server_abandons_unreadable_initial() ->
    {ok, #{name := Name, port := Port} = Server} = quic_test_echo_server:start(?OPTS),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, unreadable_initial()),
        ?assertMatch([_], wait_connections(Name, fun(Conns) -> Conns =/= [] end)),
        ?assertEqual([], wait_connections(Name, fun(Conns) -> Conns =:= [] end))
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.

%% The server never answers: the client is told the connection closed.
client_abandons_silent_server_test_() ->
    {timeout, 30, fun client_abandons_silent_server/0}.

client_abandons_silent_server() ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Silent} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Silent),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, ?OPTS#{verify => false}, self()),
        receive
            {quic, Conn, {closed, Reason}} -> ?assertEqual(handshake_timeout, Reason)
        after 10000 -> ?assert(false)
        end
    after
        gen_udp:close(Silent)
    end.

%% With the idle timeout on, it bounds the handshake: a silent server is
%% given up on at the idle timeout, not the disconnect timeout.
client_waits_for_the_idle_timeout_test_() ->
    {timeout, 30, fun client_waits_for_the_idle_timeout/0}.

client_waits_for_the_idle_timeout() ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Silent} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Silent),
        Start = erlang:monotonic_time(millisecond),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, ?IDLE_OPTS#{verify => false}, self()),
        receive
            {quic, Conn, {closed, Reason}} ->
                ?assertEqual(idle_timeout, Reason),
                ?assert(erlang:monotonic_time(millisecond) - Start >= 4000)
        after 10000 -> ?assert(false)
        end
    after
        gen_udp:close(Silent)
    end.

server_waits_for_the_idle_timeout_test_() ->
    {timeout, 30, fun server_waits_for_the_idle_timeout/0}.

server_waits_for_the_idle_timeout() ->
    {ok, #{name := Name, port := Port} = Server} = quic_test_echo_server:start(?IDLE_OPTS),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, unreadable_initial()),
        ?assertMatch([_], wait_connections(Name, fun(Conns) -> Conns =/= [] end)),
        timer:sleep(3000),
        ?assertMatch({ok, [_]}, quic:get_server_connections(Name)),
        ?assertEqual([], wait_connections(Name, fun(Conns) -> Conns =:= [] end))
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.

%% Fence: once connected, a quiet connection is not given up on.
connected_and_quiet_stays_open_test_() ->
    {timeout, 30, fun connected_and_quiet_stays_open/0}.

connected_and_quiet_stays_open() ->
    {ok, #{port := Port} = Server} = quic_test_echo_server:start(?OPTS),
    try
        Opts = ?OPTS#{verify => false, alpn => [<<"echo">>]},
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        receive
            {quic, Conn, {closed, Reason}} -> ?assertEqual(still_open, Reason)
        after 3000 -> ok
        end,
        quic:close(Conn)
    after
        quic_test_echo_server:stop(Server)
    end.

-define(S, quic_connection_test_support).

%% The deadline is the idle timeout, else the disconnect timeout, else none.
deadline_value_test() ->
    ?assertEqual(
        5000, quic_connection:handshake_deadline(?S:handshake_with_timeouts(server, 5000, 1000))
    ),
    ?assertEqual(
        1000, quic_connection:handshake_deadline(?S:handshake_with_timeouts(client, 0, 1000))
    ),
    ?assertEqual(
        infinity,
        quic_connection:handshake_deadline(?S:handshake_with_timeouts(server, 0, infinity))
    ).

%% At the deadline a running handshake is closed, the peer told, and the
%% owner gets handshake_timeout.
deadline_closes_the_handshake_test_() ->
    [
        {atom_to_list(Role) ++ " " ++ atom_to_list(StateName), fun() ->
            deadline_closes(Role, StateName)
        end}
     || Role <- [client, server], StateName <- [idle, handshaking]
    ].

deadline_closes(Role, StateName) ->
    S0 = ?S:handshake_with_timeouts(Role, 5000, 1000),
    {next_state, draining, S1} = quic_connection:StateName(
        {timeout, handshake_deadline}, expired, S0
    ),
    ?assertEqual(handshake_timeout, ?S:close_reason(S1)),
    ?assert(?S:state_get(S1, handshake_next_pn) > ?S:state_get(S0, handshake_next_pn)),
    {keep_state, _} = quic_connection:draining(enter, StateName, S1),
    Me = self(),
    receive
        {quic, Me, {closed, Reason}} -> ?assertEqual(handshake_timeout, Reason)
    after 0 -> ?assert(false)
    end.

%% A peer silent for the whole idle timeout is an idle timeout, closed silently.
deadline_on_a_silent_peer_is_an_idle_timeout_test() ->
    S0 = ?S:handshake_with_timeouts(server, 1000, 1000),
    Silent = S0#state{last_activity = erlang:monotonic_time(millisecond) - 2000},
    {next_state, draining, S1} = quic_connection:handshaking(
        {timeout, handshake_deadline}, expired, Silent
    ),
    ?assertEqual(idle_timeout, ?S:close_reason(S1)),
    ?assertEqual(?S:state_get(Silent, handshake_next_pn), ?S:state_get(S1, handshake_next_pn)).

%% Once connected the deadline no longer applies.
deadline_after_the_handshake_is_ignored_test() ->
    S = ?S:handshake_with_timeouts(server, 5000, 1000),
    ?assertEqual(
        {keep_state, S}, quic_connection:connected({timeout, handshake_deadline}, expired, S)
    ).

%% A client that resends its Initial within every idle period does not
%% keep the handshake open past the idle timeout from its start.
server_closes_trickling_handshake_test_() ->
    {timeout, 30, fun server_closes_trickling_handshake/0}.

server_closes_trickling_handshake() ->
    {ok, #{name := Name, port := Port} = Server} =
        quic_test_echo_server:start(#{idle_timeout => 1000}),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        Initial = client_initial(Port),
        Start = erlang:monotonic_time(millisecond),
        Close = trickle(Socket, Port, Initial, 1, Start + 3000),
        ?assertMatch({connection_close, transport, ?QUIC_APPLICATION_ERROR, _, _}, Close),
        ?assert(erlang:monotonic_time(millisecond) - Start >= 1000),
        ?assertEqual([], wait_connections(Name, fun(Conns) -> Conns =:= [] end))
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.

%% Resend the Initial under a new packet number every 300 ms until the
%% server's Initial carries a CONNECTION_CLOSE, or Deadline passes.
trickle(Socket, Port, Initial, PN, Deadline) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, renumber(Initial, PN)),
    case close_in(Socket, dcid(Initial), erlang:monotonic_time(millisecond) + 300) of
        {ok, Close} ->
            Close;
        none ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> no_close;
                false -> trickle(Socket, Port, Initial, PN + 1, Deadline)
            end
    end.

close_in(Socket, ODCID, Until) ->
    case gen_udp:recv(Socket, 0, max(0, Until - erlang:monotonic_time(millisecond))) of
        {ok, {_, _, Datagram}} ->
            Closes = [F || {connection_close, _, _, _, _} = F <- initial_frames(ODCID, Datagram)],
            case Closes of
                [Close | _] -> {ok, Close};
                [] -> close_in(Socket, ODCID, Until)
            end;
        {error, timeout} ->
            none
    end.

%% The client's Initial under packet number PN (below 256), padded so the
%% datagram stays at 1200 bytes or more.
renumber(Initial, PN) ->
    <<_, Version:32, DL, DCID:DL/binary, SL, SCID:SL/binary, R0/binary>> = Initial,
    {TokenLen, R1} = quic_varint:decode(R0),
    <<Token:TokenLen/binary, R2/binary>> = R1,
    {Len, R3} = quic_varint:decode(R2),
    <<Encrypted:Len/binary, _/binary>> = R3,
    Header = binary:part(Initial, 0, byte_size(Initial) - byte_size(R3)),
    {Key, IV, HP} = quic_keys:derive_initial_client(DCID),
    {ok, _, _, Plaintext} =
        quic_aead:unprotect_long_packet(aes_128_gcm, Key, IV, HP, Header, Encrypted, undefined),
    Payload = <<Plaintext/binary, 0:64>>,
    Prefix =
        <<16#C0, Version:32, DL, DCID/binary, SL, SCID/binary,
            (quic_varint:encode(TokenLen))/binary, Token/binary,
            (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(aes_128_gcm, Key, IV, HP, PN, Prefix, Payload).

%% The first Initial of a real client, captured without sending it.
client_initial(Port) ->
    Self = self(),
    Tag = make_ref(),
    Adapter = #{
        send_fun => fun(_IP, _Port, Pkt) ->
            Self ! {Tag, iolist_to_binary(Pkt)},
            ok
        end,
        close_fun => fun() -> ok end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => make_ref()
    },
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Initial =
        receive
            {Tag, Datagram} -> Datagram
        after 5000 -> error(no_client_initial)
        end,
    quic:close(Conn, normal),
    Initial.

dcid(<<1:1, 1:1, _:6, _Version:32, DL, DCID:DL/binary, _/binary>>) ->
    DCID.

%% Frames of the server Initials coalesced in Datagram.
initial_frames(
    ODCID, <<1:1, 1:1, Type:2, _:4, _:32, DL, _:DL/binary, SL, _:SL/binary, R0/binary>> = D
) ->
    {TokenLen, R1} =
        case Type of
            0 -> quic_varint:decode(R0);
            _ -> {0, R0}
        end,
    <<_:TokenLen/binary, R2/binary>> = R1,
    {Len, R3} = quic_varint:decode(R2),
    <<Encrypted:Len/binary, Next/binary>> = R3,
    Header = binary:part(D, 0, byte_size(D) - byte_size(R3)),
    Frames =
        case Type of
            0 -> decrypt_initial(ODCID, Header, Encrypted);
            _ -> []
        end,
    Frames ++ initial_frames(ODCID, Next);
initial_frames(_ODCID, _) ->
    [].

decrypt_initial(ODCID, Header, Encrypted) ->
    {Key, IV, HP} = quic_keys:derive_initial_server(ODCID),
    case quic_aead:unprotect_long_packet(aes_128_gcm, Key, IV, HP, Header, Encrypted, undefined) of
        {ok, _PN, _, Plaintext} ->
            {ok, Frames} = quic_frame:decode_all(Plaintext),
            Frames;
        {error, _} ->
            []
    end.

%% A v1 Initial with 8-byte connection IDs, padded to 1200 bytes, whose
%% protected part is zeros.
unreadable_initial() ->
    <<16#C3, 1:32, 8, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0:((1200 - 23) * 8)>>.

wait_connections(Name, Done) ->
    wait_connections(Name, Done, erlang:monotonic_time(millisecond) + 8000).

wait_connections(Name, Done, Deadline) ->
    {ok, Listed} = quic:get_server_connections(Name),
    Conns = lists:usort(Listed),
    case Done(Conns) orelse erlang:monotonic_time(millisecond) > Deadline of
        true ->
            Conns;
        false ->
            timer:sleep(50),
            wait_connections(Name, Done, Deadline)
    end.
