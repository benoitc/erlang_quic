%%% -*- erlang -*-
%%%
%%% The server's default group preference.
%%%
%%% A server whose preference list holds only x25519 sends a
%%% HelloRetryRequest to any client whose key_share leads with another
%%% curve, even when the crypto layer speaks that curve perfectly well.
%%% The handshake still completes, so nothing looks broken, but it costs
%%% a full extra round trip on every such connection and drags the
%%% rarely-exercised HRR path into flows that do not need it. picoquic
%%% shares P-256 first, so this was every connection from it.
%%%
%%% Both outcomes connect successfully, so the cases here also count the
%%% Initial-level datagrams the client puts on the wire before the
%%% connection is up. A client must expand every datagram carrying an
%%% Initial to 1200 bytes while it is unvalidated (RFC 9000 §14.1), so
%%% the count is a direct read on how many Initial-level exchanges the
%%% handshake needed. An HRR adds a round trip and the count goes up.
%%% The assertions are made against a same-run baseline rather than
%%% against a fixed number, so they survive unrelated changes to the
%%% handshake shape.

-module(quic_server_default_groups_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    p256_first_client_is_accepted_directly/1,
    p384_first_client_is_accepted_directly/1,
    x25519_client_is_still_accepted_directly/1,
    explicit_groups_still_restrict_and_force_hrr/1,
    explicit_groups_still_reject_a_disjoint_client/1
]).

%% A client pads every datagram carrying an Initial to this while it is
%% unvalidated (RFC 9000 §14.1).
-define(PADDED_INITIAL, 1200).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        p256_first_client_is_accepted_directly,
        p384_first_client_is_accepted_directly,
        x25519_client_is_still_accepted_directly,
        explicit_groups_still_restrict_and_force_hrr,
        explicit_groups_still_reject_a_disjoint_client
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Default server: no HRR for any classical group
%%====================================================================

p256_first_client_is_accepted_directly(_Config) ->
    {_, Baseline} = handshake(#{}, [x25519]),
    {Group, Count} = handshake(#{}, [secp256r1, x25519]),
    %% The server takes the client's lead group instead of steering it
    %% back to x25519 ...
    ?assertEqual(secp256r1, Group),
    %% ... and does it without an extra Initial-level round trip.
    ?assertEqual(Baseline, Count).

p384_first_client_is_accepted_directly(_Config) ->
    {_, Baseline} = handshake(#{}, [x25519]),
    {Group, Count} = handshake(#{}, [secp384r1, x25519]),
    ?assertEqual(secp384r1, Group),
    ?assertEqual(Baseline, Count).

x25519_client_is_still_accepted_directly(_Config) ->
    %% The case that already worked. Broadening the default must not
    %% cost the common client its direct acceptance.
    {Group, _Count} = handshake(#{}, [x25519]),
    ?assertEqual(x25519, Group).

%%====================================================================
%% An explicit preference still means what it says
%%====================================================================

explicit_groups_still_restrict_and_force_hrr(_Config) ->
    %% Server pinned to secp256r1, client leading with x25519. The HRR
    %% is correct here, and this is also the fence that proves the
    %% detector above can actually see a second flight.
    {_, Baseline} = handshake(#{}, [x25519]),
    {Group, Count} = handshake(#{groups => [secp256r1]}, [x25519, secp256r1]),
    ?assertEqual(secp256r1, Group),
    %% Strictly more than a direct handshake: this is the fence proving
    %% the counter can see an HRR at all, so the equalities above are
    %% not vacuous.
    ?assert(Count > Baseline).

explicit_groups_still_reject_a_disjoint_client(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{groups => [secp384r1]}),
    try
        Port = maps:get(port, Server),
        Opts = #{verify => false, alpn => [<<"echo">>], groups => [x25519]},
        ?assertMatch({error, _}, connect_plain(Port, Opts))
    after
        quic_test_echo_server:stop(Server)
    end.

%%====================================================================
%% Harness
%%====================================================================

%% Run one handshake through a recording bridge. Returns the negotiated
%% group and the number of Initial-level datagrams the client sent.
handshake(ServerOpts, ClientGroups) ->
    {ok, Server} = quic_test_echo_server:start(ServerOpts),
    try
        Port = maps:get(port, Server),
        SocketRef = make_ref(),
        Self = self(),
        Bridge = spawn_link(fun() -> bridge_init({127, 0, 0, 1}, Port, SocketRef, Self) end),
        Adapter = #{
            send_fun => fun(IP, P, Pkt) ->
                Bridge ! {send, IP, P, Pkt},
                ok
            end,
            close_fun => fun() ->
                Bridge ! stop,
                ok
            end,
            local => {{127, 0, 0, 1}, 0},
            socket_ref => SocketRef
        },
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => ClientGroups,
            socket_backend => adapter,
            socket_adapter => Adapter
        },
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        Bridge ! {set_conn, Conn},
        Info =
            receive
                {quic, Conn, {connected, I}} -> I
            after 10000 -> ct:fail("connect timeout")
            end,
        Count = count_initials(0),
        ct:pal("server ~p / client ~p: negotiated ~p over ~p client Initial datagram(s)", [
            maps:get(groups, ServerOpts, default),
            ClientGroups,
            maps:get(negotiated_group, Info, undefined),
            Count
        ]),
        _ = quic:safe_close(Conn, normal),
        {maps:get(negotiated_group, Info, undefined), Count}
    after
        quic_test_echo_server:stop(Server)
    end.

connect_plain(Port, Opts) ->
    case quic:connect(<<"127.0.0.1">>, Port, Opts, self()) of
        {ok, Conn} ->
            receive
                {quic, Conn, {connected, _}} ->
                    _ = quic:safe_close(Conn, normal),
                    ok;
                {quic, Conn, {error, Reason}} ->
                    {error, Reason};
                {quic, Conn, {closed, Reason}} ->
                    {error, Reason}
            after 10000 ->
                _ = quic:safe_close(Conn, timeout),
                {error, timeout}
            end;
        {error, _} = Err ->
            Err
    end.

count_initials(N) ->
    receive
        {client_initial, Size} when Size >= ?PADDED_INITIAL -> count_initials(N + 1);
        {client_initial, _Small} -> count_initials(N)
    after 300 -> N
    end.

%%====================================================================
%% Bridge
%%====================================================================

%% Relays between the client's socket adapter and a real UDP socket,
%% reporting the size of every client Initial. The long-header form bit
%% and packet-type bits are outside the header-protection mask, so the
%% type is readable without keys.
bridge_init(ServerIP, ServerPort, SocketRef, Reporter) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef,
        reporter => Reporter
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        {send, _IP, _Port, Pkt} ->
            case header_type(Pkt) of
                initial ->
                    maps:get(reporter, Bridge) ! {client_initial, iolist_size(Pkt)};
                _ ->
                    ok
            end,
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            case maps:get(conn, Bridge) of
                undefined ->
                    bridge_loop(Bridge#{pending := [Data | maps:get(pending, Bridge)]});
                Conn ->
                    deliver(Bridge, Conn, Data),
                    bridge_loop(Bridge)
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Bridge)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.

header_type(Pkt) ->
    <<First:8, _/binary>> = iolist_to_binary(Pkt),
    case First band 16#80 of
        0 ->
            short;
        _ ->
            case First band 16#30 of
                16#00 -> initial;
                _ -> other_long
            end
    end.
