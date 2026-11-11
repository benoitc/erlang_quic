%%% -*- erlang -*-
%%%
%%% Tests for QUIC Listener
%%% RFC 9000 Section 5 - Connections
%%%

-module(quic_listener_tests).

%% Logger handler callback for the send_packet error-visibility tests.
%% Referenced via `?MODULE' in logger:add_handler/3.
-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(FAKE_SCID, <<1, 2, 3, 4>>).

%%====================================================================
%% Test Fixtures
%%====================================================================

%% Generate a test certificate and key for server
generate_test_cert() ->
    %% For tests, use dummy data - real certs would be loaded from files
    Cert = <<"test_certificate_data">>,
    % Simplified for tests
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

%%====================================================================
%% Listener Lifecycle Tests
%%====================================================================

start_stop_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener),
    timer:sleep(10),
    ?assertNot(is_process_alive(Listener)).

get_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Port = quic_listener:get_port(Listener),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    ok = quic_listener:stop(Listener).

get_sockname_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    {ok, {IP, Port}} = quic_listener:get_sockname(Listener),
    ?assert(is_tuple(IP)),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    %% The sockname port must match the cached get_port/1 value.
    ?assertEqual(quic_listener:get_port(Listener), Port),
    ok = quic_listener:stop(Listener).

specific_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    %% Use a random high port
    TestPort = 40000 + rand:uniform(10000),
    {ok, Listener} = quic_listener:start_link(TestPort, Opts),
    ActualPort = quic_listener:get_port(Listener),
    ?assertEqual(TestPort, ActualPort),
    ok = quic_listener:stop(Listener).

get_connections_empty_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Connections = quic_listener:get_connections(Listener),
    ?assertEqual([], Connections),
    ok = quic_listener:stop(Listener).

%% Regression for #146: an IPv6 family in extra_socket_opts must start a
%% listener instead of crashing init with the hard-coded inet family.
listen_ipv6_inet6_atom_test() ->
    listen_ipv6_with(#{extra_socket_opts => [inet6]}).

listen_ipv6_bind_addr_test() ->
    listen_ipv6_with(#{extra_socket_opts => [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]}).

listen_ipv6_with(Extra) ->
    case ipv6_available() of
        false ->
            ok;
        true ->
            {Cert, PrivKey} = generate_test_cert(),
            Opts = maps:merge(#{cert => Cert, key => PrivKey, alpn => [<<"h3">>]}, Extra),
            {ok, Listener} = quic_listener:start_link(0, Opts),
            ?assert(is_process_alive(Listener)),
            ok = quic_listener:stop(Listener)
    end.

ipv6_available() ->
    case gen_udp:open(0, [binary, inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}]) of
        {ok, S} ->
            gen_udp:close(S),
            true;
        {error, _} ->
            false
    end.

%%====================================================================
%% Multiple Listener Tests
%%====================================================================

multiple_listeners_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener1} = quic_listener:start_link(0, Opts),
    {ok, Listener2} = quic_listener:start_link(0, Opts),
    Port1 = quic_listener:get_port(Listener1),
    Port2 = quic_listener:get_port(Listener2),
    ?assertNotEqual(Port1, Port2),
    ok = quic_listener:stop(Listener1),
    ok = quic_listener:stop(Listener2).

%%====================================================================
%% ALPN Configuration Tests
%%====================================================================

alpn_list_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>, <<"hq-29">>, <<"hq-28">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

default_alpn_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Certificate Chain Tests
%%====================================================================

cert_chain_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    IntermediateCert = <<"intermediate_cert">>,
    RootCert = <<"root_cert">>,
    Opts = #{
        cert => Cert,
        cert_chain => [IntermediateCert, RootCert],
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Connection Handler Callback Tests
%%====================================================================

connection_handler_registration_test() ->
    %% Test that connection_handler option is accepted
    {Cert, PrivKey} = generate_test_cert(),
    TestPid = self(),
    Handler = fun(ConnPid, ConnRef) ->
        %% Notify test that handler was invoked
        TestPid ! {handler_invoked, ConnPid, ConnRef},
        HandlerPid = spawn(fun() ->
            receive
                stop -> ok
            after 5000 -> ok
            end
        end),
        {ok, HandlerPid}
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%% {error, Reason} declines the connection: it is stopped before it sees
%% the Initial, leaves the routing table, and the client is refused.
connection_handler_declines_test_() ->
    {timeout, 30, fun() ->
        Test = self(),
        DCID = <<3, 3, 3, 3, 3, 3, 3, 3>>,
        {ok, Listener} = quic_listener:start(0, #{
            connection_handler => fun(ConnPid, D) ->
                Test ! {conn, D, ConnPid},
                receive
                    monitored -> {error, overloaded}
                end
            end,
            psks => #{<<"id">> => <<"secret">>},
            alpn => [<<"h3">>]
        }),
        {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
        try
            Port = quic_listener:get_port(Listener),
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(DCID)),
            receive
                {conn, DCID, ConnPid} ->
                    Ref = erlang:monitor(process, ConnPid),
                    Listener ! monitored,
                    receive
                        {'DOWN', Ref, process, ConnPid, Reason} ->
                            ?assertEqual(shutdown, Reason)
                    after 2000 -> error(declined_connection_still_up)
                    end
            after 5000 -> error(handler_not_called)
            end,
            ?assertEqual({ok, ?QUIC_CONNECTION_REFUSED}, recv_refusal(Sock, DCID)),
            ?assertEqual(timeout, recv_any(Sock, 200)),
            ?assertEqual([], quic_listener:get_connections(Listener))
        after
            gen_udp:close(Sock),
            catch quic_listener:stop(Listener)
        end
    end}.

%% A handler that misbehaves for one connection costs that connection
%% only: the listener and the connections it already serves stay up.
connection_handler_failure_test_() ->
    [
        {Title, {timeout, 30, fun() -> connection_handler_failure(Misbehave) end}}
     || {Title, Misbehave} <- [
            {"handler raises", fun(_ConnPid) -> error(handler_bug) end},
            {"handler returns something else", fun(_ConnPid) -> invalid_return end},
            {"handler returns an owner for a dead connection", fun(ConnPid) ->
                Ref = erlang:monitor(process, ConnPid),
                exit(ConnPid, kill),
                receive
                    {'DOWN', Ref, process, ConnPid, _} -> {ok, self()}
                end
            end}
        ]
    ].

connection_handler_failure(Misbehave) ->
    Test = self(),
    Good = <<1, 1, 1, 1, 1, 1, 1, 1>>,
    Handler = fun(ConnPid, DCID) ->
        Test ! {conn, DCID, ConnPid},
        case DCID of
            Good -> {ok, Test};
            _ -> Misbehave(ConnPid)
        end
    end,
    {ok, Listener} = quic_listener:start(0, #{
        connection_handler => Handler,
        psks => #{<<"id">> => <<"secret">>},
        alpn => [<<"h3">>]
    }),
    Port = quic_listener:get_port(Listener),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(Good)),
        GoodConn = await_handler_call(Good),
        Bad = <<2, 2, 2, 2, 2, 2, 2, 2>>,
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(Bad)),
        BadConn = await_handler_call(Bad),
        Ref = erlang:monitor(process, BadConn),
        receive
            {'DOWN', Ref, process, BadConn, _} -> ok
        after 5000 -> error(connection_not_closed)
        end,
        ?assertEqual({ok, ?QUIC_INTERNAL_ERROR}, recv_refusal(Sock, Bad)),
        ?assert(is_process_alive(Listener)),
        ?assert(is_process_alive(GoodConn)),
        ?assertEqual([GoodConn], quic_listener:get_connections(Listener))
    after
        gen_udp:close(Sock),
        catch quic_listener:stop(Listener)
    end.

%% Only the header is parsed to route it; padded to the 1200 bytes a
%% client Initial datagram has.
fake_initial(DCID) ->
    fake_initial(DCID, ?QUIC_VERSION_1).

fake_initial(DCID, Version) ->
    fake_long(initial, DCID, Version).

fake_long(Type, DCID, Version) ->
    FirstByte = 16#C0 bor (quic_packet:type_to_bits(Type, Version) bsl 4),
    SCID = ?FAKE_SCID,
    Packet =
        <<FirstByte, Version:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary>>,
    <<Packet/binary, 0:((1200 - byte_size(Packet)) * 8)>>.

%%====================================================================
%% Refusal (RFC 9000 Section 5.2.2)
%%====================================================================

%% The refusal is an Initial carrying only CONNECTION_CLOSE, addressed to
%% the client's SCID, keyed from the client's DCID, and not padded.
refusal_packet_test_() ->
    [
        {Name ++ " " ++ CodeName, fun() -> refusal_packet(Version, Code) end}
     || {Name, Version} <- [{"v1", ?QUIC_VERSION_1}, {"v2", ?QUIC_VERSION_2}],
        {CodeName, Code} <- [
            {"CONNECTION_REFUSED", ?QUIC_CONNECTION_REFUSED},
            {"INTERNAL_ERROR", ?QUIC_INTERNAL_ERROR}
        ]
    ].

refusal_packet(Version, Code) ->
    DCID = <<9, 8, 7, 6, 5, 4, 3, 2>>,
    Refusal = quic_listener:build_refusal(Code, ?FAKE_SCID, DCID, Version),
    ?assertEqual(
        {ok, #{
            version => Version,
            dcid => ?FAKE_SCID,
            scid => DCID,
            token => <<>>,
            pn => 0,
            frames => [{connection_close, transport, Code, 0, <<>>}]
        }},
        decode_refusal(DCID, Refusal)
    ),
    %% Header 1+4+1+4+1+8, token length 1, Length 1, PN 1, frame 4, tag 16.
    ?assertEqual(42, byte_size(Refusal)),
    ?assert(byte_size(Refusal) < byte_size(fake_initial(DCID, Version))).

%% At max_connections the Initial is answered with CONNECTION_REFUSED,
%% for each supported version.
max_connections_refused_test_() ->
    [
        {Name, {timeout, 30, fun() -> max_connections_refused(Version) end}}
     || {Name, Version} <- [{"v1", ?QUIC_VERSION_1}, {"v2", ?QUIC_VERSION_2}]
    ].

max_connections_refused(Version) ->
    with_refusing_listener(fun(Sock, Port) ->
        DCID = <<4, 4, 4, 4, 4, 4, 4, 4>>,
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(DCID, Version)),
        ?assertEqual({ok, ?QUIC_CONNECTION_REFUSED}, recv_refusal(Sock, DCID, Version)),
        ?assertEqual(timeout, recv_any(Sock, 200))
    end).

%% Handshake and 0-RTT packets for an unknown connection get no reply.
non_initial_not_refused_test_() ->
    {timeout, 30, fun() ->
        with_refusing_listener(fun(Sock, Port) ->
            Initial = <<5, 5, 5, 5, 5, 5, 5, 5>>,
            [
                ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_long(Type, Initial, V))
             || Type <- [handshake, zero_rtt], V <- [?QUIC_VERSION_1, ?QUIC_VERSION_2]
            ],
            %% The listener handles datagrams in order: the first reply is
            %% the one to this Initial.
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(Initial)),
            ?assertEqual({ok, ?QUIC_CONNECTION_REFUSED}, recv_refusal(Sock, Initial)),
            ?assertEqual(timeout, recv_any(Sock, 200))
        end)
    end}.

%% Initials drained in one receive sweep go through the batched dispatch,
%% which refuses each new connection once.
batched_initials_refused_test_() ->
    {timeout, 30, fun() ->
        with_refusing_listener(fun(Sock, Port, Listener) ->
            A = <<6, 6, 6, 6, 6, 6, 6, 6>>,
            B = <<7, 7, 7, 7, 7, 7, 7, 7>>,
            erlang:trace_pattern({quic_listener, dispatch_batched_packets, 3}, true, [local]),
            1 = erlang:trace(Listener, true, [call]),
            ok = sys:suspend(Listener),
            try
                [
                    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(D))
                 || D <- [A, A, B]
                ],
                ok = await_queue_len(Listener, 3, 5000)
            after
                ok = sys:resume(Listener)
            end,
            receive
                {trace, Listener, call, {quic_listener, dispatch_batched_packets, [Ps, _, _]}} ->
                    ?assertEqual(3, length(Ps))
            after 5000 -> error(not_batched)
            end,
            erlang:trace(Listener, false, [call]),
            erlang:trace_pattern({quic_listener, dispatch_batched_packets, 3}, false, [local]),
            {ok, D1} = recv_any(Sock, 5000),
            {ok, D2} = recv_any(Sock, 5000),
            ?assertEqual(timeout, recv_any(Sock, 200)),
            ?assertEqual(
                lists:sort([{A, ?QUIC_CONNECTION_REFUSED}, {B, ?QUIC_CONNECTION_REFUSED}]),
                lists:sort([refused_cid([A, B], D) || D <- [D1, D2]])
            )
        end)
    end}.

%% At most 100 refusals per one-second window, then the next window
%% allows again.
refusal_allowance_test() ->
    Ref = quic_listener:new_refusal_allowance(),
    Now = erlang:monotonic_time(second),
    ?assertEqual(
        lists:duplicate(100, true),
        [quic_listener:refusal_allowed(Ref, Now) || _ <- lists:seq(1, 100)]
    ),
    ?assertNot(quic_listener:refusal_allowed(Ref, Now)),
    ?assert(quic_listener:refusal_allowed(Ref, Now + 1)),
    ?assertEqual({Now + 1, 1}, {atomics:get(Ref, 1), atomics:get(Ref, 2)}).

%% The listener drops the Initial past the allowance and answers again
%% once the window is over. The window is set by hand, not by sleeping.
refusals_bounded_test_() ->
    {timeout, 60, fun() ->
        with_refusing_listener(fun(Sock, Port, Listener) ->
            Ref = refusal_allowance(Listener),
            Now = erlang:monotonic_time(second),
            ok = atomics:put(Ref, 1, Now + 3600),
            ok = atomics:put(Ref, 2, 0),
            lists:foreach(
                fun(N) ->
                    D = <<N:64>>,
                    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(D)),
                    ?assertEqual({ok, ?QUIC_CONNECTION_REFUSED}, recv_refusal(Sock, D))
                end,
                lists:seq(1, 100)
            ),
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(<<101:64>>)),
            ok = await_atomic(Ref, 2, 101, 5000),
            ok = atomics:put(Ref, 1, Now - 1),
            Next = <<102:64>>,
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, fake_initial(Next)),
            %% First datagram since the 100th refusal: none for the 101st.
            ?assertEqual({ok, ?QUIC_CONNECTION_REFUSED}, recv_refusal(Sock, Next)),
            ?assertEqual(timeout, recv_any(Sock, 200)),
            ?assertEqual(1, atomics:get(Ref, 2))
        end)
    end}.

%% The listener's one two-slot atomics ref.
refusal_allowance(Listener) ->
    [Ref] = [
        E
     || E <- tuple_to_list(sys:get_state(Listener)),
        is_reference(E),
        try atomics:info(E) of
            #{size := 2} -> true;
            _ -> false
        catch
            error:badarg -> false
        end
    ],
    Ref.

await_atomic(Ref, Ix, Value, Left) when Left > 0 ->
    case atomics:get(Ref, Ix) of
        Value ->
            ok;
        _ ->
            receive
            after 10 -> await_atomic(Ref, Ix, Value, Left - 10)
            end
    end;
await_atomic(_Ref, _Ix, _Value, _Left) ->
    error(allowance_not_reached).

with_refusing_listener(Fun) when is_function(Fun, 2) ->
    with_refusing_listener(fun(Sock, Port, _Listener) -> Fun(Sock, Port) end);
with_refusing_listener(Fun) ->
    {ok, Listener} = quic_listener:start(0, #{
        max_connections => 0,
        psks => #{<<"id">> => <<"secret">>},
        alpn => [<<"h3">>]
    }),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        Fun(Sock, quic_listener:get_port(Listener), Listener)
    after
        gen_udp:close(Sock),
        quic_listener:stop(Listener)
    end.

await_queue_len(Pid, N, Left) when Left > 0 ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, L} when L >= N ->
            ok;
        _ ->
            receive
            after 10 -> await_queue_len(Pid, N, Left - 10)
            end
    end;
await_queue_len(_Pid, _N, _Left) ->
    error(datagrams_not_queued).

%% Which of the DCIDs the refusal answers, and its error code.
refused_cid(DCIDs, Datagram) ->
    [Found] = [
        {D, Code}
     || D <- DCIDs,
        {ok, #{frames := [{connection_close, transport, Code, 0, <<>>}]}} <-
            [decode_refusal(D, Datagram)]
    ],
    Found.

recv_any(Sock, Timeout) ->
    case gen_udp:recv(Sock, 0, Timeout) of
        {ok, {_IP, _Port, Datagram}} -> {ok, Datagram};
        {error, timeout} -> timeout
    end.

%% The error code of the refusal to the fake Initial for DCID, checked
%% field by field against what the client sent.
recv_refusal(Sock, DCID) ->
    recv_refusal(Sock, DCID, ?QUIC_VERSION_1).

recv_refusal(Sock, DCID, Version) ->
    {ok, Datagram} = recv_any(Sock, 5000),
    ?assert(byte_size(Datagram) < 1200),
    {ok, #{
        version := Version,
        dcid := ?FAKE_SCID,
        scid := DCID,
        token := <<>>,
        pn := 0,
        frames := [{connection_close, transport, Code, 0, <<>>}]
    }} = decode_refusal(DCID, Datagram),
    {ok, Code}.

%% Decrypt a datagram holding exactly one server Initial, keyed from the
%% client's DCID.
decode_refusal(ClientDCID, Datagram) ->
    <<1:1, 1:1, TypeBits:2, _:4, Version:32, DL, DCID:DL/binary, SL, SCID:SL/binary, Rest0/binary>> =
        Datagram,
    initial = quic_packet:bits_to_type(TypeBits, Version),
    {TokenLen, Rest1} = quic_varint:decode(Rest0),
    <<Token:TokenLen/binary, Rest2/binary>> = Rest1,
    {Len, Rest3} = quic_varint:decode(Rest2),
    Len = byte_size(Rest3),
    Header = binary:part(Datagram, 0, byte_size(Datagram) - Len),
    {Key, IV, HP} = quic_keys:derive_initial_server(ClientDCID, Version),
    case quic_aead:unprotect_long_packet(aes_128_gcm, Key, IV, HP, Header, Rest3, undefined) of
        {ok, PN, _, Plaintext} ->
            {ok, Frames} = quic_frame:decode_all(Plaintext),
            {ok, #{
                version => Version,
                dcid => DCID,
                scid => SCID,
                token => Token,
                pn => PN,
                frames => Frames
            }};
        {error, _} = Err ->
            Err
    end.

await_handler_call(DCID) ->
    receive
        {conn, DCID, ConnPid} -> ConnPid
    after 5000 -> error(handler_not_called)
    end.

%%====================================================================
%% Connection Cleanup Tests
%%====================================================================

%% Test that cleanup_connection properly removes CID entries for dead processes
%% This tests the fix for the bug where literal atom '_' was used instead of
%% the match spec variable '$1', causing entries to never be cleaned up
cleanup_connection_removes_entries_test() ->
    %% Create an ETS table like the listener uses
    Conns = ets:new(test_conns, [set, public]),

    %% Create fake connection PIDs
    Pid1 = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Pid2 = spawn(fun() ->
        receive
            stop -> ok
        end
    end),

    %% Insert CID entries for both connections (mimics create_connection)
    CID1a = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID1b = <<10, 20, 30, 40, 50, 60, 70, 80>>,
    CID2a = <<11, 12, 13, 14, 15, 16, 17, 18>>,
    CID2b = <<21, 22, 23, 24, 25, 26, 27, 28>>,

    ets:insert(Conns, {CID1a, Pid1}),
    ets:insert(Conns, {CID1b, Pid1}),
    ets:insert(Conns, {CID2a, Pid2}),
    ets:insert(Conns, {CID2b, Pid2}),

    %% Verify all 4 entries exist
    ?assertEqual(4, ets:info(Conns, size)),

    %% Simulate cleanup for Pid1 using the same logic as quic_listener
    Pattern = {{'$1', Pid1}, [], [true]},
    ets:select_delete(Conns, [Pattern]),

    %% Verify Pid1's entries are removed, Pid2's remain
    ?assertEqual(2, ets:info(Conns, size)),
    ?assertEqual([], ets:lookup(Conns, CID1a)),
    ?assertEqual([], ets:lookup(Conns, CID1b)),
    ?assertEqual([{CID2a, Pid2}], ets:lookup(Conns, CID2a)),
    ?assertEqual([{CID2b, Pid2}], ets:lookup(Conns, CID2b)),

    %% Cleanup
    Pid1 ! stop,
    Pid2 ! stop,
    ets:delete(Conns).

%% Test both '_' and '$1' work as wildcards in match specs
cleanup_connection_match_spec_variants_test() ->
    %% Both '_' and '$1' work as wildcards in ETS match specs
    Conns = ets:new(test_conns, [set, public]),

    Pid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID2 = <<9, 10, 11, 12, 13, 14, 15, 16>>,

    %% Test with '_' wildcard
    ets:insert(Conns, {CID1, Pid}),
    ?assertEqual(1, ets:info(Conns, size)),

    Pattern1 = {{'_', Pid}, [], [true]},
    Deleted1 = ets:select_delete(Conns, [Pattern1]),
    ?assertEqual(1, Deleted1),
    ?assertEqual(0, ets:info(Conns, size)),

    %% Test with '$1' match variable
    ets:insert(Conns, {CID2, Pid}),
    ?assertEqual(1, ets:info(Conns, size)),

    Pattern2 = {{'$1', Pid}, [], [true]},
    Deleted2 = ets:select_delete(Conns, [Pattern2]),
    ?assertEqual(1, Deleted2),
    ?assertEqual(0, ets:info(Conns, size)),

    %% Cleanup
    Pid ! stop,
    ets:delete(Conns).

%%====================================================================
%% send_packet/6 error handling + logger visibility
%%====================================================================

%% Minimal logger handler that forwards only the listener_send_failed
%% report to the configured pid. Any other log event is silently
%% ignored so the test process mailbox is not polluted by unrelated
%% warnings from concurrent eunit tests.
log(
    #{level := warning, msg := {report, #{what := listener_send_failed} = R}},
    #{config := #{pid := Pid}}
) ->
    Pid ! {listener_send_failed, R};
log(_Event, _Config) ->
    ok.

install_capture() ->
    Id = list_to_atom(
        "quic_listener_capture_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    ok = logger:add_handler(Id, ?MODULE, #{
        level => warning,
        config => #{pid => self()}
    }),
    Id.

remove_capture(Id) ->
    logger:remove_handler(Id).

wait_for_listener_warning(Timeout) ->
    receive
        {listener_send_failed, R} -> {ok, R}
    after Timeout ->
        timeout
    end.

send_packet_gen_udp_surfaces_and_logs_error_test() ->
    Id = install_capture(),
    try
        {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
        ok = gen_udp:close(Sock),
        Result = quic_listener:send_packet(
            Sock, undefined, gen_udp, {127, 0, 0, 1}, 65535, <<"x">>
        ),
        ?assertMatch({error, _}, Result),
        ?assertMatch({ok, #{backend := gen_udp}}, wait_for_listener_warning(1000))
    after
        remove_capture(Id)
    end.

send_packet_socket_backend_surfaces_and_logs_error_test() ->
    Id = install_capture(),
    try
        {ok, Raw} = socket:open(inet, dgram, udp),
        {ok, State} = quic_socket:new_sender(Raw, #{backend => socket}),
        ok = socket:close(Raw),
        Result = quic_listener:send_packet(
            undefined, State, socket, {127, 0, 0, 1}, 65535, <<"x">>
        ),
        ?assertMatch({error, _}, Result),
        ?assertMatch({ok, #{backend := socket}}, wait_for_listener_warning(1000))
    after
        remove_capture(Id)
    end.
