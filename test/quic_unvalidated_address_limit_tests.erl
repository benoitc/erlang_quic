%%% -*- erlang -*-
%%%
%%% Until a client's new address is validated, the server sends it at
%%% most three times what it received from it (RFC 9000 Sections 8 and
%%% 9.3.1), and pads a path probe only as far as that allows (Section
%%% 8.2.1). What does not fit waits for more data or for validation.
%%% The same holds for answers to probes from an address on no path.

-module(quic_unvalidated_address_limit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).
-define(SPOOFED, {{127, 0, 0, 1}, 40001}).

holds_data_beyond_three_times_received_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 100, Peer, state()),
        [Challenge] = recv_all(Sock),
        ?assert(byte_size(Challenge) =< 300),
        S2 = quic_connection:send_frame({stream, 0, 0, binary:copy(<<"x">>, 1000), false}, S1),
        ?assertEqual([], recv_all(Sock)),
        S3 = recv(2, 400, Peer, S2),
        ?assertMatch([D] when byte_size(D) > 1000, recv_all(Sock)),
        ?assertEqual(Peer, S3#state.remote_addr)
    end).

validation_releases_held_data_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 100, Peer, state()),
        _ = recv_all(Sock),
        S2 = quic_connection:send_frame({stream, 0, 0, binary:copy(<<"x">>, 1000), false}, S1),
        ?assertEqual([], recv_all(Sock)),
        #path_state{challenge_data = Data} = quic_connection_test_support:pending_peer_path(S2),
        S3 = quic_connection:handle_path_response(Data, S2),
        ?assert(lists:any(fun(D) -> byte_size(D) > 1000 end, recv_all(Sock))),
        ?assertEqual(Peer, S3#state.remote_addr)
    end).

answer_to_a_short_challenge_needs_a_full_size_one_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 100, Peer, state()),
        _ = recv_all(Sock),
        #path_state{challenge_data = Short} = quic_connection_test_support:pending_peer_path(S1),
        S2 = quic_connection:handle_path_response(Short, S1),
        ?assertMatch([D] when byte_size(D) >= 1200, recv_all(Sock)),
        #path_state{challenge_data = Full} = quic_connection_test_support:pending_peer_path(S2),
        S3 = quic_connection:handle_path_response(Full, S2),
        ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S3)),
        ?assertEqual(Peer, S3#state.remote_addr)
    end).

answer_to_a_full_size_challenge_validates_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 500, Peer, state()),
        ?assertMatch([D] when byte_size(D) >= 1200, recv_all(Sock)),
        #path_state{challenge_data = Data} = quic_connection_test_support:pending_peer_path(S1),
        S2 = quic_connection:handle_path_response(Data, S1),
        ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S2))
    end).

a_response_the_limit_leaves_no_room_for_is_not_sent_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 100, Peer, state()),
        _ = recv_all(Sock),
        S = quic_connection:send_path_response_to_addr(Peer, <<"response">>, S1),
        ?assertEqual([], recv_all(Sock)),
        ?assertEqual(Peer, S#state.remote_addr)
    end).

probe_answer_stays_within_three_times_received_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = probe(1, 60, Peer, with_spare_cid(state())),
        [Answer] = recv_all(Sock),
        ?assert(byte_size(Answer) =< 180),
        ?assertMatch(
            [#path_state{challenge_data = undefined}], quic_connection_test_support:alt_paths(S1)
        ),
        _ = probe(2, 60, Peer, S1),
        ?assertMatch([D] when byte_size(D) =< 360 - byte_size(Answer), recv_all(Sock))
    end).

probe_answer_is_padded_when_the_limit_allows_test() ->
    with_peer(fun(Peer, Sock) ->
        S = probe(1, 400, Peer, with_spare_cid(state())),
        ?assertMatch([D] when byte_size(D) >= 1200, recv_all(Sock)),
        ?assertMatch(
            [#path_state{challenge_data = <<_:64>>}], quic_connection_test_support:alt_paths(S)
        )
    end).

a_short_probe_answer_challenges_the_address_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = probe(1, 60, Peer, with_spare_cid(state())),
        [Answer] = recv_all(Sock),
        ?assert(byte_size(Answer) =< 180),
        [#path_state{challenge_data = undefined, short_challenges = [Data]}] =
            quic_connection_test_support:alt_paths(S1),
        S2 = quic_connection:handle_path_response(Data, S1),
        ?assertMatch([D] when byte_size(D) >= 1200, recv_all(Sock)),
        ?assertMatch(
            [#path_state{status = validating, challenge_data = <<_:64>>, short_challenges = []}],
            quic_connection_test_support:alt_paths(S2)
        )
    end).

%% A path keeps its two latest short challenges (RFC 9000 Section 8.2.1).
short_probe_answers_keep_two_challenges_test() ->
    with_peer(fun(Peer, Sock) ->
        S = lists:foldl(
            fun(PN, S0) -> probe(PN, 60, Peer, S0) end, with_spare_cid(state()), lists:seq(1, 8)
        ),
        Answers = recv_all(Sock),
        ?assertEqual(8, length(Answers)),
        [#path_state{challenge_data = undefined, short_challenges = Short}] =
            quic_connection_test_support:alt_paths(S),
        ?assertEqual(2, length(Short)),
        [Last, Previous] = Short,
        S1 = quic_connection:handle_path_response(Previous, S),
        ?assertMatch([D] when byte_size(D) >= 1200, recv_all(Sock)),
        ?assertMatch(
            [#path_state{challenge_data = <<_:64>>, short_challenges = []}],
            quic_connection_test_support:alt_paths(S1)
        ),
        ?assertNotEqual(Last, Previous)
    end).

a_validating_path_keeps_two_short_challenges_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = recv(1, 100, Peer, state()),
        _ = recv_all(Sock),
        #path_state{challenge_data = First, short_challenges = [First]} =
            quic_connection_test_support:pending_peer_path(S1),
        S = lists:foldl(fun short_challenge/2, S1, [First, <<2:64>>, <<3:64>>, <<3:64>>]),
        ?assertMatch(
            #path_state{short_challenges = [<<3:64>>, <<2:64>>]},
            quic_connection_test_support:pending_peer_path(S)
        )
    end).

short_challenge(Data, #state{mig = #mig{pending_peer_validation = Path} = Mig} = State) ->
    S = State#state{
        mig = Mig#mig{pending_peer_validation = Path#path_state{challenge_data = Data}}
    },
    quic_connection:note_short_challenge(Data, 100, S).

a_server_keeps_the_latest_probed_paths_test() ->
    Addrs = [{{127, 0, 0, 1}, 40100 + N} || N <- lists:seq(1, 10)],
    S = lists:foldl(
        fun({PN, Addr}, S0) -> probe(PN, 60, Addr, S0) end,
        with_spare_cid(state()),
        lists:zip(lists:seq(1, 10), Addrs)
    ),
    Kept = [A || #path_state{remote_addr = A} <- quic_connection_test_support:alt_paths(S)],
    ?assertEqual(lists:reverse(lists:nthtail(6, Addrs)), Kept),
    ?assertEqual(not_found, quic_cid:retire_peer(S#state.cid_pool_state, <<1:64>>)).

holds_data_to_a_second_address_during_the_handshake_test() ->
    with_peer(fun(Peer, Sock) ->
        S1 = hs_recv(1, 100, ?SPOOFED, handshaking()),
        S2 = hs_recv(2, 100, Peer, S1),
        ?assertEqual(Peer, S2#state.remote_addr),
        ?assertMatch([C] when byte_size(C) =< 300, recv_all(Sock)),
        _ = quic_connection:send_frame({stream, 0, 0, binary:copy(<<"x">>, 1000), false}, S2),
        ?assertEqual([], recv_all(Sock))
    end).

hs_recv(PN, Size, From, State) ->
    quic_connection:handle_packet(From, packet(PN, ping, Size, State), State).

recv(PN, Size, From, State) ->
    quic_connection:server_recv_pass([packet(PN, ping, Size, State)], From, undefined, State).

probe(PN, Size, From, State) ->
    Packet = packet(PN, {path_challenge, <<PN:64>>}, Size, State),
    quic_connection:server_recv_pass([Packet], From, undefined, State).

%% Frame padded to Size bytes on the wire.
packet(PN, Frame, Size, #state{app_keys = {ClientKeys, _}, cfg = #conn_cfg{scid = SCID}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Encoded = quic_frame:encode(Frame),
    Pad = Size - (1 + byte_size(SCID) + 1 + byte_size(Encoded) + 16),
    Payload = <<Encoded/binary, 0:(8 * Pad)>>,
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, 16#40, SCID, Payload).

recv_all(Sock) ->
    receive
        {udp, Sock, _, _, D} -> [D | recv_all(Sock)]
    after 100 -> []
    end.

with_peer(Fun) ->
    {ok, Sock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    try
        Fun({{127, 0, 0, 1}, Port}, Sock)
    after
        gen_udp:close(Sock)
    end.

state() ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    S0#state{
        remote_addr = ?OLD,
        owner = owner(),
        pmtu_state = quic_pmtu:new(),
        coalesce = false,
        hs = (S0#state.hs)#hs{tls_state = handshake_complete, address_validated = true}
    }.

with_spare_cid(S) ->
    quic_connection:process_frame(
        app, {new_connection_id, 1, 0, <<1:64>>, crypto:strong_rand_bytes(16)}, S
    ).

handshaking() ->
    #state{hs = Hs} = S = state(),
    S#state{hs = Hs#hs{pn_initial = #pn_space{}, pn_handshake = #pn_space{}}}.

%% Takes the path_changed notices, which would otherwise reach later tests.
owner() ->
    spawn(fun() ->
        receive
        after 10000 -> ok
        end
    end).
