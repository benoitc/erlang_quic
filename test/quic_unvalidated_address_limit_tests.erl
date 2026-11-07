%%% -*- erlang -*-
%%%
%%% Until a client's new address is validated, the server sends it at
%%% most three times what it received from it (RFC 9000 Sections 8 and
%%% 9.3.1), and pads a path probe only as far as that allows (Section
%%% 8.2.1). What does not fit waits for more data or for validation.

-module(quic_unvalidated_address_limit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).

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

recv(PN, Size, From, State) ->
    quic_connection:server_recv_pass([packet(PN, Size, State)], From, undefined, State).

%% A PING padded to Size bytes on the wire.
packet(PN, Size, #state{app_keys = {ClientKeys, _}, cfg = #conn_cfg{scid = SCID}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Ping = quic_frame:encode(ping),
    Pad = Size - (1 + byte_size(SCID) + 1 + byte_size(Ping) + 16),
    Payload = <<Ping/binary, 0:(8 * Pad)>>,
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

%% Takes the path_changed notices, which would otherwise reach later tests.
owner() ->
    spawn(fun() ->
        receive
        after 10000 -> ok
        end
    end).
