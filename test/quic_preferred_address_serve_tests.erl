%%% -*- erlang -*-
%%%
%%% A server keeps sending from its original address until it has
%%% validated a client's move to its preferred address (RFC 9000
%%% Section 9.6.2), and never uses one connection ID from two of its
%%% addresses (Section 9.5).

-module(quic_preferred_address_serve_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(OLD, {{127, 0, 0, 1}, 40000}).

stays_on_the_original_address_until_validated_test() ->
    with_sockets(fun(Pref, Peer) ->
        S0 = server(true),
        S1 = quic_connection:maybe_handle_address_change({path, Pref, Peer}, 1200, S0),
        ?assertEqual(?OLD, S1#state.remote_addr),
        ?assertEqual(S0#state.socket, S1#state.socket),
        ?assertMatch(
            #path_state{remote_addr = Peer, via = Pref, status = validating},
            quic_connection_test_support:pending_peer_path(S1)
        )
    end).

moves_at_once_to_a_path_it_already_validated_test() ->
    with_sockets(fun(Pref, Peer) ->
        Validated = #path_state{
            remote_addr = Peer, via = Pref, status = validated, dcid = <<"spare-ci">>, dcid_seq = 1
        },
        S0 = server(true),
        S1 = S0#state{mig = (S0#state.mig)#mig{alt_paths = [Validated]}},
        S2 = quic_connection:maybe_handle_address_change({path, Pref, Peer}, 1200, S1),
        ?assertEqual(Peer, S2#state.remote_addr),
        ?assertEqual(Pref, S2#state.socket),
        ?assertEqual(undefined, quic_connection_test_support:pending_peer_path(S2))
    end).

no_answer_without_a_cid_for_another_address_test() ->
    with_sockets(fun(Pref, Peer) ->
        S0 = (server(false))#state{current_packet_via = Pref},
        S1 = quic_connection:answer_probe_on_new_path(Peer, <<"challeng">>, S0),
        ?assertEqual([], quic_connection_test_support:alt_paths(S1)),
        ?assertEqual(S0#state.dcid, S1#state.dcid)
    end).

%% A client with a zero-length CID is sent that empty CID on every path
%% (RFC 9000 Section 5.1.1), so its probe of the preferred address, from
%% the address it already uses, is answered there (Section 8.2.2).
zero_length_cid_probe_is_answered_test() ->
    with_peer_socket(fun(Pref, Peer, PeerSock) ->
        %% The probe brought 1232 bytes, room for a full-size answer.
        S = zero_length_server(Peer),
        S0 = S#state{current_packet_via = Pref, mig = (S#state.mig)#mig{pass_rx = 1232}},
        S1 = quic_connection:answer_probe_on_new_path(Peer, <<"challeng">>, S0),
        ?assertMatch(
            [#path_state{remote_addr = Peer, via = Pref, dcid = <<>>, status = validating}],
            quic_connection_test_support:alt_paths(S1)
        ),
        {ok, PrefPort} = inet:port(Pref),
        ?assertMatch({ok, {_, PrefPort, _}}, gen_udp:recv(PeerSock, 0, 1000))
    end).

%% Its first packet there starts validating that path, and the server keeps
%% its original socket until the path is validated (Section 9.6.2).
zero_length_cid_move_is_validated_test() ->
    with_peer_socket(fun(Pref, Peer, _PeerSock) ->
        S0 = zero_length_server(Peer),
        S1 = quic_connection:maybe_handle_address_change({path, Pref, Peer}, 1200, S0),
        ?assertEqual(S0#state.socket, S1#state.socket),
        ?assertMatch(
            #path_state{remote_addr = Peer, via = Pref, dcid = <<>>, status = validating},
            quic_connection_test_support:pending_peer_path(S1)
        )
    end).

%% A connected server whose client uses a zero-length CID from Peer.
zero_length_server(Peer) ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<>>),
    S0#state{remote_addr = Peer, owner = self(), pmtu_state = quic_pmtu:new()}.

with_peer_socket(Fun) ->
    {ok, Pref} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, PeerSock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, PeerPort} = inet:port(PeerSock),
    try
        Fun(Pref, {{127, 0, 0, 1}, PeerPort}, PeerSock)
    after
        gen_udp:close(Pref),
        gen_udp:close(PeerSock),
        flush()
    end.

%% The owner notifications these servers send to the test process.
flush() ->
    receive
        {quic, _, _} -> flush()
    after 0 -> ok
    end.

%% A connected server on its listening socket, its client on ?OLD, with a
%% spare client CID or not.
server(Spare) ->
    S0 = quic_connection_test_support:server_with_peer_cid(<<"peer-cid">>),
    Pool =
        case Spare of
            true ->
                {ok, P, _} = quic_cid:add_peer_cid(
                    S0#state.cid_pool_state, 1, 0, <<"spare-ci">>, binary:copy(<<1>>, 16)
                ),
                P;
            false ->
                S0#state.cid_pool_state
        end,
    S0#state{
        remote_addr = ?OLD, cid_pool_state = Pool, owner = self(), pmtu_state = quic_pmtu:new()
    }.

with_sockets(Fun) ->
    {ok, Pref} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, PeerSock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, PeerPort} = inet:port(PeerSock),
    try
        Fun(Pref, {{127, 0, 0, 1}, PeerPort})
    after
        gen_udp:close(Pref),
        gen_udp:close(PeerSock)
    end.
