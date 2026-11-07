%%% -*- erlang -*-
%%%
%%% What a server sends while processing the packet that moves a client
%%% to a new address goes to that address (RFC 9000 Section 9.3), not
%%% down the path the client left. The NEW_CONNECTION_ID answering the
%%% RETIRE_CONNECTION_ID a migrating client sends used to go to the old
%%% address; when that path was gone the client never received a spare
%%% connection id and could not migrate again.

-module(quic_migration_reply_path_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(PEER_CID0, <<"peer-cd0">>).
-define(PEER_CID1, <<"peer-cd1">>).

replacement_cid_follows_the_migrating_client_test() ->
    with_sockets(fun(Old, OldSock, New, NewSock) ->
        S0 = state(Old),
        %% Our seq 1 goes out on the current path, and is what the client
        %% moves to.
        S1 = quic_connection:issue_new_connection_ids(S0),
        [OurCID1] = [C || {new_connection_id, 1, _, C, _} <- frames(OldSock, ?PEER_CID0, S1)],
        %% From its new address, the client retires seq 0.
        Packet = packet(1, OurCID1, [{retire_connection_id, 0}, ping], S1),
        S2 = quic_connection:server_recv_pass([Packet], New, undefined, S1),
        ?assertEqual(New, S2#state.remote_addr),
        ?assertMatch([_], [S || {new_connection_id, S, _, _, _} <- frames(NewSock, ?PEER_CID1, S2)]),
        ?assertEqual([], [S || {new_connection_id, S, _, _, _} <- frames(OldSock, ?PEER_CID0, S2)])
    end).

%% A pass from the current address sends at once, as before.
reply_on_the_current_path_is_not_held_test() ->
    with_sockets(fun(Old, OldSock, _New, _NewSock) ->
        S1 = quic_connection:issue_new_connection_ids(state(Old)),
        [OurCID1] = [C || {new_connection_id, 1, _, C, _} <- frames(OldSock, ?PEER_CID0, S1)],
        Packet = packet(1, OurCID1, [{retire_connection_id, 0}, ping], S1),
        S2 = quic_connection:server_recv_pass([Packet], Old, undefined, S1),
        ?assertMatch([_], [S || {new_connection_id, S, _, _, _} <- frames(OldSock, ?PEER_CID0, S2)])
    end).

%%====================================================================
%% Helpers
%%====================================================================

state(Addr) ->
    S0 = quic_connection_test_support:server_with_peer_cid(?PEER_CID0),
    S1 = S0#state{
        remote_addr = Addr,
        owner = owner(),
        pmtu_state = quic_pmtu:new(),
        coalesce = false,
        hs = (S0#state.hs)#hs{tls_state = handshake_complete, address_validated = true}
    },
    %% The client's spare CID, for the server to use on the new path.
    quic_connection:handle_new_connection_id(1, 0, ?PEER_CID1, binary:copy(<<7>>, 16), S1).

%% A 1-RTT packet from the client carrying Frames, padded so the
%% unvalidated-address limit leaves room for the reply.
packet(PN, DCID, Frames, #state{app_keys = {ClientKeys, _}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Payload0 = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    Payload = <<Payload0/binary, 0:(8 * 500)>>,
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, 16#40, DCID, Payload).

%% Frames of the server packets that reached Sock under DCID.
frames(Sock, DCID, #state{app_keys = {_, ServerKeys}}) ->
    lists:append([short_frames(ServerKeys, DCID, D) || D <- recv_all(Sock)]).

short_frames(Keys, DCID, <<0:1, _:7, _/binary>> = D) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = Keys,
    HeaderLen = 1 + byte_size(DCID),
    case D of
        <<Header:HeaderLen/binary, Encrypted/binary>> ->
            case
                quic_aead:unprotect_short_packet(Cipher, Key, IV, HP, Header, Encrypted, undefined)
            of
                {ok, _PN, _, Plaintext} ->
                    {ok, Frames} = quic_frame:decode_all(Plaintext),
                    Frames;
                {error, _} ->
                    []
            end;
        _ ->
            []
    end;
short_frames(_Keys, _DCID, _) ->
    [].

recv_all(Sock) ->
    receive
        {udp, Sock, _, _, D} -> [D | recv_all(Sock)]
    after 100 -> []
    end.

with_sockets(Fun) ->
    {ok, OldSock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, NewSock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, OldPort} = inet:port(OldSock),
    {ok, NewPort} = inet:port(NewSock),
    try
        Fun({{127, 0, 0, 1}, OldPort}, OldSock, {{127, 0, 0, 1}, NewPort}, NewSock)
    after
        gen_udp:close(OldSock),
        gen_udp:close(NewSock)
    end.

%% Takes the path_changed notices, which would otherwise reach later tests.
owner() ->
    spawn(fun() ->
        receive
        after 10000 -> ok
        end
    end).
