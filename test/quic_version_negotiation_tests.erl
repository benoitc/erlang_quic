%%% -*- erlang -*-
%%%
%%% Client handling of Version Negotiation packets (RFC 9000 §6.2).
%%%
%%% The tests stand in for the server with a plain UDP socket: they read the
%%% connection IDs off the client's Initial and answer with a hand-built
%%% Version Negotiation packet, which is unprotected.

-module(quic_version_negotiation_tests).

-include_lib("eunit/include/eunit.hrl").

-define(V1, 16#00000001).
%% A version no implementation speaks, plus a GREASE-shaped one.
-define(OTHER_VERSIONS, [16#00000009, 16#1a2a3a4a]).

%% No mutually supported version: the client gives up with the offered list
%% instead of retransmitting its Initial until the handshake timeout.
unsupported_versions_abandon_test_() ->
    {timeout, 30, fun unsupported_versions_abandon/0}.

unsupported_versions_abandon() ->
    {ok, Sock, Port} = fake_server(),
    try
        {ok, Conn} = connect(Port),
        {Peer, DCID, SCID} = recv_initial(Sock),
        send_vn(Sock, Peer, SCID, DCID, ?OTHER_VERSIONS),
        receive
            {quic, Conn, {closed, Reason}} ->
                ?assertEqual({version_negotiation, ?OTHER_VERSIONS}, Reason)
        after 5000 -> error(connection_not_abandoned)
        end
    after
        gen_udp:close(Sock)
    end.

%% RFC 9000 §6.2: a Version Negotiation listing the version the client sent
%% is bogus, since the server would have answered it. Discard it and keep
%% the handshake going (the Initial is retransmitted as usual).
own_version_offered_is_discarded_test_() ->
    {timeout, 30, fun own_version_offered_is_discarded/0}.

own_version_offered_is_discarded() ->
    {ok, Sock, Port} = fake_server(),
    try
        {ok, Conn} = connect(Port),
        {Peer, DCID, SCID} = recv_initial(Sock),
        send_vn(Sock, Peer, SCID, DCID, [?V1 | ?OTHER_VERSIONS]),
        ?assertEqual(no_close, wait_close(Conn, 1000)),
        %% Still handshaking: the client keeps retransmitting its Initial.
        ?assertMatch({_, _, _}, recv_initial(Sock))
    after
        gen_udp:close(Sock)
    end.

%% A Version Negotiation for another connection's ID is not ours to act on.
foreign_cid_is_discarded_test_() ->
    {timeout, 30, fun foreign_cid_is_discarded/0}.

foreign_cid_is_discarded() ->
    {ok, Sock, Port} = fake_server(),
    try
        {ok, Conn} = connect(Port),
        {Peer, DCID, _SCID} = recv_initial(Sock),
        send_vn(Sock, Peer, crypto:strong_rand_bytes(8), DCID, ?OTHER_VERSIONS),
        ?assertEqual(no_close, wait_close(Conn, 1000))
    after
        gen_udp:close(Sock)
    end.

%%====================================================================
%% Helpers
%%====================================================================

fake_server() ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    {ok, Sock, Port}.

connect(Port) ->
    quic:connect({127, 0, 0, 1}, Port, #{verify => false}, self()).

%% Read the client's Initial and return its address plus the connection IDs
%% it put on the wire. Long-header connection IDs are not protected.
recv_initial(Sock) ->
    {ok, {IP, ClientPort, Data}} = gen_udp:recv(Sock, 0, 5000),
    <<1:1, _:7, _Version:32, DCIDLen:8, DCID:DCIDLen/binary, SCIDLen:8, SCID:SCIDLen/binary,
        _/binary>> = Data,
    {{IP, ClientPort}, DCID, SCID}.

%% RFC 9000 §17.2.1. `DCID' is the client's source connection ID, `SCID' the
%% one it addressed us by.
send_vn(Sock, {IP, Port}, DCID, SCID, Versions) ->
    Packet = quic_packet:encode_version_negotiation(DCID, SCID, Versions),
    ok = gen_udp:send(Sock, IP, Port, Packet).

wait_close(Conn, Timeout) ->
    receive
        {quic, Conn, {closed, Reason}} -> {closed, Reason}
    after Timeout -> no_close
    end.
