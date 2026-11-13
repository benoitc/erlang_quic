%%% -*- erlang -*-
%%%
%%% BBR's ACK frequency requests on the wire (draft-ietf-ccwg-bbr-07
%%% Section 4.1.3.3, draft-ietf-quic-ack-frequency-14): a connection whose
%%% controller is in a given phase sends its packets to a local socket,
%%% and the test decrypts what arrived.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_ack_frequency_wire_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(M, quic_cc_bbr_model_tests).
-define(SEC, 1000000).
-define(PEER, #{min_ack_delay => 1000}).

%% ProbeBW_CRUISE asks for an ACK per quarter cwnd and half an RTT.
cruise_asks_for_fewer_acks_test() ->
    {BBR, _} = phases(),
    {Sock, S0} = connection(BBR, ?PEER),
    S = quic_connection:maybe_request_ack_frequency(S0),
    CwndPkts = quic_cc_bbr:cwnd(BBR) div 1200,
    SrttUs = srtt_us(S),
    ?assertEqual(
        [{ack_frequency, 0, CwndPkts div 4, SrttUs div 2, 3}], ack_frequency(recv(Sock, S))
    ),
    ?assert(CwndPkts div 4 > 1).

%% Entering ProbeBW_REFILL asks for frequent ACKs again, at once.
refill_asks_for_more_acks_at_once_test() ->
    {BBR, _} = phases(),
    Refill = refill(),
    {Sock, S0} = connection(BBR, ?PEER),
    S1 = quic_connection:maybe_request_ack_frequency(S0),
    S2 = quic_connection:maybe_request_ack_frequency(S1#state{cc_state = wrap(Refill)}),
    [{ack_frequency, 0, T0, _, 3}, {ack_frequency, 1, T1, D1, 1}] = ack_frequency(recv(Sock, S2)),
    ?assert(T1 =< 1 andalso T1 < T0),
    ?assert(D1 =< srtt_us(S2) div 4).

%% The last packet of a ProbeRTT flight carries IMMEDIATE_ACK; outside
%% ProbeRTT it does not.
probe_rtt_flight_end_carries_immediate_ack_test() ->
    {Cruise, ProbeRtt} = phases(),
    ?assertEqual(probe_rtt, maps:get(mode, quic_cc_bbr:info(ProbeRtt))),
    {Sock1, S1} = connection(ProbeRtt, ?PEER),
    ?assertEqual([[ping, immediate_ack]], recv(Sock1, quic_connection:send_frame(ping, S1))),
    {Sock2, S2} = connection(Cruise, ?PEER),
    ?assertEqual([[ping]], recv(Sock2, quic_connection:send_frame(ping, S2))).

%% Nothing of the extension goes to a peer without min_ack_delay.
nothing_to_a_peer_without_min_ack_delay_test() ->
    {Cruise, ProbeRtt} = phases(),
    {Sock1, S1} = connection(Cruise, #{}),
    ?assertEqual([], recv(Sock1, quic_connection:maybe_request_ack_frequency(S1))),
    {Sock2, S2} = connection(ProbeRtt, #{}),
    ?assertEqual([[ping]], recv(Sock2, quic_connection:send_frame(ping, S2))).

%%====================================================================
%% Helpers
%%====================================================================

%% BBR in ProbeBW_CRUISE and in ProbeRTT, from the simulated path.
phases() ->
    Sim = ?M:to_probe_bw(?M:sim(?M:bulk_path())),
    Cruise = ?M:run_until(Sim, ?M:in_mode(probe_bw_cruise), 5 * ?SEC),
    ProbeRtt = ?M:run_until(Cruise, ?M:in_mode(probe_rtt), 15 * ?SEC),
    {maps:get(cc, Cruise), maps:get(cc, ProbeRtt)}.

refill() ->
    Sim = ?M:to_probe_bw(?M:sim(?M:bulk_path())),
    Cruise = ?M:run_until(Sim, ?M:in_mode(probe_bw_cruise), 5 * ?SEC),
    maps:get(cc, ?M:run_until(Cruise, ?M:in_mode(probe_bw_refill), 5 * ?SEC)).

%% quic_cc's wrapper around a BBR state.
wrap(BBR) ->
    {cc_wrapper, quic_cc_bbr, BBR}.

%% A connected client using BBR whose packets reach Sock.
connection(BBR, PeerTP) ->
    {ok, Sock} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Sock),
    S = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ),
    {Sock, S#state{
        coalesce = false,
        remote_addr = {{127, 0, 0, 1}, Port},
        transport_params = PeerTP,
        cc_state = wrap(BBR),
        pn_app = (S#state.hs)#hs.pn_handshake
    }}.

srtt_us(#state{loss_state = LS}) ->
    quic_rtt:smoothed(quic_loss:rtt(LS)) * 1000.

%% The frames of each 1-RTT packet that reached Sock.
recv(Sock, #state{app_keys = {ClientKeys, _}, dcid = DCID}) ->
    [frames(ClientKeys, DCID, D) || D <- datagrams(Sock)].

datagrams(Sock) ->
    case gen_udp:recv(Sock, 0, 1500) of
        {ok, {_, _, D}} -> [D | datagrams(Sock)];
        {error, timeout} -> []
    end.

frames(#crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher}, DCID, D) ->
    HeaderLen = 1 + byte_size(DCID),
    <<Header:HeaderLen/binary, Encrypted/binary>> = D,
    {ok, _PN, _, Plaintext} =
        quic_aead:unprotect_short_packet(Cipher, Key, IV, HP, Header, Encrypted, undefined),
    {ok, Frames} = quic_frame:decode_all(Plaintext),
    [F || F <- Frames, F =/= padding].

ack_frequency(Packets) ->
    [F || Frames <- Packets, {ack_frequency, _, _, _, _} = F <- Frames].
