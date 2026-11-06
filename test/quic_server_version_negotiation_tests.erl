%%% -*- erlang -*-
%%%
%%% Server-side Version Negotiation (RFC 9000 section 6.1). A peer that
%%% probes with a version we do not speak must get a VN packet listing
%%% what we do speak; probing with a reserved version is how readiness
%%% checks and the interop runner detect a live server, and silence
%%% reads as down.

-module(quic_server_version_negotiation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% A GREASE version (RFC 9000 section 15): reserved, never supported.
-define(GREASE_VERSION, 16#0a0a0a0a).

vn_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        fun an_unknown_version_gets_a_version_list/1,
        fun the_reply_swaps_the_connection_ids/1,
        fun a_version_negotiation_packet_is_not_answered/1,
        fun a_small_probe_is_dropped/1,
        fun the_type_bits_do_not_matter/1
    ]}.

setup() ->
    {ok, Srv} = quic_test_echo_server:start(),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    {Srv, Sock}.

cleanup({Srv, Sock}) ->
    gen_udp:close(Sock),
    quic_test_echo_server:stop(Srv).

an_unknown_version_gets_a_version_list({Srv, Sock}) ->
    fun() ->
        {ok, {0, _DCID, _SCID, Versions}} = probe(Srv, Sock, ?GREASE_VERSION),
        ?assert(lists:member(?QUIC_VERSION_1, Versions)),
        ?assert(lists:member(?QUIC_VERSION_2, Versions)),
        ?assertNot(lists:member(?GREASE_VERSION, Versions))
    end.

%% The client matches the reply to its attempt by the connection IDs, so
%% they come back swapped.
the_reply_swaps_the_connection_ids({Srv, Sock}) ->
    fun() ->
        DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        SCID = <<9, 10, 11, 12>>,
        {ok, {0, ReplyDCID, ReplySCID, _}} =
            probe(Srv, Sock, long_header(16#c0, ?GREASE_VERSION, DCID, SCID, 1200)),
        ?assertEqual(SCID, ReplyDCID),
        ?assertEqual(DCID, ReplySCID)
    end.

%% Version 0 is itself a VN packet. Answering one lets two servers trade
%% them forever.
a_version_negotiation_packet_is_not_answered({Srv, Sock}) ->
    fun() ->
        ?assertEqual({error, timeout}, probe(Srv, Sock, 0))
    end.

%% RFC 9000 Section 5.2.2: a packet too small to start a connection is
%% dropped, not answered.
a_small_probe_is_dropped({Srv, Sock}) ->
    fun() ->
        ?assertEqual({error, timeout}, probe(Srv, Sock, long_header(16#c0, ?GREASE_VERSION, 1199)))
    end.

%% Under an unknown version the long header type bits mean nothing
%% (RFC 8999 Section 5.1); a 0-RTT- or Handshake-looking probe is answered.
the_type_bits_do_not_matter({Srv, Sock}) ->
    fun() ->
        [
            ?assertMatch(
                {ok, {0, _, _, [_ | _]}},
                probe(Srv, Sock, long_header(First, ?GREASE_VERSION, 1200))
            )
         || First <- [16#d0, 16#e0, 16#f0]
        ]
    end.

%%====================================================================
%% Helpers
%%====================================================================

probe(Srv, Sock, Version) when is_integer(Version) ->
    probe(Srv, Sock, long_header(16#c0, Version, 1200));
probe(Srv, Sock, Pkt) ->
    #{port := Port} = Srv,
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, Pkt),
    case gen_udp:recv(Sock, 0, 1000) of
        {ok, {_, _, Data}} -> {ok, parse_vn(Data)};
        {error, _} = E -> E
    end.

%% Minimal long header carrying the probe version, padded to Size.
long_header(First, Version, Size) ->
    long_header(First, Version, <<1, 2, 3, 4, 5, 6, 7, 8>>, <<9, 9, 9, 9>>, Size).

long_header(First, Version, DCID, SCID, Size) ->
    Head = <<
        First,
        Version:32,
        (byte_size(DCID)),
        DCID/binary,
        (byte_size(SCID)),
        SCID/binary
    >>,
    Pad = binary:copy(<<0>>, max(0, Size - byte_size(Head))),
    <<Head/binary, Pad/binary>>.

parse_vn(<<First, 0:32, DLen, DCID:DLen/binary, SLen, SCID:SLen/binary, Rest/binary>>) when
    First band 16#80 =:= 16#80
->
    {0, DCID, SCID, [V || <<V:32>> <= Rest]}.
