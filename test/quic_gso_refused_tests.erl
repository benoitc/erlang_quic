%%% -*- erlang -*-
%%%
%%% A socket can take the UDP_SEGMENT option and still have the kernel
%%% refuse every segmented send: Linux answers EIO when the route's
%%% device cannot checksum for GSO. The packets then go out one by one,
%%% and the socket stops trying.
%%%
%%% The refusal here is the one a test can get without touching the
%%% host's network setup: a run of more segments than the kernel takes
%%% in one send (EINVAL).

-module(quic_gso_refused_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LOCALHOST, {127, 0, 0, 1}).
-define(TOO_MANY, 300).

gso_refused_test_() ->
    case os:type() of
        {unix, linux} ->
            [
                fun refused_run_is_sent_packet_by_packet/0,
                fun runs_after_a_refusal_skip_the_attempt/0,
                fun refusal_turns_gso_off/0
            ];
        _ ->
            []
    end.

refused_run_is_sent_packet_by_packet() ->
    Packets = [packet(N, 100) || N <- lists:seq(1, ?TOO_MANY)],
    {Result, Received} = send_runs([{gso, 100, Packets}]),
    ?assertMatch({gso_refused, _}, Result),
    ?assertEqual(Packets, Received).

runs_after_a_refusal_skip_the_attempt() ->
    Refused = [packet(N, 100) || N <- lists:seq(1, ?TOO_MANY)],
    After = [packet(N, 1200) || N <- [1, 2, 3]],
    {Result, Received} = send_runs([{gso, 100, Refused}, {gso, 1200, After}]),
    ?assertMatch({gso_refused, _}, Result),
    ?assertEqual(Refused ++ After, Received).

refusal_turns_gso_off() ->
    {ok, S0} = quic_socket:open_for_send(?LOCALHOST, #{backend => socket, gso => true}),
    try
        ?assert(quic_socket:gso_supported(S0)),
        S1 = quic_socket:gso_refused(eio, S0),
        ?assertNot(quic_socket:gso_supported(S1))
    after
        quic_socket:close(S0)
    end.

send_runs(Runs) ->
    {ok, Recv} = gen_udp:open(0, [binary, {active, false}, {ip, ?LOCALHOST}, {recbuf, 1 bsl 20}]),
    {ok, Port} = inet:port(Recv),
    {ok, S} = socket:open(inet, dgram, udp),
    try
        Dest = #{family => inet, addr => ?LOCALHOST, port => Port},
        Result = quic_socket:send_runs(S, Dest, Runs),
        {Result, recv_all(Recv)}
    after
        socket:close(S),
        gen_udp:close(Recv)
    end.

recv_all(Recv) ->
    case gen_udp:recv(Recv, 0, 200) of
        {ok, {_, _, Data}} -> [Data | recv_all(Recv)];
        {error, timeout} -> []
    end.

packet(N, Size) ->
    <<N:16, (binary:copy(<<0>>, Size - 2))/binary>>.
