%%% -*- erlang -*-
%%%
%%% A server discards an Initial in a datagram under 1200 bytes (RFC 9000
%%% Section 14.1) and answers no such packet with a Version Negotiation
%%% packet (Section 5.2.2), so a small spoofed datagram cannot draw a
%%% larger reply.

-module(quic_small_initial_datagram_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID_LEN, 8).

small_unsupported_version_gets_no_reply_test_() ->
    {timeout, 20, fun() -> ?assertEqual(timeout, reply_to(initial(16#1A2A3A4A, 100))) end}.

full_size_unsupported_version_gets_negotiation_test_() ->
    {timeout, 20, fun() ->
        ?assertMatch({ok, <<_:1, _:7, 0:32, _/binary>>}, reply_to(initial(16#1A2A3A4A, 1200)))
    end}.

small_initial_starts_no_connection_test() ->
    Conns = ets:new(conns, [set]),
    try
        Small = initial(1, 100),
        ?assertEqual(
            #{}, quic_listener:group_packets_by_conn([Small, Small], ?DCID_LEN, Conns, #{})
        )
    after
        ets:delete(Conns)
    end.

initial(Version, Size) ->
    Header = <<16#C0, Version:32, 8, "client-d", 8, "client-s", 0>>,
    PayloadLen = Size - byte_size(Header) - 2,
    <<Header/binary, 1:2, PayloadLen:14, 0:(PayloadLen * 8)>>.

reply_to(Datagram) ->
    {ok, Server} = quic_test_echo_server:start(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Socket, {127, 0, 0, 1}, maps:get(port, Server), Datagram),
        case gen_udp:recv(Socket, 0, 1000) of
            {ok, {_, _, Reply}} -> {ok, Reply};
            {error, timeout} -> timeout
        end
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.
