%%% -*- erlang -*-
%%%
%%% Tests for Happy Eyeballs (quic_happy): pure address ordering/parsing
%%% and end-to-end racing against an in-process echo server.

-module(quic_happy_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Pure helpers
%%====================================================================

interleave_test() ->
    ?assertEqual([a, c, b, d], quic_happy:interleave([a, b], [c, d])),
    ?assertEqual([a], quic_happy:interleave([a], [])),
    ?assertEqual([c], quic_happy:interleave([], [c])),
    ?assertEqual([a, d, b, c], quic_happy:interleave([a, b, c], [d])),
    ?assertEqual([], quic_happy:interleave([], [])).

parse_host_test() ->
    ?assertEqual({literal, {0, 0, 0, 0, 0, 0, 0, 1}}, quic_happy:parse_host(<<"[::1]">>)),
    ?assertEqual({literal, {0, 0, 0, 0, 0, 0, 0, 1}}, quic_happy:parse_host("::1")),
    ?assertEqual({literal, {127, 0, 0, 1}}, quic_happy:parse_host("127.0.0.1")),
    ?assertEqual({literal, {127, 0, 0, 1}}, quic_happy:parse_host({127, 0, 0, 1})),
    ?assertEqual({name, "example.com"}, quic_happy:parse_host(<<"example.com">>)).

%%====================================================================
%% End-to-end
%%====================================================================

%% happy_eyeballs => false keeps the immediate async return and still
%% connects (IPv4-first single resolve).
he_disabled_async_test_() ->
    {timeout, 30, fun he_disabled_async/0}.

he_disabled_async() ->
    {ok, Srv} = quic_test_echo_server:start(#{}),
    try
        #{port := Port} = Srv,
        Opts = maps:put(happy_eyeballs, false, quic_test_echo_server:client_opts()),
        {ok, Conn} = quic:connect("localhost", Port, Opts, self()),
        try
            ?assert(is_pid(Conn)),
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> ?assert(false)
            end
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

%% An IP-tuple host takes the direct path and connects.
tuple_host_test_() ->
    {timeout, 30, fun tuple_host/0}.

tuple_host() ->
    {ok, Srv} = quic_test_echo_server:start(#{}),
    try
        #{port := Port} = Srv,
        {ok, Conn} = quic:connect(
            {127, 0, 0, 1}, Port, quic_test_echo_server:client_opts(), self()
        ),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> ?assert(false)
            end
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

%% Dual-stack "localhost" races; with the server only on IPv6, the IPv6
%% attempt wins and the connection's peer is the v6 loopback.
he_ipv6_winner_test_() ->
    {timeout, 30, fun he_ipv6_winner/0}.

he_ipv6_winner() ->
    case ipv6_available() of
        false ->
            ok;
        true ->
            {ok, Srv} = quic_test_echo_server:start(#{
                extra_socket_opts => [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]
            }),
            try
                #{port := Port} = Srv,
                {ok, Conn} = quic:connect(
                    "localhost", Port, quic_test_echo_server:client_opts(), self()
                ),
                try
                    receive
                        {quic, Conn, {connected, _}} -> ok
                    after 5000 -> ?assert(false)
                    end,
                    {ok, {PeerIP, _}} = quic:peername(Conn),
                    ?assertEqual(8, tuple_size(PeerIP))
                after
                    catch quic:close(Conn)
                end
            after
                quic_test_echo_server:stop(Srv)
            end
    end.

%% No server: every raced attempt fails, connect returns an error within
%% the (shortened) overall timeout rather than hanging or dialing localhost.
he_all_fail_test_() ->
    {timeout, 30, fun he_all_fail/0}.

he_all_fail() ->
    {ok, _} = application:ensure_all_started(quic),
    DeadPort = 1,
    Opts = #{
        verify => false,
        happy_eyeballs => true,
        connection_attempt_delay => 100,
        connect_timeout => 800
    },
    Result = quic:connect("localhost", DeadPort, Opts, self()),
    ?assertMatch({error, _}, Result).

ipv6_available() ->
    case gen_udp:open(0, [binary, inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}]) of
        {ok, S} ->
            gen_udp:close(S),
            true;
        {error, _} ->
            false
    end.
