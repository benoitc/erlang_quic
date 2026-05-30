%%% -*- erlang -*-
%%%
%%% Tests for client address resolution: no silent localhost fallback,
%%% and IPv6 literal (bracketed) hosts.

-module(quic_resolve_tests).

-include_lib("eunit/include/eunit.hrl").

%% An unresolvable name must fail the connect, not silently dial 127.0.0.1.
resolve_failure_returns_error_test() ->
    {ok, _} = application:ensure_all_started(quic),
    Result = quic:connect(<<"no-such-host.invalid">>, 9, #{verify => false}, self()),
    ?assertMatch({error, _}, Result).

%% A bracketed IPv6 literal resolves and connects to an IPv6 server.
ipv6_literal_brackets_test_() ->
    {timeout, 30, fun ipv6_literal_brackets/0}.

ipv6_literal_brackets() ->
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
                    "[::1]", Port, quic_test_echo_server:client_opts(), self()
                ),
                try
                    receive
                        {quic, Conn, {connected, _}} -> ok
                    after 5000 ->
                        ?assert(false)
                    end
                after
                    catch quic:close(Conn)
                end
            after
                quic_test_echo_server:stop(Srv)
            end
    end.

ipv6_available() ->
    case gen_udp:open(0, [binary, inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}]) of
        {ok, S} ->
            gen_udp:close(S),
            true;
        {error, _} ->
            false
    end.
