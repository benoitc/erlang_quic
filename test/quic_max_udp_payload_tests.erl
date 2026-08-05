%%% -*- erlang -*-
%%%
%%% The advertised `max_udp_payload_size' transport parameter (RFC 9000
%%% §18.2) is the largest UDP payload an endpoint is willing to receive. It
%%% used to be the PMTU probing ceiling (1500 by default), which is a send
%%% limit and one that does not fit a 1500-byte path once IP and UDP headers
%%% are counted, and the `max_udp_payload_size' option never reached it.

-module(quic_max_udp_payload_tests).

-include_lib("eunit/include/eunit.hrl").

%% 1500-byte IPv4 path: 1500 - 20 (IP) - 8 (UDP).
-define(IPV4_DEFAULT, 1472).

default_is_receivable_over_ipv4_test_() ->
    {timeout, 30, fun default_is_receivable_over_ipv4/0}.

default_is_receivable_over_ipv4() ->
    with_connection(#{}, #{}, fun(PeerTPs, OwnTPs) ->
        ?assertEqual(?IPV4_DEFAULT, maps:get(max_udp_payload_size, PeerTPs)),
        ?assertEqual(?IPV4_DEFAULT, maps:get(max_udp_payload_size, OwnTPs))
    end).

configured_size_is_advertised_test_() ->
    {timeout, 30, fun configured_size_is_advertised/0}.

configured_size_is_advertised() ->
    ServerOpts = #{max_udp_payload_size => 1300},
    ClientOpts = #{max_udp_payload_size => 1250},
    with_connection(ServerOpts, ClientOpts, fun(PeerTPs, OwnTPs) ->
        ?assertEqual(1300, maps:get(max_udp_payload_size, PeerTPs)),
        ?assertEqual(1250, maps:get(max_udp_payload_size, OwnTPs))
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% Connect over IPv4 and hand the callback the server's transport
%% parameters (as the client sees them) and the client's own (as the server
%% sees them).
with_connection(ServerOpts, ClientOpts, Fun) ->
    {ok, Srv} = quic_test_echo_server:start(ServerOpts),
    try
        #{name := Name, port := Port} = Srv,
        Opts = maps:merge(quic_test_echo_server:client_opts(), ClientOpts),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, Opts, self()),
        try
            PeerTPs =
                receive
                    {quic, Conn, {connected, Info}} -> maps:get(transport_params, Info)
                after 5000 -> error(not_connected)
                end,
            Fun(PeerTPs, client_params_seen_by_server(Name))
        after
            quic:safe_close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

client_params_seen_by_server(Name) ->
    {ok, [ServerConn | _]} = quic:get_server_connections(Name),
    {ok, TPs} = quic:get_peer_transport_params(ServerConn),
    TPs.
