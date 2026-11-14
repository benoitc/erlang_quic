%%% -*- erlang -*-
%%%
%%% 0-RTT data sent before a Retry goes out again as 0-RTT
%%% (RFC 9000 Section 17.2.5.3), repaired like lost data (Section 13.3).
%%% The replay went through the 1-RTT path, which has no keys before the
%%% handshake: processing the Retry failed and the connection never
%%% completed.

-module(quic_retry_zero_rtt_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(NEW_DCID, <<"retry-cid">>).

%% The replay is a 0-RTT packet to the connection ID from the Retry, under
%% the next packet number of the application space, carrying the data.
replay_goes_out_as_zero_rtt_test() ->
    {Rx, S0} = client_with_early_write(<<"hello">>),
    _FirstSend = recv_datagram(Rx),
    NextPN = quic_connection_test_support:next_app_pn(S0),
    {S1, Early} = quic_connection:reset_initial_pn_space(S0#state{dcid = ?NEW_DCID}),
    ?assertMatch([#sent_packet{}], Early),
    S2 = quic_connection:replay_early_data(Early, S1),
    <<First, ?QUIC_VERSION_1:32, DCIDLen, DCID:DCIDLen/binary, _/binary>> = recv_datagram(Rx),
    ?assertEqual(quic_packet:type_to_bits(zero_rtt, ?QUIC_VERSION_1), (First bsr 4) band 3),
    ?assertEqual(?NEW_DCID, DCID),
    ?assertEqual(NextPN + 1, quic_connection_test_support:next_app_pn(S2)),
    ?assertMatch(
        #{NextPN := #sent_packet{frames = [{stream, 0, 0, <<"hello">>, false}]}},
        quic_loss:sent_packets(app, S2#state.loss_state)
    ).

%% Data of a stream whose send side is done is not sent again.
replay_skips_finished_streams_test() ->
    {Rx, S0} = client_with_early_write(<<"hello">>),
    _FirstSend = recv_datagram(Rx),
    NextPN = quic_connection_test_support:next_app_pn(S0),
    {S1, Early} = quic_connection:reset_initial_pn_space(S0#state{dcid = ?NEW_DCID}),
    #{0 := Stream} = S1#state.streams,
    Done = S1#state{streams = #{0 => Stream#stream_state{send_done = true}}},
    S2 = quic_connection:replay_early_data(Early, Done),
    ?assertEqual(NextPN, quic_connection_test_support:next_app_pn(S2)),
    ?assertEqual({error, timeout}, gen_udp:recv(Rx, 0, 100)).

%% A resumed connection whose 0-RTT request left before the server's Retry
%% completes, and the request is answered.
early_request_answered_after_retry_test_() ->
    {timeout, 60, fun early_request_answered_after_retry/0}.

early_request_answered_after_retry() ->
    {ok, Srv} = quic_test_echo_server:start(#{address_validation => always}),
    try
        #{port := Port} = Srv,
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{
            alpn => [<<"echo">>], server_name => <<"localhost">>
        }),
        {ok, First} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        await_connected(First),
        Ticket =
            receive
                {quic, First, {session_ticket, T}} -> T
            after 5000 -> error(no_session_ticket)
            end,
        quic:close(First, normal),
        %% Without the NEW_TOKEN from the first connection, the server
        %% answers the resumed one with a Retry.
        ok = quic_token_cache:clear(),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts#{session_ticket => Ticket}, self()),
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"early hello">>, true),
        await_connected(Conn),
        receive
            {quic, Conn, {stream_data, StreamId, Data, true}} ->
                ?assertEqual(<<"early hello">>, Data)
        after 5000 -> error(no_echo)
        end,
        ?assert(quic:early_data_accepted(Conn)),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Srv)
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% A client before the handshake, holding 0-RTT keys, that has sent
%% Data on stream 0 as 0-RTT to a socket the test reads.
client_with_early_write(Data) ->
    {ok, Rx} = gen_udp:open(0, [binary, {active, false}]),
    {ok, RxPort} = inet:port(Rx),
    S0 = quic_connection_test_support:zero_rtt_client([0]),
    S1 = S0#state{app_keys = undefined, remote_addr = {{127, 0, 0, 1}, RxPort}},
    {keep_state, S2, _} = quic_connection:zero_rtt_sends([{async, 0, Data, false}], S1),
    {Rx, S2}.

recv_datagram(Rx) ->
    {ok, {_, _, Datagram}} = gen_udp:recv(Rx, 0, 1000),
    Datagram.

await_connected(Conn) ->
    receive
        {quic, Conn, {connected, _}} -> ok
    after 5000 -> error(not_connected)
    end.
