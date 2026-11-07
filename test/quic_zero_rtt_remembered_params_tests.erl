%%% -*- erlang -*-
%%%
%%% A client sending 0-RTT data stays within the transport parameters
%%% the server sent on the connection that issued the ticket (RFC 9000
%%% Section 7.4.1). The ticket keeps them; one without them is used
%%% without 0-RTT. A write that would exceed them waits for 1-RTT.

-module(quic_zero_rtt_remembered_params_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

remembers_what_0rtt_may_rely_on_test() ->
    TP = #{
        initial_max_data => 1000,
        initial_max_streams_bidi => 2,
        max_ack_delay => 40,
        initial_scid => <<"server-scid">>,
        stateless_reset_token => binary:copy(<<1>>, 16),
        max_datagram_frame_size => 1200,
        peer_max_stream_data_bidi_remote => 500
    },
    ?assertEqual(
        #{initial_max_data => 1000, initial_max_streams_bidi => 2},
        quic_connection:remembered_transport_params(TP)
    ).

no_early_keys_without_remembered_params_test() ->
    {ok, _} = application:ensure_all_started(quic),
    ?assertNot(early_keys(undefined)),
    ?assert(early_keys(#{initial_max_data => 100000, initial_max_streams_bidi => 4})).

old_ticket_is_used_without_0rtt_test() ->
    {ok, _} = application:ensure_all_started(quic),
    Old = erlang:delete_element(tuple_size(ticket(#{})), ticket(#{})),
    ?assertNot(with_connection(Old, fun quic:has_early_keys/1)).

remembered_limits_bind_0rtt_test() ->
    {ok, _} = application:ensure_all_started(quic),
    Ticket = ticket(#{initial_max_data => 1234, initial_max_streams_bidi => 4}),
    ?assertEqual(
        1234,
        with_connection(Ticket, fun(Conn) ->
            {_, S} = sys:get_state(Conn),
            S#state.max_data_remote
        end)
    ).

write_beyond_the_stream_limit_waits_test() ->
    S0 = with_limits(100, 1000000),
    {keep_state, S, _} = quic_connection:zero_rtt_sends([{async, 0, data(200), false}], S0),
    ?assertEqual([{0, data(200), false}], S#state.pending_data),
    ?assertEqual(
        quic_connection_test_support:next_app_pn(S0), quic_connection_test_support:next_app_pn(S)
    ).

write_beyond_the_connection_limit_waits_test() ->
    S0 = with_limits(1000000, 100),
    {keep_state, S, _} = quic_connection:zero_rtt_sends([{async, 0, data(200), false}], S0),
    ?assertEqual([{0, data(200), false}], S#state.pending_data).

writes_after_a_waiting_one_wait_too_test() ->
    S0 = with_limits(100, 1000000),
    {keep_state, S1, _} = quic_connection:zero_rtt_sends([{async, 0, data(200), false}], S0),
    {keep_state, S2, _} = quic_connection:zero_rtt_sends([{async, 0, data(10), true}], S1),
    ?assertEqual([{0, data(200), false}, {0, data(10), true}], S2#state.pending_data).

write_within_the_limits_goes_as_0rtt_test() ->
    S0 = with_limits(1000, 1000),
    {keep_state, S, _} = quic_connection:zero_rtt_sends([{async, 0, data(200), false}], S0),
    ?assertEqual([], S#state.pending_data),
    ?assertEqual(
        quic_connection_test_support:next_app_pn(S0) + 1,
        quic_connection_test_support:next_app_pn(S)
    ).

data(N) -> binary:copy(<<"x">>, N).

with_limits(StreamMax, ConnMax) ->
    S = quic_connection_test_support:zero_rtt_client([0]),
    #{0 := Stream} = S#state.streams,
    S#state{
        streams = #{0 => Stream#stream_state{send_max_data = StreamMax}},
        max_data_remote = ConnMax
    }.

early_keys(TP) ->
    with_connection(ticket(TP), fun quic:has_early_keys/1).

ticket(TP) ->
    #session_ticket{
        server_name = <<"127.0.0.1">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16#ffffffff,
        received_at = erlang:system_time(second) - 10,
        cipher = aes_128_gcm,
        alpn = <<"h3">>,
        transport_params = TP
    }.

with_connection(Ticket, Fun) ->
    {ok, Silent} = gen_udp:open(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Silent),
    Opts = #{verify => false, alpn => [<<"h3">>], session_ticket => Ticket},
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    try
        Fun(Conn)
    after
        quic:close(Conn, normal),
        gen_udp:close(Silent)
    end.
