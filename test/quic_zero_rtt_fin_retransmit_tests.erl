%%% -*- erlang -*-
%%%
%%% Lost 0-RTT STREAM data is retransmitted even when the write carried a
%%% FIN: the send side is done only once that FIN is acknowledged.

-module(quic_zero_rtt_fin_retransmit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

lost_zero_rtt_fin_is_retransmitted_test() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    S1 = S0#state{
        streams = #{0 => #stream_state{id = 0, send_offset = 0}},
        hs = (S0#state.hs)#hs{early_keys = S0#state.app_keys}
    },
    {ok, S2} = quic_connection:do_send_zero_rtt_data(0, <<"hello">>, true, S1),
    Lost = [{stream, 0, 0, <<"hello">>, true}],
    ?assertEqual(Lost, quic_connection:filter_reset_stream_at_data(Lost, S2)).
