%%% -*- erlang -*-
%%%
%%% A client that has Handshake keys probes with a Handshake packet,
%%% even while its own Initial packets are unacknowledged (RFC 9002
%%% Section 6.2.2.1).
%%%
%%% If the server's Handshake flight is lost after its ServerHello got
%%% through, an Initial probe does not help a server that will not
%%% acknowledge it: haproxy answers with Initial PINGs only, so the
%%% client's Initial probes stay in flight, every PTO picks the Initial
%%% space again, and the handshake never completes. A Handshake packet
%%% validates the client's address and makes the server resend its
%%% flight.

-module(quic_client_handshake_probe_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

probes_with_a_handshake_packet_test() ->
    S = quic_connection:handle_pto_timeout(initial_probe_due(client_with_keys())),
    ?assertEqual(1, handshake_next_pn(S)),
    ?assertEqual(undefined, (S#state.hs)#hs.initial_keys).

probes_with_an_initial_packet_without_handshake_keys_test() ->
    #state{hs = HS} = S0 = client_with_keys(),
    S = quic_connection:handle_pto_timeout(
        initial_probe_due(S0#state{hs = HS#hs{handshake_keys = undefined}})
    ),
    ?assertEqual(0, handshake_next_pn(S)),
    ?assertEqual(2, ((S#state.hs)#hs.pn_initial)#pn_space.next_pn).

client_with_keys() ->
    quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ).

initial_probe_due(#state{hs = HS, loss_state = LossState} = S0) ->
    Sent = erlang:monotonic_time(millisecond) - 5000,
    S = quic_connection:set_pto_timer(S0#state{
        coalesce = false,
        loss_state = quic_loss:on_packet_sent(initial, LossState, 0, 1200, true, [ping], Sent),
        hs = HS#hs{
            pn_initial = #pn_space{
                next_pn = 1,
                largest_recv = undefined,
                recv_time = undefined,
                ack_ranges = [],
                ack_eliciting_in_flight = 1
            }
        }
    }),
    initial = S#state.pto_space,
    S.

handshake_next_pn(#state{hs = #hs{pn_handshake = #pn_space{next_pn = PN}}}) ->
    PN.
