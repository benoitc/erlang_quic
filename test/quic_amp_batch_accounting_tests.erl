%%% -*- erlang -*-
%%%
%%% Anti-amplification accounting on the batched receive path
%%% (RFC 9000 §8.1).
%%%
%%% A server must not send more than three times the bytes it has
%%% received from an unvalidated address. The credit side of that
%%% budget was only maintained in the single-datagram path
%%% (handle_packet/2); the batched path the listener uses for GRO
%%% trains skipped it entirely. A server whose ClientHello arrived in
%%% a batch kept amp_rx at or near zero, deferred most of its
%%% handshake flight, and the handshake wedged.
%%%
%%% These tests pin the accounting at the handle_packets_batch/2
%%% boundary, which the listener delivery path uses for servers only:
%%% every received datagram must be credited for an unvalidated
%%% server, and must not be for a validated one. The datagrams are
%%% junk the packet parser drops, so the credit is isolated from
%%% packet processing.
%%%
%%% The end-to-end consequence (a lost first server flight) is covered
%%% by quic_server_flight_retransmit_SUITE.

-module(quic_amp_batch_accounting_tests).

-include_lib("eunit/include/eunit.hrl").

datagrams() ->
    %% Sizes chosen unequal so a partial fold shows up in the sum.
    [binary:copy(<<16#ff>>, N) || N <- [100, 321, 47]].

total() ->
    lists:sum([byte_size(D) || D <- datagrams()]).

batch(Role, Validated) ->
    State = quic_connection:test_state_amp(Role, Validated),
    NewState = quic_connection:handle_packets_batch(datagrams(), State),
    quic_connection:test_amp_counters(NewState).

unvalidated_server_credits_every_datagram_test() ->
    Counters = batch(server, false),
    ?assertEqual(total(), maps:get(amp_rx, Counters)).

validated_server_does_not_count_test() ->
    Counters = batch(server, true),
    ?assertEqual(0, maps:get(amp_rx, Counters)).

%% The batch must not send anything on its own: junk datagrams are
%% dropped, and with nothing deferred the flush is a no-op.
batch_does_not_touch_the_spend_side_test() ->
    Counters = batch(server, false),
    ?assertEqual(0, maps:get(amp_tx, Counters)),
    ?assertEqual(0, maps:get(deferred, Counters)).
