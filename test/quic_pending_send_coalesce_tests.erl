%%% -*- erlang -*-
%%%
%%% Writes accepted before the handshake finished share packets when they
%%% go out on entering `connected'. A server that answers 0-RTT requests
%%% before its handshake completes otherwise sends every response in a
%%% packet of its own.

-module(quic_pending_send_coalesce_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAMS, 10).

pending_writes_share_packets_test() ->
    Sids = [4 * N || N <- lists:seq(0, ?STREAMS - 1)],
    S0 = quic_connection_test_support:state_with_send_stream(0, 0, false),
    #stream_state{} = Template = maps:get(0, S0#state.streams),
    S1 = S0#state{
        coalesce = false,
        streams = maps:from_list([{Sid, Template#stream_state{id = Sid}} || Sid <- Sids])
    },
    Before = quic_connection_test_support:state_get(S1, packets_sent),
    S2 = quic_connection:send_pending_data([{Sid, <<"response">>, true} || Sid <- Sids], S1),
    Packets = quic_connection_test_support:state_get(S2, packets_sent) - Before,
    ?assert(Packets > 0),
    ?assert(Packets < ?STREAMS div 2).
