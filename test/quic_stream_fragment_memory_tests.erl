%%% -*- erlang -*-
%%%
%%% Stream fragmentation (RFC 9000 §21.7): out-of-order stream data is
%%% bounded by the memory it takes, not only by its byte count. A peer
%%% sending one byte in every other position would otherwise hold a
%%% reassembly entry many times its size for each byte, and a small
%%% fragment would keep the whole packet it was decoded from.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_stream_fragment_memory_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SID, 0).
-define(MAX_RECV_BUFFER_BYTES, 33554432).

many_one_byte_fragments_stay_within_the_buffer_cap_test_() ->
    {timeout, 120, fun() ->
        S0 = recv_state(1 bsl 30),
        {S, Peak} = one_byte_fragments(S0, 0, ?MAX_RECV_BUFFER_BYTES div 64),
        ?assertMatch(
            {transport, ?QUIC_FLOW_CONTROL_ERROR, _},
            quic_connection_test_support:close_reason(S)
        ),
        ?assert(erts_debug:size(Peak) * erlang:system_info(wordsize) =< ?MAX_RECV_BUFFER_BYTES)
    end}.

a_small_fragment_does_not_keep_its_packet_test() ->
    S0 = recv_state(1 bsl 20),
    Packet = crypto:strong_rand_bytes(1200),
    Fragment = binary:part(Packet, 100, 65),
    S = quic_connection:process_stream_data(?SID, 10, Fragment, false, S0),
    {value, Stored} = gb_trees:lookup(10, recv_buffer(S)),
    ?assertEqual(Fragment, Stored),
    ?assertEqual(65, binary:referenced_byte_size(Stored)).

a_large_fragment_is_kept_as_received_test() ->
    S0 = recv_state(1 bsl 20),
    Packet = crypto:strong_rand_bytes(1200),
    Fragment = binary:part(Packet, 50, 1100),
    S = quic_connection:process_stream_data(?SID, 10, Fragment, false, S0),
    {value, Stored} = gb_trees:lookup(10, recv_buffer(S)),
    ?assertEqual(1200, binary:referenced_byte_size(Stored)).

recv_state(Credit) ->
    quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:recv_stream_state(?SID, 0, Credit, Credit)
    ).

one_byte_fragments(S, N, Max) when N >= Max ->
    {S, recv_buffer(S)};
one_byte_fragments(S0, N, Max) ->
    S = quic_connection:process_stream_data(?SID, 1 + 2 * N, <<N>>, false, S0),
    case quic_connection_test_support:close_reason(S) of
        undefined -> one_byte_fragments(S, N + 1, Max);
        _ -> {S, recv_buffer(S0)}
    end.

recv_buffer(#state{streams = #{?SID := #stream_state{recv_buffer = Buffer}}}) ->
    Buffer.
