%%% -*- erlang -*-
%%%
%%% RFC 9297 Section 2.1: a datagram whose Quarter Stream ID does not
%%% decode, or decodes above 2^60-1, is a malformed HTTP/3 datagram and
%%% the receiver MUST treat it as an H3 connection error of type
%%% H3_DATAGRAM_ERROR (0x33). A datagram for a valid but unknown stream
%%% MAY be dropped; the connection stays up.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_datagram_error_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% The malformed shapes RFC 9297 names
%%====================================================================

%% An empty payload has no Quarter Stream ID at all.
empty_payload_is_h3_datagram_error_test() ->
    {action, {next_state, closing, _}} = deliver(<<>>).

%% A varint that claims more bytes than the payload holds.
truncated_varint_is_h3_datagram_error_test() ->
    %% 0x40 continues into a second byte that never arrives.
    {action, {next_state, closing, _}} = deliver(<<16#40>>).

%% A Quarter Stream ID of 2^60 cannot name a stream: the largest stream
%% id is 2^62-4 and the field carries it divided by four. RFC 9297
%% Section 2.1 calls this maliciously large.
quarter_stream_id_two_to_the_sixty_is_h3_datagram_error_test() ->
    QSID = 1 bsl 60,
    {action, {next_state, closing, _}} = deliver(quic_varint:encode(QSID)).

%% One above the limit: 2^60 exactly is already out of range, and so is
%% the largest value a varint can carry.
quarter_stream_id_above_limit_is_h3_datagram_error_test() ->
    {action, {next_state, closing, _}} =
        deliver(quic_varint:encode(1 bsl 60)),
    {action, {next_state, closing, _}} =
        deliver(quic_varint:encode((1 bsl 62) - 1)).

%%====================================================================
%% The boundary and the allowed drop
%%====================================================================

%% 2^60-1 is the largest legal Quarter Stream ID: it decodes, whether
%% or not a stream lives there.
quarter_stream_id_at_limit_decodes_test() ->
    QSID = (1 bsl 60) - 1,
    ?assertMatch(
        {ok, _, _},
        quic_h3_connection:decode_h3_datagram(quic_varint:encode(QSID))
    ).

%% A datagram for a valid but unknown stream is dropped and the
%% connection stays up: Section 2.1 allows dropping it.
unknown_stream_is_dropped_connection_stays_up_test() ->
    State = make_state(#{}),
    {ok, _State1} = quic_h3_connection:deliver_h3_datagram(
        <<0, <<"payload">>/binary>>, State
    ),
    %% The connection is not closing: close_reason is still `normal'
    %% and no error event reached the owner.
    ?assertEqual(normal, close_reason_of(State)).

%% A datagram for a live stream is delivered to the owner as before.
live_stream_is_delivered_test() ->
    State = make_state(#{
        streams => #{0 => #h3_stream{id = 0}}
    }),
    {ok, _} = quic_h3_connection:deliver_h3_datagram(
        <<0, <<"payload">>/binary>>, State
    ),
    receive
        {quic_h3, _, {datagram, 0, <<"payload">>}} -> ok
    after 1000 -> error(delivery_missing)
    end.

%% A malformed datagram closes: the returned action moves to closing
%% with the H3 error recorded. The inline #state{} is addressed
%% positionally, as the compliance suite does: close_reason is the
%% 54th element.
malformed_closes_test() ->
    State = make_state(#{}),
    {action, {next_state, closing, ClosedState}} =
        quic_h3_connection:deliver_h3_datagram(<<>>, State),
    {h3_error, ?H3_DATAGRAM_ERROR, _} = close_reason_of(ClosedState),
    %% The owner hears the error.
    receive
        {quic_h3, _, {error, ?H3_DATAGRAM_ERROR, _}} -> ok
    after 1000 -> error(owner_not_notified)
    end.

%% The inline #state{} is addressed without the record name, the way
%% the compliance suite works positionally. close_reason is element 56
%% in the tuple this builder produces; the builder mirrors the record
%% field order, so if the record grows this position moves with it and
%% the tests say so rather than silently reading the wrong field.
-define(CLOSE_REASON_POS, 56).

close_reason_of(StateTuple) ->
    element(?CLOSE_REASON_POS, StateTuple).

%%====================================================================
%% Fixtures
%%====================================================================

deliver(Data) ->
    State = make_state(#{}),
    quic_h3_connection:deliver_h3_datagram(Data, State).
%% The same shape make_test_state builds in quic_h3_compliance_tests:
%% every field of #state{} in record order.
make_state(Overrides) ->
    Default = #{
        quic_conn => self(),
        quic_ref => undefined,
        role => client,
        owner => self(),
        owner_monitor => undefined,
        local_control_stream => undefined,
        local_encoder_stream => undefined,
        local_decoder_stream => undefined,
        peer_control_stream => undefined,
        peer_encoder_stream => undefined,
        peer_decoder_stream => undefined,
        qpack_encoder => quic_qpack:new(),
        qpack_decoder => quic_qpack:new(),
        local_settings => #{},
        peer_settings => undefined,
        settings_sent => false,
        settings_received => false,
        goaway_id => undefined,
        last_stream_id => 0,
        streams => #{},
        pending_response_headers => #{},
        next_stream_id => 0,
        stream_buffers => #{},
        uni_stream_buffers => #{},
        discarded_uni_streams => sets:new([{version, 2}]),
        encoder_buffer => <<>>,
        decoder_buffer => <<>>,
        blocked_streams => #{},
        peer_max_field_section_size => 65536,
        peer_max_blocked_streams => 0,
        peer_connect_enabled => false,
        local_max_field_section_size => 65536,
        local_max_blocked_streams => 0,
        local_connect_enabled => false,
        max_push_id => undefined,
        next_push_id => 0,
        push_streams => #{},
        local_max_push_id => undefined,
        promised_pushes => #{},
        received_pushes => #{},
        local_cancelled_pushes => sets:new([{version, 2}]),
        last_accepted_push_id => undefined,
        stream_handlers => #{},
        stream_data_buffers => #{},
        buffered_bytes => 0,
        max_buffered_body => ?H3_MAX_BUFFERED_BODY,
        stream_type_handler => undefined,
        claimed_uni_streams => #{},
        h3_datagram_enabled => true,
        peer_h3_datagram_enabled => true,
        bidi_type_buffers => #{},
        claimed_bidi_streams => #{},
        has_early_keys => false,
        quic_connected => true,
        close_reason => normal,
        send_blocked => #{},
        peer_goaway_id => undefined,
        defer_requests => false,
        deferred_requests => [],
        held_streams => #{},
        held_data => [],
        held_bytes => 0,
        reset_final_size => false,
        notify_streams => false,
        streams_wanted => [],
        no_content_ended => {sets:new([{version, 2}]), queue:new()},
        answered_unread => #{}
    },
    Merged = maps:merge(Default, Overrides),
    %% Build the state tuple in the same order as the record definition
    %% (mirrors make_test_state in quic_h3_compliance_tests; the two
    %% builders must agree field for field).
    {state, maps:get(quic_conn, Merged), maps:get(quic_ref, Merged), maps:get(role, Merged),
        maps:get(owner, Merged), maps:get(owner_monitor, Merged),
        maps:get(local_control_stream, Merged), maps:get(local_encoder_stream, Merged),
        maps:get(local_decoder_stream, Merged), maps:get(peer_control_stream, Merged),
        maps:get(peer_encoder_stream, Merged), maps:get(peer_decoder_stream, Merged),
        maps:get(qpack_encoder, Merged), maps:get(qpack_decoder, Merged),
        maps:get(local_settings, Merged), maps:get(peer_settings, Merged),
        maps:get(settings_sent, Merged), maps:get(settings_received, Merged),
        maps:get(goaway_id, Merged), maps:get(last_stream_id, Merged), maps:get(streams, Merged),
        maps:get(next_stream_id, Merged), maps:get(stream_buffers, Merged),
        maps:get(uni_stream_buffers, Merged), maps:get(discarded_uni_streams, Merged),
        maps:get(encoder_buffer, Merged), maps:get(decoder_buffer, Merged),
        maps:get(blocked_streams, Merged), maps:get(peer_max_field_section_size, Merged),
        maps:get(peer_max_blocked_streams, Merged), maps:get(peer_connect_enabled, Merged),
        maps:get(local_max_field_section_size, Merged), maps:get(local_max_blocked_streams, Merged),
        %% Push fields
        maps:get(max_push_id, Merged), maps:get(next_push_id, Merged),
        maps:get(push_streams, Merged), maps:get(local_max_push_id, Merged),
        maps:get(promised_pushes, Merged), maps:get(received_pushes, Merged),
        maps:get(local_cancelled_pushes, Merged), maps:get(last_accepted_push_id, Merged),
        %% Per-stream handler registration
        maps:get(stream_handlers, Merged), maps:get(stream_data_buffers, Merged),
        maps:get(buffered_bytes, Merged), maps:get(max_buffered_body, Merged),
        maps:get(local_connect_enabled, Merged), maps:get(stream_type_handler, Merged),
        maps:get(claimed_uni_streams, Merged), maps:get(h3_datagram_enabled, Merged),
        maps:get(peer_h3_datagram_enabled, Merged), maps:get(bidi_type_buffers, Merged),
        maps:get(claimed_bidi_streams, Merged), maps:get(pending_response_headers, Merged),
        %% 0-RTT bootstrap fields
        maps:get(has_early_keys, Merged), maps:get(quic_connected, Merged),
        maps:get(close_reason, Merged), maps:get(send_blocked, Merged),
        maps:get(peer_goaway_id, Merged), maps:get(defer_requests, Merged),
        maps:get(deferred_requests, Merged), maps:get(held_streams, Merged),
        maps:get(held_data, Merged), maps:get(held_bytes, Merged),
        maps:get(reset_final_size, Merged), maps:get(notify_streams, Merged),
        maps:get(streams_wanted, Merged), maps:get(no_content_ended, Merged),
        maps:get(answered_unread, Merged)}.
