%%% -*- erlang -*-
%%%
%%% The reset_stream_at transport parameter is 0x1d
%%% (draft-ietf-quic-reliable-stream-reset-11 Section 3); peers still on
%%% draft -07 use 0x17f7586d2cb571. Both are sent, and either enables the
%%% extension, for the client and the server and for 0-RTT, which uses the
%%% parameters a ticket remembers.

-module(quic_reset_stream_at_tp_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ID, 16#1d).
-define(ID_DRAFT07, 16#17f7586d2cb571).

both_ids_are_sent_test() ->
    Ids = ids(quic_tls:encode_transport_params(#{reset_stream_at => true})),
    ?assertEqual([?ID, ?ID_DRAFT07], lists:sort(Ids)).

neither_id_is_sent_when_disabled_test() ->
    ?assertEqual([], ids(quic_tls:encode_transport_params(#{reset_stream_at => false}))).

id_alone_enables_test() ->
    ?assertEqual({ok, #{reset_stream_at => true}}, decode([{?ID, <<>>}])).

draft07_id_alone_enables_test() ->
    ?assertEqual({ok, #{reset_stream_at => true}}, decode([{?ID_DRAFT07, <<>>}])).

both_ids_enable_test() ->
    ?assertEqual({ok, #{reset_stream_at => true}}, decode([{?ID, <<>>}, {?ID_DRAFT07, <<>>}])),
    ?assertEqual({ok, #{reset_stream_at => true}}, decode([{?ID_DRAFT07, <<>>}, {?ID, <<>>}])).

%% Section 3: a non-empty value is a TRANSPORT_PARAMETER_ERROR, under
%% either id, alone or next to the other.
non_empty_value_is_rejected_test_() ->
    [
        ?_assertMatch({error, _}, decode([{?ID, <<0>>}])),
        ?_assertMatch({error, _}, decode([{?ID_DRAFT07, <<0>>}])),
        ?_assertMatch({error, _}, decode([{?ID, <<>>}, {?ID_DRAFT07, <<0>>}])),
        ?_assertMatch({error, _}, decode([{?ID, <<0>>}, {?ID_DRAFT07, <<>>}]))
    ].

repeated_id_is_rejected_test_() ->
    [
        ?_assertMatch({error, _}, decode([{?ID, <<>>}, {?ID, <<>>}])),
        ?_assertMatch({error, _}, decode([{?ID_DRAFT07, <<>>}, {?ID_DRAFT07, <<>>}]))
    ].

%% Section 3: both endpoints remember it for 0-RTT, whichever id the
%% server sent.
ticket_remembers_either_id_test_() ->
    [
        ?_assertEqual(
            #{reset_stream_at => true},
            remembered(decode([{Id, <<>>} || Id <- Ids]))
        )
     || Ids <- [[?ID], [?ID_DRAFT07], [?ID, ?ID_DRAFT07]]
    ].

remembered({ok, Params}) -> quic_connection:remembered_transport_params(Params);
remembered(Error) -> Error.

%% Our own parameters, read back as a peer reads them.
roundtrip_test() ->
    Encoded = quic_tls:encode_transport_params(#{reset_stream_at => true}),
    ?assertEqual({ok, #{reset_stream_at => true}}, quic_tls:decode_transport_params(Encoded)).

%%====================================================================
%% Helpers
%%====================================================================

decode(Params) ->
    quic_tls:decode_transport_params(
        iolist_to_binary([
            [quic_varint:encode(Id), quic_varint:encode(byte_size(V)), V]
         || {Id, V} <- Params
        ])
    ).

ids(<<>>) ->
    [];
ids(Bin) ->
    {Id, R1} = quic_varint:decode(Bin),
    {Len, R2} = quic_varint:decode(R1),
    <<_:Len/binary, R3/binary>> = R2,
    [Id | ids(R3)].
