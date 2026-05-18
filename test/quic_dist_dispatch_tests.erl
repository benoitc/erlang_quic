%%% -*- erlang -*-
%%% EUnit tests for quic_dist_dispatch — the per-message stream picker.

-module(quic_dist_dispatch_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DATA_STREAMS, [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64]).
-define(CTRL, 0).

%%====================================================================
%% Encoding helpers — build the on-wire forms we want to test against
%%====================================================================

new_pid(Node, Id, Serial, Creation) ->
    NodeBin = small_atom_utf8(Node),
    <<88, NodeBin/binary, Id:32, Serial:32, Creation:32>>.

small_atom_utf8(Name) when is_atom(Name) ->
    Bin = atom_to_binary(Name, utf8),
    <<119, (byte_size(Bin)):8, Bin/binary>>.

%% PASS_THROUGH + version + small_tuple(N) + small_int(Tag) + elems...
plain_dop(Tag, Elems) when is_integer(Tag), Tag =< 255 ->
    Arity = length(Elems) + 1,
    Body = iolist_to_binary([<<97, Tag>> | Elems]),
    <<112, 131, 104, Arity, Body/binary>>.

%% First fragment with NumberOfAtomCacheRefs = 0.
first_frag(SeqId, FragId, Tag, Elems) ->
    Arity = length(Elems) + 1,
    Body = iolist_to_binary([<<97, Tag>> | Elems]),
    <<131, 69, SeqId:64, FragId:64, 0, 104, Arity, Body/binary>>.

cont_frag(SeqId, FragId, Payload) ->
    <<131, 70, SeqId:64, FragId:64, Payload/binary>>.

%%====================================================================
%% classify/1
%%====================================================================

classify_plain_send_sender_test() ->
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    Data = plain_dop(22, [From, To]),
    ?assertMatch({plain, {ok, From, To}}, quic_dist_dispatch:classify(Data)).

classify_plain_reg_send_to_atom_test() ->
    %% REG_SEND = {6, FromPid, Cookie, ToName}
    %% ToName is element 4, NOT element 3 (cookie).
    From = new_pid('a@host', 7, 0, 1),
    Cookie = small_atom_utf8(''),
    ToName = small_atom_utf8(some_registered_name),
    Data = plain_dop(6, [From, Cookie, ToName]),
    {plain, {ok, FromBytes, ToBytes}} = quic_dist_dispatch:classify(Data),
    ?assertEqual(From, FromBytes),
    ?assertEqual(ToName, ToBytes),
    ?assertNotEqual(Cookie, ToBytes).

classify_plain_node_link_test() ->
    %% NODE_LINK = {5} — no principals.
    Data = <<112, 131, 104, 1, 97, 5>>,
    ?assertEqual({plain, no_principals}, quic_dist_dispatch:classify(Data)).

classify_unknown_dop_test() ->
    %% Tag 99 is not in positions/1.
    Data = <<112, 131, 104, 3, 97, 99, 0, 0>>,
    ?assertEqual({plain, unknown_dop}, quic_dist_dispatch:classify(Data)).

classify_not_control_test() ->
    ?assertEqual(not_control, quic_dist_dispatch:classify(<<1, 2, 3>>)),
    ?assertEqual(not_control, quic_dist_dispatch:classify(<<>>)).

classify_dist_header_zero_refs_test() ->
    %% <<131, 68, NumRefs=0, ControlTuple>> — OTP still emits this even
    %% when atom cache is rejected (with empty cache section).
    From = new_pid('a@host', 7, 0, 1),
    Cookie = small_atom_utf8(''),
    ToName = small_atom_utf8(somename),
    %% REG_SEND control tuple (no leading 131 inside dist header).
    Tuple = <<104, 4, 97, 6, From/binary, Cookie/binary, ToName/binary>>,
    Data = <<131, 68, 0, Tuple/binary>>,
    {plain, {ok, FromBytes, ToBytes}} = quic_dist_dispatch:classify(Data),
    ?assertEqual(From, FromBytes),
    ?assertEqual(ToName, ToBytes).

classify_dist_header_with_refs_is_fatal_test() ->
    %% Atom cache section non-empty — must be rejected by the picker.
    Data = <<131, 68, 1, 0, 0, 0>>,
    ?assertEqual({atom_cache_active, 1}, quic_dist_dispatch:classify(Data)),
    {{fatal, Reason}, _} =
        quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertMatch({atom_cache_active, 1}, Reason).

classify_first_fragment_test() ->
    From = new_pid('a@host', 10, 0, 1),
    To = new_pid('b@host', 11, 0, 1),
    SeqId = 123,
    FragId = 3,
    Data = first_frag(SeqId, FragId, 22, [From, To]),
    ?assertEqual(
        {first, SeqId, FragId, {ok, From, To}},
        quic_dist_dispatch:classify(Data)
    ).

classify_cont_fragment_test() ->
    Data = cont_frag(999, 2, <<"payload">>),
    ?assertEqual({cont, 999, 2}, quic_dist_dispatch:classify(Data)).

classify_unlink_id_small_int_id_test() ->
    %% UNLINK_ID = {35, Id, FromPid, ToPid} — Id at elem 2 (small_int).
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    IdBytes = <<97, 42>>,
    Data = plain_dop(35, [IdBytes, From, To]),
    ?assertMatch({plain, {ok, From, To}}, quic_dist_dispatch:classify(Data)).

classify_unlink_id_large_big_id_test() ->
    %% Same DOP but with Id encoded as SMALL_BIG_EXT (110).
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    %% SMALL_BIG_EXT: <<110, N=4, Sign=0, Bytes...>>
    IdBytes = <<110, 4, 0, 16#FF, 16#FF, 16#FF, 16#FF>>,
    Data = plain_dop(35, [IdBytes, From, To]),
    ?assertMatch({plain, {ok, From, To}}, quic_dist_dispatch:classify(Data)).

classify_spawn_request_from_at_elem3_test() ->
    %% SPAWN_REQUEST = {29, ReqId, From, GL, {M,F,A}, Opts}
    %% From at elem 3 (ReqId is elem 2, a reference).
    %% Construct a minimal NEWER_REFERENCE_EXT.
    NodeAtom = small_atom_utf8('a@host'),
    ReqId = <<90, 1:16, NodeAtom/binary, 1:32, 0:32>>,
    From = new_pid('a@host', 3, 0, 1),
    %% We only need to read up to elem 3 (From). Truncated message ok.
    Data = plain_dop(29, [ReqId, From]),
    ?assertMatch({plain, {ok, From, undefined}}, quic_dist_dispatch:classify(Data)).

%%====================================================================
%% pick_stream/4
%%====================================================================

pick_stream_plain_deterministic_test() ->
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    Data = plain_dop(22, [From, To]),
    {{ok, Sid1}, F1} = quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    {{ok, Sid2}, _F2} = quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, F1),
    ?assertEqual(Sid1, Sid2),
    ?assert(lists:member(Sid1, ?DATA_STREAMS)).

pick_stream_node_link_routes_to_first_data_stream_test() ->
    Data = <<112, 131, 104, 1, 97, 5>>,
    {{ok, Sid}, _} = quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertEqual(hd(?DATA_STREAMS), Sid).

pick_stream_unknown_dop_is_fatal_test() ->
    Data = <<112, 131, 104, 3, 97, 99, 0, 0>>,
    {{fatal, Reason}, _} = quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertMatch({unknown_dop, _}, Reason).

pick_stream_empty_data_streams_is_fatal_test() ->
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    Data = plain_dop(22, [From, To]),
    {{fatal, no_data_streams}, _} =
        quic_dist_dispatch:pick_stream(Data, [], ?CTRL, #{}).

pick_stream_not_control_is_fatal_test() ->
    {{fatal, not_control_message}, _} =
        quic_dist_dispatch:pick_stream(<<1, 2, 3>>, ?DATA_STREAMS, ?CTRL, #{}).

%%--------------------------------------------------------------------
%% Fragment routing
%%--------------------------------------------------------------------

pick_stream_first_fragment_records_state_test() ->
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    SeqId = 7777,
    Data = first_frag(SeqId, 3, 22, [From, To]),
    {{ok, Sid}, Frags} =
        quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertMatch(#{SeqId := Sid}, Frags),
    ?assertEqual(1, map_size(Frags)).

pick_stream_continuation_routes_to_same_stream_test() ->
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    SeqId = 7777,
    First = first_frag(SeqId, 3, 22, [From, To]),
    {{ok, Sid}, F1} =
        quic_dist_dispatch:pick_stream(First, ?DATA_STREAMS, ?CTRL, #{}),
    %% Middle continuation
    Cont = cont_frag(SeqId, 2, <<"middle">>),
    {{ok, Sid2}, F2} =
        quic_dist_dispatch:pick_stream(Cont, ?DATA_STREAMS, ?CTRL, F1),
    ?assertEqual(Sid, Sid2),
    ?assertEqual(F1, F2),
    %% Last continuation: FragId = 1 → entry dropped.
    Last = cont_frag(SeqId, 1, <<"last">>),
    {{ok, Sid3}, F3} =
        quic_dist_dispatch:pick_stream(Last, ?DATA_STREAMS, ?CTRL, F2),
    ?assertEqual(Sid, Sid3),
    ?assertNot(maps:is_key(SeqId, F3)).

pick_stream_orphan_continuation_is_fatal_test() ->
    Data = cont_frag(42, 1, <<"orphan">>),
    {{fatal, Reason}, _} =
        quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertMatch({orphan_fragment, 42, 1}, Reason).

pick_stream_single_fragment_message_no_state_test() ->
    %% First fragment with FragId = 1 == single-fragment message.
    From = new_pid('a@host', 1, 0, 1),
    To = new_pid('b@host', 2, 0, 1),
    SeqId = 9,
    Data = first_frag(SeqId, 1, 22, [From, To]),
    {{ok, _Sid}, Frags} =
        quic_dist_dispatch:pick_stream(Data, ?DATA_STREAMS, ?CTRL, #{}),
    ?assertEqual(#{}, Frags).

pick_stream_interleaved_fragments_test() ->
    %% Two independent multi-fragment messages share the connection but
    %% must each route to their own recorded stream.
    A_From = new_pid('a@host', 1, 0, 1),
    A_To = new_pid('b@host', 2, 0, 1),
    B_From = new_pid('a@host', 3, 0, 1),
    B_To = new_pid('b@host', 4, 0, 1),
    SeqA = 100,
    SeqB = 200,
    A1 = first_frag(SeqA, 2, 22, [A_From, A_To]),
    B1 = first_frag(SeqB, 2, 22, [B_From, B_To]),
    {{ok, SidA}, F1} = quic_dist_dispatch:pick_stream(A1, ?DATA_STREAMS, ?CTRL, #{}),
    {{ok, SidB}, F2} = quic_dist_dispatch:pick_stream(B1, ?DATA_STREAMS, ?CTRL, F1),
    %% Last fragment of A — should route to SidA.
    {{ok, SidA2}, F3} =
        quic_dist_dispatch:pick_stream(cont_frag(SeqA, 1, <<>>), ?DATA_STREAMS, ?CTRL, F2),
    ?assertEqual(SidA, SidA2),
    %% Last fragment of B — should route to SidB.
    {{ok, SidB2}, F4} =
        quic_dist_dispatch:pick_stream(cont_frag(SeqB, 1, <<>>), ?DATA_STREAMS, ?CTRL, F3),
    ?assertEqual(SidB, SidB2),
    ?assertEqual(#{}, F4).

%%--------------------------------------------------------------------
%% Spread (statistical sanity)
%%--------------------------------------------------------------------

pick_stream_spreads_across_streams_test() ->
    Pairs = [
        begin
            From = new_pid('n@host', I, 0, 1),
            To = new_pid('m@host', I bsl 1, 0, 1),
            plain_dop(22, [From, To])
        end
     || I <- lists:seq(1, 200)
    ],
    Sids = [
        begin
            {{ok, Sid}, _} = quic_dist_dispatch:pick_stream(D, ?DATA_STREAMS, ?CTRL, #{}),
            Sid
        end
     || D <- Pairs
    ],
    Distinct = sets:size(sets:from_list(Sids)),
    %% 200 random pairs over 16 streams: expect well above half the streams used.
    ?assert(Distinct >= length(?DATA_STREAMS) div 2).
