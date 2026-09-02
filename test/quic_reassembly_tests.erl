%%% Out-of-order reassembly tests.
%%%
%%% RFC 9000 §2.2 and §13.3 let a peer split or coalesce data it
%%% retransmits differently from the original send, so buffered chunks
%%% can overlap and can repeat data already delivered. The reassembler
%%% must therefore not assume a chunk starts exactly where the next
%%% delivery does.
-module(quic_reassembly_tests).

-include_lib("eunit/include/eunit.hrl").

%% Byte at absolute stream offset N, so assembled output can be checked
%% against the offsets it claims to cover.
chunk(Start, Len) ->
    <<<<(B rem 256)>> || B <- lists:seq(Start, Start + Len - 1)>>.

%% The buffer is an ordered tree; tests build and compare it as a map
%% so the fixtures stay readable.
tree(Map) ->
    gb_trees:from_orddict(lists:sort(maps:to_list(Map))).

extract(Buffer, Offset) ->
    {Data, Off, Rest} = quic_connection:extract_contiguous_data(tree(Buffer), Offset),
    {Data, Off, maps:from_list(gb_trees:to_list(Rest))}.

trim(Buffer, Offset) ->
    maps:from_list(gb_trees:to_list(quic_connection:trim_reassembly_buffer(tree(Buffer), Offset))).

%%====================================================================
%% Extraction
%%====================================================================

exact_chunks_are_joined_test() ->
    Buffer = #{0 => chunk(0, 100), 100 => chunk(100, 100)},
    ?assertEqual({chunk(0, 200), 200, #{}}, extract(Buffer, 0)).

gap_stops_extraction_test() ->
    Buffer = #{0 => chunk(0, 100), 200 => chunk(200, 100)},
    ?assertEqual({chunk(0, 100), 100, #{200 => chunk(200, 100)}}, extract(Buffer, 0)).

%% The regression: the second chunk starts inside the first, so nothing
%% is keyed at the offset extraction reaches. Keying by exact offset
%% left those bytes unreachable and stalled the stream for good.
overlapping_chunks_do_not_stall_test() ->
    Buffer = #{1000 => chunk(1000, 500), 1200 => chunk(1200, 500)},
    ?assertEqual({chunk(1000, 700), 1700, #{}}, extract(Buffer, 1000)).

%% Same shape one level deeper: a re-framed retransmission that overlaps
%% two buffered chunks at once.
overlap_spanning_two_chunks_test() ->
    Buffer = #{
        0 => chunk(0, 100),
        50 => chunk(50, 300),
        200 => chunk(200, 400)
    },
    ?assertEqual({chunk(0, 600), 600, #{}}, extract(Buffer, 0)).

%% A chunk wholly contained in one already buffered adds nothing and
%% must not truncate the delivery.
contained_chunk_is_absorbed_test() ->
    Buffer = #{0 => chunk(0, 500), 100 => chunk(100, 50)},
    ?assertEqual({chunk(0, 500), 500, #{}}, extract(Buffer, 0)).

%% Data below the delivery point was already handed to the owner. It has
%% to be dropped rather than left to accumulate: it was never counted
%% against the receive-buffer cap, so it grew unbounded and unnoticed.
consumed_chunks_are_dropped_test() ->
    Buffer = #{0 => chunk(0, 100), 100 => chunk(100, 100)},
    ?assertEqual({<<>>, 500, #{}}, extract(Buffer, 500)).

duplicate_below_offset_is_dropped_but_gap_kept_test() ->
    Buffer = #{0 => chunk(0, 100), 900 => chunk(900, 10)},
    ?assertEqual({<<>>, 500, #{900 => chunk(900, 10)}}, extract(Buffer, 500)).

empty_buffer_test() ->
    ?assertEqual({<<>>, 42, #{}}, extract(#{}, 42)).

%%====================================================================
%% Trimming
%%====================================================================

trim_drops_consumed_and_rekeys_straddling_test() ->
    Buffer = #{100 => chunk(100, 500), 300 => chunk(300, 100)},
    ?assertEqual(#{400 => chunk(400, 200)}, trim(Buffer, 400)).

%% Two chunks that both trim to the same offset collapse to the longer
%% one, so overlapping retransmissions cannot displace live data.
trim_keeps_the_longer_chunk_test() ->
    Buffer = #{100 => chunk(100, 500), 200 => chunk(200, 600)},
    ?assertEqual(#{300 => chunk(300, 500)}, trim(Buffer, 300)).

trim_is_idempotent_test() ->
    Buffer = #{0 => chunk(0, 100), 50 => chunk(50, 300), 200 => chunk(200, 400)},
    Once = trim(Buffer, 120),
    ?assertEqual(Once, trim(Once, 120)).

trim_leaves_future_chunks_untouched_test() ->
    Buffer = #{800 => chunk(800, 100), 900 => chunk(900, 100)},
    ?assertEqual(Buffer, trim(Buffer, 800)).

%% The walk stops at the delivery point: with a large hole and many
%% chunks buffered above it, a miss at the hole is answered without
%% rebuilding the buffer (the returned tree is the input, unchanged).
gap_below_a_large_buffer_is_answered_without_a_walk_test() ->
    Above = tree(maps:from_list([{Off, chunk(Off, 100)} || Off <- lists:seq(1000, 100000, 100)])),
    ?assertMatch({<<>>, 500, Above}, quic_connection:extract_contiguous_data(Above, 500)).

%% With one straddling chunk below the point, only that chunk is
%% touched; the chunks above come back as they were.
trim_touches_only_chunks_below_the_point_test() ->
    Above = [{Off, chunk(Off, 100)} || Off <- lists:seq(1000, 5000, 100)],
    Buffer = maps:from_list([{300, chunk(300, 400)} | Above]),
    Expected = maps:from_list([{500, chunk(500, 200)} | Above]),
    ?assertEqual(Expected, trim(Buffer, 500)).

%%====================================================================
%% Randomised: any fragmentation of a known stream reassembles to it
%%====================================================================

random_fragmentations_reassemble_test() ->
    Total = 4000,
    Stream = chunk(0, Total),
    lists:foreach(
        fun(Seed) ->
            rand:seed(exsplus, {Seed, Seed * 7 + 1, Seed * 13 + 3}),
            Buffer = lists:foldl(
                fun(_, Acc) ->
                    Off = rand:uniform(Total) - 1,
                    Len = rand:uniform(min(600, Total - Off)),
                    add_chunk(Off, chunk(Off, Len), Acc)
                end,
                #{},
                lists:seq(1, 60)
            ),
            %% Guarantee full coverage so the whole stream is contiguous.
            Full = add_chunk(0, Stream, Buffer),
            ?assertEqual({Seed, {Stream, Total, #{}}}, {Seed, extract(Full, 0)})
        end,
        lists:seq(1, 100)
    ).

%% Mirrors how the connection inserts: keep whichever chunk is longer.
add_chunk(Off, Data, Buffer) ->
    case Buffer of
        #{Off := Existing} when byte_size(Existing) >= byte_size(Data) -> Buffer;
        _ -> Buffer#{Off => Data}
    end.
