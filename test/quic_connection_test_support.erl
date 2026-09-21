%%% Builds and inspects quic_connection #state{} values for unit tests.
%%% quic_connection is compiled with export_all under TEST, so tests call
%%% its internal functions directly; state builders and accessors go here.
-module(quic_connection_test_support).

-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-export([
    state_with_loss/1,
    state_with_loss/2,
    state_get/2,
    state_set/3,
    check_flow_control/6,
    queue_blocked_send/5,
    complete_migration/3,
    app_recv_state/2,
    recv_stream_state/4,
    add_recv_stream/3,
    spin_state/1,
    spin_state_for/2,
    state_with_secret/1,
    state_for_reset/3,
    state_amp/2,
    amp_counters/1,
    state_for_role/1,
    state_for_client/1,
    state_with_keys/1,
    close_reason/1,
    state_for_server/3,
    state_with_pn_app/2,
    recv_summary/2,
    state_closing/2,
    state_with_socket/2,
    state_in_recv_pass/1,
    state_coalescing/2,
    pacing_timer/1,
    pending_delivery/1,
    finish_recv_pass/1,
    coalesce_small_stream/1,
    zero_byte_fin_in_queue/0,
    decimate_initial_state/0,
    decimate_step/1,
    decimate_on_timer_fire/1,
    maybe_send_ack_app/2,
    classify_recv_trigger/2,
    loss_state/1,
    update_spin_from_recv/3,
    state_for_cid_limit/1,
    requeued_offsets/1,
    state_before_initial/2,
    peer_cids/1,
    await_spare_cid/2,
    local_cids/1,
    pending_frames/1,
    ack_counters/1
]).

%% Update the spin-bit tracking state from a received 1-RTT packet.
%% RFC 9000 §17.4 only updates on packets whose PN is greater than any
%% previously received on this path so that reorderings don't flip the
%% edge. Client mirrors the received bit; server inverts it.
%% Kept for the spin-bit unit tests and as the reference the fused
%% record_app_recv/4 is checked against.
update_spin_from_recv(
    FirstByte, PN, #state{spin_recv_largest_pn = Largest, role = Role} = State
) when PN > Largest ->
    RecvSpin = (FirstByte bsr 5) band 1,
    Outgoing =
        case State#state.spin_bit_enabled of
            false -> State#state.spin_outgoing;
            true when Role =:= client -> RecvSpin;
            true when Role =:= server -> 1 - RecvSpin
        end,
    State#state{
        spin_recv = RecvSpin,
        spin_recv_largest_pn = PN,
        spin_outgoing = Outgoing
    };
update_spin_from_recv(_FirstByte, _PN, State) ->
    State.

%% Inspect the spin-bit state of a #state{} from tests without
%% exposing the record definition.
-spec spin_state(#state{}) ->
    #{
        outgoing := 0 | 1,
        recv := 0 | 1,
        largest_pn := integer(),
        enabled := boolean()
    }.
spin_state(#state{
    spin_outgoing = O,
    spin_recv = R,
    spin_recv_largest_pn = L,
    spin_bit_enabled = E
}) ->
    #{outgoing => O, recv => R, largest_pn => L, enabled => E}.

%% Minimal #state{} for spin-bit unit tests.
-spec spin_state_for(client | server, boolean()) -> #state{}.
spin_state_for(Role, Enabled) ->
    #state{role = Role, spin_bit_enabled = Enabled}.

%% #state{} holding one peer-initiated stream at RecvOffset with the
%% given stream and connection receive credit, the caller as owner.
%% For the tests that run the lean stream-data path against the
%% general one.
-spec recv_stream_state(
    non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()
) -> #state{}.
recv_stream_state(StreamId, RecvOffset, StreamCredit, ConnCredit) ->
    Stream = #stream_state{
        id = StreamId,
        state = open,
        send_offset = 0,
        send_max_data = 0,
        send_fin = false,
        send_buffer = [],
        recv_offset = RecvOffset,
        recv_max_data = RecvOffset + StreamCredit,
        recv_fin = false,
        recv_buffer = gb_trees:empty(),
        final_size = undefined
    },
    #state{
        role = server,
        owner = self(),
        streams = #{StreamId => Stream},
        data_received = RecvOffset,
        max_data_local = RecvOffset + ConnCredit,
        fc_max_receive_window = ?DEFAULT_MAX_RECEIVE_WINDOW,
        recv_buffer_bytes = 0
    }.

%% Add another peer-initiated stream at offset 0 to a test state.
-spec add_recv_stream(#state{}, non_neg_integer(), non_neg_integer()) -> #state{}.
add_recv_stream(#state{streams = Streams} = State, StreamId, StreamCredit) ->
    Stream = #stream_state{
        id = StreamId,
        state = open,
        send_offset = 0,
        send_max_data = 0,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = StreamCredit,
        recv_fin = false,
        recv_buffer = gb_trees:empty(),
        final_size = undefined
    },
    State#state{streams = Streams#{StreamId => Stream}}.

%% Give a test state a 1-RTT PN space that has received 0..Largest.
-spec state_with_pn_app(#state{}, non_neg_integer()) -> #state{}.
state_with_pn_app(State, Largest) ->
    State#state{
        pn_app = #pn_space{
            next_pn = 0,
            largest_recv = Largest,
            recv_time = 0,
            ack_ranges = [{0, Largest}],
            ack_eliciting_in_flight = 0
        },
        transport_params = #{max_ack_delay => 25}
    }.

%% The receive-side fields a batch-opened run is expected to move.
-spec recv_summary(#state{}, non_neg_integer()) -> map().
recv_summary(#state{pn_app = PN, streams = Streams} = State, StreamId) ->
    #{
        largest_recv => PN#pn_space.largest_recv,
        ack_ranges => PN#pn_space.ack_ranges,
        recv_offset => (maps:get(StreamId, Streams))#stream_state.recv_offset,
        data_received => State#state.data_received,
        packets_received => State#state.packets_received,
        ack_elicited_count => State#state.ack_elicited_count,
        pend_deliver => State#state.pend_deliver,
        spin_recv_largest_pn => State#state.spin_recv_largest_pn,
        has_non_probing_frame => State#state.has_non_probing_frame
    }.

%% Minimal #state{} with a 1-RTT PN space, for the receive-bookkeeping
%% tests that run record_app_recv/4 against its unfused parts.
-spec app_recv_state(client | server, boolean()) -> #state{}.
app_recv_state(Role, SpinEnabled) ->
    S = decimate_initial_state(),
    S#state{role = Role, spin_bit_enabled = SpinEnabled}.

%% Minimal #state{} for stateless-reset tests.
-spec state_with_secret(binary() | undefined) -> #state{}.
state_with_secret(Secret) ->
    #state{stateless_reset_secret = Secret}.

%% Minimal client #state{} for stateless-reset recognition tests: a current DCID
%% and an explicit peer CID pool.
-spec state_for_reset(binary(), quic_cid:pool(), binary() | undefined) -> #state{}.
state_for_reset(DCID, PeerCIDPool, Secret) ->
    #state{
        role = client,
        dcid = DCID,
        cid_pool_state = PeerCIDPool,
        stateless_reset_secret = Secret
    }.

%% Minimal #state{} for pinning the anti-amplification accounting on the
%% batched receive path. The datagrams fed through it are junk the parser
%% drops, so only the accounting itself is exercised.
-spec state_amp(client | server, boolean()) -> #state{}.
state_amp(Role, Validated) ->
    #state{role = Role, address_validated = Validated}.

-spec amp_counters(#state{}) -> #{atom() => non_neg_integer()}.
amp_counters(#state{amp_rx = Rx, amp_tx = Tx, amp_deferred = Deferred}) ->
    #{amp_rx => Rx, amp_tx => Tx, deferred => length(Deferred)}.

%% Minimal #state{} scoped to role for frame-dispatch tests.
-spec state_for_role(client | server) -> #state{}.
state_for_role(Role) ->
    #state{
        role = Role,
        app_keys = undefined,
        max_streams_bidi_local = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = ?DEFAULT_MAX_STREAMS_UNI
    }.

%% A #state{} holding real Initial and Handshake keys, for the
%% key-discard hooks. The two key pairs are derived the same way; these
%% cases only care whether they are present.
-spec state_with_keys(client | server) -> #state{}.
state_with_keys(Role) ->
    Keys = quic_connection:derive_initial_keys(<<"discard-cid">>, ?QUIC_VERSION_1),
    #state{
        role = Role,
        initial_keys = Keys,
        handshake_keys = Keys,
        app_keys = Keys,
        loss_state = quic_loss:new(),
        cc_state = quic_cc:new(#{})
    }.

-spec state_for_client({inet:ip_address(), inet:port_number()}) -> #state{}.
state_for_client(RemoteAddr) ->
    #state{role = client, app_keys = undefined, remote_addr = RemoteAddr}.

-spec state_for_server(
    {inet:ip_address(), inet:port_number()},
    binary() | undefined,
    binary()
) -> #state{}.
state_for_server(RemoteAddr, Secret, ODCID) ->
    #state{
        role = server,
        app_keys = undefined,
        remote_addr = RemoteAddr,
        stateless_reset_secret = Secret,
        original_dcid = ODCID
    }.

-spec close_reason(#state{}) -> term().
close_reason(#state{close_reason = R}) -> R.

-spec state_closing(#state{}, term()) -> #state{}.
state_closing(State, Reason) -> State#state{close_reason = Reason}.

-spec state_with_socket(#state{}, gen_udp:socket()) -> #state{}.
state_with_socket(State, Socket) -> State#state{socket = Socket}.

%% Minimal #state{} carrying a caller-supplied loss tracker, for tests
%% that need to observe what an incoming frame does to it.
state_get(#state{} = S, pto_timer) -> S#state.pto_timer;
state_get(#state{} = S, pto_scheduled_at) -> S#state.pto_scheduled_at;
state_get(#state{} = S, dcid) -> S#state.dcid;
state_get(#state{} = S, initial_keys) -> S#state.initial_keys;
state_get(#state{} = S, handshake_keys) -> S#state.handshake_keys.

state_set(#state{} = S, loss_state, V) ->
    S#state{loss_state = V};
state_set(#state{} = S, pto_scheduled_at, V) ->
    S#state{pto_scheduled_at = V};
state_set(#state{} = S, peer_active_cid_limit, V) ->
    S#state{cid_pool_state = quic_cid:set_peer_active_limit(S#state.cid_pool_state, V)};
state_set(#state{} = S, dcid, V) ->
    S#state{dcid = V};
state_set(#state{} = S, retry_scid, V) ->
    S#state{retry_scid = V};
state_set(#state{} = S, transport_params, V) ->
    S#state{transport_params = V}.

%% A #state{} carrying a loss tracker, for the space whose timer is
%% under test. The application space is only reachable once the handshake
%% is confirmed (RFC 9002 Section 6.2.1), so asking for `app' confirms it.
-spec state_with_loss(quic_loss:loss_state(), quic_loss:space()) -> #state{}.
state_with_loss(LossState, app) ->
    state_with_loss(quic_loss:on_handshake_confirmed(LossState));
state_with_loss(LossState, _Space) ->
    state_with_loss(LossState).

-spec state_with_loss(quic_loss:loss_state()) -> #state{}.
state_with_loss(LossState) ->
    #state{
        role = client,
        app_keys = undefined,
        loss_state = LossState,
        cc_state = quic_cc:new(#{})
    }.

%% Read the loss tracker back out without exposing the record.
-spec loss_state(#state{}) -> quic_loss:loss_state().
loss_state(#state{loss_state = L}) -> L.

%% Test helper for check_send_queue_flow_control/3.
%% Wraps the internal function to avoid exposing #state{} record.
%% RFC 9000 Section 4.1: Connection-level flow control (max_data)
%% RFC 9000 Section 4.2: Stream-level flow control (max_stream_data)
check_flow_control(StreamId, Offset, DataSize, MaxDataRemote, DataSent, StreamsMap) ->
    Streams = maps:map(
        fun(_K, {SendMaxData, SendOffset}) ->
            #stream_state{send_max_data = SendMaxData, send_offset = SendOffset}
        end,
        StreamsMap
    ),
    State = #state{
        max_data_remote = MaxDataRemote,
        data_sent = DataSent,
        streams = Streams
    },
    quic_connection:check_send_queue_flow_control(StreamId, Offset, DataSize, State).

%% Test helper for queue_blocked_send/6. A send the peer's window has no
%% room for must be queued, not dropped, and the stream offset must
%% advance so later sends order behind it.
%% Returns {ok, NewSendOffset, QueuedCount} | {error, Reason}.
queue_blocked_send(StreamId, Offset, Data, Fin, SendOffset) ->
    Stream = #stream_state{send_offset = SendOffset, send_max_data = 0},
    State = #state{streams = #{StreamId => Stream}},
    case
        quic_connection:queue_blocked_send(StreamId, Offset, Data, Fin, iolist_size(Data), State)
    of
        {ok, S2} ->
            #{StreamId := S} = S2#state.streams,
            {ok, S#stream_state.send_offset, S2#state.send_queue_count};
        Error ->
            Error
    end.

%% Test helper for complete_migration/2.
%% Tests that path_changed notification is sent to owner on active migration.
%% Returns {ok, notified} if notification was sent, {ok, not_notified} for NAT rebinding.
-spec complete_migration(
    Owner :: pid(),
    OldPath :: #path_state{} | undefined,
    NewPath :: #path_state{}
) -> {ok, notified | not_notified}.
complete_migration(Owner, OldPath, NewPath) ->
    %% Create minimal state for testing
    State = #state{
        owner = Owner,
        current_path = OldPath,
        %% Minimal required fields for complete_migration
        pmtu_state = quic_pmtu:new(),
        pmtu_probe_timer = undefined,
        pmtu_raise_timer = undefined,
        alt_paths = []
    },
    %% Call complete_migration - it will send message to Owner if active migration
    _ = quic_connection:complete_migration(NewPath, State),
    %% Check if owner received the notification
    receive
        {quic, _, {path_changed, _, _}} -> {ok, notified}
    after 0 ->
        {ok, not_notified}
    end.

%% Exercise dequeue_small_stream_frame_tuple/1 on a crafted #state{} that
%% has a single small stream frame queued, and return the resulting
%% counters. Used by the regression test for the coalesce-path
%% accounting fix.
-spec coalesce_small_stream(non_neg_integer()) ->
    #{
        dequeued := boolean(),
        send_queue_bytes := non_neg_integer(),
        send_queue_count := non_neg_integer(),
        send_queue_version := non_neg_integer()
    }.
%% Regression helper: simulate an empty FIN-only send (iodata <<>>,
%% Fin=true) that was queued while the connection was pacing/cwnd-blocked.
%% Demonstrates why the fast-path emptiness check must use
%% send_queue_count and not send_queue_bytes: with a FIN-only entry
%% present, send_queue_bytes is 0 but the queue is non-empty.
-spec zero_byte_fin_in_queue() ->
    #{
        empty_by_count := boolean(),
        empty_by_bytes := boolean(),
        queue_empty := boolean()
    }.
zero_byte_fin_in_queue() ->
    Entry = {stream_data, 0, 0, <<>>, true, 0},
    PQ = quic_pqueue:in(Entry, 3, quic_pqueue:new()),
    State = #state{
        send_queue = PQ,
        send_queue_bytes = 0,
        send_queue_count = 1,
        send_queue_version = 1
    },
    #{
        empty_by_count => (State#state.send_queue_count =:= 0),
        empty_by_bytes => (State#state.send_queue_bytes =:= 0),
        queue_empty => quic_pqueue:is_empty(State#state.send_queue)
    }.

coalesce_small_stream(DataSize) ->
    Data = binary:copy(<<0>>, DataSize),
    Entry = {stream_data, 0, 0, Data, false, DataSize},
    PQ = quic_pqueue:in(Entry, 3, quic_pqueue:new()),
    State0 = #state{
        send_queue = PQ,
        send_queue_bytes = DataSize,
        send_queue_count = 1,
        send_queue_version = 1
    },
    case quic_connection:dequeue_small_stream_frame_tuple(State0) of
        {ok, _FrameTuple, #state{
            send_queue_bytes = NewBytes,
            send_queue_count = NewCount,
            send_queue_version = NewVersion
        }} ->
            #{
                dequeued => true,
                send_queue_bytes => NewBytes,
                send_queue_count => NewCount,
                send_queue_version => NewVersion
            };
        none ->
            #{
                dequeued => false,
                send_queue_bytes => DataSize,
                send_queue_count => 1,
                send_queue_version => 1
            }
    end.

%% Initial #state{} for ACK-decimation unit tests. ack_ranges is
%% intentionally empty so send_app_ack/1 short-circuits without a
%% full pn_space + encrypt keys; tests observe the decimation
%% state transitions, not the actual ACK packet on the wire.
-spec decimate_initial_state() -> #state{}.
decimate_initial_state() ->
    PN = #pn_space{
        next_pn = 0,
        largest_recv = undefined,
        recv_time = undefined,
        ack_ranges = [],
        ack_eliciting_in_flight = 0
    },
    #state{
        pn_app = PN,
        transport_params = #{max_ack_delay => 25},
        ack_elicited_count = 0,
        ack_timer = undefined
    }.

%% Run one ack-eliciting-packet step through maybe_decimate_app_ack/1
%% and return the observable decimation fields.
-spec decimate_step(#state{}) ->
    {#state{}, #{
        ack_elicited_count := non_neg_integer(),
        ack_timer_armed := boolean()
    }}.
decimate_step(State) ->
    NewState = quic_connection:maybe_decimate_app_ack(State),
    {NewState, #{
        ack_elicited_count => NewState#state.ack_elicited_count,
        ack_timer_armed => NewState#state.ack_timer =/= undefined
    }}.

%% Mark the state as inside a connected-state receive pass, as the
%% datagram handlers do before processing a train.
-spec state_in_recv_pass(#state{}) -> #state{}.
state_in_recv_pass(State) ->
    State#state{recv_pass = true}.

-spec pacing_timer(#state{}) -> undefined | reference().
pacing_timer(#state{pacing_timer = Ref}) -> Ref.

-spec state_coalescing(#state{}, boolean()) -> #state{}.
state_coalescing(State, On) ->
    State#state{delivery_coalescing = On}.

-spec pending_delivery(#state{}) -> none | {non_neg_integer(), [binary()], boolean()}.
pending_delivery(#state{pend_deliver = P}) -> P.

%% A client state for connection-id tests, holding the peer's initial CID
%% as sequence 0 and accepting Limit of the peer's CIDs.
%%
%% `coalesce' is on so RETIRE_CONNECTION_ID frames accumulate in the
%% pending packet instead of reaching send_app_packet_now/3, which
%% matches `app_keys' in its head and would fail on a state with no
%% keys installed.
-spec state_for_cid_limit(non_neg_integer()) -> #state{}.
state_for_cid_limit(Limit) ->
    DCID = <<"peer-cid">>,
    SCID = <<"own-cid0">>,
    #state{
        role = client,
        app_keys = undefined,
        coalesce = true,
        dcid = DCID,
        scid = SCID,
        %% Both pools carry sequence 0 the way the init paths build them:
        %% the peer's handshake CID and our own. Leaving our pool empty
        %% would let issuance look one CID short of the peer's limit.
        cid_pool_state = quic_cid:set_initial_peer_cid(quic_cid:new(SCID, Limit), DCID, undefined)
    }.

%% With the burst budget spent, hand a remainder at offset 0 to the
%% chunked send step while a later chunk (offset 1000) is already queued
%% on the same stream. Returns the offsets in the order the queue will
%% send them. Where is the requeue position the caller computed: front
%% for a remainder coming off the queue, back for a fresh send.
-spec requeued_offsets(front | back) -> [non_neg_integer()].
requeued_offsets(Where) ->
    S0 = #state{
        streams = #{0 => #stream_state{}},
        burst_budget = 1,
        burst_sent = 1
    },
    {ok, S1} = quic_connection:queue_stream_data(0, 1000, <<0:8000>>, false, S0, back),
    Ctx = {chunked_ctx, 1200, 3, 1200, <<>>, <<>>, Where},
    {S2, 0} = quic_connection:send_stream_chunked_step(0, 0, <<0:8000>>, false, S1, 0, Ctx),
    %% The step arms a zero-delay continuation by messaging this process.
    receive
        {pacing_timeout, _} -> ok
    after 0 -> ok
    end,
    queued_offsets(S2#state.send_queue).

queued_offsets(PQ) ->
    case quic_pqueue:out(PQ) of
        {{value, {stream_data, _Sid, Offset, _Data, _Fin, _Size}}, Rest} ->
            [Offset | queued_offsets(Rest)];
        {empty, _} ->
            []
    end.

%% A state that has not yet seen the peer's Initial: the peer pool is
%% empty, as both init paths leave it. Sequence 0 must come from
%% quic_connection:adopt_peer_scid/2, never from the fixture.
-spec state_before_initial(client | server, non_neg_integer()) -> #state{}.
state_before_initial(Role, Limit) ->
    DCID =
        case Role of
            server -> <<>>;
            client -> <<"orig-dcid">>
        end,
    #state{
        role = Role,
        app_keys = undefined,
        coalesce = true,
        dcid = DCID,
        original_dcid = DCID,
        scid = <<"own-cid0">>,
        cid_pool_state = quic_cid:new(<<"own-cid0">>, Limit)
    }.

%% The peer CIDs we currently hold, newest first.
-spec peer_cids(#state{}) -> [#cid_entry{}].
peer_cids(#state{cid_pool_state = Pool}) -> quic_cid:peer_entries(Pool).

%% Wait until a connection holds a peer CID it can migrate onto.
%%
%% RFC 9000 Section 9.5 forbids reusing a CID on a new path, so
%% `quic:migrate/1' refuses until the peer's NEW_CONNECTION_ID arrives,
%% which is shortly after `connected' rather than before it.
-spec await_spare_cid(pid(), non_neg_integer()) -> boolean().
await_spare_cid(Conn, BudgetMs) ->
    quic_test_wait:until(
        fun() ->
            {_StateName, Data} = sys:get_state(Conn),
            length([E || #cid_entry{status = active} = E <- peer_cids(Data)]) > 1
        end,
        BudgetMs
    ).

%% Frames queued in the pending coalesced packet, in send order.
-spec pending_frames(#state{}) -> [term()].
pending_frames(#state{pend_frames = Frames}) -> lists:reverse(Frames).

%% The CIDs we have issued, including sequence 0.
-spec local_cids(#state{}) -> [#cid_entry{}].
local_cids(#state{cid_pool_state = Pool}) -> quic_cid:local_entries(Pool).

%% ACK bookkeeping, for the functions that take and return #state{}.
%% The timer reference comes back raw so a test can tell "still the same
%% timer" from "armed a second one".
-spec ack_counters(#state{}) ->
    #{
        ack_sent := non_neg_integer(),
        ack_elicited_count := non_neg_integer(),
        ack_timer := undefined | reference()
    }.
ack_counters(#state{ack_sent = Sent, ack_elicited_count = Count, ack_timer = Timer}) ->
    #{ack_sent => Sent, ack_elicited_count => Count, ack_timer => Timer}.

%% Run finish_recv_pass/1 and return the observable decimation fields.
-spec finish_recv_pass(#state{}) ->
    {#state{}, #{
        ack_elicited_count := non_neg_integer(),
        ack_timer_armed := boolean(),
        recv_pass := boolean()
    }}.
finish_recv_pass(State) ->
    NewState = quic_connection:finish_recv_pass(State),
    {NewState, #{
        ack_elicited_count => NewState#state.ack_elicited_count,
        ack_timer_armed => NewState#state.ack_timer =/= undefined,
        recv_pass => NewState#state.recv_pass
    }}.

%% Simulate the delayed-ack timer firing by routing through
%% send_app_ack/1 (which clears the decimation state). Returns the
%% post-fire state fields for assertion.
-spec decimate_on_timer_fire(#state{}) ->
    #{
        ack_elicited_count := non_neg_integer(),
        ack_timer_armed := boolean()
    }.
decimate_on_timer_fire(State) ->
    NewState = quic_connection:send_app_ack(State),
    #{
        ack_elicited_count => NewState#state.ack_elicited_count,
        ack_timer_armed => NewState#state.ack_timer =/= undefined
    }.

%% Run `quic_connection:maybe_send_ack(app, Frames, State)' under a given
%% `last_recv_trigger' and return the observable post-state so tests
%% can assert reordered → immediate ACK, sequential → decimate.
-spec maybe_send_ack_app(sequential | reordered, #state{}) ->
    #{
        ack_elicited_count := non_neg_integer(),
        ack_timer_armed := boolean()
    }.
maybe_send_ack_app(Trigger, State) ->
    Frame = {stream, 0, 0, <<"x">>, false},
    NewState = quic_connection:maybe_send_ack(app, [Frame], State#state{last_recv_trigger = Trigger}),
    #{
        ack_elicited_count => NewState#state.ack_elicited_count,
        ack_timer_armed => NewState#state.ack_timer =/= undefined
    }.

%% Expose `classify_recv_trigger/2' for direct unit coverage of the
%% sequential / reordered classifier without going through the full
%% receive path.
-spec classify_recv_trigger(non_neg_integer(), non_neg_integer() | undefined) ->
    sequential | reordered.
classify_recv_trigger(PN, LargestRecv) ->
    quic_connection:classify_recv_trigger(PN, #pn_space{largest_recv = LargestRecv}).
