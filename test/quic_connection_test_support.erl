%%% Builds and inspects quic_connection #state{} values for unit tests.
%%% quic_connection is compiled with export_all under TEST, so tests call
%%% its internal functions directly; state builders and accessors go here.
-module(quic_connection_test_support).

-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-export([
    state_with_loss/1,
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
    update_spin_from_recv/3
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
            largest_acked = undefined,
            largest_recv = Largest,
            recv_time = 0,
            ack_ranges = [{0, Largest}],
            ack_eliciting_in_flight = 0,
            loss_time = undefined,
            sent_packets = #{}
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
-spec state_for_reset(binary(), [#cid_entry{}], binary() | undefined) -> #state{}.
state_for_reset(DCID, PeerCIDPool, Secret) ->
    #state{
        role = client,
        dcid = DCID,
        peer_cid_pool = PeerCIDPool,
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
state_get(#state{} = S, pto_scheduled_at) -> S#state.pto_scheduled_at.

state_set(#state{} = S, loss_state, V) -> S#state{loss_state = V};
state_set(#state{} = S, pto_scheduled_at, V) -> S#state{pto_scheduled_at = V}.

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
    PQ = quic_connection:pqueue_in(Entry, 3, quic_connection:empty_pqueue()),
    State = #state{
        send_queue = PQ,
        send_queue_bytes = 0,
        send_queue_count = 1,
        send_queue_version = 1
    },
    #{
        empty_by_count => (State#state.send_queue_count =:= 0),
        empty_by_bytes => (State#state.send_queue_bytes =:= 0),
        queue_empty => quic_connection:pqueue_is_empty(State#state.send_queue)
    }.

coalesce_small_stream(DataSize) ->
    Data = binary:copy(<<0>>, DataSize),
    Entry = {stream_data, 0, 0, Data, false, DataSize},
    PQ = quic_connection:pqueue_in(Entry, 3, quic_connection:empty_pqueue()),
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
        largest_acked = undefined,
        largest_recv = undefined,
        recv_time = undefined,
        ack_ranges = [],
        ack_eliciting_in_flight = 0,
        loss_time = undefined,
        sent_packets = #{}
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
