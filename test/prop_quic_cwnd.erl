%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 7: bytes in flight exceed the congestion window only
%%% through a PTO probe (Section 7.5) or the one packet sent on entering
%%% recovery (Section 7.3.2). Random sequences of control frames, stream
%%% writes, acknowledgements, losses and PTOs run against a connection;
%%% after any step other than a PTO that sent a packet, in-flight bytes
%%% are within the window, or the step entered recovery and sent that one
%%% packet only.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(prop_quic_cwnd).

-include_lib("proper/include/proper.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(WINDOW, 8 * 1200).

prop_in_flight_exceeds_cwnd_only_by_probes_and_the_recovery_packet() ->
    ?FORALL(
        Ops,
        list(op()),
        begin
            {Ok, #state{socket = Socket}} = lists:foldl(fun step/2, {true, initial()}, Ops),
            gen_udp:close(Socket),
            Ok
        end
    ).

op() ->
    frequency([
        {4, {control, control_frame()}},
        {4, {stream, range(1, 6000)}},
        {1, keep_alive},
        {4, {ack, range(0, 100), range(0, 100)}},
        {1, pto}
    ]).

control_frame() ->
    oneof([
        ping,
        {retire_connection_id, range(0, 3)},
        ?LET(Len, range(1, 900), {new_token, binary(Len)}),
        {streams_blocked, bidi, range(0, 100)}
    ]).

step(_Op, {false, S}) ->
    {false, S};
step(Op, {true, S0}) ->
    S1 = run(Op, S0),
    {holds(Op, S0, S1), S1}.

run({control, Frame}, S) ->
    quic_connection:send_frame(Frame, S);
run({stream, Size}, S) ->
    {ok, S1} = quic_connection:do_send_data(0, binary:copy(<<"s">>, Size), false, S, force),
    S1;
run(keep_alive, S) ->
    quic_connection:send_keep_alive_ping(S);
run({ack, A, B}, #state{pn_app = #pn_space{next_pn = 0}} = S) ->
    _ = {A, B},
    S;
run({ack, A, B}, #state{pn_app = #pn_space{next_pn = Next}} = S) ->
    %% A block of packet numbers; the packets below it that are still
    %% unacknowledged become lost by the packet threshold.
    Lo = (min(A, B) * (Next - 1)) div 100,
    Hi = (max(A, B) * (Next - 1)) div 100,
    quic_connection:process_frame(app, {ack, [{Hi, Hi - Lo}], 0, undefined}, S);
run(pto, S) ->
    quic_connection:handle_pto_timeout(S#state{pto_space = app}).

holds(pto, _Before, _After) ->
    true;
holds(_Op, #state{pn_app = #pn_space{next_pn = N}}, #state{pn_app = #pn_space{next_pn = N}}) ->
    true;
holds(_Op, #state{cc_state = CC0} = Before, #state{cc_state = CC} = After) ->
    InFlight = quic_cc:bytes_in_flight(CC),
    Cwnd = quic_cc:cwnd(CC),
    Recovery = recovery_packet(CC0) orelse (Cwnd < quic_cc:cwnd(CC0)),
    %% The recovery packet is the step's first; nothing may follow it.
    case InFlight =< Cwnd of
        true ->
            true;
        false when Recovery ->
            next_pn(After) - next_pn(Before) =:= 1;
        false ->
            false
    end.

next_pn(#state{pn_app = #pn_space{next_pn = N}}) -> N.

%% The wrapper's Section 7.3.2 flag, read for the check.
recovery_packet(CC) ->
    element(4, CC).

initial() ->
    S = quic_connection_test_support:state_for_admission(0, 0, 100000000, 100000000),
    S#state{
        loss_state = quic_loss:on_handshake_confirmed(quic_loss:new()),
        cc_state = quic_cc:new(#{algorithm => newreno, initial_window => ?WINDOW}),
        owner = self(),
        transport_params = #{},
        max_data_local = 1000000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        last_activity = erlang:monotonic_time(millisecond)
    }.
