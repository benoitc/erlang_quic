%%% -*- erlang -*-
%%%
%%% RFC 9001 Section 4.9.3: after receiving a 1-RTT packet, a server
%%% MUST discard its 0-RTT keys within a short time; three PTOs is the
%%% recommended period. Packet reordering can deliver a 0-RTT packet
%%% after a 1-RTT one, so the keys stay usable through the window and
%%% go when it closes.
%%%
%%% The trigger is the first successfully processed 1-RTT packet - the
%%% receive event the section names - not handshake completion, which
%%% can precede any 1-RTT packet.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_server_0rtt_discard_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

early_keys(Server) ->
    {_, #state{hs = #hs{early_keys = EK}}} = sys:get_state(Server),
    EK.

%%====================================================================
%% E2E: the server-side disposal window
%%====================================================================

%% A 0-RTT connection that completes its handshake, then sends an
%% explicit 1-RTT packet (the trigger): the keys survive the handshake,
%% the window arms on the 1-RTT packet, and the keys are gone after
%% three PTOs. Fails on main, where the keys live for the connection.
server_discards_early_keys_after_first_1rtt_test() ->
    {timeout, 60, fun server_discards_early_keys_after_first_1rtt/0}.

server_discards_early_keys_after_first_1rtt() ->
    {ok, #{name := Name, port := Port} = Srv} = quic_test_echo_server:start(),
    try
        Opts = quic_test_echo_server:client_opts(),
        {ok, First} = quic:connect("127.0.0.1", Port, Opts, self()),
        Ticket = wait_ticket(First),
        quic:close(First, normal),
        ?assert(
            quic_test_wait:until(
                fun() -> quic:get_server_connections(Name) =:= {ok, []} end, 5000
            )
        ),

        {ok, Conn} = quic:connect(
            "127.0.0.1", Port, Opts#{session_ticket => Ticket}, self()
        ),
        {ok, StreamId} = quic:open_stream(Conn),
        Early = <<"zero rtt payload">>,
        ok = quic:send_data(Conn, StreamId, Early, true),
        wait_connected(Conn),
        ?assertEqual(true, quic:early_data_accepted(Conn)),

        {ok, [Server]} = quic:get_server_connections(Name),
        ?assertMatch({_, _}, early_keys(Server)),

        %% The explicit trigger: a 1-RTT packet from the client.
        ok = quic:send_ping(Conn),

        %% The window arms once the ping is processed: wait for the
        %% deadline to appear, then read it.
        ?assert(
            quic_test_wait:until(
                fun() ->
                    {_, #state{early_keys_discard_deadline = D}} = sys:get_state(Server),
                    is_integer(D)
                end,
                5000
            )
        ),
        {_, #state{early_keys_discard_deadline = Deadline}} = sys:get_state(Server),
        Margin = 3000,
        Wait = min(30_000, Deadline - erlang:monotonic_time(millisecond) + Margin),
        ?assert(quic_test_wait:until(fun() -> early_keys(Server) =:= undefined end, Wait)),

        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Srv)
    end.

wait_connected(Conn) ->
    receive
        {quic, Conn, {connected, _}} -> ok
    after 5000 -> error(connect_timeout)
    end.

wait_ticket(Conn) ->
    receive
        {quic, Conn, {session_ticket, Ticket}} -> Ticket
    after 5000 -> error(no_ticket)
    end.

%%====================================================================
%% Unit: the arming hook and the timer handler
%%====================================================================

%% The hook arms only for a server holding 0-RTT keys, once.
unit_arms_once_at_3pto_test() ->
    S0 = server_with_early_keys(),
    ?assertMatch({_, _}, (S0#state.hs)#hs.early_keys),
    S1 = quic_connection:server_schedule_0rtt_discard(app, S0),
    ?assert(is_reference(S1#state.early_keys_discard_timer)),
    ?assert(is_integer(S1#state.early_keys_discard_deadline)),
    Now = erlang:monotonic_time(millisecond),
    Expected = Now + 3 * quic_loss:get_pto(S0#state.loss_state, app),
    ?assert(S1#state.early_keys_discard_deadline - Expected < 50),
    %% A second app packet does not re-arm or move the deadline.
    S2 = quic_connection:server_schedule_0rtt_discard(app, S1),
    ?assertEqual(S1#state.early_keys_discard_timer, S2#state.early_keys_discard_timer),
    ?assertEqual(S1#state.early_keys_discard_deadline, S2#state.early_keys_discard_deadline).

%% The batched receive path arms the same window: nothing for a run
%% that opened no packet, the deadline on the first run that did, and
%% the same deadline after later runs.
unit_batched_receive_arms_once_test() ->
    S0 = server_with_early_keys(),
    S1 = quic_connection:opened_run([], S0),
    ?assertEqual(undefined, S1#state.early_keys_discard_deadline),
    S2 = quic_connection:opened_run([{0, 16#40, [ping]}], S1),
    ?assert(is_reference(S2#state.early_keys_discard_timer)),
    ?assert(is_integer(S2#state.early_keys_discard_deadline)),
    S3 = quic_connection:opened_run([{1, 16#40, [ping]}, {2, 16#40, [ping]}], S2),
    ?assertEqual(S2#state.early_keys_discard_timer, S3#state.early_keys_discard_timer),
    ?assertEqual(S2#state.early_keys_discard_deadline, S3#state.early_keys_discard_deadline).

%% Other packet types and roles arm nothing.
unit_arms_only_for_server_app_test() ->
    S0 = server_with_early_keys(),
    ?assertEqual(
        S0#state.early_keys_discard_timer,
        (quic_connection:server_schedule_0rtt_discard(handshake, S0))#state.early_keys_discard_timer
    ),
    ?assertEqual(
        S0#state.early_keys_discard_timer,
        (quic_connection:server_schedule_0rtt_discard(app, S0#state{
            cfg = #conn_cfg{role = client}
        }))#state.early_keys_discard_timer
    ),
    NoKeys = S0#state{hs = (S0#state.hs)#hs{early_keys = undefined}},
    ?assertEqual(
        NoKeys#state.early_keys_discard_timer,
        (quic_connection:server_schedule_0rtt_discard(app, NoKeys))#state.early_keys_discard_timer
    ).

%% The handler drops the keys and both fields when the deadline passed.
unit_handler_discards_at_deadline_test() ->
    S0 = server_with_early_keys(),
    S1 = quic_connection:server_schedule_0rtt_discard(app, S0),
    %% Simulate a fire at the deadline: rewind it so Now >= Deadline.
    Past = S1#state{early_keys_discard_deadline = erlang:monotonic_time(millisecond) - 1},
    Ref = Past#state.early_keys_discard_timer,
    {keep_state, S2} = quic_connection:handle_common_event(
        info, {timeout, Ref, early_keys_discard_timeout}, connected, Past
    ),
    ?assertEqual(undefined, (S2#state.hs)#hs.early_keys),
    ?assertEqual(undefined, S2#state.early_keys_discard_timer),
    ?assertEqual(undefined, S2#state.early_keys_discard_deadline).

%% A message delivered before the deadline re-arms for the remainder and
%% keeps the deadline (an early delivery must not be lost).
unit_handler_rearms_on_early_delivery_test() ->
    S0 = server_with_early_keys(),
    S1 = quic_connection:server_schedule_0rtt_discard(app, S0),
    Ref = S1#state.early_keys_discard_timer,
    Far = S1#state{early_keys_discard_deadline = erlang:monotonic_time(millisecond) + 60_000},
    {keep_state, S2} = quic_connection:handle_common_event(
        info, {timeout, Ref, early_keys_discard_timeout}, connected, Far
    ),
    ?assertMatch({_, _}, (S2#state.hs)#hs.early_keys),
    ?assert(is_reference(S2#state.early_keys_discard_timer)),
    ?assertNotEqual(Ref, S2#state.early_keys_discard_timer),
    ?assertEqual(Far#state.early_keys_discard_deadline, S2#state.early_keys_discard_deadline).

%% A stale reference is ignored in every state.
unit_handler_ignores_stale_ref_test() ->
    S0 = server_with_early_keys(),
    S1 = quic_connection:server_schedule_0rtt_discard(app, S0),
    {keep_state, S2} = quic_connection:handle_common_event(
        info,
        {timeout, make_ref(), early_keys_discard_timeout},
        connected,
        S1
    ),
    ?assertEqual(S1#state.early_keys_discard_timer, S2#state.early_keys_discard_timer),
    ?assertEqual(S1#state.early_keys_discard_deadline, S2#state.early_keys_discard_deadline),
    ?assertMatch({_, _}, (S2#state.hs)#hs.early_keys).

%% Accept path: the decoder still opens a 0-RTT packet inside the
%% window. Reject path: {error, no_early_keys} once the keys are gone.
unit_decode_before_and_after_expiry_test() ->
    S0 = server_with_early_keys(),
    {EarlyKeys, _} = (S0#state.hs)#hs.early_keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = EarlyKeys,
    PN = 3,
    Payload = pad_payload(quic_frame:encode(ping)),
    %% PN length from the packet number itself, as the send path does
    %% (quic_packet:pn_length/1), so the first byte's encoding matches.
    PNLen = quic_packet:pn_length(PN),
    PayloadLen = iolist_size(Payload) + 16,
    Length = quic_varint:encode(PNLen + PayloadLen),
    #state{dcid = DCID, cfg = #conn_cfg{scid = SCID}, version = Version} = S0,
    FirstByte0 = 16#C0 bor (PNLen - 1),
    Header =
        <<FirstByte0, Version:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary,
            Length/binary>>,
    Packet = quic_aead:protect_long_packet(Cipher, Key, IV, HP, PN, Header, Payload),
    <<FirstByte, Version:32, DCIDLen, DCID:DCIDLen/binary, SCIDLen, SCID:SCIDLen/binary,
        Rest/binary>> = Packet,
    {ok, zero_rtt, _, <<>>, _, processed} =
        quic_connection:decode_long_header_type(
            zero_rtt, Packet, FirstByte, Version, DCID, SCID, Rest, S0
        ),
    S1 = quic_connection:discard_early_keys(S0),
    ?assertEqual(
        {error, no_early_keys},
        quic_connection:decode_long_header_type(
            zero_rtt, Packet, FirstByte, Version, DCID, SCID, Rest, S1
        )
    ).

%%====================================================================
%% Fixtures
%%====================================================================

server_with_early_keys() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    Keys = (S0#state.hs)#hs.initial_keys,
    EarlyKeys = element(1, Keys),
    S0#state{
        %% 0-RTT shares the application packet number space
        %% (RFC 9001 Section 4.1.4), which the decoder reads.
        pn_app = #pn_space{largest_recv = undefined, ack_ranges = []},
        hs = (S0#state.hs)#hs{early_keys = {EarlyKeys, binary:copy(<<9>>, 32)}}
    }.

%% Header protection needs a 16-byte ciphertext sample after the PN;
%% a bare PING frame is too small, so pad to the QUIC minimum.
pad_payload(Frames) ->
    Pad = 1200 - iolist_size(Frames) - 16,
    if
        Pad > 0 -> [Frames, <<0:Pad/unit:8>>];
        true -> Frames
    end.
