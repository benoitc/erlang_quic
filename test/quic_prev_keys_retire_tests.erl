%%% -*- erlang -*-
%%%
%%% RFC 9001 Section 6.5: an endpoint SHOULD retain old read keys for
%%% no more than three times the PTO after having received a packet
%%% protected using the new keys; after that they and their
%%% corresponding secrets SHOULD be discarded. The clock starts at the
%%% first packet that opens under the new keys - after AEAD
%%% authentication - never at key selection.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_prev_keys_retire_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% Arming: only an authenticated packet under the new keys
%%====================================================================

%% A forged new-phase packet (header unprotects, AEAD fails) arms
%% nothing and commits nothing: exact result, unchanged key state, no
%% timer, no deadline.
forged_packet_arms_nothing_test() ->
    S0 = peer_update_candidate(),
    {Keys, _, _} = quic_connection:select_decrypt_keys(1, 101, S0),
    {NewKeys, _} = Keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = NewKeys,
    Payload = <<0:1200/unit:8>>,
    Good = quic_aead:protect_short_packet(Cipher, Key, IV, HP, 101, 16#40, <<"own-cid0">>, Payload),
    Len = byte_size(Good),
    <<Body:(Len - 1)/binary, _/binary>> = Good,
    Forged = <<Body/binary, 16#FF>>,
    ?assertEqual(
        {error, decryption_failed}, quic_connection:decode_short_header_packet(Forged, S0)
    ),
    ?assertEqual(undefined, S0#state.prev_keys_retire_timer),
    ?assertEqual(undefined, S0#state.prev_keys_retire_deadline).

%% A real new-phase packet opens under the derived keys: recv_first_pn
%% is set, the deadline is three PTOs out, and the timer is armed.
first_authenticated_packet_arms_test() ->
    {S0, Packet} = opened_new_phase(),
    {ok, app, _, <<>>, S1, processed} =
        quic_connection:decode_short_header_packet(Packet, S0),
    KS = S1#state.key_state,
    ?assertEqual(101, KS#key_update_state.recv_first_pn),
    ?assert(is_reference(S1#state.prev_keys_retire_timer)),
    Now = erlang:monotonic_time(millisecond),
    ?assert(S1#state.prev_keys_retire_deadline > Now),
    ?assert(
        S1#state.prev_keys_retire_deadline =<
            Now + 3 * quic_loss:get_pto(S0#state.loss_state, app) + 100
    ).

%%====================================================================
%% Expiry: old read keys go, current-generation state stays
%%====================================================================

%% The fire handler drops prev_keys and their contexts, clears both
%% timer fields, and leaves recv_first_pn and the traffic secrets -
%% the current generation's - alone.
expiry_drops_prev_keys_only_test() ->
    {S0, Packet} = opened_new_phase(),
    {ok, app, _, <<>>, S1, processed} =
        quic_connection:decode_short_header_packet(Packet, S0),
    KS1 = S1#state.key_state,
    ?assertMatch({_, _}, KS1#key_update_state.prev_keys),
    Ref = S1#state.prev_keys_retire_timer,
    Past = S1#state{prev_keys_retire_deadline = erlang:monotonic_time(millisecond) - 1},
    {keep_state, S2} = quic_connection:handle_common_event(
        info, {timeout, Ref, prev_keys_retire_timeout}, connected, Past
    ),
    KS2 = S2#state.key_state,
    ?assertEqual(undefined, KS2#key_update_state.prev_keys),
    ?assertEqual(undefined, S2#state.prev_keys_retire_timer),
    ?assertEqual(undefined, S2#state.prev_keys_retire_deadline),
    %% Current-generation state: untouched by the retirement.
    ?assertEqual(KS1#key_update_state.recv_first_pn, KS2#key_update_state.recv_first_pn),
    ?assertEqual(
        KS1#key_update_state.client_app_secret, KS2#key_update_state.client_app_secret
    ),
    ?assertEqual(
        KS1#key_update_state.server_app_secret, KS2#key_update_state.server_app_secret
    ).

%% After expiry a late old-phase packet decrypts under the derived
%% next-generation keys? No: prev_keys is gone, so the packet looks
%% like a peer update candidate, the derived keys do not match the
%% old-phase ciphertext, and the exact result is
%% {error, decryption_failed} - with no candidate key-update state
%% committed and no timer armed.
post_expiry_old_phase_packet_test() ->
    {S0, Packet} = opened_new_phase(),
    {ok, app, _, <<>>, S1, processed} =
        quic_connection:decode_short_header_packet(Packet, S0),
    {OldPrev, _} = prev_and_current(S1),
    {OldClientKeys, _} = OldPrev,
    #crypto_keys{key = OKey, iv = OIV, hp = OHP, cipher = OCipher} = OldClientKeys,
    Payload = <<0:1200/unit:8>>,
    Late = quic_aead:protect_short_packet(
        OCipher, OKey, OIV, OHP, 90, 16#44, <<"own-cid0">>, Payload
    ),
    Ref = S1#state.prev_keys_retire_timer,
    Past = S1#state{prev_keys_retire_deadline = erlang:monotonic_time(millisecond) - 1},
    {keep_state, S2} = quic_connection:handle_common_event(
        info, {timeout, Ref, prev_keys_retire_timeout}, connected, Past
    ),
    KSBefore = key_shape(S2),
    ?assertEqual({error, decryption_failed}, quic_connection:decode_short_header_packet(Late, S2)),
    ?assertEqual(KSBefore, key_shape(S2)),
    ?assertEqual(undefined, S2#state.prev_keys_retire_timer).

%%====================================================================
%% Replacement: a later update cancels the pending retirement
%%====================================================================

%% Generation N armed, then generation N+1 replaces prev_keys: the old
%% timer and deadline are cleared, N+1 has no retirement timer yet,
%% and N's stale timeout leaves N+1's previous keys and fresh deadline
%% intact.
replacement_cancels_pending_retirement_test() ->
    %% Stage 1: arm generation N.
    {S0, Packet} = opened_new_phase(),
    {ok, app, _, <<>>, S1, processed} =
        quic_connection:decode_short_header_packet(Packet, S0),
    ?assert(is_reference(S1#state.prev_keys_retire_timer)),
    %% Stage 2: a local update installs generation N+1.
    S2 = quic_connection:initiate_key_update(S1),
    ?assertEqual(undefined, S2#state.prev_keys_retire_timer),
    ?assertEqual(undefined, S2#state.prev_keys_retire_deadline),
    ?assertMatch({_, _}, (S2#state.key_state)#key_update_state.prev_keys),
    %% Stage 3: the first authenticated N+1 packet arms a fresh
    %% deadline. The new generation's phase: 1 - N's current phase.
    NewPhase = (S2#state.key_state)#key_update_state.current_phase,
    {NewKeys, _} = (S2#state.key_state)#key_update_state.current_keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = NewKeys,
    Payload = <<0:1200/unit:8>>,
    Good = quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, 200, 16#40 bor (NewPhase bsl 2), <<"own-cid0">>, Payload
    ),
    {ok, app, _, <<>>, S3, processed} =
        quic_connection:decode_short_header_packet(Good, S2),
    ?assert(is_reference(S3#state.prev_keys_retire_timer)),
    ?assert(is_integer(S3#state.prev_keys_retire_deadline)),
    %% Stage 4: generation N's stale timeout arrives. N+1's previous
    %% keys and the fresh deadline survive.
    StaleRef = S1#state.prev_keys_retire_timer,
    {keep_state, S4} = quic_connection:handle_common_event(
        info, {timeout, StaleRef, prev_keys_retire_timeout}, connected, S3
    ),
    ?assertEqual(S3#state.prev_keys_retire_timer, S4#state.prev_keys_retire_timer),
    ?assertEqual(S3#state.prev_keys_retire_deadline, S4#state.prev_keys_retire_deadline),
    ?assertEqual(
        (S3#state.key_state)#key_update_state.prev_keys,
        (S4#state.key_state)#key_update_state.prev_keys
    ).

%%====================================================================
%% Fixtures
%%====================================================================

%% A server at rest after completing an update (phase 1 current, the
%% phase-0 generation as prev_keys), with a real packet that opens
%% under the current keys: phase bit 1, PN above everything received.
opened_new_phase() ->
    S0 = quic_connection_test_support:after_own_key_update(100),
    S1 = S0#state{
        pn_app = (S0#state.pn_app)#pn_space{ack_ranges = [{95, 100}]},
        hs = (S0#state.hs)#hs{tls_state = handshake_complete}
    },
    {CurrentKeys, _} = (S1#state.key_state)#key_update_state.current_keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = CurrentKeys,
    Payload = <<0:1200/unit:8>>,
    Packet = quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, 101, 16#44, <<"own-cid0">>, Payload
    ),
    {S1, Packet}.

%% A server whose next incoming packet is the peer's update: phase 0
%% current (the phase-1 pair held as prev), a newer other-phase packet
%% arriving. The returned packet authenticates under the derived keys.
peer_update_candidate() ->
    S0 = quic_connection_test_support:after_own_key_update(100),
    S1 = S0#state{
        key_state = (S0#state.key_state)#key_update_state{update_state = idle},
        pn_app = (S0#state.pn_app)#pn_space{ack_ranges = [{95, 100}]},
        hs = (S0#state.hs)#hs{tls_state = handshake_complete}
    },
    Current = (S1#state.key_state)#key_update_state.current_keys,
    Prev = (S1#state.key_state)#key_update_state.prev_keys,
    S1#state{
        key_state = (S1#state.key_state)#key_update_state{
            current_phase = 0,
            current_keys = Prev,
            prev_keys = Current
        }
    }.

%% The peer-update state with a real packet that opens under the
%% derived generation: phase bit 0, PN above everything received.
opened_new_phase_from_peer_update() ->
    S0 = peer_update_candidate(),
    {Keys, _, _} = quic_connection:select_decrypt_keys(1, 101, S0),
    {NewKeys, _} = Keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = NewKeys,
    Payload = <<0:1200/unit:8>>,
    Packet = quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, 101, 16#40, <<"own-cid0">>, Payload
    ),
    {S0, Packet}.

prev_and_current(S) ->
    #key_update_state{current_keys = Current, prev_keys = Prev} = S#state.key_state,
    {Prev, Current}.

key_shape(#state{key_state = KS}) ->
    {
        KS#key_update_state.current_phase,
        KS#key_update_state.update_state,
        KS#key_update_state.prev_keys =:= undefined,
        KS#key_update_state.recv_first_pn
    }.
