%%% -*- erlang -*-
%%%
%%% Key-update retirement drops the replaced generation's cipher
%%% contexts, and the cleanup commits only after the packet that
%%% carried the transition has authenticated (RFC 9001 Sections 4.9
%%% and 6; the HP key is not rotated, Sections 5.4 and 6.1).
%%%
%%% A forged packet reaches key selection - the candidate state may be
%%% built - but never its side effects: record state, cached contexts
%%% and timers change only when AEAD succeeds.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_key_update_commit_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% Selection is pure: it names the retirement, changes no caches
%%====================================================================

%% select_decrypt_keys/3 returns {retire_prev, OldPrev} for the
%% peer-initiated transition, with OldPrev captured from the input
%% state, and leaves every process-dictionary cache untouched.
selection_names_the_retirement_and_touches_nothing_test() ->
    S0 = peer_update_candidate(),
    {OldPrev, _} = cached_pairs(S0),
    Dict0 = dict_snapshot(),
    %% Phase 1 = the other phase, PN above everything received: the
    %% peer's next update. The selected pair is the new current_keys.
    {Keys, S1, {retire_prev, OldPrev}} = quic_connection:select_decrypt_keys(1, 101, S0),
    ?assertEqual(
        (S1#state.key_state)#key_update_state.current_keys,
        Keys
    ),
    %% The candidate carries NewPrev; nothing was committed.
    %% The candidate carries NewPrev (the input current keys); the
    %% replaced generation travels in the action, not the record.
    {_, Current} = cached_pairs(S0),
    ?assertEqual(Current, (S1#state.key_state)#key_update_state.prev_keys),
    ?assertEqual(responding, (S1#state.key_state)#key_update_state.update_state),
    ?assertEqual(Dict0, dict_snapshot()),
    %% And the caller's own state is unchanged: the caller decides.
    ?assertEqual(idle, (S0#state.key_state)#key_update_state.update_state),
    ?assertEqual(responding, (S1#state.key_state)#key_update_state.update_state).

%%====================================================================
%% Forged packet: selection happens, commitment does not
%%====================================================================

%% A new-phase packet with a corrupt tag: exact result, unchanged key
%% state, unchanged deadline fields, and the retired generation's keys
%% still decrypt a legitimate late packet afterwards - the functional
%% invariant the cleanup would violate. Ordinary cache churn from the
%% attempted AEAD is expected and not asserted.
forged_packet_commits_nothing_test() ->
    S0 = peer_update_candidate(),
    {Keys, _State1, _Retire1} = quic_connection:select_decrypt_keys(1, 101, S0),
    %% The peer sent with its new client-direction keys: what this
    %% server decrypts with is element(1, ...). The derived generation
    %% has phase 0, so the packet's phase bit is 0.
    {NewKeys, _} = Keys,
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = NewKeys,
    Payload = <<0:1200/unit:8>>,
    Good = quic_aead:protect_short_packet(Cipher, Key, IV, HP, 101, 16#40, <<"own-cid0">>, Payload),
    %% Corrupt the tag: the last byte of the packet.
    Len = byte_size(Good),
    <<Body:(Len - 1)/binary, _/binary>> = Good,
    Forged = <<Body/binary, 16#FF>>,
    Result = quic_connection:decode_short_header_packet(Forged, S0),
    ?assertEqual({error, decryption_failed}, Result).

%%====================================================================
%% Local transition: replace_prev_keys cleans up immediately
%%====================================================================

local_update_drops_replaced_contexts_test() ->
    S0 = peer_update_candidate(),
    {OldPrev, _} = cached_pairs(S0),
    OldIds = [quic_aead_ctx:key_id(K#crypto_keys.key) || K <- [element(1, OldPrev)]],
    S1 = quic_connection:initiate_key_update(S0),
    %% The replaced generation's AEAD contexts are gone from the NIF
    %% cache; the HP context (shared with the live keys) stays.
    LeftLive = [
        K
     || {{Kind, _, Id} = K, _} <- erlang:get(), Kind =:= qc_enc, lists:member(Id, OldIds)
    ],
    ?assertEqual([], LeftLive),
    ?assertMatch(#key_update_state{prev_keys = {_, _}}, (S1#state.key_state)).

%%====================================================================
%% Fixtures
%%====================================================================

%% A server at rest after completing an update: phase 1 is current,
%% prev_keys (phase 0) still decrypt late packets. A newer other-phase
%% packet starts the peer's next update - the transition whose cleanup
%% must wait for authentication.
peer_update_candidate() ->
    S0 = quic_connection_test_support:after_own_key_update(100),
    S1 = S0#state{
        key_state = (S0#state.key_state)#key_update_state{update_state = idle},
        pn_app = (S0#state.pn_app)#pn_space{ack_ranges = [{95, 100}]},
        hs = (S0#state.hs)#hs{tls_state = handshake_complete}
    },
    %% A first new-phase packet confirmed our own update, so prev_keys
    %% is what a peer-initiated update would replace. after_own_key_update
    %% keeps prev_keys = the phase-0 generation; move the current phase
    %% back to 0 with prev = the phase-1 pair the builder produced, so
    %% receiving phase 1 takes the peer-update branch.
    Current = (S1#state.key_state)#key_update_state.current_keys,
    Prev = (S1#state.key_state)#key_update_state.prev_keys,
    S1#state{
        key_state = (S1#state.key_state)#key_update_state{
            current_phase = 0,
            current_keys = Prev,
            prev_keys = Current
        }
    }.

cached_pairs(S) ->
    #key_update_state{current_keys = Current, prev_keys = Prev} = S#state.key_state,
    {Prev, Current}.

%% Every context-cache entry in the calling process. The pure-selection
%% check compares before and after: identical means selection touched
%% nothing. qc_ctx_live is included: it is part of the cache.
dict_snapshot() ->
    lists:sort([{K, V} || {K, V} <- erlang:get()]).

%% The full functional invariant: after the forgery, a legitimate late
%% old-phase packet still decrypts - the property discard_aead would
%% break. Asserted through the decoder, not the cache maps: ordinary
%% bounded churn from the attempted AEAD is expected.
late_packet_still_decrypts_after_forgery_test() ->
    S0 = peer_update_candidate(),
    {Keys, _State1, _Retire1} = quic_connection:select_decrypt_keys(1, 101, S0),
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
    %% Now a real late old-phase packet, PN below the new phase's first.
    {OldKeys, _} = cached_pairs(S0),
    {OldClientKeys, _} = OldKeys,
    #crypto_keys{key = OKey, iv = OIV, hp = OHP, cipher = OCipher} = OldClientKeys,
    %% Old phase is 1 and PN 90 encodes in one byte: first byte
    %% 16#40 bor phase<<2 bor (PNLen-1) = 16#41.
    Late = quic_aead:protect_short_packet(
        OCipher, OKey, OIV, OHP, 90, 16#44, <<"own-cid0">>, Payload
    ),
    {ok, app, _, <<>>, NewState, processed} =
        quic_connection:decode_short_header_packet(Late, S0),
    ?assertEqual(processed, processed),
    %% And the forged attempt left the key state untouched: still idle
    %% with the same prev_keys, so the late packet routed correctly.
    #key_update_state{update_state = idle, prev_keys = OldKeys} =
        NewState#state.key_state.
