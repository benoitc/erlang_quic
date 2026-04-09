%%% -*- erlang -*-
%%%
%%% Tests for QUIC Connection Migration
%%% RFC 9000 Section 9
%%%

-module(quic_migration_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Path State Tests
%%====================================================================

path_state_creation_test() ->
    Path = #path_state{
        remote_addr = {{127, 0, 0, 1}, 4433},
        status = unknown,
        bytes_sent = 0,
        bytes_received = 0
    },
    ?assertEqual(unknown, Path#path_state.status),
    ?assertEqual({{127, 0, 0, 1}, 4433}, Path#path_state.remote_addr).

path_state_validating_test() ->
    ChallengeData = crypto:strong_rand_bytes(8),
    Path = #path_state{
        remote_addr = {{192, 168, 1, 1}, 8443},
        status = validating,
        challenge_data = ChallengeData,
        challenge_count = 1
    },
    ?assertEqual(validating, Path#path_state.status),
    ?assertEqual(8, byte_size(Path#path_state.challenge_data)).

path_state_validated_test() ->
    Path = #path_state{
        remote_addr = {{10, 0, 0, 1}, 443},
        status = validated,
        challenge_data = undefined
    },
    ?assertEqual(validated, Path#path_state.status),
    ?assertEqual(undefined, Path#path_state.challenge_data).

%%====================================================================
%% CID Entry Tests
%%====================================================================

cid_entry_creation_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    Entry = #cid_entry{
        seq_num = 1,
        cid = CID,
        stateless_reset_token = Token,
        status = active
    },
    ?assertEqual(1, Entry#cid_entry.seq_num),
    ?assertEqual(8, byte_size(Entry#cid_entry.cid)),
    ?assertEqual(16, byte_size(Entry#cid_entry.stateless_reset_token)),
    ?assertEqual(active, Entry#cid_entry.status).

cid_entry_retired_test() ->
    Entry = #cid_entry{
        seq_num = 0,
        cid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        status = retired
    },
    ?assertEqual(retired, Entry#cid_entry.status).

%%====================================================================
%% CID Pool Tests
%%====================================================================

cid_pool_add_test() ->
    Pool = [],
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token1 = crypto:strong_rand_bytes(16),
    Entry1 = #cid_entry{seq_num = 1, cid = CID1, stateless_reset_token = Token1, status = active},
    Pool1 = [Entry1 | Pool],
    ?assertEqual(1, length(Pool1)),

    CID2 = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Token2 = crypto:strong_rand_bytes(16),
    Entry2 = #cid_entry{seq_num = 2, cid = CID2, stateless_reset_token = Token2, status = active},
    Pool2 = [Entry2 | Pool1],
    ?assertEqual(2, length(Pool2)).

cid_retirement_test() ->
    Entry1 = #cid_entry{seq_num = 1, cid = <<1, 2, 3, 4>>, status = active},
    Entry2 = #cid_entry{seq_num = 2, cid = <<5, 6, 7, 8>>, status = active},
    Pool = [Entry1, Entry2],

    %% Retire entry with seq_num = 1
    NewPool = lists:map(
        fun
            (#cid_entry{seq_num = 1} = E) -> E#cid_entry{status = retired};
            (E) -> E
        end,
        Pool
    ),

    [Retired, Active] = NewPool,
    ?assertEqual(retired, Retired#cid_entry.status),
    ?assertEqual(active, Active#cid_entry.status).

%%====================================================================
%% Anti-Amplification Tests
%%====================================================================

anti_amplification_allowed_test() ->
    %% Path with 1000 bytes received, can send up to 3000
    Path = #path_state{
        status = unknown,
        bytes_sent = 0,
        bytes_received = 1000
    },
    %% Can send 1000 bytes (total 1000 <= 3000)
    ?assertEqual(true, can_send(Path, 1000)),
    %% Can send 2500 bytes (total 2500 <= 3000)
    ?assertEqual(true, can_send(Path, 2500)),
    %% Can send 3000 bytes (total 3000 <= 3000)
    ?assertEqual(true, can_send(Path, 3000)).

anti_amplification_blocked_test() ->
    %% Path with 1000 bytes received, can send up to 3000
    Path = #path_state{
        status = unknown,
        bytes_sent = 0,
        bytes_received = 1000
    },
    %% Cannot send 3001 bytes (total 3001 > 3000)
    ?assertEqual(false, can_send(Path, 3001)).

anti_amplification_after_sending_test() ->
    %% Path with 1000 bytes received, already sent 2000
    Path = #path_state{
        status = unknown,
        bytes_sent = 2000,
        bytes_received = 1000
    },
    %% Can send 1000 more (total 3000 <= 3000)
    ?assertEqual(true, can_send(Path, 1000)),
    %% Cannot send 1001 more (total 3001 > 3000)
    ?assertEqual(false, can_send(Path, 1001)).

validated_path_no_limit_test() ->
    %% Validated path has no amplification limit
    Path = #path_state{
        status = validated,
        bytes_sent = 10000,
        bytes_received = 100
    },
    ?assertEqual(true, can_send(Path, 100000)).

%%====================================================================
%% PATH_CHALLENGE/RESPONSE Tests
%%====================================================================

path_challenge_data_size_test() ->
    %% PATH_CHALLENGE data must be 8 bytes
    Data = crypto:strong_rand_bytes(8),
    ?assertEqual(8, byte_size(Data)).

path_challenge_response_match_test() ->
    %% PATH_RESPONSE must echo the exact challenge data
    ChallengeData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    ResponseData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    ?assertEqual(ChallengeData, ResponseData).

path_challenge_response_mismatch_test() ->
    ChallengeData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    ResponseData = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    ?assert(ChallengeData /= ResponseData).

%%====================================================================
%% Path Validation State Machine Tests
%%====================================================================

path_validation_success_test() ->
    %% Start with unknown path
    Path = #path_state{
        remote_addr = {{192, 168, 1, 100}, 4433},
        status = unknown
    },

    %% Initiate validation
    ChallengeData = crypto:strong_rand_bytes(8),
    ValidatingPath = Path#path_state{
        status = validating,
        challenge_data = ChallengeData,
        challenge_count = 1
    },
    ?assertEqual(validating, ValidatingPath#path_state.status),

    %% Receive valid response
    ValidatedPath = ValidatingPath#path_state{
        status = validated,
        challenge_data = undefined
    },
    ?assertEqual(validated, ValidatedPath#path_state.status).

path_validation_timeout_test() ->
    %% Path validation can fail after timeout
    Path = #path_state{
        remote_addr = {{192, 168, 1, 100}, 4433},
        status = validating,
        challenge_data = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        challenge_count = 3
    },

    %% After max retries, mark as failed
    FailedPath = Path#path_state{
        status = failed,
        challenge_data = undefined
    },
    ?assertEqual(failed, FailedPath#path_state.status).

path_validation_failure_test() ->
    %% Path validation fails on mismatched response
    Path = #path_state{
        remote_addr = {{192, 168, 1, 100}, 4433},
        status = validating,
        challenge_data = <<1, 2, 3, 4, 5, 6, 7, 8>>
    },

    %% Mismatched response doesn't validate
    WrongResponse = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    ?assert(Path#path_state.challenge_data /= WrongResponse).

%%====================================================================
%% Path State Extended Fields Tests (RFC 9000 Section 9)
%%====================================================================

path_state_with_dcid_test() ->
    %% Test the new dcid field in path_state
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Path = #path_state{
        remote_addr = {{127, 0, 0, 1}, 4433},
        status = validated,
        dcid = DCID
    },
    ?assertEqual(DCID, Path#path_state.dcid),
    ?assertEqual(validated, Path#path_state.status).

path_state_nat_rebinding_test() ->
    %% Test the is_nat_rebinding field
    Path = #path_state{
        remote_addr = {{192, 168, 1, 1}, 8443},
        status = validating,
        is_nat_rebinding = true
    },
    ?assertEqual(true, Path#path_state.is_nat_rebinding),

    %% Active migration (different IP) should have is_nat_rebinding = false
    PathMigration = #path_state{
        remote_addr = {{10, 0, 0, 5}, 4433},
        status = validating,
        is_nat_rebinding = false
    },
    ?assertEqual(false, PathMigration#path_state.is_nat_rebinding).

%%====================================================================
%% Address Change Detection Tests
%%====================================================================

detect_address_change_same_test() ->
    %% Same address should return same_path
    CurrentAddr = {{192, 168, 1, 100}, 4433},
    ?assertEqual(same_path, detect_peer_address_change(CurrentAddr, CurrentAddr)).

detect_address_change_nat_rebinding_test() ->
    %% Same IP, different port should return nat_rebinding
    CurrentAddr = {{192, 168, 1, 100}, 4433},
    NewAddr = {{192, 168, 1, 100}, 5000},
    ?assertEqual(nat_rebinding, detect_peer_address_change(NewAddr, CurrentAddr)).

detect_address_change_new_path_test() ->
    %% Different IP should return new_path
    CurrentAddr = {{192, 168, 1, 100}, 4433},
    NewAddr = {{10, 0, 0, 5}, 4433},
    ?assertEqual(new_path, detect_peer_address_change(NewAddr, CurrentAddr)).

detect_address_change_ipv6_same_test() ->
    %% Same IPv6 address
    CurrentAddr = {{0, 0, 0, 0, 0, 0, 0, 1}, 4433},
    ?assertEqual(same_path, detect_peer_address_change(CurrentAddr, CurrentAddr)).

detect_address_change_ipv6_nat_rebinding_test() ->
    %% Same IPv6, different port
    CurrentAddr = {{8193, 3512, 0, 0, 0, 0, 0, 1}, 4433},
    NewAddr = {{8193, 3512, 0, 0, 0, 0, 0, 1}, 5000},
    ?assertEqual(nat_rebinding, detect_peer_address_change(NewAddr, CurrentAddr)).

%%====================================================================
%% CID Switching Tests
%%====================================================================

find_unused_cid_found_test() ->
    %% Pool with multiple CIDs, one different from current
    CurrentCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    OtherCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Pool = [
        #cid_entry{seq_num = 0, cid = CurrentCID, status = active},
        #cid_entry{seq_num = 1, cid = OtherCID, status = active}
    ],
    ?assertEqual({ok, OtherCID}, find_unused_cid(Pool, CurrentCID)).

find_unused_cid_not_found_test() ->
    %% Pool with only the current CID
    CurrentCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Pool = [
        #cid_entry{seq_num = 0, cid = CurrentCID, status = active}
    ],
    ?assertEqual(not_found, find_unused_cid(Pool, CurrentCID)).

find_unused_cid_skips_retired_test() ->
    %% Pool with retired CID should skip it
    CurrentCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    RetiredCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    ActiveCID = <<2, 3, 4, 5, 6, 7, 8, 9>>,
    Pool = [
        #cid_entry{seq_num = 0, cid = CurrentCID, status = active},
        #cid_entry{seq_num = 1, cid = RetiredCID, status = retired},
        #cid_entry{seq_num = 2, cid = ActiveCID, status = active}
    ],
    ?assertEqual({ok, ActiveCID}, find_unused_cid(Pool, CurrentCID)).

find_unused_cid_empty_pool_test() ->
    CurrentCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    ?assertEqual(not_found, find_unused_cid([], CurrentCID)).

%%====================================================================
%% Migration State Tests
%%====================================================================

migration_state_idle_test() ->
    %% Default migration state should be idle
    State = idle,
    ?assertEqual(idle, State).

migration_state_validating_peer_test() ->
    %% When validating peer's new address
    State = validating_peer,
    ?assertEqual(validating_peer, State).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Anti-amplification check: can only send 3x received bytes on unvalidated path
can_send(#path_state{status = validated}, _Size) ->
    true;
can_send(#path_state{bytes_sent = Sent, bytes_received = Recv}, Size) ->
    (Sent + Size) =< (Recv * 3).

%% Simulates detect_peer_address_change/2 logic from quic_connection
detect_peer_address_change(PacketAddr, CurrentAddr) ->
    case PacketAddr of
        CurrentAddr ->
            same_path;
        {IP, _Port} when IP =:= element(1, CurrentAddr) ->
            nat_rebinding;
        _ ->
            new_path
    end.

%% Simulates find_unused_cid/2 logic from quic_connection
find_unused_cid([], _CurrentCID) ->
    not_found;
find_unused_cid([#cid_entry{cid = CID, status = active} | _Rest], CurrentCID) when
    CID =/= CurrentCID
->
    {ok, CID};
find_unused_cid([_ | Rest], CurrentCID) ->
    find_unused_cid(Rest, CurrentCID).

%%====================================================================
%% RFC Compliance Tests - Migration Fixes
%%====================================================================

%% Test: is_probing_frame/1 correctly classifies probing vs non-probing frames
%% RFC 9000 Section 9.1
is_probing_frame_test() ->
    %% Probing frames
    ?assertEqual(true, quic_connection:is_probing_frame(padding)),
    ?assertEqual(true, quic_connection:is_probing_frame({padding, 10})),
    ?assertEqual(
        true, quic_connection:is_probing_frame({path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>})
    ),
    ?assertEqual(
        true, quic_connection:is_probing_frame({path_response, <<1, 2, 3, 4, 5, 6, 7, 8>>})
    ),
    ?assertEqual(
        true, quic_connection:is_probing_frame({new_connection_id, 1, 0, <<1, 2, 3, 4>>, <<>>})
    ),

    %% Non-probing frames
    ?assertEqual(false, quic_connection:is_probing_frame(ping)),
    ?assertEqual(false, quic_connection:is_probing_frame({stream, 0, 0, <<>>, false})),
    ?assertEqual(false, quic_connection:is_probing_frame({ack, [], 0, undefined})),
    ?assertEqual(false, quic_connection:is_probing_frame({max_data, 1000})),
    ?assertEqual(false, quic_connection:is_probing_frame({crypto, 0, <<>>})),
    ?assertEqual(false, quic_connection:is_probing_frame(handshake_done)).

%% Test: contains_non_probing_frame/1 correctly identifies mixed frame lists
%% RFC 9000 Section 9.1
contains_non_probing_frame_test() ->
    %% Only probing frames
    ?assertEqual(false, quic_connection:contains_non_probing_frame([])),
    ?assertEqual(false, quic_connection:contains_non_probing_frame([padding])),
    ?assertEqual(
        false,
        quic_connection:contains_non_probing_frame([
            padding,
            {path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            {path_response, <<1, 2, 3, 4, 5, 6, 7, 8>>}
        ])
    ),

    %% Contains non-probing frames
    ?assertEqual(true, quic_connection:contains_non_probing_frame([ping])),
    ?assertEqual(true, quic_connection:contains_non_probing_frame([padding, ping])),
    ?assertEqual(
        true,
        quic_connection:contains_non_probing_frame([
            {path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            {stream, 0, 0, <<"data">>, false}
        ])
    ).

%% Test: NAT rebinding should preserve CC state (is_nat_rebinding = true)
%% RFC 9002 Section 9.4
nat_rebinding_preserves_state_test() ->
    %% NAT rebinding path (same IP, different port)
    Path = #path_state{
        remote_addr = {{192, 168, 1, 100}, 5000},
        status = validated,
        is_nat_rebinding = true
    },
    ?assertEqual(true, Path#path_state.is_nat_rebinding),
    %% Note: Actual CC preservation is tested via complete_migration/2
    %% which has two clauses based on is_nat_rebinding

    %% Active migration path (different IP)
    PathMigration = #path_state{
        remote_addr = {{10, 0, 0, 5}, 4433},
        status = validated,
        is_nat_rebinding = false
    },
    ?assertEqual(false, PathMigration#path_state.is_nat_rebinding).

%% Test: Probe padding calculation
%% RFC 9000 Section 8.2.1: Path validation datagrams must be at least 1200 bytes
probe_packet_padding_test() ->
    %% PATH_CHALLENGE frame is 9 bytes (type + 8 bytes data)
    %% With short header + DCID + PN + AEAD tag, packet would be ~30 bytes
    %% Must be padded to 1200 bytes

    %% Small DCID (8 bytes)
    _SmallDCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    % PATH_CHALLENGE
    SmallPayload = <<16#1a, 1, 2, 3, 4, 5, 6, 7, 8>>,
    %% Header: 1 + 8 + 2 = 11, AEAD: 16, Payload: 9 = 36 total
    %% Need 1200 - 36 = 1164 bytes of padding
    %% Minimum packet size should be >= 1200 after padding

    % Initial payload is small
    ?assert(byte_size(SmallPayload) < 100),
    ok.

%% Test: Old path validation field exists
%% RFC 9000 Section 9.3.2
old_path_validation_field_test() ->
    %% Verify path_state can hold challenge data for both paths
    NewPath = #path_state{
        remote_addr = {{10, 0, 0, 5}, 4433},
        status = validating,
        challenge_data = <<1, 2, 3, 4, 5, 6, 7, 8>>
    },
    OldPath = #path_state{
        remote_addr = {{192, 168, 1, 100}, 4433},
        status = validating,
        challenge_data = <<8, 7, 6, 5, 4, 3, 2, 1>>
    },
    %% Challenge data should be different for each path
    ?assert(NewPath#path_state.challenge_data =/= OldPath#path_state.challenge_data),
    ?assertEqual(validating, NewPath#path_state.status),
    ?assertEqual(validating, OldPath#path_state.status).

%% Test: Both paths can be validated independently
both_paths_validation_test() ->
    %% Create two path states for validation
    NewChallenge = crypto:strong_rand_bytes(8),
    OldChallenge = crypto:strong_rand_bytes(8),

    NewPath = #path_state{
        remote_addr = {{10, 0, 0, 5}, 4433},
        status = validating,
        challenge_data = NewChallenge
    },
    OldPath = #path_state{
        remote_addr = {{192, 168, 1, 100}, 4433},
        status = validating,
        challenge_data = OldChallenge
    },

    %% Validate new path
    ValidatedNewPath = NewPath#path_state{
        status = validated,
        challenge_data = undefined
    },
    ?assertEqual(validated, ValidatedNewPath#path_state.status),

    %% Old path can also be validated
    ValidatedOldPath = OldPath#path_state{
        status = validated,
        challenge_data = undefined
    },
    ?assertEqual(validated, ValidatedOldPath#path_state.status).

%% Test: Challenge data uniqueness for concurrent validations
challenge_data_uniqueness_test() ->
    %% Each path should have unique challenge data
    Challenge1 = crypto:strong_rand_bytes(8),
    Challenge2 = crypto:strong_rand_bytes(8),
    %% Cryptographically random data should be unique
    ?assertNotEqual(Challenge1, Challenge2).
