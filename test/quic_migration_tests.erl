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
%% Helper Functions
%%====================================================================

%% Anti-amplification check: can only send 3x received bytes on unvalidated path
can_send(#path_state{status = validated}, _Size) ->
    true;
can_send(#path_state{bytes_sent = Sent, bytes_received = Recv}, Size) ->
    (Sent + Size) =< (Recv * 3).
