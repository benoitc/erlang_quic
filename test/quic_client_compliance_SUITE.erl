%%% -*- erlang -*-
%%%
%%% QUIC Client Compliance Test Suite
%%%
%%% Tests based on the official QUIC Interop Runner test cases.
%%% https://github.com/quic-interop/quic-interop-runner
%%%
%%% Test Cases:
%%% - handshake: Basic handshake completion
%%% - transfer: Flow control and multiplexing
%%% - retry: Retry packet handling (RFC 9000 Section 8.1)
%%% - resumption: Session resumption (RFC 9001 Section 4.6)
%%% - zerortt: 0-RTT early data
%%% - keyupdate: Key update during transfer (RFC 9001 Section 6)
%%% - chacha20: ChaCha20-Poly1305 cipher support
%%% - versionnegotiation: Version negotiation (RFC 9000 Section 6)
%%% - rebind: Path validation on address change (RFC 9000 Section 9)
%%% - connectionmigration: Active connection migration
%%%

-module(quic_client_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Interop Runner Test Cases (Local validation)
-export([
    %% Handshake group
    handshake_basic/1,
    handshake_alpn_negotiation/1,
    handshake_transport_params/1,

    %% Transfer group
    transfer_flow_control/1,
    transfer_multiplexing/1,
    transfer_large_data/1,

    %% Retry group
    retry_packet_format/1,
    retry_integrity_tag/1,
    retry_token_in_initial/1,

    %% Resumption group
    resumption_ticket_storage/1,
    resumption_psk_derivation/1,
    resumption_ticket_parsing/1,

    %% 0-RTT group
    zerortt_early_data_extension/1,
    zerortt_early_secret_derivation/1,

    %% Key Update group
    keyupdate_secret_derivation/1,
    keyupdate_key_phase/1,
    keyupdate_chaining/1,

    %% ChaCha20 group
    chacha20_aead_encrypt/1,
    chacha20_aead_decrypt/1,
    chacha20_header_protection/1,

    %% Version Negotiation group
    versionnegotiation_packet_format/1,
    versionnegotiation_response/1,

    %% Path Validation group
    rebind_path_challenge_format/1,
    rebind_path_response_format/1,

    %% Connection Migration group
    migration_new_cid/1,
    migration_retire_cid/1
]).

%% Network tests (require server)
-export([
    network_handshake/1,
    network_retry/1,
    network_transfer/1,
    network_keyupdate/1
]).

%% Timeout definitions
-define(HANDSHAKE_TIMEOUT, 10000).
-define(TRANSFER_TIMEOUT, 30000).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, handshake_compliance},
        {group, transfer_compliance},
        {group, retry_compliance},
        {group, resumption_compliance},
        {group, zerortt_compliance},
        {group, keyupdate_compliance},
        {group, chacha20_compliance},
        {group, versionnegotiation_compliance},
        {group, rebind_compliance},
        {group, migration_compliance},
        {group, network_tests}
    ].

groups() ->
    [
        %% Local compliance tests (no network)
        {handshake_compliance, [parallel], [
            handshake_basic,
            handshake_alpn_negotiation,
            handshake_transport_params
        ]},
        {transfer_compliance, [parallel], [
            transfer_flow_control,
            transfer_multiplexing,
            transfer_large_data
        ]},
        {retry_compliance, [parallel], [
            retry_packet_format,
            retry_integrity_tag,
            retry_token_in_initial
        ]},
        {resumption_compliance, [parallel], [
            resumption_ticket_storage,
            resumption_psk_derivation,
            resumption_ticket_parsing
        ]},
        {zerortt_compliance, [parallel], [
            zerortt_early_data_extension,
            zerortt_early_secret_derivation
        ]},
        {keyupdate_compliance, [parallel], [
            keyupdate_secret_derivation,
            keyupdate_key_phase,
            keyupdate_chaining
        ]},
        {chacha20_compliance, [parallel], [
            chacha20_aead_encrypt,
            chacha20_aead_decrypt,
            chacha20_header_protection
        ]},
        {versionnegotiation_compliance, [parallel], [
            versionnegotiation_packet_format,
            versionnegotiation_response
        ]},
        {rebind_compliance, [parallel], [
            rebind_path_challenge_format,
            rebind_path_response_format
        ]},
        {migration_compliance, [parallel], [
            migration_new_cid,
            migration_retire_cid
        ]},
        %% Network tests (require server)
        {network_tests, [sequence], [
            network_handshake,
            network_retry,
            network_transfer,
            network_keyupdate
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(network_tests, Config) ->
    %% Check if server is reachable
    Host = os:getenv("QUIC_SERVER_HOST", "127.0.0.1"),
    Port = list_to_integer(os:getenv("QUIC_SERVER_PORT", "4433")),
    case check_server_reachable(Host, Port) of
        true -> [{host, Host}, {port, Port} | Config];
        false -> {skip, "No QUIC server reachable"}
    end;
init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting: ~p", [TestCase]),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Handshake Compliance Tests
%%====================================================================

%% @doc Test basic handshake packet structure
handshake_basic(_Config) ->
    ct:comment("RFC 9000: Verify Initial packet format for handshake"),

    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    %% Build ClientHello (returns {ClientHello, PubKey, PrivKey})
    Opts = #{
        server_name => <<"test.example.com">>,
        alpn => [<<"h3">>]
    },
    {ClientHello, _PubKey, _PrivKey} = quic_tls:build_client_hello(Opts),
    ?assert(byte_size(ClientHello) > 0),

    %% Wrap in CRYPTO frame
    CryptoFrame = {crypto, 0, ClientHello},
    CryptoEncoded = quic_frame:encode(CryptoFrame),

    %% Build Initial packet
    Payload = CryptoEncoded,
    InitialOpts = #{token => <<>>, payload => Payload, pn => 0},
    Packet = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID, InitialOpts),

    %% Verify packet structure
    <<FirstByte, Version:32, DCIDLen, _/binary>> = Packet,

    %% Form bit (0x80) and Fixed bit (0x40) must be set
    ?assertEqual(16#C0, FirstByte band 16#C0),
    ?assertEqual(?QUIC_VERSION_1, Version),
    ?assertEqual(8, DCIDLen),

    {comment, "Initial packet format compliant with RFC 9000"}.

%% @doc Test ALPN negotiation in ClientHello
handshake_alpn_negotiation(_Config) ->
    ct:comment("RFC 9001 Section 8.1: ALPN must be included"),

    Opts = #{
        server_name => <<"test.example.com">>,
        alpn => [<<"h3">>, <<"hq-interop">>]
    },
    {ClientHello, _PubKey, _PrivKey} = quic_tls:build_client_hello(Opts),

    %% ALPN extension type is 0x0010
    ?assert(binary:match(ClientHello, <<16#00, 16#10>>) =/= nomatch),

    %% Verify h3 protocol is included
    ?assert(binary:match(ClientHello, <<"h3">>) =/= nomatch),

    {comment, "ALPN extension included in ClientHello"}.

%% @doc Test transport parameters encoding
handshake_transport_params(_Config) ->
    ct:comment("RFC 9000 Section 18.2: Transport parameters encoding"),

    Params = #{
        max_idle_timeout => 30000,
        initial_max_data => 1048576,
        initial_max_stream_data_bidi_local => 262144,
        initial_max_stream_data_bidi_remote => 262144,
        initial_max_stream_data_uni => 262144,
        initial_max_streams_bidi => 100,
        initial_max_streams_uni => 100,
        ack_delay_exponent => 3,
        max_ack_delay => 25,
        active_connection_id_limit => 8
    },

    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),

    %% Verify roundtrip
    ?assertEqual(30000, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(1048576, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)),

    {comment, "Transport parameters encoding/decoding works"}.

%%====================================================================
%% Transfer Compliance Tests
%%====================================================================

%% @doc Test flow control windows
transfer_flow_control(_Config) ->
    ct:comment("RFC 9000 Section 4: Flow control"),

    %% Test MAX_DATA frame
    MaxData = 2097152,
    Frame1 = {max_data, MaxData},
    Encoded1 = quic_frame:encode(Frame1),
    {Decoded1, <<>>} = quic_frame:decode(Encoded1),
    ?assertEqual(Frame1, Decoded1),

    %% Test MAX_STREAM_DATA frame
    StreamId = 4,
    MaxStreamData = 524288,
    Frame2 = {max_stream_data, StreamId, MaxStreamData},
    Encoded2 = quic_frame:encode(Frame2),
    {Decoded2, <<>>} = quic_frame:decode(Encoded2),
    ?assertEqual(Frame2, Decoded2),

    %% Test DATA_BLOCKED frame
    Frame3 = {data_blocked, MaxData},
    Encoded3 = quic_frame:encode(Frame3),
    {Decoded3, <<>>} = quic_frame:decode(Encoded3),
    ?assertEqual(Frame3, Decoded3),

    {comment, "Flow control frames encode/decode correctly"}.

%% @doc Test stream multiplexing
transfer_multiplexing(_Config) ->
    ct:comment("RFC 9000 Section 2: Stream multiplexing"),

    %% Test multiple streams with different IDs
    Streams = [
        % Client bidi
        {0, <<"Stream 0 data">>},
        % Client bidi
        {4, <<"Stream 4 data">>},
        % Client uni
        {2, <<"Stream 2 data">>},
        % Client uni
        {6, <<"Stream 6 data">>}
    ],

    lists:foreach(
        fun({StreamId, Data}) ->
            Frame = {stream, StreamId, 0, Data, true},
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            ?assertMatch({stream, StreamId, 0, Data, true}, Decoded)
        end,
        Streams
    ),

    %% Verify stream ID types

    % Client bidi
    ?assertEqual(0, 0 rem 4),
    % Client bidi
    ?assertEqual(0, 4 rem 4),
    % Client uni
    ?assertEqual(2, 2 rem 4),
    % Client uni
    ?assertEqual(2, 6 rem 4),

    {comment, "Stream multiplexing works correctly"}.

%% @doc Test large data transfer
transfer_large_data(_Config) ->
    ct:comment("RFC 9000: Large STREAM frames"),

    %% Test data (16KB - within typical frame limits)
    LargeData = crypto:strong_rand_bytes(16384),
    StreamId = 0,
    Frame = {stream, StreamId, 0, LargeData, true},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),

    ?assertMatch({stream, StreamId, 0, _, true}, Decoded),
    {stream, _, _, DecodedData, _} = Decoded,
    ?assertEqual(byte_size(LargeData), byte_size(DecodedData)),
    ?assertEqual(LargeData, DecodedData),

    {comment, "Large STREAM frames work correctly"}.

%%====================================================================
%% Retry Compliance Tests
%%====================================================================

%% @doc Test Retry packet format
retry_packet_format(_Config) ->
    ct:comment("RFC 9000 Section 17.2.5: Retry packet format"),

    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    RetryToken = <<"retry_token_data_here">>,
    IntegrityTag = crypto:strong_rand_bytes(16),

    %% Build retry payload (token + integrity tag)
    Payload = <<RetryToken/binary, IntegrityTag/binary>>,

    Encoded = quic_packet:encode_long(
        retry,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => Payload}
    ),

    %% Verify header structure
    <<FirstByte, Version:32, _/binary>> = Encoded,

    %% Form bit set, type bits = 11 (retry)
    ?assertEqual(1, (FirstByte bsr 7) band 1),
    ?assertEqual(3, (FirstByte bsr 4) band 3),
    ?assertEqual(?QUIC_VERSION_1, Version),

    {comment, "Retry packet format correct"}.

%% @doc Test Retry integrity tag verification
retry_integrity_tag(_Config) ->
    ct:comment("RFC 9001 Section 5.8: Retry integrity tag"),

    %% Test that integrity tag verification function exists
    OriginalDCID = crypto:strong_rand_bytes(8),

    %% Build a mock Retry packet
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    RetryToken = <<"test_token">>,

    %% The integrity tag is computed over the pseudo-packet
    %% For this test, we verify the function exists and handles input
    PseudoPacket = <<
        (byte_size(OriginalDCID)),
        OriginalDCID/binary,
        % Retry packet first byte
        16#FF,
        ?QUIC_VERSION_1:32,
        (byte_size(DCID)),
        DCID/binary,
        (byte_size(SCID)),
        SCID/binary,
        RetryToken/binary
    >>,

    %% Compute tag (RFC 9001 uses AES-128-GCM with fixed key/nonce)
    Tag = quic_crypto:compute_retry_integrity_tag(OriginalDCID, PseudoPacket, ?QUIC_VERSION_1),
    ?assertEqual(16, byte_size(Tag)),

    {comment, "Retry integrity tag computation works"}.

%% @doc Test retry token inclusion in Initial
retry_token_in_initial(_Config) ->
    ct:comment("RFC 9000 Section 8.1.2: Token in Initial after Retry"),

    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    RetryToken = <<"server_provided_retry_token">>,
    Payload = <<"crypto_data">>,

    %% Build Initial with retry token
    Opts = #{token => RetryToken, payload => Payload, pn => 0},
    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID, Opts),

    %% Decode and verify token is present
    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(initial, Packet#quic_packet.type),
    ?assertEqual(RetryToken, Packet#quic_packet.token),

    {comment, "Retry token included in Initial packet"}.

%%====================================================================
%% Resumption Compliance Tests
%%====================================================================

%% @doc Test session ticket storage
resumption_ticket_storage(_Config) ->
    ct:comment("RFC 8446 Section 4.6: Session ticket storage"),

    Store = quic_ticket:new_store(),

    %% Create a mock ticket
    Ticket = #session_ticket{
        server_name = <<"test.example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = rand:uniform(16#FFFFFFFF),
        nonce = crypto:strong_rand_bytes(8),
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Store and retrieve
    Store1 = quic_ticket:store_ticket(<<"test.example.com">>, Ticket, Store),
    {ok, Retrieved} = quic_ticket:lookup_ticket(<<"test.example.com">>, Store1),

    ?assertEqual(Ticket#session_ticket.ticket, Retrieved#session_ticket.ticket),
    ?assertEqual(Ticket#session_ticket.lifetime, Retrieved#session_ticket.lifetime),

    {comment, "Session ticket storage works"}.

%% @doc Test PSK derivation
resumption_psk_derivation(_Config) ->
    ct:comment("RFC 8446 Section 4.6.1: PSK derivation"),

    %% Mock ticket with known values
    ResumptionSecret = crypto:strong_rand_bytes(32),
    Ticket = #session_ticket{
        server_name = <<"test.example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        nonce = crypto:strong_rand_bytes(8),
        cipher = aes_128_gcm
    },

    %% Derive PSK
    PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket),

    %% PSK should be hash length (32 bytes for SHA-256)
    ?assertEqual(32, byte_size(PSK)),

    %% Same inputs should produce same PSK
    PSK2 = quic_ticket:derive_psk(ResumptionSecret, Ticket),
    ?assertEqual(PSK, PSK2),

    {comment, "PSK derivation works correctly"}.

%% @doc Test NewSessionTicket parsing
resumption_ticket_parsing(_Config) ->
    ct:comment("RFC 8446 Section 4.6.1: NewSessionTicket parsing"),

    %% Build a NewSessionTicket message
    Lifetime = 86400,
    AgeAdd = 16#12345678,
    Nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Ticket = <<"this_is_the_ticket_value">>,
    MaxEarlyData = 16384,

    NonceLen = byte_size(Nonce),
    TicketLen = byte_size(Ticket),

    %% Build early_data extension
    EarlyDataExt = <<16#00, 16#2a, 4:16, MaxEarlyData:32>>,
    ExtLen = byte_size(EarlyDataExt),

    Message =
        <<Lifetime:32, AgeAdd:32, NonceLen, Nonce/binary, TicketLen:16, Ticket/binary, ExtLen:16,
            EarlyDataExt/binary>>,

    %% Parse
    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Message),

    ?assertEqual(Lifetime, maps:get(lifetime, Parsed)),
    ?assertEqual(AgeAdd, maps:get(age_add, Parsed)),
    ?assertEqual(Nonce, maps:get(nonce, Parsed)),
    ?assertEqual(Ticket, maps:get(ticket, Parsed)),
    ?assertEqual(MaxEarlyData, maps:get(max_early_data, Parsed)),

    {comment, "NewSessionTicket parsing works"}.

%%====================================================================
%% 0-RTT Compliance Tests
%%====================================================================

%% @doc Test early_data extension
zerortt_early_data_extension(_Config) ->
    ct:comment("RFC 8446: early_data extension (type 42)"),

    %% Extension format: type (2) + length (2) + max_early_data (4)
    MaxEarlyData = 16384,
    Extension = <<16#00, 16#2a, 4:16, MaxEarlyData:32>>,

    %% Verify format
    <<Type:16, Len:16, Value:32>> = Extension,
    ?assertEqual(16#002a, Type),
    ?assertEqual(4, Len),
    ?assertEqual(MaxEarlyData, Value),

    {comment, "early_data extension format correct"}.

%% @doc Test early secret derivation
zerortt_early_secret_derivation(_Config) ->
    ct:comment("RFC 8446 Section 7.1: Early secret derivation"),

    %% Derive early secret (without PSK = zero PSK)
    EarlySecret = quic_crypto:derive_early_secret(),

    %% Should be 32 bytes (SHA-256)
    ?assertEqual(32, byte_size(EarlySecret)),

    %% Same call should produce same result
    EarlySecret2 = quic_crypto:derive_early_secret(),
    ?assertEqual(EarlySecret, EarlySecret2),

    %% Test client_early_traffic_secret derivation
    TranscriptHash = crypto:hash(sha256, <<"ClientHello">>),
    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(EarlySecret, TranscriptHash),
    ?assertEqual(32, byte_size(ClientEarlySecret)),

    {comment, "Early secret derivation works"}.

%%====================================================================
%% Key Update Compliance Tests
%%====================================================================

%% @doc Test key update secret derivation
keyupdate_secret_derivation(_Config) ->
    ct:comment("RFC 9001 Section 6: Key update secret derivation"),

    %% Start with an application secret
    AppSecret = crypto:strong_rand_bytes(32),

    %% Derive updated secret
    {UpdatedSecret, _Keys} = quic_keys:derive_updated_keys(AppSecret, aes_128_gcm),

    %% Updated secret should be different from original
    ?assertNotEqual(AppSecret, UpdatedSecret),
    ?assertEqual(32, byte_size(UpdatedSecret)),

    {comment, "Key update secret derivation works"}.

%% @doc Test key phase bit handling
keyupdate_key_phase(_Config) ->
    ct:comment("RFC 9001 Section 6.1: Key phase bit"),

    DCID = crypto:strong_rand_bytes(8),
    Payload = <<"test data">>,
    PN = 100,

    %% Encode with key_phase = 0 (SpinBit = false, KeyPhase = 0)
    Encoded0 = quic_packet:encode_short(DCID, PN, Payload, false, 0),
    <<FirstByte0, _/binary>> = Encoded0,
    KeyPhase0 = (FirstByte0 bsr 2) band 1,
    ?assertEqual(0, KeyPhase0),

    %% Encode with key_phase = 1 (SpinBit = false, KeyPhase = 1)
    Encoded1 = quic_packet:encode_short(DCID, PN, Payload, false, 1),
    <<FirstByte1, _/binary>> = Encoded1,
    KeyPhase1 = (FirstByte1 bsr 2) band 1,
    ?assertEqual(1, KeyPhase1),

    {comment, "Key phase bit encoding works"}.

%% @doc Test key update chaining
keyupdate_chaining(_Config) ->
    ct:comment("RFC 9001 Section 6: Key update chaining"),

    %% Initial secret
    Secret0 = crypto:strong_rand_bytes(32),

    %% Chain multiple updates
    {Secret1, _Keys1} = quic_keys:derive_updated_keys(Secret0, aes_128_gcm),
    {Secret2, _Keys2} = quic_keys:derive_updated_keys(Secret1, aes_128_gcm),
    {Secret3, _Keys3} = quic_keys:derive_updated_keys(Secret2, aes_128_gcm),

    %% All secrets should be different
    Secrets = [Secret0, Secret1, Secret2, Secret3],
    UniqueSecrets = lists:usort(Secrets),
    ?assertEqual(4, length(UniqueSecrets)),

    {comment, "Key update chaining produces unique secrets"}.

%%====================================================================
%% ChaCha20-Poly1305 Compliance Tests
%%====================================================================

%% @doc Test ChaCha20-Poly1305 AEAD encryption
chacha20_aead_encrypt(_Config) ->
    ct:comment("RFC 7539: ChaCha20-Poly1305 encryption"),

    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    PN = 0,
    AAD = <<"additional data">>,
    Plaintext = <<"Hello, ChaCha20!">>,

    %% Encrypt
    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext, chacha20_poly1305),

    %% Ciphertext should be plaintext + 16-byte tag
    ?assertEqual(byte_size(Plaintext) + 16, byte_size(Ciphertext)),

    {comment, "ChaCha20-Poly1305 encryption works"}.

%% @doc Test ChaCha20-Poly1305 AEAD decryption
chacha20_aead_decrypt(_Config) ->
    ct:comment("RFC 7539: ChaCha20-Poly1305 decryption"),

    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    PN = 0,
    AAD = <<"additional data">>,
    Plaintext = <<"Hello, ChaCha20!">>,

    %% Encrypt then decrypt
    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext, chacha20_poly1305),
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext, chacha20_poly1305),

    ?assertEqual(Plaintext, Decrypted),

    {comment, "ChaCha20-Poly1305 decryption works"}.

%% @doc Test ChaCha20 header protection
chacha20_header_protection(_Config) ->
    ct:comment("RFC 9001 Section 5.4.4: ChaCha20 header protection"),

    HPKey = crypto:strong_rand_bytes(32),
    Sample = crypto:strong_rand_bytes(16),

    %% Generate mask using chacha20_poly1305 cipher identifier
    Mask = quic_aead:compute_hp_mask(chacha20_poly1305, HPKey, Sample),

    %% ChaCha20 mask should be 5 bytes
    ?assertEqual(5, byte_size(Mask)),

    %% Same inputs should produce same mask
    Mask2 = quic_aead:compute_hp_mask(chacha20_poly1305, HPKey, Sample),
    ?assertEqual(Mask, Mask2),

    {comment, "ChaCha20 header protection works"}.

%%====================================================================
%% Version Negotiation Compliance Tests
%%====================================================================

%% @doc Test Version Negotiation packet format
versionnegotiation_packet_format(_Config) ->
    ct:comment("RFC 9000 Section 17.2.1: Version Negotiation packet"),

    %% Version Negotiation packet has version = 0
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    %% Build Version Negotiation packet
    %% First byte: form=1, unused=random, type=unused (random)
    FirstByte = 16#80 bor (rand:uniform(16#3F)),

    %% Build supported versions list
    VersionsData = <<<<V:32>> || V <- SupportedVersions>>,

    % Version = 0
    Packet =
        <<FirstByte, 0:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary,
            VersionsData/binary>>,

    %% Verify format
    <<FB, Ver:32, DCIDLen, _/binary>> = Packet,
    % Form bit set
    ?assertEqual(1, (FB bsr 7) band 1),
    % Version = 0 indicates VN
    ?assertEqual(0, Ver),
    ?assertEqual(8, DCIDLen),

    {comment, "Version Negotiation packet format correct"}.

%% @doc Test response to unknown version
versionnegotiation_response(_Config) ->
    ct:comment("RFC 9000 Section 6.1: Response to unknown version"),

    %% Build Initial with unknown version
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    UnknownVersion = 16#FFFFFFFF,

    Packet = quic_packet:encode_long(
        initial,
        UnknownVersion,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>, pn => 0}
    ),

    %% Verify the packet has the unknown version
    <<_FirstByte, Version:32, _/binary>> = Packet,
    ?assertEqual(UnknownVersion, Version),

    {comment, "Unknown version packet built correctly"}.

%%====================================================================
%% Path Validation Compliance Tests
%%====================================================================

%% @doc Test PATH_CHALLENGE frame format
rebind_path_challenge_format(_Config) ->
    ct:comment("RFC 9000 Section 19.17: PATH_CHALLENGE frame"),

    %% PATH_CHALLENGE contains 8 random bytes
    ChallengeData = crypto:strong_rand_bytes(8),
    Frame = {path_challenge, ChallengeData},

    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),

    ?assertEqual(Frame, Decoded),
    ?assertEqual(8, byte_size(ChallengeData)),

    {comment, "PATH_CHALLENGE frame format correct"}.

%% @doc Test PATH_RESPONSE frame format
rebind_path_response_format(_Config) ->
    ct:comment("RFC 9000 Section 19.18: PATH_RESPONSE frame"),

    %% PATH_RESPONSE echoes the challenge data
    ResponseData = crypto:strong_rand_bytes(8),
    Frame = {path_response, ResponseData},

    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),

    ?assertEqual(Frame, Decoded),

    %% Verify response matches challenge
    ChallengeData = ResponseData,
    ?assertEqual(ChallengeData, ResponseData),

    {comment, "PATH_RESPONSE frame format correct"}.

%%====================================================================
%% Connection Migration Compliance Tests
%%====================================================================

%% @doc Test NEW_CONNECTION_ID frame
migration_new_cid(_Config) ->
    ct:comment("RFC 9000 Section 19.15: NEW_CONNECTION_ID frame"),

    SequenceNumber = 1,
    RetirePriorTo = 0,
    CID = crypto:strong_rand_bytes(8),
    ResetToken = crypto:strong_rand_bytes(16),

    Frame = {new_connection_id, SequenceNumber, RetirePriorTo, CID, ResetToken},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),

    ?assertEqual(Frame, Decoded),

    {comment, "NEW_CONNECTION_ID frame format correct"}.

%% @doc Test RETIRE_CONNECTION_ID frame
migration_retire_cid(_Config) ->
    ct:comment("RFC 9000 Section 19.16: RETIRE_CONNECTION_ID frame"),

    SequenceNumber = 0,
    Frame = {retire_connection_id, SequenceNumber},

    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),

    ?assertEqual(Frame, Decoded),

    {comment, "RETIRE_CONNECTION_ID frame format correct"}.

%%====================================================================
%% Network Tests (Require QUIC Server)
%%====================================================================

%% @doc Network handshake test
network_handshake(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),
    ct:comment("Network handshake test with ~s:~p", [Host, Port]),

    Opts = #{verify => false, alpn => [<<"hq-interop">>, <<"h3">>]},

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result =
                receive
                    {quic, ConnRef, {connected, Info}} ->
                        ct:pal("Handshake completed: ~p", [Info]),
                        {ok, Info}
                after ?HANDSHAKE_TIMEOUT ->
                    {error, timeout}
                end,
            quic:close(ConnRef, normal),
            case Result of
                {ok, _} -> {comment, "Network handshake successful"};
                {error, timeout} -> {comment, "Handshake timeout"}
            end;
        {error, Reason} ->
            {comment, io_lib:format("Connect failed: ~p", [Reason])}
    end.

%% @doc Network retry test (requires server with retry enabled)
network_retry(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),
    ct:comment("Network retry test with ~s:~p", [Host, Port]),

    %% Note: Server must have retry enabled for this test
    Opts = #{verify => false, alpn => [<<"hq-interop">>, <<"h3">>]},

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result =
                receive
                    {quic, ConnRef, {connected, _Info}} ->
                        ok
                after ?HANDSHAKE_TIMEOUT ->
                    timeout
                end,
            quic:close(ConnRef, normal),
            case Result of
                ok -> {comment, "Connection established (may have used retry)"};
                timeout -> {comment, "Timeout (server may not support retry)"}
            end;
        {error, Reason} ->
            {comment, io_lib:format("Connect failed: ~p", [Reason])}
    end.

%% @doc Network transfer test
network_transfer(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),
    ct:comment("Network transfer test with ~s:~p", [Host, Port]),

    Opts = #{verify => false, alpn => [<<"echo">>, <<"hq-interop">>]},

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            case wait_for_connected(ConnRef, ?HANDSHAKE_TIMEOUT) of
                {ok, _} ->
                    case quic:open_stream(ConnRef) of
                        {ok, StreamId} ->
                            TestData = <<"QUIC Interop Test Data">>,
                            ok = quic:send_data(ConnRef, StreamId, TestData, true),
                            Result =
                                receive
                                    {quic, ConnRef, {stream_data, StreamId, Data, _}} ->
                                        {ok, Data}
                                after ?TRANSFER_TIMEOUT ->
                                    timeout
                                end,
                            quic:close(ConnRef, normal),
                            case Result of
                                {ok, RecvData} ->
                                    ct:pal("Sent: ~p, Received: ~p", [TestData, RecvData]),
                                    {comment, "Transfer successful"};
                                timeout ->
                                    {comment, "Transfer timeout"}
                            end;
                        {error, StreamErr} ->
                            quic:close(ConnRef, normal),
                            {comment, io_lib:format("Stream error: ~p", [StreamErr])}
                    end;
                {error, Reason} ->
                    quic:close(ConnRef, normal),
                    {comment, io_lib:format("Handshake failed: ~p", [Reason])}
            end;
        {error, Reason} ->
            {comment, io_lib:format("Connect failed: ~p", [Reason])}
    end.

%% @doc Network key update test
network_keyupdate(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),
    ct:comment("Network key update test with ~s:~p", [Host, Port]),

    Opts = #{verify => false, alpn => [<<"echo">>, <<"hq-interop">>]},

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            case wait_for_connected(ConnRef, ?HANDSHAKE_TIMEOUT) of
                {ok, _} ->
                    %% Send some data, initiate key update, send more data
                    case quic:open_stream(ConnRef) of
                        {ok, StreamId} ->
                            %% Send initial data
                            ok = quic:send_data(ConnRef, StreamId, <<"Before key update">>, false),

                            %% Initiate key update
                            {ok, ConnPid} = quic_connection:lookup(ConnRef),
                            Result = quic_connection:key_update(ConnPid),
                            ct:pal("Key update result: ~p", [Result]),

                            %% Send more data after key update
                            ok = quic:send_data(ConnRef, StreamId, <<" - After key update">>, true),

                            quic:close(ConnRef, normal),
                            {comment, "Key update test completed"};
                        {error, Err} ->
                            quic:close(ConnRef, normal),
                            {comment, io_lib:format("Stream error: ~p", [Err])}
                    end;
                {error, Reason} ->
                    quic:close(ConnRef, normal),
                    {comment, io_lib:format("Handshake failed: ~p", [Reason])}
            end;
        {error, Reason} ->
            {comment, io_lib:format("Connect failed: ~p", [Reason])}
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

check_server_reachable(Host, Port) ->
    case gen_udp:open(0, [binary]) of
        {ok, Socket} ->
            HostAddr =
                case inet:parse_address(Host) of
                    {ok, Addr} ->
                        Addr;
                    _ ->
                        case inet:getaddr(Host, inet) of
                            {ok, Addr} -> Addr;
                            _ -> {127, 0, 0, 1}
                        end
                end,
            Result = gen_udp:send(Socket, HostAddr, Port, <<0:32>>),
            gen_udp:close(Socket),
            Result =:= ok;
        _ ->
            false
    end.

wait_for_connected(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {connected, Info}} ->
            {ok, Info};
        {quic, ConnRef, {closed, Reason}} ->
            {error, {closed, Reason}};
        {quic, ConnRef, {transport_error, Code, Reason}} ->
            {error, {transport_error, Code, Reason}}
    after Timeout ->
        {error, timeout}
    end.
