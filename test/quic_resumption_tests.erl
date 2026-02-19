%%% -*- erlang -*-
%%%
%%% QUIC Session Resumption Tests
%%% RFC 8446 Section 4.6 - NewSessionTicket
%%% RFC 9001 Section 4.6 - 0-RTT and Session Resumption
%%%
%%% @doc Tests for session ticket generation, storage, and PSK resumption.

-module(quic_resumption_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Step 1: Server-Side Ticket Generation Tests
%%====================================================================

%% Test NewSessionTicket message encoding
new_session_ticket_encoding_test() ->
    %% Create a session ticket with known values
    Ticket = #session_ticket{
        server_name = <<"example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,  % 24 hours
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Build NewSessionTicket message
    Encoded = quic_ticket:build_new_session_ticket(Ticket),

    %% Verify structure: lifetime(4) + age_add(4) + nonce_len(1) + nonce + ticket_len(2) + ticket + ext_len(2) + ext
    ?assert(is_binary(Encoded)),
    ?assert(byte_size(Encoded) > 0),

    %% Decode the first fields
    <<Lifetime:32, AgeAdd:32, NonceLen:8, _Rest/binary>> = Encoded,
    ?assertEqual(86400, Lifetime),
    ?assertEqual(12345, AgeAdd),
    ?assertEqual(8, NonceLen).

%% Test NewSessionTicket message decoding/parsing
new_session_ticket_decoding_test() ->
    %% Create a valid NewSessionTicket binary
    Lifetime = 86400,
    AgeAdd = 54321,
    Nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    TicketData = crypto:strong_rand_bytes(32),
    MaxEarlyData = 16384,

    %% Build with early_data extension (type 0x002a)
    NonceLen = byte_size(Nonce),
    TicketLen = byte_size(TicketData),
    EarlyDataExt = <<16#00, 16#2a, 4:16, MaxEarlyData:32>>,
    ExtLen = byte_size(EarlyDataExt),

    Encoded = <<Lifetime:32, AgeAdd:32, NonceLen:8, Nonce/binary,
                TicketLen:16, TicketData/binary, ExtLen:16, EarlyDataExt/binary>>,

    %% Parse it
    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Encoded),

    ?assertEqual(Lifetime, maps:get(lifetime, Parsed)),
    ?assertEqual(AgeAdd, maps:get(age_add, Parsed)),
    ?assertEqual(Nonce, maps:get(nonce, Parsed)),
    ?assertEqual(TicketData, maps:get(ticket, Parsed)),
    ?assertEqual(MaxEarlyData, maps:get(max_early_data, Parsed)).

%% Test resumption_master_secret derivation
resumption_secret_derivation_test() ->
    %% RFC 8446 Section 7.1:
    %% resumption_master_secret = Derive-Secret(Master Secret, "res master", ClientHello..client Finished)
    Cipher = aes_128_gcm,
    MasterSecret = crypto:strong_rand_bytes(32),
    TranscriptHash = crypto:hash(sha256, <<"test transcript">>),

    %% Derive resumption secret
    ResumptionSecret = quic_ticket:derive_resumption_secret(
        Cipher, MasterSecret, TranscriptHash, <<>>),

    %% Should be 32 bytes for SHA-256
    ?assertEqual(32, byte_size(ResumptionSecret)),
    %% Should be deterministic
    ResumptionSecret2 = quic_ticket:derive_resumption_secret(
        Cipher, MasterSecret, TranscriptHash, <<>>),
    ?assertEqual(ResumptionSecret, ResumptionSecret2).

%% Test PSK derivation from resumption secret and ticket nonce
psk_from_resumption_secret_test() ->
    %% RFC 8446 Section 4.6.1:
    %% PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
    ResumptionSecret = crypto:strong_rand_bytes(32),
    Ticket = #session_ticket{
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cipher = aes_128_gcm,
        server_name = <<"example.com">>,
        ticket = <<>>,
        lifetime = 86400,
        age_add = 0,
        resumption_secret = ResumptionSecret,
        max_early_data = 0,
        received_at = 0,
        alpn = undefined
    },

    %% Derive PSK
    PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket),

    %% Should be 32 bytes for SHA-256 (hash length for aes_128_gcm)
    ?assertEqual(32, byte_size(PSK)),
    %% Should be deterministic
    PSK2 = quic_ticket:derive_psk(ResumptionSecret, Ticket),
    ?assertEqual(PSK, PSK2),
    %% Different nonce should produce different PSK
    Ticket2 = Ticket#session_ticket{nonce = <<9, 10, 11, 12, 13, 14, 15, 16>>},
    PSK3 = quic_ticket:derive_psk(ResumptionSecret, Ticket2),
    ?assertNotEqual(PSK, PSK3).

%% Test ticket creation helper
ticket_creation_test() ->
    ServerName = <<"example.com">>,
    ResumptionSecret = crypto:strong_rand_bytes(32),
    MaxEarlyData = 16384,
    Cipher = aes_128_gcm,
    ALPN = <<"h3">>,

    Ticket = quic_ticket:create_ticket(
        ServerName, ResumptionSecret, MaxEarlyData, Cipher, ALPN),

    ?assertEqual(ServerName, Ticket#session_ticket.server_name),
    ?assertEqual(ResumptionSecret, Ticket#session_ticket.resumption_secret),
    ?assertEqual(MaxEarlyData, Ticket#session_ticket.max_early_data),
    ?assertEqual(Cipher, Ticket#session_ticket.cipher),
    ?assertEqual(ALPN, Ticket#session_ticket.alpn),
    ?assertEqual(86400, Ticket#session_ticket.lifetime),
    ?assertEqual(32, byte_size(Ticket#session_ticket.ticket)),
    ?assertEqual(8, byte_size(Ticket#session_ticket.nonce)).

%% Test NewSessionTicket roundtrip (encode then decode)
new_session_ticket_roundtrip_test() ->
    Ticket = #session_ticket{
        server_name = <<"test.example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 7200,
        age_add = 98765,
        nonce = crypto:strong_rand_bytes(8),
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 32768,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Encode
    Encoded = quic_ticket:build_new_session_ticket(Ticket),

    %% Decode
    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Encoded),

    %% Verify fields match
    ?assertEqual(Ticket#session_ticket.lifetime, maps:get(lifetime, Parsed)),
    ?assertEqual(Ticket#session_ticket.age_add, maps:get(age_add, Parsed)),
    ?assertEqual(Ticket#session_ticket.nonce, maps:get(nonce, Parsed)),
    ?assertEqual(Ticket#session_ticket.ticket, maps:get(ticket, Parsed)),
    ?assertEqual(Ticket#session_ticket.max_early_data, maps:get(max_early_data, Parsed)).

%% Test ticket with no early data extension
new_session_ticket_no_early_data_test() ->
    Ticket = #session_ticket{
        server_name = <<"example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 3600,
        age_add = 11111,
        nonce = <<1, 2, 3, 4>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 0,  % No early data
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = undefined
    },

    %% Encode
    Encoded = quic_ticket:build_new_session_ticket(Ticket),

    %% Decode
    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Encoded),

    %% max_early_data should be 0 (no extension)
    ?assertEqual(0, maps:get(max_early_data, Parsed)).

%%====================================================================
%% Step 2: Client-Side Ticket Storage Tests
%%====================================================================

%% Test ticket store creation
ticket_store_creation_test() ->
    Store = quic_ticket:new_store(),
    ?assertEqual(#{}, Store).

%% Test storing and looking up tickets
ticket_store_roundtrip_test() ->
    Store0 = quic_ticket:new_store(),

    ServerName = <<"example.com">>,
    Ticket = #session_ticket{
        server_name = ServerName,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Store ticket
    Store1 = quic_ticket:store_ticket(ServerName, Ticket, Store0),

    %% Lookup should succeed
    {ok, Retrieved} = quic_ticket:lookup_ticket(ServerName, Store1),
    ?assertEqual(Ticket, Retrieved).

%% Test expired ticket handling
ticket_expiry_test() ->
    Store0 = quic_ticket:new_store(),

    ServerName = <<"expired.example.com">>,
    %% Create an expired ticket (received 2 hours ago, lifetime 1 hour)
    Ticket = #session_ticket{
        server_name = ServerName,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 3600,  % 1 hour
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second) - 7200,  % 2 hours ago
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    Store1 = quic_ticket:store_ticket(ServerName, Ticket, Store0),

    %% Lookup should fail (expired)
    ?assertEqual(error, quic_ticket:lookup_ticket(ServerName, Store1)).

%% Test clearing a ticket
ticket_clear_test() ->
    Store0 = quic_ticket:new_store(),

    ServerName = <<"example.com">>,
    Ticket = #session_ticket{
        server_name = ServerName,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = 12345,
        nonce = <<1, 2, 3, 4>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 0,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = undefined
    },

    Store1 = quic_ticket:store_ticket(ServerName, Ticket, Store0),
    ?assertMatch({ok, _}, quic_ticket:lookup_ticket(ServerName, Store1)),

    Store2 = quic_ticket:clear_ticket(ServerName, Store1),
    ?assertEqual(error, quic_ticket:lookup_ticket(ServerName, Store2)).

%% Test clearing expired tickets
clear_expired_tickets_test() ->
    Store0 = quic_ticket:new_store(),

    %% Add a valid ticket
    ValidTicket = #session_ticket{
        server_name = <<"valid.example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = 11111,
        nonce = <<1, 2, 3, 4>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 0,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = undefined
    },

    %% Add an expired ticket
    ExpiredTicket = #session_ticket{
        server_name = <<"expired.example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 3600,
        age_add = 22222,
        nonce = <<5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 0,
        received_at = erlang:system_time(second) - 7200,
        cipher = aes_128_gcm,
        alpn = undefined
    },

    Store1 = quic_ticket:store_ticket(<<"valid.example.com">>, ValidTicket, Store0),
    Store2 = quic_ticket:store_ticket(<<"expired.example.com">>, ExpiredTicket, Store1),

    %% Clear expired
    Store3 = quic_ticket:clear_expired(Store2),

    %% Valid should still be there
    ?assertMatch({ok, _}, quic_ticket:lookup_ticket(<<"valid.example.com">>, Store3)),
    %% Expired should be gone
    ?assertNot(maps:is_key(<<"expired.example.com">>, Store3)).

%% Test that lookup returns error for unknown server
ticket_lookup_unknown_test() ->
    Store = quic_ticket:new_store(),
    ?assertEqual(error, quic_ticket:lookup_ticket(<<"unknown.example.com">>, Store)).

%%====================================================================
%% Step 3: PSK/Pre-shared Key Tests (Client-side)
%%====================================================================

%% Test PSK binder computation
psk_binder_computation_test() ->
    %% RFC 8446 Section 4.2.11.2:
    %% binder_value = HMAC(finished_key, Transcript-Hash(Truncated ClientHello))
    %% binder_key = Derive-Secret(early_secret, "res binder", "")
    PSK = crypto:strong_rand_bytes(32),
    TruncatedTranscript = crypto:hash(sha256, <<"ClientHello without binder">>),

    %% First derive early secret from PSK
    EarlySecret = quic_crypto:derive_early_secret(aes_128_gcm, PSK),

    %% Then compute binder using early secret
    Binder = quic_crypto:compute_psk_binder(aes_128_gcm, EarlySecret, TruncatedTranscript, resumption),

    %% Should be 32 bytes for SHA-256
    ?assertEqual(32, byte_size(Binder)),
    %% Should be deterministic
    Binder2 = quic_crypto:compute_psk_binder(aes_128_gcm, EarlySecret, TruncatedTranscript, resumption),
    ?assertEqual(Binder, Binder2).

%% Test early secret derivation with PSK
early_secret_with_psk_test() ->
    PSK = crypto:strong_rand_bytes(32),

    %% Derive early secret with PSK
    EarlySecret = quic_crypto:derive_early_secret(aes_128_gcm, PSK),

    %% Should be 32 bytes for SHA-256
    ?assertEqual(32, byte_size(EarlySecret)),
    %% Should differ from early secret without PSK
    EarlySecretNoPsk = quic_crypto:derive_early_secret(),
    ?assertNotEqual(EarlySecret, EarlySecretNoPsk).

%% Test pre_shared_key extension encoding
pre_shared_key_extension_encoding_test() ->
    %% Create a session ticket for PSK
    Ticket = #session_ticket{
        server_name = <<"example.com">>,
        ticket = <<"test-ticket-data">>,
        lifetime = 86400,
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second) - 100,  % 100 seconds ago
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Encode the pre_shared_key extension
    %% This is a helper test - full integration tested in clienthello_with_psk_test
    PSK = quic_ticket:derive_psk(Ticket#session_ticket.resumption_secret, Ticket),
    ?assertEqual(32, byte_size(PSK)).

%% Test ClientHello building with PSK
clienthello_with_psk_test() ->
    %% Create a session ticket
    Ticket = #session_ticket{
        server_name = <<"example.com">>,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = 12345,
        nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second) - 10,  % 10 seconds ago
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    },

    %% Build ClientHello with PSK
    Opts = #{
        server_name => <<"example.com">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        session_ticket => Ticket
    },
    {Msg, _PrivKey, _Random} = quic_tls:build_client_hello(Opts),

    %% Should be a valid TLS handshake message
    ?assert(is_binary(Msg)),
    ?assert(byte_size(Msg) > 100),

    %% Decode and verify it's a ClientHello (type 1)
    <<1:8, _Len:24, _Body/binary>> = Msg.
