%%% -*- erlang -*-
%%%
%%% Tests for QUIC Session Tickets
%%% RFC 9001 Section 4.6
%%%

-module(quic_ticket_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Ticket Store Tests
%%====================================================================

ticket_store_empty_test() ->
    Store = quic_ticket:new_store(),
    ?assertEqual(error, quic_ticket:lookup_ticket(<<"example.com">>, Store)).

ticket_store_roundtrip_test() ->
    Store = quic_ticket:new_store(),

    %% Create a session ticket
    Ticket = create_test_ticket(<<"example.com">>),

    %% Store it
    Store1 = quic_ticket:store_ticket(<<"example.com">>, Ticket, Store),

    %% Look it up
    {ok, Retrieved} = quic_ticket:lookup_ticket(<<"example.com">>, Store1),
    ?assertEqual(<<"example.com">>, Retrieved#session_ticket.server_name).

ticket_store_clear_test() ->
    Store = quic_ticket:new_store(),
    Ticket = create_test_ticket(<<"example.com">>),
    Store1 = quic_ticket:store_ticket(<<"example.com">>, Ticket, Store),

    %% Clear the ticket
    Store2 = quic_ticket:clear_ticket(<<"example.com">>, Store1),

    %% Should no longer be found
    ?assertEqual(error, quic_ticket:lookup_ticket(<<"example.com">>, Store2)).

ticket_store_multiple_test() ->
    Store = quic_ticket:new_store(),
    Ticket1 = create_test_ticket(<<"example.com">>),
    Ticket2 = create_test_ticket(<<"other.com">>),

    Store1 = quic_ticket:store_ticket(<<"example.com">>, Ticket1, Store),
    Store2 = quic_ticket:store_ticket(<<"other.com">>, Ticket2, Store1),

    {ok, R1} = quic_ticket:lookup_ticket(<<"example.com">>, Store2),
    {ok, R2} = quic_ticket:lookup_ticket(<<"other.com">>, Store2),

    ?assertEqual(<<"example.com">>, R1#session_ticket.server_name),
    ?assertEqual(<<"other.com">>, R2#session_ticket.server_name).

%%====================================================================
%% PSK Derivation Tests
%%====================================================================

psk_derivation_test() ->
    %% Test that PSK derivation produces correct-length output
    ResumptionSecret = crypto:strong_rand_bytes(32),
    Ticket = create_test_ticket(<<"example.com">>),
    Ticket1 = Ticket#session_ticket{resumption_secret = ResumptionSecret},

    PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket1),
    ?assertEqual(32, byte_size(PSK)).

psk_derivation_deterministic_test() ->
    ResumptionSecret = crypto:strong_rand_bytes(32),
    Nonce = crypto:strong_rand_bytes(8),
    Ticket = #session_ticket{
        server_name = <<"example.com">>,
        nonce = Nonce,
        cipher = aes_128_gcm,
        resumption_secret = ResumptionSecret,
        lifetime = 86400,
        received_at = erlang:system_time(second),
        max_early_data = 0,
        age_add = 0,
        ticket = <<>>
    },

    PSK1 = quic_ticket:derive_psk(ResumptionSecret, Ticket),
    PSK2 = quic_ticket:derive_psk(ResumptionSecret, Ticket),
    ?assertEqual(PSK1, PSK2).

psk_derivation_aes_256_test() ->
    %% AES-256-GCM uses SHA-384, so PSK should be 48 bytes
    ResumptionSecret = crypto:strong_rand_bytes(48),
    Ticket = create_test_ticket(<<"example.com">>),
    Ticket1 = Ticket#session_ticket{cipher = aes_256_gcm},

    PSK = quic_ticket:derive_psk(ResumptionSecret, Ticket1),
    ?assertEqual(48, byte_size(PSK)).

%%====================================================================
%% NewSessionTicket Parsing Tests
%%====================================================================

parse_new_session_ticket_basic_test() ->
    %% Build a simple NewSessionTicket message
    Lifetime = 86400,
    AgeAdd = 12345,
    Nonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Ticket = <<"session_ticket_data">>,
    TicketLen = byte_size(Ticket),
    NonceLen = byte_size(Nonce),

    %% No extensions
    Message = <<Lifetime:32, AgeAdd:32, NonceLen, Nonce/binary, TicketLen:16, Ticket/binary, 0:16>>,

    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Message),
    ?assertEqual(Lifetime, maps:get(lifetime, Parsed)),
    ?assertEqual(AgeAdd, maps:get(age_add, Parsed)),
    ?assertEqual(Nonce, maps:get(nonce, Parsed)),
    ?assertEqual(Ticket, maps:get(ticket, Parsed)),
    ?assertEqual(0, maps:get(max_early_data, Parsed)).

parse_new_session_ticket_with_early_data_test() ->
    Lifetime = 3600,
    AgeAdd = 99999,
    Nonce = <<1, 2, 3, 4>>,
    Ticket = <<"ticket">>,
    MaxEarlyData = 16384,

    %% early_data extension (type 0x002a)
    EarlyDataExt = <<16#00, 16#2a, 4:16, MaxEarlyData:32>>,
    ExtLen = byte_size(EarlyDataExt),

    Message =
        <<Lifetime:32, AgeAdd:32, (byte_size(Nonce)), Nonce/binary, (byte_size(Ticket)):16,
            Ticket/binary, ExtLen:16, EarlyDataExt/binary>>,

    {ok, Parsed} = quic_ticket:parse_new_session_ticket(Message),
    ?assertEqual(MaxEarlyData, maps:get(max_early_data, Parsed)).

parse_new_session_ticket_invalid_test() ->
    %% Too short
    ?assertEqual({error, invalid_format}, quic_ticket:parse_new_session_ticket(<<1, 2, 3>>)).

%%====================================================================
%% Resumption Secret Tests
%%====================================================================

resumption_secret_derivation_test() ->
    MasterSecret = crypto:strong_rand_bytes(32),
    TranscriptHash = crypto:strong_rand_bytes(32),

    ResSecret = quic_ticket:derive_resumption_secret(
        aes_128_gcm, MasterSecret, TranscriptHash, <<>>
    ),

    ?assertEqual(32, byte_size(ResSecret)).

%%====================================================================
%% Helper Functions
%%====================================================================

create_test_ticket(ServerName) ->
    #session_ticket{
        server_name = ServerName,
        ticket = crypto:strong_rand_bytes(32),
        lifetime = 86400,
        age_add = rand:uniform(16#FFFFFFFF),
        nonce = crypto:strong_rand_bytes(8),
        resumption_secret = crypto:strong_rand_bytes(32),
        max_early_data = 16384,
        received_at = erlang:system_time(second),
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    }.
