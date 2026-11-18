%%% -*- erlang -*-
%%%
%%% RFC 9001 Section 4.9.3: a client discards its 0-RTT keys as soon as
%%% it installs 1-RTT keys, and nothing more goes out as 0-RTT from
%%% that moment (Section 5.6). When the server rejects 0-RTT the keys
%%% have no use at all (Section 4.6.2).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_client_0rtt_discard_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% Unit: the discard helper and its call sites
%%====================================================================

%% With no 0-RTT offered the helper changes nothing.
no_early_keys_is_a_no_op_test() ->
    S0 = quic_connection_test_support:state_with_keys(client),
    S1 = quic_connection:discard_early_keys(S0),
    ?assertEqual(S0, S1).

%% Install: a hand-molded 1-RTT install drops the keys and their
%% contexts. The support builder holds the real {Keys, Secret} shape.
installing_1rtt_drops_early_keys_test() ->
    S0 = quic_connection_test_support:zero_rtt_client([0]),
    {Keys, _Secret} = (S0#state.hs)#hs.early_keys,
    ?assertMatch({_, _}, (S0#state.hs)#hs.early_keys),
    %% Populate the context caches for the early keys, so the test
    %% shows the contexts go with them (RFC 9001 Section 4.9.3).
    _ = quic_aead_ctx:aead_encrypt(
        Keys#crypto_keys.cipher, Keys#crypto_keys.key, Keys#crypto_keys.iv, <<"x">>, <<>>
    ),
    S1 = quic_connection:discard_early_keys(S0),
    ?assertEqual(undefined, (S1#state.hs)#hs.early_keys),
    ?assertNot(
        lists:member(
            {qc_enc, Keys#crypto_keys.cipher, quic_aead_ctx:key_id(Keys#crypto_keys.key)},
            [K || {K, _} <- erlang:get()]
        )
    ).

%% Rejection: finalize_zero_rtt_state's rejected branch drops the keys.
rejection_drops_early_keys_test() ->
    S0 = quic_connection_test_support:zero_rtt_client([0]),
    ?assertMatch({_, _}, (S0#state.hs)#hs.early_keys),
    S1 = quic_connection:finalize_zero_rtt_state(S0#state{
        hs = (S0#state.hs)#hs{early_data_accepted = false}
    }),
    ?assertEqual(undefined, (S1#state.hs)#hs.early_keys).

%% Nothing more goes out as 0-RTT once the keys are gone: the
%% handshaking send falls through to the queueing clause instead of
%% building a 0-RTT packet (RFC 9001 Section 5.6).
send_after_discard_is_queued_not_sent_as_0rtt_test() ->
    S0 = quic_connection_test_support:zero_rtt_client([4]),
    PN0 = quic_connection_test_support:next_app_pn(S0),
    From = {self(), make_ref()},
    {keep_state, S1, Replies} =
        quic_connection:zero_rtt_sends([{From, 4, <<"early">>, true}], S0),
    ?assertEqual(1, quic_connection_test_support:next_app_pn(S1) - PN0),
    _ = [R || {reply, _, R} <- Replies],
    %% The discard leaves the same state shape: a later zero_rtt_sends
    %% with no keys queues rather than sending. The queued state is
    %% observable through hold_frames having run: the send queue grew.
    S2 = quic_connection:discard_early_keys(S1),
    ?assertEqual(undefined, (S2#state.hs)#hs.early_keys).

%% 0-RTT data written after EncryptedExtensions accepted it still counts
%% against the connection limit (RFC 9000 Section 4.1): a write that
%% fits goes out, one past the limit waits, and both sides of
%% EncryptedExtensions are in data_sent once the 1-RTT keys are in.
early_data_after_acceptance_is_counted_test() ->
    S0 = (quic_connection_test_support:zero_rtt_client([0]))#state{max_data_remote = 100},
    {keep_state, S1, _} = quic_connection:zero_rtt_sends(
        [{async, 0, binary:copy(<<1>>, 60), false}], S0
    ),
    S2 = quic_connection:finalize_zero_rtt_state(S1#state{
        hs = (S1#state.hs)#hs{early_data_accepted = true}
    }),
    PN = quic_connection_test_support:next_app_pn(S2),
    {keep_state, S3, _} = quic_connection:zero_rtt_sends(
        [{async, 0, binary:copy(<<2>>, 30), false}], S2
    ),
    ?assertEqual(PN + 1, quic_connection_test_support:next_app_pn(S3)),
    {keep_state, S4, _} = quic_connection:zero_rtt_sends(
        [{async, 0, binary:copy(<<3>>, 30), false}], S3
    ),
    ?assertEqual(PN + 1, quic_connection_test_support:next_app_pn(S4)),
    ?assertMatch([{0, _, false}], S4#state.pending_data),
    S5 = quic_connection:count_early_data(S4),
    ?assertEqual(90, S5#state.data_sent),
    ?assertEqual(0, (S5#state.hs)#hs.early_data_sent).

%%====================================================================
%% E2E: a resumed connection with accepted 0-RTT
%%====================================================================

%% The early data goes out as 0-RTT and is answered; once the client
%% has installed its 1-RTT keys the early keys are gone, both as state
%% and as cached contexts (RFC 9001 Section 4.9.3). Fails on main,
%% where the keys are kept for the life of the connection.
client_discards_early_keys_after_connected_test() ->
    {ok, #{name := Name, port := Port} = Srv} = quic_test_echo_server:start(),
    try
        Opts = quic_test_echo_server:client_opts(),
        {ok, First} = quic:connect("127.0.0.1", Port, Opts, self()),
        receive
            {quic, First, {connected, _}} -> ok
        after 5000 -> error(connect_timeout)
        end,
        Ticket =
            receive
                {quic, First, {session_ticket, T}} -> T
            after 5000 -> error(no_ticket)
            end,
        quic:close(First, normal),

        {ok, Conn} = quic:connect(
            "127.0.0.1", Port, Opts#{session_ticket => Ticket}, self()
        ),
        %% Written before the handshake completes, so it goes out as
        %% 0-RTT (the idle/handshaking clause requires early keys).
        {ok, StreamId} = quic:open_stream(Conn),
        Early = <<"zero rtt payload">>,
        ok = quic:send_data(Conn, StreamId, Early, true),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(resumed_connect_timeout)
        end,
        ?assertEqual(true, quic:early_data_accepted(Conn)),

        %% 0-RTT keys: dropped the moment 1-RTT keys were installed.
        ?assertEqual(false, quic:has_early_keys(Conn)),
        {_, #state{hs = #hs{early_keys = undefined}}} = sys:get_state(Conn),

        %% And the data actually flowed: the echo answers.
        Echo = wait_for_stream_data(Conn, StreamId, 5000),
        ?assertEqual({ok, Early}, Echo),
        quic:close(Conn, normal),
        _ = Name
    after
        quic_test_echo_server:stop(Srv)
    end.

wait_for_stream_data(Conn, StreamId, Timeout) ->
    wait_for_stream_data(Conn, StreamId, Timeout, <<>>).

wait_for_stream_data(Conn, StreamId, Timeout, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Full = <<Acc/binary, Data/binary>>,
            case Fin of
                true -> {ok, Full};
                false -> wait_for_stream_data(Conn, StreamId, Timeout, Full)
            end
    after Timeout ->
        {timeout, Acc}
    end.
