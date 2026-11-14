%%% -*- erlang -*-
%%%
%%% What a connection stops holding once its handshake is confirmed.

-module(quic_handshake_release_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).

%% RFC 8446 Section 7.1: a secret is erased once what is derived from it
%% has been, and RFC 9001 Section 4.9.2 discards the Handshake keys. The
%% client still gets a session ticket it can resume with: its secret is
%% derived before the transcript goes.
released_after_confirmation_test_() ->
    {timeout, 60, fun released_after_confirmation/0}.

released_after_confirmation() ->
    {ok, #{name := Name, port := Port} = Srv} = quic_test_echo_server:start(),
    try
        Opts = quic_test_echo_server:client_opts(),
        {Conn, Ticket} = connect(Port, Opts),
        ?assert(quic_test_wait:until(fun() -> released(Conn) end, 5000)),
        {ok, [Server]} = quic:get_server_connections(Name),
        ?assert(quic_test_wait:until(fun() -> released(Server) end, 5000)),
        quic:close(Conn, normal),
        ?assert(
            quic_test_wait:until(fun() -> quic:get_server_connections(Name) =:= {ok, []} end, 5000)
        ),
        {Resumed, _} = connect(Port, Opts#{session_ticket => Ticket}),
        {ok, [ResumedServer]} = quic:get_server_connections(Name),
        {_, #state{hs = #hs{selected_psk = Psk}}} = sys:get_state(ResumedServer),
        ?assertNotEqual(undefined, Psk),
        quic:close(Resumed, normal)
    after
        quic_test_echo_server:stop(Srv)
    end.

connect(Port, Opts) ->
    {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
    receive
        {quic, Conn, {connected, _}} -> ok
    after 5000 -> error(connect_timeout)
    end,
    receive
        {quic, Conn, {session_ticket, Ticket}} -> {Conn, Ticket}
    after 5000 -> error(no_ticket)
    end.

released(Conn) ->
    {_, #state{hs = Hs}} = sys:get_state(Conn),
    Hs#hs.tls_transcript =:= <<>> andalso
        Hs#hs.master_secret =:= undefined andalso
        Hs#hs.handshake_secret =:= undefined andalso
        Hs#hs.client_hs_secret =:= undefined andalso
        Hs#hs.server_hs_secret =:= undefined andalso
        Hs#hs.tls_private_key =:= undefined andalso
        Hs#hs.server_private_key =:= undefined andalso
        Hs#hs.handshake_keys =:= undefined andalso
        Hs#hs.initial_keys =:= undefined andalso
        length([
            K
         || {{Kind, _, _} = K, _} <- element(2, process_info(Conn, dictionary)),
            Kind =:= qc_enc orelse Kind =:= qc_dec orelse Kind =:= qc_hp
        ]) =< 4.

%% Discarding a level's keys drops their cached contexts and no others.
discard_drops_only_those_contexts_test() ->
    case quic_crypto_nif:is_loaded() of
        false ->
            ok;
        true ->
            [
                erlang:erase(K)
             || {K, _} <- erlang:get(), K =:= qc_ctx_live orelse tuple_size(K) =:= 3
            ],
            Keys = fun() ->
                #crypto_keys{
                    key = crypto:strong_rand_bytes(16),
                    iv = ?IV,
                    hp = crypto:strong_rand_bytes(16),
                    cipher = aes_128_gcm
                }
            end,
            Use = fun(#crypto_keys{key = Key, hp = HP}) ->
                Sealed = quic_aead_ctx:aead_encrypt(aes_128_gcm, Key, ?IV, <<"payload">>, <<>>),
                <<"payload">> = quic_aead_ctx:aead_decrypt(aes_128_gcm, Key, ?IV, Sealed, <<>>),
                _ = quic_aead_ctx:hp_block(aes_128_ecb, HP, <<0:128>>)
            end,
            {Old1, Old2, Kept} = {Keys(), Keys(), Keys()},
            Use(Kept),
            Use(Old1),
            ok = quic_aead_ctx:discard({Old1, Old2}),
            ok = quic_aead_ctx:discard(undefined),
            Left = [K || {{_, _, _} = K, _} <- erlang:get()],
            ?assertEqual(
                lists:sort([
                    {qc_enc, aes_128_gcm, quic_aead_ctx:key_id(Kept#crypto_keys.key)},
                    {qc_dec, aes_128_gcm, quic_aead_ctx:key_id(Kept#crypto_keys.key)},
                    {qc_hp, aes_128_ecb, quic_aead_ctx:key_id(Kept#crypto_keys.hp)}
                ]),
                lists:sort(Left)
            ),
            ?assertEqual(lists:sort(Left), lists:sort(erlang:get(qc_ctx_live))),
            Use(Old1)
    end.
