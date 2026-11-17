%%% -*- erlang -*-
%%%
%%% What a connection stops holding once its handshake is confirmed.

-module(quic_handshake_release_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).

%% RFC 9846 Section 7.1: a secret is erased once what is derived from it
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

%% The Negotiated cipher names the AEAD; its HP cipher is derived. Any
%% AES-128 AEAD or ECB context left in the connection process is a
%% discarded Initial or Handshake key's.
no_initial_cipher_contexts(Conn) ->
    {_, #state{app_keys = {#crypto_keys{cipher = Negotiated}, _}}} = sys:get_state(Conn),
    InitialCiphers = [aes_128_gcm, aes_128_ecb],
    [] =:=
        [
            K
         || {K, _} <- element(2, process_info(Conn, dictionary)),
            tuple_size(K) =:= 3 orelse tuple_size(K) =:= 2,
            lists:member(initial_cipher(K), InitialCiphers),
            K =/= {aead_ctx, Negotiated, false} andalso K =/= {aead_ctx, Negotiated, true}
        ].

initial_cipher({qc_enc, C, _}) -> C;
initial_cipher({qc_dec, C, _}) -> C;
initial_cipher({qc_hp, C, _}) -> C;
initial_cipher({aead_ctx, C, _}) -> C;
initial_cipher({hp_ctx, C}) -> C;
initial_cipher(_) -> none.

%% Discarded Initial/Handshake keys leave no AES-128 context on either
%% cache. Meaningful only when the connection negotiated a different
%% suite, where every AES-128 entry is by definition a discarded key's
%% (RFC 9001 Section 4.9.1: Initial keys go once a Handshake packet is
%% used, Section 4.9.2: Handshake keys go at confirmation). Fails on
%% main on both paths: the NIF-path entries survive discard/1 for
%% nothing, and the default-path maps are never touched by it.
released_leaves_no_initial_cipher_contexts_test() ->
    {ok, #{name := Name, port := Port} = Srv} =
        quic_test_echo_server:start(#{ciphers => [aes_256_gcm]}),
    try
        Opts = quic_test_echo_server:client_opts(),
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(connect_timeout)
        end,
        receive
            {quic, Conn, {session_ticket, _}} -> ok
        after 5000 -> error(no_ticket)
        end,
        ?assert(quic_test_wait:until(fun() -> released(Conn) end, 5000)),
        {ok, [Server]} = quic:get_server_connections(Name),
        ?assert(quic_test_wait:until(fun() -> released(Server) end, 5000)),
        %% Both sides negotiated AES-256: every AES-128 entry in the
        %% process dictionaries is a discarded key's context.
        ?assert(no_initial_cipher_contexts(Conn)),
        ?assert(no_initial_cipher_contexts(Server)),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Srv)
    end.

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

%% The default (no-NIF) path caches cipher contexts under
%% {aead_ctx, Cipher, Enc} and {hp_ctx, EcbCipher} maps
%% (quic_aead:aead_ctx/3, ecb_ctx/2). Discarding keys must drop their
%% entries from both, and only theirs, on every suite: the HP cipher
%% mapping has one clause per AEAD (RFC 9001 Section 5.4.3, Section
%% 5.4.4). Fails on main, where discard/1 never reaches these maps.
default_path_discard_drops_only_those_contexts_test() ->
    %% aead_ctx/3 caches only where the running OTP has the context
    %% API; the ECB cache always exists. Pin the NIF off so the OTP
    %% path is the one under test.
    erlang:erase(),
    erlang:put(qc_nif, false),
    lists:foreach(
        fun default_path_discard_case/1, [aes_128_gcm, aes_256_gcm, chacha20_poly1305]
    ),
    erlang:erase().

has_aead_ctx_api() ->
    lists:member({crypto_one_time_aead_init, 4}, crypto:module_info(exports)).

default_path_discard_case(Cipher) -> default_path_discard_case(Cipher, has_aead_ctx_api()).

default_path_discard_case(Cipher, HasAeadCtxApi) ->
    KeyLen =
        case Cipher of
            aes_128_gcm -> 16;
            _ -> 32
        end,
    Keys = fun() ->
        #crypto_keys{
            key = crypto:strong_rand_bytes(KeyLen),
            iv = ?IV,
            hp = crypto:strong_rand_bytes(KeyLen),
            cipher = Cipher
        }
    end,
    {Old1, Old2, Kept} = {Keys(), Keys(), Keys()},
    %% Populate both caches for all three keys: seal/open for the AEAD
    %% contexts (context API only), one HP block each.
    Use = fun(K = #crypto_keys{key = Key, hp = HP}) ->
        Sealed = quic_aead_ctx:aead_encrypt(Cipher, Key, ?IV, <<"payload">>, <<>>),
        <<"payload">> = quic_aead_ctx:aead_decrypt(Cipher, Key, ?IV, Sealed, <<>>),
        %% The HP path production takes: quic_aead:compute_hp_mask/3
        %% routes AES through hp_block/3 and ChaCha through
        %% crypto_one_time directly (Section 5.4.4 has no ECB step).
        _ = quic_aead:compute_hp_mask(Cipher, HP, <<0:(8 * 16)>>),
        K
    end,
    Use(Old1),
    Use(Old2),
    Use(Kept),
    ok = quic_aead_ctx:discard([Old1, Old2]),
    ok = quic_aead_ctx:discard(undefined),
    %% Every cache kind holds only the kept key's entries. The OTP AEAD
    %% maps exist exactly when the context API does.
    Dict = erlang:get(),
    AeadLeft =
        [
            K
         || {{aead_ctx, C, Enc} = K, _} <- Dict,
            C =:= Cipher orelse hp_cipher_of(Cipher) =:= C,
            Enc =:= true orelse Enc =:= false
        ],
    case HasAeadCtxApi of
        true ->
            ?assertEqual(
                lists:sort([{aead_ctx, Cipher, true}, {aead_ctx, Cipher, false}]),
                lists:sort(AeadLeft)
            );
        false ->
            ?assertEqual([], AeadLeft)
    end,
    HpCipher = hp_cipher_of(Cipher),
    ?assertEqual(
        case Cipher of
            chacha20_poly1305 -> [];
            _ -> [{hp_ctx, HpCipher}]
        end,
        [K || {K, _} <- Dict, K =:= {hp_ctx, HpCipher}]
    ),
    case HasAeadCtxApi of
        true ->
            %% The kept key's entry survived the discard (its context
            %% is an opaque NIF resource; only its presence matters).
            ?assert(
                maps:is_key(
                    quic_aead_ctx:key_id(Kept#crypto_keys.key),
                    erlang:get({aead_ctx, Cipher, true})
                )
            );
        false ->
            ok
    end,
    %% The kept key still seals: its contexts survived.
    Sealed = quic_aead_ctx:aead_encrypt(Cipher, Kept#crypto_keys.key, ?IV, <<"again">>, <<>>),
    <<"again">> = quic_aead_ctx:aead_decrypt(
        Cipher, Kept#crypto_keys.key, ?IV, Sealed, <<>>
    ).

hp_cipher_of(aes_128_gcm) -> aes_128_ecb;
hp_cipher_of(aes_256_gcm) -> aes_256_ecb;
hp_cipher_of(chacha20_poly1305) -> chacha20.
