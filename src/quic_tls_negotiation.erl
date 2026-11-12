%%% -*- erlang -*-
%%%
%%% TLS 1.3 negotiation choices: cipher suite, ALPN protocol, and
%%% key-exchange group.
%%%
%%% Functions over what the ClientHello offered and what this
%%% endpoint is configured to accept. They decide; `quic_connection'
%%% acts on the decision.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_tls_negotiation).

-include("quic.hrl").

-export([
    select_cipher/2,
    select_cipher/3,
    known_external_psk/2,
    cipher_code_to_atom/1,
    cipher_atom_to_code/1,
    negotiate_alpn/2,
    extract_group_key/2,
    group_atom/1,
    select_key_share_group/3
]).

%% @doc Server: select a cipher suite from the client's list.
%%
%% ClientCipherSuites is a list of TLS cipher suite codes (integers),
%% converted to atoms for internal use. The server's own order decides,
%% so a deployment that must not negotiate a particular suite can say so;
%% without this the preference was fixed in code and a `ciphers' option
%% had nowhere to take effect. `none' when the two lists share no suite.
-spec select_cipher([integer()], [atom()]) -> atom() | none.
select_cipher(ClientCipherSuites, ServerPreference) ->
    ClientCiphers = [cipher_code_to_atom(C) || C <- ClientCipherSuites],
    %% A client that puts ChaCha20-Poly1305 first is saying it lacks
    %% AES hardware; honour that when the server allows the suite
    %% (the same rule as OpenSSL's SSL_OP_PRIORITIZE_CHACHA).
    case ClientCiphers of
        [chacha20_poly1305 | _] ->
            case lists:member(chacha20_poly1305, ServerPreference) of
                true -> chacha20_poly1305;
                false -> select_first_match(ServerPreference, ClientCiphers)
            end;
        _ ->
            select_first_match(ServerPreference, ClientCiphers)
    end.

%% @doc Server: as `select_cipher/2', preferring a suite of the PSK's `Hash' (RFC 9846 §4.3.11).
-spec select_cipher([integer()], [atom()], sha256 | sha384 | undefined) -> atom() | none.
select_cipher(ClientCipherSuites, ServerPreference, undefined) ->
    select_cipher(ClientCipherSuites, ServerPreference);
select_cipher(ClientCipherSuites, ServerPreference, Hash) ->
    OfHash = [C || C <- ServerPreference, quic_crypto:cipher_to_hash(C) =:= Hash],
    case select_cipher(ClientCipherSuites, OfHash) of
        none -> select_cipher(ClientCipherSuites, ServerPreference);
        Cipher -> Cipher
    end.

%% @doc Server: the first offered external PSK `PskConfig' knows, each identity looked up once.
-spec known_external_psk(map(), map() | undefined) ->
    {ok, #{identity_idx := non_neg_integer(), identity := binary(), secret := binary()}} | none.
known_external_psk(#{pre_shared_key := #{identities := Identities}}, #{} = PskConfig) ->
    find_known_psk(Identities, 0, PskConfig);
known_external_psk(_ClientHello, _PskConfig) ->
    none.

find_known_psk([], _Idx, _PskConfig) ->
    none;
find_known_psk([{Identity, _Age} | Rest], Idx, PskConfig) ->
    case lookup_psk_secret(Identity, PskConfig) of
        {ok, Secret} -> {ok, #{identity_idx => Idx, identity => Identity, secret => Secret}};
        not_found -> find_known_psk(Rest, Idx + 1, PskConfig)
    end.

lookup_psk_secret(Identity, #{psk_callback := Fn} = Config) when is_function(Fn, 1) ->
    case safe_callback(Fn, Identity) of
        {ok, Secret} when is_binary(Secret) ->
            {ok, Secret};
        _ ->
            lookup_in_psk_map(Identity, Config)
    end;
lookup_psk_secret(Identity, Config) ->
    lookup_in_psk_map(Identity, Config).

lookup_in_psk_map(Identity, #{psks := Map}) when is_map(Map) ->
    case maps:find(Identity, Map) of
        {ok, Secret} when is_binary(Secret) -> {ok, Secret};
        _ -> not_found
    end;
lookup_in_psk_map(_Identity, _) ->
    not_found.

safe_callback(Fn, Identity) ->
    try Fn(Identity) of
        Result -> Result
    catch
        Class:Reason:Stack ->
            logger:warning(
                #{
                    what => psk_callback_failed,
                    class => Class,
                    reason => Reason,
                    stack => Stack
                },
                #{domain => [erlang_quic, tls]}
            ),
            not_found
    end.

select_first_match([], _) ->
    none;
select_first_match([Cipher | Rest], ClientSuites) ->
    case lists:member(Cipher, ClientSuites) of
        true -> Cipher;
        false -> select_first_match(Rest, ClientSuites)
    end.

%% @doc Convert a TLS cipher suite code to its internal atom.
-spec cipher_code_to_atom(integer()) -> atom().
cipher_code_to_atom(?TLS_AES_128_GCM_SHA256) -> aes_128_gcm;
cipher_code_to_atom(?TLS_AES_256_GCM_SHA384) -> aes_256_gcm;
cipher_code_to_atom(?TLS_CHACHA20_POLY1305_SHA256) -> chacha20_poly1305;
cipher_code_to_atom(_) -> unknown.

%% @doc Convert an internal cipher atom to its TLS cipher suite code.
%%
%% Used when building ServerHello to send the correct suite to the client.
-spec cipher_atom_to_code(atom()) -> integer().
cipher_atom_to_code(aes_128_gcm) -> ?TLS_AES_128_GCM_SHA256;
cipher_atom_to_code(aes_256_gcm) -> ?TLS_AES_256_GCM_SHA384;
cipher_atom_to_code(chacha20_poly1305) -> ?TLS_CHACHA20_POLY1305_SHA256;
cipher_atom_to_code(_) -> ?TLS_AES_128_GCM_SHA256.

%% @doc Server: pick the first server protocol the client also offered.
-spec negotiate_alpn([binary()], [binary()]) -> binary() | undefined.
negotiate_alpn(ClientALPN, ServerALPN) ->
    case [A || A <- ServerALPN, lists:member(A, ClientALPN)] of
        [First | _] -> First;
        [] -> undefined
    end.

%% @doc Extract the client's key_share public key for a given group atom.
-spec extract_group_key(atom(), [{integer(), binary()}] | undefined) -> binary() | undefined.
extract_group_key(_Group, undefined) ->
    undefined;
extract_group_key(_Group, []) ->
    undefined;
extract_group_key(Group, [{Code, PubKey} | Rest]) ->
    case group_atom(Code) of
        Group -> PubKey;
        _ -> extract_group_key(Group, Rest)
    end.

%% @doc Named-group wire code to atom. An unknown code stays an integer.
-spec group_atom(integer()) -> atom() | integer().
group_atom(?GROUP_X25519) -> x25519;
group_atom(?GROUP_SECP256R1) -> secp256r1;
group_atom(?GROUP_SECP384R1) -> secp384r1;
group_atom(?GROUP_X25519MLKEM768) -> x25519mlkem768;
group_atom(Other) -> Other.

%% @doc Decide the key-exchange group for a ClientHello (RFC 9846 §4.2.4).
%%
%% Returns `{direct, Group}' when the client already sent a usable
%% key_share, `{hrr, Group}' when a HelloRetryRequest is needed, or
%% `none' when there is no group both sides support.
-spec select_key_share_group([atom()], [{integer(), binary()}] | undefined, [atom()]) ->
    {direct, atom()} | {hrr, atom()} | none.
select_key_share_group(ServerGroups, KeyShareEntries, SupportedGroups) ->
    Offered = [group_atom(C) || {C, _} <- entries_or_empty(KeyShareEntries)],
    case first_in(ServerGroups, Offered) of
        {ok, G} ->
            {direct, G};
        none ->
            case first_in(ServerGroups, SupportedGroups) of
                {ok, G} -> {hrr, G};
                none -> none
            end
    end.

entries_or_empty(undefined) -> [];
entries_or_empty(L) when is_list(L) -> L.

%% First element of Prefs that also appears in Avail.
first_in([], _Avail) ->
    none;
first_in([P | Rest], Avail) ->
    case lists:member(P, Avail) of
        true -> {ok, P};
        false -> first_in(Rest, Avail)
    end.
