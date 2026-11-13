%%% -*- erlang -*-
%%%
%%% QUIC-LB Connection ID Encoding
%%% draft-ietf-quic-load-balancers-22 - QUIC-LB: Generating Routable QUIC Connection IDs
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC Load Balancer Connection ID encoding and decoding.
%%%
%%% This module implements the QUIC-LB (draft-ietf-quic-load-balancers-22)
%%% Connection ID encoding schemes
%%% that allow load balancers to route QUIC packets to the correct
%%% server based on server identity encoded in the Connection ID.
%%%
%%% == CID Format ==
%%%
%%% The first byte contains:
%%% - CR (Config Rotation): 3 bits identifying the configuration
%%% - Length: 5 bits, the number of bytes after the first octet
%%%
%%% <pre>
%%% +--------+----------------+--------+
%%% | CR:3   | Server ID      | Nonce  |
%%% | Len:5  | (1-15 bytes)   | (4-18) |
%%% +--------+----------------+--------+
%%% </pre>
%%%
%%% Server ID and nonce together are at most 19 bytes (Section 5.3).
%%%
%%% == Algorithms ==
%%%
%%% 1. Plaintext: No encryption, server_id visible in CID
%%% 2. Encrypted: AES-128-ECB single pass for a 16-byte server ID and nonce,
%%%    four-pass Feistel network otherwise (draft-ietf-quic-load-balancers-22
%%%    Section 5.4)
%%%
%%% The `stream_cipher' and `block_cipher' algorithms of earlier drafts
%%% are refused with `{error, {unsupported_lb_algorithm, Algorithm}}'.
%%%
%%% @end

-module(quic_lb).

-export([
    new_config/1,
    new_cid_config/1,
    validate_config/1,
    generate_cid/1,
    generate_cid/2,
    decode_server_id/2,
    get_config_rotation/1,
    is_lb_routable/1,
    expected_cid_len/1
]).

-include("quic.hrl").

%%====================================================================
%% API
%%====================================================================

%% @doc Create a new LB configuration from options map.
%%
%% Options:
%%   - server_id: binary() (required) - Server identifier (1-15 bytes)
%%   - algorithm: plaintext | encrypted (default: plaintext)
%%   - config_rotation: 0..6 (default: 0)
%%   - nonce_len: 4..18 (default: 4)
%%   - key: binary() - 16-byte AES key (required for encrypted)
%%
%% The server ID and nonce lengths sum to 19 bytes or less.
%%
%% @returns {ok, #lb_config{}} | {error, term()}
-spec new_config(map()) -> {ok, #lb_config{}} | {error, term()}.
new_config(Opts) when is_map(Opts) ->
    try
        ServerID = maps:get(server_id, Opts),
        ServerIDLen = id_size(ServerID),
        Algorithm = maps:get(algorithm, Opts, plaintext),
        CR = maps:get(config_rotation, Opts, 0),
        NonceLen = maps:get(nonce_len, Opts, 4),
        Key = maps:get(key, Opts, undefined),

        Config = #lb_config{
            config_rotation = CR,
            algorithm = Algorithm,
            server_id = ServerID,
            server_id_len = ServerIDLen,
            nonce_len = NonceLen,
            key = Key
        },

        case validate_config(Config) of
            ok -> {ok, Config};
            {error, _} = Error -> Error
        end
    catch
        error:{badkey, server_id} ->
            {error, missing_server_id}
    end.

%% @doc Create a CID generation configuration from options map.
%%
%% Options:
%%   - lb_config: #lb_config{} | undefined - LB configuration
%%   - cid_len: 1..20 (default: 8) - Target CID length
%%   - reset_secret: binary() - Secret for reset token generation
%%
%% @returns {ok, #cid_config{}} | {error, term()}
-spec new_cid_config(map()) -> {ok, #cid_config{}} | {error, term()}.
new_cid_config(Opts) when is_map(Opts) ->
    LBConfig = maps:get(lb_config, Opts, undefined),
    CIDLen = maps:get(cid_len, Opts, 8),
    ResetSecret = maps:get(reset_secret, Opts, undefined),
    case cid_len(LBConfig, CIDLen) of
        {ok, Len} ->
            {ok, #cid_config{lb_config = LBConfig, cid_len = Len, reset_secret = ResetSecret}};
        {error, _} = Error ->
            Error
    end.

%% @private With an LB config the CID is 1 + server ID + nonce bytes;
%% the default length 8 is taken to mean that length.
cid_len(_LBConfig, CIDLen) when not is_integer(CIDLen); CIDLen < 1; CIDLen > 20 ->
    {error, {invalid_cid_len, CIDLen}};
cid_len(undefined, CIDLen) ->
    {ok, CIDLen};
cid_len(#lb_config{} = LBConfig, CIDLen) ->
    case validate_config(LBConfig) of
        ok ->
            ExpectedLen = expected_cid_len(LBConfig),
            case (CIDLen =:= ExpectedLen) orelse (CIDLen =:= 8) of
                true -> {ok, ExpectedLen};
                false -> {error, {cid_len_mismatch, CIDLen, ExpectedLen}}
            end;
        {error, _} = Error ->
            Error
    end.

%% @doc Validate an LB configuration.
-spec validate_config(#lb_config{}) -> ok | {error, term()}.
validate_config(#lb_config{
    config_rotation = CR,
    algorithm = Algorithm,
    server_id = ServerID,
    server_id_len = ServerIDLen,
    nonce_len = NonceLen,
    key = Key
}) ->
    Validations = [
        {fun() -> in_range(CR, 0, 6) end, {invalid_config_rotation, CR}},
        {
            fun() -> not lists:member(Algorithm, [stream_cipher, block_cipher]) end,
            {unsupported_lb_algorithm, Algorithm}
        },
        {
            fun() -> lists:member(Algorithm, [plaintext, encrypted]) end,
            {invalid_algorithm, Algorithm}
        },
        {fun() -> is_binary(ServerID) end, {invalid_server_id, not_binary}},
        {
            fun() -> in_range(ServerIDLen, 1, ?LB_MAX_SERVER_ID_LEN) end,
            {invalid_server_id_len, ServerIDLen}
        },
        {
            fun() -> id_size(ServerID) =:= ServerIDLen end,
            {server_id_len_mismatch, id_size(ServerID), ServerIDLen}
        },
        {
            fun() -> in_range(NonceLen, ?LB_MIN_NONCE_LEN, ?LB_MAX_NONCE_LEN) end,
            {invalid_nonce_len, NonceLen}
        },
        %% Section 5.3: at most 19 so the CID fits in 20 bytes.
        {
            fun() -> ServerIDLen + NonceLen =< ?LB_MAX_SERVER_ID_NONCE_LEN end,
            {invalid_server_id_nonce_len, ServerIDLen, NonceLen}
        },
        {
            fun() ->
                Algorithm =:= plaintext orelse (is_binary(Key) andalso byte_size(Key) =:= 16)
            end,
            {missing_or_invalid_key, Algorithm}
        }
    ],
    validate_list(Validations).

%% @doc Generate a CID using the configuration.
%% Uses a random nonce.
-spec generate_cid(#cid_config{}) -> binary().
generate_cid(#cid_config{lb_config = undefined, cid_len = Len}) ->
    crypto:strong_rand_bytes(Len);
generate_cid(#cid_config{lb_config = #lb_config{nonce_len = NonceLen}} = Config) ->
    Nonce = crypto:strong_rand_bytes(NonceLen),
    generate_cid(Config, Nonce).

%% @doc Generate a CID with an explicit nonce.
-spec generate_cid(#cid_config{}, binary()) -> binary().
generate_cid(#cid_config{lb_config = undefined, cid_len = Len}, _Nonce) ->
    crypto:strong_rand_bytes(Len);
generate_cid(#cid_config{lb_config = LBConfig}, Nonce) ->
    #lb_config{
        config_rotation = CR,
        algorithm = Algorithm,
        server_id = ServerID,
        server_id_len = ServerIDLen,
        nonce_len = NonceLen,
        key = Key
    } = LBConfig,

    %% Ensure nonce is correct length
    ActualNonce =
        case byte_size(Nonce) of
            NonceLen ->
                Nonce;
            N when N > NonceLen -> binary:part(Nonce, 0, NonceLen);
            N when N < NonceLen ->
                Pad = crypto:strong_rand_bytes(NonceLen - N),
                <<Nonce/binary, Pad/binary>>
        end,

    %% Calculate CID length (excluding first byte with CR/Len)
    CIDLen = 1 + ServerIDLen + NonceLen,

    %% First byte: CR (3 bits) | Length-1 (5 bits)
    FirstByte = (CR bsl 5) bor (CIDLen - 1),

    case Algorithm of
        plaintext ->
            encode_plaintext(FirstByte, ServerID, ActualNonce);
        encrypted ->
            <<FirstByte, (encrypt(<<ServerID/binary, ActualNonce/binary>>, Key))/binary>>
    end.

%% @doc Extract the server ID from a CID.
-spec decode_server_id(binary(), #lb_config{}) -> {ok, binary()} | {error, term()}.
decode_server_id(
    <<FirstByte, _/binary>> = CID, #lb_config{config_rotation = CR, algorithm = Algorithm} = Config
) when FirstByte bsr 5 =:= CR ->
    case Algorithm of
        plaintext ->
            decode_plaintext(CID, Config);
        encrypted ->
            decode_encrypted(CID, Config)
    end;
%% Section 3.1: the first three bits name the configuration the CID uses.
decode_server_id(<<_, _/binary>>, #lb_config{}) ->
    {error, config_rotation_mismatch};
decode_server_id(_CID, _Config) ->
    {error, cid_too_short}.

%% @doc Get the config rotation bits from a CID's first byte.
-spec get_config_rotation(binary()) -> 0..7.
get_config_rotation(<<FirstByte, _/binary>>) ->
    FirstByte bsr 5;
get_config_rotation(_) ->
    ?LB_CR_UNROUTABLE.

%% @doc Check if a CID is LB-routable (CR != 0b111).
-spec is_lb_routable(binary()) -> boolean().
is_lb_routable(CID) ->
    get_config_rotation(CID) =/= ?LB_CR_UNROUTABLE.

%% @doc Calculate the expected CID length from configuration.
-spec expected_cid_len(#lb_config{}) -> pos_integer().
expected_cid_len(#lb_config{server_id_len = ServerIDLen, nonce_len = NonceLen}) ->
    1 + ServerIDLen + NonceLen.

%%====================================================================
%% Plaintext Encoding (draft-ietf-quic-load-balancers-22 Section 5.4)
%%====================================================================

%% @private Encode plaintext CID
encode_plaintext(FirstByte, ServerID, Nonce) ->
    <<FirstByte, ServerID/binary, Nonce/binary>>.

%% @private Decode plaintext CID
decode_plaintext(<<_FirstByte, Rest/binary>>, #lb_config{server_id_len = ServerIDLen}) ->
    case Rest of
        <<ServerID:ServerIDLen/binary, _Nonce/binary>> ->
            {ok, ServerID};
        _ ->
            {error, cid_too_short}
    end.

%%====================================================================
%% Encrypted Encoding (draft-ietf-quic-load-balancers-22 Section 5.4)
%%====================================================================

%% @private A 16-byte server ID and nonce is one AES block (Section 5.4.1).
encrypt(<<_:16/binary>> = Block, Key) ->
    crypto:crypto_one_time(aes_128_ecb, Key, Block, true);
encrypt(Plain, Key) ->
    Len = byte_size(Plain),
    {L0, R0} = split_halves(Plain),
    R1 = feistel_pass(Key, Len, 1, L0, R0),
    L1 = feistel_pass(Key, Len, 2, R1, L0),
    R2 = feistel_pass(Key, Len, 3, L1, R1),
    L2 = feistel_pass(Key, Len, 4, R2, L1),
    join_halves(L2, R2, Len).

%% @private Decode an encrypted CID (Section 5.5).
decode_encrypted(
    <<_FirstByte, Rest/binary>>,
    #lb_config{server_id_len = ServerIDLen, nonce_len = NonceLen, key = Key}
) ->
    Len = ServerIDLen + NonceLen,
    case Rest of
        <<Body:Len/binary, _ServerUse/binary>> ->
            Plain = decrypt(Body, ServerIDLen, NonceLen, Key),
            <<ServerID:ServerIDLen/binary, _/bits>> = Plain,
            {ok, ServerID};
        _ ->
            {error, cid_too_short}
    end.

%% @private Returns at least the server ID bits of the plaintext.
decrypt(<<_:16/binary>> = Block, _ServerIDLen, _NonceLen, Key) ->
    crypto:crypto_one_time(aes_128_ecb, Key, Block, false);
decrypt(Body, ServerIDLen, NonceLen, Key) ->
    Len = byte_size(Body),
    {L2, R2} = split_halves(Body),
    L1 = feistel_pass(Key, Len, 4, R2, L2),
    R1 = feistel_pass(Key, Len, 3, L1, R2),
    L0 = feistel_pass(Key, Len, 2, R1, L1),
    case ServerIDLen =< NonceLen of
        %% left_0 holds the whole server ID, a fourth pass is not needed.
        true ->
            L0;
        false ->
            R0 = feistel_pass(Key, Len, 1, L0, R1),
            join_halves(L0, R0, Len)
    end.

%% @private XOR Half with AES-ECB(expand(Len, Pass, Input)); odd passes
%% write the right half, even passes the left (Section 5.4.2.3).
feistel_pass(Key, Len, Pass, Input, Half) ->
    HalfLen = byte_size(Half),
    Expanded = <<Input/binary, 0:((14 - HalfLen) * 8), Len, Pass>>,
    <<Mask:HalfLen/binary, _/binary>> = crypto:crypto_one_time(aes_128_ecb, Key, Expanded, true),
    clear_nibble(crypto:exor(Half, Mask), Len rem 2, Pass rem 2).

%% @private With an odd length, the left half ends and the right half
%% starts with four zero bits.
clear_nibble(Half, 0, _Side) ->
    Half;
clear_nibble(<<_:4, Rest/bits>>, 1, 1) ->
    <<0:4, Rest/bits>>;
clear_nibble(Half, 1, 0) ->
    Keep = bit_size(Half) - 4,
    <<Bits:Keep/bits, _:4>> = Half,
    <<Bits/bits, 0:4>>.

%% @private Split into equal halves; an odd middle octet is split by nibble.
split_halves(Bin) ->
    Bits = byte_size(Bin) * 4,
    <<Left:Bits/bits, Right:Bits/bits>> = Bin,
    {pad_bits(Left, last), pad_bits(Right, first)}.

pad_bits(Bits, _Side) when bit_size(Bits) rem 8 =:= 0 ->
    Bits;
pad_bits(Bits, last) ->
    <<Bits/bits, 0:4>>;
pad_bits(Bits, first) ->
    <<0:4, Bits/bits>>.

%% @private Inverse of split_halves/1 for a Len-octet result.
join_halves(Left, Right, Len) ->
    Bits = Len * 4,
    Skip = bit_size(Right) - Bits,
    <<LeftBits:Bits/bits, _/bits>> = Left,
    <<_:Skip, RightBits/bits>> = Right,
    <<LeftBits/bits, RightBits/bits>>.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private Return the error of the first check that fails
validate_list([]) ->
    ok;
validate_list([{Check, Error} | Rest]) ->
    case Check() of
        true -> validate_list(Rest);
        false -> {error, Error}
    end.

id_size(ServerID) when is_binary(ServerID) -> byte_size(ServerID);
id_size(_ServerID) -> 0.

in_range(N, Min, Max) ->
    is_integer(N) andalso N >= Min andalso N =< Max.
