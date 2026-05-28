%%% -*- erlang -*-
%%%
%%% Server certificate validation for QUIC clients.
%%%
%%% Performs the two checks RFC 8446 requires of a client after it
%%% receives the server's Certificate message: chain validation against
%%% a set of trust anchors (§4.4.2.4) and identity (hostname) matching
%%% (RFC 6125). Signature verification of CertificateVerify is handled
%%% in `quic_tls:verify_certificate_verify/4'; this module covers the
%%% chain and the name.

-module(quic_cert).

-include_lib("public_key/include/public_key.hrl").

-export([validate_server/4]).

-define(MAX_PATH_LENGTH, 10).

%% @doc Validate a server's certificate chain and identity.
%%
%% `Leaf' is the server's end-entity certificate (DER). `Intermediates'
%% are the remaining certificates sent by the peer (DER), in the
%% leaf-to-root order they arrive on the wire. `CaCerts' are the trust
%% anchors as a DER list, or `undefined' to use the OS trust store.
%% `ServerName' is the expected identity (binary hostname or IP literal),
%% or `undefined' to skip the hostname check.
-spec validate_server(
    binary() | undefined,
    [binary()],
    [binary()] | undefined,
    binary() | undefined
) -> ok | {error, term()}.
validate_server(undefined, _Intermediates, _CaCerts, _ServerName) ->
    {error, no_certificate};
validate_server(Leaf, Intermediates, CaCerts, ServerName) when is_binary(Leaf) ->
    case verify_chain(Leaf, Intermediates, trust_anchors(CaCerts)) of
        ok -> verify_hostname(Leaf, ServerName);
        {error, _} = Error -> Error
    end.

%%====================================================================
%% Chain validation
%%====================================================================

%% Trust anchors as DER. `cacerts_get/0' returns `#cert{}' records on
%% recent OTP and bare DER on older ones; normalise both.
trust_anchors(undefined) ->
    [normalize_anchor(C) || C <- safe_cacerts_get()];
trust_anchors(CaCerts) when is_list(CaCerts) ->
    [normalize_anchor(C) || C <- CaCerts].

safe_cacerts_get() ->
    try
        public_key:cacerts_get()
    catch
        _:_ -> []
    end.

normalize_anchor(#cert{der = Der}) -> Der;
normalize_anchor(Der) when is_binary(Der) -> Der.

verify_chain(_Leaf, _Intermediates, []) ->
    {error, no_trust_anchors};
verify_chain(Leaf, Intermediates, Anchors) ->
    %% `pkix_path_validation/3' wants the path ordered from the cert
    %% issued by the anchor down to the leaf; the wire order is the
    %% reverse (leaf first).
    Path = lists:reverse([Leaf | Intermediates]),
    case anchored_subpath(Path, Anchors) of
        {ok, Anchor, SubPath} ->
            try
                public_key:pkix_path_validation(
                    Anchor, SubPath, [{max_path_length, ?MAX_PATH_LENGTH}]
                )
            of
                {ok, _} -> ok;
                {error, {bad_cert, Reason}} -> {error, {bad_cert, Reason}}
            catch
                _:_ -> {error, {bad_cert, validation_failed}}
            end;
        error ->
            {error, unknown_ca}
    end.

%% Highest cert in the path whose issuer is a trust anchor, plus the
%% sub-path from that cert down to the leaf. Lets the server send extra
%% or cross-signed certs above the cert that actually chains.
anchored_subpath([], _Anchors) ->
    error;
anchored_subpath([Cert | Rest] = SubPath, Anchors) ->
    case find_anchor(Cert, Anchors) of
        {ok, Anchor} -> {ok, Anchor, SubPath};
        error -> anchored_subpath(Rest, Anchors)
    end.

%% Find the anchor that issued `Cert' (a self-signed cert is its own
%% issuer, which covers self-signed leaves supplied as anchors).
find_anchor(_Cert, []) ->
    error;
find_anchor(Cert, [Anchor | Rest]) ->
    case is_issuer(Cert, Anchor) of
        true -> {ok, Anchor};
        false -> find_anchor(Cert, Rest)
    end.

is_issuer(Cert, Anchor) ->
    try
        public_key:pkix_is_issuer(Cert, Anchor)
    catch
        _:_ -> false
    end.

%%====================================================================
%% Hostname validation
%%====================================================================

verify_hostname(_Leaf, undefined) ->
    ok;
verify_hostname(Leaf, ServerName) when is_binary(ServerName) ->
    Host = binary_to_list(ServerName),
    RefId =
        case inet:parse_address(Host) of
            {ok, IP} -> {ip, IP};
            {error, _} -> {dns_id, Host}
        end,
    case safe_verify_hostname(Leaf, RefId) of
        true -> ok;
        false -> {error, {hostname_mismatch, ServerName}}
    end.

safe_verify_hostname(Leaf, RefId) ->
    try
        public_key:pkix_verify_hostname(Leaf, [RefId])
    catch
        _:_ -> false
    end.
