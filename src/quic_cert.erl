%%% -*- erlang -*-
%%%
%%% Server certificate validation for QUIC clients.
%%%
%%% Performs the two checks RFC 9846 requires of a client after it
%%% receives the server's Certificate message: chain validation against
%%% a set of trust anchors (§4.5.1.3) and identity (hostname) matching
%%% (RFC 9525). Signature verification of CertificateVerify is handled
%%% in `quic_tls:verify_certificate_verify/4'; this module covers the
%%% chain and the name.

-module(quic_cert).

-include_lib("public_key/include/public_key.hrl").

-export([validate_server/4, validate_client/3, cacerts_from_file/1, resolve_cacerts/1]).
-export([requests_client_cert/1, check_client_auth/1, host_address/1]).

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

%% @doc Validate a client's certificate chain (mutual TLS, RFC 9846 §4.5.1.3).
%%
%% Same trust-anchor chain validation as {@link validate_server/4}, but with no
%% identity/hostname check: a client certificate is not bound to a server name,
%% and the peer's application identity is established separately (e.g. from the
%% certificate subject plus an out-of-band token). `Leaf' is the client's
%% end-entity certificate (DER), `Intermediates' the rest of the chain in
%% wire (leaf-to-root) order, and `CaCerts' the trust anchors (DER list, or
%% `undefined' for the OS trust store).
-spec validate_client(binary() | undefined, [binary()], [binary()] | undefined) ->
    ok | {error, term()}.
validate_client(undefined, _Intermediates, _CaCerts) ->
    {error, no_certificate};
validate_client(Leaf, Intermediates, CaCerts) when is_binary(Leaf) ->
    verify_chain(Leaf, Intermediates, trust_anchors(CaCerts)).

%% @doc Whether a server with these options asks the client for a
%% certificate: `verify' (`true' or `verify_peer') asks and accepts a
%% client without one; `require_client_cert' asks and refuses one
%% without.
-spec requests_client_cert(map()) -> boolean().
requests_client_cert(Opts) ->
    case {maps:get(verify, Opts, false), maps:get(require_client_cert, Opts, false)} of
        {_, true} -> true;
        {Verify, _} -> lists:member(Verify, [true, verify_peer])
    end.

%% @doc Check, where a server starts, that a listener asking for client
%% certificates has trust anchors to check them against. Without
%% `cacerts' or `cacertfile' every client certificate would be checked
%% against the OS store, so any publicly issued one would authenticate.
-spec check_client_auth(map()) -> ok | {error, term()}.
check_client_auth(Opts) ->
    Anchors =
        case maps:get(cacerts, Opts, undefined) of
            [_ | _] -> true;
            _ -> maps:get(cacertfile, Opts, undefined) =/= undefined
        end,
    case {maps:get(require_client_cert, Opts, false), requests_client_cert(Opts), Anchors} of
        {Require, _, _} when not is_boolean(Require) -> {error, {bad_option, require_client_cert}};
        {_, true, false} -> {error, client_auth_needs_cacerts};
        _ -> ok
    end.

%% @doc Turn a `cacertfile' option into the DER `cacerts' the rest of the
%% library takes.
%%
%% Called once where a connection or server starts, so the file is read
%% once and a bad path fails the call that named it. An explicit
%% `cacerts' is what the caller already resolved, so it wins.
-spec resolve_cacerts(map()) -> {ok, map()} | {error, term()}.
resolve_cacerts(Opts) ->
    case {maps:is_key(cacerts, Opts), maps:get(cacertfile, Opts, undefined)} of
        {true, _} ->
            {ok, Opts};
        {false, undefined} ->
            {ok, Opts};
        {false, File} ->
            case cacerts_from_file(File) of
                {ok, Ders} -> {ok, Opts#{cacerts => Ders}};
                {error, _} = Error -> Error
            end
    end.

%% @doc Read trust anchors from a PEM file as DER.
%%
%% A bundle yields every certificate in it. A file that cannot be read,
%% or that holds no certificate, is an error rather than an empty list:
%% empty anchors mean trust nothing, which fails every later handshake
%% with a reason that says nothing about the file.
-spec cacerts_from_file(file:name_all()) ->
    {ok, [public_key:der_encoded()]} | {error, {cacertfile, file:name_all(), term()}}.
cacerts_from_file(File) ->
    case file:read_file(File) of
        {ok, Pem} ->
            case certificates(Pem) of
                [] -> {error, {cacertfile, File, no_certificates}};
                Ders -> {ok, Ders}
            end;
        {error, Reason} ->
            {error, {cacertfile, File, Reason}}
    end.

certificates(Pem) ->
    try
        [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)]
    catch
        _:_ -> []
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
    case candidate_anchorings(Path, Anchors) of
        [] ->
            {error, unknown_ca};
        [Primary | Alternatives] ->
            validate_anchored(Primary, Alternatives)
    end.

%% Every `{Anchor, SubPath}' pairing, highest anchorable cert first. The
%% head is the pairing the single-anchor lookup would have chosen (lets
%% the server send extra or cross-signed certs above the cert that
%% actually chains); the tail anchors lower in the served chain, or at a
%% different trust anchor for the same cert.
candidate_anchorings([], _Anchors) ->
    [];
candidate_anchorings([Cert | Rest] = SubPath, Anchors) ->
    [{Anchor, SubPath} || Anchor <- Anchors, is_issuer(Cert, Anchor)] ++
        candidate_anchorings(Rest, Anchors).

%% Validate the primary anchoring; on an expired-cert failure, recover by
%% trying the alternatives. Mirrors OTP's
%% `ssl_certificate:find_cross_sign_root_paths/4': an expired cross-signed
%% root (e.g. Let's Encrypt ISRG Root X2 cross-signed by the expired X1)
%% is dropped for a still-valid trust anchor with the same key, reached
%% lower in the chain. Recovery only moves the anchor; an expired leaf or
%% intermediate stays in every remaining sub-path, so it still fails as
%% `cert_expired'.
validate_anchored(Primary, Alternatives) ->
    case validate_path(Primary) of
        ok ->
            ok;
        {error, {bad_cert, Reason}} = Error ->
            case is_expiry(Reason) of
                true ->
                    case try_anchorings(Alternatives) of
                        ok -> ok;
                        error -> {error, {bad_cert, cert_expired}}
                    end;
                false ->
                    Error
            end
    end.

%% First anchoring that validates wins. Returns a bare `error' on
%% exhaustion, discarding each alternative's reason, so a failing
%% alternative never replaces the caller's expiry outcome.
try_anchorings([]) ->
    error;
try_anchorings([Candidate | Rest]) ->
    case validate_path(Candidate) of
        ok -> ok;
        {error, _} -> try_anchorings(Rest)
    end.

validate_path({Anchor, SubPath}) ->
    try
        public_key:pkix_path_validation(
            Anchor, SubPath, [{max_path_length, ?MAX_PATH_LENGTH}]
        )
    of
        {ok, _} -> ok;
        {error, {bad_cert, Reason}} -> {error, {bad_cert, Reason}}
    catch
        _:_ -> {error, {bad_cert, validation_failed}}
    end.

is_expiry(cert_expired) -> true;
is_expiry(root_cert_expired) -> true;
is_expiry(_) -> false.

%% A self-signed cert is its own issuer, which covers self-signed leaves
%% supplied as anchors.
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
    RefId =
        case host_address(ServerName) of
            {ok, IP} -> {ip, IP};
            error -> {dns_id, binary_to_list(ServerName)}
        end,
    case has_san_id(Leaf) andalso safe_verify_hostname(Leaf, RefId) of
        true -> ok;
        false -> {error, {hostname_mismatch, ServerName}}
    end.

%% @doc The address a host or server name gives as an IP literal, bare
%% or in brackets (`[::1]'), with or without an IPv6 zone ID; `error'
%% for a hostname.
-spec host_address(binary() | string()) -> {ok, inet:ip_address()} | error.
host_address(Host) when is_binary(Host) ->
    host_address(binary_to_list(Host));
host_address(Host) when is_list(Host) ->
    Literal = strip_brackets(Host),
    case inet:parse_address(Literal) of
        {ok, IP} -> {ok, IP};
        {error, _} -> zoned_ipv6_address(Literal)
    end.

%% inet:parse_address/1 takes a zone ID on link-local addresses only.
zoned_ipv6_address(Literal) ->
    case string:split(Literal, "%") of
        [Addr, [_ | _]] ->
            case inet:parse_ipv6strict_address(Addr) of
                {ok, IP} -> {ok, IP};
                {error, _} -> error
            end;
        _ ->
            error
    end.

strip_brackets([$[ | Rest]) ->
    case lists:reverse(Rest) of
        [$] | RevInner] -> lists:reverse(RevInner);
        _ -> [$[ | Rest]
    end;
strip_brackets(Host) ->
    Host.

%% RFC 9525 Section 2: the subject CN never identifies a service, so a
%% leaf without a DNS-ID or IP-ID in subjectAltName matches no name.
has_san_id(Leaf) ->
    try public_key:pkix_decode_cert(Leaf, otp) of
        #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{extensions = Exts}} ->
            lists:any(fun is_san_id/1, san_entries(Exts))
    catch
        _:_ -> false
    end.

san_entries(Exts) when is_list(Exts) ->
    case lists:keyfind(?'id-ce-subjectAltName', #'Extension'.extnID, Exts) of
        #'Extension'{extnValue = Names} when is_list(Names) -> Names;
        _ -> []
    end;
san_entries(_) ->
    [].

is_san_id({dNSName, _}) -> true;
is_san_id({iPAddress, _}) -> true;
is_san_id(_) -> false.

safe_verify_hostname(Leaf, RefId) ->
    try
        public_key:pkix_verify_hostname(Leaf, [RefId], [{match_fun, fun match_id/2}])
    catch
        _:_ -> false
    end.

%% DNS-IDs follow RFC 9525 Section 6.3; IP-IDs use OTP's octet-exact
%% comparison (Section 6.4); nothing else matches.
match_id({dns_id, Ref}, {dNSName, Presented}) ->
    match_dns_id(Ref, Presented);
match_id({ip, _}, {iPAddress, _}) ->
    default;
match_id(_, _) ->
    false.

match_dns_id(Ref, Presented) when is_list(Ref), is_list(Presented) ->
    RefLabels = string:split(lower_ascii(Ref), ".", all),
    case string:split(lower_ascii(Presented), ".", all) of
        ["*" | Rest] ->
            match_wildcard(RefLabels, Rest);
        Labels ->
            not lists:member($*, Presented) andalso Labels =:= RefLabels
    end;
match_dns_id(_, _) ->
    false.

%% A wildcard is the whole leftmost label and stands for exactly one
%% non-empty label of the reference identifier; a bare `*' names no domain.
match_wildcard(_RefLabels, []) ->
    false;
match_wildcard([First | RefRest], Rest) ->
    First =/= "" andalso
        not lists:member($*, First) andalso
        not lists:member($*, lists:append(Rest)) andalso
        RefRest =:= Rest.

lower_ascii(S) ->
    [lower_char(C) || C <- S].

lower_char(C) when C >= $A, C =< $Z -> C + ($a - $A);
lower_char(C) -> C.
