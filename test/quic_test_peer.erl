%%% Liveness probe for an external QUIC peer.
%%%
%%% A UDP send succeeds whether or not anything listens, so it cannot tell
%%% a running server from an empty port. A QUIC server answers a packet
%%% carrying an unsupported version with Version Negotiation (RFC 9000
%%% section 6): a reply proves a live endpoint, silence means none.
-module(quic_test_peer).

-export([reachable/2, reachable/3, wait_reachable/3]).

%% Reserved 0x?a?a?a?a pattern (RFC 9000 section 15), never negotiated.
-define(PROBE_VERSION, 16#1a2a3a4a).
-define(PROBE_TIMEOUT, 1500).

-spec reachable(inet:hostname() | inet:ip_address() | binary(), inet:port_number()) -> boolean().
reachable(Host, Port) ->
    reachable(Host, Port, ?PROBE_TIMEOUT).

-spec reachable(inet:hostname() | inet:ip_address() | binary(), inet:port_number(), timeout()) ->
    boolean().
reachable(Host, Port, Timeout) ->
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            try
                ok = gen_udp:send(Socket, address(Host), Port, probe_packet()),
                case gen_udp:recv(Socket, 0, Timeout) of
                    {ok, {_, _, <<1:1, _:7, 0:32, _/binary>>}} -> true;
                    _ -> false
                end
            catch
                _:_ -> false
            after
                gen_udp:close(Socket)
            end;
        {error, _} ->
            false
    end.

%% Retry for a server that is still starting.
-spec wait_reachable(
    inet:hostname() | inet:ip_address() | binary(), inet:port_number(), non_neg_integer()
) -> ok | {error, not_reachable}.
wait_reachable(_Host, _Port, 0) ->
    {error, not_reachable};
wait_reachable(Host, Port, Retries) ->
    case reachable(Host, Port) of
        true -> ok;
        false -> wait_reachable(Host, Port, Retries - 1)
    end.

probe_packet() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Header = <<16#C0, ?PROBE_VERSION:32, 8, DCID/binary, 8, SCID/binary>>,
    %% Padded to 1200 bytes: servers may drop smaller client datagrams.
    <<Header/binary, 0:((1200 - byte_size(Header)) * 8)>>.

address(Host) when is_tuple(Host) ->
    Host;
address(Host) when is_binary(Host) ->
    address(binary_to_list(Host));
address(Host) ->
    case inet:parse_address(Host) of
        {ok, Addr} ->
            Addr;
        {error, _} ->
            case inet:getaddr(Host, inet) of
                {ok, Addr} -> Addr;
                {error, _} -> Host
            end
    end.
