%%% -*- erlang -*-
%%%
%%% Packets the spec says to drop (RFC 9000 Sections 17.2 and 17.2.5.1)
%%% are dropped without a warning, and the warning for a packet that
%%% fails to decrypt carries no stateless reset token.

-module(quic_dropped_packet_log_tests).

-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(ODCID, <<"orig-dci">>).
-define(SCID, <<"own-cid0">>).

log(#{level := Level, msg := {report, #{what := What} = R}}, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Level, What, R};
log(_Event, _Config) ->
    ok.

connection_drops_long_cid_without_warning_test() ->
    S0 = server(),
    S = captured(fun() -> handle(initial(<<"own-cid0">>, cid(21)), S0) end),
    ?assertEqual(<<>>, S#state.dcid),
    ?assertEqual([], warnings()).

client_drops_retry_echoing_its_dcid_without_warning_test() ->
    S0 = client(),
    S = captured(fun() -> handle(retry(?ODCID), S0) end),
    ?assertNot((S#state.hs)#hs.retry_received),
    ?assertEqual([], warnings()).

undecryptable_packet_still_warns_test() ->
    S0 = client(),
    _ = captured(fun() -> handle(<<16#41, ?SCID/binary, 0:(40 * 8)>>, S0) end),
    ?assertMatch([packet_decode_decrypt_failed], warnings()).

decrypt_warning_names_peer_cids_without_reset_tokens_test() ->
    Token = binary:copy(<<16#AB>>, 16),
    S0 = (client())#state{
        cid_pool_state = quic_cid:set_initial_peer_cid(quic_cid:new(?SCID, 2), ?ODCID, Token)
    },
    _ = captured(fun() -> handle(<<16#41, ?SCID/binary, 0:(40 * 8)>>, S0) end),
    receive
        {logged, warning, packet_decode_decrypt_failed, R} ->
            Text = lists:flatten(io_lib:format("~p", [R])),
            ?assertEqual(nomatch, string:find(Text, quic_connection:binhex(Token))),
            ?assertEqual([{0, quic_connection:binhex(?ODCID)}], maps:get(peer_cids, R))
    after 0 ->
        ?assert(false)
    end.

listener_logs_unparsable_packet_at_debug_test() ->
    Opts = #{cert => <<"cert">>, key => crypto:strong_rand_bytes(32), alpn => [<<"h3">>]},
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Port = quic_listener:get_port(Listener),
    {ok, Sock} = gen_udp:open(0, [binary]),
    Packet = <<16#C0, ?QUIC_VERSION_1:32, 21, (cid(21))/binary, 8, (cid(8))/binary, 0:(1200 * 8)>>,
    try
        captured(fun() ->
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, Packet),
            receive
                {logged, debug, packet_parse_failed, R} ->
                    ?assertEqual(cid_too_long, maps:get(reason, R))
            after 3000 ->
                ?assert(false)
            end
        end),
        ?assertEqual([], warnings())
    after
        gen_udp:close(Sock),
        quic_listener:stop(Listener)
    end.

%% Runs Fun with a debug-level capture installed.
captured(Fun) ->
    flush(),
    Id = list_to_atom("quic_drop_log_" ++ integer_to_list(erlang:unique_integer([positive]))),
    #{level := Primary} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun()
    after
        logger:remove_handler(Id),
        logger:set_primary_config(level, Primary)
    end.

warnings() ->
    receive
        {logged, Level, What, _} when Level =:= warning; Level =:= error -> [What | warnings()];
        {logged, _, _, _} -> warnings()
    after 0 -> []
    end.

flush() ->
    receive
        {logged, _, _, _} -> flush()
    after 0 -> ok
    end.

handle(Packet, State) ->
    quic_connection:handle_packet_loop(Packet, State).

server() ->
    S = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(server)
    ),
    S#state{dcid = <<>>}.

client() ->
    #state{cfg = Cfg, hs = HS} =
        S = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_keys(client)
        ),
    S#state{
        dcid = ?ODCID,
        version = ?QUIC_VERSION_1,
        cfg = Cfg#conn_cfg{original_dcid = ?ODCID, scid = ?SCID},
        hs = HS#hs{retry_received = false}
    }.

cid(Len) ->
    binary:copy(<<$c>>, Len).

retry(RetrySCID) ->
    quic_packet:encode_retry(?ODCID, ?SCID, RetrySCID, <<"token">>, ?QUIC_VERSION_1).

initial(DCID, SCID) ->
    {ClientKeys, _} = quic_connection:derive_initial_keys(<<"discard-cid">>, ?QUIC_VERSION_1),
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ClientKeys,
    Header =
        <<16#C0, ?QUIC_VERSION_1:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary,
            0>>,
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix = <<Header/binary, (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, 0, Prefix, Payload).
