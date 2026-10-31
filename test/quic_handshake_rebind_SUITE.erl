%%% -*- erlang -*-
%%%
%%% A NAT rebinding during the handshake.
%%%
%%% The client's port changes after its first datagram, before the
%%% server's reply gets back, so the old port is dead from the start.
%%% The client retransmits from the new port; a server that keeps
%%% sending its flight to the old port never completes the handshake.

-module(quic_handshake_rebind_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    control_plain_handshake/1,
    completes_after_a_rebind_before_the_first_reply/1,
    challenges_the_new_path/1
]).

-define(CONNECT_MS, 15000).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        control_plain_handshake,
        completes_after_a_rebind_before_the_first_reply,
        challenges_the_new_path
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

control_plain_handshake(_Config) ->
    with_server(fun(Port) ->
        Conn = connect_through_bridge(Port, #{}),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

completes_after_a_rebind_before_the_first_reply(_Config) ->
    with_server(fun(Port) ->
        Conn = connect_through_bridge(Port, #{rebind_at => 2}),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

%% RFC 9000 Section 9: a peer that moves before the handshake is
%% confirmed is either dropped or validated. The server follows it, so the
%% first thing it sends to the new address is a PATH_CHALLENGE.
challenges_the_new_path(_Config) ->
    with_server(fun(Port) ->
        Self = self(),
        Record = fun(Pkt, _N) ->
            Self ! {new_path_datagram, Pkt},
            false
        end,
        Conn = connect_through_bridge(Port, #{rebind_at => 2, drop_in => Record}, Self),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        First =
            receive
                {new_path_datagram, D} -> D
            after 0 -> ct:fail("nothing on the new path")
            end,
        ?assertMatch(<<0:1, 1:1, _/bitstring>>, First),
        {_, #state{app_keys = {ClientKeys, ServerKeys}, dcid = DCID, cfg = #conn_cfg{scid = SCID}}} =
            sys:get_state(Conn),
        {path_challenge, Challenge} =
            lists:keyfind(path_challenge, 1, short_frames(ServerKeys, SCID, First)),
        Responses = [
            R
         || D <- recorded(client_datagram),
            {path_response, R} <- short_frames(ClientKeys, DCID, D)
        ],
        ?assert(lists:member(Challenge, Responses)),
        quic:close(Conn, normal)
    end).

%%====================================================================
%% Harness
%%====================================================================

with_server(Fun) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Fun(maps:get(port, Server))
    after
        quic_test_echo_server:stop(Server)
    end.

connected_within(Conn, Budget) ->
    receive
        {quic, Conn, {connected, _}} -> ok;
        {quic, Conn, {closed, Reason}} -> ct:fail({closed_during_handshake, Reason})
    after Budget -> ct:fail("connect timeout")
    end.

echo_roundtrip(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = <<"rebind check">>,
    ok = quic:send_data(Conn, StreamId, Payload, true),
    ?assertEqual(Payload, collect_echo(Conn, StreamId, 5000, <<>>)).

collect_echo(Conn, StreamId, Budget, Acc) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Acc1 = <<Acc/binary, Data/binary>>,
            case Fin of
                true -> Acc1;
                false -> collect_echo(Conn, StreamId, Budget - spent(Start), Acc1)
            end;
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc)
    after max(0, Budget) -> Acc
    end.

%% The frames of the 1-RTT packet a datagram ends with, or none if it
%% has none or it does not decrypt with these keys.
short_frames(Keys, DCID, <<1:1, _:7, _Version:32, DL, _:DL/binary, SL, _:SL/binary, _/binary>> = D) ->
    Rest0 = binary:part(D, 7 + DL + SL, byte_size(D) - 7 - DL - SL),
    Rest1 =
        case D of
            <<_:2, 0:2, _:4, _/binary>> ->
                {TokenLen, R} = quic_varint:decode(Rest0),
                binary:part(R, TokenLen, byte_size(R) - TokenLen);
            _ ->
                Rest0
        end,
    {Len, Rest2} = quic_varint:decode(Rest1),
    short_frames(Keys, DCID, binary:part(Rest2, Len, byte_size(Rest2) - Len));
short_frames(Keys, DCID, <<0:1, _:7, _/binary>> = D) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = Keys,
    HeaderLen = 1 + byte_size(DCID),
    <<Header:HeaderLen/binary, Encrypted/binary>> = D,
    case quic_aead:unprotect_short_packet(Cipher, Key, IV, HP, Header, Encrypted, undefined) of
        {ok, _PN, _, Plaintext} ->
            {ok, Frames} = quic_frame:decode_all(Plaintext),
            Frames;
        {error, _} ->
            []
    end;
short_frames(_Keys, _DCID, _) ->
    [].

recorded(Tag) ->
    receive
        {Tag, D} -> [D | recorded(Tag)]
    after 0 -> []
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

connect_through_bridge(Port, BridgeOpts) ->
    connect_through_bridge(Port, BridgeOpts, undefined).

connect_through_bridge(Port, BridgeOpts, Recorder) ->
    SocketRef = make_ref(),
    Bridge = quic_test_bridge:start(BridgeOpts#{
        server => {{127, 0, 0, 1}, Port},
        socket_ref => SocketRef
    }),
    Adapter = #{
        send_fun => fun(IP, P, Pkt) ->
            is_pid(Recorder) andalso (Recorder ! {client_datagram, iolist_to_binary(Pkt)}),
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ok = quic_test_bridge:set_conn(Bridge, Conn),
    Conn.
