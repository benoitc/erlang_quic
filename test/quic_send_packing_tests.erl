%%% -*- erlang -*-
%%%
%%% Writes that wait for each other share packets.
%%%
%%% A write larger than a packet leaves as full packets and a tail. The
%%% tail used to go out in a packet of its own, although the next write
%%% was already waiting and could have filled it: 4 KiB writes took four
%%% packets each, the last one nearly empty.

-module(quic_send_packing_tests).

-include_lib("eunit/include/eunit.hrl").

-define(WRITES, 200).
-define(WRITE_SIZE, 4096).
-define(DATAGRAMS, 64).

queued_writes_fill_their_packets_test_() ->
    {timeout, 60, fun() ->
        with_sink(fun(Conn) ->
            {ok, Before} = quic:get_stats(Conn),
            {ok, StreamId} = quic:open_unidirectional_stream(Conn),
            Write = binary:copy(<<"x">>, ?WRITE_SIZE),
            [ok = quic:send_data_async(Conn, StreamId, Write, false) || _ <- lists:seq(1, ?WRITES)],
            Total = ?WRITES * ?WRITE_SIZE,
            ?assert(quic_test_wait:until(fun() -> sent(Conn, Before) =:= Total end, 30000)),
            {ok, After} = quic:get_stats(Conn),
            Packets = delta(packets_sent, After, Before) - delta(retransmits, After, Before),
            %% Three packets a write when they are packed, four when each
            %% tail travels alone.
            ?assert(Packets < ?WRITES * 15 div 4, {packets, Packets})
        end)
    end}.

waiting_datagrams_share_packets_test_() ->
    {timeout, 60, fun() ->
        with_sink(fun(Conn) ->
            {ok, Before} = quic:get_stats(Conn),
            Self = self(),
            Payloads = [<<N:32, 0:(66 * 8)>> || N <- lists:seq(1, ?DATAGRAMS)],
            true = erlang:suspend_process(Conn),
            [spawn_link(fun() -> Self ! {sent, quic:send_datagram(Conn, P)} end) || P <- Payloads],
            ?assert(
                quic_test_wait:until(
                    fun() ->
                        process_info(Conn, message_queue_len) >= {message_queue_len, ?DATAGRAMS}
                    end,
                    5000
                )
            ),
            true = erlang:resume_process(Conn),
            [
                receive
                    {sent, Result} -> ?assertEqual(ok, Result)
                after 5000 -> error(send_timeout)
                end
             || _ <- Payloads
            ],
            Received = [
                receive
                    {datagram, D} -> D
                after 5000 -> error(datagram_timeout)
                end
             || _ <- Payloads
            ],
            ?assertEqual(Payloads, lists:sort(Received)),
            {ok, After} = quic:get_stats(Conn),
            Packets = delta(packets_sent, After, Before),
            ?assert(Packets < ?DATAGRAMS div 4, {packets, Packets})
        end)
    end}.

delta(Key, After, Before) ->
    maps:get(Key, After) - maps:get(Key, Before).

sent(Conn, Before) ->
    {ok, Stats} = quic:get_stats(Conn),
    maps:get(data_sent, Stats) - maps:get(data_sent, Before).

with_sink(Fun) ->
    {ok, _} = application:ensure_all_started(quic),
    Test = self(),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("packing_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        alpn => [<<"sink">>],
        max_datagram_frame_size => 65535,
        connection_handler => fun(_Conn, _Ref) -> {ok, spawn(fun() -> sink(Test) end)} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        {ok, Conn} = quic:connect(
            "127.0.0.1",
            Port,
            #{verify => false, alpn => [<<"sink">>], max_datagram_frame_size => 65535},
            self()
        ),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            Fun(Conn)
        after
            quic:safe_close(Conn, normal)
        end
    after
        quic:stop_server(Name)
    end.

sink(Test) ->
    receive
        {quic, _, {datagram, Data}} -> Test ! {datagram, Data};
        _ -> ok
    end,
    sink(Test).
