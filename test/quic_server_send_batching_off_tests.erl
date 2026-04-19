%%% Regression test: server with socket_backend => socket and
%%% server_send_batching => false must still be able to send packets.
%%% Before the fix, server init dropped socket_state to undefined in
%%% that mode and do_socket_send / send_packet_to_addr fell back to
%%% gen_udp:send/4, but on the socket backend #state.socket is an OTP
%%% socket handle, so all server-side sends failed silently.

-module(quic_server_send_batching_off_tests).

-include_lib("eunit/include/eunit.hrl").

server_socket_backend_batching_off_test_() ->
    %% Linux-only: detect_capabilities/0 only exposes the OTP socket
    %% NIF as the listener backend there. Elsewhere the bug this test
    %% targets (gen_udp:send/4 on an OTP socket handle) cannot fire.
    case os:type() of
        {unix, linux} -> [{timeout, 15, fun server_socket_backend_batching_off/0}];
        _ -> []
    end.

server_socket_backend_batching_off() ->
    {ok, Srv} = quic_test_echo_server:start(#{
        socket_backend => socket,
        server_send_batching => false
    }),
    try
        #{port := Port} = Srv,
        ClientOpts = quic_test_echo_server:client_opts(),
        {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                error(connect_timeout)
            end,
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = <<"hello">>,
            ok = quic:send_data(Conn, StreamId, Payload, true),
            Received = collect_echo(Conn, StreamId, <<>>, 5000),
            ?assertEqual(Payload, Received)
        after
            catch quic:close(Conn)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

collect_echo(Conn, StreamId, Acc, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_echo(Conn, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic, Conn, {closed, _}} ->
            Acc;
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Acc, Timeout)
    after Timeout ->
        error({collect_timeout, byte_size(Acc)})
    end.
