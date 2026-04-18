%%% -*- erlang -*-
%%%
%%% End-to-end smoke test for the opt-in `socket_backend => socket'
%%% client path. Verifies a 1 MB echo round-trip works with the OTP
%%% socket NIF + dedicated receiver process instead of gen_udp + active
%%% mode.

-module(quic_client_socket_backend_tests).

-include_lib("eunit/include/eunit.hrl").

client_socket_backend_roundtrip_test_() ->
    {timeout, 30, fun client_socket_backend_roundtrip/0}.

client_socket_backend_roundtrip() ->
    {ok, Srv} = quic_test_echo_server:start(#{
        max_data => 16 * 1024 * 1024,
        max_stream_data_bidi_local => 8 * 1024 * 1024,
        max_stream_data_bidi_remote => 8 * 1024 * 1024,
        max_stream_data_uni => 8 * 1024 * 1024
    }),
    try
        #{port := Port} = Srv,
        ClientOpts = maps:merge(quic_test_echo_server:client_opts(), #{
            socket_backend => socket,
            max_data => 16 * 1024 * 1024,
            max_stream_data_bidi_local => 8 * 1024 * 1024,
            max_stream_data_bidi_remote => 8 * 1024 * 1024,
            max_stream_data_uni => 8 * 1024 * 1024
        }),
        {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 ->
                ?assert(false)
            end,
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = crypto:strong_rand_bytes(1 * 1024 * 1024),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            Received = collect_echo(Conn, StreamId, <<>>, 10000),
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
        {quic, Conn, {stream_closed, StreamId, _}} ->
            Acc;
        {quic, Conn, {closed, _}} ->
            Acc
    after Timeout ->
        error({collect_timeout, byte_size(Acc)})
    end.
