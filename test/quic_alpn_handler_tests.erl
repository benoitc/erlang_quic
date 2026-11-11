%%% A listener's `alpn_handler' picks each connection's owner by the
%%% negotiated ALPN, before any stream data can reach the owner.
-module(quic_alpn_handler_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TIMEOUT, 5000).
%% CRYPTO_ERROR for the TLS alerts (RFC 9001 Section 4.8).
-define(HANDSHAKE_FAILURE, 16#0128).
-define(NO_APPLICATION_PROTOCOL, 16#0178).

owner_chosen_by_alpn_receives_the_stream_test() ->
    Test = self(),
    Name = start_server(#{
        connection_handler => fun(_Conn) -> {ok, relay(pre, Test)} end,
        alpn_handler => fun(Conn, Alpn) ->
            Test ! {handler_called, Conn, Alpn},
            {ok, relay(Alpn, Test)}
        end
    }),
    try
        {ok, Client} = connect(Name, <<"proto-b">>),
        {ok, StreamId} = quic:open_stream(Client),
        ok = quic:send_data(Client, StreamId, <<"hello">>, true),
        Conn =
            receive
                {handler_called, C, <<"proto-b">>} -> C
            after ?TIMEOUT -> error(handler_not_called)
            end,
        ?assertEqual(<<"hello">>, recv_stream(<<"proto-b">>, Conn, <<>>)),
        ?assertEqual([], [M || {pre, {quic, _, {stream_data, _, _, _}} = M} <- flush()]),
        quic:close(Client, normal)
    after
        quic:stop_server(Name)
    end.

each_alpn_gets_its_own_owner_test() ->
    Test = self(),
    Name = start_server(#{alpn_handler => fun(_Conn, Alpn) -> {ok, relay(Alpn, Test)} end}),
    try
        lists:foreach(
            fun(Alpn) ->
                {ok, Client} = connect(Name, Alpn),
                receive
                    {Alpn, {quic, _, {connected, #{alpn := Alpn}}}} -> ok
                after ?TIMEOUT -> error({not_connected, Alpn})
                end,
                quic:close(Client, normal)
            end,
            [<<"proto-a">>, <<"proto-b">>]
        )
    after
        quic:stop_server(Name)
    end.

an_error_fails_the_handshake_test() ->
    Name = start_server(#{alpn_handler => fun(_Conn, _Alpn) -> {error, busy} end}),
    try
        ?assertMatch(
            {error, {peer_closed, transport, ?HANDSHAKE_FAILURE, _, _}},
            connect(Name, <<"proto-a">>)
        )
    after
        quic:stop_server(Name)
    end.

an_exception_fails_the_handshake_test() ->
    Name = start_server(#{alpn_handler => fun(_Conn, _Alpn) -> error(boom) end}),
    try
        ?assertMatch(
            {error, {peer_closed, transport, ?HANDSHAKE_FAILURE, _, _}},
            connect(Name, <<"proto-a">>)
        )
    after
        quic:stop_server(Name)
    end.

%% ALPN is negotiated before the hook runs, so a ClientHello with no
%% common protocol is refused without calling it (RFC 9001 Section 8.1).
no_common_alpn_is_refused_before_the_handler_test() ->
    Test = self(),
    Name = start_server(#{
        alpn_handler => fun(_Conn, Alpn) ->
            Test ! {handler_called, Alpn},
            {ok, relay(Alpn, Test)}
        end
    }),
    try
        ?assertMatch(
            {error, {peer_closed, transport, ?NO_APPLICATION_PROTOCOL, _, _}},
            connect(Name, <<"proto-c">>)
        ),
        ?assertEqual([], [M || {handler_called, _} = M <- flush()])
    after
        quic:stop_server(Name)
    end.

start_server(Opts) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("quic_alpn_handler_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic:start_server(Name, 0, Opts#{
        cert => Cert, key => Key, alpn => [<<"proto-a">>, <<"proto-b">>]
    }),
    Name.

connect(Name, Alpn) ->
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic:connect("127.0.0.1", Port, #{alpn => [Alpn], verify => false}, self()),
    receive
        {quic, Conn, {connected, _}} -> {ok, Conn};
        {quic, Conn, {closed, Reason}} -> {error, Reason};
        {quic, Conn, {error, Reason}} -> {error, Reason}
    after ?TIMEOUT -> {error, timeout}
    end.

relay(Tag, Test) ->
    spawn(fun() -> relay_loop(Tag, Test) end).

relay_loop(Tag, Test) ->
    receive
        Msg ->
            Test ! {Tag, Msg},
            relay_loop(Tag, Test)
    end.

recv_stream(Tag, Conn, Acc) ->
    receive
        {Tag, {quic, Conn, {stream_data, _, Data, true}}} ->
            <<Acc/binary, Data/binary>>;
        {Tag, {quic, Conn, {stream_data, _, Data, false}}} ->
            recv_stream(Tag, Conn, <<Acc/binary, Data/binary>>)
    after ?TIMEOUT -> error({no_stream_data, Acc})
    end.

flush() ->
    receive
        M -> [M | flush()]
    after 100 -> []
    end.
