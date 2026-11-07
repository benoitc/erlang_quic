%%% `quic_h3:accept/2' starts HTTP/3 on a connection an `alpn_handler'
%%% picked by ALPN, so one listener serves HTTP/3 and another protocol.
-module(quic_h3_accept_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TIMEOUT, 5000).

h3_and_another_protocol_on_one_listener_test() ->
    Test = self(),
    Name = start_server(fun
        (Conn, <<"h3">>) ->
            quic_h3:accept(Conn, #{handler => fun hello/5});
        (_Conn, <<"myproto">>) ->
            {ok, spawn(fun() -> relay(Test) end)}
    end),
    try
        {ok, Port} = quic:get_server_port(Name),
        {ok, H3} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
        {ok, StreamId} = quic_h3:request(H3, [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/x">>},
            {<<":authority">>, <<"localhost">>}
        ]),
        receive
            {quic_h3, H3, {response, StreamId, 200, _}} -> ok
        after ?TIMEOUT -> error(no_response)
        end,
        ?assertEqual(<<"hello /x">>, recv_body(H3, StreamId, <<>>)),
        quic_h3:close(H3),

        {ok, Other} = quic:connect(
            "127.0.0.1", Port, #{alpn => [<<"myproto">>], verify => false}, self()
        ),
        receive
            {relayed, {quic, _, {connected, #{alpn := <<"myproto">>}}}} -> ok
        after ?TIMEOUT -> error(myproto_not_routed)
        end,
        quic:close(Other, normal)
    after
        quic:stop_server(Name)
    end.

bad_options_fail_the_handshake_test() ->
    Name = start_server(fun(Conn, _Alpn) -> quic_h3:accept(Conn, #{max_buffered_body => -1}) end),
    try
        {ok, Port} = quic:get_server_port(Name),
        ?assertMatch(
            {error, _}, quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true})
        )
    after
        quic:stop_server(Name)
    end.

start_server(AlpnHandler) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("quic_h3_accept_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        alpn => [<<"h3">>, <<"myproto">>],
        alpn_handler => AlpnHandler
    }),
    Name.

hello(Conn, StreamId, _Method, Path, _Headers) ->
    quic_h3:respond(Conn, StreamId, 200, [], <<"hello ", Path/binary>>).

relay(Test) ->
    receive
        Msg ->
            Test ! {relayed, Msg},
            relay(Test)
    end.

recv_body(H3, StreamId, Acc) ->
    receive
        {quic_h3, H3, {data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic_h3, H3, {data, StreamId, Data, false}} ->
            recv_body(H3, StreamId, <<Acc/binary, Data/binary>>)
    after ?TIMEOUT -> error({no_body, Acc})
    end.
