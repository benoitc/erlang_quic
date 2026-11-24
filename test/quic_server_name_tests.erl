%%% -*- erlang -*-
%%%
%%% quic:server_name/1 returns the SNI the client sent.

-module(quic_server_name_tests).

-include_lib("eunit/include/eunit.hrl").

both_sides_see_the_name_the_client_sent_test_() ->
    {timeout, 30, fun() ->
        with_connection(#{server_name => <<"host.test">>}, fun(Client, Server) ->
            ?assertEqual({ok, <<"host.test">>}, quic:server_name(Client)),
            ?assertEqual({ok, <<"host.test">>}, server_name_when_connected(Server))
        end)
    end}.

no_name_when_the_client_connects_to_an_address_test_() ->
    {timeout, 30, fun() ->
        with_connection(#{}, fun(Client, Server) ->
            ?assertEqual({error, no_server_name}, quic:server_name(Client)),
            ?assert(
                quic_test_wait:until(
                    fun() -> quic:server_name(Server) =:= {error, no_server_name} end, 5000
                )
            )
        end)
    end}.

server_name_when_connected(Server) ->
    true = quic_test_wait:until(fun() -> element(1, quic:server_name(Server)) =:= ok end, 5000),
    quic:server_name(Server).

with_connection(ClientOpts, Fun) ->
    {ok, _} = application:ensure_all_started(quic),
    Test = self(),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("server_name_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        alpn => [<<"sni">>],
        connection_handler => fun(Conn, _Ref) ->
            Test ! {server_conn, Conn},
            {ok, spawn(fun sink/0)}
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        {ok, Client} = quic:connect(
            "127.0.0.1", Port, ClientOpts#{verify => false, alpn => [<<"sni">>]}, self()
        ),
        try
            receive
                {quic, Client, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            receive
                {server_conn, Server} -> Fun(Client, Server)
            after 5000 -> error(no_server_conn)
            end
        after
            quic:safe_close(Client, normal)
        end
    after
        quic:stop_server(Name)
    end.

sink() ->
    receive
        _ -> sink()
    end.
