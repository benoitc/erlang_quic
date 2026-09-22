%% A client socket must own its ephemeral port. With SO_REUSEADDR set
%% the kernel may autobind two sockets to the same port and then deliver
%% every datagram to one of them, so the other connection never sees a
%% reply. Seen as one of 150 simultaneous connects stalling in idle.
%% The port is assigned on the first send, so each test sends once.
-module(quic_client_socket_port_tests).
-include_lib("eunit/include/eunit.hrl").

client_port_is_exclusive_socket_backend_test() ->
    case maps:get(backend, quic_socket:detect_capabilities()) of
        socket ->
            SS = client(socket),
            Client = quic_socket:get_socket(SS),
            {ok, #{port := Port}} = socket:sockname(Client),
            ?assertNotEqual(0, Port),
            {ok, Other} = socket:open(inet, dgram, udp),
            ok = socket:setopt(Other, {socket, reuseaddr}, true),
            ?assertEqual(
                {error, eaddrinuse},
                socket:bind(Other, #{family => inet, addr => any, port => Port})
            ),
            socket:close(Other),
            quic_socket:close(SS);
        _ ->
            ok
    end.

client_port_is_exclusive_gen_udp_test() ->
    SS = client(gen_udp),
    {ok, Port} = inet:port(quic_socket:get_socket(SS)),
    ?assertNotEqual(0, Port),
    ?assertEqual({error, eaddrinuse}, gen_udp:open(Port, [{reuseaddr, true}])),
    quic_socket:close(SS).

many_clients_get_distinct_ports_test() ->
    Backend = maps:get(backend, quic_socket:detect_capabilities()),
    States = [client(Backend) || _ <- lists:seq(1, 200)],
    Ports = [port_of(quic_socket:get_socket(SS)) || SS <- States],
    [quic_socket:close(SS) || SS <- States],
    ?assertEqual(200, length(lists:usort(Ports))).

%% An opened client socket with one datagram sent, so the kernel has
%% assigned its port.
client(Backend) ->
    {ok, SS} = quic_socket:open_for_send({127, 0, 0, 1}, #{
        backend => Backend, batching => #{enabled => false}
    }),
    {ok, SS1} = quic_socket:send(SS, {127, 0, 0, 1}, 9, <<"x">>),
    SS1.

port_of(Socket) when is_port(Socket) ->
    {ok, P} = inet:port(Socket),
    P;
port_of(Socket) ->
    {ok, #{port := P}} = socket:sockname(Socket),
    P.
