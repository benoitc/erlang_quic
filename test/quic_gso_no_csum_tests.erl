%%% -*- erlang -*-
%%%
%%% Before Linux 6.11 the kernel answers EIO to a segmented send when
%%% the route's device does not checksum on transmit, as virtio-net
%%% under some hypervisors does not. scripts/test_gso_no_csum.sh builds
%%% such a device and runs these tests against it; without the peer it
%%% names in the environment there is nothing to run.

-module(quic_gso_no_csum_tests).

-include_lib("eunit/include/eunit.hrl").

-export([log/2]).

-define(TRANSFER_SIZE, 1 bsl 20).

gso_no_csum_test_() ->
    case {os:getenv("QUIC_GSO_PEER_NETNS"), os:getenv("QUIC_GSO_PEER_ADDR")} of
        {Netns, Addr} when is_list(Netns), is_list(Addr) ->
            {ok, Peer} = inet:parse_address(Addr),
            [
                {timeout, 30, fun() -> kernel_refuses_the_run(Netns, Peer) end},
                {timeout, 60, fun() -> transfer_turns_gso_off_once(Netns, Peer) end}
            ];
        _ ->
            []
    end.

kernel_refuses_the_run(Netns, Peer) ->
    {ok, Recv} = gen_udp:open(0, [
        binary, {active, false}, {ip, Peer}, {netns, Netns}, {recbuf, 1 bsl 20}
    ]),
    {ok, Port} = inet:port(Recv),
    {ok, S} = socket:open(inet, dgram, udp),
    try
        Packets = [packet(N, 1200) || N <- [1, 2, 3]],
        Dest = #{family => inet, addr => Peer, port => Port},
        ?assertEqual({gso_refused, eio}, quic_socket:send_runs(S, Dest, [{gso, 1200, Packets}])),
        ?assertEqual(Packets, recv_all(Recv))
    after
        socket:close(S),
        gen_udp:close(Recv)
    end.

transfer_turns_gso_off_once(Netns, Peer) ->
    {ok, Server} = quic_test_echo_server:start(#{
        extra_socket_opts => [{ip, Peer}, {netns, Netns}]
    }),
    ok = logger:add_handler(?MODULE, ?MODULE, #{level => warning, config => self()}),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{
            alpn => [<<"echo">>], socket_backend => socket
        }),
        {ok, Conn} = quic:connect(Peer, maps:get(port, Server), Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> error(connect_timeout)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        Data = crypto:strong_rand_bytes(?TRANSFER_SIZE),
        ok = quic:send_data(Conn, StreamId, Data, true),
        ?assertEqual(Data, collect(Conn, StreamId, <<>>)),
        quic:close(Conn, normal),
        ?assertEqual([{gso_disabled, eio}], socket_warnings())
    after
        logger:remove_handler(?MODULE),
        quic_test_echo_server:stop(Server)
    end.

%% logger handler callback
log(#{msg := {report, #{what := What} = Report}}, #{config := Pid}) when
    What =:= gso_disabled; What =:= gso_run_send_error
->
    Pid ! {socket_warning, What, maps:get(reason, Report, undefined)};
log(_, _) ->
    ok.

socket_warnings() ->
    receive
        {socket_warning, What, Reason} -> [{What, Reason} | socket_warnings()]
    after 0 -> []
    end.

collect(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 30000 ->
        error({transfer_timeout, byte_size(Acc)})
    end.

recv_all(Recv) ->
    case gen_udp:recv(Recv, 0, 500) of
        {ok, {_, _, Data}} -> [Data | recv_all(Recv)];
        {error, timeout} -> []
    end.

packet(N, Size) ->
    <<N:16, (binary:copy(<<0>>, Size - 2))/binary>>.
