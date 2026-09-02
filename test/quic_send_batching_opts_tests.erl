%%% -*- erlang -*-
%%%
%%% Options and socket wiring on the batched send/receive path.
%%%
%%% GSO and GRO themselves need a Linux kernel, so what is covered here
%%% is what does not: the source bind the client performs, and the two
%%% send-path options staying honest end to end. A too-small burst
%%% budget or ACK tolerance must slow a transfer down, never stall or
%%% corrupt it.

-module(quic_send_batching_opts_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PAYLOAD_SIZE, 262144).

%%====================================================================
%% Client source bind (#261)
%%====================================================================

%% The socket backend used to leave the source address to the kernel's
%% route lookup, which picks a different address than the caller asked
%% for on a multi-address host.
client_binds_the_requested_source_address_test() ->
    {ok, State} = quic_socket:open_for_send({127, 0, 0, 1}, #{
        backend => socket,
        extra_socket_opts => [{ip, {127, 0, 0, 1}}]
    }),
    try
        {ok, {Addr, Port}} = quic_socket:sockname(State),
        ?assertEqual({127, 0, 0, 1}, Addr),
        ?assert(Port > 0)
    after
        quic_socket:close(State)
    end.

%% Without the option the kernel still chooses, and the socket is
%% usable: the bind is opt-in, not a new requirement.
client_without_a_source_option_still_opens_test() ->
    {ok, State} = quic_socket:open_for_send({127, 0, 0, 1}, #{backend => socket}),
    try
        ?assertMatch({ok, {_Addr, _Port}}, quic_socket:sockname(State))
    after
        quic_socket:close(State)
    end.

%%====================================================================
%% Send-path options (#213, #214)
%%====================================================================

burst_budget_test_() ->
    {timeout, 30, fun a_small_burst_budget_still_delivers/0}.

ack_tolerance_test_() ->
    {timeout, 30, fun a_tight_ack_tolerance_still_delivers/0}.

%% max_burst_packets bounds how many packets leave per drain. Setting it
%% far below the default must only add drains, never drop the remainder
%% of the queue.
a_small_burst_budget_still_delivers() ->
    ?assertEqual(?PAYLOAD_SIZE, echo_roundtrip(#{max_burst_packets => 4})).

%% ack_packet_tolerance controls how many ack-eliciting packets pile up
%% before an ACK goes out. 1 acks every packet, which is legal and just
%% chattier.
a_tight_ack_tolerance_still_delivers() ->
    ?assertEqual(?PAYLOAD_SIZE, echo_roundtrip(#{ack_packet_tolerance => 1})).

%%====================================================================
%% Helpers
%%====================================================================

echo_roundtrip(ExtraClientOpts) ->
    Windows = #{
        max_data => 16 * 1024 * 1024,
        max_stream_data_bidi_local => 8 * 1024 * 1024,
        max_stream_data_bidi_remote => 8 * 1024 * 1024,
        max_stream_data_uni => 8 * 1024 * 1024
    },
    {ok, Srv} = quic_test_echo_server:start(Windows),
    try
        #{port := Port} = Srv,
        Opts = maps:merge(
            maps:merge(quic_test_echo_server:client_opts(), Windows),
            ExtraClientOpts
        ),
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = binary:copy(<<"x">>, ?PAYLOAD_SIZE),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            byte_size(collect(Conn, StreamId, <<>>))
        after
            quic:safe_close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

collect(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 20000 ->
        Acc
    end.
