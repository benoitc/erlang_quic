%% A client Initial flight larger than one datagram must reach the
%% connection in full.
%%
%% The listener drains its mailbox into one receive sweep and groups
%% the packets by destination. For a DCID it has never seen, the group
%% starts a connection; every packet in that group after the first has
%% to be forwarded to it as well. Dropping them costs a PTO before the
%% client resends, and a chunked ClientHello (x25519mlkem768 splits one
%% across Initials) makes a multi-datagram flight the normal case.
%%
%% Determinism: the listener is suspended while both datagrams are put
%% on the wire, so they are both in its mailbox before it runs and the
%% sweep is guaranteed to see them together. The connection is
%% suspended the moment it is created, so its mailbox accumulates
%% whatever the listener routed instead of draining it.
-module(quic_listener_initial_flight_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID, <<9, 9, 9, 9, 9, 9, 9, 9>>).
-define(SCID, <<1, 2, 3, 4>>).

%% Long header, fixed bit, QUIC v1 Initial (type bits 00). Only the
%% header is parsed for routing, so the body can be anything: the
%% connection process is suspended before it looks at it.
%% Padded to the 1200 bytes a client Initial datagram has.
initial(Body) ->
    Packet = <<
        16#C0,
        1:32,
        (byte_size(?DCID)),
        ?DCID/binary,
        (byte_size(?SCID)),
        ?SCID/binary,
        Body/binary
    >>,
    <<Packet/binary, 0:((1200 - byte_size(Packet)) * 8)>>.

%% Capture and freeze the connection the listener creates. Returning
%% {error, _} keeps the listener from calling set_owner_sync, which
%% would deadlock against the suspend.
handler(Test) ->
    fun(ConnPid, _DCID) ->
        sys:suspend(ConnPid),
        Test ! {conn, ConnPid},
        {error, frozen_by_test}
    end.

wait_for_queue(Pid, N, 0) ->
    ?assertEqual(
        {N, ok},
        {element(2, process_info(Pid, message_queue_len)), timed_out_waiting_for_packets}
    );
wait_for_queue(Pid, N, Tries) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, Len} when Len >= N -> ok;
        _ ->
            timer:sleep(20),
            wait_for_queue(Pid, N, Tries - 1)
    end.

%% Both Initials of a two-datagram flight reach the new connection.
whole_initial_flight_reaches_the_connection_test_() ->
    {timeout, 30, fun() ->
        %% A PSK satisfies the listener's auth check without needing
        %% cert files; no handshake runs here, the connection is frozen
        %% before it looks at a packet.
        {ok, Listener} = quic_listener:start(0, #{
            connection_handler => handler(self()),
            psks => #{<<"id">> => <<"secret">>},
            alpn => [<<"h3">>]
        }),
        Port = quic_listener:get_port(Listener),
        {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
        try
            P1 = initial(<<"first-chunk">>),
            P2 = initial(<<"second-chunk">>),

            %% Freeze the listener so both datagrams queue up and the
            %% sweep sees them as one group.
            sys:suspend(Listener),
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, P1),
            ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, P2),
            wait_for_queue(Listener, 2, 100),
            sys:resume(Listener),

            ConnPid =
                receive
                    {conn, Pid} -> Pid
                after 5000 -> exit(no_connection_created)
                end,

            %% One {quic_packet, P1, _} from connection creation and
            %% one {quic_packets, [P2], _} for the remainder of the
            %% flight. Without the forward, only the first ever
            %% arrives and this times out.
            wait_for_queue(ConnPid, 2, 100),
            {messages, Msgs} = process_info(ConnPid, messages),
            Delivered = lists:append([
                case M of
                    {quic_packet, P, _} -> [P];
                    {quic_packets, Ps, _} -> Ps;
                    _ -> []
                end
             || M <- Msgs
            ]),
            ?assertEqual([P1, P2], Delivered),

            sys:resume(ConnPid)
        after
            gen_udp:close(Sock),
            catch quic_listener:stop(Listener)
        end
    end}.
