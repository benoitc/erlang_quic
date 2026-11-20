%%% -*- erlang -*-
%%%
%%% A fatal alert ends the handshake (RFC 9846 Section 6.2), and a closing
%%% connection repeats the CONNECTION_CLOSE it sent rather than sending a
%%% different one (RFC 9000 Section 10.2.1).
%%%
%%% A server that requires a client certificate and gets an empty one
%%% closes with certificate_required. The client's Finished, in the same
%%% flight, must not be read after that: it used to raise a second alert,
%%% unexpected_message, sent as a second CONNECTION_CLOSE that the client
%%% could see instead of the first.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_tls_one_close_tests).

-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% certificate_request_context <<>>, certificate_list <<>>.
-define(EMPTY_CERTIFICATE, <<?TLS_CERTIFICATE, 4:24, 0, 0:24>>).
-define(FINISHED, <<?TLS_FINISHED, 32:24, 0:256>>).

the_rest_of_the_flight_is_not_read_test() ->
    Alone = refuse(?EMPTY_CERTIFICATE),
    WithFinished = captured(fun() -> refuse(<<?EMPTY_CERTIFICATE/binary, ?FINISHED/binary>>) end),
    %% The Finished never reaches the handshake: nothing logs it as unexpected.
    ?assertEqual([], unexpected_messages()),
    ?assertEqual({tls_alert, ?TLS_ALERT_CERTIFICATE_REQUIRED}, close_reason(Alone)),
    ?assertEqual({tls_alert, ?TLS_ALERT_CERTIFICATE_REQUIRED}, close_reason(WithFinished)),
    ?assertEqual(packets_sent(Alone), packets_sent(WithFinished)).

a_second_close_sends_nothing_test() ->
    S0 = server(),
    S1 = quic_connection:send_tls_alert(?TLS_ALERT_CERTIFICATE_REQUIRED, S0),
    Sent = packets_sent(S1),
    ?assert(Sent > 0),
    S2 = quic_connection:send_tls_alert(?TLS_ALERT_UNEXPECTED_MESSAGE, S1),
    ?assertEqual({tls_alert, ?TLS_ALERT_CERTIFICATE_REQUIRED}, close_reason(S2)),
    ?assertEqual(Sent, packets_sent(S2)),
    ?assertEqual(S1#state.closing_frame, S2#state.closing_frame).

%%====================================================================
%% Helpers
%%====================================================================

log(#{msg := {report, #{what := unexpected_tls_message} = Report}}, #{config := #{pid := Pid}}) ->
    Pid ! {unexpected_tls_message, Report};
log(_Event, _Config) ->
    ok.

captured(Fun) ->
    Id = list_to_atom("quic_tls_one_close_" ++ integer_to_list(erlang:unique_integer([positive]))),
    #{level := Primary} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun()
    after
        logger:remove_handler(Id),
        logger:set_primary_config(level, Primary)
    end.

unexpected_messages() ->
    receive
        {unexpected_tls_message, Report} -> [Report | unexpected_messages()]
    after 0 -> []
    end.

%% A server waiting for the client's Certificate, with mTLS required,
%% given one handshake flight.
refuse(Flight) ->
    #state{cfg = Cfg, hs = HS} = S0 = server(),
    quic_connection:process_tls_messages(handshake, Flight, S0#state{
        cfg = Cfg#conn_cfg{require_client_cert = true},
        hs = HS#hs{tls_state = awaiting_client_cert}
    }).

%% Built anew each time: the packet counter is shared by copies of a state.
server() ->
    quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ).

close_reason(#state{close_reason = Reason}) -> Reason.

packets_sent(State) ->
    quic_connection_test_support:state_get(State, packets_sent).
