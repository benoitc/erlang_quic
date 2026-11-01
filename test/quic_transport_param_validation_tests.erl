%%% -*- erlang -*-
%%%
%%% Transport parameters RFC 9000 Sections 7.3, 7.4 and 18.2 and RFC 9001
%%% Section 8.2 require an endpoint to reject.

-module(quic_transport_param_validation_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% max_idle_timeout = 10 as a two-byte varint, then one byte too many.
integer_with_trailing_bytes_test() ->
    ?assertMatch({error, _}, quic_tls:decode_transport_params(<<1, 3, 16#40, 10, 0>>)).

short_stateless_reset_token_test() ->
    ?assertMatch({error, _}, quic_tls:decode_transport_params(<<2, 8, 0:64>>)).

preferred_address_with_empty_cid_test() ->
    PA = <<0:32, 0:16, 0:128, 0:16, 0, 0:128>>,
    ?assertMatch(
        {error, _}, quic_tls:decode_transport_params(<<16#0d, (byte_size(PA)), PA/binary>>)
    ).

retry_scid_without_retry_test() ->
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        apply(server_tp(#{retry_scid => <<"retry-sc">>}))
    ).

missing_extension_test() ->
    ?assertMatch({pending_close, transport, 16#016d, _}, apply(missing)).

undecodable_parameters_test() ->
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        apply({error, invalid_transport_params})
    ).

valid_parameters_test() ->
    ?assertEqual(undefined, apply(server_tp(#{}))).

apply(TP) ->
    S = quic_connection:apply_peer_transport_params(TP, client()),
    S#state.close_reason.

server_tp(Extra) ->
    maps:merge(#{original_dcid => <<"orig-dci">>, initial_scid => <<"server-c">>}, Extra).

client() ->
    #state{cfg = Cfg} = S = quic_connection_test_support:state_with_keys(client),
    S#state{dcid = <<"server-c">>, cfg = Cfg#conn_cfg{original_dcid = <<"orig-dci">>}}.
