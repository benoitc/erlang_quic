%%% -*- erlang -*-
%%%
%%% RFC 9000 §7.4 / §18.2: bad peer transport parameters must cause a
%%% TRANSPORT_PARAMETER_ERROR CONNECTION_CLOSE. h3spec exercises this path.

-module(quic_transport_param_errors_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

server_rejects_client_with_server_only_param_test() ->
    S0 = quic_connection:test_state_for_role(server),
    %% original_dcid is server-only; a client MUST NOT send it.
    BadParams = #{
        initial_scid => <<>>,
        original_dcid => <<1, 2, 3, 4>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_missing_initial_scid_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:apply_peer_transport_params(#{}, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_preferred_address_from_client_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        preferred_address => <<0:16/unit:8>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).
