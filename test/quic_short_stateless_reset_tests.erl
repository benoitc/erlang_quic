%%% -*- erlang -*-
%%%
%%% A stateless reset is recognised at every size from the 21-byte
%%% minimum (RFC 9000 Section 10.3), including those too short to
%%% carry a header-protection sample after our CID.

-module(quic_short_stateless_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(PEER_CID, <<10, 11, 12, 13, 14, 15, 16, 17>>).

reset_sizes_test_() ->
    Token = crypto:strong_rand_bytes(16),
    State = client(Token),
    [
        {integer_to_list(Size), fun() ->
            ?assertEqual(
                {error, stateless_reset},
                quic_connection:decode_and_decrypt_packet(reset(Size, Token), State)
            )
        end}
     || Size <- lists:seq(21, 45)
    ].

client(Token) ->
    Pool = quic_cid:record_initial_reset_token(
        quic_cid:set_initial_peer_cid(quic_cid:new(<<"own-cid0">>, 2), ?PEER_CID, undefined),
        Token
    ),
    #state{cfg = Cfg} =
        S = quic_connection_test_support:state_for_reset(?PEER_CID, Pool, undefined),
    S1 = quic_connection_test_support:state_with_pn_app(S, 0),
    S1#state{
        app_keys = quic_connection:derive_initial_keys(<<"reset-cid">>, ?QUIC_VERSION_1),
        cfg = Cfg#conn_cfg{scid = <<"own-cid0">>}
    }.

reset(Size, Token) ->
    <<16#40, (crypto:strong_rand_bytes(Size - 17))/binary, Token/binary>>.
