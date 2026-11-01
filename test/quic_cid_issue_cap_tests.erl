%%% -*- erlang -*-
%%%
%%% active_connection_id_limit has no upper bound (RFC 9000 Section
%%% 18.2), so how many CIDs we issue is ours to cap.

-module(quic_cid_issue_cap_tests).

-include_lib("eunit/include/eunit.hrl").

huge_peer_limit_test() ->
    Pool = quic_cid:set_peer_active_limit(quic_cid:new(<<"own-cid0">>, 2), 1 bsl 30),
    ?assert(quic_cid:replenish_needed(Pool) < 16).
