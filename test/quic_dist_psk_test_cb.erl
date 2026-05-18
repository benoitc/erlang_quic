%%% -*- erlang -*-
%%%
%%% PSK lookup callback used by quic_dist_psk_SUITE. The dist
%%% driver dispatches `Module:Function(Identity)` on the configured
%%% callback; this module hands back a fixed shared secret for the
%%% test identity. Keeping the callback in its own module keeps
%%% production code free of test fixtures.

-module(quic_dist_psk_test_cb).

-export([cluster/1]).

cluster(<<"cluster">>) ->
    {ok, <<"shared-cluster-psk-32-bytes!!!!!">>};
cluster(_) ->
    not_found.
