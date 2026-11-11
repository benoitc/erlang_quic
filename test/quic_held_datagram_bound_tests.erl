%%% -*- erlang -*-
%%%
%%% Datagrams held by the anti-amplification limit stay bounded.
%%%
%%% RFC 9000 Section 8.1 holds sending to an unvalidated address to
%%% three times what it received; what cannot go out yet is held. Held
%%% datagrams are already tracked as sent, so dropping one past the bound
%%% loses nothing loss detection cannot resend.
-module(quic_held_datagram_bound_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

held_datagrams_are_bounded_test() ->
    S = lists:foldl(fun hold/2, #state{mig = #mig{}}, lists:seq(1, 10 * ?MAX_HELD_DATAGRAMS)),
    Held = (S#state.mig)#mig.held,
    ?assertEqual(?MAX_HELD_DATAGRAMS, length(Held)),
    %% The oldest are kept, so release order stays the send order.
    ?assertEqual(lists:seq(1, ?MAX_HELD_DATAGRAMS), [N || <<N:32, _/binary>> <- lists:reverse(Held)]).

below_the_bound_every_datagram_is_held_test() ->
    S = lists:foldl(fun hold/2, #state{mig = #mig{}}, lists:seq(1, ?MAX_HELD_DATAGRAMS - 1)),
    ?assertEqual(?MAX_HELD_DATAGRAMS - 1, length((S#state.mig)#mig.held)).

hold(N, State) ->
    Packet = <<N:32, 0:(1196 * 8)>>,
    quic_connection:note_amp_send(Packet, byte_size(Packet), 0, true, State).
