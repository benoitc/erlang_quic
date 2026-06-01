%%% -*- erlang -*-
%%%
%%% PropEr properties for HTTP/3 0-RTT machinery introduced by the
%%% 0-RTT plan: session-ticket event forwarding (Task 3) and request
%%% postponement during `bootstrapping' until `prime' (Task 5).

-module(prop_quic_h3_0rtt).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(WAIT_MS, 2000).

%%====================================================================
%% Generators
%%====================================================================

session_ticket_gen() ->
    ?LET(
        {TicketLen, Nonce, ServerName},
        {range(8, 64), binary(8), oneof([<<"example.com">>, <<"api.test">>, <<"h3.example">>])},
        #session_ticket{
            server_name = ServerName,
            ticket = binary:copy(<<"t">>, TicketLen),
            lifetime = 7200,
            age_add = 0,
            nonce = Nonce,
            resumption_secret = binary:copy(<<0>>, 32),
            max_early_data = 16#FFFFFFFF,
            received_at = 0,
            cipher = aes_128_gcm,
            alpn = <<"h3">>
        }
    ).

session_tickets_gen() ->
    ?LET(N, range(1, 10), vector(N, session_ticket_gen())).

request_headers_gen() ->
    ?LET(
        Tag,
        range(0, 16#FFFFFF),
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":authority">>, <<"example.com">>},
            {<<":path">>, list_to_binary(["/", integer_to_list(Tag)])}
        ]
    ).

request_seq_gen() ->
    ?LET(N, range(1, 8), vector(N, request_headers_gen())).

%%====================================================================
%% Property 1: session_ticket forwarding is lossless
%%====================================================================

prop_session_ticket_forwarding_is_lossless() ->
    ?SETUP(
        fun mock_quic/0,
        ?FORALL(
            Tickets,
            session_tickets_gen(),
            begin
                reset_stream_counters(),
                FakeQC = spawn_fake_quic(),
                {ok, H3} = start_h3_in_early_data(FakeQC),
                ok = drain_owner_mailbox(H3),
                lists:foreach(
                    fun(T) ->
                        H3 ! {quic, FakeQC, {session_ticket, T}}
                    end,
                    Tickets
                ),
                Received = collect_forwarded_tickets(H3, length(Tickets), ?WAIT_MS),
                teardown_h3(H3, FakeQC),
                Received =:= Tickets
            end
        )
    ).

%%====================================================================
%% Property 2: postponed requests are replayed without loss
%%
%% Pragmatic shape: H3 starts in `bootstrapping' and postpones every
%% {request, _, _} call. After `prime', it advances to `early_data',
%% where postponed calls are replayed via gen_statem's [postpone]
%% mechanism. quic:open_stream/1 is mocked to return strictly-
%% increasing stream IDs (delta = 4 per call). The invariant: each
%% caller's reply carries a unique stream ID, the multiset of returned
%% IDs equals the set produced by the mock, and no request is dropped.
%% This is a multiset check, not a strict order check.
%%====================================================================

prop_postponed_requests_replayed_without_loss() ->
    ?SETUP(
        fun mock_quic/0,
        ?FORALL(
            Requests,
            request_seq_gen(),
            begin
                reset_stream_counters(),
                FakeQC = spawn_fake_quic(),
                {ok, H3} = quic_h3_connection:start_link(FakeQC, <<"example.com">>, 443, #{}),
                unlink(H3),
                bootstrapping = current_state(H3),
                CallerPids = spawn_requesters(H3, Requests),
                wait_postponed_calls(H3, length(Requests), ?WAIT_MS),
                ok = quic_h3_connection:prime(H3),
                wait_state(H3, early_data, ?WAIT_MS),
                Results = collect_request_results(CallerPids, ?WAIT_MS),
                teardown_h3(H3, FakeQC),
                check_request_results(Results, length(Requests))
            end
        )
    ).

%%====================================================================
%% EUnit wrapper. Default to 100 runs; both properties are dominated
%% by gen_statem startup/teardown, so we keep counts modest to stay
%% under 30s.
%%====================================================================

proper_test_() ->
    {timeout, 180, [
        ?_assert(
            proper:quickcheck(
                prop_session_ticket_forwarding_is_lossless(),
                [{numtests, 50}, {to_file, user}]
            )
        ),
        ?_assert(
            proper:quickcheck(
                prop_postponed_requests_replayed_without_loss(),
                [{numtests, 50}, {to_file, user}]
            )
        )
    ]}.

%%====================================================================
%% Helpers
%%====================================================================

%% Install the `quic' mock once per property run (PropEr ?SETUP) and
%% return the finalizer. Re-mocking the large, cover-compiled `quic'
%% god-module on every ?FORALL iteration serialised through the global
%% cover_server and made meck_proc:start/2 time out under CI load.
mock_quic() ->
    ok = setup_meck(true),
    fun teardown_meck/0.

%% Restart the per-run stream-id counters at the top of each iteration so
%% ids restart at 0 even though the mock is installed once per property.
reset_stream_counters() ->
    counters:put(persistent_term:get({?MODULE, uni_counter}), 1, 0),
    counters:put(persistent_term:get({?MODULE, bidi_counter}), 1, 0),
    ok.

setup_meck(HasEarlyKeys) ->
    catch meck:unload(quic),
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    meck:expect(quic, has_early_keys, fun(_) -> HasEarlyKeys end),
    meck:expect(quic, early_data_accepted, fun(_) -> unknown end),
    UniCounter = counters:new(1, []),
    BidiCounter = counters:new(1, []),
    persistent_term:put({?MODULE, uni_counter}, UniCounter),
    persistent_term:put({?MODULE, bidi_counter}, BidiCounter),
    meck:expect(quic, open_unidirectional_stream, fun(_) ->
        counters:add(UniCounter, 1, 1),
        N = counters:get(UniCounter, 1),
        {ok, (N - 1) * 4 + 2}
    end),
    meck:expect(quic, open_stream, fun(_) ->
        counters:add(BidiCounter, 1, 1),
        N = counters:get(BidiCounter, 1),
        {ok, (N - 1) * 4}
    end),
    meck:expect(quic, send_data, fun(_, _, _, _) -> ok end),
    ok.

teardown_meck() ->
    catch meck:unload(quic),
    persistent_term:erase({?MODULE, uni_counter}),
    persistent_term:erase({?MODULE, bidi_counter}),
    ok.

spawn_fake_quic() ->
    spawn(fun fake_quic_loop/0).

fake_quic_loop() ->
    receive
        stop -> ok;
        _ -> fake_quic_loop()
    end.

start_h3_in_early_data(QuicConn) ->
    {ok, H3} = quic_h3_connection:start_link(QuicConn, <<"example.com">>, 443, #{}),
    unlink(H3),
    ok = quic_h3_connection:prime(H3),
    wait_state(H3, early_data, ?WAIT_MS),
    {ok, H3}.

current_state(Pid) ->
    {StateName, _} = sys:get_state(Pid, 2000),
    StateName.

wait_state(_Pid, _Target, Timeout) when Timeout =< 0 ->
    erlang:error(timeout_waiting_for_state);
wait_state(Pid, Target, Timeout) ->
    case current_state(Pid) of
        Target ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Pid, Target, Timeout - 10)
    end.

drain_owner_mailbox(H3) ->
    receive
        {quic_h3, H3, _} -> drain_owner_mailbox(H3)
    after 0 -> ok
    end.

collect_forwarded_tickets(_H3, 0, _Timeout) ->
    [];
collect_forwarded_tickets(H3, N, Timeout) ->
    receive
        {quic_h3, H3, {session_ticket, T}} ->
            [T | collect_forwarded_tickets(H3, N - 1, Timeout)]
    after Timeout ->
        erlang:error({timeout_waiting_for_tickets, N})
    end.

spawn_requesters(H3, Requests) ->
    Parent = self(),
    lists:map(
        fun({Idx, Headers}) ->
            Pid = spawn(fun() ->
                Parent ! {ready, self()},
                receive
                    go -> ok
                end,
                Reply = quic_h3_connection:request(H3, Headers),
                Parent ! {result, self(), Idx, Reply}
            end),
            receive
                {ready, Pid} -> ok
            after ?WAIT_MS ->
                erlang:error({timeout_spawning_requester, Idx})
            end,
            Pid ! go,
            %% Sleep briefly so this caller's $gen_call message lands
            %% in the H3 mailbox before the next caller is spawned.
            %% gen_statem's mailbox is FIFO per-sender, so a tiny
            %% inter-sender gap is enough to make global ordering
            %% deterministic.
            timer:sleep(2),
            {Idx, Pid}
        end,
        lists:zip(lists:seq(1, length(Requests)), Requests)
    ).

%% Verify the gen_statem has at least N pending postponed messages
%% by checking message_queue_len + already-postponed count via
%% process_info. This is a coarse check; we just sleep until the
%% queue settles.
wait_postponed_calls(_Pid, 0, _Timeout) ->
    ok;
wait_postponed_calls(Pid, _N, Timeout) when Timeout =< 0 ->
    erlang:error({timeout_waiting_for_postponed_calls, Pid});
wait_postponed_calls(Pid, N, Timeout) ->
    %% Best-effort: sample until the mailbox has been drained into
    %% postponed state. gen_statem with `postpone` keeps messages
    %% out of the regular mailbox once processed, so a small sleep
    %% is sufficient.
    case erlang:process_info(Pid, message_queue_len) of
        {message_queue_len, 0} ->
            ok;
        _ ->
            timer:sleep(5),
            wait_postponed_calls(Pid, N, Timeout - 5)
    end.

collect_request_results(CallerPids, Timeout) ->
    lists:map(
        fun({Idx, Pid}) ->
            receive
                {result, Pid, Idx, Reply} -> {Idx, Reply}
            after Timeout ->
                erlang:error({timeout_waiting_for_result, Idx, Pid})
            end
        end,
        CallerPids
    ).

check_request_results(Results, N) ->
    %% Every caller must have produced {ok, StreamId}; stream IDs
    %% must be the N distinct client-bidi IDs the mock generated.
    StreamIds = [
        case R of
            {ok, Id} -> Id;
            Other -> erlang:error({unexpected_reply, Other})
        end
     || {_Idx, R} <- Results
    ],
    Sorted = lists:sort(StreamIds),
    Unique = lists:usort(StreamIds),
    Expected = [I * 4 || I <- lists:seq(0, N - 1)],
    %% No drops, no duplicates, exactly the IDs the mock minted.
    Sorted =:= Expected andalso length(Unique) =:= N.

teardown_h3(H3, FakeQC) ->
    catch unlink(H3),
    wait_down(H3, shutdown),
    catch unlink(FakeQC),
    wait_down(FakeQC, shutdown),
    ok.

%% Stop a helper process and block until it is actually dead, so no
%% iteration leaves an H3 still executing a mocked `quic' call when the
%% next iteration (or the ?SETUP finalizer's meck:unload) runs.
wait_down(Pid, Reason) ->
    MRef = erlang:monitor(process, Pid),
    catch exit(Pid, Reason),
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after ?WAIT_MS ->
        erlang:demonitor(MRef, [flush]),
        ok
    end.
