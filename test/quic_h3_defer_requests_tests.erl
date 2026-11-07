%%% -*- erlang -*-
%%%
%%% Server option defer_requests_until_settings: a request whose HEADERS
%%% arrive before the client's SETTINGS is dispatched only once SETTINGS
%%% are applied, and so are the streams a stream_type_handler would see
%%% (WebTransport draft-17 §7.1).

-module(quic_h3_defer_requests_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    Uni = counters:new(1, []),
    meck:expect(quic, open_unidirectional_stream, fun(_) ->
        counters:add(Uni, 1, 1),
        {ok, (counters:get(Uni, 1) - 1) * 4 + 3}
    end),
    meck:expect(quic, send_data, fun(_, _, _, _) -> ok end),
    meck:expect(quic, set_stream_priority, fun(_, _, _, _) -> ok end),
    ok.

teardown(_) ->
    meck:unload(quic).

deferred_request_waits_for_settings_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(#{defer_requests_until_settings => true}),
        send_request(Conn, Fake),
        refute_request(Conn),
        send_settings(Conn, Fake),
        assert_request(Conn),
        ?assertMatch({handler, #{}}, handler_saw()),
        stop(Conn, Fake)
    end}.

deferred_requests_keep_arrival_order_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(#{defer_requests_until_settings => true}),
        send_request(Conn, Fake, 0, <<"/a">>),
        send_request(Conn, Fake, 4, <<"/b">>),
        refute_request(Conn),
        send_settings(Conn, Fake),
        receive
            {quic_h3, Conn, {request, 0, <<"GET">>, <<"/a">>, _}} -> ok
        after 500 -> error(no_first_request)
        end,
        receive
            {quic_h3, Conn, {request, 4, <<"GET">>, <<"/b">>, _}} -> ok
        after 500 -> error(no_second_request)
        end,
        _ = [handler_saw() || _ <- [1, 2]],
        stop(Conn, Fake)
    end}.

%% Default off: the request is dispatched at once, before SETTINGS.
request_not_deferred_by_default_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(#{}),
        send_request(Conn, Fake),
        assert_request(Conn),
        ?assertEqual({handler, undefined}, handler_saw()),
        stop(Conn, Fake)
    end}.

%% A WebTransport uni stream and bidi stream that arrive before SETTINGS
%% reach the owner after them, in arrival order.
streams_held_until_settings_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(wt_opts(#{defer_requests_until_settings => true})),
        Conn ! {quic, Fake, {stream_data, 6, <<16#40, 16#54, 0, "u1">>, false}},
        Conn ! {quic, Fake, {stream_data, 6, <<"u2">>, false}},
        Conn ! {quic, Fake, {stream_data, 4, <<16#40, 16#41, 0, "b1">>, false}},
        refute_stream_event(Conn),
        send_settings(Conn, Fake),
        ?assertEqual(
            [
                {stream_type_open, uni, 6, 16#54},
                {stream_type_data, uni, 6, <<0, "u1">>, false},
                {stream_type_data, uni, 6, <<"u2">>, false},
                {stream_type_open, bidi, 4, 16#41},
                {stream_type_data, bidi, 4, <<0, "b1">>, false}
            ],
            [next_stream_event(Conn) || _ <- lists:seq(1, 5)]
        ),
        stop(Conn, Fake)
    end}.

streams_not_held_by_default_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(wt_opts(#{})),
        Conn ! {quic, Fake, {stream_data, 4, <<16#40, 16#41, 0>>, false}},
        ?assertEqual({stream_type_open, bidi, 4, 16#41}, next_stream_event(Conn)),
        stop(Conn, Fake)
    end}.

%% A held stream the peer resets never reaches the owner.
reset_held_stream_is_dropped_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {Fake, Conn} = start_server(wt_opts(#{defer_requests_until_settings => true})),
        Conn ! {quic, Fake, {stream_data, 6, <<16#40, 16#54, 0>>, false}},
        Conn ! {quic, Fake, {stream_reset, 6, 16#10c}},
        send_settings(Conn, Fake),
        refute_stream_event(Conn),
        stop(Conn, Fake)
    end}.

%% What is held before SETTINGS is bounded by max_buffered_body.
held_streams_are_bounded_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        Self = self(),
        meck:expect(quic, safe_close, fun(_, Code, _) ->
            Self ! {quic_close, Code},
            ok
        end),
        {Fake, Conn} = start_server(
            wt_opts(#{defer_requests_until_settings => true, max_buffered_body => 8})
        ),
        Conn ! {quic, Fake, {stream_data, 6, <<16#40, 16#54, 0:64>>, false}},
        receive
            {quic_close, Code} -> ?assertEqual(16#0107, Code)
        after 500 -> error(no_close)
        end,
        stop(Conn, Fake)
    end}.

bad_option_value_is_rejected_test() ->
    ?assertError(
        {bad_opts, {defer_requests_until_settings, yes}},
        quic_h3:start_server(defer_bad_opt, 0, #{defer_requests_until_settings => yes})
    ).

%%====================================================================
%% Helpers
%%====================================================================

start_server(Opts) ->
    Self = self(),
    Handler = fun(C, _StreamId, _Method, _Path, _Headers) ->
        Self ! {handler, quic_h3_connection:get_peer_settings(C)}
    end,
    Fake = spawn(fun fake_quic_loop/0),
    {ok, Conn} = gen_statem:start(
        quic_h3_connection, {server, Fake, Opts#{handler => Handler}, Self}, []
    ),
    Conn ! {quic, Fake, {connected, #{}}},
    wait_state(Conn, h3_connecting, 500),
    {Fake, Conn}.

wt_opts(Opts) ->
    Opts#{stream_type_handler => fun(_Dir, _StreamId, _Type) -> claim end}.

next_stream_event(Conn) ->
    receive
        {quic_h3, Conn, {stream_type_open, _, _, _} = E} -> E;
        {quic_h3, Conn, {stream_type_data, _, _, _, _} = E} -> E
    after 500 -> no_stream_event
    end.

refute_stream_event(Conn) ->
    receive
        {quic_h3, Conn, {stream_type_open, _, _, _} = E} -> error({early, E});
        {quic_h3, Conn, {stream_type_data, _, _, _, _} = E} -> error({early, E})
    after 100 -> ok
    end.

send_request(Conn, Fake) ->
    send_request(Conn, Fake, 0, <<"/">>).

send_request(Conn, Fake, StreamId, Path) ->
    Block = quic_qpack:encode([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, Path}
    ]),
    Conn ! {quic, Fake, {stream_data, StreamId, quic_h3_frame:encode({headers, Block}), true}}.

send_settings(Conn, Fake) ->
    Type = quic_h3_frame:encode_stream_type(control),
    Settings = quic_h3_frame:encode_settings(#{}),
    Conn ! {quic, Fake, {stream_data, 2, <<Type/binary, Settings/binary>>, false}}.

refute_request(Conn) ->
    receive
        {quic_h3, Conn, {request, _, _, _, _}} -> error(request_before_settings);
        {handler, _} -> error(handler_before_settings)
    after 100 -> ok
    end.

assert_request(Conn) ->
    receive
        {quic_h3, Conn, {request, 0, <<"GET">>, <<"/">>, _}} -> ok
    after 500 -> error(no_request)
    end.

handler_saw() ->
    receive
        {handler, _} = Msg -> Msg
    after 500 -> error(handler_not_run)
    end.

wait_state(_Pid, Target, Timeout) when Timeout =< 0 ->
    error({timeout_waiting_for_state, Target});
wait_state(Pid, Target, Timeout) ->
    case sys:get_state(Pid, 1000) of
        {Target, _} ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Pid, Target, Timeout - 10)
    end.

stop(Conn, Fake) ->
    exit(Conn, kill),
    exit(Fake, kill),
    ok.

fake_quic_loop() ->
    receive
        stop -> ok;
        _ -> fake_quic_loop()
    end.
