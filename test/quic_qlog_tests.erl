%%%-------------------------------------------------------------------
%%% @doc Unit tests for quic_qlog module
%%% @end
%%%-------------------------------------------------------------------
-module(quic_qlog_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_qlog.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

setup() ->
    %% Create temp directory for test files
    TmpDir = filename:join(["/tmp", "qlog_test_" ++ integer_to_list(erlang:system_time())]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    TmpDir.

cleanup(TmpDir) ->
    %% Clean up test files
    case file:list_dir(TmpDir) of
        {ok, Files} ->
            [file:delete(filename:join(TmpDir, F)) || F <- Files],
            file:del_dir(TmpDir);
        _ ->
            ok
    end.

%%====================================================================
%% Context Creation Tests
%%====================================================================

new_disabled_test() ->
    %% QLOG disabled by default
    Result = quic_qlog:new(#{}, <<1, 2, 3, 4>>, client),
    ?assertEqual(undefined, Result).

new_disabled_explicit_test() ->
    %% QLOG explicitly disabled
    Opts = #{qlog => #{enabled => false}},
    Result = quic_qlog:new(Opts, <<1, 2, 3, 4>>, client),
    ?assertEqual(undefined, Result).

new_enabled_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<16#de, 16#ad, 16#be, 16#ef>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        [
            ?_assertEqual(true, Ctx#qlog_ctx.enabled),
            ?_assertEqual(ODCID, Ctx#qlog_ctx.odcid),
            ?_assertEqual(client, Ctx#qlog_ctx.vantage_point),
            ?_assertEqual(all, Ctx#qlog_ctx.events),
            ?_assert(is_pid(Ctx#qlog_ctx.writer)),
            ?_assert(is_integer(Ctx#qlog_ctx.reference_time)),
            %% Cleanup
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

new_with_event_filter_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<1, 2, 3, 4>>,
        Events = [packet_sent, packet_received],
        Opts = #{qlog => #{enabled => true, dir => TmpDir, events => Events}},
        Ctx = quic_qlog:new(Opts, ODCID, server),
        [
            ?_assertEqual(Events, Ctx#qlog_ctx.events),
            ?_assertEqual(server, Ctx#qlog_ctx.vantage_point),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

%%====================================================================
%% is_enabled Tests
%%====================================================================

is_enabled_undefined_test() ->
    ?assertEqual(false, quic_qlog:is_enabled(undefined)).

is_enabled_disabled_test() ->
    Ctx = #qlog_ctx{enabled = false},
    ?assertEqual(false, quic_qlog:is_enabled(Ctx)).

is_enabled_enabled_test() ->
    Ctx = #qlog_ctx{enabled = true},
    ?assertEqual(true, quic_qlog:is_enabled(Ctx)).

%%====================================================================
%% Event Emission Tests
%%====================================================================

event_undefined_ctx_test() ->
    %% All events should handle undefined gracefully
    ?assertEqual(ok, quic_qlog:packet_sent(undefined, #{})),
    ?assertEqual(ok, quic_qlog:packet_received(undefined, #{})),
    ?assertEqual(ok, quic_qlog:frames_processed(undefined, [])),
    ?assertEqual(ok, quic_qlog:connection_started(undefined)),
    ?assertEqual(ok, quic_qlog:connection_state_updated(undefined, idle, handshaking)),
    ?assertEqual(ok, quic_qlog:connection_closed(undefined, 0, <<>>)),
    ?assertEqual(ok, quic_qlog:packets_acked(undefined, [1, 2, 3], #{})),
    ?assertEqual(ok, quic_qlog:packet_lost(undefined, #{packet_number => 1})),
    ?assertEqual(ok, quic_qlog:metrics_updated(undefined, #{})).

event_disabled_ctx_test() ->
    %% All events should handle disabled context gracefully
    Ctx = #qlog_ctx{enabled = false},
    ?assertEqual(ok, quic_qlog:packet_sent(Ctx, #{})),
    ?assertEqual(ok, quic_qlog:packet_received(Ctx, #{})),
    ?assertEqual(ok, quic_qlog:frames_processed(Ctx, [])),
    ?assertEqual(ok, quic_qlog:connection_started(Ctx)),
    ?assertEqual(ok, quic_qlog:connection_state_updated(Ctx, idle, handshaking)),
    ?assertEqual(ok, quic_qlog:connection_closed(Ctx, 0, <<>>)),
    ?assertEqual(ok, quic_qlog:packets_acked(Ctx, [1, 2, 3], #{})),
    ?assertEqual(ok, quic_qlog:packet_lost(Ctx, #{packet_number => 1})),
    ?assertEqual(ok, quic_qlog:metrics_updated(Ctx, #{})).

packet_sent_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<16#aa, 16#bb, 16#cc, 16#dd>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        Info = #{
            packet_type => initial,
            packet_number => 0,
            length => 1200,
            frames => [ping, {crypto, 0, <<"data">>}]
        },
        [
            ?_assertEqual(ok, quic_qlog:packet_sent(Ctx, Info)),
            %% Give writer time to process
            ?_assertEqual(ok, timer:sleep(50)),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

connection_lifecycle_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, server),
        [
            ?_assertEqual(ok, quic_qlog:connection_started(Ctx)),
            ?_assertEqual(ok, quic_qlog:connection_state_updated(Ctx, idle, handshaking)),
            ?_assertEqual(ok, quic_qlog:connection_state_updated(Ctx, handshaking, connected)),
            ?_assertEqual(ok, quic_qlog:connection_state_updated(Ctx, connected, draining)),
            ?_assertEqual(ok, quic_qlog:connection_closed(Ctx, 0, <<"no error">>)),
            ?_assertEqual(ok, timer:sleep(50)),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

recovery_events_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<10, 20, 30, 40>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        [
            ?_assertEqual(ok, quic_qlog:packets_acked(Ctx, [0, 1, 2], #{rtt_sample => 50})),
            ?_assertEqual(
                ok,
                quic_qlog:packet_lost(Ctx, #{
                    packet_number => 3,
                    reason => timeout
                })
            ),
            ?_assertEqual(
                ok,
                quic_qlog:metrics_updated(Ctx, #{
                    smoothed_rtt => 100,
                    cwnd => 14720,
                    bytes_in_flight => 5000
                })
            ),
            ?_assertEqual(ok, timer:sleep(50)),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

%%====================================================================
%% Event Filtering Tests
%%====================================================================

event_filter_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<1, 2, 3, 4>>,
        %% Only enable packet_sent events
        Opts = #{qlog => #{enabled => true, dir => TmpDir, events => [packet_sent]}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        [
            %% packet_sent should work
            ?_assertEqual(ok, quic_qlog:packet_sent(Ctx, #{packet_number => 0})),
            %% Other events should be filtered (still return ok)
            ?_assertEqual(ok, quic_qlog:packet_received(Ctx, #{})),
            ?_assertEqual(ok, quic_qlog:connection_started(Ctx)),
            ?_assertEqual(ok, timer:sleep(50)),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.

%%====================================================================
%% File Output Tests
%%====================================================================

file_created_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<16#de, 16#ad, 16#be, 16#ef>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        quic_qlog:connection_started(Ctx),
        quic_qlog:packet_sent(Ctx, #{packet_number => 0, packet_type => initial}),
        timer:sleep(50),
        quic_qlog:close(Ctx),
        %% Check file was created
        {ok, Files} = file:list_dir(TmpDir),
        QlogFiles = [F || F <- Files, filename:extension(F) =:= ".qlog"],
        [
            ?_assert(length(QlogFiles) > 0),
            ?_assert(
                lists:any(
                    fun(F) ->
                        string:find(F, "deadbeef") =/= nomatch
                    end,
                    QlogFiles
                )
            )
        ]
    end}.

json_seq_format_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<1, 2, 3, 4>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, server),
        quic_qlog:connection_started(Ctx),
        quic_qlog:packet_sent(Ctx, #{packet_number => 0, packet_type => initial}),
        timer:sleep(100),
        quic_qlog:close(Ctx),
        %% Read and validate file contents
        {ok, Files} = file:list_dir(TmpDir),
        [QlogFile | _] = [F || F <- Files, filename:extension(F) =:= ".qlog"],
        {ok, Content} = file:read_file(filename:join(TmpDir, QlogFile)),
        Lines = binary:split(Content, <<"\n">>, [global, trim_all]),
        [
            %% Should have at least header + events
            ?_assert(length(Lines) >= 2),
            %% First line should be header with qlog_format
            ?_assert(binary:match(hd(Lines), <<"qlog_format">>) =/= nomatch),
            %% Header should have qlog_version
            ?_assert(binary:match(hd(Lines), <<"qlog_version">>) =/= nomatch)
        ]
    end}.

%%====================================================================
%% Close Tests
%%====================================================================

close_undefined_test() ->
    ?assertEqual(ok, quic_qlog:close(undefined)).

close_disabled_test() ->
    Ctx = #qlog_ctx{enabled = false},
    ?assertEqual(ok, quic_qlog:close(Ctx)).

%%====================================================================
%% Macro Tests
%%====================================================================

qlog_enabled_macro_test() ->
    %% Test the QLOG_ENABLED macro
    %% Note: undefined is not a valid record, so we skip that case
    ?assertEqual(false, ?QLOG_ENABLED(#qlog_ctx{enabled = false})),
    ?assertEqual(true, ?QLOG_ENABLED(#qlog_ctx{enabled = true})).

qlog_event_enabled_macro_test() ->
    %% Test with all events enabled
    CtxAll = #qlog_ctx{enabled = true, events = all},
    ?assertEqual(true, ?QLOG_EVENT_ENABLED(CtxAll, packet_sent)),
    ?assertEqual(true, ?QLOG_EVENT_ENABLED(CtxAll, packet_received)),

    %% Test with specific events
    CtxFiltered = #qlog_ctx{enabled = true, events = [packet_sent]},
    ?assertEqual(true, ?QLOG_EVENT_ENABLED(CtxFiltered, packet_sent)),
    ?assertEqual(false, ?QLOG_EVENT_ENABLED(CtxFiltered, packet_received)),

    %% Test disabled
    CtxDisabled = #qlog_ctx{enabled = false, events = all},
    ?assertEqual(false, ?QLOG_EVENT_ENABLED(CtxDisabled, packet_sent)).

%%====================================================================
%% Frame Encoding Tests
%%====================================================================

frames_processed_all_types_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(TmpDir) ->
        ODCID = <<1, 2, 3, 4>>,
        Opts = #{qlog => #{enabled => true, dir => TmpDir}},
        Ctx = quic_qlog:new(Opts, ODCID, client),
        Frames = [
            padding,
            ping,
            {crypto, 0, <<"crypto data">>},
            {ack, [{0, 5}, {10, 15}], 25, undefined},
            {stream, 0, 0, <<"stream data">>, false},
            {stream, 4, 100, <<"more data">>, true},
            {max_data, 1000000},
            {max_stream_data, 0, 500000},
            {max_streams, bidi, 100},
            {max_streams, uni, 100},
            {reset_stream, 4, 0, 1000},
            {stop_sending, 8, 0},
            {connection_close, 0, undefined, <<"closing">>},
            {new_connection_id, 1, 0, <<1, 2, 3, 4>>, <<0:128>>},
            {retire_connection_id, 0},
            {path_challenge, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            {path_response, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            handshake_done,
            {new_token, <<"token">>},
            {datagram, <<"datagram data">>}
        ],
        [
            ?_assertEqual(ok, quic_qlog:frames_processed(Ctx, Frames)),
            ?_assertEqual(ok, timer:sleep(50)),
            ?_assertEqual(ok, quic_qlog:close(Ctx))
        ]
    end}.
