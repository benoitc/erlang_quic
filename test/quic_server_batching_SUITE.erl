%%% -*- erlang -*-
%%%
%%% Server-side Send Batching Behaviour Tests
%%%
%%% Drives real server-originated multi-packet flows (downloads) and
%%% asserts that the per-connection batch buffer actually coalesces
%%% packets. Complements quic_server_e2e_SUITE which only verifies the
%%% wiring is in place at handshake time.
%%%
%%% These tests run with the default `gen_udp' listener backend and do
%%% not require GSO. They only verify the batch buffer is being used
%%% end-to-end on the send side. A Linux/GSO-specific variant is a
%%% follow-up.

-module(quic_server_batching_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    server_download_coalesces_by_default/1,
    server_download_no_batching_when_disabled/1,
    opt_out_still_completes_transfer/1
]).

-define(DOWNLOAD_SIZE, 262144).
-define(REQUEST_TIMEOUT_MS, 10000).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        server_download_coalesces_by_default,
        server_download_no_batching_when_disabled,
        opt_out_still_completes_transfer
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

%% Client requests a multi-KB download; server responds with Size bytes
%% of filler in one send_data call. Assert that the server connection's
%% batch_flushes and packets_coalesced counters advanced, proving the
%% per-connection batch buffer actually coalesced packets before flush.
server_download_coalesces_by_default(Config) ->
    {ok, Srv} = start_download_server(#{}),
    try
        {Received, ServerStats} = run_download(Srv, ?DOWNLOAD_SIZE),

        ?assertEqual(?DOWNLOAD_SIZE, byte_size(Received)),

        Flushes = maps:get(batch_flushes, ServerStats),
        Coalesced = maps:get(packets_coalesced, ServerStats),
        ct:log("server batch stats: flushes=~p coalesced=~p", [Flushes, Coalesced]),

        %% Must have at least one successful flush and the batch must
        %% have coalesced more than one packet somewhere along the way.
        ?assert(Flushes >= 1),
        ?assert(Coalesced > 1),
        %% Sanity: total coalesced cannot exceed total packets sent.
        PacketsSent = maps:get(packets_sent, ServerStats),
        ?assert(Coalesced =< PacketsSent)
    after
        stop_server(Srv)
    end,
    Config.

%% Same flow, but with server_send_batching disabled on the server.
%% Every server packet should go via do_socket_send's gen_udp fallback
%% (socket_state = undefined) and NOT through the batch buffer, so both
%% counters must stay at zero.
server_download_no_batching_when_disabled(Config) ->
    {ok, Srv} = start_download_server(#{server_send_batching => false}),
    try
        {Received, ServerStats} = run_download(Srv, ?DOWNLOAD_SIZE),

        ?assertEqual(?DOWNLOAD_SIZE, byte_size(Received)),

        ?assertEqual(0, maps:get(batch_flushes, ServerStats)),
        ?assertEqual(0, maps:get(packets_coalesced, ServerStats))
    after
        stop_server(Srv)
    end,
    Config.

%% Regression: the opt-out fallback path must still deliver the full
%% payload correctly. Checks that disabling batching does not break
%% bulk send semantics (flow control, ordering, FIN delivery).
opt_out_still_completes_transfer(Config) ->
    {ok, Srv} = start_download_server(#{server_send_batching => false}),
    try
        Size = ?DOWNLOAD_SIZE,
        {Received, _Stats} = run_download(Srv, Size),
        ?assertEqual(Size, byte_size(Received)),
        %% Spot-check payload integrity: every byte should be 0x42 per
        %% send_download/3. Verify a sample of bytes rather than the
        %% whole buffer to keep the failure message small.
        ?assertEqual(<<16#42>>, binary:part(Received, 0, 1)),
        ?assertEqual(<<16#42>>, binary:part(Received, Size - 1, 1)),
        ?assertEqual(<<16#42>>, binary:part(Received, Size div 2, 1))
    after
        stop_server(Srv)
    end,
    Config.

%%====================================================================
%% Download server
%%====================================================================

start_download_server(Extra) when is_map(Extra) ->
    %% Reuse quic_test_echo_server's cert loading by starting it with
    %% our download handler overriding the default echo handler.
    DownloadHandler = fun(ConnPid, _ConnRef) ->
        Handler = spawn_link(fun() -> download_loop(ConnPid, #{}) end),
        ok = quic:set_owner_sync(ConnPid, Handler),
        {ok, Handler}
    end,
    Override = maps:merge(#{connection_handler => DownloadHandler}, Extra),
    quic_test_echo_server:start(Override).

stop_server(Handle) ->
    quic_test_echo_server:stop(Handle).

%% Per-connection handler: waits for an 8-byte request on each stream,
%% then sends that many bytes of filler back with FIN. Buffers partial
%% request bytes across stream_data events so small initial chunks do
%% not hang the handler.
download_loop(Conn, PendingReq) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            download_loop(Conn, PendingReq);
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Prev = maps:get(StreamId, PendingReq, <<>>),
            Buffer = <<Prev/binary, Data/binary>>,
            case Buffer of
                <<Size:64/big-unsigned-integer, _/binary>> when Fin ->
                    send_download(Conn, StreamId, Size),
                    download_loop(Conn, maps:remove(StreamId, PendingReq));
                _ when Fin ->
                    %% Short request; ignore.
                    download_loop(Conn, maps:remove(StreamId, PendingReq));
                _ ->
                    download_loop(Conn, PendingReq#{StreamId => Buffer})
            end;
        {quic, Conn, {stream_closed, _StreamId, _Code}} ->
            download_loop(Conn, PendingReq);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        {quic, Conn, _Other} ->
            download_loop(Conn, PendingReq);
        {'DOWN', _, process, Conn, _} ->
            ok;
        _Unexpected ->
            download_loop(Conn, PendingReq)
    end.

send_download(Conn, StreamId, Size) ->
    Payload = binary:copy(<<16#42>>, Size),
    _ = quic:send_data_async(Conn, StreamId, Payload, true),
    ok.

%%====================================================================
%% Client
%%====================================================================

run_download(#{name := Name, port := Port}, Size) ->
    %% Share the echo server's generous flow-control windows so large
    %% downloads do not stall on default 768 KiB stream windows.
    ClientOpts = quic_test_echo_server:client_opts(),
    {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
    try
        receive
            {quic, Conn, {connected, _Info}} -> ok
        after ?REQUEST_TIMEOUT_MS ->
            error(connect_timeout)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        Request = <<Size:64/big-unsigned-integer>>,
        ok = quic:send_data(Conn, StreamId, Request, true),
        Received = collect_stream_data(Conn, StreamId, <<>>),

        %% Find the server-side connection pid; register has both DCID
        %% and SCID mapped to the same pid, so usort collapses to one.
        {ok, ConnPids} = quic:get_server_connections(Name),
        [ServerPid | _] = lists:usort(ConnPids),
        {ok, Stats} = quic:get_stats(ServerPid),
        {Received, Stats}
    after
        quic:close(Conn)
    end.

collect_stream_data(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_stream_data(Conn, StreamId, <<Acc/binary, Data/binary>>);
        {quic, Conn, {stream_closed, StreamId, _Code}} ->
            Acc;
        {quic, Conn, {closed, _Reason}} ->
            Acc
    after ?REQUEST_TIMEOUT_MS ->
        error({download_timeout, byte_size(Acc)})
    end.
