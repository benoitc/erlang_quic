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
    opt_out_still_completes_transfer/1,
    server_download_uses_gso_on_linux/1
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
        opt_out_still_completes_transfer,
        server_download_uses_gso_on_linux
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
        {Received, Delta} = run_download(Srv, ?DOWNLOAD_SIZE),

        ?assertEqual(?DOWNLOAD_SIZE, byte_size(Received)),

        Flushes = maps:get(batch_flushes, Delta),
        Coalesced = maps:get(packets_coalesced, Delta),
        PacketsSent = maps:get(packets_sent, Delta),
        ct:log(
            "download delta: flushes=~p coalesced=~p packets_sent=~p",
            [Flushes, Coalesced, PacketsSent]
        ),

        %% Download produced real server -> client traffic.
        ?assert(Flushes >= 1),
        ?assert(PacketsSent > 1),
        %% Strict: any single-packet-only flush pattern would give
        %% Coalesced == Flushes. Coalesced > Flushes proves at least one
        %% flush combined multiple packets on the download path.
        ?assert(Coalesced > Flushes),
        %% Sanity: never claim more coalesced than actually sent.
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
        {Received, Delta} = run_download(Srv, ?DOWNLOAD_SIZE),

        ?assertEqual(?DOWNLOAD_SIZE, byte_size(Received)),

        %% Data actually flowed on the download path before we assert
        %% the counters stayed at zero (otherwise the zeros would be
        %% trivial).
        ?assert(maps:get(packets_sent, Delta) > 1),
        ?assertEqual(0, maps:get(batch_flushes, Delta)),
        ?assertEqual(0, maps:get(packets_coalesced, Delta))
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
        {Received, Delta} = run_download(Srv, Size),
        ?assertEqual(Size, byte_size(Received)),
        %% Spot-check payload integrity: every byte should be 0x42 per
        %% send_download/3. Verify a sample of bytes rather than the
        %% whole buffer to keep the failure message small.
        ?assertEqual(<<16#42>>, binary:part(Received, 0, 1)),
        ?assertEqual(<<16#42>>, binary:part(Received, Size - 1, 1)),
        ?assertEqual(<<16#42>>, binary:part(Received, Size div 2, 1)),
        %% Opt-out path is actually the direct-send path, not batched.
        ?assertEqual(0, maps:get(batch_flushes, Delta)),
        ?assertEqual(0, maps:get(packets_coalesced, Delta))
    after
        stop_server(Srv)
    end,
    Config.

%% Linux-only: proves GSO actually kicks in on a capable host.
%% Skipped when the opt-in env var QUIC_ENABLE_GSO_TEST is not set.
%% When the env var IS set (as in the dedicated CI job), the test hard
%% fails if we are not on Linux or if UDP_SEGMENT is unsupported, so a
%% silent skip in CI cannot mask a regression in GSO detection.
%% Starts the listener with socket_backend => socket so the quic_socket
%% abstraction is active on the listener's UDP socket and GSO propagates
%% into each server connection's per-connection sender.
server_download_uses_gso_on_linux(Config) ->
    case os:getenv("QUIC_ENABLE_GSO_TEST") of
        false ->
            {skip, "QUIC_ENABLE_GSO_TEST not set"};
        _ ->
            ?assertEqual({unix, linux}, os:type()),
            Caps = quic_socket:detect_capabilities(),
            ?assertEqual(true, maps:get(gso, Caps, false)),
            {ok, Srv} = start_download_server(#{socket_backend => socket}),
            try
                {Received, Delta} = run_download(Srv, ?DOWNLOAD_SIZE),
                ?assertEqual(?DOWNLOAD_SIZE, byte_size(Received)),

                ServerPid = server_connection_pid(maps:get(name, Srv)),
                {_State, Info} = quic_connection:get_state(ServerPid),
                ?assertEqual(true, maps:get(send_gso_supported, Info)),

                Flushes = maps:get(batch_flushes, Delta),
                Coalesced = maps:get(packets_coalesced, Delta),
                Ratio =
                    case Flushes of
                        0 -> 0.0;
                        _ -> Coalesced / Flushes
                    end,
                ct:log(
                    "GSO delta: flushes=~p coalesced=~p ratio=~.2f",
                    [Flushes, Coalesced, float(Ratio)]
                ),
                %% On Linux + GSO the download-path batches should
                %% coalesce significantly. A ratio > 1.5 proves real
                %% coalescing on top of the Coalesced > Flushes check.
                ?assert(Coalesced > Flushes),
                ?assert(Ratio > 1.5)
            after
                stop_server(Srv)
            end,
            Config
    end.

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

        %% Snapshot baseline stats on the server connection BEFORE the
        %% download request. Using the post-transfer lifetime counters
        %% would fold in handshake traffic (handshake alone can produce
        %% coalesced > 1, flushes > 1), making any coalescing assertion
        %% trivially pass. Taking a before/after delta scopes the
        %% assertion to the download-path traffic only.
        ServerPid = server_connection_pid(Name),
        {ok, Before} = quic:get_stats(ServerPid),

        {ok, StreamId} = quic:open_stream(Conn),
        Request = <<Size:64/big-unsigned-integer>>,
        ok = quic:send_data(Conn, StreamId, Request, true),
        Received = collect_stream_data(Conn, StreamId, <<>>),

        {ok, After} = quic:get_stats(ServerPid),
        {Received, stats_delta(After, Before)}
    after
        quic:close(Conn)
    end.

server_connection_pid(Name) ->
    {ok, ConnPids} = quic:get_server_connections(Name),
    %% register has both DCID and SCID mapped to the same pid, so
    %% usort collapses the list to one entry per connection.
    [Pid | _] = lists:usort(ConnPids),
    Pid.

stats_delta(After, Before) ->
    maps:from_list(
        [
            {K, maps:get(K, After, 0) - maps:get(K, Before, 0)}
         || K <- [packets_sent, batch_flushes, packets_coalesced]
        ]
    ).

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
