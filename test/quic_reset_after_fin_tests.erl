%%% -*- erlang -*-
%%%
%%% A server stops reading an upload after its first bytes, while most of
%%% the upload is still queued and its FIN has already gone out. The reset
%%% that answers STOP_SENDING carries the final size the FIN set, so the
%%% server keeps the connection open (RFC 9000 Section 4.5). Issue #551.

-module(quic_reset_after_fin_tests).

-include_lib("eunit/include/eunit.hrl").

%% Windows large enough for the whole upload, so its FIN can be sent well
%% ahead of its data.
-define(WINDOWS, #{
    max_stream_data_bidi_remote => 4194320,
    max_data => 16777216,
    max_receive_window => 16777216
}).

upload_rejected_after_its_fin_test_() ->
    {timeout, 60, fun upload_rejected_after_its_fin/0}.

upload_rejected_after_its_fin() ->
    Server = spawn_link(fun rejecting_server/0),
    {ok, Srv} = quic_test_echo_server:start(
        maps:merge(?WINDOWS, #{
            alpn => [<<"test">>],
            connection_handler => fun(_Pid, _Ref) -> {ok, Server} end
        })
    ),
    try
        #{port := Port} = Srv,
        Opts = maps:merge(maps:merge(quic_test_echo_server:client_opts(), ?WINDOWS), #{
            alpn => [<<"test">>]
        }),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        lists:foreach(fun(_) -> rejected_upload(Conn) end, lists:seq(1, 3)),
        ?assertMatch({ok, _}, quic:open_stream(Conn)),
        receive
            {quic, Conn, {closed, Reason}} -> error({closed, Reason})
        after 200 -> ok
        end,
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Srv),
        unlink(Server),
        exit(Server, kill)
    end.

%% A small write, then 1 MiB and the FIN, mostly still queued when the
%% server's STOP_SENDING arrives.
rejected_upload(Conn) ->
    {ok, S} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, S, <<"first">>, false),
    %% STOP_SENDING can reset the stream between these writes.
    _ = quic:send_data(Conn, S, binary:copy(<<"u">>, 1048576), false),
    _ = quic:send_data(Conn, S, <<>>, true),
    receive
        {quic, Conn, {stop_sending, S, _}} -> ok;
        {quic, Conn, {closed, Reason}} -> error({closed, Reason})
    after 5000 -> error(no_stop_sending)
    end,
    %% The reset that answers it reaches the server before the next stream.
    timer:sleep(200),
    receive
        {quic, Conn, {closed, Reason2}} -> error({closed, Reason2})
    after 0 -> ok
    end.

%% Answers each stream at its first data and stops reading it.
rejecting_server() ->
    receive
        {quic, Conn, {stream_data, S, _Data, _Fin}} ->
            case get(S) of
                undefined ->
                    put(S, answered),
                    _ = quic:send_data(Conn, S, <<"answer">>, true),
                    _ = quic:stop_sending(Conn, S, 1);
                answered ->
                    ok
            end,
            rejecting_server();
        _ ->
            rejecting_server()
    end.
