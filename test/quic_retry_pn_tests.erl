%%% -*- erlang -*-
%%%
%%% RFC 9000 §17.2.5.3: a client MUST NOT reset the packet number for any
%%% packet number space after processing a Retry. The retried Initial used to
%%% go out as packet number 0 again, so a server that treats a repeated
%%% Initial packet number as a duplicate drops it and the handshake stalls.

-module(quic_retry_pn_tests).

-include_lib("eunit/include/eunit.hrl").

retry_keeps_initial_pn_test_() ->
    {timeout, 30, fun retry_keeps_initial_pn/0}.

retry_keeps_initial_pn() ->
    QlogDir = qlog_dir(),
    {ok, Srv} = quic_test_echo_server:start(#{address_validation => always}),
    try
        #{port := Port} = Srv,
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{
            qlog => #{enabled => true, dir => QlogDir}
        }),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        %% The connection closes its qlog as it terminates, so once it is
        %% down the file holds every event.
        MRef = erlang:monitor(process, Conn),
        quic:safe_close(Conn),
        receive
            {'DOWN', MRef, process, Conn, _} -> ok
        after 5000 -> error(not_closed)
        end,
        PNs = initial_packet_numbers(QlogDir),
        %% Retry (address_validation => always) means at least two
        %% Initials: the ClientHello and the retried one.
        length(PNs) >= 2 orelse error({too_few_initials, PNs, qlog_files(QlogDir)}),
        ?assertEqual(lists:usort(PNs), PNs)
    after
        quic_test_echo_server:stop(Srv),
        del_dir(QlogDir)
    end.

qlog_dir() ->
    Dir = filename:join(
        "/tmp",
        "quic_retry_pn_" ++ integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

%% What was on disk, for a failure to explain itself.
qlog_files(Dir) ->
    [{F, filelib:file_size(F)} || F <- filelib:wildcard(filename:join(Dir, "*"))].

%% Packet numbers of the Initial packets the client sent, in send order.
%% Read off the qlog rather than the connection state: `packet_sent' is the
%% only place the number a packet went out with is visible from a test.
initial_packet_numbers(Dir) ->
    Files = filelib:wildcard(filename:join(Dir, "*client*.qlog")),
    lists:append([initial_packet_numbers_of(F) || F <- Files]).

initial_packet_numbers_of(File) ->
    {ok, Bin} = file:read_file(File),
    %% Drop the space after each `:' so one matcher fits either spacing.
    Compact = binary:replace(Bin, <<": ">>, <<":">>, [global]),
    Lines = binary:split(Compact, <<"\n">>, [global, trim_all]),
    [packet_number(L) || L <- Lines, is_initial_sent(L)].

is_initial_sent(Line) ->
    lists:all(
        fun(Needle) -> binary:match(Line, Needle) =/= nomatch end,
        [<<"\"quic:packet_sent\"">>, <<"\"packet_type\":\"initial\"">>]
    ).

packet_number(Line) ->
    [_, Rest] = binary:split(Line, <<"\"packet_number\":">>),
    [Digits | _] = binary:split(Rest, [<<",">>, <<"}">>]),
    binary_to_integer(Digits).

del_dir(Dir) ->
    _ = [file:delete(F) || F <- filelib:wildcard(filename:join(Dir, "*"))],
    _ = file:del_dir(Dir),
    ok.
