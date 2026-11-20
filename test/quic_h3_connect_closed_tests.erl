%%% -*- erlang -*-
%%%
%%% quic_h3:connect/3 against a server that closes the connection right
%%% after the handshake: one that requires a client certificate and gets
%%% none closes with 0x174 (certificate_required). The close can reach the
%%% client before or after connect/3 hands the connection to the HTTP/3
%%% process; either way the caller gets `{error, _}' and stays up.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_connect_closed_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(CERTIFICATE_REQUIRED, 16#174).
%% One address: Happy Eyeballs would race ::1 too, and its timeout is
%% not what these tests are about.
-define(HOST, <<"127.0.0.1">>).

closed_before_hand_off_test_() ->
    {setup, fun start_server/0, fun stop_server/1, fun(Server) ->
        [
            {"a draining connection refuses a new owner", fun() ->
                a_draining_connection_refuses_a_new_owner(Server)
            end},
            {"connect/3 returns the close when it beats the hand-off", fun() ->
                connect_returns_the_close(Server, #{sync => true})
            end},
            {"the same without sync", fun() ->
                connect_returns_the_close(Server, #{})
            end},
            {"the server hand-off declines a closed connection", fun() ->
                server_hand_off_declines_a_closed_connection(Server)
            end},
            {"a refused client always gets an error",
                {timeout, 120, fun() ->
                    a_refused_client_always_gets_an_error(Server)
                end}},
            {"a client with a certificate connects", fun() ->
                a_client_with_a_certificate_connects(Server)
            end}
        ]
    end}.

%%====================================================================
%% Tests
%%====================================================================

a_draining_connection_refuses_a_new_owner(#{port := Port}) ->
    {Conn, Reason} = refused_connection(Port),
    ?assertMatch({peer_closed, transport, ?CERTIFICATE_REQUIRED, _, _}, Reason),
    ?assertMatch({draining, _}, sys:get_state(Conn)),
    Other = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ?assertEqual({error, closed}, quic:set_owner_sync(Conn, Other)),
    Other ! stop.

%% quic:connect/4 is held until the server's close is in the caller's
%% mailbox, so the hand-off always finds the connection closed.
connect_returns_the_close(#{port := Port}, Opts) ->
    meck:new(quic, [passthrough]),
    try
        meck:expect(quic, connect, fun(Host, P, QuicOpts, Owner) ->
            {ok, Conn} = meck:passthrough([Host, P, QuicOpts, Owner]),
            ok = wait_for_close_message(Conn, 5000),
            put(quic_conn, Conn),
            {ok, Conn}
        end),
        Trap = process_flag(trap_exit, true),
        try
            Result = quic_h3:connect(?HOST, Port, Opts#{verify => verify_none}),
            ?assertMatch({error, {peer_closed, transport, ?CERTIFICATE_REQUIRED, _, _}}, Result),
            %% The connection, linked to us as quic:connect/4 starts it,
            %% may end its drain period meanwhile. Nothing else is left.
            Conn = get(quic_conn),
            ?assertEqual([], leftover_messages() -- [{'EXIT', Conn, normal}])
        after
            process_flag(trap_exit, Trap)
        end
    after
        meck:unload(quic)
    end.

%% The listener calls this before it hands the connection a packet. A
%% connection that is already closed is declined, and the HTTP/3
%% process started for it is stopped without taking the caller down.
server_hand_off_declines_a_closed_connection(#{port := Port}) ->
    {Conn, _Reason} = refused_connection(Port),
    Trap = process_flag(trap_exit, true),
    try
        Handler = fun(_C, _S, _M, _P, _H) -> ok end,
        ?assertEqual(
            {error, closed},
            quic_h3:h3_connection_handler(Conn, #{handler => Handler, settings => #{}})
        ),
        ?assertEqual([], leftover_messages())
    after
        process_flag(trap_exit, Trap)
    end.

%% With every scheduler busy the close lands before or after the
%% hand-off from one call to the next. Every call returns the error.
a_refused_client_always_gets_an_error(#{port := Port}) ->
    Busy = [spawn(fun spin/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    try
        Results = [one_connect(Port) || _ <- lists:seq(1, 100)],
        ?assertEqual([], [R || R <- Results, not refused(R)])
    after
        [exit(P, kill) || P <- Busy]
    end.

a_client_with_a_certificate_connects(#{port := Port, client := Client}) ->
    {ok, Conn} = quic_h3:connect(?HOST, Port, Client#{
        verify => verify_none, sync => true
    }),
    ok = quic_h3:close(Conn).

%%====================================================================
%% Helpers
%%====================================================================

start_server() ->
    {ok, _} = application:ensure_all_started(quic),
    #{server_config := S, client_config := C} = public_key:pkix_test_data(#{
        server_chain => chain([{dNSName, "localhost"}]),
        client_chain => chain([{dNSName, "client.example"}])
    }),
    Name = list_to_atom("h3_closed_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => proplists:get_value(cert, S),
        key => decode_key(S),
        cacerts => proplists:get_value(cacerts, S),
        quic_opts => #{require_client_cert => true},
        handler => fun(Conn, StreamId, _M, _P, _H) ->
            quic_h3:respond(Conn, StreamId, 200, [], <<"ok">>)
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    Client = #{cert => proplists:get_value(cert, C), key => decode_key(C)},
    #{name => Name, port => Port, client => Client}.

stop_server(#{name := Name}) ->
    quic_h3:stop_server(Name).

chain(SanNames) ->
    Key = {key, {namedCurve, secp256r1}},
    San = #'Extension'{
        extnID = ?'id-ce-subjectAltName', critical = false, extnValue = SanNames
    },
    %% The default digest is SHA-1, which TLS 1.3 refuses.
    Digest = {digest, sha256},
    #{root => [Key, Digest], intermediates => [], peer => [Key, Digest, {extensions, [San]}]}.

decode_key(Config) ->
    {KeyType, KeyDer} = proplists:get_value(key, Config),
    public_key:der_decode(KeyType, KeyDer).

%% A client connection the server refused, still ours, and why.
refused_connection(Port) ->
    Opts = #{alpn => [<<"h3">>], server_name => <<"localhost">>, verify => verify_none},
    {ok, Conn} = quic:connect(?HOST, Port, Opts, self()),
    %% Its exit at the end of the drain period must not land in a later test.
    true = unlink(Conn),
    receive
        {quic, Conn, {closed, Reason}} ->
            %% Drop what came before it, `connected' among them, so the
            %% next test starts with an empty mailbox. No wait: the
            %% connection is still draining when this returns.
            flush_from(Conn),
            {Conn, Reason}
    after 5000 -> error(no_close)
    end.

flush_from(Conn) ->
    receive
        {quic, Conn, _} -> flush_from(Conn)
    after 0 -> ok
    end.

%% Waits without taking the message, so connect/3 finds it.
wait_for_close_message(_Conn, Left) when Left =< 0 ->
    {error, timeout};
wait_for_close_message(Conn, Left) ->
    {messages, Msgs} = process_info(self(), messages),
    case [M || {quic, C, {closed, _}} = M <- Msgs, C =:= Conn] of
        [_ | _] ->
            ok;
        [] ->
            timer:sleep(1),
            wait_for_close_message(Conn, Left - 1)
    end.

leftover_messages() ->
    receive
        Msg -> [Msg | leftover_messages()]
    after 100 -> []
    end.

one_connect(Port) ->
    Self = self(),
    %% Not trapping exits: a linked process going down takes this one too.
    {Pid, MRef} = spawn_monitor(fun() ->
        R = quic_h3:connect(?HOST, Port, #{verify => verify_none, sync => true}),
        Self ! {self(), R}
    end),
    receive
        {Pid, R} ->
            erlang:demonitor(MRef, [flush]),
            R;
        {'DOWN', MRef, process, Pid, Reason} ->
            {crashed, Reason}
    after 15000 -> timeout
    end.

refused({error, {peer_closed, transport, ?CERTIFICATE_REQUIRED, _, _}}) -> true;
refused(_) -> false.

spin() -> spin().
