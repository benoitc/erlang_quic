%%% -*- erlang -*-
%%%
%%% Crash reports and sys:get_status/1 of the processes that hold keys,
%%% secrets or PSKs show none of them.

-module(quic_status_redaction_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-export([log/2]).

-define(TIMEOUT, 5000).
-define(PSK_ID, <<"redaction-test-psk">>).

%%====================================================================
%% Server connection that exits on a TLS alert
%%====================================================================

tls_alert_crash_report_has_no_secret_test_() ->
    {timeout, 30, fun tls_alert_crash_report_has_no_secret/0}.

tls_alert_crash_report_has_no_secret() ->
    with_server(fun(#{port := Port, secrets := Secrets}) ->
        Events = captured(fun() ->
            {ok, Conn} = quic:connect(
                <<"127.0.0.1">>, Port, #{alpn => [<<"not-served">>], verify => false}, self()
            ),
            receive
                {quic, Conn, {closed, _}} -> ok
            after ?TIMEOUT -> error(no_close)
            end,
            _ = quic:safe_close(Conn),
            timer:sleep(200)
        end),
        [Report | _] = [
            E
         || #{msg := {report, #{label := {gen_statem, terminate}}}} = E <- Events
        ],
        #{msg := {report, #{reason := {exit, Reason, _}, state := {_, Data}}}} = Report,
        ?assertEqual({tls_alert, no_application_protocol}, Reason),
        assert_absent(Secrets, Events),
        ?assertMatch(#state{hs = #hs{server_private_key = redacted}}, Data)
    end).

%%====================================================================
%% Stack traces: format_status/1 never sees them
%%====================================================================

%% A quic process that crashes with function_clause on its state, under a
%% supervisor, while a caller outside erlang_quic waits on it: the
%% terminate, crash and supervisor reports, and the caller's crash
%% report, show neither the state nor its secrets.
crash_stack_trace_has_no_secret_test_() ->
    {timeout, 30, fun crash_stack_trace_has_no_secret/0}.

crash_stack_trace_has_no_secret() ->
    process_flag(trap_exit, true),
    with_connection(fun([Client | _], _ServerSecrets) ->
        {_, State} = sys:get_state(Client),
        Secrets = state_secrets(State),
        Events = captured(fun() ->
            {ok, Sup} = quic_redaction_crasher:start_sup(State),
            [{crasher, Pid, worker, _}] = supervisor:which_children(Sup),
            Caller = proc_lib:spawn(erlang, apply, [fun gen_statem:call/2, [Pid, crash]]),
            Ref = monitor(process, Caller),
            receive
                {'DOWN', Ref, process, Caller, _} -> ok
            after ?TIMEOUT -> error(caller_alive)
            end,
            timer:sleep(200),
            unlink(Sup),
            exit(Sup, shutdown)
        end),
        Labels = [L || #{msg := {report, #{label := L}}} <- Events],
        ?assert(lists:member({gen_statem, terminate}, Labels)),
        ?assert(lists:member({supervisor, child_terminated}, Labels)),
        ?assertEqual(2, length([L || {proc_lib, crash} = L <- Labels])),
        ?assert(contains(Events, function_clause)),
        assert_absent(Secrets, Events)
    end).

%% Outside a quic process only quic frames lose their arguments.
log_filter_other_process_test() ->
    Secret = secret(),
    Stack = [{quic_connection, f, [Secret], [{line, 1}]}, {lists, map, [x, [y]], []}],
    Event = report({gen_server, terminate}, #{reason => {function_clause, Stack}}),
    #{msg := {report, #{reason := {function_clause, Out}}}} = quic_redact:log_filter(Event, []),
    ?assertEqual([{quic_connection, f, 1, [{line, 1}]}, {lists, map, [x, [y]], []}], Out).

%% In a quic process every frame loses its arguments, and secrets and
%% copies of a state are dropped, except the formatted `state'.
log_filter_quic_process_test() ->
    Secret = secret(),
    Stack = [{lists, foldl, [Secret, #state{}, []], []}],
    Report = #{
        reason => {error, {badmatch, #state{}}, Stack},
        queue => [{cast, #{key => Secret}}],
        state => {connected, kept}
    },
    Out = in_quic_process(fun() ->
        quic_redact:log_filter(report({gen_statem, terminate}, Report), [])
    end),
    #{msg := {report, #{reason := Reason, queue := Queue, state := St}}} = Out,
    ?assertEqual({error, {badmatch, redacted}, [{lists, foldl, 3, []}]}, Reason),
    ?assertEqual([{cast, #{key => redacted}}], Queue),
    ?assertEqual({connected, kept}, St).

log_filter_each_crash_label_test_() ->
    Secret = secret(),
    Frames = [{quic_connection, f, [Secret], []}],
    [
        ?_assertNot(contains_secret(quic_redact:log_filter(report(L, #{r => Frames}), []), Secret))
     || L <- [{gen_statem, terminate}, {gen_server, terminate}, {proc_lib, crash}, {supervisor, x}]
    ].

log_filter_other_events_unchanged_test() ->
    Secret = secret(),
    Frames = [{quic_connection, f, [Secret], []}],
    Events = [
        report({application_controller, progress}, #{r => Frames}),
        #{level => error, msg => {string, "x"}, meta => #{}},
        #{level => error, msg => {"~p", [Frames]}, meta => #{}}
    ],
    [?assertEqual(E, quic_redact:log_filter(E, [])) || E <- Events].

report(Label, Report) ->
    #{level => error, msg => {report, Report#{label => Label}}, meta => #{}}.

in_quic_process(F) ->
    Self = self(),
    Pid = spawn(fun() ->
        put('$initial_call', {quic_connection, init, 1}),
        Self ! {self(), F()}
    end),
    receive
        {Pid, Result} -> Result
    after ?TIMEOUT -> error(timeout)
    end.

%%====================================================================
%% Live connections and the listener
%%====================================================================

connection_status_has_no_secret_test_() ->
    {timeout, 30, fun connection_status_has_no_secret/0}.

connection_status_has_no_secret() ->
    with_connection(fun(Pids, ServerSecrets) ->
        lists:foreach(
            fun(Pid) ->
                Secrets = live_secrets(Pid),
                {status, Pid, _, _} = Status = sys:get_status(Pid),
                assert_absent(Secrets ++ ServerSecrets, Status),
                ?assert(contains(Status, redacted))
            end,
            Pids
        )
    end).

connection_crash_report_has_no_secret_test_() ->
    {timeout, 30, fun connection_crash_report_has_no_secret/0}.

connection_crash_report_has_no_secret() ->
    process_flag(trap_exit, true),
    with_connection(fun(Pids, ServerSecrets) ->
        Secrets = lists:flatmap(fun live_secrets/1, Pids),
        Events = captured(fun() ->
            [sys:terminate(Pid, redaction_test) || Pid <- Pids],
            timer:sleep(200)
        end),
        Labels = [L || #{msg := {report, #{label := L}}} <- Events],
        assert_absent(Secrets ++ ServerSecrets, Events),
        ?assertEqual(2, length([L || {gen_statem, terminate} = L <- Labels])),
        ?assertEqual(2, length([L || {proc_lib, crash} = L <- Labels]))
    end).

listener_status_has_no_secret_test_() ->
    {timeout, 30, fun listener_status_has_no_secret/0}.

listener_status_has_no_secret() ->
    with_server(fun(#{sup := Sup, secrets := Secrets}) ->
        [Listener | _] = quic_listener_sup:get_listeners(Sup),
        Status = sys:get_status(Listener),
        assert_absent(Secrets, Status),
        ?assert(contains(Status, redacted))
    end).

%%====================================================================
%% Supervisors holding server options
%%====================================================================

supervisor_status_has_no_secret_test_() ->
    {timeout, 30, fun supervisor_status_has_no_secret/0}.

supervisor_status_has_no_secret() ->
    with_server(fun(#{sup := Sup, secrets := Secrets}) ->
        Sups = [whereis(quic_server_sup), Sup, sup_sup(Sup)],
        lists:foreach(
            fun(Pid) ->
                Status = sys:get_status(Pid),
                assert_absent(Secrets, Status),
                ?assert(has_sealed(Status))
            end,
            Sups
        )
    end).

listener_restart_report_has_no_secret_test_() ->
    {timeout, 30, fun listener_restart_report_has_no_secret/0}.

listener_restart_report_has_no_secret() ->
    with_server(fun(#{name := Name, sup := Sup, secrets := Secrets}) ->
        [L1, L2] = quic_listener_sup:get_listeners(Sup),
        Events = captured(fun() ->
            exit(L1, kill),
            timer:sleep(300)
        end),
        assert_absent(Secrets, Events),
        ?assertMatch([_ | _], terminated_reports(Events)),
        [New] = quic_listener_sup:get_listeners(Sup) -- [L2],
        ?assertNotEqual(L1, New),
        ?assertEqual(connected, connect_to(Name))
    end).

pool_restart_report_has_no_secret_test_() ->
    {timeout, 30, fun pool_restart_report_has_no_secret/0}.

pool_restart_report_has_no_secret() ->
    with_server(fun(#{name := Name, sup := Sup, secrets := Secrets}) ->
        Old = sup_sup(Sup),
        Events = captured(fun() ->
            exit(Old, kill),
            timer:sleep(300)
        end),
        assert_absent(Secrets, Events),
        ?assertMatch([_ | _], terminated_reports(Events)),
        ?assertNotEqual(Old, sup_sup(Sup)),
        ?assertEqual(2, length(quic_listener_sup:get_listeners(Sup))),
        ?assertEqual(connected, connect_to(Name))
    end).

server_spec_has_no_secret_test() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Psk = secret(),
    Spec = quic_server_sup:server_spec(n, 0, #{key => Key, psks => #{?PSK_ID => Psk}}),
    assert_absent([Key#'ECPrivateKey'.privateKey, Psk], Spec),
    #{start := {quic_listener_sup, start_link, [0, Sealed]}} = Spec,
    ?assertMatch(#{key := Key}, quic_redact:open(Sealed)).

%%====================================================================
%% Other processes that see secrets
%%====================================================================

registry_message_redacted_test() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Psk = secret(),
    Opts = #{key => Key, psks => #{?PSK_ID => Psk}, reset_secret => secret()},
    Status = quic_server_registry:format_status(#{
        state => {state, #{}},
        message => {'$gen_call', {self(), make_ref()}, {register, n, self(), 1, Opts}},
        reason => normal,
        log => []
    }),
    assert_absent(
        [Key#'ECPrivateKey'.privateKey, Psk, maps:get(reset_secret, Opts)], Status
    ),
    ?assert(contains(Status, redacted)).

h3_connection_ticket_redacted_test() ->
    Ticket = ticket(),
    Status = quic_h3_connection:format_status(#{
        state => connected,
        data => {state, self(), Ticket},
        reason => normal,
        queue => [{info, {quic, self(), {session_ticket, Ticket}}}],
        postponed => [],
        timeouts => [],
        log => []
    }),
    assert_absent([Ticket#session_ticket.resumption_secret], Status),
    ?assert(contains(Status, redacted)).

dist_tickets_message_redacted_test() ->
    Ticket = ticket(),
    Status = quic_dist_tickets:format_status(#{
        state => #{},
        message => {'$gen_cast', {store, node(), Ticket}},
        reason => normal,
        log => []
    }),
    assert_absent([Ticket#session_ticket.resumption_secret], Status),
    ?assert(contains(Status, redacted)).

%%====================================================================
%% Distribution controller holding a session ticket
%%====================================================================

dist_controller_status_has_no_ticket_secret_test() ->
    {Conn, Ctrl, Ticket} = dist_controller_with_ticket(),
    Secret = Ticket#session_ticket.resumption_secret,
    try
        ?assert(contains_secret(sys:get_state(Ctrl), Secret)),
        Status = sys:get_status(Ctrl),
        assert_absent([Secret], Status),
        ?assert(contains(Status, redacted))
    after
        gen_statem:stop(Ctrl),
        Conn ! stop
    end.

dist_controller_crash_report_has_no_ticket_secret_test() ->
    {Conn, Ctrl, Ticket} = dist_controller_with_ticket(),
    Secret = Ticket#session_ticket.resumption_secret,
    ?assert(contains_secret(sys:get_state(Ctrl), Secret)),
    Events = captured(fun() ->
        MRef = erlang:monitor(process, Ctrl),
        sys:terminate(Ctrl, redaction_test),
        receive
            {'DOWN', MRef, process, Ctrl, _} -> ok
        after ?TIMEOUT -> error(controller_alive)
        end,
        timer:sleep(200)
    end),
    Conn ! stop,
    Labels = [L || #{msg := {report, #{label := L}}} <- Events],
    ?assert(lists:member({gen_statem, terminate}, Labels)),
    assert_absent([Secret], Events).

dist_controller_queued_ticket_redacted_test() ->
    Ticket = ticket(),
    Status = quic_dist_controller:format_status(#{
        state => connected,
        data => {state, self()},
        reason => normal,
        queue => [{info, {quic, self(), {session_ticket, Ticket}}}],
        postponed => [{info, {quic, self(), {session_ticket, Ticket}}}],
        timeouts => [],
        log => []
    }),
    assert_absent([Ticket#session_ticket.resumption_secret], Status),
    ?assert(contains(Status, redacted)).

%%====================================================================
%% Dist settings are not kept in a supervisor
%%====================================================================

dist_settings_not_in_supervisor_status_test_() ->
    {timeout, 30, fun dist_settings_not_in_supervisor_status/0}.

dist_settings_not_in_supervisor_status() ->
    [Psk, Ext, Lb] = [secret() || _ <- lists:seq(1, 3)],
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Secrets = [Key#'ECPrivateKey'.privateKey, Psk, Ext, Lb],
    Saved = application:get_env(quic, dist),
    ok = application:stop(quic),
    ok = application:set_env(quic, dist, [
        {key, Key}, {psks, #{?PSK_ID => Psk}}, {external_psk, {?PSK_ID, Ext}}, {lb_key, Lb}
    ]),
    try
        {ok, _} = application:ensure_all_started(quic),
        lists:foreach(
            fun(Name) -> assert_absent(Secrets, sys:get_status(whereis(Name))) end,
            [quic_sup, quic_dist_sup]
        )
    after
        ok = application:stop(quic),
        case Saved of
            {ok, Value} -> application:set_env(quic, dist, Value);
            undefined -> application:unset_env(quic, dist)
        end,
        {ok, _} = application:ensure_all_started(quic)
    end.

%% Secrets nested in records and option maps anywhere in a term.
nested_secrets_redacted_test() ->
    [Lb, Reset, Token, Psk, Ext] = [secret() || _ <- lists:seq(1, 5)],
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Term = {
        #cid_config{
            lb_config = #lb_config{server_id = <<1>>, server_id_len = 1, key = Lb},
            reset_secret = Reset
        },
        [#cid_entry{seq_num = 0, cid = <<1>>, stateless_reset_token = Token}],
        #psk_offer{type = external, identity = ?PSK_ID, secret = Psk, cipher = aes_128_gcm},
        #{opts => #{external_psk => {?PSK_ID, Ext}, cert_key => Key}}
    },
    assert_absent(
        [Lb, Reset, Token, Psk, Ext, Key#'ECPrivateKey'.privateKey], quic_redact:term(Term)
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% A server-role controller over a connection stub, holding a ticket
%% the connection delivered.
dist_controller_with_ticket() ->
    Conn = spawn(fun conn_stub/0),
    {ok, Ctrl} = quic_dist_controller:start_link(Conn, server, undefined),
    true = unlink(Ctrl),
    Ticket = ticket(),
    Ctrl ! {quic, Conn, {session_ticket, Ticket}},
    {Conn, Ctrl, Ticket}.

%% Answers the calls a controller makes at startup.
conn_stub() ->
    receive
        {'$gen_call', From, open_stream} ->
            gen_statem:reply(From, {ok, 0}),
            conn_stub();
        {'$gen_call', From, _} ->
            gen_statem:reply(From, ok),
            conn_stub();
        stop ->
            ok;
        _ ->
            conn_stub()
    end.

contains_secret(Term, Secret) ->
    Text = lists:flatten(io_lib:format("~w", [Term])),
    string:find(Text, lists:flatten(io_lib:format("~w", [Secret]))) =/= nomatch.

sup_sup(Sup) ->
    {quic_listener_sup_sup, Pid, _, _} =
        lists:keyfind(quic_listener_sup_sup, 1, supervisor:which_children(Sup)),
    Pid.

terminated_reports(Events) ->
    [E || #{msg := {report, #{label := {supervisor, child_terminated}}}} = E <- Events].

has_sealed(Term) ->
    string:find(io_lib:format("~w", [Term]), "#Fun<quic_redact.") =/= nomatch.

connect_to(Name) ->
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic:connect(
        <<"127.0.0.1">>, Port, #{alpn => [<<"h3">>], verify => false}, self()
    ),
    Result =
        receive
            {quic, Conn, {connected, _}} -> connected
        after ?TIMEOUT -> timeout
        end,
    _ = quic:safe_close(Conn),
    Result.

%% A connected client and its server connection.
with_connection(F) ->
    with_server(fun(#{port := Port, name := Name, secrets := ServerSecrets}) ->
        {ok, Client} = quic:connect(
            <<"127.0.0.1">>, Port, #{alpn => [<<"h3">>], verify => false}, self()
        ),
        try
            receive
                {quic, Client, {connected, _}} -> ok
            after ?TIMEOUT -> error(not_connected)
            end,
            {ok, [Server | _]} = quic_server_registry:get_connections(Name),
            F([Client, Server], ServerSecrets)
        after
            quic:safe_close(Client)
        end
    end).

live_secrets(Pid) ->
    {_, State} = sys:get_state(Pid),
    Secrets = state_secrets(State),
    ?assertMatch([_, _, _, _, _, _ | _], Secrets),
    Secrets.

%% Every key and secret binary the connection holds.
state_secrets(#state{app_keys = App, key_state = KS, hs = Hs, cfg = Cfg}) ->
    Keys = [App, Hs#hs.initial_keys, Hs#hs.handshake_keys],
    lists:filter(
        fun is_binary/1,
        lists:flatmap(fun key_pair_bytes/1, Keys) ++
            [
                KS#key_update_state.client_app_secret,
                KS#key_update_state.server_app_secret,
                Hs#hs.handshake_secret,
                Hs#hs.master_secret,
                Hs#hs.server_hs_secret,
                Hs#hs.client_hs_secret,
                Hs#hs.resumption_secret,
                Cfg#conn_cfg.stateless_reset_secret
            ]
    ).

key_pair_bytes({A, B}) -> crypto_key_bytes(A) ++ crypto_key_bytes(B);
key_pair_bytes(_) -> [].

crypto_key_bytes(#crypto_keys{key = K, iv = IV, hp = HP}) -> [K, IV, HP];
crypto_key_bytes(_) -> [].

assert_absent(Secrets, Term) ->
    Text = lists:flatten(io_lib:format("~w", [Term])),
    lists:foreach(
        fun(Secret) ->
            Needle = lists:flatten(io_lib:format("~w", [Secret])),
            ?assertEqual({Secret, nomatch}, {Secret, string:find(Text, Needle)})
        end,
        Secrets
    ).

contains(Term, Atom) ->
    string:find(io_lib:format("~w", [Term]), atom_to_list(Atom)) =/= nomatch.

%% A leading zero byte keeps the secret from printing as text.
secret() ->
    <<0, (crypto:strong_rand_bytes(31))/binary>>.

ticket() ->
    #session_ticket{
        server_name = <<"example.com">>,
        ticket = <<"ticket">>,
        lifetime = 60,
        age_add = 0,
        nonce = <<0>>,
        resumption_secret = secret(),
        max_early_data = 0,
        received_at = 0,
        cipher = aes_128_gcm,
        alpn = <<"h3">>
    }.

%% A server with a certificate key, a PSK and a reset secret, all known.
with_server(F) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = self_signed(),
    Psk = secret(),
    ResetSecret = secret(),
    Name = list_to_atom("quic_redaction_" ++ integer_to_list(erlang:unique_integer([positive]))),
    %% A fixed port, so a restarted listener binds the one clients use.
    {ok, Probe} = gen_udp:open(0),
    {ok, Free} = inet:port(Probe),
    ok = gen_udp:close(Probe),
    {ok, Sup} = quic:start_server(Name, Free, #{
        cert => Cert,
        key => Key,
        psks => #{?PSK_ID => Psk},
        reset_secret => ResetSecret,
        alpn => [<<"h3">>],
        pool_size => 2
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(#{
            name => Name,
            sup => Sup,
            port => Port,
            secrets => [Key#'ECPrivateKey'.privateKey, Psk, ResetSecret]
        })
    after
        quic:stop_server(Name)
    end.

captured(Fun) ->
    Id = list_to_atom("quic_redaction_log_" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun()
    after
        logger:remove_handler(Id)
    end,
    collect().

collect() ->
    receive
        {logged, Event} -> [Event | collect()]
    after 0 -> []
    end.

%% logger handler callback
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.

self_signed() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    #'ECPrivateKey'{publicKey = Pub, parameters = Params} = Key,
    Name =
        {rdnSequence, [
            [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, <<"x">>}}]
        ]},
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = erlang:unique_integer([positive, monotonic]),
        signature = #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'},
        issuer = Name,
        validity = #'Validity'{
            notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "350101000000Z"}
        },
        subject = Name,
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
            subjectPublicKey = #'ECPoint'{point = Pub}
        },
        extensions = asn1_NOVALUE
    },
    {public_key:pkix_sign(TBS, Key), Key}.
