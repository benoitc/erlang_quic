%%% -*- erlang -*-
%%%
%%% Refusing a peer, or closing on one that breaks the protocol, is the
%%% endpoint doing its job, and any peer can make it happen as often as it
%%% can open handshakes. It is logged at debug with its reason, never as a
%%% warning or an error, while the owner and the peer still learn why.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_peer_refusal_log_tests).

-export([log/2]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("quic.hrl").

-define(ALPN, <<"refuse">>).
-define(LOUD, [warning, error, critical, alert, emergency]).

%%====================================================================
%% Certificates
%%====================================================================

a_client_without_a_certificate_is_refused_quietly_test_() ->
    {timeout, 30, fun() ->
        #{server := Server, owner := Owner} = start_server(#{require_client_cert => true}),
        try
            {Closed, Events} = captured(fun() ->
                Closed = client_closed(maps:get(port, Server), #{}),
                {error, {certificate_invalid, no_certificate}} = server_error(Owner),
                Closed
            end),
            ?assertMatch({peer_closed, transport, 16#174, _, _}, Closed),
            ?assertEqual([], loud(Events)),
            ?assertEqual([no_certificate], reasons(client_cert_invalid, Events))
        after
            stop_server(Server)
        end
    end}.

a_client_certificate_from_another_ca_is_refused_quietly_test_() ->
    {timeout, 30, fun() ->
        #{server := Server, owner := Owner} = start_server(#{require_client_cert => true}),
        try
            Stranger = other_client_creds(),
            {Closed, Events} = captured(fun() ->
                Closed = client_closed(maps:get(port, Server), Stranger),
                {error, {certificate_invalid, Reason}} = server_error(Owner),
                {Closed, Reason}
            end),
            {PeerClosed, Reason} = Closed,
            Alert = quic_connection:cert_alert_code(Reason),
            ?assertMatch(
                {peer_closed, transport, Code, _, _} when Code =:= 16#100 + Alert, PeerClosed
            ),
            ?assertEqual([], loud(Events)),
            ?assertEqual([Reason], reasons(client_cert_invalid, Events))
        after
            stop_server(Server)
        end
    end}.

a_client_refuses_an_untrusted_server_quietly_test_() ->
    {timeout, 30, fun() ->
        #{server := Server} = start_server(#{}),
        try
            Opts = #{verify => verify_peer, cacerts => other_server_cacerts()},
            {Closed, Events} = captured(fun() -> client_closed(maps:get(port, Server), Opts) end),
            {certificate_invalid, Reason} = Closed,
            ?assertEqual([], loud(Events)),
            ?assertEqual([Reason], reasons(server_cert_invalid, Events))
        after
            stop_server(Server)
        end
    end}.

%%====================================================================
%% The application refuses
%%====================================================================

a_declined_connection_is_logged_at_debug_test_() ->
    {timeout, 30, fun() ->
        #{server := Server} = start_server(#{decline => true}),
        try
            {Closed, Events} = captured(fun() -> client_closed(maps:get(port, Server), #{}) end),
            ?assertMatch({peer_closed, transport, ?QUIC_CONNECTION_REFUSED, _, _}, Closed),
            ?assertEqual([], loud(Events)),
            ?assertEqual([not_today], reasons(connection_declined, Events))
        after
            stop_server(Server)
        end
    end}.

%%====================================================================
%% Protocol violations
%%====================================================================

an_unknown_frame_type_is_logged_at_debug_test() ->
    %% 0xff as a two-byte varint: a frame type nobody assigned.
    {{ok, S1, []}, Events} = captured(fun() ->
        quic_connection:decode_and_process_streaming(app, <<16#40, 16#ff>>, server_state())
    end),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _}, quic_connection_test_support:close_reason(S1)
    ),
    ?assertEqual([], loud(Events)),
    ?assertMatch([#{type := 16#ff}], reports(unknown_frame_type, Events)).

a_truncated_frame_is_logged_at_debug_test() ->
    %% 0xff alone opens an eight-byte varint and ends there.
    {{ok, S1, []}, Events} = captured(fun() ->
        quic_connection:decode_and_process_streaming(app, <<16#ff>>, server_state())
    end),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _}, quic_connection_test_support:close_reason(S1)
    ),
    ?assertEqual([], loud(Events)),
    ?assertEqual([truncated_frame_type], reasons(frame_decode_error, Events)).

an_empty_packet_is_logged_at_debug_test() ->
    {{ok, S1, []}, Events} = captured(fun() ->
        quic_connection:decode_and_process_streaming(app, <<>>, server_state())
    end),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _}, quic_connection_test_support:close_reason(S1)
    ),
    ?assertEqual([], loud(Events)),
    ?assertMatch([_], reports(packet_with_no_frames, Events)).

bad_transport_parameters_are_logged_at_debug_test() ->
    {S1, Events} = captured(fun() ->
        quic_connection:apply_peer_transport_params(#{}, server_state())
    end),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ),
    ?assertEqual([], loud(Events)),
    ?assertMatch([_], reports(transport_parameter_validation_failed, Events)).

%%====================================================================
%% Log capture
%%====================================================================

log(#{level := Level, msg := Msg}, #{config := #{pid := Pid}}) ->
    {What, Report} =
        case Msg of
            {report, #{what := W} = R} -> {W, R};
            _ -> {other, Msg}
        end,
    Pid ! {logged, Level, What, Report},
    ok.

%% Runs Fun with every log event, of any level and domain, sent here.
captured(Fun) ->
    flush_logged(),
    Id = list_to_atom("quic_peer_refusal_" ++ integer_to_list(erlang:unique_integer([positive]))),
    #{level := Primary} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Result = Fun(),
        {Result, logged()}
    after
        logger:remove_handler(Id),
        logger:set_primary_config(level, Primary)
    end.

logged() ->
    receive
        {logged, _, _, _} = E -> [E | logged()]
    after 0 -> []
    end.

flush_logged() ->
    _ = logged(),
    ok.

loud(Events) ->
    [
        {Level, What, reason(Report)}
     || {logged, Level, What, Report} <- Events, lists:member(Level, ?LOUD)
    ].

reason(#{reason := Reason}) -> Reason;
reason(_) -> undefined.

reports(What, Events) ->
    [R || {logged, debug, W, R} <- Events, W =:= What].

reasons(What, Events) ->
    [maps:get(reason, R) || R <- reports(What, Events)].

%%====================================================================
%% Server and clients
%%====================================================================

start_server(Cfg) ->
    {ok, _} = application:ensure_all_started(quic),
    #{server_config := S} = test_data(),
    Test = self(),
    Owner = spawn(fun() -> owner(Test) end),
    Handler =
        case maps:get(decline, Cfg, false) of
            true -> fun(_Conn) -> {error, not_today} end;
            false -> fun(_Conn) -> {ok, Owner} end
        end,
    Name = list_to_atom("refusal_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Opts0 = #{
        cert => proplists:get_value(cert, S),
        key => decode_key(S),
        cacerts => proplists:get_value(cacerts, S),
        alpn => [?ALPN],
        connection_handler => Handler
    },
    Opts = maps:merge(Opts0, maps:with([require_client_cert], Cfg)),
    {ok, _} = quic:start_server(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    #{server => #{name => Name, port => Port}, owner => Owner}.

stop_server(#{name := Name}) ->
    quic:stop_server(Name).

%% Owns the server's connections and passes their errors on.
owner(Test) ->
    receive
        {quic, _Conn, {error, _} = Error} ->
            Test ! {server_error, Error},
            owner(Test);
        _ ->
            owner(Test)
    end.

server_error(_Owner) ->
    receive
        {server_error, Error} -> Error
    after 5000 -> error(no_server_error)
    end.

%% How the client's connection ended.
client_closed(Port, Extra) ->
    Opts = maps:merge(
        #{alpn => [?ALPN], server_name => <<"localhost">>, verify => verify_none}, Extra
    ),
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    true = unlink(Conn),
    wait_closed(Conn).

wait_closed(Conn) ->
    receive
        {quic, Conn, {closed, Reason}} -> Reason;
        {quic, Conn, _} -> wait_closed(Conn)
    after 5000 -> error(no_close)
    end.

%% A client certificate from a CA the server does not trust.
other_client_creds() ->
    #{client_config := C} = test_data(),
    #{cert => proplists:get_value(cert, C), key => decode_key(C)}.

%% Trust anchors that do not cover the server's certificate.
other_server_cacerts() ->
    #{client_config := C} = test_data(),
    proplists:get_value(cacerts, C).

test_data() ->
    public_key:pkix_test_data(#{
        server_chain => chain([{dNSName, "localhost"}]),
        client_chain => chain([{dNSName, "client.example"}])
    }).

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

server_state() ->
    quic_connection_test_support:state_set(
        quic_connection_test_support:state_for_role(server), dcid, <<"client-scid">>
    ).
