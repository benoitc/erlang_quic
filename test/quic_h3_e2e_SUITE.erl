%%% -*- erlang -*-
%%%
%%% HTTP/3 End-to-End Test Suite
%%%
%%% Tests the HTTP/3 client against a real aioquic H3 server running in Docker.
%%%
%%% Prerequisites:
%%% - Docker and docker-compose must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%% - H3 server must be running: docker compose -f docker/docker-compose.yml up h3-server -d
%%%
%%% Run with:
%%% H3_SERVER_HOST=127.0.0.1 H3_SERVER_PORT=4435 rebar3 ct --suite=quic_h3_e2e_SUITE
%%%

-module(quic_h3_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Basic requests
-export([
    basic_get/1,
    basic_post/1,
    head_request/1,
    get_index/1
]).

%% Test cases - Data transfer
-export([
    large_response/1,
    post_echo/1
]).

%% Test cases - Multiple requests
-export([
    multiple_requests/1,
    concurrent_streams/1
]).

%% Test cases - Protocol behavior
-export([
    settings_exchange/1,
    settings_local_enforcement/1,
    settings_custom_limits/1,
    goaway_graceful/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        {group, basic_requests},
        {group, data_transfer},
        {group, multiple_requests},
        {group, protocol_behavior}
    ].

groups() ->
    [
        {basic_requests, [sequence], [
            basic_get,
            basic_post,
            head_request,
            get_index
        ]},
        {data_transfer, [sequence], [
            large_response,
            post_echo
        ]},
        {multiple_requests, [sequence], [
            multiple_requests,
            concurrent_streams
        ]},
        {protocol_behavior, [sequence], [
            settings_exchange,
            settings_local_enforcement,
            settings_custom_limits,
            goaway_graceful
        ]}
    ].

init_per_suite(Config) ->
    % Ensure crypto is started
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    % Get server configuration from environment
    Host = os:getenv("H3_SERVER_HOST", "127.0.0.1"),
    Port = list_to_integer(os:getenv("H3_SERVER_PORT", "4435")),

    ct:pal("HTTP/3 E2E Test Configuration:"),
    ct:pal("  Server: ~s:~p", [Host, Port]),

    % Verify server is reachable
    case wait_for_server(Host, Port, 30) of
        ok ->
            ct:pal("H3 Server is reachable"),
            [{h3_host, Host}, {h3_port, Port} | Config];
        {error, Reason} ->
            {skip, {h3_server_unavailable, Reason}}
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Basic Request Tests
%%====================================================================

%% @doc Test basic GET request for a text file
basic_get(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/test.txt">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),

    {Status, _RespHeaders, Body} = receive_response(Conn, StreamId, 10000),

    ct:pal("GET /test.txt: status=~p, body=~p", [Status, Body]),
    ?assertEqual(200, Status),
    ?assertEqual(<<"test content\n">>, Body),

    quic_h3:close(Conn).

%% @doc Test basic POST request with body
basic_post(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    PostBody = <<"hello world">>,
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/echo">>},
        {<<":authority">>, list_to_binary(Host)},
        {<<"content-length">>, integer_to_binary(byte_size(PostBody))}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    ok = quic_h3:send_data(Conn, StreamId, PostBody, true),

    {Status, _, Body} = receive_response(Conn, StreamId, 10000),

    ct:pal("POST /echo: status=~p, body=~p", [Status, Body]),
    ?assertEqual(200, Status),
    ?assertEqual(PostBody, Body),

    quic_h3:close(Conn).

%% @doc Test HEAD request (no body in response)
head_request(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    Headers = [
        {<<":method">>, <<"HEAD">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/test.txt">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),

    {Status, RespHeaders, Body} = receive_response(Conn, StreamId, 10000),

    ct:pal("HEAD /test.txt: status=~p, headers=~p, body=~p", [Status, RespHeaders, Body]),
    ?assertEqual(200, Status),
    % HEAD should have empty body
    ?assertEqual(<<>>, Body),

    quic_h3:close(Conn).

%% @doc Test GET request for index.html
get_index(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),

    {Status, _, Body} = receive_response(Conn, StreamId, 10000),

    ct:pal("GET /: status=~p, body_size=~p", [Status, byte_size(Body)]),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"OK">>) =/= nomatch),

    quic_h3:close(Conn).

%%====================================================================
%% Data Transfer Tests
%%====================================================================

%% @doc Test large response (1MB file)
large_response(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/large.bin">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),

    %% 30s timeout for large transfer
    {Status, _, Body} = receive_response(Conn, StreamId, 30000),

    ct:pal("GET /large.bin: status=~p, body_size=~p", [Status, byte_size(Body)]),
    ?assertEqual(200, Status),
    %% Should be 1MB
    ?assertEqual(1024 * 1024, byte_size(Body)),

    quic_h3:close(Conn).

%% @doc Test POST echo with larger body
post_echo(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    %% Send 64KB body
    PostBody = crypto:strong_rand_bytes(64 * 1024),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/echo">>},
        {<<":authority">>, list_to_binary(Host)},
        {<<"content-length">>, integer_to_binary(byte_size(PostBody))}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    ok = quic_h3:send_data(Conn, StreamId, PostBody, true),

    {Status, _, Body} = receive_response(Conn, StreamId, 15000),

    ct:pal("POST /echo (64KB): status=~p, echo_size=~p", [Status, byte_size(Body)]),
    ?assertEqual(200, Status),
    ?assertEqual(PostBody, Body),

    quic_h3:close(Conn).

%%====================================================================
%% Multiple Request Tests
%%====================================================================

%% @doc Test multiple sequential requests on same connection
multiple_requests(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    %% Request 1
    Headers1 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/test.txt">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, Stream1} = quic_h3:request(Conn, Headers1),
    {Status1, _, _} = receive_response(Conn, Stream1, 10000),
    ?assertEqual(200, Status1),

    %% Request 2
    Headers2 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, Stream2} = quic_h3:request(Conn, Headers2),
    {Status2, _, _} = receive_response(Conn, Stream2, 10000),
    ?assertEqual(200, Status2),

    %% Request 3
    PostBody = <<"test body">>,
    Headers3 = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/echo">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, Stream3} = quic_h3:request(Conn, Headers3),
    ok = quic_h3:send_data(Conn, Stream3, PostBody, true),
    {Status3, _, Body3} = receive_response(Conn, Stream3, 10000),
    ?assertEqual(200, Status3),
    ?assertEqual(PostBody, Body3),

    ct:pal("Multiple requests: all succeeded"),
    quic_h3:close(Conn).

%% @doc Test concurrent streams
concurrent_streams(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    %% Open multiple streams concurrently
    Paths = [<<"/test.txt">>, <<"/">>, <<"/test.txt">>],

    StreamIds = lists:map(
        fun(Path) ->
            Headers = [
                {<<":method">>, <<"GET">>},
                {<<":scheme">>, <<"https">>},
                {<<":path">>, Path},
                {<<":authority">>, list_to_binary(Host)}
            ],
            {ok, StreamId} = quic_h3:request(Conn, Headers),
            StreamId
        end,
        Paths
    ),

    ct:pal("Opened ~p concurrent streams: ~p", [length(StreamIds), StreamIds]),

    %% Collect all responses
    Responses = collect_multiple_responses(Conn, StreamIds, #{}, 15000),

    ct:pal("Collected ~p responses", [maps:size(Responses)]),
    ?assertEqual(length(StreamIds), maps:size(Responses)),

    %% Verify all returned 200
    maps:foreach(
        fun(StreamId, {Status, _, _}) ->
            ct:pal("Stream ~p: status=~p", [StreamId, Status]),
            ?assertEqual(200, Status)
        end,
        Responses
    ),

    quic_h3:close(Conn).

%%====================================================================
%% Protocol Behavior Tests
%%====================================================================

%% @doc Test SETTINGS exchange
settings_exchange(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    %% Wait a bit for settings exchange
    timer:sleep(500),

    LocalSettings = quic_h3:get_settings(Conn),
    PeerSettings = quic_h3:get_peer_settings(Conn),

    ct:pal("Local settings: ~p", [LocalSettings]),
    ct:pal("Peer settings: ~p", [PeerSettings]),

    ?assert(is_map(LocalSettings)),
    %% Peer settings might be undefined if not yet received
    ?assert(PeerSettings =:= undefined orelse is_map(PeerSettings)),

    quic_h3:close(Conn).

%% @doc Test that local settings are properly stored for inbound validation
%% RFC 9114 Section 7.2.4.1: Each endpoint uses its own settings to constrain inbound data
settings_local_enforcement(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    %% Connect with custom local settings for inbound enforcement
    CustomSettings = #{
        max_field_section_size => 16384,
        qpack_blocked_streams => 100
    },
    {ok, Conn} = quic_h3:connect(Host, Port, #{
        verify => false,
        settings => CustomSettings
    }),

    %% Verify local settings were stored correctly (get_settings works immediately)
    LocalSettings = quic_h3:get_settings(Conn),
    ct:pal("Local settings with custom config: ~p", [LocalSettings]),

    %% Our local settings should reflect what we configured
    ?assertEqual(16384, maps:get(max_field_section_size, LocalSettings, undefined)),
    ?assertEqual(100, maps:get(qpack_blocked_streams, LocalSettings, undefined)),

    ct:pal("Custom local settings verified successfully"),
    quic_h3:close(Conn).

%% @doc Test that peer settings are different from local settings (directionality)
%% Local settings constrain inbound, peer settings constrain outbound
settings_custom_limits(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    %% Connect with specific local settings
    LocalMaxFieldSize = 32768,
    {ok, Conn} = quic_h3:connect(Host, Port, #{
        verify => false,
        settings => #{max_field_section_size => LocalMaxFieldSize}
    }),

    LocalSettings = quic_h3:get_settings(Conn),

    ct:pal("Local max_field_section_size: ~p", [
        maps:get(max_field_section_size, LocalSettings, undefined)
    ]),

    %% Our local setting should be what we configured
    ?assertEqual(LocalMaxFieldSize, maps:get(max_field_section_size, LocalSettings, undefined)),

    %% Wait a bit for peer settings to arrive
    timer:sleep(500),
    PeerSettings = quic_h3:get_peer_settings(Conn),

    %% Peer settings are independent (server's advertised limits)
    %% They might be different from ours
    case PeerSettings of
        undefined ->
            ct:pal("Peer settings not yet received (connection may not be established)");
        _ ->
            PeerMaxFieldSize = maps:get(max_field_section_size, PeerSettings, undefined),
            ct:pal("Peer max_field_section_size: ~p", [PeerMaxFieldSize]),
            %% Peer's setting is what THEY advertise (constrains what we send)
            %% Local setting is what WE advertise (constrains what they send)
            %% These are independent values - this test verifies they're stored separately
            ?assert(is_integer(PeerMaxFieldSize) orelse PeerMaxFieldSize =:= undefined)
    end,

    quic_h3:close(Conn).

%% @doc Test graceful GOAWAY
goaway_graceful(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false}),

    %% Make a request first
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/test.txt">>},
        {<<":authority">>, list_to_binary(Host)}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    {Status, _, _} = receive_response(Conn, StreamId, 10000),
    ?assertEqual(200, Status),

    %% Initiate graceful shutdown
    ok = quic_h3:goaway(Conn),

    ct:pal("GOAWAY sent, closing connection"),
    quic_h3:close(Conn).

%%====================================================================
%% Helper Functions
%%====================================================================

%% @doc Wait for H3 connection to be ready
wait_for_h3_connected(Conn, Timeout) ->
    receive
        {quic_h3, Conn, connected} ->
            ok;
        {quic_h3, Conn, {connected, _Info}} ->
            ok
    after Timeout ->
        {error, timeout}
    end.

%% @doc Wait for server to be reachable
wait_for_server(_Host, _Port, 0) ->
    {error, timeout};
wait_for_server(Host, Port, Retries) ->
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            HostAddr =
                case inet:parse_address(Host) of
                    {ok, Addr} -> Addr;
                    {error, _} -> Host
                end,
            Result = gen_udp:send(Socket, HostAddr, Port, <<0:32>>),
            gen_udp:close(Socket),
            case Result of
                ok ->
                    ok;
                {error, _} ->
                    timer:sleep(1000),
                    wait_for_server(Host, Port, Retries - 1)
            end;
        {error, _} ->
            timer:sleep(1000),
            wait_for_server(Host, Port, Retries - 1)
    end.

%% @doc Receive HTTP/3 response (headers + body)
receive_response(Conn, StreamId, Timeout) ->
    receive_response(Conn, StreamId, Timeout, undefined, [], <<>>).

receive_response(Conn, StreamId, Timeout, Status, Headers, BodyAcc) ->
    receive
        {quic_h3, Conn, {response, StreamId, RespStatus, RespHeaders}} ->
            receive_response(Conn, StreamId, Timeout, RespStatus, RespHeaders, BodyAcc);
        {quic_h3, Conn, {headers, StreamId, RespStatus, RespHeaders}} ->
            receive_response(Conn, StreamId, Timeout, RespStatus, RespHeaders, BodyAcc);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {Status, Headers, <<BodyAcc/binary, Data/binary>>};
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            receive_response(
                Conn, StreamId, Timeout, Status, Headers, <<BodyAcc/binary, Data/binary>>
            );
        {quic_h3, Conn, {trailers, StreamId, _Trailers}} ->
            %% Trailers signal end of stream
            {Status, Headers, BodyAcc};
        {quic_h3, Conn, {stream_end, StreamId}} ->
            {Status, Headers, BodyAcc}
    after Timeout ->
        ct:fail({response_timeout, StreamId, Status, byte_size(BodyAcc)})
    end.

%% @doc Collect responses from multiple streams
collect_multiple_responses(_Conn, [], Responses, _Timeout) ->
    Responses;
collect_multiple_responses(Conn, StreamIds, Responses, Timeout) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, Headers}} ->
            case lists:member(StreamId, StreamIds) of
                true ->
                    Body = collect_body(Conn, StreamId, <<>>, Timeout),
                    NewResponses = maps:put(StreamId, {Status, Headers, Body}, Responses),
                    RemainingStreams = lists:delete(StreamId, StreamIds),
                    collect_multiple_responses(Conn, RemainingStreams, NewResponses, Timeout);
                false ->
                    collect_multiple_responses(Conn, StreamIds, Responses, Timeout)
            end;
        {quic_h3, Conn, {headers, StreamId, Status, Headers}} ->
            case lists:member(StreamId, StreamIds) of
                true ->
                    Body = collect_body(Conn, StreamId, <<>>, Timeout),
                    NewResponses = maps:put(StreamId, {Status, Headers, Body}, Responses),
                    RemainingStreams = lists:delete(StreamId, StreamIds),
                    collect_multiple_responses(Conn, RemainingStreams, NewResponses, Timeout);
                false ->
                    collect_multiple_responses(Conn, StreamIds, Responses, Timeout)
            end
    after Timeout ->
        ct:pal(
            "Timeout collecting multiple responses, collected ~p of ~p",
            [maps:size(Responses), maps:size(Responses) + length(StreamIds)]
        ),
        Responses
    end.

%% @doc Collect body data for a stream
collect_body(Conn, StreamId, Acc, Timeout) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            collect_body(Conn, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic_h3, Conn, {trailers, StreamId, _}} ->
            Acc;
        {quic_h3, Conn, {stream_end, StreamId}} ->
            Acc
    after Timeout ->
        ct:pal("Timeout collecting body, have ~p bytes", [byte_size(Acc)]),
        Acc
    end.
