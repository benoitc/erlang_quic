%%% -*- erlang -*-
%%%
%%% A peer sending header blocks over the advertised field section size
%%% (RFC 9114 §4.2.2) over a real connection: the server rejects an
%%% oversized header block at once rather than decoding all of it, and
%%% oversized trailers reset only their own request.
%%%
%%% The client is a raw QUIC connection writing HTTP/3 frames itself, so
%%% it can send what a well-behaved client never would. Server and client
%%% run in this VM over 127.0.0.1.
-module(quic_h3_field_section_limit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    large_header_block_is_refused_at_once/1,
    oversized_trailers_reset_only_their_request/1
]).

%% H3_EXCESSIVE_LOAD (RFC 9114 Section 8.1).
-define(EXCESSIVE_LOAD, 16#107).
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [large_header_block_is_refused_at_once, oversized_trailers_reset_only_their_request].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

%% 512 KB of two-byte field lines ("static name, empty value"). Decoding
%% all of it used to take minutes; the server now stops at the limit.
large_header_block_is_refused_at_once(Config) ->
    with_server(Config, fun(Conn) ->
        Lines = binary:copy(<<16#51, 0>>, 256000),
        {ok, StreamId} = quic:open_stream(Conn),
        T0 = erlang:monotonic_time(millisecond),
        ok = quic:send_data(Conn, StreamId, headers_frame(<<0, 0, Lines/binary>>), false),
        Reason = closed_reason(Conn),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ?assertMatch({peer_closed, application, ?EXCESSIVE_LOAD, _}, Reason),
        ?assert(Elapsed < ?WAIT_MS)
    end).

%% Trailers of 2000 static "cookie" fields (76 000 bytes by the RFC's count) over
%% the 64 KiB default: that request is reset and the connection goes on.
oversized_trailers_reset_only_their_request(Config) ->
    with_server(Config, fun(Conn) ->
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, headers_frame(request(<<"/upload">>)), false),
        Trailers = <<0, 0, (binary:copy(<<16#C5>>, 2000))/binary>>,
        ok = quic:send_data(Conn, StreamId, headers_frame(Trailers), true),
        ?assertEqual({stream_reset, StreamId, ?EXCESSIVE_LOAD}, stream_reset(Conn, StreamId)),
        {ok, Next} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, Next, headers_frame(request(<<"/ok">>)), true),
        ?assertEqual(got_response, response(Conn, Next))
    end).

%%====================================================================
%% Helpers
%%====================================================================

with_server(Config, F) ->
    Name = list_to_atom("h3_fsl_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun
            (C, S, _Method, <<"/ok">>, _Headers) -> quic_h3:respond(C, S, 200, [], <<"ok">>);
            (_C, _S, _Method, _Path, _Headers) -> ok
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    Opts = #{alpn => [<<"h3">>], verify => false},
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    try
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?WAIT_MS -> ct:fail(connect_timeout)
        end,
        {ok, Control} = quic:open_unidirectional_stream(Conn),
        Settings = quic_h3_frame:encode_settings(#{}),
        ok = quic:send_data(
            Conn,
            Control,
            <<(quic_h3_frame:encode_stream_type(control))/binary, Settings/binary>>,
            false
        ),
        F(Conn)
    after
        _ = quic:safe_close(Conn),
        quic_h3:stop_server(Name)
    end.

request(Path) ->
    quic_qpack:encode([
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, Path}
    ]).

headers_frame(Block) ->
    quic_h3_frame:encode({headers, Block}).

closed_reason(Conn) ->
    receive
        {quic, Conn, {closed, Reason}} -> Reason
    after ?WAIT_MS -> not_closed
    end.

stream_reset(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_reset, StreamId, Code}} -> {stream_reset, StreamId, Code};
        {quic, Conn, {closed, Reason}} -> {closed, Reason}
    after ?WAIT_MS -> no_reset
    end.

%% A HEADERS frame back on the stream is the response.
response(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, <<16#01, _/binary>>, _}} -> got_response;
        {quic, Conn, {closed, Reason}} -> {closed, Reason}
    after ?WAIT_MS -> no_response
    end.
