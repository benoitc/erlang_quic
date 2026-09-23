%%% -*- erlang -*-
%%%
%%% Trust anchors given as a PEM file.
%%%
%%% The library takes anchors as DER `cacerts' only, so every caller that
%%% had a CA file read it themselves. `cacertfile' does that once, where
%%% a bad path fails the call instead of quietly falling back to the OS
%%% trust store and failing the handshake later.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cacertfile_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Reading the file
%%====================================================================

a_bundle_yields_every_certificate_test() ->
    File = write_pem([cert_der(), cert_der()]),
    try
        {ok, Ders} = quic_cert:cacerts_from_file(File),
        ?assertEqual(2, length(Ders)),
        ?assert(lists:all(fun is_binary/1, Ders))
    after
        file:delete(File)
    end.

%% Falling back to the OS store on a missing file would verify against
%% anchors the caller did not ask for.
a_missing_file_is_an_error_test() ->
    ?assertMatch(
        {error, {cacertfile, _, enoent}},
        quic_cert:cacerts_from_file("/nonexistent/ca.pem")
    ).

%% An empty anchor list means trust nothing, which fails every handshake
%% with a reason that says nothing about the file.
a_file_without_a_certificate_is_an_error_test() ->
    File = write_raw(<<"not a pem at all\n">>),
    try
        ?assertMatch(
            {error, {cacertfile, _, no_certificates}},
            quic_cert:cacerts_from_file(File)
        )
    after
        file:delete(File)
    end.

%%====================================================================
%% The option
%%====================================================================

a_bad_cacertfile_fails_the_connect_test() ->
    Opts = #{cacertfile => "/nonexistent/ca.pem"},
    ?assertMatch(
        {error, {cacertfile, _, enoent}}, quic:connect("127.0.0.1", 4433, Opts, self())
    ).

a_bad_cacertfile_fails_the_server_test() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Opts = #{cert => Cert, key => Key, cacertfile => "/nonexistent/ca.pem"},
    ?assertMatch(
        {error, {cacertfile, _, enoent}}, quic:start_server(bad_ca_server, 0, Opts)
    ).

%% Given both, the DER list is what the caller already resolved, so it
%% wins and the file is not read.
cacerts_wins_over_cacertfile_test() ->
    Der = cert_der(),
    Resolved = quic_cert:resolve_cacerts(#{
        cacerts => [Der], cacertfile => "/nonexistent/ca.pem"
    }),
    ?assertEqual({ok, #{cacerts => [Der], cacertfile => "/nonexistent/ca.pem"}}, Resolved).

a_cacertfile_becomes_cacerts_test() ->
    Der = cert_der(),
    File = write_pem([Der]),
    try
        {ok, Opts} = quic_cert:resolve_cacerts(#{cacertfile => File}),
        ?assertEqual([Der], maps:get(cacerts, Opts))
    after
        file:delete(File)
    end.

%% The HTTP/3 layer builds its transport options with a whitelist, so a
%% key it does not know never reaches quic:connect/4.
the_http3_whitelist_passes_it_through_test() ->
    Opts = quic_h3:test_client_quic_opts(#{cacertfile => "/tmp/ca.pem"}),
    ?assertEqual("/tmp/ca.pem", maps:get(cacertfile, Opts)).

%%====================================================================
%% Helpers
%%====================================================================

cert_der() ->
    {Cert, _Key} = quic_test_echo_server:cert_and_key(),
    Cert.

write_pem(Ders) ->
    Entries = [{'Certificate', Der, not_encrypted} || Der <- Ders],
    write_raw(public_key:pem_encode(Entries)).

write_raw(Bytes) ->
    File = lists:flatten(
        io_lib:format("/tmp/quic_cacertfile_~p.pem", [erlang:unique_integer([positive])])
    ),
    ok = file:write_file(File, Bytes),
    File.
