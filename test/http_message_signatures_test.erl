-module(http_message_signatures_test).

-include_lib("eunit/include/eunit.hrl").

extracts_headers_test() ->
    extracts_headers_test([
        {<<"testheader">>, <<"test">>},
        {<<"test-header-1">>, <<"test1">>},
        {"Test-Header-2", "test2"},
        {<<"test-Header-3">>, "test3"},
        {"TEST-HEADER-4", <<"te">>},
        {<<"test-header-4">>, "st4"}
    ]).

extracts_headers_test([]) ->
    ok;
extracts_headers_test([{Key, Value} | Rest] = Headers) ->
    http_message_signatures:sign(#{headers => Headers}, #{
        components => [iolist_to_binary([Key])],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, binary_to_list(iolist_to_binary([Value]))) > 0),

            "hash"
        end
    }),

    http_message_signatures:sign(#{headers => Headers}, #{
        components => [string:uppercase(iolist_to_binary([Key]))],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, binary_to_list(iolist_to_binary([Value]))) > 0),

            "hash"
        end
    }),

    http_message_signatures:sign(#{headers => Headers}, #{
        components => [string:lowercase(iolist_to_binary([Key]))],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, binary_to_list(iolist_to_binary([Value]))) > 0),

            "hash"
        end
    }),

    extracts_headers_test(Rest).

extract_method_test() ->
    http_message_signatures:sign(#{method => post}, #{
        components => [method],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@method\": POST") > 0),

            "hash"
        end
    }),

    ok.

extract_target_uri_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [target_uri],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@target-uri\": https://example.com/path?param=value") > 0),

            "hash"
        end
    }),

    ok.

extract_authority_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [authority],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@authority\": example.com") > 0),

            "hash"
        end
    }),

    ok.

extract_scheme_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [scheme],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@scheme\": https") > 0),

            "hash"
        end
    }),

    ok.

extract_request_target_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [request_target],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@request-target\": /path?param=value") > 0),

            "hash"
        end
    }),

    ok.

extract_path_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [path],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@path\": /path") > 0),

            "hash"
        end
    }),

    ok.

extract_query_test() ->
    http_message_signatures:sign(#{url => <<"https://example.com/path?param=value">>}, #{
        components => [query],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@query\": ?param=value") > 0),

            "hash"
        end
    }),
    http_message_signatures:sign(#{url => <<"https://example.com/path?queryString">>}, #{
        components => [query],
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(string:str(Data, "\"@query\": ?queryString") > 0),

            "hash"
        end
    }),

    ok.

build_input_test() ->
    http_message_signatures:sign(#{}, #{
        components => [],
        created => {{2024, 01, 01}, {0, 0, 0}},
        keyid => <<"test-key-rsa-pss">>,
        alg => <<"rsa-pss-sha512">>,
        signer => fun(Data0) ->
            Data = binary_to_list(iolist_to_binary(Data0)),

            ?assert(
                string:str(
                    Data, "();alg=\"rsa-pss-sha512\";created=1704067200;keyid=\"test-key-rsa-pss\""
                ) > 0
            ),

            "hash"
        end
    }),

    http_message_signatures:sign(
        #{
            url => <<"https://example.com/path?queryString">>,
            headers => [{"content-type", "text/plain"}]
        },
        #{
            components => [authority, <<"Content-Type">>],
            created => {{2024, 01, 01}, {0, 0, 0}},
            keyid => <<"test-key-rsa-pss">>,
            signer => fun(Data0) ->
                Data = binary_to_list(iolist_to_binary(Data0)),

                ?assert(
                    string:str(
                        Data,
                        "(\"@authority\" \"content-type\")" ++
                            ";created=1704067200;keyid=\"test-key-rsa-pss\""
                    ) > 0
                ),

                "hash"
            end
        }
    ),

    http_message_signatures:sign(
        #{
            method => get,
            url => <<"https://example.com/path?queryString">>,
            headers => [{"content-type", "text/plain"}]
        },
        #{
            components => [
                <<"Date">>,
                method,
                path,
                query,
                authority,
                <<"Content-Type">>,
                <<"Digest">>,
                <<"Content-Length">>
            ],
            created => {{2024, 01, 01}, {0, 0, 0}},
            keyid => <<"test-key-rsa-pss">>,
            signer => fun(Data0) ->
                Data = binary_to_list(iolist_to_binary(Data0)),

                ?assert(
                    string:str(
                        Data,
                        "(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"digest\" \"content-length\")" ++
                            ";created=1704067200;keyid=\"test-key-rsa-pss\""
                    ) > 0
                ),

                "hash"
            end
        }
    ),

    ok.

build_sign_data_test() ->
    Request = #{
        method => post,
        url => "https://example.com/foo?param=value&pet=dog",
        headers => [
            {"Host", "example.com"},
            {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
            {"Content-Type", "application/json"},
            {"Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
            {"Content-Length", "18"}
        ]
    },

    http_message_signatures:sign(
        Request,
        #{
            components => [],
            created => {{2024, 01, 01}, {0, 0, 0}},
            keyid => <<"test-key-rsa-pss">>,
            alg => <<"rsa-pss-sha512">>,
            signer => fun(Data0) ->
                Data = binary_to_list(iolist_to_binary(Data0)),

                ?assert(
                    string:str(
                        Data,
                        "();alg=\"rsa-pss-sha512\";created=1704067200;keyid=\"test-key-rsa-pss\""
                    ) > 0
                ),

                "hash"
            end
        }
    ),

    http_message_signatures:sign(
        Request,
        #{
            components => [authority, <<"Content-Type">>],
            created => {{2024, 01, 01}, {0, 0, 0}},
            keyid => <<"test-key-rsa-pss">>,
            signer => fun(Data0) ->
                Data = binary_to_list(iolist_to_binary(Data0)),

                ?assert(
                    string:str(
                        Data,
                        "\"@signature-params\": (\"@authority\" \"content-type\")" ++
                            ";created=1704067200;keyid=\"test-key-rsa-pss\""
                    ) > 0
                ),

                ?assert(string:str(Data, "\"@authority\": example.com") > 0),
                ?assert(string:str(Data, "\"content-type\": application/json") > 0),

                "hash"
            end
        }
    ),

    #{
        headers := [
            {<<"Signature">>, Signature}, {<<"Signature-Input">>, SignatureInput} | _Headers
        ]
    } = http_message_signatures:sign(
        Request,
        #{
            components => [
                <<"Date">>,
                method,
                path,
                query,
                authority,
                <<"Content-Type">>,
                <<"Digest">>,
                <<"Content-Length">>
            ],
            created => {{2024, 01, 01}, {0, 0, 0}},
            keyid => <<"test-key-rsa-pss">>,
            signer => fun(Data0) ->
                Data = binary_to_list(iolist_to_binary(Data0)),

                ?assert(
                    string:str(
                        Data,
                        "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"digest\" \"content-length\")" ++
                            ";created=1704067200;keyid=\"test-key-rsa-pss\""
                    ) > 0
                ),

                ?assert(string:str(Data, "\"date\": Tue, 20 Apr 2021 02:07:55 GMT") > 0),
                ?assert(string:str(Data, "\"@method\": POST") > 0),
                ?assert(string:str(Data, "\"@path\": /foo") > 0),
                ?assert(string:str(Data, "\"@query\": ?param=value&pet=dog") > 0),
                ?assert(string:str(Data, "\"@authority\": example.com") > 0),
                ?assert(string:str(Data, "\"content-type\": application/json") > 0),
                ?assert(
                    string:str(
                        Data, "\"digest\": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
                    ) > 0
                ),
                ?assert(string:str(Data, "\"content-length\": 18") > 0),

                "hash"
            end
        }
    ),

    ?assertEqual(
        iolist_to_binary(["sig1=:", base64:encode("hash"), ":"]), iolist_to_binary(Signature)
    ),
    ?assertEqual(
        <<"sig1=(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"digest\" \"content-length\")",
            ";created=1704067200;keyid=\"test-key-rsa-pss\"">>,
        iolist_to_binary(SignatureInput)
    ),

    ok.

verify_test() ->
    Request = #{
        method => post,
        url => "https://example.com/foo?param=value&pet=dog",
        headers => [
            {"Host", "example.com"},
            {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
            {"Content-Type", "application/json"},
            {"Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
            {"Content-Length", "18"},
            {"Signature", "sig1=:aGFzaA==:"},
            {"Signature-Input",
                "sig1=(\"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"digest\")" ++
                    ";created=1681004344;keyid=\"test-key\";alg=\"hmac-sha256\""}
        ]
    },

    Result = http_message_signatures:verify(Request, #{
        verifier => fun(Data, Signature, Parameters) ->
            ?assertEqual(
                <<"\"@method\": POST\n\"@path\": /foo\n\"@query\": ?param=value&pet=dog\n",
                    "\"@authority\": example.com\n\"content-type\": application/json\n",
                    "\"digest\": SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n",
                    "\"@signature-params\": (\"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"digest\")",
                    ";created=1681004344;keyid=\"test-key\";alg=\"hmac-sha256\"">>,
                iolist_to_binary(Data)
            ),

            ?assertEqual(
                [
                    {created, {{2023, 4, 9}, {1, 39, 4}}},
                    {keyid, <<"test-key">>},
                    {alg, <<"hmac-sha256">>}
                ],
                Parameters
            ),

            ?assertEqual(<<"hash">>, Signature),

            ok
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig1">> := {[method, path, query, authority, <<"content-type">>, <<"digest">>], [
                {created, {{2023, 4, 9}, {1, 39, 4}}},
                {keyid, <<"test-key">>},
                {alg, <<"hmac-sha256">>}
            ]}
        }},
        Result
    ),

    ok.

sign_jws_test() ->
    JwkPath = filename:join([code:priv_dir(http_message_signatures), "test", "b_1_1.jwk.json"]),
    Jwk = jose_jwk:from_file(JwkPath),

    Message = #{},

    SignedMessage = http_message_signatures:sign_jws(Message, Jwk, #{
        components => [],
        created => {{2024, 01, 30}, {15, 43, 00}}
    }),

    ?assertMatch(
        {ok, #{
            <<"sig1">> :=
                {[], [{created, {{2024, 1, 30}, {15, 43, 0}}}]}
        }},
        http_message_signatures:verify_jws(SignedMessage, Jwk)
    ),

    ok.

verify_jws_none_test() ->
    jose:unsecured_signing(true),

    SignedMessage = #{
        headers => [
            {<<"Signature">>,
                <<"sig1=:eyJhbGciOiJub25lIn0.IkBzaWduYXR1cmUtcGFyYW1zIjogKCk7Y",
                    "3JlYXRlZD0xNzA2NjI5Mzgw.:">>},
            {<<"Signature-Input">>, <<"sig1=();created=1706629380">>}
        ]
    },

    ?assertMatch(
        {error, none_alg_used},
        http_message_signatures:verify_jws(SignedMessage, jose_jwk:generate_key(16))
    ),

    ok.
