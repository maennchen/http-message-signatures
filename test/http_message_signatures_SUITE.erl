-module(http_message_signatures_SUITE).

% Based on RFC Test Cases
% https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#appendix-B.2

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([b21_sign/1]).
-export([b21_verify/1]).
-export([b22_sign/1]).
-export([b22_verify/1]).
-export([b23_sign/1]).
-export([b23_verify/1]).
-export([b24_sign/1]).
-export([b24_verify/1]).
-export([b25_sign/1]).
-export([b25_verify/1]).
-export([b26_sign/1]).
-export([b26_verify/1]).

% -define(B11_PrivateKey, read_key("b_1_1.priv.pem")).
% -define(B11_PublicKey, read_key("b_1_1.pub.pem")).
% -define(B12_PrivateKey, read_key("b_1_2.priv.pem")).
-define(B12_PublicKey, read_key("b_1_2.pub.pem")).
% -define(B13_PrivateKey, read_key("b_1_3.priv.pem")).
-define(B13_PublicKey, read_key("b_1_3.pub.pem")).
% -define(B14_PrivateKey, read_key("b_1_4.priv.pem")).
% -define(B14_PublicKey, read_key("b_1_4.pub.pem")).
-define(B15_SharedSecret, base64:decode(read_file("b_1_5.secret.txt"))).

all() ->
    [
        b21_sign,
        b21_verify,
        b22_sign,
        b22_verify,
        b23_sign,
        b23_verify,
        b24_sign,
        b24_verify,
        b25_sign,
        b25_verify,
        b26_sign,
        b26_verify
    ].

-define(Request, #{
    method => post,
    url => "https://example.com/foo?param=Value&Pet=dog",
    headers => [
        {"Host", "example.com"},
        {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
        {"Content-Type", "application/json"},
        {"Content-Digest", [
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T",
            "aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        ]},
        {"Content-Length", "18"}
    ],
    body => <<"{\"hello\": \"world\"}">>
}).

-define(Response, #{
    status => 200,
    headers => [
        {"Date", "Tue, 20 Apr 2021 02:07:56 GMT"},
        {"Content-Type", "application/json"},
        {"Content-Digest", [
            "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4",
            "1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"
        ]},
        {"Content-Length", "23"}
    ],
    body => <<"{\"message\": \"good dog\"}">>
}).

%
% B.2.1. Minimal Signature Using rsa-pss-sha512
%

-define(B21_Components, []).

-define(B21_Input,
    <<"sig-b21=();created=1618884473;keyid=\"test-key-rsa-pss\"",
        ";nonce=\"b3k2pp5k7z-50gnwp.yemd\"">>
).

-define(B21_Signature,
    <<"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem",
        "LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG",
        "52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx",
        "2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6",
        "UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3",
        "+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:">>
).

-define(B21_SignatureData,
    <<"\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\"",
        ";nonce=\"b3k2pp5k7z-50gnwp.yemd\"">>
).

-define(B21_SignatureRaw,
    base64:decode(
        <<"d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem",
            "LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG",
            "52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx",
            "2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6",
            "UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3",
            "+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==">>
    )
).

b21_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Response, #{
        components => ?B21_Components,
        key => <<"sig-b21">>,
        keyid => <<"test-key-rsa-pss">>,
        nonce => <<"b3k2pp5k7z-50gnwp.yemd">>,
        signer => fun(Data) ->
            ?assertEqual(?B21_SignatureData, iolist_to_binary(Data)),

            ?B21_SignatureRaw
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B21_Input, SignatureInput),
    ?assertEqual(?B21_Signature, Signature),

    ok.

b21_verify(_) ->
    Message = sign_with(?Response, ?B21_Input, ?B21_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B21_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B21_SignatureRaw, Signature),

            case
                public_key:verify(
                    iolist_to_binary(Data),
                    sha512,
                    Signature,
                    ?B12_PublicKey,
                    [{rsa_padding, rsa_pkcs1_pss_padding}]
                )
            of
                true -> ok;
                false -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b21">> :=
                {?B21_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-key-rsa-pss">>},
                    {nonce, <<"b3k2pp5k7z-50gnwp.yemd">>}
                ]}
        }},
        Result
    ),

    ok.

%
% B.2.2. Selective Covered Components using rsa-pss-sha512
%

-define(B22_Components, [authority, <<"content-digest">>, {query_param, <<"Pet">>}]).

-define(B22_Input,
    <<"sig-b22=(\"@authority\" \"content-digest\" ", "\"@query-param\";name=\"Pet\")",
        ";created=1618884473;keyid=\"test-key-rsa-pss\"", ";tag=\"header-example\"">>
).

-define(B22_Signature,
    <<"sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ",
        "EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT",
        "8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA",
        "RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd",
        "4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK",
        "UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:">>
).

-define(B22_SignatureData,
    <<"\"@authority\": example.com\n",
        "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX",
        "+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n",
        "\"@query-param\";name=\"Pet\": dog\n",
        "\"@signature-params\": (\"@authority\" \"content-digest\" ",
        "\"@query-param\";name=\"Pet\")", ";created=1618884473;keyid=\"test-key-rsa-pss\"",
        ";tag=\"header-example\"">>
).

-define(B22_SignatureRaw,
    base64:decode(
        <<"LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ",
            "EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT",
            "8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA",
            "RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd",
            "4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK",
            "UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==">>
    )
).

b22_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Request, #{
        components => ?B22_Components,
        key => <<"sig-b22">>,
        keyid => <<"test-key-rsa-pss">>,
        tag => <<"header-example">>,
        signer => fun(Data) ->
            ?assertEqual(?B22_SignatureData, iolist_to_binary(Data)),

            ?B22_SignatureRaw
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B22_Input, SignatureInput),
    ?assertEqual(?B22_Signature, Signature),

    ok.

b22_verify(_) ->
    Message = sign_with(?Request, ?B22_Input, ?B22_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B22_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B22_SignatureRaw, Signature),

            case
                public_key:verify(
                    iolist_to_binary(Data),
                    sha512,
                    Signature,
                    ?B12_PublicKey,
                    [{rsa_padding, rsa_pkcs1_pss_padding}]
                )
            of
                true -> ok;
                false -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b22">> :=
                {?B22_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-key-rsa-pss">>},
                    {tag, <<"header-example">>}
                ]}
        }},
        Result
    ),

    ok.

%
% B.2.3. Full Coverage using rsa-pss-sha512
%

-define(B23_Components, [
    <<"date">>,
    method,
    path,
    query,
    authority,
    <<"content-type">>,
    <<"content-digest">>,
    <<"content-length">>
]).

-define(B23_Input,
    <<"sig-b23=(\"date\" \"@method\" \"@path\" \"@query\" ",
        "\"@authority\" \"content-type\" \"content-digest\" \"content-length\")",
        ";created=1618884473;keyid=\"test-key-rsa-pss\"">>
).

-define(B23_Signature,
    <<"sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB",
        "iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU",
        "xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1",
        "pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9",
        "bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z",
        "JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:">>
).

-define(B23_SignatureData,
    <<"\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n", "\"@method\": POST\n", "\"@path\": /foo\n",
        "\"@query\": ?param=Value&Pet=dog\n", "\"@authority\": example.com\n",
        "\"content-type\": application/json\n",
        "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX",
        "+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n", "\"content-length\": 18\n",
        "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@query\" ",
        "\"@authority\" \"content-type\" \"content-digest\" \"content-length\")",
        ";created=1618884473;keyid=\"test-key-rsa-pss\"">>
).

-define(B23_SignatureRaw,
    base64:decode(
        <<"bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB",
            "iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU",
            "xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1",
            "pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9",
            "bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z",
            "JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==">>
    )
).

b23_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Request, #{
        components => ?B23_Components,
        key => <<"sig-b23">>,
        keyid => <<"test-key-rsa-pss">>,
        signer => fun(Data) ->
            ?assertEqual(?B23_SignatureData, iolist_to_binary(Data)),

            ?B23_SignatureRaw
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B23_Input, SignatureInput),
    ?assertEqual(?B23_Signature, Signature),

    ok.

b23_verify(_) ->
    Message = sign_with(?Request, ?B23_Input, ?B23_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B23_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B23_SignatureRaw, Signature),

            case
                public_key:verify(
                    iolist_to_binary(Data),
                    sha512,
                    Signature,
                    ?B12_PublicKey,
                    [{rsa_padding, rsa_pkcs1_pss_padding}]
                )
            of
                true -> ok;
                false -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b23">> :=
                {?B23_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-key-rsa-pss">>}
                ]}
        }},
        Result
    ),

    ok.

%
% B.2.4. Signing a Response using ecdsa-p256-sha256
%

-define(B24_Components, [status, <<"content-type">>, <<"content-digest">>, <<"content-length">>]).

-define(B24_Input,
    <<"sig-b24=(\"@status\" \"content-type\" \"content-digest\" ",
        "\"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"">>
).

-define(B24_Signature,
    <<"sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK",
        "ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:">>
).

-define(B24_SignatureData,
    <<"\"@status\": 200\n", "\"content-type\": application/json\n",
        "\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4",
        "1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n", "\"content-length\": 23\n",
        "\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" ",
        "\"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"">>
).

-define(B24_SignatureRaw,
    base64:decode(
        <<"wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK",
            "ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==">>
    )
).

b24_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Response, #{
        components => ?B24_Components,
        key => <<"sig-b24">>,
        keyid => <<"test-key-ecc-p256">>,
        signer => fun(Data) ->
            ?assertEqual(?B24_SignatureData, iolist_to_binary(Data)),

            ?B24_SignatureRaw
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B24_Input, SignatureInput),
    ?assertEqual(?B24_Signature, Signature),

    ok.

b24_verify(_) ->
    Message = sign_with(?Response, ?B24_Input, ?B24_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B24_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B24_SignatureRaw, Signature),

            {Key, _} = jose_jwk_kty_ec:from_key(?B13_PublicKey),

            case jose_jwk_kty_ec:verify(iolist_to_binary(Data), 'ES256', Signature, Key) of
                true -> ok;
                false -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b24">> :=
                {?B24_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-key-ecc-p256">>}
                ]}
        }},
        Result
    ),

    ok.

%
% B.2.5. Signing a Request using hmac-sha256
%

-define(B25_Components, [<<"date">>, authority, <<"content-type">>]).

-define(B25_Input,
    <<"sig-b25=(\"date\" \"@authority\" \"content-type\")",
        ";created=1618884473;keyid=\"test-shared-secret\"">>
).

-define(B25_Signature, <<"sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:">>).

-define(B25_SignatureData,
    <<"\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n", "\"@authority\": example.com\n",
        "\"content-type\": application/json\n",
        "\"@signature-params\": (\"date\" \"@authority\" \"content-type\")",
        ";created=1618884473;keyid=\"test-shared-secret\"">>
).

-define(B25_SignatureRaw, base64:decode(<<"pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=">>)).

b25_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Request, #{
        components => ?B25_Components,
        key => <<"sig-b25">>,
        keyid => <<"test-shared-secret">>,
        signer => fun(Data) ->
            ?assertEqual(?B25_SignatureData, iolist_to_binary(Data)),

            Signature = crypto:mac(hmac, sha256, ?B15_SharedSecret, iolist_to_binary(Data)),

            ?assertEqual(?B25_SignatureRaw, Signature),

            Signature
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B25_Input, SignatureInput),
    ?assertEqual(?B25_Signature, Signature),

    ok.

b25_verify(_) ->
    Message = sign_with(?Request, ?B25_Input, ?B25_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B25_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B25_SignatureRaw, Signature),

            case crypto:mac(hmac, sha256, ?B15_SharedSecret, iolist_to_binary(Data)) of
                Signature -> ok;
                _Other -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b25">> :=
                {?B25_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-shared-secret">>}
                ]}
        }},
        Result
    ),

    ok.

%
% B.2.6. Signing a Request using ed25519
%

-define(B26_Components, [
    <<"date">>, method, path, authority, <<"content-type">>, <<"content-length">>
]).

-define(B26_Input,
    <<"sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" ",
        "\"content-type\" \"content-length\");created=1618884473", ";keyid=\"test-key-ed25519\"">>
).

-define(B26_Signature,
    <<"sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1",
        "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:">>
).

-define(B26_SignatureData,
    <<"\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n", "\"@method\": POST\n", "\"@path\": /foo\n",
        "\"@authority\": example.com\n", "\"content-type\": application/json\n",
        "\"content-length\": 18\n",
        "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" ",
        "\"content-type\" \"content-length\");created=1618884473", ";keyid=\"test-key-ed25519\"">>
).

-define(B26_SignatureRaw,
    base64:decode(
        <<"wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1",
            "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==">>
    )
).

b26_sign(_) ->
    #{headers := SignedHeaders} = http_message_signatures:sign(?Request, #{
        components => ?B26_Components,
        key => <<"sig-b26">>,
        keyid => <<"test-key-ed25519">>,
        signer => fun(Data) ->
            ?assertEqual(?B26_SignatureData, iolist_to_binary(Data)),

            ?B26_SignatureRaw
        end,
        created => {{2021, 4, 20}, {2, 7, 53}}
    }),

    SignatureInput = iolist_to_binary(find_headers(<<"signature-input">>, SignedHeaders)),
    Signature = iolist_to_binary(find_headers(<<"signature">>, SignedHeaders)),

    ?assertEqual(?B26_Input, SignatureInput),
    ?assertEqual(?B26_Signature, Signature),

    ok.

b26_verify(_) ->
    Message = sign_with(?Request, ?B26_Input, ?B26_Signature),

    Result = http_message_signatures:verify(Message, #{
        verifier => fun(Data, Signature, _Parameters) ->
            ?assertEqual(?B26_SignatureData, iolist_to_binary(Data)),
            ?assertEqual(?B26_SignatureRaw, Signature),

            {Key, _} = jose_jwk_kty_okp_ed25519:from_pem(read_file("b_1_4.pub.pem")),

            case
                jose_jwk_kty_okp_ed25519:verify(iolist_to_binary(Data), 'Ed25519', Signature, Key)
            of
                true -> ok;
                false -> {error, invalid_signature}
            end
        end
    }),

    ?assertMatch(
        {ok, #{
            <<"sig-b26">> :=
                {?B26_Components, [
                    {created, {{2021, 4, 20}, {2, 7, 53}}},
                    {keyid, <<"test-key-ed25519">>}
                ]}
        }},
        Result
    ),

    ok.

find_headers(Key, Headers) ->
    NormalizedKey = string:lowercase(Key),
    lists:flatmap(
        fun({CmpKey, Value}) ->
            case string:lowercase(iolist_to_binary([CmpKey])) of
                NormalizedKey -> [Value];
                _Other -> []
            end
        end,
        Headers
    ).

sign_with(Message, SignatureInput, Signature) ->
    maps:put(
        headers,
        [
            {<<"signature-input">>, SignatureInput},
            {<<"signature">>, Signature}
            | maps:get(headers, Message, [])
        ],
        Message
    ).

read_file(Path) ->
    FullPath = filename:join([code:priv_dir(http_message_signatures), "test", Path]),
    {ok, Content} = file:read_file(FullPath),
    Content.

read_key(Path) ->
    Content = read_file(Path),
    [Key] = public_key:pem_decode(Content),
    public_key:pem_entry_decode(Key).
