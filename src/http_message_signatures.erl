%%%-------------------------------------------------------------------
%% @doc Verify / Sign HTTP requests / responses using HTTP Message Signatures
%%
%% RFC draft-ietf-httpbis-message-signatures-19 - [https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures]
%%
%% @end
%% @since 1.0.0
%%%-------------------------------------------------------------------

-module(http_message_signatures).

-feature(maybe_expr, enable).

-export([canonicalize_headers/3]).
-export([sign/2]).
-export([verify/2]).

-export_type([body/0]).
-export_type([component/0]).
-export_type([header/0]).
-export_type([headers/0]).
-export_type([method/0]).
-export_type([parameters/0]).
-export_type([request/0]).
-export_type([response/0]).
-export_type([signer/0]).
-export_type([sign_options/0]).
-export_type([status/0]).
-export_type([url/0]).
-export_type([verifier/0]).
-export_type([verifier/1]).
-export_type([verify_error_reason/0]).
-export_type([verify_options/0]).
-export_type([verify_options/1]).

-type request() :: #{
    url := url(),
    method := method(),
    headers => headers(),
    body => body()
}.

-type response() :: #{
    status := status(),
    headers => headers(),
    body => body()
}.

-type status() :: 100..599.
-type url() :: uri_string:uri_string().
-type method() :: head | get | put | patch | post | trace | options | delete.
-type headers() :: [header()].
-type header_value() :: binary() | iolist().
-type header() :: {Field :: [byte()], Value :: header_value()}.
-type body() :: iolist() | binary().

-type component() ::
    method
    | target_uri
    | authority
    | scheme
    | request_target
    | path
    | query
    | query_params
    | status
    | request_response
    | binary().
-type signer() :: fun((Data :: iolist() | binary()) -> binary()).

-type sign_options() :: #{
    expires => calendar:datetime(),
    created => calendar:datetime(),
    nonce => binary(),
    alg := binary(),
    keyid := binary(),
    tag => binary(),
    components => [component()],
    key => binary(),
    signer := signer()
}.

-type verifier(Reason) :: fun(
    (Data :: iolist() | binary(), Signature :: binary(), Parameters :: parameters()) ->
        ok | {error, Reason}
).
-type verifier() :: verifier(term()).

-type verify_options(VerifierErrorReason) :: #{
    verifier := verifier(VerifierErrorReason)
}.
-type verify_options() :: verify_options(term()).

-type verify_error_reason() ::
    {parse_error, Type :: signature | input, Subject :: binary(), ErrorDescription :: binary()}.

-type parameters() :: [
    {created, calendar:datetime()}
    | {expires, calendar:datetime()}
    | {nonce, binary()}
    | {alg, binary()}
    | {keyid, binary()}
    | {tag, binary()}
].

%% @doc Sign a HTTP request / response
%%
%% <h2>Example</h2>
%%
%% ```
%% Request = #{
%%   method => get,
%%   url => <<"https://example.com/path?queryString">>,
%%   headers => [{"content-type", "text/plain"}]
%% },
%%
%% SignedRequest = http_message_signatures:sign(
%%   Request,
%%   #{
%%     components => [method, path, <<"content-type">>],
%%     key => <<"sig1">>,
%%     signer => fun(Data) ->
%%       execute_signature(Data)
%%     end
%%   }
%% ).
%% '''
%% @end
%% @since 1.0.0
-spec sign(Message, Options) -> Message when
    Message :: request() | response(),
    Options :: sign_options().
sign(Message, Options) ->
    Signer = maps:get(signer, Options),

    DefaultComponents =
        case maps:is_key(status, Message) of
            true -> [status, <<"content-type">>, <<"digest">>];
            false -> [method, path, query, authority, <<"content-type">>, <<"digest">>]
        end,
    Components = maps:get(components, Options, DefaultComponents),

    Key = maps:get(key, Options, <<"sig1">>),

    SignatureParams = lists:sort(
        maps:to_list(
            maps:merge(
                #{created => calendar:local_time()},
                maps:without([signer, components, key], Options)
            )
        )
    ),
    SignatureInput = build_signature_input(Components, SignatureParams),
    SignatureData = build_signature_data(Message, Components, SignatureInput),

    Signature = Signer(SignatureData),
    SignatureEncoded = base64:encode(iolist_to_binary(Signature)),

    OriginalHeaders = maps:get(headers, Message, []),

    maps:put(
        headers,
        [
            {<<"Signature">>, [Key, "=:", SignatureEncoded, ":"]},
            {<<"Signature-Input">>, [Key, "=", SignatureInput]}
            | OriginalHeaders
        ],
        Message
    ).

-spec build_signature_input(Components, Parameters) -> Out when
    Components :: [component()],
    Parameters :: parameters(),
    Out :: iolist().
build_signature_input(Components, Parameters) ->
    [
        "(",
        build_components_string(Components, []),
        ")",
        build_parameters_string(Parameters, [])
    ].

-spec build_components_string(Components, Acc) -> Out when
    Components :: [component()],
    Acc :: iolist(),
    Out :: iolist().
build_components_string([], []) ->
    [];
build_components_string([], Acc) ->
    lists:reverse(tl(lists:reverse(Acc)));
build_components_string([Component | Components], Acc) when is_atom(Component) ->
    build_components_string(Components, [Acc, "\"@", atom_to_binary(Component), "\" "]);
build_components_string([Component | Components], Acc) when is_binary(Component) ->
    build_components_string(Components, [Acc, "\"", string:lowercase(Component), "\"", " "]);
build_components_string([{query_param, Name} | Components], Acc) when is_binary(Name) ->
    build_components_string(Components, [Acc, "\"@query-param\";name=\"", Name, "\"", " "]).

-spec build_parameters_string(Parameters, Acc) -> Out when
    Parameters :: parameters(),
    Acc :: iolist(),
    Out :: iolist().
build_parameters_string([], Acc) ->
    Acc;
build_parameters_string([{Key, Value} | Parameters], Acc) when is_binary(Value) ->
    build_parameters_string(Parameters, [Acc, ";", atom_to_list(Key), "=\"", Value, "\""]);
build_parameters_string([{Key, {_Date, _Time} = Value} | Parameters], Acc) ->
    build_parameters_string(Parameters, [
        Acc,
        ";",
        atom_to_list(Key),
        "=",
        integer_to_list(date_to_integer(Value))
    ]).

-spec build_signature_data(Message, Components, SignatureInput) -> Out when
    Message :: request() | response(),
    Components :: [component()],
    SignatureInput :: iolist(),
    Out :: iolist().
build_signature_data(Message, Components, SignatureInput) ->
    [
        extract_components(Components, Message, []),
        "\"@signature-params\": ",
        SignatureInput
    ].

-spec extract_components(Components, Message, Acc) -> Out when
    Components :: [component()],
    Message :: request() | response(),
    Acc :: iolist(),
    Out :: iolist().
extract_components([], _Message, Acc) ->
    Acc;
extract_components([method | Components], Message, Acc) ->
    Method = string:uppercase(atom_to_list(maps:get(method, Message))),
    extract_components(Components, Message, [Acc, "\"@method\": ", Method, "\n"]);
extract_components([status | Components], Message, Acc) ->
    Status = integer_to_list(maps:get(status, Message)),
    extract_components(Components, Message, [Acc, "\"@status\": ", Status, "\n"]);
extract_components([target_uri | Components], Message, Acc) ->
    Url = maps:get(url, Message),
    extract_components(Components, Message, [Acc, "\"@target-uri\": ", Url, "\n"]);
extract_components([authority | Components], Message, Acc) ->
    Url = maps:get(url, Message),
    extract_components(Components, Message, [Acc, "\"@authority\": ", uri_authority(Url), "\n"]);
extract_components([scheme | Components], Message, Acc) ->
    #{scheme := Scheme} = uri_string:parse(maps:get(url, Message)),
    extract_components(Components, Message, [Acc, "\"@scheme\": ", Scheme, "\n"]);
extract_components([request_target | Components], Message, Acc) ->
    Uri = maps:get(url, Message),
    extract_components(Components, Message, [Acc, "\"@request-target\": ", uri_target(Uri), "\n"]);
extract_components([path | Components], Message, Acc) ->
    #{path := Path} = uri_string:parse(maps:get(url, Message)),
    extract_components(Components, Message, [Acc, "\"@path\": ", Path, "\n"]);
extract_components([query | Components], Message, Acc) ->
    #{query := Query} = uri_string:parse(maps:get(url, Message)),
    extract_components(Components, Message, [Acc, "\"@query\": ?", Query, "\n"]);
extract_components([{query_param, Name} | Components], Message, Acc) ->
    #{query := Query} = uri_string:parse(maps:get(url, Message)),
    QueryParams = uri_string:dissect_query(Query),
    Value = proplists:get_value(binary_to_list(Name), QueryParams, <<>>),
    extract_components(Components, Message, [
        Acc, "\"@query-param\";name=\"", Name, "\": ", Value, "\n"
    ]);
extract_components([Header | Components], Message, Acc) when is_binary(Header) ->
    HeaderValue = lists:join(", ", find_headers(Header, maps:get(headers, Message))),
    extract_components(Components, Message, [
        Acc, "\"", string:lowercase(Header), "\": ", HeaderValue, "\n"
    ]).

-spec find_headers(Key, Headers) -> Out when
    Key :: binary(), Headers :: headers(), Out :: [header_value()].
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

-spec uri_authority(Uri) -> Authority when Uri :: url(), Authority :: iolist().
uri_authority(Uri) ->
    UriMap = uri_string:parse(Uri),
    Authority0 = maps:get(host, UriMap),
    Authority1 =
        case UriMap of
            #{port := Port} -> [Authority0, ":", integer_to_list(Port)];
            _NoPort -> Authority0
        end,
    case UriMap of
        #{userinfo := UserInfo} -> [UserInfo, "@", Authority1];
        _NoUserInfo -> Authority1
    end.

-spec uri_target(Uri) -> Target when Uri :: url(), Target :: iolist().
uri_target(Uri) ->
    UriMap = uri_string:parse(Uri),
    Target0 = maps:get(path, UriMap, ""),
    case UriMap of
        #{query := Query} -> [Target0, "?", Query];
        _NoQuery -> [Target0]
    end.

%% @doc Verify HTTP request / response signatures
%%
%% <h2>Example</h2>
%%
%% ```
%% SignedRequest = #{
%%   %% Get the signed request from somewhere
%% },
%%
%% {ok, #{<<"sig1">> := Parameters} = http_message_signatures:verify(
%%   SignedRequest,
%%   #{
%%     verifier => fun(Data, Signature, SignatureParameters) ->
%%       case execute_signature_verification(Data) of
%%         true -> ok;
%%         false -> {error, invalid_signature}
%%       end
%%     end
%%   }
%% ).
%% '''
%% @end
%% @since 1.0.0
-spec verify(Message, Options) -> {ok, SignatureParameters} | {error, Reason} when
    Message :: request() | response(),
    Options :: verify_options(VerifierErrorReason),
    Reason :: VerifierErrorReason | verify_error_reason(),
    SignatureParameters :: #{KeyId := parameters()},
    KeyId :: binary().
verify(Message, Options) ->
    Headers = maps:get(headers, Message, []),
    Signatures = extract_keyid(find_headers(<<"signature">>, Headers)),
    SignatureInputs = extract_keyid(find_headers(<<"signature-input">>, Headers)),

    Zipped = zip_headers(Signatures, SignatureInputs),

    verify_signatures(Zipped, Message, Options, #{}).

-spec extract_keyid(Headers) -> Out when
    Headers :: [header_value()],
    Out :: [{Key, Value}],
    Key :: binary(),
    Value :: binary().
extract_keyid(Headers) ->
    lists:map(
        fun(Header) ->
            HeaderBin = iolist_to_binary(Header),
            [Key, Value] = binary:split(HeaderBin, <<"=">>),
            {Key, Value}
        end,
        Headers
    ).

-spec zip_headers(HeadersA, HeadersB) -> Out when
    HeadersA :: [{Key, HeaderA}],
    HeadersB :: [{Key, HeaderB}],
    Out :: [{Key, HeaderA, HeaderB}],
    Key :: binary().
zip_headers(HeadersA, HeadersB) ->
    Keys = proplists:get_keys(HeadersA) ++ proplists:get_keys(HeadersB),
    UniqueKeys = sets:to_list(sets:from_list(Keys)),

    lists:map(
        fun(Key) ->
            {Key, proplists:get_value(Key, HeadersA), proplists:get_value(Key, HeadersB)}
        end,
        UniqueKeys
    ).

-spec verify_signatures(Signatures, Message, Options, Acc) -> {ok, Acc} | {error, Reason} when
    Signatures :: [{KeyId, Signature, SignatureInput}],
    KeyId :: binary(),
    Signature :: binary(),
    SignatureInput :: #{
        components := [component()],
        parameters := parameters()
    },
    Message :: request() | response(),
    Options :: verify_options(VerifierErrorReason),
    Reason :: VerifierErrorReason | verify_error_reason(),
    Acc :: #{KeyId := parameters()}.
verify_signatures([], _Message, _Options, Acc) ->
    {ok, Acc};
verify_signatures(
    [{KeyId, SignatureBin, SignatureInputBin} | Rest],
    Message,
    Options,
    Acc
) ->
    Verifier = maps:get(verifier, Options),
    maybe
        {ok, SignatureTokens, _} ?=
            http_message_signatures_signature_lexer:string(binary_to_list(SignatureBin)),
        {ok, SignatureInputTokens, _} ?=
            http_message_signatures_input_lexer:string(binary_to_list(SignatureInputBin)),
        {ok, SignatureBase64} = http_message_signatures_signature_parser:parse(SignatureTokens),
        Signature = base64:decode(SignatureBase64),
        {ok, #{components := Components, parameters := Parameters}} = http_message_signatures_input_parser:parse(
            SignatureInputTokens
        ),
        SignatureData = build_signature_data(Message, Components, [SignatureInputBin]),
        ok ?= Verifier(SignatureData, Signature, Parameters),
        verify_signatures(Rest, Message, Options, maps:put(KeyId, Parameters, Acc))
    else
        {error, {_Loc, http_message_signatures_signature_lexer, Reason}, _EndLoc} ->
            {error,
                {parse_error, signature, SignatureBin,
                    http_message_signatures_signature_lexer:format_error(Reason)}};
        {error, {_Loc, http_message_signatures_input_lexer, Reason}, _EndLoc} ->
            {error,
                {parse_error, input, SignatureInputBin,
                    http_message_signatures_input_lexer:format_error(Reason)}};
        {error, {_Loc, http_message_signatures_signature_parser, Reason}} ->
            {error,
                {parse_error, signature, SignatureBin,
                    http_message_signatures_signature_parser:format_error(Reason)}};
        {error, {_Loc, http_message_signatures_input_parser, Reason}} ->
            {error,
                {parse_error, input, SignatureInputBin,
                    http_message_signatures_input_parser:format_error(Reason)}}
    end.

%% @hidden
-spec canonicalize_headers(Message, RequestedHeaders, Options) ->
    {ok, Message} | {error, header_missing}
when
    Message :: request() | response(), RequestedHeaders :: [binary()], Options :: #{created => calendar:datetime(), expires => calendar:datetime()}.
canonicalize_headers(_Message, [], _Options) ->
    {ok, []};
canonicalize_headers(Message, RequestedHeaders, Options) ->
    NormalizedHeaders = lists:map(
        fun({Field, Value}) -> {string:lowercase(iolist_to_binary(Field)), Value} end,
        maps:get(headers, Message, [])
    ),

    CanonicalizedHeaders = lists:flatmap(
        fun
            (<<"(created)">> = RequestedHeader)  ->
                [
                    {RequestedHeader, [integer_to_list(date_to_integer(maps:get(created, Options, calendar:local_time())))]}
                ];
            (<<"(expires)">> = RequestedHeader)  ->
                [
                    {RequestedHeader, [integer_to_list(date_to_integer(maps:get(expires, Options, calendar:local_time())))]}
                ];

            (<<"(request-target)">> = RequestedHeader) ->
                [
                    {RequestedHeader, [
                        atom_to_list(maps:get(method, Message)), " ", maps:get(url, Message)
                    ]}
                ];
            (RequestedHeader) ->
                LowercaseRequestedHeader = string:lowercase(RequestedHeader),

                case proplists:lookup_all(LowercaseRequestedHeader, NormalizedHeaders) of
                    [] -> [{error, header_missing}];
                    Headers -> Headers
                end
        end,
        RequestedHeaders
    ),

    case proplists:get_value(error, CanonicalizedHeaders) of
        undefined -> {ok, CanonicalizedHeaders};
        Reason -> {error, Reason}
    end.

-spec date_to_integer(DateTime) -> integer() when DateTime :: calendar:datetime().
date_to_integer(DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime) -
        calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}).
