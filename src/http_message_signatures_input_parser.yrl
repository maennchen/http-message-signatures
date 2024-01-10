Header "%% @private".

Terminals keyword '(' ')' '=' ';' string num.
Nonterminals signature component_list components component parameters parameter.
Rootsymbol signature.

signature -> component_list ';' parameters : #{
    components => '$1',
    parameters => '$3'
}.

component_list -> '(' components ')' : '$2'.
component_list -> '(' ')' : [].

components -> component components : ['$1' | '$2'].
components -> component : ['$1'].

component -> string : cast_component(extract_simple_token('$1'), []).
component -> string ';' parameters : cast_component(extract_simple_token('$1'), '$3').

parameters -> parameter ';' parameters : ['$1' | '$3'].
parameters -> parameter : ['$1'].

parameter -> keyword '=' string : cast_parameter(extract_simple_token('$1'), extract_simple_token('$3')).
parameter -> keyword '=' num : cast_parameter(extract_simple_token('$1'), extract_simple_token('$3')).
parameter -> keyword : cast_parameter(extract_simple_token('$1'), true).

Erlang code.

extract_simple_token({_Token, _Location, Value}) ->
    Value.

cast_component(<<"@method">>, []) -> method;
cast_component(<<"@target-uri">>, []) -> target_uri;
cast_component(<<"@authority">>, []) -> authority;
cast_component(<<"@scheme">>, []) -> scheme;
cast_component(<<"@request-target">>, []) -> request_target;
cast_component(<<"@path">>, []) -> path;
cast_component(<<"@query">>, []) -> query;
cast_component(<<"@query-param">>, [{<<"name">>, Name}]) -> {query_param, Name};
cast_component(<<"@status">>, []) -> status;
cast_component(<<"@request-response">>, []) -> request_response;
cast_component(Header, []) -> Header.

cast_parameter(<<"created">>, Value) when is_integer(Value) -> {created, cast_datetime(Value)};
cast_parameter(<<"expires">>, Value) when is_integer(Value) -> {expires, cast_datetime(Value)};
cast_parameter(Key, Value) when
    Key =:= <<"nonce">>;
    Key =:= <<"alg">>;
    Key =:= <<"keyid">>;
    Key =:= <<"tag">>
->
    {binary_to_existing_atom(Key), Value};
cast_parameter(Key, Value) ->
    {Key, Value}.

-spec cast_datetime(Value) -> Out when
    Value :: integer(),
    Out :: calendar:datetime().
cast_datetime(Value) ->
    calendar:gregorian_seconds_to_datetime(
        Value + calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
    ).
