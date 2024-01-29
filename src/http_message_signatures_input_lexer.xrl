%% @private

Definitions.

KEYWORD = [a-zA-Z0-9]+
STRING = \"([^"\\]|\\.)*\"
NUM = [0-9]+
WS = [\s\t]

Rules.

\(        : {token, {'(', TokenLoc}}.
\)        : {token, {')', TokenLoc}}.
\=        : {token, {'=', TokenLoc}}.
\;        : {token, {';', TokenLoc}}.
{STRING}  : {token, {string, TokenLoc, list_to_binary(remove_quotes(TokenChars))}}.
{NUM}     : {token, {num, TokenLoc, list_to_integer(TokenChars)}}.
{KEYWORD} : {token, {keyword, TokenLoc, list_to_binary(TokenChars)}}.
{WS}      : skip_token.

Erlang code.

remove_quotes(String) ->
    lists:sublist(String, 2, length(String) - 2).
