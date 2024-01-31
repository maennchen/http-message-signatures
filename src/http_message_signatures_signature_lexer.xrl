%% @private

Definitions.

SIGNATURE = [A-Za-z0-9\/\+=\-_\.]+
DELIMITER = :

Rules.

{DELIMITER} : {token, {':', TokenLoc, TokenChars}}.
{SIGNATURE} : {token, {signature_chars, TokenLoc, list_to_binary(TokenChars)}}.

Erlang code.
