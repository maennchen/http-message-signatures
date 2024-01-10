Header "%% @private".

Terminals ':' signature_chars.
Nonterminals signature.
Rootsymbol signature.

signature -> ':' signature_chars ':' : extract_simple_token('$2').

Erlang code.

extract_simple_token({_Token, _Location, Value}) ->
    Value.