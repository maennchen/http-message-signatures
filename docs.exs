[
  extras: ["README.md", "LICENSE"],
  main: "readme",
  source_url: "https://github.com/erlef/http-message-signatures",
  filter_modules: fn
    :http_message_signatures_input_lexer, _metdata -> false
    :http_message_signatures_signature_lexer, _metdata -> false
    _module, _metadata -> true
  end
]
