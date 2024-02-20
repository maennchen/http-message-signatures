# HTTP Message Signatures

Implements [HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/maennchen/http-message-signatures/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/maennchen/http-message-signatures/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/http_message_signatures.svg)](https://hex.pm/packages/http_message_signatures)
[![Total Download](https://img.shields.io/hexpm/dt/http_message_signatures.svg)](https://hex.pm/packages/http_message_signatures)
[![License](https://img.shields.io/hexpm/l/http_message_signatures.svg)](https://github.com/maennchen/http-message-signatures/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/maennchen/http-message-signatures.svg)](https://github.com/maennchen/http-message-signatures/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/maennchen/http-message-signatures/badge.svg?branch=main)](https://coveralls.io/github/maennchen/http-message-signatures?branch=main)

## Usage

### Sign Request / Response

```erlang
Request = #{
  method => get,
  url => <<"https://example.com/path?queryString">>,
  headers => [{"content-type", "text/plain"}]
},

SignedRequest = http_message_signatures:sign(
  Request,
  #{
    components => [method, path, <<"content-type">>],
    key => <<"sig1">>,
    signer => fun(Data) ->
      execute_signature(Data)
    end
  }
).
```

### Verify Request / Response

```erlang
SignedRequest = #{
  %% Get the signed request from somewhere
},

{ok, #{<<"sig1">> := Parameters} = http_message_signatures:verify(
  SignedRequest,
  #{
    verifier => fun(Data, Signature, SignatureParameters) ->
      case execute_signature_verification(Data) of
        true -> ok;
        false -> {error, invalid_signature}
      end
    end
  }
).
```