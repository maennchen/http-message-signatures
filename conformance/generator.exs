#!/usr/bin/env elixir

import ExUnit.CaptureIO

capture_io(fn ->
  Mix.install([
    {:http_message_signatures, path: __ENV__.file |> Path.dirname() |> Path.dirname()},
    {:erlhttp, github: "mme/erlhttp"}
  ])
end)

help_text = """
Usage: #{Path.relative_to_cwd(__ENV__.file)} <command> [options]

Options:
  -V, --version                    output the version number
  -d, --headers <headers>          A list of header names, optionally quoted
  -k, --keyId <keyId>              A Key Id string.
  -p, --private-key <privateKey>   A private key file name filename.
  -t, --key-type <keyType>         The type of the keys.
  -u, --public-key <publicKey>     A public key file name filename.
  -a, --algorithm <algorithm>      One of: rsa-sha1, hmac-sha1, rsa-sha256, hmac-sha256, hs2019.
  -c, --created <created>          The created param for the signature.
  -e, --expires <expires>          The expires param for the signature.
  -h, --help                       output usage information

Modes:
  canonicalize
  sign
  verify
"""

{options, commands} =
  OptionParser.parse!(System.argv(),
    strict: [
      version: :boolean,
      headers: [:string, :keep],
      keyId: :string,
      private_key: :string,
      key_type: :string,
      public_key: :string,
      algorithm: :string,
      created: :integer,
      expires: :integer,
      help: :boolean
    ],
    aliases: [
      V: :version,
      d: :headers,
      k: :keyId,
      p: :private_key,
      t: :key_type,
      u: :public_key,
      a: :algorithm,
      c: :created,
      e: :expires,
      h: :help
    ]
  )

offset_1970 = :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

options =
  options
  |> Keyword.update(
    :created,
    :calendar.local_time(),
    &:calendar.gregorian_seconds_to_datetime(&1 + offset_1970)
  )
  |> Keyword.update(
    :expires,
    :calendar.local_time(),
    &:calendar.gregorian_seconds_to_datetime(&1 + offset_1970)
  )

parse_stdin = fn ->
  {:ok, parser} = :erlhttp.new()

  parser =
    Enum.reduce(IO.stream(), parser, fn line, parser ->
      {:ok, _rest, parser} = :erlhttp.update(line, parser)
      parser
    end)

  case :erlhttp.parse(parser) do
    {:request, options, {_ref, :headers, :undefined, fields, []}} ->
      %{
        method: options[:method],
        url: options[:url],
        body: fields[:body],
        headers:
          Enum.reduce(fields, {nil, []}, fn
            {:header_field, header}, {_, acc_headers} ->
              {header, acc_headers}

            {:header_value, value}, {header, acc_headers} ->
              {nil, acc_headers ++ [{header, value}]}

            {:body, _body}, acc ->
              acc

            :done, {nil, acc_headers} ->
              acc_headers
          end)
      }
  end
end

cond do
  options[:help] ->
    Mix.Shell.IO.info(help_text)
    System.halt(0)

  options[:version] ->
    :http_message_signatures
    |> Application.spec(:vsn)
    |> List.to_string()
    |> Mix.Shell.IO.info()

    System.halt(0)

  commands == ["canonicalize"] ->
    message = parse_stdin.()

    requested_headers =
      options
      |> Keyword.put_new(:headers, "(created)")
      |> Keyword.get_values(:headers)
      |> Enum.join(" ")
      |> String.split(" ", trim: true)

    message
    |> :http_message_signatures.canonicalize_headers(
      requested_headers,
      options |> Keyword.take([:created, :expires]) |> Map.new()
    )
    |> case do
      {:ok, canonicalized_headers} ->
        canonicalized_headers
        |> Enum.map(fn {header, value} -> [header, ": ", value] end)
        |> Enum.intersperse("\n")
        |> Enum.into(IO.stream())

      {:error, reason} ->
        Mix.Shell.IO.error(inspect(reason))
        System.halt(1)
    end

  # headers =
  #   options |> Keyword.get_values(:headers) |> Enum.join(" ") |> String.split(" ", trim: true)

  # :http_message_signatures.sign(message, %{
  #   components: headers,
  #   signer: fn data ->
  #     send(self(), {:data, data})
  #     "hash"
  #   end
  # })

  # receive do
  #   {:data, data} -> IO.write(data)
  # after
  #   0 ->
  #     Mix.Shell.IO.error("No data received")
  #     System.halt(1)
  # end

  commands == ["verify"] ->
    message = parse_stdin.()

    :http_message_signatures.verify(message, %{
      verifier: fn _data, _signature, _params ->
        :ok
      end
    })

  true ->
    Mix.Shell.IO.info(help_text)
    System.halt(1)
end
