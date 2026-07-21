# Streaming transfers

`TlsSession.SendStreamingAsync` streams an `HttpRequestMessage` content body to the
network and writes the final response body to a caller-provided destination. It uses the
managed HTTP/1.1 or HTTP/2 stack selected by the session; it does not switch to
`HttpClient`, `SslStream`, or a native transport.

For GET downloads, use the shorter overload:

```csharp
await using var destination = File.Create("release.zip");

TlsResponse response = await session.DownloadAsync(
    "https://example.com/release.zip",
    destination,
    new TlsStreamingOptions { BufferSize = 128 * 1024 },
    cancellationToken);

response.EnsureSuccessStatusCode();
```

The buffer may be 4 KiB through 1 MiB and defaults to 64 KiB. It bounds individual
request reads, HTTP/1.1 response copies, and decoded response writes. The session's
`MaximumRequestBodyBytes` and `MaximumResponseBodyBytes` still cap total encoded and
decoded data.

## Streaming an upload

Use `StreamContent` to make stream ownership and the source explicit:

```csharp
await using var source = File.OpenRead("video.mp4");
using var content = new StreamContent(source);
content.Headers.ContentType = new("video/mp4");
content.Headers.ContentLength = source.Length;

using var request = new HttpRequestMessage(
    HttpMethod.Post,
    "https://example.com/videos")
{
    Content = content,
};
await using var responseBody = new MemoryStream();

TlsResponse response = await session.SendStreamingAsync(
    request,
    responseBody,
    cancellationToken: cancellationToken);
```

When `Content-Length` is known, TlsClient verifies that the source produces exactly that
many bytes. An HTTP/1.1 upload without a known length uses chunked transfer coding. HTTP/2
does not need chunked coding and sends bounded DATA frames governed by both connection
and stream flow-control windows.

TlsClient does not close the request source, response destination, `HttpContent`, or
`HttpRequestMessage`. Their lifetime remains the caller's responsibility. Disposing a
request normally disposes its content, and `StreamContent` normally disposes its source,
so keep the request alive until the operation completes.

## Responses and decompression

gzip, zlib-wrapped deflate, and Brotli bodies are decoded incrementally when session
automatic decompression is enabled. Set `TlsStreamingOptions.AutomaticDecompression` to
override that behavior for one transfer. Unsupported content encodings are written as
wire bytes and do not set `WasDecompressed`.

The returned `TlsResponse` contains status, headers, trailers, redirect history, and TLS
metadata. `BodyWasStreamed` is true and `Body` is empty because the bytes live in the
supplied destination. `Text` and `Json<T>()` throw in this mode instead of silently
interpreting an empty buffer.

## Backpressure and cancellation

HTTP/1.1 reads the next bounded chunk only after the destination accepts the current
chunk. HTTP/2 queues DATA per stream within the peer-visible receive-window budget and
returns WINDOW_UPDATE credit only after that stream's destination accepts the bytes.
This preserves multiplexing: one slow destination does not stop other response streams
on the same connection.

Cancellation reaches source reads, destination writes, flow-control waits, DNS, TCP,
proxy setup, and SharpTls. Cancelling one HTTP/2 transfer sends RST_STREAM without
closing unrelated streams. The session timeout covers all redirect hops and both sides
of the transfer.

## Redirect and replay rules

When redirects are enabled, redirect response bodies are drained without being written
to the final destination. Only the final response body reaches the caller's stream.
Cookies and redirect history work the same way as buffered requests.

A streamed request body is non-replayable by default. Redirects that switch to GET may
proceed after dropping it, but a 307/308 or another redirect that must re-send the body
throws `HttpRequestException`. Opt in explicitly when bounded buffering is acceptable:

```csharp
TlsRequestOptions.For(request).ReplayPolicy = TlsRequestReplayPolicy.Buffer;
```

`Buffer` consumes the upload before connecting and enforces `MaximumRequestBodyBytes`.
Session retry policy may then replay it. A streamed response is retried only before its
destination receives bytes; retry-status bodies are drained separately.

## Continue and request trailers

Set `request.Headers.ExpectContinue = true` to send request headers first. HTTP/1.1 and
HTTP/2 wait up to `TlsSessionOptions.Expect100ContinueTimeout` for `100 Continue`. A final
response such as 417 prevents the upload source from being read. When the timeout expires,
the body is sent so a silent server cannot stall the request indefinitely.

Request trailers are per-request fields:

```csharp
TlsRequestOptions.For(request).Trailers.Set("X-Checksum", checksum);
```

HTTP/1.1 switches the request to chunked transfer coding and writes the fields after the
zero-size chunk. HTTP/2 sends a final trailing HEADERS block. Framing, routing,
authentication, and cookie fields are rejected as trailers. Response trailers are
available through `TlsResponse.Trailers` in buffered and streaming modes.
