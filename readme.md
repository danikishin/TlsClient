# TlsClient

TlsClient is a simple yet extensible TLS (Transport Layer Security) client library written in C#. It allows you to establish TLS connections with various configurations, including custom JA3 fingerprints, cipher suites, and application protocols.

## Features

- Custom HTTP client: The [`CustomHttpClient`](command:_github.copilot.openSymbolInFile?%5B%22CustomHttpClient.cs%22%2C%22CustomHttpClient%22%5D "CustomHttpClient.cs") class provides a custom implementation of an HTTP client. It includes methods for sending HTTP requests and handling responses.
- Support for custom JA3 fingerprints
- Configurable cipher suites
- Configurable application protocols (e.g., HTTP/1.1)
- Custom server certificate validation callback

## Examples
#### These passes Cloudflare's TLS check
##### Example 1 (using TlsClient)
```csharp
using var tlsClient = new TlsClient.TlsClient("example.com", 443, ja3Fingerprint);
string request = "GET / HTTP/1.1\r\n" +
                     "Host: example.com\r\n" +
                     "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n" +
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,#1#*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n" +
                     "Accept-Language: en-US,en;q=0.9\r\n" +
                     "Connection: close\r\n\r\n";

string response = await tlsClient.SendRequestAsync(request, TimeSpan.FromSeconds(30));
```
##### Example 2 (using CustomHttpClient)
```csharp
    var ja3FingerprintString =
        "769,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-41-28-19,29-23-24,0";
    var ja3Fingerprint = CipherSuiteConverter.JA3FingerprintParser.Parse(ja3FingerprintString);

    var test1 = new CustomHttpClient("example.com", 443, ja3Fingerprint);
    var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
    req.Headers.ConnectionClose = true;
    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
    req.Headers.AcceptLanguage.Add(new StringWithQualityHeaderValue("en-US"));
    req.Headers.Add("User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3");
    var res = await test1.SendAsync(req, TimeSpan.FromSeconds(30));
    Console.WriteLine(res.StatusCode);
    Console.WriteLine(res.Content.Headers.ContentLength);
    Console.WriteLine(res.Headers.ToString());
```

### Prerequisites

- .NET 8.0 SDK

### What's Missing?

While TlsClient provides a solid foundation for establishing TLS connections, there are a few notable missing features:
- !!! It's too much broken to be used in production.
- It's not a full-fledged HTTP client: TlsClient is primarily focused on establishing TLS connections and sending raw HTTP requests. It does not provide high-level features like automatic redirection, cookie management, or response parsing.
- HTTP/2 Support: The current implementation only supports HTTP/1.1 as the application protocol. Adding support for HTTP/2 would be a valuable addition.
- Automatic Certificate Management: The library currently requires manual management of client certificates. Implementing automatic certificate retrieval and renewal would enhance usability.
- Connection Pooling: Connection pooling can improve performance by reusing existing connections for subsequent requests.
- Proxy Support: Adding support for proxy servers would increase flexibility in various network scenarios.
- Comprehensive Logging and Error Handling: Enhancing logging and error handling capabilities would aid in debugging and troubleshooting.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
## License

This project is licensed under the terms of the MIT license.