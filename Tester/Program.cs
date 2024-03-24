using System.Net;
using System.Net.Http.Headers;
using TlsClient;

async Task MakeRequest()
{
    var ja3FingerprintString =
        "769,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-41-28-19,29-23-24,0";
    var ja3Fingerprint = CipherSuiteConverter.JA3FingerprintParser.Parse(ja3FingerprintString);

    var test1 = new CustomHttpClient("example.com", 443, ja3Fingerprint);
    var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
    req.Headers.ConnectionClose = true; //without this, the server will keep the connection open tls-client doesn't support keep-alive yet
    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
    req.Headers.AcceptLanguage.Add(new StringWithQualityHeaderValue("en-US"));
    req.Headers.Add("User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3");
    var res = await test1.SendAsync(req, TimeSpan.FromSeconds(30));
    Console.WriteLine(res.StatusCode);
    Console.WriteLine(res.Content.Headers.ContentLength);
    Console.WriteLine(res.Headers.ToString());


    /*
    using var tlsClient = new TlsClient.TlsClient("example.com", 443, ja3Fingerprint);
    string request = "GET / HTTP/1.1\r\n" +
                     "Host: example.com\r\n" +
                     "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n" +
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,#1#*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n" +
                     "Accept-Language: en-US,en;q=0.9\r\n" +
                     "Connection: close\r\n\r\n";

    string response = await tlsClient.SendRequestAsync(request, TimeSpan.FromSeconds(30));
    HttpResponseMessage message = ParseRawResponse(response);

    Console.WriteLine($"Status Code: {message.StatusCode}");
    Console.WriteLine($"Content Length: {message.Content.Headers.ContentLength}");*/
}

HttpResponseMessage ParseRawResponse(string rawResponse)
{
    // Split the raw response into headers and content
    var parts = rawResponse.Split(new[] { "\r\n\r\n" }, 2, StringSplitOptions.None);
    var headers = parts[0];
    var content = parts.Length > 1 ? parts[1] : string.Empty;

    // Parse the status line and headers
    var statusLineParts = headers.Split('\r', 1, StringSplitOptions.RemoveEmptyEntries);
    var statusLine = statusLineParts[0];
    var statusParts = statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var statusCode = (HttpStatusCode)int.Parse(statusParts[1]);

    var startIndex = statusLine.Length + 2;
    if (startIndex <= headers.Length)
        headers = headers.Substring(startIndex);
    else
        headers = string.Empty;

    // Create the HttpResponseMessage instance
    var response = new HttpResponseMessage(statusCode);
    response.Content = new StringContent(content);
    response.RequestMessage = new HttpRequestMessage(); // Required for headers to be set properly

    // Parse and set the headers
    using (var reader = new StringReader(headers))
    {
        string line;
        while ((line = reader.ReadLine()) != null)
        {
            var separatorIndex = line.IndexOf(':');
            if (separatorIndex > 0)
            {
                var name = line.Substring(0, separatorIndex);
                var value = line.Substring(separatorIndex + 1).Trim();
                response.Headers.TryAddWithoutValidation(name, value);
                response.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }
    }

    return response;
}

await MakeRequest();