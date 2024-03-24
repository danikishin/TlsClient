using System.Net;

namespace TlsClient;

public class CustomHttpClient : IDisposable
{
    private readonly TlsClient _tlsClient;

    public CustomHttpClient(string host, int port = 443, JA3Fingerprint ja3Fingerprint = null)
    {
        _tlsClient = new TlsClient(host, port, ja3Fingerprint);
    }

    public void Dispose()
    {
        _tlsClient?.Dispose();
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, TimeSpan timeout)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        // Convert the HttpRequestMessage to a raw HTTP request string.
        var requestString = ConvertHttpRequestMessageToString(request);

        // Use the TlsClient to send the raw request string.
        var responseString = await _tlsClient.SendRequestAsync(requestString, timeout);

        // Convert the raw HTTP response string back into an HttpResponseMessage.
        var response = ConvertStringToHttpResponseMessage(responseString);

        return response;
    }

    private string ConvertHttpRequestMessageToString(HttpRequestMessage request)
    {
        using (var sw = new StringWriter())
        {
            sw.WriteLine($"{request.Method} {request.RequestUri.PathAndQuery} HTTP/1.1");
            sw.WriteLine($"Host: {request.RequestUri.Host}");

            foreach (var header in request.Headers) sw.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");

            if (request.Content != null)
                foreach (var header in request.Content.Headers)
                    sw.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");

            sw.WriteLine();

            if (request.Content != null) sw.WriteLine(request.Content.ReadAsStringAsync().Result);

            return sw.ToString();
        }
    }

    private HttpResponseMessage ConvertStringToHttpResponseMessage(string response)
    {
        var httpResponse = new HttpResponseMessage();

        using (var sr = new StringReader(response))
        {
            // Parse status line
            var statusLine = sr.ReadLine();
            if (statusLine != null)
            {
                var statusLineParts = statusLine.Split(' ');
                if (statusLineParts.Length >= 3)
                    httpResponse.StatusCode = (HttpStatusCode)Enum.Parse(typeof(HttpStatusCode), statusLineParts[1]);
            }

            // Parse headers
            string line;
            while ((line = sr.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    break; // Headers end

                var headerParts = line.Split(new[] { ':' }, 2);
                if (headerParts.Length == 2)
                    httpResponse.Headers.TryAddWithoutValidation(headerParts[0].Trim(), headerParts[1].Trim());
            }

            // Parse body
            httpResponse.Content = new StringContent(sr.ReadToEnd());
        }

        return httpResponse;
    }
}