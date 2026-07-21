using System.Buffers;
using System.Text;

namespace TlsClient;

internal static class Http11RequestWriter
{
    private static readonly SearchValues<char> InvalidMethodCharacters = SearchValues.Create(
        "()<>@,;:\\\"/[]?={} \t\r\n");

    public static byte[] SerializeHeaders(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string[] preferredOrder,
        string? cookieHeader)
    {
        var headers = MergeHeaders(request, sessionHeaders, cookieHeader);
        if (!Contains(headers, "Connection"))
        {
            headers.Add(new HeaderEntry("Connection", ["keep-alive"]));
        }

        headers = Order(headers, preferredOrder);
        var target = request.Url.GetComponents(
            UriComponents.PathAndQuery,
            UriFormat.UriEscaped);
        if (target.Length == 0)
        {
            target = "/";
        }

        var builder = new StringBuilder(512);
        builder.Append(request.Method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
        foreach (var header in headers)
        {
            ValidateHeaderName(header.Name);
            foreach (var value in header.Values)
            {
                ValidateHeaderValue(value);
                builder.Append(header.Name).Append(": ").Append(value).Append("\r\n");
            }
        }
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    internal static List<HeaderEntry> MergeHeaders(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader)
    {
        var headers = sessionHeaders
            .Where(entry => !request.SuppressSensitiveSessionHeaders ||
                !IsOriginBoundHeader(entry.Name))
            .Select(entry => new HeaderEntry(entry.Name, (string[])entry.Values.Clone()))
            .ToList();
        foreach (var header in request.Headers)
        {
            BufferedRequest.AddOrReplace(headers, header);
        }

        Remove(headers, "Content-Length");
        Remove(headers, "Transfer-Encoding");
        Remove(headers, "Proxy-Authorization");

        if (!Contains(headers, "Host"))
        {
            headers.Insert(0, new HeaderEntry("Host", [FormatAuthority(request.Url)]));
        }
        if (!Contains(headers, "Cookie") && !string.IsNullOrEmpty(cookieHeader))
        {
            headers.Add(new HeaderEntry("Cookie", [cookieHeader]));
        }
        if (request.HasPayload)
        {
            if (!request.HasTrailers && request.ContentLength is { } contentLength)
            {
                headers.Add(new HeaderEntry(
                    "Content-Length",
                    [contentLength.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
            }
            else
            {
                headers.Add(new HeaderEntry("Transfer-Encoding", ["chunked"]));
            }
            if (request.HasTrailers)
            {
                Remove(headers, "Trailer");
                headers.Add(new HeaderEntry(
                    "Trailer",
                    [string.Join(", ", request.Trailers.Select(trailer => trailer.Name))]));
            }
        }
        return headers;
    }

    internal static bool Has100Continue(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader)
    {
        var headers = MergeHeaders(request, sessionHeaders, cookieHeader);
        return headers
            .Where(header => header.Name.Equals("Expect", StringComparison.OrdinalIgnoreCase))
            .SelectMany(header => header.Values)
            .SelectMany(value => value.Split(','))
            .Any(value => value.Trim().Equals("100-continue", StringComparison.OrdinalIgnoreCase));
    }

    internal static byte[] SerializeTrailers(BufferedRequest request)
    {
        if (!request.HasTrailers)
        {
            return [];
        }
        var builder = new StringBuilder();
        builder.Append("0\r\n");
        foreach (var trailer in request.Trailers)
        {
            ValidateHeaderName(trailer.Name);
            foreach (var value in trailer.Values)
            {
                ValidateHeaderValue(value);
                builder.Append(trailer.Name).Append(": ").Append(value).Append("\r\n");
            }
        }
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    public static void ValidateMethod(string method)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        if (!method.All(character => character is > '\u001f' and < '\u007f') ||
            method.AsSpan().IndexOfAny(InvalidMethodCharacters) >= 0)
        {
            throw new ArgumentException("The HTTP method is not a valid token.", nameof(method));
        }
    }

    internal static string FormatAuthority(Uri uri)
    {
        var host = uri.HostNameType == UriHostNameType.IPv6 ? $"[{uri.IdnHost}]" : uri.IdnHost;
        return uri.IsDefaultPort ? host : $"{host}:{uri.Port}";
    }

    internal static List<HeaderEntry> Order(List<HeaderEntry> headers, string[] preferredOrder)
    {
        if (preferredOrder.Length == 0)
        {
            return headers;
        }

        var ordered = new List<HeaderEntry>(headers.Count);
        foreach (var name in preferredOrder)
        {
            var index = headers.FindIndex(header =>
                string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                continue;
            }
            ordered.Add(headers[index]);
            headers.RemoveAt(index);
        }
        ordered.AddRange(headers);
        return ordered;
    }

    internal static bool Contains(List<HeaderEntry> headers, string name) => headers.Any(
        header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));

    internal static void Remove(List<HeaderEntry> headers, string name) => headers.RemoveAll(
        header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));

    private static bool IsOriginBoundHeader(string name) =>
        name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Host", StringComparison.OrdinalIgnoreCase);

    internal static void ValidateHeaderName(string name)
    {
        var headers = new TlsHeaders();
        headers.Set(name, string.Empty);
    }

    internal static void ValidateHeaderValue(string value)
    {
        if (value.Any(character => character > '\u00ff' ||
            (character < '\u0020' && character != '\t') || character == '\u007f'))
        {
            throw new ArgumentException(
                "HTTP/1.1 header values must contain only Latin-1 text without control characters.",
                nameof(value));
        }
    }
}
