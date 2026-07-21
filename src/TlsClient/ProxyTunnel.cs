using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace TlsClient;

internal static class ProxyTunnel
{
    public static ValueTask EstablishAsync(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        int maximumHeaderBytes,
        CancellationToken cancellationToken) => proxy.Type switch
        {
            TlsProxyType.Http => EstablishHttpAsync(
                transport,
                origin,
                proxy,
                maximumHeaderBytes,
                cancellationToken),
            TlsProxyType.Socks4 => EstablishSocks4Async(
                transport,
                origin,
                proxy,
                cancellationToken),
            TlsProxyType.Socks5 => EstablishSocks5Async(
                transport,
                origin,
                proxy,
                cancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(proxy)),
        };

    private static async ValueTask EstablishHttpAsync(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        int maximumHeaderBytes,
        CancellationToken cancellationToken)
    {
        var authority = Http11RequestWriter.FormatAuthority(origin);
        var request = new StringBuilder()
            .Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n")
            .Append("Host: ").Append(authority).Append("\r\n")
            .Append("Proxy-Connection: keep-alive\r\n");
        var authorization = proxy.GetBasicAuthorizationValue();
        if (authorization is not null)
        {
            request.Append("Proxy-Authorization: ").Append(authorization).Append("\r\n");
        }
        request.Append("\r\n");

        await transport.WriteAsync(
            Encoding.Latin1.GetBytes(request.ToString()),
            cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);

        var reader = new BufferedHttpReader(transport);
        var status = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
            .ConfigureAwait(false) ?? throw new HttpRequestException(
                "The proxy closed before returning a CONNECT response.");
        var (_, statusCode, reason) = Http11ResponseReader.ParseStatusLine(status.Text);
        var consumed = status.WireLength;
        while (true)
        {
            var line = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new HttpRequestException(
                "The proxy closed in the middle of its CONNECT response.");
            consumed = checked(consumed + line.WireLength);
            if (consumed > maximumHeaderBytes)
            {
                throw new HttpRequestException("The proxy CONNECT response headers were too large.");
            }
            if (line.Text.Length == 0)
            {
                break;
            }
        }
        if (statusCode != 200)
        {
            throw new HttpRequestException(
                $"The proxy rejected CONNECT with HTTP {statusCode} {reason}.");
        }
    }

    private static async ValueTask EstablishSocks4Async(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        CancellationToken cancellationToken)
    {
        var user = Encoding.UTF8.GetBytes(proxy.GetCredentials()?.UserName ?? string.Empty);
        if (user.Length > 255)
        {
            throw new HttpRequestException("The SOCKS4 user ID exceeds 255 bytes.");
        }
        var host = origin.IdnHost;
        var isIpv4 = IPAddress.TryParse(host, out var address) &&
            address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        if (address?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            throw new HttpRequestException("SOCKS4 cannot connect to an IPv6 literal.");
        }
        var hostBytes = isIpv4 ? [] : Encoding.ASCII.GetBytes(host);
        if (hostBytes.Length > 255)
        {
            throw new HttpRequestException("The SOCKS4a destination hostname is too long.");
        }
        var request = new byte[9 + user.Length + (isIpv4 ? 0 : hostBytes.Length + 1)];
        request[0] = 4;
        request[1] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2, 2), checked((ushort)origin.Port));
        if (isIpv4)
        {
            address!.GetAddressBytes().CopyTo(request, 4);
        }
        else
        {
            request[7] = 1;
        }
        user.CopyTo(request, 8);
        if (!isIpv4)
        {
            hostBytes.CopyTo(request, 9 + user.Length);
        }
        await transport.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = new byte[8];
        await ReadExactlyAsync(transport, response, cancellationToken).ConfigureAwait(false);
        if (response[0] is not 0 and not 4 || response[1] != 0x5a)
        {
            throw new HttpRequestException(
                $"The SOCKS4 proxy rejected CONNECT with status 0x{response[1]:x2}.");
        }
    }

    private static async ValueTask EstablishSocks5Async(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        CancellationToken cancellationToken)
    {
        var credentials = proxy.GetCredentials();
        var greeting = credentials is null
            ? new byte[] { 5, 1, 0 }
            : new byte[] { 5, 2, 0, 2 };
        await transport.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var method = new byte[2];
        await ReadExactlyAsync(transport, method, cancellationToken).ConfigureAwait(false);
        if (method[0] != 5 || method[1] == 0xff)
        {
            throw new HttpRequestException("The SOCKS5 proxy did not accept an authentication method.");
        }
        if (method[1] == 2)
        {
            if (credentials is null)
            {
                throw new HttpRequestException(
                    "The SOCKS5 proxy requires username/password authentication.");
            }
            await AuthenticateSocks5Async(
                transport,
                credentials,
                cancellationToken).ConfigureAwait(false);
        }
        else if (method[1] != 0)
        {
            throw new HttpRequestException(
                $"The SOCKS5 proxy selected unsupported method 0x{method[1]:x2}.");
        }

        var destination = CreateSocks5Destination(origin);
        await transport.WriteAsync(destination, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = new byte[4];
        await ReadExactlyAsync(transport, response, cancellationToken).ConfigureAwait(false);
        if (response[0] != 5 || response[2] != 0)
        {
            throw new HttpRequestException("The SOCKS5 proxy returned a malformed CONNECT response.");
        }
        if (response[1] != 0)
        {
            throw new HttpRequestException(
                $"The SOCKS5 proxy rejected CONNECT with status 0x{response[1]:x2}.");
        }
        var addressLength = response[3] switch
        {
            1 => 4,
            4 => 16,
            3 => await ReadByteAsync(transport, cancellationToken).ConfigureAwait(false),
            _ => throw new HttpRequestException(
                "The SOCKS5 proxy returned an unknown address type."),
        };
        if (response[3] == 3 && addressLength == 0)
        {
            throw new HttpRequestException(
                "The SOCKS5 proxy returned an empty domain address.");
        }
        var remainder = new byte[checked(addressLength + 2)];
        await ReadExactlyAsync(transport, remainder, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask AuthenticateSocks5Async(
        Stream transport,
        NetworkCredential credentials,
        CancellationToken cancellationToken)
    {
        var username = Encoding.UTF8.GetBytes(credentials.UserName);
        var password = Encoding.UTF8.GetBytes(credentials.Password);
        if (username.Length is < 1 or > 255 || password.Length is < 1 or > 255)
        {
            throw new HttpRequestException(
                "SOCKS5 usernames and passwords must each encode to 1–255 bytes.");
        }
        var request = new byte[checked(username.Length + password.Length + 3)];
        request[0] = 1;
        request[1] = (byte)username.Length;
        username.CopyTo(request, 2);
        request[username.Length + 2] = (byte)password.Length;
        password.CopyTo(request, username.Length + 3);
        await transport.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = new byte[2];
        await ReadExactlyAsync(transport, response, cancellationToken).ConfigureAwait(false);
        if (response[0] != 1 || response[1] != 0)
        {
            throw new HttpRequestException(
                "The SOCKS5 proxy rejected username/password authentication.");
        }
    }

    private static byte[] CreateSocks5Destination(Uri origin)
    {
        var host = origin.IdnHost;
        byte addressType;
        byte[] addressBytes;
        if (IPAddress.TryParse(host, out var address))
        {
            addressType = address.AddressFamily ==
                System.Net.Sockets.AddressFamily.InterNetwork ? (byte)1 : (byte)4;
            addressBytes = address.GetAddressBytes();
        }
        else
        {
            addressType = 3;
            var hostBytes = Encoding.ASCII.GetBytes(host);
            if (hostBytes.Length is < 1 or > 255)
            {
                throw new HttpRequestException(
                    "The SOCKS5 destination hostname must encode to 1–255 bytes.");
            }
            addressBytes = new byte[hostBytes.Length + 1];
            addressBytes[0] = (byte)hostBytes.Length;
            hostBytes.CopyTo(addressBytes, 1);
        }
        var request = new byte[checked(addressBytes.Length + 6)];
        request[0] = 5;
        request[1] = 1;
        request[2] = 0;
        request[3] = addressType;
        addressBytes.CopyTo(request, 4);
        BinaryPrimitives.WriteUInt16BigEndian(
            request.AsSpan(request.Length - 2),
            checked((ushort)origin.Port));
        return request;
    }

    private static async ValueTask<int> ReadByteAsync(
        Stream transport,
        CancellationToken cancellationToken)
    {
        var value = new byte[1];
        await ReadExactlyAsync(transport, value, cancellationToken).ConfigureAwait(false);
        return value[0];
    }

    private static async ValueTask ReadExactlyAsync(
        Stream transport,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await transport.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new HttpRequestException("The proxy closed during tunnel negotiation.");
            }
            offset += read;
        }
    }
}
