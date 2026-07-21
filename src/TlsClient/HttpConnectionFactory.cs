using SharpTls;

namespace TlsClient;

internal static class HttpConnectionFactory
{
    public static async ValueTask<IHttpConnection> ConnectAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        DnsEndpointResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        var transport = await SharpTlsTransport.ConnectAsync(
            origin,
            versionPolicy,
            proxy,
            configuration,
            tls13SessionCache,
            tls12SessionCache,
            dnsResolver,
            cancellationToken).ConfigureAwait(false);
        if (transport.ApplicationProtocol == "h2")
        {
            return await Http2Connection.CreateAsync(
                transport,
                configuration,
                cancellationToken).ConfigureAwait(false);
        }
        return new Http11Connection(transport);
    }
}
