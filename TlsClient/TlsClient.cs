using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsClient;

public class TlsClient : IDisposable
{
    private readonly string _host;
    private readonly JA3Fingerprint _ja3Fingerprint;
    private readonly int _port;
    private readonly TcpClient _tcpClient;
    private SslStream _sslStream;

    public TlsClient(string host, int port = 443, JA3Fingerprint ja3Fingerprint = null)
    {
        _host = host;
        _port = port;
        _ja3Fingerprint = ja3Fingerprint ?? JA3Fingerprint.Default;

        _tcpClient = new TcpClient();
    }

    public void Dispose()
    {
        _sslStream?.Dispose();
        _tcpClient?.Dispose();
    }

    public async Task<string> SendRequestAsync(string request, TimeSpan timeout)
    {
        try
        {
            await _tcpClient.ConnectAsync(_host, _port);
            _sslStream = new SslStream(_tcpClient.GetStream(), false, ServerCertificateCustomValidationCallback);
            var clientCertificates = await GetClientCertificatesAsync();
            var cipherSuites = _ja3Fingerprint.GetCipherSuites();
            var applicationProtocols = _ja3Fingerprint.GetApplicationProtocols()
                .Select(p => new SslApplicationProtocol(Encoding.UTF8.GetBytes(p)))
                .ToList();

            var sslClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                ClientCertificates = clientCertificates,
                EnabledSslProtocols = _ja3Fingerprint.GetSslProtocols(),
                //CipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites),
                ApplicationProtocols = applicationProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption
            };

            using var cts = new CancellationTokenSource(timeout);
            await _sslStream.AuthenticateAsClientAsync(sslClientAuthenticationOptions, cts.Token);

            var requestBytes = Encoding.UTF8.GetBytes(request);
            await _sslStream.WriteAsync(requestBytes, 0, requestBytes.Length);

            using var memoryStream = new MemoryStream();
            await _sslStream.CopyToAsync(memoryStream);
            var response = Encoding.UTF8.GetString(memoryStream.ToArray());

            return response;
        }
        catch (Exception ex)
        {
            // Handle exceptions and log errors

            Console.WriteLine($"Error: {ex.Message}");
            throw;
        }
    }

    private async Task<X509CertificateCollection> GetClientCertificatesAsync()
    {
        // Implement logic to retrieve client certificates based on the JA3 fingerprint
        // We can load certificates from a certificate store or a file
        // Return the appropriate X509CertificateCollection
        var certificates = new X509CertificateCollection();
        // TODO: Load client certificates based on the JA3 fingerprint
        return certificates;
    }

    private bool ServerCertificateCustomValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // Implement custom server certificate validation logic here
        // We can check for specific certificate properties, chain validation, etc.
        // Return true to accept the certificate, false to reject it
        // TODO: Implement custom server certificate validation logic
        return true;
    }
}

public class JA3Fingerprint
{
    public static readonly JA3Fingerprint Default = new(
        769,
        new[] { 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53 },
        new[] { 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21, 41, 28, 19 },
        new[] { 29, 23, 24 },
        new[] { 0 }
    );

    public JA3Fingerprint(int sslVersion, int[] cipherSuites, int[] extensions, int[] ellipticCurves,
        int[] ellipticCurvePointFormats)
    {
        SslVersion = sslVersion;
        CipherSuites = cipherSuites;
        Extensions = extensions;
        EllipticCurves = ellipticCurves;
        EllipticCurvePointFormats = ellipticCurvePointFormats;
    }

    public int SslVersion { get; }
    public int[] CipherSuites { get; }
    public int[] Extensions { get; }
    public int[] EllipticCurves { get; }
    public int[] EllipticCurvePointFormats { get; }

    public SslProtocols GetSslProtocols()
    {
        return SslVersion switch
        {
            769 => SslProtocols.Tls12,
            768 => SslProtocols.Tls11,
            767 => SslProtocols.Tls,
            _ => SslProtocols.None
        };
    }

    public TlsCipherSuite[] GetCipherSuites()
    {
        return CipherSuites.Select(CipherSuiteConverter.GetCipherSuite).ToArray();
    }

    public string[] GetApplicationProtocols()
    {
        var applicationProtocols = Extensions
            .Where(extensionType => extensionType == 16)
            .Select(extensionType => "http/1.1")
            .ToArray();
        return applicationProtocols;
    }
}

public static class CipherSuiteConverter
{
    private static readonly Dictionary<int, TlsCipherSuite> _cipherSuiteMap = new()
    {
        { 4865, TlsCipherSuite.TLS_AES_128_GCM_SHA256 },
        { 4866, TlsCipherSuite.TLS_AES_256_GCM_SHA384 },
        { 4867, TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 },
        { 49195, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
        { 49199, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
        { 49196, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
        { 49200, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
        { 52393, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 },
        { 52392, TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
        { 49171, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA },
        { 49172, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA },
        { 156, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 },
        { 157, TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 },
        { 47, TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA },
        { 53, TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA }
    };

    public static TlsCipherSuite GetCipherSuite(int cipherSuiteId)
    {
        if (_cipherSuiteMap.TryGetValue(cipherSuiteId, out var cipherSuite)) return cipherSuite;

        throw new ArgumentException($"Unsupported cipher suite ID: {cipherSuiteId}", nameof(cipherSuiteId));
    }

    public static class JA3FingerprintParser
    {
        public static JA3Fingerprint Parse(string ja3FingerprintString)
        {
            var fields = ja3FingerprintString.Split(',');
            if (fields.Length != 5)
                throw new ArgumentException("Invalid JA3 fingerprint format.", nameof(ja3FingerprintString));

            var sslVersion = int.Parse(fields[0]);
            var cipherSuites = ParseIntArray(fields[1]);
            var extensions = ParseIntArray(fields[2]);
            var ellipticCurves = ParseIntArray(fields[3]);
            var ellipticCurvePointFormats = ParseIntArray(fields[4]);

            return new JA3Fingerprint(sslVersion, cipherSuites, extensions, ellipticCurves, ellipticCurvePointFormats);
        }

        private static int[] ParseIntArray(string field)
        {
            return string.IsNullOrWhiteSpace(field) ? Array.Empty<int>() : field.Split('-').Select(int.Parse).ToArray();
        }
    }
}