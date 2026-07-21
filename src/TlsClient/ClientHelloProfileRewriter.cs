using SharpTls;

namespace TlsClient;

internal static class ClientHelloProfileRewriter
{
    public static ClientHelloProfile WithAlpn(
        ClientHelloProfile profile,
        bool includeSni,
        params string[] protocols)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(protocols);
        var spec = profile.Spec;
        var applicationSettingsProtocols = spec.ApplicationSettingsProtocols
            .Where(protocol => protocols.Contains(protocol, StringComparer.Ordinal))
            .ToArray();
        var layout = spec.Extensions
            .Where(extension => applicationSettingsProtocols.Length != 0 ||
                extension.BuiltInKind != ClientHelloExtensionKind.ApplicationSettings)
            .Where(extension => includeSni ||
                extension.BuiltInKind != ClientHelloExtensionKind.ServerName)
            .ToList();

        if (!layout.Any(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation))
        {
            var insertionIndex = layout.FindIndex(extension => extension.BuiltInKind is
                ClientHelloExtensionKind.Padding or ClientHelloExtensionKind.PreSharedKey);
            if (insertionIndex < 0)
            {
                insertionIndex = layout.Count;
            }

            layout.Insert(
                insertionIndex,
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation));
        }

        return ClientHelloProfiles.Custom(builder =>
        {
            builder.WithCipherSuites(spec.CipherSuites.ToArray());
            if (spec.Extensions.Any(extension =>
                    extension.BuiltInKind == ClientHelloExtensionKind.SupportedVersions))
            {
                builder.WithSupportedVersions(spec.SupportedVersions.ToArray());
            }
            else
            {
                builder.WithLegacyTls12ClientHello();
            }

            if (spec.GreasePolicy is not null)
            {
                builder.WithGrease(spec.GreasePolicy);
            }
            if (spec.SecondaryGreaseExtensionBody is not null)
            {
                builder.WithSecondaryGreaseExtension(spec.SecondaryGreaseExtensionBody);
            }
            if (spec.FixedGreaseKeyShareBody is not null)
            {
                builder.WithGreaseKeyShareBody(spec.FixedGreaseKeyShareBody);
            }

            builder
                .WithSupportedGroups(spec.SupportedGroups.ToArray())
                .WithKeyShares(spec.KeyShareGroups.ToArray())
                .AllowDuplicateSignatureAlgorithms(spec.AllowsDuplicateSignatureAlgorithms)
                .WithSignatureAlgorithms(spec.SignatureAlgorithms.ToArray())
                .WithCertificateSignatureAlgorithms(
                    spec.CertificateSignatureAlgorithms?.ToArray())
                .WithAlpn(protocols)
                .WithSessionResumption(spec.SupportsSessionResumption)
                .WithPostHandshakeAuthentication(spec.SupportsPostHandshakeAuthentication)
                .WithRecordSizeLimit(spec.RecordSizeLimit)
                .WithDelegatedCredentials(spec.DelegatedCredentialSignatureAlgorithms?.ToArray())
                .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity(
                    spec.AllowsUnsupportedDelegatedCredentialAlgorithmsForWireFidelity)
                .WithQuicTransportParameters(spec.QuicTransportParameters)
                .WithSni(includeSni && spec.IncludeSni)
                .WithSessionId(spec.SessionId)
                .WithExtensionShuffling(spec.ShuffleExtensions);

            if (applicationSettingsProtocols.Length != 0 &&
                spec.ApplicationSettingsCodePoint.HasValue)
            {
                builder.WithApplicationSettings(
                    spec.ApplicationSettingsCodePoint.Value,
                    applicationSettingsProtocols);
            }

            if (spec.UseBoringPadding)
            {
                builder.WithBoringPadding();
            }
            else if (spec.PaddingLength.HasValue)
            {
                builder.WithPadding(spec.PaddingLength);
            }

            if (spec.GreaseEncryptedClientHello)
            {
                builder.WithGreaseEncryptedClientHello(
                    spec.GreaseEchCipherSuites,
                    spec.GreaseEchPayloadLengths.ToArray());
            }

            builder.WithExtensionLayout(layout.ToArray());
        });
    }
}
