using SharpTls;

namespace TlsClient.Tests;

public sealed class TlsProfileTests
{
    [Theory]
    [MemberData(nameof(BrowserProfiles))]
    public void Http11Profile_AdvertisesOnlyHttp11(TlsProfile profile)
    {
        var spec = profile.Http11ClientHello.Spec;

        Assert.Equal(["http/1.1"], spec.AlpnProtocols);
        Assert.DoesNotContain(
            spec.Extensions,
            extension => extension.BuiltInKind == ClientHelloExtensionKind.ApplicationSettings);
    }

    public static TheoryData<TlsProfile> BrowserProfiles => new()
    {
        TlsProfiles.Chrome,
        TlsProfiles.Firefox,
        TlsProfiles.Edge,
        TlsProfiles.Safari,
        TlsProfiles.IOS,
        TlsProfiles.Android,
        TlsProfiles.Modern,
    };
}
