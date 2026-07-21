namespace TlsClient;

/// <summary>Controls streaming request and response transfers.</summary>
public sealed class TlsStreamingOptions
{
    private int _bufferSize = 64 * 1024;

    /// <summary>Gets or sets the copy buffer size. The default is 64 KiB.</summary>
    public int BufferSize
    {
        get => _bufferSize;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 4096);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 1024 * 1024);
            _bufferSize = value;
        }
    }

    /// <summary>
    /// Gets or sets whether gzip, deflate, and Brotli responses are decoded while streaming.
    /// Null inherits <see cref="TlsSessionOptions.AutomaticDecompression"/>.
    /// </summary>
    public bool? AutomaticDecompression { get; set; }

    internal TlsStreamingConfiguration Snapshot(bool sessionAutomaticDecompression)
    {
        return new TlsStreamingConfiguration(
            BufferSize,
            AutomaticDecompression ?? sessionAutomaticDecompression);
    }
}

internal sealed record TlsStreamingConfiguration(
    int BufferSize,
    bool AutomaticDecompression);
