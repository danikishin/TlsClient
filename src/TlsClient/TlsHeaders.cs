using System.Buffers;
using System.Collections;

namespace TlsClient;

/// <summary>
/// A case-insensitive, insertion-ordered HTTP header collection. Setting an existing
/// header keeps its original position; removing and adding it moves it to the end.
/// </summary>
public sealed class TlsHeaders : IEnumerable<KeyValuePair<string, IReadOnlyList<string>>>
{
    private static readonly SearchValues<char> InvalidNameCharacters = SearchValues.Create(
        "()<>@,;:\\\"/[]?={} \t\r\n");

    private readonly object _sync = new();
    private readonly List<HeaderEntry> _entries = [];

    /// <summary>Gets the number of distinct header names.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Gets comma-separated values for a header.</summary>
    public string this[string name]
    {
        get
        {
            if (!TryGetValues(name, out var values))
            {
                throw new KeyNotFoundException($"Header '{name}' was not found.");
            }

            return string.Join(", ", values);
        }
        set => Set(name, value);
    }

    /// <summary>Sets one value, replacing all existing values.</summary>
    public void Set(string name, string value) => Set(name, [value]);

    /// <summary>Sets one or more values, replacing all existing values.</summary>
    public void Set(string name, params string[] values)
    {
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(values);
        if (values.Length == 0)
        {
            throw new ArgumentException("At least one header value is required.", nameof(values));
        }

        var copy = ValidateAndCloneValues(values);
        lock (_sync)
        {
            var index = FindIndex(name);
            if (index >= 0)
            {
                _entries[index] = new HeaderEntry(name, copy);
            }
            else
            {
                _entries.Add(new HeaderEntry(name, copy));
            }
        }
    }

    /// <summary>Adds another value to a header, preserving its position.</summary>
    public void Add(string name, string value)
    {
        ValidateName(name);
        ValidateValue(value);
        lock (_sync)
        {
            var index = FindIndex(name);
            if (index < 0)
            {
                _entries.Add(new HeaderEntry(name, [value]));
                return;
            }

            var current = _entries[index];
            var values = new string[current.Values.Length + 1];
            current.Values.CopyTo(values, 0);
            values[^1] = value;
            _entries[index] = new HeaderEntry(current.Name, values);
        }
    }

    /// <summary>Removes a header if present.</summary>
    public bool Remove(string name)
    {
        ValidateName(name);
        lock (_sync)
        {
            var index = FindIndex(name);
            if (index < 0)
            {
                return false;
            }

            _entries.RemoveAt(index);
            return true;
        }
    }

    /// <summary>Returns whether the collection contains a header.</summary>
    public bool Contains(string name)
    {
        ValidateName(name);
        lock (_sync)
        {
            return FindIndex(name) >= 0;
        }
    }

    /// <summary>Gets all values for a header.</summary>
    public bool TryGetValues(string name, out IReadOnlyList<string> values)
    {
        ValidateName(name);
        lock (_sync)
        {
            var index = FindIndex(name);
            if (index < 0)
            {
                values = [];
                return false;
            }

            values = Array.AsReadOnly((string[])_entries[index].Values.Clone());
            return true;
        }
    }

    /// <summary>Removes every header.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            _entries.Clear();
        }
    }

    /// <summary>Returns an independent copy.</summary>
    public TlsHeaders Clone()
    {
        var clone = new TlsHeaders();
        foreach (var entry in Snapshot())
        {
            clone._entries.Add(entry);
        }

        return clone;
    }

    /// <inheritdoc />
    public IEnumerator<KeyValuePair<string, IReadOnlyList<string>>> GetEnumerator() =>
        Snapshot()
            .Select(entry => new KeyValuePair<string, IReadOnlyList<string>>(
                entry.Name,
                Array.AsReadOnly((string[])entry.Values.Clone())))
            .GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    internal HeaderEntry[] Snapshot()
    {
        lock (_sync)
        {
            return _entries
                .Select(entry => new HeaderEntry(entry.Name, (string[])entry.Values.Clone()))
                .ToArray();
        }
    }

    internal string? GetFirstOrDefault(string name)
    {
        lock (_sync)
        {
            var index = FindIndex(name);
            return index < 0 ? null : _entries[index].Values[0];
        }
    }

    private int FindIndex(string name) => _entries.FindIndex(
        entry => string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase));

    private static string[] ValidateAndCloneValues(IEnumerable<string> values)
    {
        var copy = values.ToArray();
        foreach (var value in copy)
        {
            ValidateValue(value);
        }

        return copy;
    }

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!name.All(character => character is > '\u001f' and < '\u007f') ||
            name.AsSpan().IndexOfAny(InvalidNameCharacters) >= 0)
        {
            throw new ArgumentException("The HTTP header name is not a valid token.", nameof(name));
        }
    }

    private static void ValidateValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Contains('\r', StringComparison.Ordinal) ||
            value.Contains('\n', StringComparison.Ordinal))
        {
            throw new ArgumentException("HTTP header values cannot contain CR or LF.", nameof(value));
        }
    }
}

internal sealed record HeaderEntry(string Name, string[] Values);
