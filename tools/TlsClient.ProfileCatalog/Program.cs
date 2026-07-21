using TlsClient;

var json = args.Length == 1 && string.Equals(args[0], "--json", StringComparison.Ordinal);

if (args.Length > 1 || (args.Length == 1 && !json))
{
    Console.Error.WriteLine("Usage: dotnet run --project tools/TlsClient.ProfileCatalog -- [--json]");
    return 2;
}

Console.Write(json ? TlsProfileCatalog.ExportJson() : TlsProfileCatalog.ExportMarkdown());
return 0;
