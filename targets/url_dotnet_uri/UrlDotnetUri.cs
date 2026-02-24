// URL parser target — C# System.Uri (.NET).
//
// Parses URLs using System.Uri and outputs parsed
// components as JSON for differential comparison.
//
// System.Uri has notable characteristics:
//   - Strict URI validation with UriKind options
//   - Automatic percent-encoding normalization
//   - International domain name (IDN) support
//   - Different handling of relative vs absolute URIs
//   - Case normalization for scheme and host
//   - .NET ecosystem (ASP.NET, Azure) SSRF relevance
//
// References:
//   - .NET docs: System.Uri
//   - RFC 3986

using System;
using System.IO;
using System.Text;

class UrlDotnetUri
{
    static string JsonString(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                        sb.Append($"\\u{(int)c:x4}");
                    else
                        sb.Append(c);
                    break;
            }
        }
        sb.Append("\"");
        return sb.ToString();
    }

    static string ParseUrl(string data)
    {
        data = data.Trim();
        if (string.IsNullOrEmpty(data))
            throw new ArgumentException("Empty input");

        Uri parsed;
        if (!Uri.TryCreate(data, UriKind.Absolute, out parsed))
        {
            // Try as relative URI with a base
            var baseUri = new Uri("http://placeholder.invalid/");
            if (!Uri.TryCreate(baseUri, data, out parsed))
                throw new UriFormatException("Invalid URL");
        }

        // Extract userinfo
        string userinfo = parsed.UserInfo ?? "";

        // Extract host
        string host = parsed.Host ?? "";

        // Extract port (-1 means default/unspecified)
        string port = parsed.Port > 0 && !parsed.IsDefaultPort
            ? parsed.Port.ToString() : "";

        // Extract path
        string path = parsed.AbsolutePath ?? "";

        // Extract query without leading ?
        string query = "";
        if (!string.IsNullOrEmpty(parsed.Query))
        {
            query = parsed.Query.StartsWith("?")
                ? parsed.Query.Substring(1) : parsed.Query;
        }

        // Extract fragment without leading #
        string fragment = "";
        if (!string.IsNullOrEmpty(parsed.Fragment))
        {
            fragment = parsed.Fragment.StartsWith("#")
                ? parsed.Fragment.Substring(1) : parsed.Fragment;
        }

        // Extract scheme
        string scheme = parsed.Scheme ?? "";

        return "{" +
            "\"fragment\":" + JsonString(fragment) + "," +
            "\"host\":" + JsonString(host) + "," +
            "\"path\":" + JsonString(path) + "," +
            "\"port\":" + JsonString(port) + "," +
            "\"query\":" + JsonString(query) + "," +
            "\"scheme\":" + JsonString(scheme) + "," +
            "\"userinfo\":" + JsonString(userinfo) +
            "}";
    }

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("Usage: UrlDotnetUri <file>");
            Environment.Exit(2);
        }

        string data;
        try
        {
            data = File.ReadAllText(args[0], Encoding.UTF8);
        }
        catch (IOException e)
        {
            Console.Error.WriteLine("IO error: " + e.Message);
            Environment.Exit(2);
            return;
        }

        try
        {
            string result = ParseUrl(data);
            Console.WriteLine(result);
            Environment.Exit(0);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("REJECT: " + e.Message);
            Environment.Exit(1);
        }
    }
}
