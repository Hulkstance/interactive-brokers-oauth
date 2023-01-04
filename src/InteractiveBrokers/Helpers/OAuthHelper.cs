using System.Security.Cryptography;
using System.Text;

namespace InteractiveBrokers.Helpers;

public static class OAuthHelper
{
    private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

    public static string GetAuthorizationHeader(string uri, string method, string consumerKey)
    {
        var oauthParameters = new Dictionary<string, string>
        {
            { "oauth_consumer_key", consumerKey },
            { "oauth_signature_method", "RSA-SHA256" },
            { "oauth_timestamp", GetTimestamp() },
            { "oauth_nonce", GetNonce() },
            { "oauth_callback", "oob" }
        };

        // The request parameters are collected, sorted and concatenated into a normalized string
        var queryParameters = ExtractQueryParams(uri);
        var oauthParamString = GetOAuthParamString(queryParameters, oauthParameters);
        var baseUri = GetBaseUriString(uri);

        // Signature Base String
        var signatureBaseString = GetSignatureBaseString(baseUri, method, oauthParamString);

        var pem = File.ReadAllText("private_encryption.pem");
        var signingKey = RSA.Create();
        signingKey.ImportFromPem(pem);

        var signature = SignSignatureBaseString(signatureBaseString, Encoding.UTF8, signingKey);
        oauthParameters.Add("oauth_signature", signature);

        // Constructs and returns the Authorization header
        var sb = new StringBuilder();
        foreach (var param in oauthParameters)
        {
            sb
                .Append(sb.Length == 0 ? "OAuth " : ",")
                .Append(param.Key)
                .Append("=\"")
                .Append(ToUriRfc3986(param.Value))
                .Append('"');
        }

        return sb.ToString();
    }

    /// <summary>
    ///     Parse query parameters out of the URL.
    /// </summary>
    private static Dictionary<string, List<string>> ExtractQueryParams(string uri)
    {
        var queryParamCollection = new Dictionary<string, List<string>>();
        var beginIndex = uri.IndexOf('?');
        if (beginIndex <= 0)
        {
            return queryParamCollection;
        }

        var rawQueryString = uri[beginIndex..];
        var decodedQueryString = Uri.UnescapeDataString(rawQueryString);
        var mustEncode = !decodedQueryString.Equals(rawQueryString);

        var queryParams = rawQueryString.Split('&', '?');
        foreach (var queryParam in queryParams)
        {
            if (string.IsNullOrEmpty(queryParam))
            {
                continue;
            }

            var separatorIndex = queryParam.IndexOf('=');
            var key = separatorIndex < 0 ? queryParam : Uri.UnescapeDataString(queryParam[..separatorIndex]);
            var value = separatorIndex < 0
                ? string.Empty
                : Uri.UnescapeDataString(queryParam[(separatorIndex + 1)..]);
            var encodedKey = mustEncode ? ToUriRfc3986(key) : key;
            var encodedValue = mustEncode ? ToUriRfc3986(value) : value;

            if (!queryParamCollection.ContainsKey(encodedKey))
            {
                queryParamCollection[encodedKey] = new List<string>();
            }

            queryParamCollection[encodedKey].Add(encodedValue);
        }

        return queryParamCollection;
    }

    /// <summary>
    ///     Lexicographically sorts all parameters and concatenates them into a string.
    /// </summary>
    private static string GetOAuthParamString(IDictionary<string, List<string>> queryParameters,
        IDictionary<string, string> oauthParameters)
    {
        var sortedParameters = new SortedDictionary<string, List<string>>(queryParameters, StringComparer.Ordinal);
        foreach (var oauthParameter in oauthParameters)
        {
            sortedParameters[oauthParameter.Key] = new List<string> { oauthParameter.Value };
        }

        // Build the OAuth parameter string
        var parameterString = new StringBuilder();
        foreach (var parameter in sortedParameters)
        {
            var values = parameter.Value;
            values.Sort(StringComparer.Ordinal); // Keys with same name are sorted by their values
            foreach (var value in values)
            {
                parameterString
                    .Append(parameterString.Length > 0 ? "&" : string.Empty)
                    .Append(parameter.Key)
                    .Append('=')
                    .Append(value);
            }
        }

        return parameterString.ToString();
    }

    /// <summary>
    ///     Normalizes the URL.
    /// </summary>
    private static string GetBaseUriString(string uriString)
    {
        var uri = new Uri(uriString);
        var lowerCaseScheme = uri.Scheme.ToLower();
        var lowerCaseAuthority = uri.Authority.ToLower();
        var path = uri.AbsolutePath;

        if (("http".Equals(lowerCaseScheme) && uri.Port == 80) || ("https".Equals(lowerCaseScheme) && uri.Port == 443))
        {
            // Remove port if it matches the default for scheme
            var index = lowerCaseAuthority.LastIndexOf(':');
            if (index >= 0)
            {
                lowerCaseAuthority = lowerCaseAuthority[..index];
            }
        }

        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        return $"{lowerCaseScheme}://{lowerCaseAuthority}{path}"; // Remove query and fragment
    }

    /// <summary>
    ///     The Signature Base String is a consistent reproducible concatenation of the request elements into a single string.
    /// </summary>
    private static string GetSignatureBaseString(string baseUri, string httpMethod, string oauthParamString)
    {
        return httpMethod.ToUpper() // Uppercase HTTP method
               + "&" + ToUriRfc3986(baseUri) // Base URI
               + "&" + ToUriRfc3986(oauthParamString); // OAuth parameter string
    }

    /// <summary>
    ///     Signs the signature base string using an RSA private key.
    /// </summary>
    private static string SignSignatureBaseString(string baseString, Encoding encoding, RSA privateKey)
    {
        var hash = Sha256Digest(baseString, encoding);
        var signedHashValue = privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signedHashValue);
    }

    /// <summary>
    ///     Percent encodes entities.
    /// </summary>
    private static string ToUriRfc3986(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        var escaped = new StringBuilder(Uri.EscapeDataString(input));
        string[] uriRfc3986EscapedChars = { "!", "*", "'", "(", ")" };
        foreach (var escapedChar in uriRfc3986EscapedChars)
        {
            escaped.Replace(escapedChar, UriHelper.HexEscape(escapedChar[0]));
        }

        return escaped.ToString();
    }

    /// <summary>
    ///     Returns a cryptographic hash of the given input.
    /// </summary>
    private static byte[] Sha256Digest(string input, Encoding encoding)
    {
        var inputBytes = encoding.GetBytes(input);
        return SHA256.HashData(inputBytes);
    }

    /// <summary>
    ///     Generates a 16 char random string for replay protection.
    /// </summary>
    private static string GetNonce()
    {
        var data = new byte[8];
        Random.GetBytes(data);
        return BitConverter.ToString(data).Replace("-", string.Empty).ToLower();
    }

    /// <summary>
    ///     Returns UNIX Timestamp.
    /// </summary>
    private static string GetTimestamp()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
    }
}
