# X509 Certificates: Tutorial 2

## 1. How to call API endpoint that requires client certificate authentication 

### 1.1. Client-Side C# console application

This example calls a hypothetical public API endpoint that requires client certificate authentication and shows how to include a certificate from a file

```csharp
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

class Program
{
    static async Task Main(string[] args)
    {
        var endpoint = "https://localhost:7051/api/resource";
        var requestJson = new
        {
            // Sample request payload
            Property1 = "Value1",
            Property2 = "Value2"
        };

        var jsonContent = JsonConvert.SerializeObject(requestJson);
        var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        // Load the certificate
        var certificatePath = @"C:\\Client_Console_Application\\Client_Console_API_call\\client_cert.pfx";
        var certificatePassword = "your_password";
        var certificate = new X509Certificate2(certificatePath, certificatePassword);

        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(certificate);

        // For demonstration purposes only: Trust all certificates
        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

        using (var httpClient = new HttpClient(handler))
        {
            httpClient.Timeout = TimeSpan.FromSeconds(30);

            // Custom headers (if required)
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation("CustomHeader", "HeaderValue");

            // Send POST request
            var response = await httpClient.PostAsync(endpoint, content);

            // Ensure the request was successful
            response.EnsureSuccessStatusCode();

            // Read and print the response content
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseContent);
        }
    }
}
```

**How to Obtain a Certificate**:

**Purchase from a Certificate Authority (CA)**: You can buy a certificate from a recognized CA. After purchasing, you'll go through a validation process, and then the CA will provide you with a certificate file (usually .crt) and a private key file.

**Generate a Self-Signed Certificate**: For development purposes, you can create a self-signed certificate using tools like **OpenSSL** (as I explained in the previous Linkedin post). However, remember that self-signed certificates are not trusted by clients by default and are not suitable for production environments.

**Use Let's Encrypt**: For web servers, you can obtain a free certificate from Let's Encrypt. They provide tools like Certbot to automate the certificate issuance and installation process.

**For Internal Use/Testing**: If the certificate is for internal use or testing, your organization's internal CA can issue one. You'll need to install the CA's root certificate on clients that need to trust the certificate.

**Convert to PFX**: If your certificate and private key are in separate files, you might need to convert them to a PFX (.pfx) or PKCS#12 (.p12) file format, which contains both the certificate and private key, for use in your application. You can use OpenSSL to perform this conversion.

**Note**:

When using a certificate for authentication, ensure it's securely stored and its password is protected.

Be cautious with **disabling** certificate validation (**ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;**) in **production environments**, as it can make your application vulnerable to man-in-the-middle attacks.

### 1.2. Server-Side C# WebAPI application

```csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel.DataAnnotations;
using System.Net.Security;

var builder = WebApplication.CreateBuilder(args);

// Assume HTTPS is properly configured in the hosting environment or through Kestrel configuration.
// For client certificate validation, we can configure Kestrel to require certificates.
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(httpsOptions =>
    {
        // Require a client certificate
        httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.RequireCertificate;
        // Optionally, add custom validation here
        httpsOptions.ClientCertificateValidation = (certificate, chain, sslPolicyErrors) => {
            // Implement validation logic as needed. For demo purposes, returning true.
            // Example: Check the certificate issuer
            var expectedIssuer = "CN=TrustedIssuer";
            if (certificate.Issuer != expectedIssuer)
            {
                return false; // Certificate was not issued by the expected issuer
            }

            // Example: Ensure the certificate is not expired
            if (DateTime.Now > certificate.NotAfter || DateTime.Now < certificate.NotBefore)
            {
                return false; // Certificate is expired or not yet valid

            }

            // Example: Validate the certificate thumbprint
            var expectedThumbprint = "cb6f3ac411c473388a680d97550ef955bc0d2ab0";
            if (certificate.Thumbprint != expectedThumbprint)
            {
                return false; // Certificate thumbprint does not match the expected value
            }

            // Check for any SSL policy errors (if you want to be strict about them)
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false; // There were SSL policy errors
            }

            return true; // All checks passed, certificate is valid
        };
    });
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/api/resource", async (HttpRequest req) =>
{
    // Deserialize the JSON content to the model.
    var requestModel = await JsonSerializer.DeserializeAsync<RequestPayload>(req.Body);

    // Process the request (here, simply echoing back the received properties).
    var response = new
    {
        Message = "Received your request",
        ReceivedProperty1 = requestModel?.Property1,
        ReceivedProperty2 = requestModel?.Property2
    };

    // Respond with JSON.
    return Results.Json(response);
});


app.Run();

// Define a model that matches the client's JSON structure.
public class RequestPayload
{
    public string Property1 { get; set; }
    public string Property2 { get; set; }
}
```


## 2. Loading an X.509 certificate from a file and using it to encrypt and decrypt a message

Below is the complete code for a C# console application that demonstrates loading an X.509 certificate from a file and using it to encrypt and decrypt a message

Make sure to replace **path_to_your_certificate.pfx** and **your_certificate_password** with the actual path to your certificate file and its password, respectively

```csharp
using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace X509CertExample
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var certPath = "path_to_your_certificate.pfx";
                var certPassword = "your_certificate_password";
                var certificate = LoadCertificate(certPath, certPassword);

                var message = "Hello, secure world!";
                var encryptedData = EncryptData(certificate, message);
                Console.WriteLine($"Encrypted data: {Convert.ToBase64String(encryptedData)}");

                var decryptedMessage = DecryptData(certificate, encryptedData);
                Console.WriteLine($"Decrypted message: {decryptedMessage}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        public static X509Certificate2 LoadCertificate(string path, string password)
        {
            return new X509Certificate2(path, password, X509KeyStorageFlags.Exportable);
        }

        public static byte[] EncryptData(X509Certificate2 cert, string dataToEncrypt)
        {
            using (var rsa = cert.GetRSAPublicKey())
            {
                return rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), RSAEncryptionPadding.OaepSHA256);
            }
        }

        public static string DecryptData(X509Certificate2 cert, byte[] dataToDecrypt)
        {
            using (var rsa = cert.GetRSAPrivateKey())
            {
                var decryptedBytes = rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}
```
