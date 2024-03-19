# X509 Certificates: Tutorial 2

## 1. How to call API endpoint that requires client certificate authentication 

### 1.1. Client-Side 

#### 1.1.1. Create a .NET8 C# console application (client-side)

This example calls a hypothetical public API endpoint that requires client certificate authentication and shows how to include a certificate from a file

Firstly, we run Visual Studio 2022 Community Edition and we create a C# console application with the following project structure:

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/7cbde71a-ed47-493d-aa19-52c2d775a166)

We add the source code:

**Program.cs**

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
        var certificatePath = @"C:\\Client_Console_Application\\client_cert.pfx";
        var certificatePassword = "your_password";
        var certificate = new X509Certificate2(certificatePath, certificatePassword);

        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(certificate);

        // For demonstration purposes only: Trust all certificates
        //handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

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

#### 1.1.2. How to Obtain a Certificate**

**Generate a Self-Signed Certificate**: For development purposes, you can create a self-signed certificate using tools like **OpenSSL** (as I explained in the previous Linkedin post)

However, remember that self-signed certificates are not trusted by clients by default and are not suitable for production environments

We are going to create a **Self-Signed Certificate** with **OpenSSL**

**Step 1: Generate the CA's Key and Certificate**

Generate the CA's Private Key

```
openssl genpkey -algorithm RSA -out ca_key.pem -pkeyopt rsa_keygen_bits:2048
```

Create the CA Certificate

```
openssl req -x509 -new -nodes -key ca_key.pem ^
-days 1024 -out ca_cert.pem ^
-subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=YourCAName"
```

**Step 2: Generate the Client's Key and CSR**

Generate the Client's Private Key

```
openssl genpkey -algorithm RSA -out client_key.pem -pkeyopt rsa_keygen_bits:2048
```

Create a CSR for the Client

```
openssl req -new -key client_key.pem ^
-out client.csr ^
-subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=YourClientName"
```

**Step 3: Sign the Client CSR with Your CA**

Sign the CSR to Create the Client Certificate

```
openssl x509 -req -in client.csr ^
-CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial ^
-out client_cert.pem -days 365 -sha256
```

**Step 4: Create a PFX File from the Client Certificate and Key**

Generate the PFX File

```
openssl pkcs12 -export -out client_cert.pfx ^
-inkey client_key.pem ^
-in client_cert.pem ^
-certfile ca_cert.pem ^
-password pass:your_password
```

After running the above commands we get the PFX file highlighed in the following picture

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/2b0440a0-3a72-413a-9749-8d7e06c4d883)

#### 1.1.3. There are another options for obtaining a certificate

**Purchase from a Certificate Authority (CA)**: You can buy a certificate from a recognized CA. After purchasing, you'll go through a validation process, and then the CA will provide you with a certificate file (usually .crt) and a private key file.

**Use Let's Encrypt**: For web servers, you can obtain a free certificate from Let's Encrypt. They provide tools like Certbot to automate the certificate issuance and installation process.

**For Internal Use/Testing**: If the certificate is for internal use or testing, your organization's internal CA can issue one. You'll need to install the CA's root certificate on clients that need to trust the certificate.

**Convert to PFX**: If your certificate and private key are in separate files, you might need to convert them to a PFX (.pfx) or PKCS#12 (.p12) file format, which contains both the certificate and private key, for use in your application. You can use OpenSSL to perform this conversion.

**Note**:

When using a certificate for authentication, ensure it's securely stored and its password is protected.

Be cautious with **disabling** certificate validation (**ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;**) in **production environments**, as it can make your application vulnerable to man-in-the-middle attacks.

### 1.2. Server-Side 

#### 1.2.1. Create a .NET8 C# WebAPI application (server-side)

We run Visual Studio 2022 Community Edition and we create a .NET8 WebAPI without controllers

This is the project structure

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/d5d68136-4a22-4cab-b6a5-a1e06c150637)

Now we input the source code in the middleware (Program.cs file)

**Program.cs**

```csharpusing Microsoft.AspNetCore.Builder;
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
            var expectedIssuer = "CN=YourCAName, O=YourOrganization, L=YourCity, S=YourState, C=US";
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
            var expectedThumbprint = "27B83C3F11DF3C716FD583366075DB30A344CF4B";
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

#### 1.2.2. Set the launchSettings.json

Copy the HTTPS endpoint and paste it in the Client application: 

```
var endpoint = "https://localhost:7051/api/resource";
```

See the server launch settings:

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/36346324-ffd0-4dd2-975b-3d42e8f4ca0d)

#### 1.2.3. Install the Certificate in the Internet WebBrowser (Google Chrome)

Before running the application we have to install the certificate in the internet web browser where we are going to run the server application

We double click on the PFX file 

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/ffff14ff-9a24-4d31-896a-4fd9c9932227)

We select to install the certificate for the **current user** or for the **local machine** and click on Next button

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/651dbd22-eaef-4d55-ba9e-88c3a5b0eb8c)

We leave the PFX file path as default input by the computer and click on Next button

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/9b1ab8a1-aa0c-4ca5-8ba2-245a3f7d28ba)

We input the password: **your_password** set in the Step 4 in this document and click on Next button

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/883dbe87-c51a-4804-a956-35bd92b0d61a)

We leave the default value to automatically place the certificate when better considered by the computer

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/f06c65f7-774c-4716-91f7-dfac05ac5ec1)

We press the Finish button

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/ac56ea80-999b-41de-a2e0-158f621555f7)

Now we first validate our certificate was installed running the **Manage user certificates** application

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/0c0d1d71-93a6-4ba8-ae66-d59d383b27cb)

We navigate into the **Personal** folder and we can see our certificate was already placed in this folder.

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/f3ec9cc8-cf08-48e5-bcd0-e858e4d80127)

#### 1.2.4. Verify the Certificate and copy certificate values in the server application

We verify the Certificate is already installed in the Internet WebBrowser (Google Chrome) and copy the certificate information in the Server source code**

Go to **Settings** in the Google Chrome menu

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/c581e772-4f1c-4b7f-b490-7d0bbb950d02)

Then we select the menu option **Privacy and Security** and then **Security**

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/129edb91-6f8e-4841-b026-83deb74ba3fc)

We select the option **Manage certificates**

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/3ba3252a-efc4-4dfb-9855-b03712cfea51)

We double click on our certificate

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/8df308de-f53c-4c38-aba6-9006cd5874d5)

We copy the certificate required data in the server application: Issuer, Valid From, Valid To and Thumbprint

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/5294ee93-db0b-4705-aa0b-7ab11141cb6e)

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/8fbfb863-cbdc-4c18-b368-28e6ac5cc4bd)

The **Issuer** value should be paste in the following server app code:

```csharp
 var expectedIssuer = "CN=YourCAName, O=YourOrganization, L=YourCity, S=YourState, C=US";
```

The **Valid From** and **Valid To** dates should comply with the following server app code:

```csharp
if (DateTime.Now > certificate.NotAfter || DateTime.Now < certificate.NotBefore)
{
   return false; // Certificate is expired or not yet valid
}
```

We also have to copy the **Thumbprint** value in the following server app code:

```csharp
 var expectedThumbprint = "27B83C3F11DF3C716FD583366075DB30A344CF4B";
```

### 1.3. How to run the applications (clien-side and server-side)

#### 1.3.1. Run the Server

As first step is recomended to clean the Internet WebBrowser History

We have to start first the **Server** application

The first time we build and **run the server-side application** in Visual Studio 2022, the internet web browser requires us to select a certificate, 

we have to **select the certificate** se installed in section 1.2.3 in this document

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/efb1d558-4ef0-4d8e-aad9-af06d96cd866)

Then we will see the WebAPI swagger docs

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/fbe71c02-14c7-4865-8ee6-67a56419660a)

#### 1.3.2. Run the Client

We open the solution in Visual Studion, we build and run it

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/0c41d8cb-8f0f-4994-aad2-f2b6521e890e)

We verify the client send the certificate to the server in the API call request

### 1.4. Hot to test the Server-side with Postman

Install and run Postman

Create a new POST request and input the following data

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/f3c0cccd-36b6-464d-b9b3-58e371b8ed30)

Before sending the request we have to **install the certificate in Postman**

We selet **Settings** in the Postman menu

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/c26cda35-0d1b-4f18-9090-cf60a03189ec)

We select **Certificates** and then we press the button **Add Certificate**

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/8085f6b8-b64f-4a5e-805b-369d973a6f7f)

We input the **server name**, we select the **certificate PFX file**, and we enter the **certificate password**, and finally we press the **Add** button

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/72d4998c-af82-4f3b-b04c-a89cfc028b72)

We close the Certificates window and we return to the Postman desktop

We can now press the **Send** button and get the response from the server

![image](https://github.com/luiscoco/X509Certificates_tutorial2/assets/32194879/59586974-956f-47db-bed9-e7d002066bdc)

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
