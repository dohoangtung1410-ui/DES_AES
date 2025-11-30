# WPF CryptoDemo


This is a simple WPF demo that implements `ICryptoService` with AES (AES-128-CBC) and DES (DES-CBC).


## How to run
1. Open this folder in Visual Studio 2022/2023
2. Restore and build (Target: .NET 6.0 Windows)
3. Run the app.


## Notes
- Key field accepts either a Base64-encoded binary key of required length or a UTF-8 string whose byte-length equals the required length (8 bytes for DES, 16 bytes for AES).
- The generated keys via the "Generate" button are Base64 binary keys. When you paste them into the Key box, the app will detect their Base64 form.
- Packaging format: `IV || ciphertext` then Base64-encoded.