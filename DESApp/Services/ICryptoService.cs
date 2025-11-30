using System.Text;

namespace DESApp.Services
{
    public interface ICryptoService
    {
        string Encrypt(string plainText, byte[] key, Encoding encoding);
        string Decrypt(string base64Package, byte[] key, Encoding encoding);
    }
}
