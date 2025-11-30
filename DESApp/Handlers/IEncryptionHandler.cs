using System.Text;

namespace DESApp.Handlers
{
    public interface IEncryptionHandler
    {
        string AlgorithmName { get; }
        byte[] Encrypt(byte[] data, byte[] key, Encoding encoder, StringBuilder processSb);
        byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder processSb);
        string GetKeyHint();
    }
}