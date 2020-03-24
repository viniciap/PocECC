using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PocECC
{
    public class Dna
    {

        public CngKey GenerateKeys()
        {
            var key = new ECDiffieHellmanCng();
            key.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            key.HashAlgorithm = CngAlgorithm.Sha256;
            return key.Key;

        }

        /// <summary>
        /// Export to file;
        /// </summary>
        /// <returns></returns>
        public bool ExportDerivedKey(string path, byte[] key) { throw new NotImplementedException(); }
        /// <summary>
        /// Import from file;
        /// </summary>
        /// <returns></returns>
        public byte[] ImportDerivedKey(string path) { throw new NotImplementedException(); }

        public byte[] DeriveKeyMaterial(byte[] privateKey, byte[] publicKey)
        {
            using (ECDiffieHellmanCng pvt = new ECDiffieHellmanCng(CngKey.Import(privateKey, CngKeyBlobFormat.EccPrivateBlob)))
            {
                return pvt.DeriveKeyMaterial(CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));
            }
        }

        public Tuple<byte[], byte[]> EncryptMessage(byte[] derivedKey, string messasge)
        {
            using (Aes aes = new AesCryptoServiceProvider()
            {
                Key = derivedKey
            })
            {
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(messasge);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    return new Tuple<byte[], byte[]>(ciphertext.ToArray(), aes.IV);
                }
            }
        }

        public string DecryptMessage(byte[] derivedKey, byte[] message, byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider()
            {
                Key = derivedKey,
                IV = iv
            })
            {
                using (MemoryStream plaintext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {

                    cs.Write(message, 0, message.Length);
                    cs.Close();
                    return Encoding.UTF8.GetString(plaintext.ToArray());
                }
            }
        }

    }
}
