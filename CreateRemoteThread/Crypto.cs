using System;
using System.Security.Cryptography;
using System.IO;

namespace CRT {
    class Crypto {
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-5.0
        public static byte[] DecryptFromBytes_AES(byte[] cipherText, byte[] key, byte[] IV) {
            using (AesManaged aesAlg = new AesManaged()) {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 128;
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream()) {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write)) {
                        csDecrypt.Write(cipherText, 0, cipherText.Length);
                    }
                    return msDecrypt.ToArray();
                }
            }
        }

        public static byte[] XOR(byte[] ciphertext, byte[] key) {
            byte[] clearText = new byte[ciphertext.Length];
            for (int i = 0; i < ciphertext.Length; i++) {
                clearText[i] = (byte)(ciphertext[i] ^ key[i % key.Length]);
            }
            return clearText;
        }
    }
}
