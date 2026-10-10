using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Atlasd.Battlenet
{
    class NLSServer
    {
        public const int ValueLength = 32;
        public const int ProofLength = 20;

        private static readonly BigInteger Modulus = BigInteger.Parse("0F8FF1A8B619918032186B68CA092B5557E976C78C73212D91216F6658523C787", System.Globalization.NumberStyles.HexNumber);
        private const int Generator = 47;

        private readonly byte[] salt;
        private readonly BigInteger verifier;
        private readonly BigInteger b;
        private readonly byte[] serverKey;

        public NLSServer(byte[] salt, byte[] verifier)
        {
            if (salt == null || salt.Length != ValueLength) throw new ArgumentException("salt must be 32 bytes", nameof(salt));
            if (verifier == null || verifier.Length != ValueLength) throw new ArgumentException("verifier must be 32 bytes", nameof(verifier));

            this.salt = salt;
            this.verifier = FromBytes(verifier);

            do
            {
                b = FromBytes(RandomNumberGenerator.GetBytes(ValueLength)) % Modulus;
            }
            while (b.IsZero);

            serverKey = ToBytes((this.verifier + BigInteger.ModPow(Generator, b, Modulus)) % Modulus);
        }

        public byte[] Salt => salt;
        public byte[] ServerKey => serverKey;

        public bool Verify(string username, byte[] clientKey, byte[] clientProof, out byte[] serverProof)
        {
            serverProof = new byte[ProofLength];

            if (clientKey == null || clientKey.Length != ValueLength || clientProof == null || clientProof.Length != ProofLength) return false;

            var A = FromBytes(clientKey);
            if ((A % Modulus).IsZero) return false;

            var u = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(SHA1.HashData(serverKey));
            var S = BigInteger.ModPow(A * BigInteger.ModPow(verifier, u, Modulus) % Modulus, b, Modulus);
            var sessionKey = Interleave(ToBytes(S));

            var hashN = SHA1.HashData(ToBytes(Modulus));
            var hashG = SHA1.HashData(new byte[] { Generator });
            var xor = hashN.Zip(hashG, (n, g) => (byte)(n ^ g)).ToArray();

            var expected = SHA1.HashData(Concat(xor, SHA1.HashData(Encoding.ASCII.GetBytes(username.ToUpperInvariant())), salt, clientKey, serverKey, sessionKey));
            if (!CryptographicOperations.FixedTimeEquals(expected, clientProof)) return false;

            serverProof = SHA1.HashData(Concat(clientKey, clientProof, sessionKey));
            return true;
        }

        private static byte[] Interleave(byte[] s)
        {
            var even = new byte[ValueLength / 2];
            var odd = new byte[ValueLength / 2];
            for (int i = 0; i < ValueLength / 2; i++)
            {
                even[i] = s[i * 2];
                odd[i] = s[i * 2 + 1];
            }

            var evenHash = SHA1.HashData(even);
            var oddHash = SHA1.HashData(odd);
            var key = new byte[ProofLength * 2];
            for (int i = 0; i < key.Length; i++)
                key[i] = (i & 1) == 0 ? evenHash[i / 2] : oddHash[i / 2];

            return key;
        }

        private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

        private static BigInteger FromBytes(byte[] bytes) => new BigInteger(bytes, isUnsigned: true, isBigEndian: false);

        private static byte[] ToBytes(BigInteger value)
        {
            var bytes = new byte[ValueLength];
            value.ToByteArray(isUnsigned: true, isBigEndian: false).CopyTo(bytes, 0);
            return bytes;
        }
    }
}
