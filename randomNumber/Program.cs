using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace randomNumber
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(GetUniqueKey());
        }
        public static string GetUniqueKey()
        {
            char[] chars1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            char[] chars2 = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            char[] chars3 = "1234567890".ToCharArray();

            byte[] data = new byte[4];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(4);
            foreach (byte b in data)
            {
                result.Append(chars1[b % (chars1.Length)]);
            }

            data = new byte[4];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            foreach (byte b in data)
            {
                result.Append(chars2[b % (chars2.Length)]);
            }

            data = new byte[4];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            foreach (byte b in data)
            {
                result.Append(chars3[b % (chars3.Length)]);
            }

            return result.ToString();
        }
    }
}
