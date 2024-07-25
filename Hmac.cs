using System;
using System.Security;
using System.Security.Cryptography;

namespace NBR14522.Model.Abnt
{
    public class Hmac
    {
        private readonly static byte IPAD_VAL = 0x36;
        private readonly static byte OPAD_VAL = 0x5C;

        private static byte[] g_ipad = new byte[64];
        private static byte[] g_opad = new byte[64];

        private static HashAlgorithm? md;

        #pragma warning disable SYSLIB0045
        public Hmac(string hf)
        {
            try
            {
                md = HashAlgorithm.Create(hf);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.StackTrace);
            }
        }

        public byte[] calc(byte[] password, byte[] text)
        {

            update_pads(password);

            byte[] aux = new byte[g_ipad.Length + text.Length];
            Array.Copy(g_ipad, 0, aux, 0, g_ipad.Length);
            Array.Copy(text, 0, aux, g_ipad.Length, text.Length);
            byte[]? hashoutput = md.ComputeHash(aux);


            Console.WriteLine( BitConverter.ToString(hashoutput));

            aux = new byte[g_opad.Length + hashoutput.Length];
            Array.Copy(g_opad, 0, aux, 0, g_opad.Length);
            Array.Copy(hashoutput, 0, aux, g_opad.Length, hashoutput.Length);

            hashoutput = md.ComputeHash(aux);

            Console.WriteLine( BitConverter.ToString(hashoutput));

            return hashoutput;
        }

        static void update_pads(byte[] password)
        {

            for (int i = 0; i < g_ipad.Length; ++i)
            {
                g_ipad[i] = IPAD_VAL;
                g_opad[i] = OPAD_VAL;
            }

            for (int i = 0; i < password.Length; ++i)
            {
                g_ipad[i] ^= password[i];
                g_opad[i] ^= password[i];
            }


            Console.WriteLine( BitConverter.ToString(g_ipad));
            Console.WriteLine( BitConverter.ToString(g_opad));
        }
    }
}

//58-84-EC-63-7E-4F-F6-0E-1B-05-0C-D6-5C-C6-8C-49-3D-BB-00-BF-D5-9E-EB-EE-36-4E-DA-D0-F3-E1-D4-CB