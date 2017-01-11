using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher_GOST
{
    public static class Encryption
    {
        #region Инициализация блока замен
        /* private static byte[,] Sblocks = {
                            { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
                             { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
  { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
   { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
   { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
   { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
   { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF },
  { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF}
                           };//Блок замен
         */
        private static byte[,] Sblocks = {
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 },
                           {0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17 }
                          };//Блок замен
        #endregion
        private static bool mod64(int length)//Проверка делится ли открытый текст нацело на 64 бита
        {
            if ((length % 8) == 0)
                return true;
            else
                return false;
        }

        private static List<UInt64> fillingListData(string data)//Возвращает список из 64-х битных блоков данных
        {
            List<UInt64> resultList = new List<UInt64>();
            byte[] temp = Encoding.Default.GetBytes(data);
            int startIndex = 0;
            while (startIndex < temp.Length)
            {
                resultList.Add(BitConverter.ToUInt64(temp, startIndex));
                startIndex += 8;
            }
            return resultList;
        }

        private static List<UInt32> fillingListKey(string key)//Возвращает список из 32-х битных блоков ключа
        {
            List<UInt32> resultList = new List<UInt32>();
            byte[] temp = Encoding.Default.GetBytes(key);
            resultList.Add(BitConverter.ToUInt32(temp, 0));
            resultList.Add(BitConverter.ToUInt32(temp, 4));
            resultList.Add(BitConverter.ToUInt32(temp, 8));
            resultList.Add(BitConverter.ToUInt32(temp, 12));
            resultList.Add(BitConverter.ToUInt32(temp, 16));
            resultList.Add(BitConverter.ToUInt32(temp, 20));
            resultList.Add(BitConverter.ToUInt32(temp, 24));
            resultList.Add(BitConverter.ToUInt32(temp, 28));
            return resultList;
        }

        private static string getPartString(UInt64 partText)//Возврашает часть зашифрованной/расшифрованной строки
        {
            byte[] temp = BitConverter.GetBytes(partText);
            string result = Encoding.Default.GetString(temp);
            return result;
        }

        private static UInt32 mod2_32(UInt32 a, UInt32 b)// Сложение по модулю 2^32
        {
            UInt32 result = a + b;
            return result;
        }

        private static UInt32 shiftN(UInt32 num, int n)//циклический сдвиг 32-х битового числа на n разрядов
        {
            UInt32 c = num;
            for (int i = 0; i < n; ++i)
            {
                //UInt32 temp = (UInt32)(num / Convert.ToUInt32(Math.Pow(2, 31)));
                UInt32 temp = num >> 31;
                num <<= 1;
                num += temp;
            }
            return num;
        } 

        private static UInt32 retL(UInt64 data)//Возвращает старшую часть 8 байтового блока данных
        {
            data >>= 32;
            UInt32 result = (UInt32)data;//temp;
            return result;
        }

        private static UInt32 retR(UInt64 data)//Возвращает младшую часть 8 байтового блока данных
        {
            UInt32 result = (UInt32)data;
            return result;
        }

        private static UInt32 func(UInt32 R, UInt32 Ki)//Функция f(Ri, Ki), используемая в сети Фейстеля
        {
            UInt32 s = mod2_32(R, Ki);
            List<UInt32> partsS = new List<UInt32>();
            for (int i = 0; i < 8; ++i)
            {

                UInt32 temp = s >> 28;
                partsS.Add(temp);
                s <<= 4;
            }
            partsS.Reverse();
            for (int i = 0; i < 8; ++i)
            {
                partsS[i] = Sblocks[i, (int)partsS[i]];
            }
            s = 0;
            for (int i = 0; i < partsS.Count; ++i)
            {
                s += partsS[i];
                s <<= 4;
            }
            s = shiftN(s, 11);
            return s;
        }

        private static UInt64 encodePartData(UInt64 partData, List<UInt32> partsKey)//Шифрует 64-х битный блок данных
        {
            for (int i = 0; i < 24; ++i)
            {
                partData = feistel(partData, partsKey[i % 8]);
            }
            for (int i = 7; i >= 0; --i)
            {
                partData = feistel(partData, partsKey[i]);
            }
            UInt64 result = (partData << 32) + (partData >> 32);
            return result;
        }

        private static UInt64 decodePartData(UInt64 partData, List<UInt32> partsKey)//Расшифровывает 64-х битный блок шифрованных данных
        {
            for (int i = 0; i < 8; ++i)
            {
                partData = feistel(partData, partsKey[i]);
            }
            for (int i = 23; i >= 0; --i)
            {
                partData = feistel(partData, partsKey[i % 8]);
            }
            UInt64 result = (partData << 32) + (partData >> 32);
            return result;
        }

        private static UInt64 feistel(UInt64 partData, UInt32 partKey)//осуществляет шаг в сети Фейстеля
        {
            UInt32 L = retL(partData);
            UInt32 R = retR(partData);
            UInt32 temp = func(R, partKey);
            UInt32 xor = L ^ temp;
            UInt64 result = (UInt64)R;
            result <<= 32;
            result += (UInt64)xor;
            return result;
        }

        public static string encode(string data, string key)//Метод шифрования
        {
            if (!mod64(data.Length))
            {
                while (!mod64(data.Length))
                {
                    data += " ";
                }
            }
            List<UInt32> partsKey = fillingListKey(key);
            List<UInt64> partsData = fillingListData(data);
            List<UInt64> encodedData = new List<UInt64>();
            string result = "";
            for (int i = 0; i < partsData.Count; ++i)
            {
                encodedData.Add(encodePartData(partsData[i], partsKey));
            }
            for (int i = 0; i < encodedData.Count; ++i)
            {
                result += getPartString(encodedData[i]);
            }
            return result;

        }

        public static string decode(string codedData, string key)//Метод расшифровки
        {
            List<UInt32> partsKey = fillingListKey(key);
            List<UInt64> partsData = fillingListData(codedData);
            List<UInt64> decodedData = new List<UInt64>();
            string result = "";
            for (int i = 0; i < partsData.Count; ++i)
            {
                decodedData.Add(decodePartData(partsData[i], partsKey));
            }
            for (int i = 0; i < decodedData.Count; ++i)
            {
                result += getPartString(decodedData[i]);
            }
            return result;
        }
    }
}
