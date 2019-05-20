using Amazon.Lambda.Core;
using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using System.Linq;
using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Models;
using AuthenticationService.Managers;

namespace Authorizer
{
    public class Authenticate
    {
        public JObject FunctionHandler(JObject input)
        {
            JToken idssokey = input.SelectToken("query.idssokey");
            JToken iduser = input.SelectToken("query.iduser");

            string status = string.Empty;
            string data = string.Empty;

            if (idssokey != null | iduser != null) {
                string key = Environment.GetEnvironmentVariable("DecryptionKey");
                string vector = Environment.GetEnvironmentVariable("DecryptionVector");

                try {
                    string decryptedString = Decrypt(idssokey.ToString(), key, vector);
                    string[] currentValues = decryptedString.Split('~');
                    int UserID = Convert.ToInt32(currentValues[0]);
                    string UserName = currentValues[1];
                    DateTime DateCreated = Convert.ToDateTime(currentValues[2]);                                      

                    if (DateTime.UtcNow.Subtract(DateCreated).TotalMinutes >= Convert.ToInt32(Environment.GetEnvironmentVariable("SSOKeyLifetime"))) {
                        LambdaLogger.Log("SSO Key has expired");
                        status = "ERROR";
                        data = "SSO Key is not valid";
                    } else {
                        IAuthContainerModel model = JWTService.GetJWTContainerModel(UserName);
                        IAuthService authService = new JWTService(model.SecretKey);
                        string jwt = authService.GenerateToken(model);

                        LambdaLogger.Log("SSO Key is valid");
                        status = "SUCCESS";
                        data = jwt;
                    }
                } catch (Exception e) {
                    status = "ERROR";
                    data = e.Message;
                    LambdaLogger.Log(e.Message);
                }    
            }

            JObject result = new JObject();
            result.Add("status", status);
            result.Add("data", data);

            return result;
        }

        #region for encryption/decryption
        public static string Decrypt(string encryptedStr, string key, string iv)
        {
            if ((key.Length != 16))
                throw new Exception("Invalid key length.  Key must be 16 characters in length.");

            string strResult = "";

            // Initialize the service provider
            TripleDESCryptoServiceProvider descsp = new TripleDESCryptoServiceProvider();
            descsp.KeySize = 128;

            descsp.Key = ConvertToByteArray(key);
            descsp.IV = ConvertToByteArray(iv);

            ICryptoTransform desDecrypt = descsp.CreateDecryptor();

            // Prepare the streams:
            // mOut is the output stream. 
            // cs is the transformation stream.
            MemoryStream mOut = new MemoryStream();
            CryptoStream cs = new CryptoStream(mOut, desDecrypt, CryptoStreamMode.Write);

            // Remember to revert the base64 encoding into a byte array to restore the original encrypted data stream
            byte[] bPlain = new byte[encryptedStr.Length + 1];

            bPlain = Convert.FromBase64CharArray(encryptedStr.ToCharArray(), 0, encryptedStr.Length);

            long lmOut = 0;
            long lRead = 0;
            long lTotal = encryptedStr.Length;

            // Perform the actual decryption
            while ((lTotal >= lRead))
            {
                lmOut = mOut.Length;

                cs.Write(bPlain, 0, System.Convert.ToInt32(bPlain.Length));

                lRead = lmOut + Convert.ToInt32(((bPlain.Length / (double)descsp.BlockSize) * descsp.BlockSize));
            }

            ASCIIEncoding aEnc = new ASCIIEncoding();
            strResult = aEnc.GetString(mOut.GetBuffer(), 0, System.Convert.ToInt32(mOut.Length));

            // Trim the string to return only the meaningful data
            // Remember that in the encrypt function, the first 5 characters hold the length of the actual data
            // This is the simplest way to remember the original length of the data, without resorting to complicated computations.
            string strLen = strResult.Substring(0, 5);
            int nLen = Convert.ToInt32(strLen);

            strResult = strResult.Substring(5, nLen);

            return strResult;
        }

        public static byte[] ConvertToByteArray(string value)
        {
            int i;
            char[] arrChar;

            arrChar = value.ToCharArray();

            byte[] arrByte = new byte[arrChar.Length - 1 + 1];

            for (i = 0; i <= arrByte.Length - 1; i++)
                arrByte[i] = Convert.ToByte(arrChar[i]);

            return arrByte;
        }
        #endregion
    }
}