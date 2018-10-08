namespace EdgeAuther
{
    using Newtonsoft.Json.Linq;
    using System;
    using System.Text;
    using static BuildStrings;
    class Program
    {
        const string BaseURL = "https://dauth-lp1.ndas.srv.nintendo.net/v3-59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404/";

        static void Main()
        {
            var ParseJSON = JObject.Parse(MakeReq($"{BaseURL}challenge", Encoding.UTF8.GetBytes(Challenge)));

            var ParseChallenge = ParseJSON["challenge"].ToString();

            var dauth_key_source = Convert.FromBase64String(ParseJSON["data"].ToString());

            var BaseRequest = BuildRequestString(ParseChallenge);

            var CMAC = GenCMAC(GenAESKekLiteEditionTM(dauth_kek_05, dauth_key_source), BaseRequest);

            var PostFinal = PostAuthToken(BaseRequest, CMAC);

            var FinalReq = MakeReq($"{BaseURL}edge_token", PostFinal);

            var Json = JObject.Parse(FinalReq);

            try
            {
                var Token = Json["dtoken"].ToString();
                Console.WriteLine($"Token:\n{Token}\n\nExpires in {Json["expires_in"].ToObject<int>() / 3600} hours.");
                System.IO.File.WriteAllText("edge_token.txt", Token);
            }
            catch (Exception)
            {
                Console.WriteLine(FinalReq);
            }
        }
    }
}