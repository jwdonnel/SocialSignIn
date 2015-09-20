using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Script.Serialization;

namespace SocialSignInApis.Apis.GoogleLogin {

    public class GoogleConnect {

        public static string ClientId { get; set; }
        public static string ClientSecret { get; set; }
        private const string googleApiUrl = "https://accounts.google.com/o/oauth2/";

        private WebRequest Web_Request { get; set; }
        private WebResponse Web_Response { get; set; }
        private string RedirectUri { get; set; }

        public GoogleConnect(string redirectUri) {
            this.RedirectUri = redirectUri;
        }

        public void Authorize(string fields) {
            HttpResponse Response = HttpContext.Current.Response;
            if (Response != null) {
                if (string.IsNullOrEmpty(fields)) {
                    fields = "profile%20email";
                }
                else {
                    string[] fieldList = fields.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                    string newFields = string.Empty;
                    for (int i = 0; i < fieldList.Length; i++) {
                        newFields += fieldList[i];
                        if (i < fieldList.Length - 1) {
                            newFields += "%20";
                        }
                    }
                    if (!string.IsNullOrEmpty(newFields)) {
                        fields = newFields;
                    }
                    else {
                        fields = "profile%20email";
                    }
                }

                Response.Redirect(googleApiUrl + "auth?client_id=" + ClientId + "&response_type=code&redirect_uri=" + HttpContext.Current.Server.UrlEncode(this.RedirectUri) + "&scope=" + fields + "&prompt=consent&include_granted_scopes=true");
            }
        }
        public string Fetch(string code, string node) {
            string jsonStr = string.Empty;

            try {
                string postData = "code=" + code + "&redirect_uri=" + HttpContext.Current.Server.UrlEncode(this.RedirectUri) + "&client_id=" + ClientId + "&client_secret=" + ClientSecret + "&grant_type=authorization_code";
                Web_Request = WebRequest.Create(googleApiUrl + "token?" + postData);
                Web_Request.Method = "POST";
                Web_Request.ContentType = "application/x-www-form-urlencoded";

                byte[] byteArray = Encoding.UTF8.GetBytes(postData);
                Web_Request.ContentLength = byteArray.Length;

                using (Stream dataStream = Web_Request.GetRequestStream()) {
                    dataStream.Write(byteArray, 0, byteArray.Length);
                }

                GoogleToken token = new GoogleToken();

                using (Web_Response = Web_Request.GetResponse()) {
                    using (Stream stream = Web_Response.GetResponseStream()) {
                        StreamReader reader = new StreamReader(stream);
                        token = new JavaScriptSerializer().Deserialize<GoogleToken>(reader.ReadToEnd());
                    }
                }

                jsonStr = GetUserInfo(token);
            }
            catch { }

            return jsonStr;
        }

        private string GetUserInfo(GoogleToken token) {
            string jsonStr = string.Empty;

            if (!string.IsNullOrEmpty(token.access_token)) {
                Web_Request = WebRequest.Create("https://www.googleapis.com/plus/v1/people/me?access_token=" + token.access_token);

                using (Web_Response = Web_Request.GetResponse()) {
                    using (Stream stream = Web_Response.GetResponseStream()) {
                        StreamReader reader = new StreamReader(stream);
                        jsonStr = reader.ReadToEnd();
                    }
                }
            }

            return jsonStr;
        }

    }


    public class GoogleToken {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string id_token { get; set; }
    }
    public class GoogleProfile {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public Image Image { get; set; }
        public List<Email> Emails { get; set; }
        public string Gender { get; set; }
        public string ObjectType { get; set; }
    }
    public class Email {
        public string Value { get; set; }
        public string Type { get; set; }
    }
    public class Image {
        public string Url { get; set; }
    }

}