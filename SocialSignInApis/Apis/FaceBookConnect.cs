using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Script.Serialization;

namespace SocialSignInApis.Apis.FaceBookLogin {

    public class FaceBookConnect {

        private const string graphApiUrl = "https://graph.facebook.com/v2.11/";
        public static string API_Key { get; set; }
        public static string API_Secret { get; set; }

        public FaceBookConnect(string redirectUrl) {
            this.Redirect_Url = redirectUrl;
        }

        private WebRequest Web_Request { get; set; }
        private WebResponse Web_Response { get; set; }
        private string AccessToken { get; set; }
        private string Redirect_Url { get; set; }

        public void Authorize(string fields) {
            HttpResponse Response = HttpContext.Current.Response;
            if (Response != null) {
                if (!string.IsNullOrEmpty(fields)) {
                    fields = "public_profile," + fields;
                }
                else {
                    fields = "public_profile,email";
                }
                Response.Redirect("https://www.facebook.com/dialog/oauth?auth_type=rerequest&client_id=" + API_Key + "&redirect_uri=" + HttpContext.Current.Server.UrlEncode(this.Redirect_Url) + "&scope=" + fields);
            }
        }
        public string Fetch(string code, string node) {
            try {
                Web_Request = WebRequest.Create("https://graph.facebook.com/oauth/access_token?client_id=" + API_Key + "&redirect_uri=" + this.Redirect_Url + "&client_secret=" + API_Secret + "&code=" + code);
                Web_Request.Method = "GET";

                using (Web_Response = Web_Request.GetResponse()) {
                    using (Stream stream = Web_Response.GetResponseStream()) {
                        StreamReader reader = new StreamReader(stream);
                        string tempAccessToken = reader.ReadToEnd();
                        try {
                            FacebookAccessTokenRequest facebookAccess = new JavaScriptSerializer().Deserialize<FacebookAccessTokenRequest>(tempAccessToken);
                            AccessToken = facebookAccess.access_token;
                        }
                        catch {
                            AccessToken = tempAccessToken;
                        }
                    }
                }
            }
            catch { }

            return GetUserInfo(node);
        }

        private string GetUserInfo(string node) {
            string jsonStr = string.Empty;
            if (!string.IsNullOrEmpty(AccessToken)) {
                try {
                    Web_Request = WebRequest.Create(graphApiUrl + node + "?access_token=" + AccessToken);
                    Web_Request.Method = "GET";

                    using (Web_Response = Web_Request.GetResponse()) {
                        using (Stream stream = Web_Response.GetResponseStream()) {
                            StreamReader reader = new StreamReader(stream);
                            jsonStr = reader.ReadToEnd();
                        }
                    }

                    DeletePermissions(node);
                }
                catch { }
            }

            return jsonStr;
        }
        private void DeletePermissions(string node) {
            if (!string.IsNullOrEmpty(AccessToken)) {
                Web_Request = WebRequest.Create(graphApiUrl + node + "/permissions?access_token=" + AccessToken);
                Web_Request.Method = "DELETE";

                using (Web_Response = Web_Request.GetResponse()) {
                    using (Stream stream = Web_Response.GetResponseStream()) {
                        StreamReader reader = new StreamReader(stream);
                        FaceBookPermissions faceBookPermisssions = new JavaScriptSerializer().Deserialize<FaceBookPermissions>(reader.ReadToEnd());

                        if (faceBookPermisssions != null && faceBookPermisssions.success.ToLower() == "true") {
                            AccessToken = string.Empty;
                        }
                    }
                }
            }
        }
    }

    public class FaceBookPermissions {
        public string success { get; set; }
    }

    public class FacebookAccessTokenRequest {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string auth_type { get; set; }
    }

    public class FaceBookUser {
        public string id { get; set; }
        public string name { get; set; }
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string email { get; set; }
    }

}
