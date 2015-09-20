using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Security;
using SocialSignInApis.Apis.FaceBookLogin;

/// <summary>
/// Summary description for TwitterSignIn
/// </summary>
namespace SocialSignInApis.Facebook {
    public class FacebookSignIn {

        public static void Authorize() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                FaceBookConnect.API_Key = ApiSettings.Default.FacebookAppId;
                FaceBookConnect.API_Secret = ApiSettings.Default.FacebookAppSecret;

                FaceBookConnect facebookConnect = new FaceBookConnect(SocialRedirectUrl.GetRedirectUrl(SocialSignIn.FacebookRedirectQuery));
                facebookConnect.Authorize("email");
            }
        }
        public static void FinishSignIn() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                try {
                    string code = Request.QueryString["code"];
                    if (string.IsNullOrEmpty(code)) {
                        return;
                    }

                    FaceBookConnect.API_Key = ApiSettings.Default.FacebookAppId;
                    FaceBookConnect.API_Secret = ApiSettings.Default.FacebookAppSecret;

                    FaceBookConnect facebookConnect = new FaceBookConnect(Request.Url.AbsoluteUri.Split('?')[0] + SocialSignIn.FacebookRedirectQuery);
                    string json = facebookConnect.Fetch(code, "me");

                    FaceBookUser faceBookUser = new JavaScriptSerializer().Deserialize<FaceBookUser>(json);

                    if (faceBookUser != null) {
                        string username = faceBookUser.name.Replace(" ", "_") + "@Facebook"; // You can change this to be anything you want.
                        string profileImg = string.Format("https://graph.facebook.com/{0}/picture", faceBookUser.id); // Simple way to get the profile image of that user

                        // From here you will need to create the user on your own database or use some method to store the user information
                    }
                }
                catch (Exception e) {
                    // Add your own code in here to capture the error and log it
                }
            }
        }

    }
}