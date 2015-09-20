using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Security;
using System.Web.SessionState;
using SocialSignInApis.Apis.GoogleLogin;

/// <summary>
/// Summary description for GoogleSignIn
/// </summary>
namespace SocialSignInApis.Google {

    public class GoogleSignIn {

        public static void Authorize() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                GoogleConnect.ClientId = ApiSettings.Default.GoogleClientId;
                GoogleConnect.ClientSecret = ApiSettings.Default.GoogleClientSecret;

                GoogleConnect googleConnect = new GoogleConnect(SocialRedirectUrl.GetRedirectUrl(SocialSignIn.GoogleRedirectQuery));
                googleConnect.Authorize("profile,email");
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

                    GoogleConnect.ClientId = ApiSettings.Default.GoogleClientId;
                    GoogleConnect.ClientSecret = ApiSettings.Default.GoogleClientSecret;

                    GoogleConnect googleConnect = new GoogleConnect(Request.Url.AbsoluteUri.Split('?')[0] + SocialSignIn.GoogleRedirectQuery);
                    string json = googleConnect.Fetch(code, "me");

                    GoogleProfile profile = new JavaScriptSerializer().Deserialize<GoogleProfile>(json);
                    if (profile != null && profile.Emails.Count > 0) {
                        foreach (Email email in profile.Emails) {
                            string username = email.Value.Replace(email.Value.Substring(email.Value.IndexOf("@")), "").Replace(" ", "_") + "@Google"; // You can change this to be anything you want.

                            // From here you will need to create the user on your own database or use some method to store the user information
                        }
                    }
                }
                catch (Exception e) {
                    // Add your own code in here to capture the error and log it
                }
            }
        }

    }

}