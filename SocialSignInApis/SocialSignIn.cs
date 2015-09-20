using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

/// <summary>
/// Summary description for SocialSignIn
/// </summary>
/// 

namespace SocialSignInApis {
    public class SocialSignIn {

        #region Constant Query Redirect Strings

        public const string GoogleRedirectQuery = "?SocialSignIn=Google";
        public const string TwitterRedirectQuery = "?SocialSignIn=Twitter";
        public const string FacebookRedirectQuery = "?SocialSignIn=Facebook";

        #endregion

        #region Attempt Login

        public static void GoogleSignIn() {
            Google.GoogleSignIn.Authorize();
        }
        public static void TwitterSignIn() {
            Twitter.TwitterSignIn.Authorize();
        }
        public static void FacebookSignIn() {
            Facebook.FacebookSignIn.Authorize();
        }

        #endregion

        public static void CheckSocialSignIn() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                switch (Request.QueryString["SocialSignIn"]) {
                    case "Google":
                        Google.GoogleSignIn.FinishSignIn();
                        break;

                    case "Twitter":
                        Twitter.TwitterSignIn.FinishSignIn();
                        break;

                    case "Facebook":
                        Facebook.FacebookSignIn.FinishSignIn();
                        break;
                }

                if (!string.IsNullOrEmpty(Request.QueryString["SocialSignIn"])) {
                    if (Request.QueryString.Count > 0) {
                        HttpResponse Response = HttpContext.Current.Response;
                        if (Response != null) {
                            Response.Redirect(Request.Url.AbsoluteUri.Split('?')[0]);
                        }
                    }
                }
            }
        }
    }
}
