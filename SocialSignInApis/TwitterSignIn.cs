using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Security;
using SocialSignInApis.Apis.TwitterLogin;

/// <summary>
/// Summary description for TwitterSignIn
/// </summary>
/// 

namespace SocialSignInApis.Twitter {
    public class TwitterSignIn {

        public static void Authorize() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                TwitterConnect.API_Key = ApiSettings.Default.TwitterConsumerKey;
                TwitterConnect.API_Secret = ApiSettings.Default.TwitterConsumerSecret;

                if (!TwitterConnect.IsAuthorized) {
                    TwitterConnect twitter = new TwitterConnect();
                    twitter.Authorize(SocialRedirectUrl.GetRedirectUrl(SocialSignIn.TwitterRedirectQuery));
                }
            }
        }
        public static void FinishSignIn() {
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                try {
                    TwitterConnect.API_Key = ApiSettings.Default.TwitterConsumerKey;
                    TwitterConnect.API_Secret = ApiSettings.Default.TwitterConsumerSecret;

                    if (TwitterConnect.IsAuthorized) {
                        TwitterConnect twitter = new TwitterConnect();
                        string json = twitter.FetchProfile();
                        TwitterUser twitterUser = new JavaScriptSerializer().Deserialize<TwitterUser>(json);

                        if (twitterUser != null) {
                            string userName = twitterUser.screen_name + "@Twitter"; // You can change this to be anything you want.
                            if (string.IsNullOrEmpty(userName)) {
                                userName = twitterUser.name.Replace(" ", "_") + "@Twitter";
                            }

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