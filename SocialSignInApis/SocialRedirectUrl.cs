using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

/// <summary>
/// Summary description for SocialRedirectUrl
/// </summary>
namespace SocialSignInApis {
    public class SocialRedirectUrl {

        public static string GetRedirectUrl(string query) {
            string result = string.Empty;
            HttpRequest Request = HttpContext.Current.Request;

            if (Request != null) {
                string currUrl = GetSitePath(Request);

                if (currUrl[currUrl.Length - 1] != '/') {
                    currUrl += "/";
                }

                result = Request.Url.Scheme + ":" + currUrl + ApiSettings.Default.RedirectPage + query;
            }

            return result;
        }

        public static string GetSitePath(HttpRequest request) {
            string absolutePath = string.Empty;
            try {
                string servername = HttpUtility.UrlEncode(request.ServerVariables["SERVER_NAME"]);
                absolutePath = "//" + HttpUtility.UrlEncode(request.ServerVariables["SERVER_NAME"]);
                if (servername == "localhost")
                    absolutePath += ":" + HttpUtility.UrlEncode(request.ServerVariables["SERVER_PORT"]) + request.ApplicationPath;

                else
                    absolutePath = "//" + HttpUtility.UrlEncode(request.ServerVariables["SERVER_NAME"]) + request.ApplicationPath;
            }
            catch (Exception e) {
                // Add your own code in here to capture the error and log it
            }
            return absolutePath;
        }

    }
}
