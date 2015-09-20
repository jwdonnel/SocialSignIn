using System;
using System.Collections;
using System.Collections.Specialized;
using System.Data;
using System.IO;
using System.Runtime.CompilerServices;
using System.Web;
using System.Web.SessionState;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Net;


namespace SocialSignInApis.Apis.TwitterLogin {
    public class TwitterConnect {
        public static string API_Key {
            get;
            set;
        }

        public static string API_Secret {
            get;
            set;
        }

        public string CallBackUrl {
            get {
                string str;
                if (HttpContext.Current.Session["CallBackUrl"] == null) {
                    str = null;
                }
                else {
                    str = HttpContext.Current.Session["CallBackUrl"].ToString();
                }
                return str;
            }
            set {
                HttpContext.Current.Session["CallBackUrl"] = value;
            }
        }

        public static bool IsAuthorized {
            get {
                bool flag = !HttpContext.Current.Request.QueryString["oauth_token"].IsEmpty();
                return flag;
            }
        }

        public static bool IsDenied {
            get {
                bool flag = !HttpContext.Current.Request.QueryString["denied"].IsEmpty();
                return flag;
            }
        }

        public string OAuthToken {
            get {
                string str;
                if (HttpContext.Current.Session["OAuthToken"] == null) {
                    str = null;
                }
                else {
                    str = HttpContext.Current.Session["OAuthToken"].ToString();
                }
                return str;
            }
            set {
                HttpContext.Current.Session["OAuthToken"] = value;
            }
        }

        public string OAuthTokenSecret {
            get {
                string str;
                if (HttpContext.Current.Session["OAuthTokenSecret"] == null) {
                    str = null;
                }
                else {
                    str = HttpContext.Current.Session["OAuthTokenSecret"].ToString();
                }
                return str;
            }
            set {
                HttpContext.Current.Session["OAuthTokenSecret"] = value;
            }
        }

        public TwitterConnect() {
        }

        public void Authorize(string callBackUrl) {
            this.OAuthToken = null;
            this.OAuthTokenSecret = null;
            this.CallBackUrl = callBackUrl;
            TwitterAuth twitterAuth = new TwitterAuth(TwitterConnect.API_Key, TwitterConnect.API_Secret, this.CallBackUrl);
            HttpContext.Current.Response.Redirect(twitterAuth.AuthorizationLinkGet());
        }

        public string FetchProfile(string screenName) {
            return this.FetchTwitterProfile(screenName);
        }

        public string FetchProfile() {
            return this.FetchTwitterProfile(null);
        }

        private string FetchTwitterProfile(string screenName) {
            string empty = string.Empty;
            string str = string.Empty;
            TwitterAuth twitterAuth = new TwitterAuth(TwitterConnect.API_Key, TwitterConnect.API_Secret, this.CallBackUrl);
            if ((this.OAuthToken == null ? false : this.OAuthTokenSecret != null)) {
                twitterAuth.TokenSecret = this.OAuthToken;
                twitterAuth.Token = this.OAuthTokenSecret;
                twitterAuth.OAuthVerifier = HttpContext.Current.Request.QueryString["oauth_verifier"];
            }
            else {
                twitterAuth.AccessTokenGet(HttpContext.Current.Request.QueryString["oauth_token"], HttpContext.Current.Request.QueryString["oauth_verifier"]);
                this.OAuthToken = twitterAuth.TokenSecret;
                this.OAuthTokenSecret = twitterAuth.Token;
            }
            if (twitterAuth.TokenSecret.Length <= 0) {
                throw new Exception("Invalid Twitter token.");
            }
            empty = "https://api.twitter.com/1.1/users/show.json";
            if (screenName == null) {
                screenName = twitterAuth.ScreenName;
            }
            str = twitterAuth.OAuthWebRequest(TwitterAuth.Method.GET, empty, string.Format("screen_name={0}", screenName));

            return str;
        }

        public void Tweet(string content) {
            string empty = string.Empty;
            string str = string.Empty;
            TwitterAuth twitterAuth = new TwitterAuth(TwitterConnect.API_Key, TwitterConnect.API_Secret, this.CallBackUrl);
            if ((this.OAuthToken == null ? false : this.OAuthTokenSecret != null)) {
                twitterAuth.TokenSecret = this.OAuthToken;
                twitterAuth.Token = this.OAuthTokenSecret;
                twitterAuth.OAuthVerifier = HttpContext.Current.Request.QueryString["oauth_verifier"];
            }
            else {
                twitterAuth.AccessTokenGet(HttpContext.Current.Request.QueryString["oauth_token"], HttpContext.Current.Request.QueryString["oauth_verifier"]);
                this.OAuthToken = twitterAuth.TokenSecret;
                this.OAuthTokenSecret = twitterAuth.Token;
            }
            if (twitterAuth.TokenSecret.Length > 0) {
                empty = "https://api.twitter.com/1.1/statuses/update.json";
                str = twitterAuth.OAuthWebRequest(TwitterAuth.Method.POST, empty, string.Concat("status=", TwitterBase.UrlEncode(content)));
            }
        }
    }

    public class TwitterUser {
        public string id { get; set; }
        public string name { get; set; }
        public string screen_name { get; set; }
        public string profile_image_url { get; set; }
    }

    internal class TwitterBase {
        protected const string OAuthVersion = "1.0";

        protected const string OAuthParameterPrefix = "oauth_";

        protected const string OAuthConsumerKeyKey = "oauth_consumer_key";

        protected const string OAuthCallbackKey = "oauth_callback";

        protected const string OAuthVersionKey = "oauth_version";

        protected const string OAuthSignatureMethodKey = "oauth_signature_method";

        protected const string OAuthSignatureKey = "oauth_signature";

        protected const string OAuthTimestampKey = "oauth_timestamp";

        protected const string OAuthNonceKey = "oauth_nonce";

        protected const string OAuthTokenKey = "oauth_token";

        protected const string OAuthTokenSecretKey = "oauth_token_secret";

        protected const string OAuthVerifierKey = "oauth_verifier";

        protected const string HMACSHA1SignatureType = "HMAC-SHA1";

        protected const string PlainTextSignatureType = "PLAINTEXT";

        protected const string RSASHA1SignatureType = "RSA-SHA1";

        protected Random random = new Random();

        protected static string unreservedChars;

        static TwitterBase() {
            TwitterBase.unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        }

        public TwitterBase() {
        }

        private string ComputeHash(HashAlgorithm hashAlgorithm, string data) {
            if (hashAlgorithm == null) {
                throw new ArgumentNullException("hashAlgorithm");
            }
            if (string.IsNullOrEmpty(data)) {
                throw new ArgumentNullException("data");
            }
            byte[] bytes = Encoding.ASCII.GetBytes(data);
            return Convert.ToBase64String(hashAlgorithm.ComputeHash(bytes));
        }

        public virtual string GenerateNonce() {
            return this.random.Next(123400, 9999999).ToString();
        }

        public string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string tokenSecret, string callBackUrl, string oauthVerifier, string httpMethod, string timeStamp, string nonce, out string normalizedUrl, out string normalizedRequestParameters) {
            string str = this.GenerateSignature(url, consumerKey, consumerSecret, token, tokenSecret, callBackUrl, oauthVerifier, httpMethod, timeStamp, nonce, TwitterBase.SignatureTypes.HMACSHA1, out normalizedUrl, out normalizedRequestParameters);
            return str;
        }

        public string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string tokenSecret, string callBackUrl, string oauthVerifier, string httpMethod, string timeStamp, string nonce, TwitterBase.SignatureTypes signatureType, out string normalizedUrl, out string normalizedRequestParameters) {
            string str;
            normalizedUrl = null;
            normalizedRequestParameters = null;
            switch (signatureType) {
                case TwitterBase.SignatureTypes.HMACSHA1: {
                        string str1 = this.GenerateSignatureBase(url, consumerKey, token, tokenSecret, callBackUrl, oauthVerifier, httpMethod, timeStamp, nonce, "HMAC-SHA1", out normalizedUrl, out normalizedRequestParameters);
                        HMACSHA1 hMACSHA1 = new HMACSHA1() {
                            Key = Encoding.ASCII.GetBytes(string.Format("{0}&{1}", TwitterBase.UrlEncode(consumerSecret), (string.IsNullOrEmpty(tokenSecret) ? string.Empty : TwitterBase.UrlEncode(tokenSecret))))
                        };
                        str = this.GenerateSignatureUsingHash(str1, hMACSHA1);
                        break;
                    }
                case TwitterBase.SignatureTypes.PLAINTEXT: {
                        str = HttpUtility.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));
                        break;
                    }
                case TwitterBase.SignatureTypes.RSASHA1: {
                        throw new NotImplementedException();
                    }
                default: {
                        throw new ArgumentException("Unknown signature type", "signatureType");
                    }
            }
            return str;
        }

        public string GenerateSignatureBase(Uri url, string consumerKey, string token, string tokenSecret, string callBackUrl, string oauthVerifier, string httpMethod, string timeStamp, string nonce, string signatureType, out string normalizedUrl, out string normalizedRequestParameters) {
            bool flag;
            if (token == null) {
                token = string.Empty;
            }
            if (tokenSecret == null) {
                tokenSecret = string.Empty;
            }
            if (string.IsNullOrEmpty(consumerKey)) {
                throw new ArgumentNullException("consumerKey");
            }
            if (string.IsNullOrEmpty(httpMethod)) {
                throw new ArgumentNullException("httpMethod");
            }
            if (string.IsNullOrEmpty(signatureType)) {
                throw new ArgumentNullException("signatureType");
            }
            normalizedUrl = null;
            normalizedRequestParameters = null;
            List<TwitterBase.QueryParameter> queryParameters = this.GetQueryParameters(url.Query);
            queryParameters.Add(new TwitterBase.QueryParameter("oauth_version", "1.0"));
            queryParameters.Add(new TwitterBase.QueryParameter("oauth_nonce", nonce));
            queryParameters.Add(new TwitterBase.QueryParameter("oauth_timestamp", timeStamp));
            queryParameters.Add(new TwitterBase.QueryParameter("oauth_signature_method", signatureType));
            queryParameters.Add(new TwitterBase.QueryParameter("oauth_consumer_key", consumerKey));
            if (!string.IsNullOrEmpty(callBackUrl)) {
                queryParameters.Add(new TwitterBase.QueryParameter("oauth_callback", TwitterBase.UrlEncode(callBackUrl)));
            }
            if (!string.IsNullOrEmpty(oauthVerifier)) {
                queryParameters.Add(new TwitterBase.QueryParameter("oauth_verifier", oauthVerifier));
            }
            if (!string.IsNullOrEmpty(token)) {
                queryParameters.Add(new TwitterBase.QueryParameter("oauth_token", token));
            }
            queryParameters.Sort(new TwitterBase.QueryParameterComparer());
            normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
            if (!(url.Scheme == "http") || url.Port != 80) {
                flag = (url.Scheme != "https" ? false : url.Port == 443);
            }
            else {
                flag = true;
            }
            if (!flag) {
                normalizedUrl = string.Concat(normalizedUrl, ":", url.Port);
            }
            normalizedUrl = string.Concat(normalizedUrl, url.AbsolutePath);
            normalizedRequestParameters = this.NormalizeRequestParameters(queryParameters);
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendFormat("{0}&", httpMethod.ToUpper());
            stringBuilder.AppendFormat("{0}&", TwitterBase.UrlEncode(normalizedUrl));
            stringBuilder.AppendFormat("{0}", TwitterBase.UrlEncode(normalizedRequestParameters));
            return stringBuilder.ToString();
        }

        public string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash) {
            return this.ComputeHash(hash, signatureBase);
        }

        public virtual string GenerateTimeStamp() {
            TimeSpan utcNow = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(utcNow.TotalSeconds).ToString();
        }

        private List<TwitterBase.QueryParameter> GetQueryParameters(string parameters) {
            if (parameters.StartsWith("?")) {
                parameters = parameters.Remove(0, 1);
            }
            List<TwitterBase.QueryParameter> queryParameters = new List<TwitterBase.QueryParameter>();
            if (!string.IsNullOrEmpty(parameters)) {
                char[] chrArray = new char[] { '&' };
                string[] strArrays = parameters.Split(chrArray);
                for (int i = 0; i < (int)strArrays.Length; i++) {
                    string str = strArrays[i];
                    if ((string.IsNullOrEmpty(str) ? false : !str.StartsWith("oauth_"))) {
                        if (str.IndexOf('=') <= -1) {
                            queryParameters.Add(new TwitterBase.QueryParameter(str, string.Empty));
                        }
                        else {
                            chrArray = new char[] { '=' };
                            string[] strArrays1 = str.Split(chrArray);
                            queryParameters.Add(new TwitterBase.QueryParameter(strArrays1[0], strArrays1[1]));
                        }
                    }
                }
            }
            return queryParameters;
        }

        protected string NormalizeRequestParameters(IList<TwitterBase.QueryParameter> parameters) {
            StringBuilder stringBuilder = new StringBuilder();
            TwitterBase.QueryParameter item = null;
            for (int i = 0; i < parameters.Count; i++) {
                item = parameters[i];
                stringBuilder.AppendFormat("{0}={1}", item.Name, item.Value);
                if (i < parameters.Count - 1) {
                    stringBuilder.Append("&");
                }
            }
            return stringBuilder.ToString();
        }

        public static string UrlEncode(string value) {
            StringBuilder stringBuilder = new StringBuilder();
            string str = value;
            for (int i = 0; i < str.Length; i++) {
                char chr = str[i];
                if (TwitterBase.unreservedChars.IndexOf(chr) == -1) {
                    stringBuilder.Append(string.Concat('%', string.Format("{0:X2}", (int)chr)));
                }
                else {
                    stringBuilder.Append(chr);
                }
            }
            return stringBuilder.ToString();
        }

        protected class QueryParameter {
            private string name;

            private string @value;

            public string Name {
                get {
                    return this.name;
                }
            }

            public string Value {
                get {
                    return this.@value;
                }
            }

            public QueryParameter(string name, string value) {
                this.name = name;
                this.@value = value;
            }
        }

        protected class QueryParameterComparer : IComparer<TwitterBase.QueryParameter> {
            public QueryParameterComparer() {
            }

            public int Compare(TwitterBase.QueryParameter x, TwitterBase.QueryParameter y) {
                int num;
                num = (!(x.Name == y.Name) ? string.Compare(x.Name, y.Name) : string.Compare(x.Value, y.Value));
                return num;
            }
        }

        public enum SignatureTypes {
            HMACSHA1,
            PLAINTEXT,
            RSASHA1
        }
    }

    internal class TwitterAuth : TwitterBase {
        public const string RequestToken = "https://api.twitter.com/oauth/request_token";

        public const string Authorize = "https://api.twitter.com/oauth/authorize";

        public const string AccessToken = "https://api.twitter.com/oauth/access_token";

        private string consumerKey = string.Empty;

        private string consumerSecret = string.Empty;

        private string token = string.Empty;

        private string tokenSecret = string.Empty;

        private string screenName = string.Empty;

        private string twitterId = string.Empty;

        private string callBackUrl = "oob";

        private string oauthVerifier = string.Empty;

        public string CallBackUrl {
            get {
                return this.callBackUrl;
            }
            set {
                this.callBackUrl = value;
            }
        }

        public string ConsumerKey {
            get {
                return this.consumerKey;
            }
            set {
                this.consumerKey = value;
            }
        }

        public string ConsumerSecret {
            get {
                return this.consumerSecret;
            }
            set {
                this.consumerSecret = value;
            }
        }

        public string OAuthVerifier {
            get {
                return this.oauthVerifier;
            }
            set {
                this.oauthVerifier = value;
            }
        }

        public string ScreenName {
            get {
                return this.screenName;
            }
            set {
                this.screenName = value;
            }
        }

        public string Token {
            get {
                return this.token;
            }
            set {
                this.token = value;
            }
        }

        public string TokenSecret {
            get {
                return this.tokenSecret;
            }
            set {
                this.tokenSecret = value;
            }
        }

        public string TwitterId {
            get {
                return this.twitterId;
            }
            set {
                this.twitterId = value;
            }
        }

        internal TwitterAuth(string key, string secret, string callBackUrl) {
            this.ConsumerKey = key;
            this.ConsumerSecret = secret;
            this.CallBackUrl = callBackUrl;
        }

        public void AccessTokenGet(string authToken, string oauthVerifier) {
            this.Token = authToken;
            this.OAuthVerifier = oauthVerifier;
            string str = this.OAuthWebRequest(TwitterAuth.Method.GET, "https://api.twitter.com/oauth/access_token", string.Empty);
            if (str.Length > 0) {
                NameValueCollection nameValueCollection = HttpUtility.ParseQueryString(str);
                if (nameValueCollection["oauth_token"] != null) {
                    this.Token = nameValueCollection["oauth_token"];
                }
                if (nameValueCollection["oauth_token_secret"] != null) {
                    this.TokenSecret = nameValueCollection["oauth_token_secret"];
                }
                if (nameValueCollection["screen_name"] != null) {
                    this.ScreenName = nameValueCollection["screen_name"];
                }
                if (nameValueCollection["user_id"] != null) {
                    this.TwitterId = nameValueCollection["user_id"];
                }
            }
        }

        public string AuthorizationLinkGet() {
            string str = null;
            string str1 = this.OAuthWebRequest(TwitterAuth.Method.GET, "https://api.twitter.com/oauth/request_token", string.Empty);
            if (str1.Length > 0) {
                NameValueCollection nameValueCollection = HttpUtility.ParseQueryString(str1);
                if (nameValueCollection["oauth_callback_confirmed"] != null) {
                    if (nameValueCollection["oauth_callback_confirmed"] != "true") {
                        throw new Exception("OAuth callback not confirmed.");
                    }
                }
                if (nameValueCollection["oauth_token"] != null) {
                    str = string.Concat("https://api.twitter.com/oauth/authorize?oauth_token=", nameValueCollection["oauth_token"]);
                }
            }
            return str;
        }

        public string OAuthWebRequest(TwitterAuth.Method method, string url, string postData) {
            string empty = string.Empty;
            string str = string.Empty;
            string empty1 = string.Empty;
            if ((method == TwitterAuth.Method.POST || method == TwitterAuth.Method.DELETE ? true : method == TwitterAuth.Method.GET)) {
                if (postData.Length > 0) {
                    NameValueCollection nameValueCollection = HttpUtility.ParseQueryString(postData);
                    postData = string.Empty;
                    string[] allKeys = nameValueCollection.AllKeys;
                    for (int i = 0; i < (int)allKeys.Length; i++) {
                        string str1 = allKeys[i];
                        if (postData.Length > 0) {
                            postData = string.Concat(postData, "&");
                        }
                        nameValueCollection[str1] = HttpUtility.UrlDecode(nameValueCollection[str1]);
                        nameValueCollection[str1] = TwitterBase.UrlEncode(nameValueCollection[str1]);
                        postData = string.Concat(postData, str1, "=", nameValueCollection[str1]);
                    }
                    if (url.IndexOf("?") <= 0) {
                        url = string.Concat(url, "?");
                    }
                    else {
                        url = string.Concat(url, "&");
                    }
                    url = string.Concat(url, postData);
                }
            }
            Uri uri = new Uri(url);
            string str2 = this.GenerateNonce();
            string str3 = this.GenerateTimeStamp();
            string str4 = base.GenerateSignature(uri, this.ConsumerKey, this.ConsumerSecret, this.Token, this.TokenSecret, this.CallBackUrl, this.OAuthVerifier, method.ToString(), str3, str2, out empty, out str);
            str = string.Concat(str, "&oauth_signature=", TwitterBase.UrlEncode(str4));
            if ((method == TwitterAuth.Method.POST ? true : method == TwitterAuth.Method.DELETE)) {
                postData = str;
                str = string.Empty;
            }
            if (str.Length > 0) {
                empty = string.Concat(empty, "?");
            }
            empty1 = this.WebRequest(method, string.Concat(empty, str), postData);
            return empty1;
        }

        public string WebRequest(TwitterAuth.Method method, string url, string postData) {
            HttpWebRequest str = null;
            StreamWriter streamWriter = null;
            string empty = string.Empty;
            str = System.Net.WebRequest.Create(url) as HttpWebRequest;
            str.Method = method.ToString();
            str.ServicePoint.Expect100Continue = false;
            if ((method == TwitterAuth.Method.POST ? true : method == TwitterAuth.Method.DELETE)) {
                str.ContentType = "application/x-www-form-urlencoded";
                streamWriter = new StreamWriter(str.GetRequestStream());
                try {
                    try {
                        streamWriter.Write(postData);
                    }
                    catch {
                        throw;
                    }
                }
                finally {
                    streamWriter.Close();
                    streamWriter = null;
                }
            }
            empty = this.WebResponseGet(str);
            str = null;
            return empty;
        }

        public string WebResponseGet(HttpWebRequest webRequest) {
            StreamReader streamReader = null;
            string empty = string.Empty;
            try {
                try {
                    streamReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
                    empty = streamReader.ReadToEnd();
                }
                catch {
                    throw;
                }
            }
            finally {
                webRequest.GetResponse().GetResponseStream().Close();
                streamReader.Close();
                streamReader = null;
            }
            return empty;
        }

        public enum Method {
            GET,
            POST,
            DELETE
        }
    }

    internal static class Extensions {
        internal static bool IsEmpty(this string value) {
            return string.IsNullOrEmpty(value);
        }
    }
}