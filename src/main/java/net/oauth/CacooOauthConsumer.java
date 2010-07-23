package net.oauth;

import static net.oauth.ParameterStyle.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthServiceProvider;
import net.oauth.client.OAuthClient;
import net.oauth.client.httpclient4.HttpClient4;

/**
 * Cacoo OAuth コンシューマ。
 * 
 * @author ikikko
 */
public class CacooOauthConsumer {

	/** oauth request token URL. */
	public String requestTokenURL = "https://cacoo.com/oauth/request_token";
	/** oauth authorize URL. */
	public String authorizeURL = "https://cacoo.com/oauth/authorize";
	/** oauth access Token URL. */
	public String accessTokenURL = "https://cacoo.com/oauth/access_token";

	/** oauth consumer key. */
	private String consumerKey;
	/** oauth consumer secret. HMAC-SHA1で署名する時に使う */
	private String consumerSecret;
	/** callback url. ユーザーがCacooで認証した後にリダイレクトするURL */
	private String callbackURL;

	/**
	 * コンストラクタ。
	 * 
	 * @param consumerKey
	 * @param consumerSecret
	 * @param callbackURL
	 */
	public CacooOauthConsumer(String consumerKey, String consumerSecret,
			String callbackURL) {
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
		this.callbackURL = callbackURL;
	}

	/**
	 * Cacoo OAuthのサービスプロバイダを作成する。
	 * 
	 * @return Cacoo OAuth Service Provider
	 */
	public OAuthServiceProvider createCacooOAuthProvider() {
		return new OAuthServiceProvider(requestTokenURL, authorizeURL,
				accessTokenURL);
	}

	/**
	 * Cacoo OAuth用のコンシューマを作成する。
	 * 
	 * @return Cacoo OAuth Consumer
	 */
	public OAuthConsumer createConsumer() {
		OAuthConsumer consumer = new OAuthConsumer(callbackURL, consumerKey,
				consumerSecret, createCacooOAuthProvider());
		consumer.setProperty("parameterStyle", AUTHORIZATION_HEADER);
		return consumer;
	}

	/**
	 * Accessorとやらを作成する。
	 * 
	 * @return OAuth Accessor
	 */
	public OAuthAccessor createAccessor() {
		return new OAuthAccessor(createConsumer());
	}

	/**
	 * OAuth用のHTTPクライアントを作成する。
	 * 
	 * @return HTTPクライアント
	 */
	public OAuthClient createClient() {
		return new OAuthClient(new HttpClient4());
	}

	/**
	 * リクエストトークンを取得する。
	 * 
	 * @return requestTokenとtokenSecretが格納されたMap
	 * @throws IOException
	 * @throws OAuthException
	 * @throws URISyntaxException
	 */
	public Map<String, String> getRequestToken() throws IOException,
			OAuthException, URISyntaxException {
		return getRequestToken(null);
	}

	/**
	 * リクエストトークンを取得する。
	 * 
	 * @return requestTokenとtokenSecretが格納されたMap
	 * @throws IOException
	 * @throws OAuthException
	 * @throws URISyntaxException
	 */
	public Map<String, String> getRequestToken(Map<String, String> params)
			throws IOException, OAuthException, URISyntaxException {
		OAuthClient client = createClient();
		OAuthAccessor accessor = createAccessor();

		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth.OAUTH_CALLBACK, accessor.consumer.callbackURL);
		if (params != null) {
			parameters.putAll(params);
		}

		client.getRequestToken(accessor, "GET", parameters.entrySet());

		Map<String, String> ret = new HashMap<String, String>();
		ret.put("requestToken", accessor.requestToken);
		ret.put("tokenSecret", accessor.tokenSecret);

		return ret;
	}

	/**
	 * アクセストークンを取得する。
	 * 
	 * @param requestToken
	 * @param tokenSecret
	 * @param verifier
	 *            ユーザーとサービスプロバイダ間の認証が済んだことを示すもの
	 * @return accessTokenとtokenSecretが格納されたMap
	 * @throws IOException
	 * @throws OAuthException
	 * @throws URISyntaxException
	 */
	public Map<String, String> getAccessToken(String requestToken,
			String tokenSecret, String verifier) throws IOException,
			OAuthException, URISyntaxException {
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("oauth_token", requestToken);
		parameters.put("oauth_verifier", verifier);

		OAuthClient client = createClient();
		OAuthAccessor accessor = createAccessor();
		accessor.tokenSecret = tokenSecret;

		OAuthMessage response = client.getAccessToken(accessor, "GET",
				parameters.entrySet());

		Map<String, String> ret = new HashMap<String, String>();
		ret.put("accessToken", response.getParameter("oauth_token"));
		ret.put("tokenSecret", response.getParameter("oauth_token_secret"));

		return ret;
	}

	/**
	 * OAuth認証サービスにアクセスする。
	 * 
	 * @param url
	 * @param accessToken
	 * @param tokenSecret
	 * @return
	 * @throws IOException
	 * @throws OAuthException
	 * @throws URISyntaxException
	 */
	public String getResource(String url, String accessToken, String tokenSecret)
			throws IOException, OAuthException, URISyntaxException {
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("oauth_token", accessToken);

		OAuthClient client = createClient();
		OAuthAccessor accessor = createAccessor();
		accessor.tokenSecret = tokenSecret;

		OAuthMessage response = client.invoke(accessor, url,
				parameters.entrySet());

		return response.readBodyAsString();
	}
}
