package oauth.signpost;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.basic.DefaultOAuthProvider;

public class TokenCreator {
	public static void main(String[] args) throws Exception {
		OAuthConsumer consumer = new DefaultOAuthConsumer(
				"***** Concumer key *****", "***** Consumer secret *****");

		OAuthProvider provider = new DefaultOAuthProvider(
				"https://cacoo.com/oauth/request_token",
				"https://cacoo.com/oauth/access_token",
				"https://cacoo.com/oauth/authorize");

		String authUrl = provider.retrieveRequestToken(consumer,
				OAuth.OUT_OF_BAND);
		System.out.println("このURLにアクセスし、表示されるPINを入力してください。");
		System.out.println(authUrl);
		System.out.print("PIN:");

		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String pin = br.readLine();

		provider.retrieveAccessToken(consumer, pin);
		System.out.println("Access token: " + consumer.getToken());
		System.out.println("Token secret: " + consumer.getTokenSecret());
	}
}
