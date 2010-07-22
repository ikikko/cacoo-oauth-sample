package oauth;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

/**
 * Hello world!
 * 
 */
public class App {
	public static void main(String[] args) {
		new App().execute();
	}

	public void execute() {

		String consumerKey = "**********";
		String consumerSecret = "************************";

		try {
			// コンシューマを生成
			CacooOauthConsumer consumer = new CacooOauthConsumer(consumerKey,
					consumerSecret, "oob");

			// リクエストトークンを取得するのに使うパラメータ
			Map<String, String> params = new HashMap<String, String>();
			params.put("scope", "https://cacoo.com/api/v1/diagrams.xml");
			// リクエストトークンを取得
			Map<String, String> result = consumer.getRequestToken(params);

			// ユーザ認証のURLを作成
			String authURL = consumer.authorizeURL + "?oauth_token="
					+ result.get("requestToken");
			System.out.println("以下のURLをWebブラウザで開いてください。");
			System.out.println(authURL);

			// ユーザ認証済みのリクエストトークンを取得
			System.out.print("verifierを入力してね：");
			String verifier = readLineFromStdin();
			result = consumer.getAccessToken(result.get("requestToken"),
					result.get("tokenSecret"), verifier);

			// Cacoo diagramsのデータを取得
			String response = consumer.getResource(
					"https://cacoo.com/api/v1/diagrams.xml",
					result.get("accessToken"), result.get("tokenSecret"));

			System.out.println(response);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 標準入力から一行取得して返す。
	 * 
	 * @return 入力された文字列
	 */
	public String readLineFromStdin() {
		String line = null;
		try {
			BufferedReader stdReader = new BufferedReader(
					new InputStreamReader(System.in));
			line = stdReader.readLine(); // ユーザの一行入力を待つ
			line = StringUtils.chomp(line);
			stdReader.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return line;
	}
}
