package oauth.signpost;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import oauth.signpost.basic.DefaultOAuthConsumer;

import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class Diagrams {
	public static void main(String[] args) throws Exception {
		// これはユーザによらない
		OAuthConsumer consumer = new DefaultOAuthConsumer(
				"***** Concumer key *****", "***** Consumer secret *****");

		// これはユーザごとに異なる
		consumer.setTokenWithSecret("***** Access token *****",
				"***** Token secret *****");

		// HTTPリクエスト
		URL url = new URL("https://cacoo.com/api/v1/diagrams.xml");
		HttpURLConnection request = (HttpURLConnection) url.openConnection();
		request.setRequestMethod("POST"); // HTTPメソッドはPOST
		consumer.sign(request); // リクエストに署名

		// レスポンスコード
		System.out.println(request.getResponseCode() + " "
				+ request.getResponseMessage());

		// 成功ならレスポンスボディをそのまま表示する
		if (request.getResponseCode() == HttpURLConnection.HTTP_OK) {
			BufferedReader br = new BufferedReader(new InputStreamReader(
					request.getInputStream()));
			String line = null;
			while ((line = br.readLine()) != null) {
				System.out.println(line);
			}
		}
		// 失敗ならエラーメッセージだけを表示する
		else {
			InputSource is = new InputSource(new BufferedReader(
					new InputStreamReader(request.getErrorStream())));
			XPath xpath = XPathFactory.newInstance().newXPath();
			Node error = (Node) xpath.evaluate("//error", is,
					XPathConstants.NODE);
			System.out.println(error.getTextContent());
		}
	}
}
