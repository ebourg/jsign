package net.jsign;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.Proxy.Type;

import org.apache.tools.ant.BuildException;
import org.bouncycastle.util.encoders.Base64;

public final class ProxySettings {

	private static final String HTTP_HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization";

	public static final ProxySettings NO_PROXY = new ProxySettings(null, null, null);

	private Proxy proxy;
	private String user;
	private String password;

	public ProxySettings(String proxyUrl, String proxyUser, String proxyPassword) {

		if (proxyUrl != null && proxyUrl.trim().length() > 0) {
			try {

				// The default type for the proxy is HTTP
				Type proxyType = Proxy.Type.HTTP;

				URL url2;
				if (proxyUrl.startsWith("http")) {
					url2 = new URL(proxyUrl);
				} else {
					url2 = new URL("http://" + proxyUrl);
				}

				int port = url2.getPort() < 0 ? 80 : url2.getPort();
				proxy = new Proxy(proxyType, new InetSocketAddress(url2.getHost(), port));

			} catch (MalformedURLException e) {
				throw new BuildException("Could not set proxy: '" + proxyUrl + "'.", e);
			}
		} else {
			proxy = Proxy.NO_PROXY;
		}

		user = proxyUser;
		password = proxyPassword;
	}

	public Proxy getProxy() {
		return proxy;
	}

	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public HttpURLConnection openConnection(URL url) throws IOException {

		if (proxy != Proxy.NO_PROXY) {
			HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
			if (user != null && user.length() > 0) {
				String proxyCredentials = user + ":" + password;
				byte[] encodedPassword = Base64.encode(proxyCredentials.getBytes("UTF-8"));
				conn.setRequestProperty(HTTP_HEADER_PROXY_AUTHORIZATION, new String(encodedPassword));
			}
			return conn;
		} else {
			return (HttpURLConnection) url.openConnection();
		}

	}

	@Override
	public String toString() {
		return proxy.toString();
	}

}
