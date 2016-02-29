package net.jsign.proxy;

import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URL;

public final class PESignerProxySettings {

	private PESignerProxySettings() {
	}

	public static void initialize(String proxyUrl, String proxyUser, String proxyPassword) throws MalformedURLException {

		// Do nothing if there is no proxy url.
		if (proxyUrl != null && proxyUrl.trim().length() > 0) {
			URL url2;
			if (proxyUrl.startsWith("http")) {
				url2 = new URL(proxyUrl);
			} else {
				url2 = new URL("http://" + proxyUrl);
			}

			int port = url2.getPort() < 0 ? 80 : url2.getPort();
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(url2.getHost(), port));

			PESignerProxySelector proxySelector = new PESignerProxySelector(ProxySelector.getDefault(), proxy);
			ProxySelector.setDefault(proxySelector);

			if (proxyUser != null && proxyUser.length() > 0) {
				PESignerProxyAuthenticator proxyAuthenticator = new PESignerProxyAuthenticator(url2.getHost(), proxyUser, proxyPassword);
				Authenticator.setDefault(proxyAuthenticator);
			}
		}

	}

}
