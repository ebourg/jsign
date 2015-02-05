package net.jsign.proxy;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class PESignerProxySelector extends ProxySelector {

	private ProxySelector parentSelector;
	private List<Proxy> proxies;

	public PESignerProxySelector(ProxySelector parentSelector, Proxy... proxies) {
		this.parentSelector = parentSelector;
		this.proxies = Arrays.asList(proxies);
	}
	
	@Override
	public List<Proxy> select(URI uri) {

		// Check the arguments
		if (uri == null) {
			throw new IllegalArgumentException("URI can't be null.");
		}

		// Is it HTTP or HTTPS?
		String protocol = uri.getScheme();
		if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol)) {
			List<Proxy> l = new ArrayList<Proxy>(proxies);
			return l;
		}

		// For any other protocol ...
		if (parentSelector != null) {
			return parentSelector.select(uri);
		} else {
			return Collections.singletonList(Proxy.NO_PROXY);
		}
	}

	@Override
	public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
		// As there is only one proxy setting the connection should fail. There
		// is no fallback proxy, except NO_PROXY.
	}

}
