package net.jsign.proxy;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

public class PESignerProxyAuthenticator extends Authenticator {

	private String proxyHost;
	private String proxyUser;
	private String proxyPassword;

	public PESignerProxyAuthenticator(String proxyHost, String proxyUser, String proxyPassword) {
		this.proxyHost = proxyHost == null ? "" : proxyHost;
		this.proxyUser = proxyUser;
		this.proxyPassword = proxyPassword;
	}
	
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {

		// First check if the requestor is a proxy.
		RequestorType requestorType = getRequestorType();
		switch (requestorType) {
		case PROXY:
			// Second check if the requestor is the proxy server
			if(proxyHost.equalsIgnoreCase(getRequestingHost())) {
				return new PasswordAuthentication(proxyUser, proxyPassword.toCharArray());
			}
			break;
		case SERVER:
			break;
		default:
			break;
		}

		return super.getPasswordAuthentication();
	}

}
