package org.renci.xmpp_pubsub;

/**
 * 
 * @author ibaldin
 *
 */
public interface IPubSubReconnectCallback {

	/**
	 * 
	 */
	public void onReconnect();
	/**
	 * 
	 * @return - name of the callback
	 */
	public String name();
}
