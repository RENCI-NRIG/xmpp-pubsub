package org.renci.xmpp_pubsub;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.log4j.Logger;
import org.jivesoftware.smack.AccountManager;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smackx.packet.DiscoverItems;
import org.jivesoftware.smackx.pubsub.AccessModel;
import org.jivesoftware.smackx.pubsub.ConfigureForm;
import org.jivesoftware.smackx.pubsub.FormType;
import org.jivesoftware.smackx.pubsub.LeafNode;
import org.jivesoftware.smackx.pubsub.Node;
import org.jivesoftware.smackx.pubsub.PayloadItem;
import org.jivesoftware.smackx.pubsub.PubSubManager;
import org.jivesoftware.smackx.pubsub.SimplePayload;
import org.jivesoftware.smackx.pubsub.Subscription;
import org.jivesoftware.smackx.pubsub.listener.ItemEventListener;

/**
 * This is ORCA-specific XMPP pubsub class that relies on smack and smackx libraries
 * @author ibaldin
 *
 */
public class XMPPPubSub implements CallbackHandler{
	private static final String ORCA_SLICELIST_NS = "pubsub:orca:sliceList";
	private static final String SLICE_LIST = "sliceList";
	private static final String ORCA_PLD_NS = "pubsub:orca:manifest";
	private static final String ORCA_PLD_ROOT = "manifest";
	private static final String PUBSUB_SERVER_PREFIX = "pubsub.";
	// be sure to have no spaces
	private static final String PUBSUB_PUBLISHER_RESOURCE = "ORCA-PubSub";
	Logger logger;
	XMPPConnection xmppCon = null;
	String server, user, password;
	int port;
	PubSubManager manager;
	String resource = PUBSUB_PUBLISHER_RESOURCE;

	private boolean usecertificate = false;
	private String keystorepath, keystoretype, truststorepath, truststorepass;
	private final IPubSubReconnectCallback cb; 

	/**
	 *
	 * @param s - server name
	 * @param prt - port number
	 * @param u - username
	 * @param p - password
	 * @param l - logger object
	 */
	public XMPPPubSub(String s, int prt, String u, String p, Logger l, IPubSubReconnectCallback _cb) {
		logger = l;
		server = s;
		port = prt;
		user = u;
		password = p;
		cb = _cb;
	}

	public XMPPPubSub(String s, int prt, String u, String p, String r, Logger l, IPubSubReconnectCallback _cb) {
		logger = l;
		server = s;
		port = prt;
		user = u;
		password = p;
		resource = r;
		cb = _cb;
	}

	public XMPPPubSub(String s, int prt, String u, String p, String kspath, String kstype, String tspath, String tspass, Logger l, IPubSubReconnectCallback _cb) {
		logger = l;
		server = s;
		port = prt;
		user = u;
		password = p;
		keystorepath = kspath;
		keystoretype = kstype;
		truststorepath = tspath;
		truststorepass = tspass;
		usecertificate = true;
		cb = _cb;
	}

	public XMPPPubSub(String s, int prt, String u, String p, String kspath, String kstype, String tspath, String tspass, String r, Logger l, IPubSubReconnectCallback _cb) {
		logger = l;
		server = s;
		port = prt;
		user = u;
		password = p;
		keystorepath = kspath;
		keystoretype = kstype;
		truststorepath = tspath;
		truststorepass = tspass;
		usecertificate = true;
		resource = r;
		cb = _cb;
	}

	/**
	 * Connect, create account and disconnect. Next time simple login can be used.
	 */
	public void createAccountAndDisconnect(){

		int errorCode;

		logger.info("Trying to create client account on the server for user: " + user);
		logger.info("Establishing connection with XMPP server " + server + ":" + port);
		ConnectionConfiguration config = new ConnectionConfiguration(server, port);
		config.setCompressionEnabled(true);

		// Create a connection and connect to the XMPP server
		xmppCon = new XMPPConnection(config);
		try {
			xmppCon.connect();
			// Log into the server
		} catch (XMPPException e) {
			logger.error("Unable to connect to XMPP server: " + e);
		}

		// Try creating client account on the server
		try {
			final AccountManager accountManager = new AccountManager(xmppCon);
			accountManager.createAccount(user, password);
		} catch (XMPPException e) {
			XMPPError error = e.getXMPPError();
			if (error != null) {
				errorCode = error.getCode();
				if(errorCode == 409){
					logger.info("Account already exists on the server for user: " + user);
				}
				else {
					logger.error("Error while creating new account for user: " + user);
					//System.exit(0);
				}
			}
			else {
				errorCode = 500; // internal server error
				logger.error("Internal server error while creating new account for user: " + user);
				//System.exit(0);
			}
		} catch (Exception ee) {
			logger.error("Unspecified error while creating new account: " + ee);
		}

		// Disconnect from the server
		//logger.info("Disconnecting from XMPP server");
		if ((xmppCon != null) && (xmppCon.isConnected())){
                    try {
			xmppCon.disconnect();
                    }
                    catch (NullPointerException npe) {
                        logger.error("Working around NPE in Smack libraries at connection disconnect.");
                        xmppCon = null;
                    }
		}

	}

	protected void logout() {
            try {
		xmppCon.disconnect();
            }
            catch (NullPointerException npe) {
                logger.error("Working around NPE in Smack libraries at connection disconnect.");
                xmppCon = null;
            }
	}

	/**
	 * Login to existing account
	 */
	protected void login() {


		logger.info("(Re)Establishing connection with XMPP server " + server + ":" + port);
		ConnectionConfiguration config = new ConnectionConfiguration(server, port);
		config.setCompressionEnabled(true);
		config.setSASLAuthenticationEnabled(true);
		//Addittional configurations

		if(usecertificate){
			config.setKeystorePath(keystorepath);
			config.setKeystoreType(keystoretype);
			config.setTruststorePath(truststorepath);
			config.setTruststorePassword(truststorepass);
			config.setCallbackHandler(this);

			config.setSecurityMode(SecurityMode.enabled);
			SASLAuthentication.supportSASLMechanism("EXTERNAL");
			config.setReconnectionAllowed(true);
			config.setRosterLoadedAtLogin(true);
			//config.setSendPresence(false);

			xmppCon = new XMPPConnection(config, this);

			try {
				xmppCon.connect();
				String usingTLS = (xmppCon.isUsingTLS() == true) ? "" : " *NOT* ";
				String secure = (xmppCon.isSecureConnection() == true) ? "" : " *NOT* ";
				logger.info("Connection is "
						+ usingTLS
						+ "using TLS and therefore is: "
						+ secure
						+ "secure.");

				Thread.sleep(3 * 1000); // Something about timing in the forums

				// Log into the server with random resource
				String rand = UUID.randomUUID().toString();
				xmppCon.login(user, password, resource + "-" + rand);
				logger.info("Logged " + user + "@" + server + " in using resource " + resource + "-" + rand);

				// create pubsub manager
				manager = new PubSubManager(xmppCon, PUBSUB_SERVER_PREFIX + server);
			} catch (XMPPException e) {
				logger.error("Unable to connect to XMPP server: " + e);
			} catch (InterruptedException ie) {
				logger.error("login() thread interrupted:" + ie);
			} catch (Exception e) {
				logger.error("Unable to connect to XMPP server: " + e);
			}
		}
		else {
			xmppCon = new XMPPConnection(config);
			try {
				xmppCon.connect();
				// Log into the server
				xmppCon.login(user, password, resource);
				logger.info("Logged " + user + "@" + server + " in.");

				// create pubsub manager
				manager = new PubSubManager(xmppCon, PUBSUB_SERVER_PREFIX + server);
			} catch (XMPPException e) {
				logger.error("Unable to connect to XMPP server: " + e);
			} catch (Exception e) {
				logger.error("Unable to connect to XMPP server: " + e);
			}
		}

		// add callbacks
		xmppCon.addConnectionListener(new ConnectionListener() {

			@Override
			public void reconnectionSuccessful() {
				logger.info("Successfully reconnected to the XMPP server.");
				if (cb != null) {
					logger.info("Calling reconnect callback handler " + cb.name());
					cb.onReconnect();
				}
			}

			@Override
			public void reconnectionFailed(Exception arg0) {
				logger.info("Failed to reconnect to the XMPP server.");
			}

			@Override
			public void reconnectingIn(int seconds) {
				logger.info("Reconnecting in " + seconds + " seconds.");
			}

			@Override
			public void connectionClosedOnError(Exception arg0) {
				logger.error("Connection to XMPP server was lost.");
			}

			@Override
			public void connectionClosed() {
				logger.info("XMPP connection was closed.");
			}
		});

	}

	/**
	 * This method handles callbacks for passwords during certificate based authentication
	 * @param callbacks
	 * @throws IOException
	 */

	public void handle(Callback[] callbacks) throws IOException {

		logger.info("Callback handler called");
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				logger.info("Name callback");
				NameCallback ncb = (NameCallback) callback;
				ncb.setName(user);
			} else if (callback instanceof PasswordCallback) {
				logger.info("Password callback");
				PasswordCallback pcb = (PasswordCallback) callback;
				if(truststorepass != null){
					pcb.setPassword(truststorepass.toCharArray());
				}
				else {
					logger.error("Password callback called but truststore password not known: Specify GMOC.pubsub.password in .xmpp.properties");
				}
			} else {
				logger.error("Unknown callback requested: " + callback.getClass().getSimpleName());
			}
		}
	}


	@Override
	protected void finalize() throws Throwable {
		//logger.info("Disconnecting from XMPP server");
		if ((xmppCon != null) && (xmppCon.isConnected()))
                    try {
			xmppCon.disconnect();
                    }
                    catch (NullPointerException npe) {
                        logger.error("Working around NPE in Smack libraries at connection disconnect.");
                        xmppCon = null;
                    }
	}

	/**
	 * expose
	 * @throws Throwable
	 */
	public void _finalize() throws Throwable {
		finalize();
	}
	
	/**
	 * create or retrieve an existing leaf node
	 * @param nodePath
	 * @return LeafNode
	 */
	protected LeafNode getLeafNode(String nodePath) {
		try {
			DiscoverItems dItems = manager.discoverNodes(null);
			Iterator<DiscoverItems.Item> iItems = dItems.getItems();
			while(iItems.hasNext()) {
				DiscoverItems.Item it = iItems.next();
				if (it.getNode().equalsIgnoreCase(nodePath)) {
					// get that node
					return (LeafNode)manager.getNode(nodePath);
				}
			}
			// create  a new node
			logger.info("Creating new pubsub node on XMPP server: " + nodePath);
			ConfigureForm form = new ConfigureForm(FormType.submit);
			form.setPersistentItems(false);
			form.setDeliverPayloads(true);
			form.setAccessModel(AccessModel.open);
			return (LeafNode)manager.createNode(nodePath, form);
		} catch (XMPPException e) {
			logger.error("Error creating XMPP pubsub node: " + e);
			return null;
		} catch (Exception e) {
			logger.error("Error creating XMPP pubsub node: " + e);
			return null;
		}
	}

	/**
	 * Subscribe to a given node with a listener
	 * @param nodeName
	 * @param listener
	 * @return subscription object or null
	 */
	public synchronized Subscription subscribeToNode(String nodeName, ItemEventListener<?> listener) {
		try {
			LeafNode node = (LeafNode)manager.getNode(nodeName);
			node.addItemEventListener(listener);
			return node.subscribe(xmppCon.getUser());
		} catch (XMPPException e) {
			logger.error("XMPP Error subscribing to XMPP pubsub node: " + e);
		} catch (Exception e) {
			logger.error("Error subscribing to XMPP pubsub node: " + e);
		}
		return null;
	}

	/**
	 * Unsubscribe from a given node given previous subscription
	 * @param nodeName
	 * @param s
	 */
	public synchronized void unsubscribeFromNode(String nodeName, Subscription s) {
		try {
			LeafNode node = (LeafNode)manager.getNode(nodeName);
			node.unsubscribe(s.getJid(), s.getId());
		} catch (XMPPException e) {
			logger.error("XMPP Error unsubscribing from XMPP pubsub node: " + e);
		} catch (Exception e) {
			logger.error("Error unsubscribing from XMPP pubsub node: " + e);
		}
	}

	/**
	 * Return a list of all nodes
	 * @return
	 */
	public synchronized List<String> listAllNodes() {
		List<String> l = new ArrayList<String>();
		if ((xmppCon == null) || (!xmppCon.isConnected()))
			login();

		try {
			DiscoverItems dItems = manager.discoverNodes(null);
			Iterator<DiscoverItems.Item> iItems = dItems.getItems();
			while(iItems.hasNext()) {
				DiscoverItems.Item it = iItems.next();
				l.add(it.getNode());
			}
		} catch (XMPPException e) {
			logger.error("Error listing nodes: " + e);
			logger.info("Trying to discover nodes one more time before failing.. ");
			try{
				DiscoverItems dItems = manager.discoverNodes(null);
				Iterator<DiscoverItems.Item> iItems = dItems.getItems();
				while(iItems.hasNext()) {
					DiscoverItems.Item it = iItems.next();
					l.add(it.getNode());
				}
			} catch (XMPPException e2) {
				logger.error("Error listing nodes AGAIN: " + e2);
			}
		} catch (Exception e) {
			logger.error("Unable to list nodes: " + e);
		}
		return l;
	}

	/**
	 * delete all nodes in the server
	 */
	public synchronized void deleteAllNodes() {
		if ((xmppCon == null) || (!xmppCon.isConnected()))
			login();
		try {
			DiscoverItems dItems = manager.discoverNodes(null);
			Iterator<DiscoverItems.Item> iItems = dItems.getItems();
			while(iItems.hasNext()) {
				DiscoverItems.Item it = iItems.next();
				logger.debug("Deleting node " + it.getNode());
				try {
					Node n = manager.getNode(it.getNode());
					if ((n != null) && (n instanceof LeafNode)){
						LeafNode ln = (LeafNode)n;
						ln.deleteAllItems();
					} else
						logger.info("Unable to delete items of node " + it.getNode());
					manager.deleteNode(it.getNode());
				} catch (XMPPException e) {
					logger.error("Error deleting node: " + e);
				}
			}
		} catch (XMPPException e) {
			logger.error("Error deleting nodes: " + e);
		}
	}

	/**
	 * delete a node in the server
	 */
	public synchronized void deleteNode(String nodepath) {
		if ((xmppCon == null) || (!xmppCon.isConnected()))
			login();

		logger.info("Deleting node " + nodepath);
		try {
			Node n = manager.getNode(nodepath);
			if ((n != null) && (n instanceof LeafNode)){
				LeafNode ln = (LeafNode)n;
				ln.deleteAllItems();
			} else 
				logger.info("Unable to delete items of node " + nodepath);
			manager.deleteNode(nodepath);
		} catch (XMPPException e) {
			logger.error("Error deleting node: " + e);
		}

	}

	/**
	 * Publish an ORCA slice manifest to a path
	 * @param nodePath
	 * @param measurement
	 */
	public synchronized void publishManifest(String nodePath, String manifest) {

		if ((xmppCon == null) || (!xmppCon.isConnected()))
			login();

		LeafNode ln = getLeafNode(nodePath);

		if (ln == null) {
			logger.error("Unable to publish measurement: node does not exist");
			return;
		}
		SimplePayload payload = new SimplePayload(ORCA_PLD_ROOT,ORCA_PLD_NS,
				"<orca xmlns='" + ORCA_PLD_NS + "'>" + manifest + "</orca>");
		String itemId = String.valueOf(System.currentTimeMillis());
		PayloadItem<SimplePayload> item = new PayloadItem<SimplePayload>(itemId, payload);

		try {
			ln.send(item);
		} catch (XMPPException e) {
			logger.error("Unable to publish measurement: " + e);
		}
	}

	/**
	 * Publish sliceList to a path
	 * @param nodePath
	 * @param measurement
	 */
	public synchronized void publishSliceList(String nodePath, String sliceListString) {

		if ((xmppCon == null) || (!xmppCon.isConnected()))
			login();

		LeafNode ln = getLeafNode(nodePath);

		if (ln == null) {
			logger.error("Unable to publish sliceList: node does not exist");
			return;
		}

		logger.info("XMPPPubSub:publishManifest(): Sending sliceList Payload");

		logger.debug("XMPPPubSub:publishManifest(): sliceList Payload = " + sliceListString);

		SimplePayload payload = new SimplePayload(SLICE_LIST,ORCA_SLICELIST_NS, 
				"<orca xmlns='" + ORCA_SLICELIST_NS + "'>" + "<sliceList>" + sliceListString + "</sliceList>" + "</orca>");

		String itemId = String.valueOf(System.currentTimeMillis());
		PayloadItem<SimplePayload> item = new PayloadItem<SimplePayload>(itemId, payload);

		try {
			ln.send(item);
		} catch (XMPPException e) {
			logger.error("Unable to publish sliceList: " + e);
		}
	}
}
