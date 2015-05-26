import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.*;


public class ChatServer implements Runnable {
    /*private String pathToEncryptedUsersFile = "files/usersInformationEncrypted";
    private String pathToDecryptedUsersFile = "files/usersInformationDecrypted";*/
    protected String keyStoreFilename = "my.keystore";
    protected String keyStorePassword = "verygoodpassword";
    protected ChatServerThread[] clients = new ChatServerThread[20];
    private ServerSocket server_socket = null;
    private Thread thread = null;
    protected int clientCount = 0;
    //private String alias = "alias";
    private FileInputStream fis;
    private ObjectInputStream ois;
    private HashMap<String, String> usersCache;
    protected KeyStore ks;


    public ChatServer(int port) {
        try {
            System.out.println("Server is starting...");
            System.out.println("Starting KeyManagement");
            KeyManagement km = new KeyManagement(this);
            km.start();
            System.out.println("Loading keystore...");
            loadKeyStore();
            System.out.println("Loaded keystore...");
            //loadUsers();
           /* for (String key : usersCache.keySet())
                System.out.println(key + " " + usersCache.get(key));*/
            // Binds to port and starts server
            System.out.println("Binding to port " + port);
            server_socket = new ServerSocket(port);
            System.out.println("Server started: " + server_socket);
            start();
        } catch (IOException ioexception) {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        }
    }

    public static void main(String args[]) {
        ChatServer server = null;

        if (args.length != 1)
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        else
            // Calls new server
            server = new ChatServer(Integer.parseInt(args[0]));
    }


   /* private void loadUsers() {
        usersCache = new HashMap<String, String>();
        String line;
        File encrypted, decrypted;
        encrypted = new File(pathToEncryptedUsersFile);
        decrypted = new File(pathToDecryptedUsersFile);

        try {
            decrypted.createNewFile();
            CryptoUtils.decrypt(fileKey, encrypted, decrypted);
            fis = new FileInputStream(pathToDecryptedUsersFile);
            ois = new ObjectInputStream(fis);
            while ((usersCache = (HashMap) ois.readObject()) != null) {
                //usersCache.put(line.split(" ")[0], line.split(" ")[1]);
            }
        } catch (CryptoException e) {
            System.out.println("Error decrypting users file - " + e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println("users file not found - " + e.getMessage());
        } catch (EOFException e) {
            System.out.println("Finished loading users. - " + e.getMessage());
        } catch (IOException e) {
            System.out.println("error loading users - " + e.getMessage());
        } catch (ClassNotFoundException e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                ois.close();
                fis.close();
            } catch (Exception e) {
                System.out.println("Error closing input streams.");
            }
        }
    }*/

    private void loadKeyStore() {
        // get user password and file input stream
        char[] password = keyStorePassword.toCharArray();
        try {
            ks = KeyStore.getInstance("JCEKS");

            java.io.FileInputStream fis = null;
            try {
                fis = new java.io.FileInputStream(keyStoreFilename);
                ks.load(fis, password);
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
        } catch (Exception e) {
            System.out.println("Error loading keystore - " + e.getMessage());
            try {
                ks.load(fis, null);
                java.io.FileOutputStream fos = null;
                try {
                    fos = new java.io.FileOutputStream(keyStoreFilename);
                    ks.store(fos, password);
                } catch (KeyStoreException e1) {
                    e1.printStackTrace();
                } finally {
                    if (fos != null) {
                        fos.close();
                    }
                }
            } catch (IOException e1) {
                e1.printStackTrace();
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            } catch (CertificateException e1) {
                e1.printStackTrace();
            }
        }

    }

    public void run() {
        while (thread != null) {
            try {
                // Adds new thread for new client
                System.out.println("Waiting for a client ...");
                addThread(server_socket.accept());
            } catch (IOException ioexception) {
                System.out.println("Accept error: " + ioexception);
                stop();
            }
        }
    }

    public void start() {
        if (thread == null) {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            // Stops running thread for client
            thread.stop();
            thread = null;
        }

    }

    private int findClient(int ID) {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

    public synchronized void handle(int ID, String username, Message input) {
        boolean integrity = false;
        try {
            integrity = checkIntegrity(input);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
            System.out.println("Error checking message integrity - " + e.getMessage());
        }

        if (integrity) {
            int leaving_id = findClient(ID);
            if (input.getMessage().equals(".quit")) {
                // Client exits
                Message msg = new Message("SERVER", ".quit");
                clients[leaving_id].send(msg);
                // Notify remaing users
                for (int i = 0; i < clientCount; i++)
                    if (i != leaving_id) {
                        msg = new Message("SERVER", "Client " + username + " exits..");
                        clients[i].send(msg);
                    }
                remove(ID);
            } else if (input.getMessage().equals("RENEW")) {
                try {
                    clients[findClient(ID)].keyAgreement();
                } catch (Exception e) {
                    System.out.println("USER NOT FOUN " + username);
                }
            } else {
                // Brodcast message for every other client online
                SecretKey srcKey = clients[leaving_id].lookUser(username);
                for (int i = 0; i < clientCount; i++) {
                    Message msg = new Message("", "");
                    msg = input;
                    SecretKey destKey = clients[i].lookUser(clients[i].username);
                    Cipher c = null;
                    try {
                        c = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        c.init(Cipher.ENCRYPT_MODE, destKey);
                        byte[] ciphertext = c.doFinal(
                                srcKey.getEncoded());
                        msg.setEncryptedPubKey(ciphertext);
                        clients[i].send(msg);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        } else {
            System.out.println("Integrity test failed.");
        }


    }

    private boolean checkIntegrity(Message input) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] ba = (input.getUsername() + input.getMessage()).getBytes("UTF8");
        md.update(ba);
        byte[] digest = md.digest();
        if (Arrays.equals(digest, input.getDigest()))
            return true;
        else
            return false;
    }

    public synchronized void remove(int ID) {
        int pos = findClient(ID);

        if (pos >= 0) {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1)
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            clientCount--;

            try {
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }

            toTerminate.stop();
        }
    }

    private void addThread(Socket socket) {
        if (clientCount < clients.length) {
            // Adds thread for new accepted client
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            try {
                clients[clientCount].open();
                clients[clientCount].start();
                clientCount++;
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }


}

class ChatServerThread extends Thread {
    public ObjectInputStream ois;
    public ObjectOutputStream oos;
    public ObjectInputStream sois;
    public ObjectOutputStream soos;
    Message msg;
    private ChatServer server = null;
    private Socket socket = null;
    private Socket sslsocket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;
    private BigInteger clientP;
    private java.math.BigInteger clientG;
    private int clientL;
    private byte[] clientKey;
    private byte[] serverKey;
    protected String username;
    protected long timestamp;

    public ChatServerThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
        msg = new Message("", "");
        timestamp = System.currentTimeMillis();
    }

    // Sends message to client
    public void send(Message msg) {
        try {
            oos.writeObject(msg);
            oos.flush();
            oos.reset();
        } catch (IOException ioexception) {
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }

    // Gets id for client
    public int getID() {
        return ID;
    }

    // Runs thread
    public void run() {
        System.out.println("Server Thread " + ID + " running.");
        SecretKey userSecretKey = null;
        try {
            msg = (Message) ois.readObject();
            //ois.reset();
            username = msg.getUsername();
            userSecretKey = lookUser(msg.getUsername());
            //System.out.println("userExists = " + userSecretKey.toString());

            /*// Get the default SSLSocketFactory
            SSLSocketFactory sf = ((SSLSocketFactory) SSLSocketFactory.getDefault());
            // Wrap 'socket' from above in a SSL socket
            InetSocketAddress remoteAddress = (InetSocketAddress) socket.getRemoteSocketAddress();

            SSLSocket s = (SSLSocket) (sf.createSocket(socket, remoteAddress.getHostName(), socket.getPort(), true));

            // we are a server
            s.setUseClientMode(false);

            // allow all supported protocols and cipher suites
            s.setEnabledProtocols(s.getSupportedProtocols());
            s.setEnabledCipherSuites(s.getSupportedCipherSuites());
            System.out.println("HANDSHAKE WITH " + ID);
            // and go!
            s.startHandshake();
            System.out.println("HANDSHAKE FINISHED");

            // continue communication on 'socket'
            sslsocket = s;
            open2();*/

            /*// Key store for your own private key and signing certificate
            InputStream keyStoreResource = new FileInputStream(server.keystoreFilename);
            char[] keyStorePassphrase = server.fileKey.toCharArray();
            KeyStore ksKeys = KeyStore.getInstance("JKS");
            ksKeys.load(keyStoreResource, keyStorePassphrase);

            // KeyManager decides which key material to use.
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ksKeys, keyStorePassphrase);

            // Trust store contains certificates of trusted certificate authorities.
            // Needed for client certificate validation.
            InputStream trustStoreIS = new FileInputStream("truststore.certs");
            char[] trustStorePassphrase = server.fileKey.toCharArray();
            KeyStore ksTrust = KeyStore.getInstance("JKS");
            ksTrust.load(trustStoreIS, trustStorePassphrase);

            // TrustManager decides which certificate authorities to use
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ksTrust);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Get your own custom SSLSocketFactory
            sf = sslContext.getSocketFactory();

            // Client must authenticate
            s.setNeedClientAuth(true);*/

        } catch (Exception e) {
            System.out.println("Exception - " + e.getMessage());
            e.printStackTrace();
        }
        try {
            if (userSecretKey != null) {
                msg.setMessage("CONFERE");
                oos.writeObject(msg);
                oos.flush();
                oos.reset();
            } else {
                msg.setUsername("SERVER");
                msg.setMessage("CREATEKEY");

                oos.writeObject(msg);
                oos.flush();
                oos.reset();
                System.out.println("starting key agreement");
                SecretKey key = keyAgreement();
                System.out.println("key agreement finished" + key.hashCode());
                storeKey(username, key);
            }

        } catch (IOException e) {
            System.out.println("Error sending message [CREATEKEY] - " + e.getMessage());
        }
        while (true) {
            try {
                server.handle(ID, username, (Message) ois.readObject());
            } catch (IOException ioe) {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    private void storeKey(String username, SecretKey key) {
        System.out.println(key.toString());
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(server.keyStorePassword.toCharArray());
        // save my secret key
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(key);
        java.io.FileOutputStream fos = null;
        try {
            try {
                server.ks.setEntry(username, skEntry, protParam);
                // store away the keystore
                fos = new FileOutputStream(server.keyStoreFilename);
                server.ks.store(fos, server.keyStorePassword.toCharArray());
            } catch (Exception e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    protected SecretKey keyAgreement() {
        Message msg;
        // Step 3:  Server uses the parameters supplied by client
        //		to generate a key pair and sends the public key
        try {
            msg = (Message) ois.readObject();

            clientP = msg.getP();
            clientG = msg.getG();
            clientL = msg.getL();
            byte[] clientPubKey = msg.getPubKey();
            System.out.println("ClientPubKey - " + clientPubKey.hashCode());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(clientP, clientG, clientL);
            kpg.initialize(dhSpec);
            KeyPair kp = kpg.generateKeyPair();
            serverKey = kp.getPublic().getEncoded();
            System.out.println("serverPubKey - " + kp.getPublic().hashCode());
            msg.setUsername("SERVER");
            msg.setMessage("KEYAGREEMENT3");
            msg.setPubKey(kp.getPublic().getEncoded());
            oos.writeObject(msg);
            oos.flush();
            oos.reset();
            // Step 5 part 1:  Server uses his private key to perform the
            //		first phase of the protocol
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kp.getPrivate());
            // Step 5 part 2:  Server uses Client's public key to perform
            //		the second phase of the protocol.
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPubKey);
            PublicKey pk = kf.generatePublic(x509Spec);
            ka.doPhase(pk, true);
            // Step 5 part 3:  Server generates the secret key
            byte secret[] = ka.generateSecret();
            // Step 6:  Server generates a DES key
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            DESKeySpec desSpec = new DESKeySpec(secret);
            SecretKey key = skf.generateSecret(desSpec);
            return key;
        } catch (Exception e) {
            System.out.println("Error [keyAgreement] - " + e.getMessage());
        }

        return null;
    }

    protected SecretKey lookUser(String username) {
        System.out.println("looking for user");
        char[] password = server.keyStorePassword.toCharArray();
        FileInputStream fIn = null;
        KeyStore keystore = null;

        try {
            fIn = new FileInputStream(server.keyStoreFilename);
            keystore = KeyStore.getInstance("JCEKS");
            keystore.load(fIn, password);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
            // get my private key
            KeyStore.SecretKeyEntry pkEntry = null;
            pkEntry = (KeyStore.SecretKeyEntry) keystore.getEntry(username, protParam);
            SecretKey myPrivateKey = pkEntry.getSecretKey();
            System.out.println(keystore.hashCode());
            return myPrivateKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    protected Message integrity(Message msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] ba = (msg.getUsername() + msg.getMessage()).getBytes("UTF8");
        md.update(ba);
        byte[] digest = md.digest();
        msg.setDigest(digest);
        System.out.println("Result: Successfully hashed");
        return msg;
    }


    // Opens thread
    public void open() throws IOException {
       /* streamIn = new DataInputStream(new
                BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));*/

        ois = new ObjectInputStream(new
                BufferedInputStream(socket.getInputStream()));
        oos = new ObjectOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
        oos.flush();
        // oos.reset();
    }

    public void open2() throws IOException {
        soos = new ObjectOutputStream(new
                BufferedOutputStream(sslsocket.getOutputStream()));
        soos.flush();
        System.out.println("SOOS");
        ois = new ObjectInputStream(new
                BufferedInputStream(sslsocket.getInputStream()));
        System.out.println("SOIS");
        //soos.reset();
    }

    // Closes thread
    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }


}

class KeyManagement extends Thread {
    private ChatServer server;

    KeyManagement(ChatServer server) {
        this.server = server;
    }

    public void run() {
        while (true) {
            try {
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            checkKeys();
        }
    }

    private void checkKeys() {
        for (int i = 0; i < server.clientCount; i++) {
            if (System.currentTimeMillis() - server.clients[i].timestamp > 30000) {
                System.out.println("client " + server.clients[i].username + " needs to renew key.");
                Message msg = new Message("SERVER", "RENEWKEY");
                try {
                    msg = server.clients[i].integrity(msg);
                    server.clients[i].oos.writeObject(msg);
                    server.clients[i].oos.flush();
                    server.clients[i].oos.reset();
                    server.ks.deleteEntry(server.clients[i].username);
                    savaKeyStore();
                } catch (IOException | NoSuchAlgorithmException | KeyStoreException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private void savaKeyStore() {
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(server.keyStorePassword.toCharArray());
        // save keystore
        java.io.FileOutputStream fos = null;
        try {
            try {
                // store away the keystore
                fos = new FileOutputStream(server.keyStoreFilename);
                server.ks.store(fos, server.keyStorePassword.toCharArray());
            } catch (Exception e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }


}

