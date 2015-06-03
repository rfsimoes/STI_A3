import Utilities.CryptoUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;


class ChatServer implements Runnable {
    final String keyStoreFilename = "my.keystore";
    final String keyStorePassword = "verygoodpassword";
    final ChatServerThread[] clients = new ChatServerThread[20];
    private ServerSocket server_socket = null;
    private Thread thread = null;
    int clientCount = 0;
    KeyStore ks;
    private PublicKey publicKey;
    private PrivateKey privateKey;


    private ChatServer(int port) {
        try {
            System.out.println("Server is starting...");
            System.out.println("Starting KeyManagement");
            KeyManagement km = new KeyManagement(this);
            km.start();
            System.out.println("Loading keystore...");
            loadKeyStore();
            System.out.println("Loaded keystore...");
            generatePrivPubKeys();
            System.out.println("Binding to port " + port);
            server_socket = new ServerSocket(port);
            System.out.println("Server started: " + server_socket);
            start();
        } catch (IOException ioexception) {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        }
    }

    private void generatePrivPubKeys() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.genKeyPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

            saveToFile("serverpublic.key", pub.getModulus(), pub.getPublicExponent());
            saveToFile("serverprivate.key", priv.getModulus(), priv.getPrivateExponent());
            CryptoUtils cu = new CryptoUtils();
            CryptoUtils.encrypt(keyStorePassword, new File("serverprivate.key"), new File("serverprivateencrypted.key"));
        } catch (Exception e) {
            System.out.println("Error [generatePrivPubKeys] - " + e.getMessage());
        }
    }

    private void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        try (ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)))) {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
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

    /**
     * Abre a keystore caso exista. Senão existir cria uma.
     */
    private void loadKeyStore() {
        // get user password and file input stream
        char[] password = keyStorePassword.toCharArray();
        java.io.FileInputStream fis = null;
        try {
            ks = KeyStore.getInstance("JCEKS");


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
            } catch (IOException | NoSuchAlgorithmException | CertificateException e1) {
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

    private void start() {
        if (thread == null) {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

    private void stop() {
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

    /**
     * Carrega a chave publica de um utilizador.
     *
     * @param pubName Nome do ficheiro
     * @return A chave publica do utilizador ou null
     */
    private PublicKey loadPubKeys(String pubName) {
        ObjectInputStream oin = null;
        CryptoUtils cu = new CryptoUtils();
        PublicKey senderPublicKey = null;
        try {
            //cu.decrypt(keyStorePassword, new File(pubNameEnc), new File(pubName));
            FileInputStream in = new FileInputStream(pubName);
            oin = new ObjectInputStream(new BufferedInputStream(in));

            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            senderPublicKey = fact.generatePublic(keySpec);

        } catch (Exception e) {
            //throw new RuntimeException("Spurious serialisation error", e);
            System.out.println("Error [loadPubKeys] - " + e.getMessage());
        } finally {
            try {
                oin.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        //System.out.println("BENFICACACACA "+senderPublicKey.hashCode());
        return senderPublicKey;
    }

    /**
     * Trata da mensagem recebida. Inicialmente é verifica se a assinatura da mensagem é válida. Se for valida faz
     * o broadcast para todos os users.
     *
     * @param ID       Id do cliente
     * @param username Nome de utilizador do cliente
     * @param input    Mensagem que o cliente enviou
     */
    public synchronized void handle(int ID, String username, Message input) {
        Signature myVerifySign;
        boolean verifySign = false;
        try {
            myVerifySign = Signature.getInstance("MD5withRSA");
            myVerifySign.initVerify(loadPubKeys(username + "public.key"));
            myVerifySign.update(input.getStrMDofDataToTransmit().getBytes());
            verifySign = myVerifySign.verify(input.getDigest());
        } catch (Exception e) {
            System.out.println("Error [handle] - " + e.getMessage());
        }

        if (!verifySign) {
            System.out.println(" Error in validating Signature ");
        } else
            System.out.println(" Successfully validated Signature ");

        if (verifySign) {
            int leaving_id = findClient(ID);
            switch (input.getMessage()) {
                case ".quit":
                    // Client exits
                    Message msg = new Message("SERVER", ".quit");
                    clients[leaving_id].send(msg);
                    // Notify remaing users
                    for (int i = 0; i < clientCount; i++)
                        if (i != leaving_id) {
                            msg = new Message("SERVER", "Client " + username + " exits..");

                            byte[] byteSignedData = null;
                            Message msgToSend = null;
                            try {
                                msgToSend = clients[findClient(ID)].integrity(msg);
                                //System.out.println(msgToSend.getDigest().toString());
                                byteSignedData = null;
                                Signature mySign = Signature.getInstance("MD5withRSA");
                                mySign.initSign(privateKey);
                                mySign.update(msgToSend.getStrMDofDataToTransmit().getBytes());
                                byteSignedData = mySign.sign();
                            } catch (Exception e) {
                                System.out.println("Error [handle] - " + e.getMessage());
                            }
                            msgToSend.setDigest(byteSignedData);
                            clients[i].send(msgToSend);
                        }
                    remove(ID);
                    break;
                default:
                    // Brodcast message for every other client online
                    SecretKey srcKey = clients[leaving_id].lookUser(username);
                    for (int i = 0; i < clientCount; i++) {
                        msg = new Message("", "");
                        msg = input;
                        SecretKey destKey = clients[i].lookUser(clients[i].username);
                        Cipher c;
                        try {
                            c = Cipher.getInstance("DES/ECB/PKCS5Padding");
                            c.init(Cipher.ENCRYPT_MODE, destKey);
                            byte[] ciphertext = c.doFinal(
                                    srcKey.getEncoded());
                            msg.setEncryptedPubKey(ciphertext);
                            byte[] byteSignedData = null;
                            Message msgToSend = null;
                            try {
                                msgToSend = clients[findClient(ID)].integrity(msg);
                                //System.out.println(msgToSend.getDigest().toString());
                                byteSignedData = null;
                                Signature mySign = Signature.getInstance("MD5withRSA");
                                mySign.initSign(privateKey);
                                mySign.update(msgToSend.getStrMDofDataToTransmit().getBytes());
                                byteSignedData = mySign.sign();
                            } catch (Exception e) {
                                System.out.println("Error [handle] - " + e.getMessage());
                            }
                            msgToSend.setDigest(byteSignedData);
                            clients[i].send(msgToSend);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    break;
            }
        } else {
            System.out.println("Integrity test failed.");
        }


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
    private ObjectInputStream ois;
    public ObjectOutputStream oos;
    private Message msg;
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private final DataInputStream streamIn = null;
    private final DataOutputStream streamOut = null;
    private BigInteger clientP;
    private java.math.BigInteger clientG;
    private int clientL;
    private byte[] serverKey;
    String username;
    final long timestamp;

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

    /**
     * Método são recebidas as mensagens dos clientes. Primeirament faz juntamente com o cliente a criação da chave
     * simetrica. Posteriormente guarda essa chave. Por fim fica infinitamente à escuta de novas mensagens.
     */
    public void run() {
        System.out.println("Server Thread " + ID + " running.");
        SecretKey userSecretKey = null;
        try {
            msg = (Message) ois.readObject();
            //ois.reset();
            username = msg.getUsername();
            userSecretKey = lookUser(msg.getUsername());

        } catch (Exception e) {
            System.out.println("Exception - " + e.getMessage());
            e.printStackTrace();
        }
        try {
            if (userSecretKey != null) {
                //msg.setMessage("CONFERE");
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

    /**
     * Este método recebe a chave simetrica gerada por mutuo acorde entre server e client e guarda-a na keystore
     *
     * @param username Nome de utilizador do cliente
     * @param key      Chave simétrica
     */
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

    /**
     * Este método é responsável por criar a chave simetrica atraves de mutuo acordo entre client e server.
     *
     * @return SecretKey chave simetrica gerada
     */
    SecretKey keyAgreement() {
        Message msg;
        // Step 3:  Server uses the parameters supplied by client
        //		to generate a key pair and sends the public key
        try {
            msg = (Message) ois.readObject();

            clientP = msg.getP();
            clientG = msg.getG();
            clientL = msg.getL();
            byte[] clientPubKey = msg.getPubKey();
            System.out.println("ClientPubKey - " + Arrays.hashCode(clientPubKey));
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
            return skf.generateSecret(desSpec);
        } catch (Exception e) {
            System.out.println("Error [keyAgreement] - " + e.getMessage());
        }

        return null;
    }

    /**
     * Este método recebe o nome de utilizador e procura na keystore por uma entrada do mesmo.
     *
     * @param username Nome de utilizador do cliente
     * @return myPrivateKey      Chave simétrica
     */
    SecretKey lookUser(String username) {
        System.out.println("looking for user");
        char[] password = server.keyStorePassword.toCharArray();
        FileInputStream fIn;
        KeyStore keystore;

        try {
            fIn = new FileInputStream(server.keyStoreFilename);
            keystore = KeyStore.getInstance("JCEKS");
            keystore.load(fIn, password);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
            // get my private key
            KeyStore.SecretKeyEntry pkEntry;
            pkEntry = (KeyStore.SecretKeyEntry) keystore.getEntry(username, protParam);
            SecretKey myPrivateKey = pkEntry.getSecretKey();
            //System.out.println(keystore.hashCode());
            return myPrivateKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    Message integrity(Message msg) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] ba = (msg.getUsername() + msg.getMessage()).getBytes();
        md.update(ba);
        byte[] digest = md.digest();
        msg.setDigest(digest);
        String strMDofDataToTransmit = "";
        for (byte aDigest : digest) {
            strMDofDataToTransmit = strMDofDataToTransmit + Integer.toHexString((int) aDigest & 0xFF);
        }
        msg.setstrMDofDataToTransmit(strMDofDataToTransmit);
        System.out.println("Result: Successfully hashed");
        return msg;
    }

    // Opens thread
    public void open() throws IOException {

        ois = new ObjectInputStream(new
                BufferedInputStream(socket.getInputStream()));
        oos = new ObjectOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
        oos.flush();
        // oos.reset();
    }

    // Closes thread
    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }


}

//classe responsável pela gestao de chaves
class KeyManagement extends Thread {
    private final ChatServer server;

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

    /**
     * Este método verifica à quando tempo os clientes se encontram online. Se ultrapassarem um certo limite
     * são obrigados a renovar as chaves.
     */
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

