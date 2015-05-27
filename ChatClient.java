
import Utilities.CryptoException;
import Utilities.CryptoUtils;
import org.apache.commons.codec.DecoderException;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import static org.apache.commons.codec.binary.Hex.decodeHex;
import static org.apache.commons.codec.binary.Hex.encodeHex;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.apache.commons.io.FileUtils.writeStringToFile;


public class ChatClient implements Runnable {
    private Socket socket = null;
    private Thread thread = null;
    private DataInputStream console = null;
    //private ObjectOutputStream oos = null;
    private ChatClientThread client = null;
    private boolean secureConnection = false;
    private String username;
    protected String keyStoreFilename = "my.keystore";
    protected String PASSWORD = "verygoodpassword";

    public ChatClient(String serverName, int serverPort) {
        System.out.println("Establishing connection to server...");
        Scanner sc = new Scanner(System.in);

        System.out.println("Please Insert Username:");
        username = sc.nextLine();
        try {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
            start(username);
        } catch (UnknownHostException uhe) {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch (IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }

    }

    public void run() {
        while (thread != null) {
            try {
                // Sends message from console to server
                Message msg = new Message(username, console.readLine());
                client.sendMessage(msg);
                /*client.soos.writeObject(msg);
                client.soos.flush();
                client.soos.reset();*/
            } catch (IOException ioexception) {
                System.out.println("Error sending string to server: " + ioexception.getMessage());
                stop(false);
            }
        }
    }


    public void handle(Message msg, SecretKey key) {
        // Receives message from server
        if (msg.getUsername().equals("SERVER") && msg.getMessage().equals(".quit")) {
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop(false);
        } else if (msg.getUsername().equals("SERVER") && msg.getMessage().equals("RENEWKEY")) {
           /* msg = new Message(username, "RENEW");
            try {
                msg.setUsername(username);
                msg = client.integrity(msg);
                client.sendMessage(msg);
                client.oos.writeObject(msg);
                client.oos.flush();
                client.oos.reset();
                client.keyAgreement();
            } catch (NoSuchAlgorithmException | IOException e) {
                e.printStackTrace();
            }*/
            System.out.println("Restart client to create new key");
            stop(true);

        } else if (msg.getUsername().equals("SERVER"))
            // else, writes message received from server to console
            System.out.println(msg.getUsername() + " " + msg.getMessage());
        else {
            // Step 8:  Client receives the encrypted text and decrypts it
            Cipher c = null;
            try {
                c = Cipher.getInstance("DES/ECB/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, key);
                byte encodedKey[] = c.doFinal(msg.getEncryptedPubKey());
                SecretKey decryptKey = new SecretKeySpec(encodedKey, "DES");
                c = Cipher.getInstance("DES/ECB/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, decryptKey);
                byte plaintext[] = c.doFinal(msg.getEncryptedMessage());
                System.out.println(msg.getUsername() + " " + new String(plaintext));
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }

    // Inits new client thread
    public void start(String username) throws IOException {
        console = new DataInputStream(System.in);
        //oos = new ObjectOutputStream(socket.getOutputStream());
        if (thread == null) {
            client = new ChatClientThread(this, socket, username);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop(boolean renew) {
        if (renew) {
            File file = new File(username + "sym.key");

            if (file.delete()) {
                System.out.println(file.getName() + " is deleted!");
            } else {
                System.out.println("Delete operation is failed.");
            }

            file = new File(username + "public.key");

            if (file.delete()) {
                System.out.println(file.getName() + " is deleted!");
            } else {
                System.out.println("Delete operation is failed.");
            }

            file = new File(username + "private.key");


            if (file.delete()) {
                System.out.println(file.getName() + " is deleted!");
            } else {
                System.out.println("Delete operation is failed.");
            }

            file = new File(username + "privateencrypted.key");


            if (file.delete()) {
                System.out.println(file.getName() + " is deleted!");
            } else {
                System.out.println("Delete operation is failed.");
            }
        }

        if (thread != null) {
            thread.stop();
            thread = null;
        }
        //System.out.println("BENFICA 1");
        try {
            if (console != null) console.close();
            // System.out.println("IF 1");
            //if (oos != null) oos.close();
            if (socket != null) socket.close();
            //System.out.println("IF 2");
        } catch (IOException ioe) {
            System.out.println("Error closing thread...");
        }
        // System.out.println("BENFICA 2");
        client.close();
        client.stop();
        System.exit(0);
    }


    public static void main(String args[]) {
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }

}

class ChatClientThread extends Thread {
    private Socket socket = null;
    private Socket sslsocket = null;
    private ChatClient client = null;
    private ObjectInputStream ois = null;
    protected ObjectOutputStream oos = null;
    private ObjectInputStream sois = null;
    protected ObjectOutputStream soos = null;
    private String username;
    private BigInteger clientG;
    private BigInteger clientP;
    private int clientL;
    private byte[] clientKey;
    private SecretKey key = null;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public ChatClientThread(ChatClient _client, Socket _socket, String _username) {
        client = _client;
        socket = _socket;
        username = _username;
        open();
        start();
    }

    public void open() {
        // System.out.println("OPEN");
        try {
            oos = new ObjectOutputStream(socket.getOutputStream());
            oos.flush();
            //oos.reset();
            //System.out.println("OOS");
            ois = new ObjectInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop(false);
        }
    }

    public void open2() {
        //System.out.println("OPEN2");
        try {
            ois = new ObjectInputStream(sslsocket.getInputStream());
            //System.out.println("SOIS");
            oos = new ObjectOutputStream(sslsocket.getOutputStream());
            oos.flush();
            //oos.reset();
            // System.out.println("SOOS");

        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop(false);
        }
    }


    public void close() {
        try {
            if (ois != null) ois.close();
            if (oos != null) oos.close();
            //if (sois != null) sois.close();
            //if (soos != null) soos.close();
            //if (sslsocket != null) sslsocket.close();
        } catch (IOException ioe) {
            System.out.println("Error closing input/output stream: " + ioe);
        }
    }

    public void run() {
        System.out.println("Client thread running!");
        Message msg = null;
        try {
            msg = new Message(username, "");
            oos.writeObject(msg);
            oos.reset();

            /*SSLSocketFactory sf = ((SSLSocketFactory) SSLSocketFactory.getDefault());
            // Wrap 'socket' from above in a SSL socket
            InetSocketAddress remoteAddress = (InetSocketAddress) socket.getRemoteSocketAddress();

            SSLSocket s = (SSLSocket) (sf.createSocket(socket, remoteAddress.getHostName(), socket.getPort(), true));

            // we are a client
            s.setUseClientMode(true);

            // allow all supported protocols and cipher suites
            s.setEnabledProtocols(s.getSupportedProtocols());
            s.setEnabledCipherSuites(s.getSupportedCipherSuites());
            System.out.println("HANDSHAKE");
            // and go!
            s.startHandshake();
            System.out.println("HANDSHAKE OVER");
            // continue communication on 'socket'
            sslsocket = s;
            open2();*/
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        try {
            msg = (Message) ois.readObject();
            //sois.reset();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        if (msg.getMessage().compareTo("CREATEKEY") == 0) {
            SecretKey key = keyAgreement();
            System.out.println("KeyAgreement finished - " + key.hashCode());
            System.out.println("Creating Priv/Pub keys");
            generatePrivPubKeys();
            System.out.println("Finished Creating Priv/Pub keys "+publicKey.hashCode());
            try {
                saveKey(key, new File(username + "sym.key"), new File(username + "symencrypted.key"));
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                key = loadSymKey(new File(username + "symencrypted.key"), new File(username + "sym.key"));
                loadPrivPubKeys(username + "public.key", username + "private.key", username + "privateencrypted.key");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("key loaded " + key.hashCode());
        }


        while (true) {
            try {
                client.handle((Message) ois.readObject(), key);
            } catch (IOException ioe) {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop(false);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    private void loadPrivPubKeys(String pubName, String privName, String privNameEnc) {
        ObjectInputStream oin = null;
        CryptoUtils cu = new CryptoUtils();
        try {
            //cu.decrypt(client.PASSWORD, new File(pubNameEnc), new File(pubName));
            FileInputStream in = new FileInputStream(pubName);
            oin = new ObjectInputStream(new BufferedInputStream(in));

            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            publicKey = fact.generatePublic(keySpec);

            cu.decrypt(client.PASSWORD, new File(privNameEnc), new File(privName));
            in = new FileInputStream(privName);
            oin = new ObjectInputStream(new BufferedInputStream(in));

            m = (BigInteger) oin.readObject();
            e = (BigInteger) oin.readObject();
            keySpec = new RSAPublicKeySpec(m, e);
            fact = KeyFactory.getInstance("RSA");
            privateKey = fact.generatePrivate(keySpec);
        } catch (Exception e) {
            //throw new RuntimeException("Spurious serialisation error", e);
            e.printStackTrace();
        } finally {
            try {
                oin.close();
            } catch (IOException e) {
                //e.printStackTrace();
                System.out.println("Error [loadPrivPubKeys] - "+e.getMessage());
            }
        }
    }

    public void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

    private void generatePrivPubKeys() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.genKeyPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

            saveToFile(username + "public.key", pub.getModulus(), pub.getPublicExponent());
            saveToFile(username + "private.key", priv.getModulus(), priv.getPrivateExponent());
            CryptoUtils cu = new CryptoUtils();
            cu.encrypt(client.PASSWORD, new File(username + "private.key"), new File(username + "privateencrypted.key"));
        } catch (Exception e) {
            System.out.println("Error [generatePrivPubKeys] - " + e.getMessage());
        }
    }

    private SecretKey loadSymKey(File fileInput, File fileOutput) throws IOException {
        CryptoUtils cu = new CryptoUtils();
        try {
            cu.decrypt(client.PASSWORD, fileInput, fileOutput);
        } catch (CryptoException e) {
            System.out.println("Error [loadSymKey] - " + e.getMessage());
        }
        String data = new String(readFileToByteArray(fileOutput));
        char[] hex = data.toCharArray();
        byte[] encoded;
        try {
            encoded = decodeHex(hex);
        } catch (DecoderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        SecretKey key = new SecretKeySpec(encoded, "DES");
        return key;
    }

    private void saveKey(SecretKey key, File fileInput, File fileOutput) throws IOException {
        byte[] encoded = key.getEncoded();
        char[] hex = encodeHex(encoded);
        String data = String.valueOf(hex);
        writeStringToFile(fileInput, data);
        CryptoUtils cu = new CryptoUtils();
        try {
            cu.encrypt(client.PASSWORD, fileInput, fileOutput);
        } catch (CryptoException e) {
            System.out.println("Error [saveKey] - " + e.getMessage());
        }
    }

    protected SecretKey keyAgreement() {
        System.out.println("starting key agreement");
        // Step 1:  Client generates a key pair
        KeyPairGenerator kpg = null;
        //SecretKey key = null;
        Message msg = new Message("", "");
        try {
            kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();
            // Step 2:  Client sends the public key and the
            // 		Diffie-Hellman key parameters to Bob
            Class dhClass = Class.forName("javax.crypto.spec.DHParameterSpec");
            DHParameterSpec dhSpec = ((DHPublicKey) kp.getPublic()).getParams();
            clientG = dhSpec.getG();
            clientP = dhSpec.getP();
            clientL = dhSpec.getL();
            clientKey = kp.getPublic().getEncoded();
            //System.out.println("dhSpecClient - "+dhSpec.hashCode());
            System.out.println("ClientPubKey - " + kp.getPublic().hashCode());
            msg.setG(clientG);
            msg.setP(clientP);
            msg.setL(clientL);
            msg.setPubKey(kp.getPublic().getEncoded());
            oos.writeObject(msg);
            oos.flush();
            oos.reset();
            // Step 4 part 1:  Client performs the first phase of the
            //		protocol with her private key
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kp.getPrivate());
            // Step 4 part 2:  Client performs the second phase of the
            //		protocol with Server's public key
            msg = (Message) ois.readObject();
            byte[] serverPubKey = msg.getPubKey();
            System.out.println("serverPubKey - " + serverPubKey.hashCode());
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPubKey);
            PublicKey pk = kf.generatePublic(x509Spec);
            ka.doPhase(pk, true);
            // Step 4 part 3:  Client can generate the secret key
            byte secret[] = ka.generateSecret();
            // Step 6:  Client generates a DES key
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            DESKeySpec desSpec = new DESKeySpec(secret);
            key = skf.generateSecret(desSpec);
            System.out.println("key agreement finished " + key.hashCode());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return key;
    }

    public void sendMessage(Message msg) {
        try {
            // Step 7:  Client encrypts data with the key and sends
            //		the encrypted data to Server
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = c.doFinal(msg.getMessage().getBytes());
            msg.setEncryptedMessage(ciphertext);
            Message msgToSend = integrity(msg);
            //System.out.println(msgToSend.getDigest().toString());
            Signature mySign = Signature.getInstance("MD5withRSA");
            mySign.initSign(privateKey);
            mySign.update(msgToSend.getStrMDofDataToTransmit().getBytes());
            byte[] byteSignedData = mySign.sign();
            msgToSend.setDigest(byteSignedData);
            oos.writeObject(msgToSend);
            oos.flush();
            oos.reset();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected Message integrity(Message msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] ba = (msg.getUsername() + msg.getMessage()).getBytes();
        md.update(ba);
        byte[] digest = md.digest();
        msg.setDigest(digest);
        String strMDofDataToTransmit = new String();
        for (int i = 0; i < digest.length; i++){
            strMDofDataToTransmit = strMDofDataToTransmit + Integer.toHexString((int)digest[i] & 0xFF) ;
        }
        msg.setstrMDofDataToTransmit(strMDofDataToTransmit);
        System.out.println("Result: Successfully hashed");
        return msg;
    }
}

