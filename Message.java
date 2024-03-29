import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by Ricardo Sim�es on 19/05/2015.
 */
class Message implements Serializable {

    private String username;
    private String message;
    private byte[] encryptedMessage;
    private byte[] pubKey;
    private byte[] encryptedPubKey;
    private BigInteger P, G;
    private int L;
    private byte[] digest;
    private String strMDofDataToTransmit;
    private byte[] iv;

    Message(String username, String message) {
        this.username = username;
        this.message = message;
        this.P = null;
        this.G = null;
        this.L = 0;
        this.pubKey = null;
        this.encryptedMessage = null;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public byte[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

    public BigInteger getP() {
        return P;
    }

    public void setP(BigInteger p) {
        P = p;
    }

    public BigInteger getG() {
        return G;
    }

    public void setG(BigInteger g) {
        G = g;
    }

    public int getL() {
        return L;
    }

    public void setL(int l) {
        L = l;
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(byte[] encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public byte[] getEncryptedPubKey() {
        return encryptedPubKey;
    }

    public void setEncryptedPubKey(byte[] encryptedPubKey) {
        this.encryptedPubKey = encryptedPubKey;
    }

    public byte[] getDigest() {
        return digest;
    }

    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

    public String getStrMDofDataToTransmit() {
        return strMDofDataToTransmit;
    }

    public void setstrMDofDataToTransmit(String strMDofDataToTransmit) {
        this.strMDofDataToTransmit = strMDofDataToTransmit;
    }
}

