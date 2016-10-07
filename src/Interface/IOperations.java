package Interface;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author bruno-p
 */
import com.healthmarketscience.rmiio.RemoteInputStream;
import com.healthmarketscience.rmiio.RemoteOutputStream;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import message.Message;

public interface IOperations extends Remote {

    public Message isLoggedIn(String email, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message logIn(String email, byte[] response, boolean usingCard, byte[] messageIntegrity, String clientRandomToken) throws RemoteException;

    public Message register(String email, String name, PublicKey pubKey, String algoritmo, X509Certificate pubKeyCC, byte[] password, X509Certificate[] certs, String clientRandomToken, byte[] testUnsigned, byte[] testSigned, byte[] messageIntegraty) throws RemoteException;

    public Message terminateSession(String email, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message listAllPbox(byte[] token, String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message listAllFiles(String email, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message setPublicKey(String email, PublicKey key, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message findPublicKey(String emailAsk,String emailOther, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getEncrySymetricKey(String email, String fileName, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getMyAlgorithm(String emailAsk,String emailOther, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;
    //-----------------------Problemas de autenticação--------------------------//

    public Message deleteFile(String fileName, byte[] token, String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message shareTableFile(String fileName, byte[] token, String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getFile(RemoteOutputStream outFile, String fileName, String email, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message shareFile(String fileName, String emailAsk,String emailOther, byte[] encryptedPublickey, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message uploadFile(String myFile, String mail, String algorit, RemoteInputStream remoteFileData, byte[] keyEncrypted, String fileExtension, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getExtensionFile(String fileName, byte[] token, String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getAlgorithmFile(String fileName, byte[] token, String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message modifyFile(String myFile, String mailPersonSend, String alg, RemoteInputStream remoteFileData, String fileExtension, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message unshareFile(String findNameFile, String emailAsk,String emailOther, byte[] token, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message getChalange(String email, boolean usecard, byte[] messageIntegrity, String clientRandomToken) throws RemoteException;

    public Message getTokenNewOperation(String email, byte[] messageIntegrity, byte[] clientRandomToken) throws RemoteException;

    public Message sendPublicKeyDH(byte[] generatePrivateKeyDH, String email, byte[] messageIntegrity, String clientRandomToken) throws RemoteException;
}
