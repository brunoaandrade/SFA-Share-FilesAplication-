package ClienteSide;

import Interface.IOperations;
import JPAEntities.Files;
import JPAEntities.Pbox;
import JPAEntities.Permissions;
import com.healthmarketscience.rmiio.RemoteInputStreamServer;
import com.healthmarketscience.rmiio.RemoteOutputStreamServer;
import com.healthmarketscience.rmiio.SimpleRemoteInputStream;
import com.healthmarketscience.rmiio.SimpleRemoteOutputStream;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.border.Border;
import message.Message;
import sun.security.pkcs11.SunPKCS11;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Bruno
 */
public class ClientActions {

    private final IOperations stub;
    private byte[] userPass;
    private String userName;
    private Message message;
    private String email = "";
    private X509Certificate pkCC;
    private SecretKey keySession;
    private PrivateKey key = null;
    private PublicKey pubKey = null;
    private String tokenSession = "";
    private boolean usingCard = false;
    private boolean buttonReg = false;
    private final int sizePacket = 1024;
    private boolean buttonClick = false;
    private String SimAlgorithm = "DES";
    private String AssimAlgorithm = "RSA";
    private boolean buttonLogInClick = false;
    private boolean buttonCancelClick = false;
    private final SecureRandom randomr = new SecureRandom();

    public ClientActions(IOperations stub) {
        this.stub = stub;
    }

    public boolean iniciateSession() {

        int option = iniciateS();
        if (option != 0) {
            try {
                usingCard = false;
                if (option == 2) {
                    usingCard = true;
                }
                String t = generateRandomToken();
                byte[] makeHash = applyHash(("getChalange" + email + usingCard + t).getBytes());
                makeHash = chipherPhase(makeHash);

                message = stub.getChalange(email, usingCard, makeHash, t);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    System.out.println("Error login  1");
                    return false;
                }
                byte[] response = message.getAnswerByte();
                if (userPass == null) {
                    getPass();
                }
                if (!buttonCancelClick) {
                    findSecretKey();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, key);
                    if (!Arrays.toString(cipher.doFinal(message.getRandomTokenChipher())).equals(Arrays.toString(applyHash(t.getBytes())))) {
                        System.out.println("Error login  2");
                        return false;
                    }
                    response = cipher.doFinal(response);
                    boolean suc = false;
                    if (option == 2) {

                        response = applyHash(response);
                        response = chipherWithCC(response);
                        t = generateRandomToken();
                        makeHash = applyHash(("logIn" + email + Arrays.toString(response) + usingCard + t).getBytes());
                        makeHash = chipherPhase(makeHash);

                        message = stub.logIn(email, response, usingCard, makeHash, t);
                        if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                            System.out.println("Error login  3");
                            return false;
                        }
                        if (!Arrays.toString(cipher.doFinal(message.getRandomTokenChipher())).equals(Arrays.toString(applyHash(t.getBytes())))) {
                            System.out.println("Error login  4");
                            return false;
                        }
                        byte[] tokenEncrp = message.getAnswerByte();
                        BigInteger[] h = message.getAnswerListBigInt();
                        String r = "Error ";
                        if (tokenEncrp != null) {
                            boolean createSessionKey = createSessionKey(tokenEncrp, h[0], h[1]);
                            if (!createSessionKey) {
                                suc = false;
                            } else {
                                r = "Success";
                                suc = true;
                            }
                        }
                        System.out.println("response: " + r);
                        System.out.println("");
                        return suc;
                    } else {
                        if (userPass == null) {
                            getPass();
                        }
                        byte[] ch = chipherWithPassword(response);
                        t = generateRandomToken();
                        makeHash = applyHash(("logIn" + email + Arrays.toString(ch) + usingCard + t).getBytes());
                        makeHash = chipherPhase(makeHash);

                        message = stub.logIn(email, ch, usingCard, makeHash, t);
                        if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                            System.out.println("Error login 5");
                            return false;
                        }
                        if (!Arrays.toString(cipher.doFinal(message.getRandomTokenChipher())).equals(Arrays.toString(applyHash(t.getBytes())))) {
                            System.out.println("Error login 6");
                            return false;
                        }

                        byte[] tokenEncrp = message.getAnswerByte();
                        BigInteger[] h = message.getAnswerListBigInt();
                        String r = "Error ";
                        if (tokenEncrp != null) {
                            boolean createSessionKey = createSessionKey(tokenEncrp, h[0], h[1]);
                            if (!createSessionKey) {
                                suc = false;
                            } else {
                                r = "Success";
                                suc = true;
                            }
                        }
                        System.out.println("response: " + r);
                        System.out.println("");
                        return suc;
                    }
                }
            } catch (RemoteException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                System.out.println("Error in connection");
            }

        }
        return false;
    }

    public boolean terminateSession() {
        try {
            verifyToken();

            String t = generateRandomToken();
            byte[] makeHash = applyHash(("terminateSession" + email + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.terminateSession(email, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return false;
            }
            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return false;
            }
            if (message.getAnswerBol()) {
                email = null;
                key = null;
                pubKey = null;
                userPass = null;
                AssimAlgorithm = "RSA";
                SimAlgorithm = "DES";
                buttonClick = false;
                buttonCancelClick = false;
                buttonLogInClick = false;
                buttonReg = false;
                tokenSession = "";
                key = null;
                usingCard = false;
                return true;
            } else {
                System.out.print("Error terminate Session");
                return false;
            }
        } catch (RemoteException ex) {
            return false;
        }
    }

    private void findSecretKey() {
        try {
            File filePrivateKey = new File("Keys/key-" + email + ".key");
            if (!filePrivateKey.exists()) {
                return;
            }
            PrivateKey pKey;
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("Keys/key-" + email + ".key"));

            byte[] privateKeyBytes = (byte[]) inputStream.readObject();
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            if (userPass == null) {
                getPass();
            }
            if (!buttonCancelClick) {
                KeySpec keySpec = new DESKeySpec(userPass);
                SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
                SecretKey passwordKey = kf.generateSecret(keySpec);
                cipher.init(Cipher.DECRYPT_MODE, passwordKey);
                byte[] textDecrypted = cipher.doFinal(privateKeyBytes);

                KeyFactory kf1 = KeyFactory.getInstance("RSA"); // or "EC" or whatever
                pKey = kf1.generatePrivate(new PKCS8EncodedKeySpec(textDecrypted));

                if (pKey != null && (key == null || key.equals(pKey))) {
                    System.out.println("Chaves privadas Valida");
                    System.out.println();
                }
                key = pKey;
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException ex) {
        }
    }

    private void createSecretKey() {
        try {
            File file = new File("Keys/key-" + email + ".key");
            if (file.exists()) {
                System.out.println("Email already have a Private Key");
                System.gc();
                file.delete();
            }
            file.createNewFile();
            file.createNewFile();
            try ( // Saving the Private key in a file
                    ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(file))) {
                privateKeyOS.writeObject(chipherWithPassword(key.getEncoded()));
            }
        } catch (IOException ex) {
        }
    }

    private void deleteSecretKey() {
        File file = new File("Keys/key-" + email + ".txt");
        if (!file.exists()) {
            return;
        }
        System.gc();
        file.delete();
    }

    public int listAllPbox() {
        try {
            verifyToken();

            String t = generateRandomToken();
            byte[] makeHash = applyHash(("listAllPbox" + tokenSession + email + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.listAllPbox(chipherToken(), email, makeHash, tcipher);

            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return 0;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return 0;
            }
            List<Pbox> response = message.getAnswerListPbox();
            System.out.println("Accounts in Pbox :");
            if (!response.isEmpty()) {
                System.out.println("|-----------------------------------------------------------------------|");
                System.out.println("|\t\tName Client\t\t|\t\t PBoxId \t|");
                System.out.println("|-----------------------------------------------------------------------|");
                for (Pbox response1 : response) {
                    if (response1.getClientsidClients().getName().length() < 6) {
                        System.out.println("|\t" + response1.getClientsidClients().getName() + "\t\t\t|\t\t    " + response1.getIdPbox() + "\t\t|");
                    } else {
                        System.out.println("|\t" + response1.getClientsidClients().getName() + "\t|\t\t    " + response1.getIdPbox() + "\t\t|");
                    }
                }
                System.out.println("|-----------------------------------------------------------------------|");
                System.out.println();
                return response.size();
            }
            System.out.println("No existing PBOX's");
            return 0;
        } catch (RemoteException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }

    public List<Files> listFiles() {
        try {
            verifyToken();

            String t = generateRandomToken();
            byte[] makeHash = applyHash(("listAllFiles" + email + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.listAllFiles(email, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return Collections.EMPTY_LIST;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return Collections.EMPTY_LIST;
            }
            List<Files> response = message.getAnswerListFiles();
            boolean exists;
            if (response != null && !response.isEmpty()) {
                List<Files> listPre = new ArrayList<>();
                for (Files prem : response) {
                    exists = true;
                    for (Files y : listPre) {
                        if (y.getName().equals(prem.getName())) {
                            exists = false;
                        }
                    }
                    if (exists) {
                        listPre.add(prem);
                    }
                }

                System.out.println("You have " + listPre.size() + " Files in Pbox :");
                for (Files response1 : listPre) {
                    System.out.println("\t  File: " + response1.getIdFiles() + "\t Name: " + response1.getName().replace("_" + email, ""));
                }
                System.out.println("");
            } else if (response == null) {
                System.out.println("Your Pbox have no files");
                response = new ArrayList<>();
            } else if (response.isEmpty()) {
                System.out.println("Your Pbox have no files");
            }
            System.out.println("");
            return response;
        } catch (RemoteException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private void generateAssimetricKey() {
        int keyLength;
        if ("ElGamal".equals(AssimAlgorithm)) {
            System.out.print("Key length: ");
            Scanner in = new Scanner(System.in);
            keyLength = in.nextInt();
            System.out.println();
            if (keyLength < 128 || keyLength >= 1024 || keyLength % 64 == 0) {
                keyLength = 512;
            }
        } else {
            System.out.print("Key length(1024,2048,3072): ");
            Scanner in = new Scanner(System.in);
            keyLength = in.nextInt();
            System.out.println();
            if (keyLength != 1024 && keyLength != 2048 && keyLength != 3072) {
                keyLength = 1024;
            }
        }
        try {
            KeyPairGenerator keyPairGenerator;
            if ("ElGamal".equals(AssimAlgorithm)) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                keyPairGenerator = KeyPairGenerator.getInstance(AssimAlgorithm, "BC");
                SecureRandom random = new SecureRandom();
                keyPairGenerator.initialize(keyLength, random);
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(AssimAlgorithm);
                keyPairGenerator.initialize(keyLength);
            }
            keyPairGenerator.initialize(keyLength);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            pubKey = publicKey;
            key = privateKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
        }
    }

    public String getEmail() {
        return email;
    }

    private synchronized String getFileExtension(File file) {
        String fileName = file.getName();
        if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0) {
            return fileName.substring(fileName.lastIndexOf(".") + 1);
        } else {
            return "";
        }
    }

    public void deleteFile(List<String> filesID) {

        System.out.print("• Name of the file to delete:");
        Scanner in = new Scanner(System.in);
        String file = in.nextLine();
        file = findNameFile(file, filesID);
        System.out.println("");
        boolean success;

        if (filesID.contains(file)) {
            try {
                verifyToken();

                String t = generateRandomToken();
                byte[] makeHash = applyHash(("deleteFile" + file + tokenSession + email + t).getBytes());
                makeHash = chipherWithSessionKey(makeHash);
                byte[] tcipher = chipherWithSessionKey(t.getBytes());
                message = stub.deleteFile(file, chipherToken(), email, makeHash, tcipher);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    return;
                }

                if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                    return;
                }
                success = message.getAnswerBol();
                if (success) {
                    System.out.println("File " + file.replace("_" + email, "") + "  Was deleted");
                } else {
                    System.out.println("Error incorret ID : File " + file.replace("_" + email, "") + " don't exit or you do't haver permission");
                }
                System.out.println();
            } catch (RemoteException ex) {
            }
        } else {
            System.out.println("Error incorret Name : File " + file.replace("_" + email, "") + " don't exit ");
            System.out.print("• 1-Try Again 2-Go Back:");
            in = new Scanner(System.in);
            int op = in.nextInt();
            System.out.println("");
            if (op == 1) {
                deleteFile(filesID);
            }
        }
    }

    public void shareTableFile(List<String> filesID) {

        System.out.print("• The file's name that you want to see: ");
        Scanner in = new Scanner(System.in);
        String file = in.nextLine();
        System.out.println("");
        boolean exists;
        try {
            List<Permissions> x;
            verifyToken();

            String t = generateRandomToken();
            byte[] makeHash = applyHash(("shareTableFile" + findNameFile(file, filesID) + tokenSession + email + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.shareTableFile(findNameFile(file, filesID), chipherToken(), email, makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }
            x = message.getAnswerListPerm();
            if (x != null && !x.isEmpty()) {
                System.out.println("\t|-----------------------------------------------------------------------------------------------------------------------------------------------|");
                System.out.println("\t|\t\tFile Name\t|\tFile ID\t\t|\tID Premissions\t|\tPbox ID\t\t|\t\t Name\t\t\t|");
                System.out.println("\t|-----------------------------------------------------------------------------------------------------------------------------------------------|");
                List<Permissions> listPre = new ArrayList<>();
                for (Permissions prem : x) {
                    exists = true;
                    for (Permissions y : listPre) {
                        if ((prem.getPboxidPbox()) == y.getPboxidPbox()) {
                            exists = false;
                        }
                    }
                    if (exists) {
                        System.out.println("\t|\t" + prem.getFilesidFiles().getName() + "\t|\t" + prem.getFilesidFiles().getIdFiles() + "\t\t|\t\t" + prem.getIdPermissions() + "\t|\t\t" + prem.getPboxidPbox().getIdPbox() + "\t|\t" + prem.getPboxidPbox().getClientsidClients().getName() + "\t|");
                        System.out.println("\t|-----------------------------------------------------------------------------------------------------------------------------------------------|");
                        listPre.add(prem);
                    }
                }
            } else {
                System.out.println("There are no information about that file");
                System.out.println();
            }
        } catch (RemoteException ex) {
        }
    }

    private void doCopy(InputStream is, OutputStream os, Cipher cipher) throws IOException {
        byte[] bytes = new byte[sizePacket];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            if (numBytes < 1024) {

                try {
                    os.write(cipher.doFinal(bytes, 0, numBytes));
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                os.write(cipher.update(bytes));
            }
            os.flush();
        }
        os.flush();
        os.close();
        is.close();
    }

    private String convertByteArrayToHexString(byte[] arrayBytes) {
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < arrayBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return stringBuffer.toString();
    }

    private String findNameFile(String file, List<String> filesID) {
        String y = file + "_" + email;
        if (filesID.contains(y)) {
            return y;
        } else if (filesID.contains(file)) {
            return file;
        } else {
            return "";
        }

    }

    public void shareFile(List<String> filesID) {
        try {
            System.out.print("• File Name:");
            Scanner in = new Scanner(System.in);
            String fileName = in.nextLine();
            System.out.println("");
            System.out.print("• Client Email:");
            String emailshare = in.nextLine();
            System.out.println("");
            boolean success;
            verifyToken();

            String t = generateRandomToken();
            byte[] makeHash = applyHash(("findPublicKey" + email + emailshare + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.findPublicKey(email, emailshare, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }

            byte[] pkBytes = dechipherWithSessionKey(message.getAnswerByte());
            PublicKey emailsharePK = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pkBytes));
            verifyToken();

            t = generateRandomToken();
            makeHash = applyHash(("getEncrySymetricKey" + email + findNameFile(fileName, filesID) + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.getEncrySymetricKey(email, findNameFile(fileName, filesID), chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }

            byte[] pass = dechipherWithSessionKey(message.getAnswerByte());
            verifyToken();

            t = generateRandomToken();
            makeHash = applyHash(("getMyAlgorithm" + email + email + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.getMyAlgorithm(email, email, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }

            String myAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
            verifyToken();

            t = generateRandomToken();
            makeHash = applyHash(("getMyAlgorithm" + email + emailshare + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.getMyAlgorithm(email, emailshare, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }

            String hisAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
            byte[] cipherText = null;
            Cipher cipher;
            byte[] plainText = null;
            if (!"".equals(myAlg)) {
                switch (myAlg) {
                    case "RSA":
                        cipher = Cipher.getInstance(myAlg);
                        cipher.init(Cipher.DECRYPT_MODE, key);
                        plainText = cipher.doFinal(pass);
                        break;
                    case "ElGamal":
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                        cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
                        SecureRandom random = new SecureRandom();
                        cipher.init(Cipher.DECRYPT_MODE, key, random);
                        plainText = cipher.doFinal(pass);
                        break;
                }
            }
            if (!"".equals(hisAlg)) {
                switch (hisAlg) {
                    case "RSA":
                        cipher = Cipher.getInstance(hisAlg);
                        cipher.init(Cipher.ENCRYPT_MODE, emailsharePK);
                        cipherText = cipher.doFinal(plainText);
                        break;
                    case "ElGamal":
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                        cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
                        SecureRandom random = new SecureRandom();
                        cipher.init(Cipher.ENCRYPT_MODE, emailsharePK, random);
                        cipherText = cipher.doFinal(plainText);
                        break;
                }
            }
            System.out.println(findNameFile(fileName, filesID));
            verifyToken();

            t = generateRandomToken();
            makeHash = applyHash(("shareFile" + findNameFile(fileName, filesID) + email + emailshare + Arrays.toString(cipherText) + tokenSession + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.shareFile(findNameFile(fileName, filesID), email, emailshare, cipherText, chipherToken(), makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }

            if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                return;
            }

            success = message.getAnswerBol();
            if (success) {
                System.out.println("File " + fileName + " shared with Pbox " + emailshare);
            } else {
                System.out.println("Error incorret ID's : File " + fileName + " or Pbox " + emailshare);

            }
            System.out.println();
        } catch (RemoteException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | NoSuchProviderException ex) {

        } catch (UnsupportedEncodingException | InvalidKeySpecException ex) {
            System.out.println("Wrong email");
        }
    }

    public void addFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(new JPanel());
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            System.out.println(selectedFile.getName());
            try {
                verifyToken();

                String t = generateRandomToken();
                byte[] makeHash = applyHash(("findPublicKey" + email + email + tokenSession + t).getBytes());
                makeHash = chipherWithSessionKey(makeHash);
                byte[] tcipher = chipherWithSessionKey(t.getBytes());
                message = stub.findPublicKey(email, email, chipherToken(), makeHash, tcipher);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    return;
                }

                if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                    return;
                }

                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(dechipherWithSessionKey(message.getAnswerByte())));

//System.out.println("My public key:" + publicKey);
                //gerar chave simetrica aleatoria
                Scanner in = new Scanner(System.in);

                System.out.println("");
                System.out.println("1-AES");
                System.out.println("2-DES");
                System.out.println("3-Triple DES");
                System.out.println("4-RC2");
                System.out.println("5-Blowfish");
                System.out.print("Option:");
                int chose = in.nextInt();
                System.out.println("");
                //shose the algoritmo:
                int length = 56;
                switch (chose) {
                    case 1:
                        SimAlgorithm = "AES";
                        System.out.print("Key length(128,192,256): ");
                        length = in.nextInt();
                        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
                        if ((length != 128 && length != 192 && length != 256)) {
                            length = 128;
                        } else if (maxKeyLen < length) {
                            length = 128;
                        }
                        System.out.println("");
                        break;
                    case 2:
                        SimAlgorithm = "DES";
                        length = 56;
                        break;
                    case 3:
                        SimAlgorithm = "DESede";
                        length = 168;
                        break;
                    case 4:
                        SimAlgorithm = "RC2";
                        length = 128;
                        break;
                    case 5:
                        SimAlgorithm = "Blowfish";
                        length = 128;
                        break;
                }
                ///////////////////////////
                //System.out.println("Generate simetrickey");
                KeyGenerator keyGen = KeyGenerator.getInstance(SimAlgorithm);
                keyGen.init(length);
                SecretKey keySimetric = keyGen.generateKey();
                //codificar ficheiro com a chave
                ////////////////////////////////////////////////////////////////////////////////
                Cipher cipherSimetric;

                cipherSimetric = Cipher.getInstance(SimAlgorithm + "/ECB/PKCS5Padding");

                cipherSimetric.init(Cipher.ENCRYPT_MODE, keySimetric);
                File ciphertextFile = new File("encrypt_" + selectedFile.getName());
                //System.out.println("Start encrypt file");
                ciphertextFile.createNewFile();

                InputStream fileData = new FileInputStream(selectedFile);
                FileOutputStream fos = new FileOutputStream(ciphertextFile);
                //CipherOutputStream cos = new CipherOutputStream(fos, cipherSimetric);
                byte[] block = new byte[sizePacket];
                int i;
                while ((i = fileData.read(block)) != -1) {
                    if (i < sizePacket) {
                        fos.write(cipherSimetric.doFinal(block, 0, i));
                    } else {

                        fos.write(cipherSimetric.update(block));
                    }
                    fos.flush();
                }
                fos.flush();
                fos.close();

                System.gc();
                fileData.close();
                //System.out.println("end encrypt file");
                //codificar chave com a minha publicKey 
                //System.out.println("encrypt my public key");
                Cipher cipher;
                verifyToken();

                t = generateRandomToken();
                makeHash = applyHash(("getMyAlgorithm" + email + email + tokenSession + t).getBytes());
                makeHash = chipherWithSessionKey(makeHash);
                tcipher = chipherWithSessionKey(t.getBytes());
                message = stub.getMyAlgorithm(email, email, chipherToken(), makeHash, tcipher);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    return;
                }

                if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                    return;
                }
                AssimAlgorithm = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                if ("ElGamal".equals(AssimAlgorithm)) {
                    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                    cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
                    SecureRandom random = new SecureRandom();
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
                } else {
                    cipher = Cipher.getInstance(AssimAlgorithm);
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                }

                byte[] keyEncrypted = cipher.doFinal(keySimetric.getEncoded());

                //////////////////////////
                //apply hash
                File hashFile = new File("hash_" + selectedFile.getName());
                fileData = new FileInputStream(ciphertextFile);
                fos = new FileOutputStream(hashFile);
                block = new byte[sizePacket - 20];
                byte[] sendbytes;
                byte[] hashedBytes;
                int result;

                while ((result = fileData.read(block)) != -1) {
                    if (result != sizePacket) {
                        byte[] block1 = new byte[result];
                        System.arraycopy(block, 0, block1, 0, result);
                        block = block1;
                    }
                    hashedBytes = applyHash(block);
                    if (hashedBytes.length < 20) {
                        System.out.println("Hash length error: should be 20 and is " + hashedBytes.length + " resulting in a incoerent  (" + (hashedBytes.length + result) + " bytes)");
                    } else if (hashedBytes.length > 20) {
                        System.out.println("Hash length error: should be 20 and is " + hashedBytes.length + " resulting in a file with more than 1024bytes (" + (hashedBytes.length + result) + " bytes)");
                    }
                    sendbytes = new byte[result + hashedBytes.length];
                    System.arraycopy(hashedBytes, 0, sendbytes, 0, hashedBytes.length);
                    System.arraycopy(block, 0, sendbytes, hashedBytes.length, result);
                    fos.write(sendbytes);
                    fos.flush();
                }
                fos.flush();
                fos.close();
                System.gc();
                fileData.close();
                //////////////////////////
                //enviar ficheiro
                System.out.println("Sending file...");
                InputStream fileData1 = new FileInputStream(hashFile);
                RemoteInputStreamServer remoteFileData = new SimpleRemoteInputStream(fileData1);
                String extension = getFileExtension(selectedFile);
                //-1 file corrupted, -2 file name already exists, -3 generic exception 0 end with Success
                verifyToken();

                t = generateRandomToken();
                makeHash = applyHash(("uploadFile" + selectedFile.getName() + email + SimAlgorithm + Arrays.toString(keyEncrypted) + extension + tokenSession + t).getBytes());
                makeHash = chipherWithSessionKey(makeHash);
                tcipher = chipherWithSessionKey(t.getBytes());
                message = stub.uploadFile(selectedFile.getName(), email, SimAlgorithm, remoteFileData.export(), keyEncrypted, extension, chipherToken(), makeHash, tcipher);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    return;
                }

                if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                    return;
                }

                int x = message.getAnswerInt();
                if (x == 0) {
                    System.out.println("Sucess send file");
                } else if (x == -1) {
                    System.out.println("Error: file corrupted");

                } else if (x == -2) {
                    System.out.println("You already have a file with the name " + selectedFile.getName());

                } else if (x == -3) {
                    System.out.println("Error send file, File corrupted in transmission");
                } else if (x == -4) {
                    System.out.println("Invalid Token");
                }

                fileData1.close();

                remoteFileData.close();
                hashFile.delete();
                ciphertextFile.delete();
            } catch (RemoteException ex) {
                System.gc();
                File f = new File("encrypt_" + selectedFile.getName());
                File f1 = new File("hash_" + selectedFile.getName());
                f.delete();
                f1.delete();

            } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
                System.gc();
                File f = new File("encrypt_" + selectedFile.getName());
                File f1 = new File("hash_" + selectedFile.getName());
                f.delete();
                f1.delete();

            } catch (NoSuchProviderException ex) {
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void getFile(List<String> filesID) {
        try {
            System.out.print("• File Name:");
            Scanner in = new Scanner(System.in);
            String fileName = in.nextLine();
            System.out.println("");
            if (filesID.contains(findNameFile(fileName, filesID))) {
                // create a RemoteStreamServer which uses no compression over the wire (note
                // the finally block to release RMI resources no matter what happens)
                RemoteOutputStreamServer ostream = null;
                String fileExt;
                verifyToken();

                String t = generateRandomToken();
                byte[] makeHash = applyHash(("getExtensionFile" + findNameFile(fileName, filesID) + tokenSession + email + t).getBytes());
                makeHash = chipherWithSessionKey(makeHash);
                byte[] tcipher = chipherWithSessionKey(t.getBytes());
                message = stub.getExtensionFile(findNameFile(fileName, filesID), chipherToken(), email, makeHash, tcipher);
                if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                    return;
                }

                if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                    return;
                }
                fileExt = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                if ("".equals(fileExt)) {
                    System.out.println("The file does not have extension");
                }
                File fileHash = new File("hash_" + fileName + "." + fileExt);
                File fileEnc = new File("enc_" + fileName + "." + fileExt);
                File fileOriginal = new File(fileName + "." + fileExt);
                try {

                    ostream = new SimpleRemoteOutputStream(new BufferedOutputStream(new FileOutputStream(fileHash)));
                    // call server (note export() call to get actual remote interface)
                    verifyToken();

                    t = generateRandomToken();
                    makeHash = applyHash(("getFile" + findNameFile(fileName, filesID) + email + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getFile(ostream.export(), findNameFile(fileName, filesID), email, chipherToken(), makeHash, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }
                    int x = message.getAnswerInt();
                    boolean integraty;

                    if (x == 0) {
                        try (InputStream fileData = new FileInputStream(fileHash); OutputStream cos = new FileOutputStream(fileEnc)) {
                            byte[] block = new byte[sizePacket];
                            int i;
                            while ((i = fileData.read(block)) != -1) {
                                integraty = false;
                                byte[] hashArray;
                                byte[] dataArray;

                                if (i != sizePacket) {
                                    hashArray = Arrays.copyOfRange(block, 0, 20);
                                    dataArray = Arrays.copyOfRange(block, 20, i);
                                } else {
                                    hashArray = Arrays.copyOfRange(block, 0, 20);
                                    dataArray = Arrays.copyOfRange(block, 20, sizePacket);
                                }
                                if (convertByteArrayToHexString(hashArray).equals(convertByteArrayToHexString(applyHash(dataArray)))) {
                                    integraty = true;
                                }

                                if (integraty) {
                                    cos.write(dataArray, 0, i - 20);
                                    cos.flush();
                                } else {
                                    System.out.println("Error downloading File - 1");
                                    cos.flush();
                                    cos.close();
                                    fileData.close();
                                    System.gc();
                                    fileHash.delete();
                                    fileEnc.delete();
                                    return;
                                }
                            }
                            fileData.close();
                        }
                        ostream.close();
                    } else {
                        System.out.println("Error downloading File - 3");
                        System.gc();
                        fileHash.delete();
                        fileEnc.delete();
                        return;
                    }
                    findSecretKey();
                    verifyToken();

                    t = generateRandomToken();
                    makeHash = applyHash(("getEncrySymetricKey" + email + findNameFile(fileName, filesID) + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getEncrySymetricKey(email, findNameFile(fileName, filesID), chipherToken(), makeHash, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }
                    byte[] pass = dechipherWithSessionKey(message.getAnswerByte());
                    verifyToken();

                    t = generateRandomToken();
                    makeHash = applyHash(("getMyAlgorithm" + email + email + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getMyAlgorithm(email, email, chipherToken(), makeHash, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }
                    String myAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                    String fileAlg = "";
                    Cipher cipher;
                    byte[] simKey = null;
                    if (!"".equals(myAlg)) {
                        switch (myAlg) {
                            case "RSA":
                                cipher = Cipher.getInstance("RSA");
                                cipher.init(Cipher.DECRYPT_MODE, key);
                                simKey = cipher.doFinal(pass);
                                break;
                            case "ElGamal":

                                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                                cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
                                SecureRandom random = new SecureRandom();
                                cipher.init(Cipher.DECRYPT_MODE, key, random);
                                simKey = cipher.doFinal(pass);
                                break;
                        }
                        verifyToken();

                        t = generateRandomToken();
                        makeHash = applyHash(("getAlgorithmFile" + findNameFile(fileName, filesID) + tokenSession + email + t).getBytes());
                        makeHash = chipherWithSessionKey(makeHash);
                        tcipher = chipherWithSessionKey(t.getBytes());
                        message = stub.getAlgorithmFile(findNameFile(fileName, filesID), chipherToken(), email, makeHash, tcipher);
                        if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                            return;
                        }

                        if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                            return;
                        }
                        fileAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                        if (!"".equals(fileAlg) && simKey != null) {
                            SecretKey originalKey = new SecretKeySpec(simKey, 0, simKey.length, fileAlg);

                            //Create the cipher
                            Cipher desCipher;
                            desCipher = Cipher.getInstance(fileAlg + "/ECB/PKCS5Padding");
                            desCipher.init(Cipher.DECRYPT_MODE, originalKey);

                            FileOutputStream os;
                            try ( //decrypt file
                                    FileInputStream is = new FileInputStream(fileEnc)) {
                                os = new FileOutputStream(fileOriginal);
                                doCopy(is, os, desCipher);
                            }
                            os.close();
                        }
                    }
                    if ("".equals(myAlg) || "".equals(fileAlg) || null == simKey) {
                        System.gc();
                        fileEnc.delete();
                        fileHash.delete();
                        System.out.println("Error decrypting File - 1");
                    }
                } catch (RemoteException | FileNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
                    System.gc();
                    fileOriginal.delete();
                    System.out.println("Error decrypting File - 2");
                } catch (IOException ex) {
                    System.out.println("Error reciving File");
                } finally {
                    System.gc();
                    fileHash.delete();
                    fileEnc.delete();

                    // since the server should have done all the work in the getFile()
                    // call, we always want to close the stream
                    if (ostream != null) {
                        ostream.close();
                    }
                    System.out.println("Download File Complete");
                    System.out.println();
                }
            } else {
                System.out.println("You don't have any file with that name.");
                System.out.print("• 1-Try Again 2-Go Back:");
                in = new Scanner(System.in);
                int op = in.nextInt();
                System.out.println("");
                if (op == 1) {
                    getFile(filesID);
                }
            }
        } catch (RemoteException ex) {
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    void updateFile(List<String> filesID) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(new JPanel());
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            System.out.println(selectedFile.getName());

            boolean exists = false;
            String fileNameDB = "";
            String fileName = selectedFile.getName().substring(0, selectedFile.getName().lastIndexOf("."));
            String extension = getFileExtension(selectedFile);
            for (String x : filesID) {
                if (x.contains(fileName)) {
                    fileNameDB = x;
                    exists = true;
                }
            }
            if (exists) {
                try {
                    verifyToken();

                    String t = generateRandomToken();
                    byte[] makeHash = applyHash(("getEncrySymetricKey" + email + fileNameDB + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    byte[] tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getEncrySymetricKey(email, fileNameDB, chipherToken(), makeHash, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }

                    byte[] pass = dechipherWithSessionKey(message.getAnswerByte());
                    verifyToken();

                    t = generateRandomToken();
                    makeHash = applyHash(("getMyAlgorithm" + email + email + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getMyAlgorithm(email, email, chipherToken(), makeHash, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }

                    String myAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                    Cipher cipher;
                    byte[] plainText = null;
                    if (!"".equals(myAlg)) {
                        switch (myAlg) {
                            case "RSA":
                                cipher = Cipher.getInstance(myAlg);
                                cipher.init(Cipher.DECRYPT_MODE, key);
                                plainText = cipher.doFinal(pass);
                                break;
                            case "ElGamal":
                                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                                cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
                                SecureRandom random = new SecureRandom();
                                cipher.init(Cipher.DECRYPT_MODE, key, random);
                                plainText = cipher.doFinal(pass);
                                break;
                        }
                    }

                    //System.out.println("My public key:" + publicKey);          
                    ///////////////////////////
                    //System.out.println("Generate simetrickey");
                    verifyToken();

                    t = generateRandomToken();
                    byte[] makeHashs = applyHash(("getAlgorithmFile" + fileNameDB + tokenSession + email + t).getBytes());
                    makeHashs = chipherWithSessionKey(makeHashs);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.getAlgorithmFile(fileNameDB, chipherToken(), email, makeHashs, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }

                    String fileAlg = new String(dechipherWithSessionKey(message.getAnswerByte()), "UTF-8");
                    SecretKey keySimetric = null;
                    if (plainText != null) {
                        keySimetric = new SecretKeySpec(plainText, 0, plainText.length, fileAlg);
                    }
                    //codificar ficheiro com a chave
                    ////////////////////////////////////////////////////////////////////////////////
                    Cipher cipherSimetric;

                    cipherSimetric = Cipher.getInstance(fileAlg + "/ECB/PKCS5Padding");

                    cipherSimetric.init(Cipher.ENCRYPT_MODE, keySimetric);
                    File ciphertextFile = new File("encrypt_" + selectedFile.getName());
                    //System.out.println("Start encrypt file");
                    ciphertextFile.createNewFile();

                    InputStream fileData = new FileInputStream(selectedFile);
                    FileOutputStream fos = new FileOutputStream(ciphertextFile);
                    //CipherOutputStream cos = new CipherOutputStream(fos, cipherSimetric);
                    byte[] block = new byte[sizePacket];
                    int i;
                    while ((i = fileData.read(block)) != -1) {
                        if (i < sizePacket) {
                            fos.write(cipherSimetric.doFinal(block, 0, i));
                        } else {

                            fos.write(cipherSimetric.update(block));
                        }
                        fos.flush();
                    }
                    fos.flush();
                    fos.close();

                    System.gc();
                    fileData.close();
                    //System.out.println("end encrypt file");
                    //codificar chave com a minha publicKey 
                    //System.out.println("encrypt my public key");

                    //////////////////////////
                    //apply hash
                    File hashFile = new File("hash_" + selectedFile.getName());
                    fileData = new FileInputStream(ciphertextFile);
                    fos = new FileOutputStream(hashFile);
                    block = new byte[sizePacket - 20];
                    byte[] sendbytes;
                    byte[] hashedBytes;
                    int result;
                    while ((result = fileData.read(block)) != -1) {
                        if (result != sizePacket) {
                            byte[] block1 = new byte[result];
                            System.arraycopy(block, 0, block1, 0, result);
                            block = block1;
                        }
                        hashedBytes = applyHash(block);
                        if (hashedBytes.length < 20) {
                            System.out.println("Hash length error: should be 20 and is " + hashedBytes.length + " resulting in a incoerent  (" + (hashedBytes.length + result) + " bytes)");
                        } else if (hashedBytes.length > 20) {
                            System.out.println("Hash length error: should be 20 and is " + hashedBytes.length + " resulting in a file with more than 1024bytes (" + (hashedBytes.length + result) + " bytes)");
                        }
                        sendbytes = new byte[result + hashedBytes.length];
                        System.arraycopy(hashedBytes, 0, sendbytes, 0, hashedBytes.length);
                        System.arraycopy(block, 0, sendbytes, hashedBytes.length, result);
                        fos.write(sendbytes);
                        fos.flush();
                    }
                    fos.flush();
                    fos.close();
                    System.gc();
                    fileData.close();
                    //////////////////////////
                    //enviar ficheiro
                    System.out.println("Sending file...");
                    InputStream fileData1 = new FileInputStream(hashFile);
                    RemoteInputStreamServer remoteFileData = new SimpleRemoteInputStream(fileData1);

                    //-1 file corrupted, -2 file name already exists, -3 generic exception 0 end with Success
                    verifyToken();

                    t = generateRandomToken();
                    makeHashs = applyHash(("modifyFile" + fileNameDB + email + SimAlgorithm + extension + tokenSession + t).getBytes());
                    makeHashs = chipherWithSessionKey(makeHashs);
                    tcipher = chipherWithSessionKey(t.getBytes());
                    message = stub.modifyFile(fileNameDB, email, SimAlgorithm, remoteFileData.export(), extension, chipherToken(), makeHashs, tcipher);
                    if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                        return;
                    }

                    if (!(Arrays.equals(dechipherWithSessionKey(message.getRandomTokenChipher()), applyHash(t.getBytes())))) {
                        return;
                    }
                    int x = message.getAnswerInt();
                    if (x == 0) {
                        System.out.println("Sucess send file");
                    } else if (x == -1) {
                        System.out.println("Error: file corrupted");

                    } else if (x == -3) {
                        System.out.println("Error send file, File corrupted in transmission");
                    } else if (x == -4) {
                        System.out.println("Invalid Token");
                    }

                    fileData1.close();

                    remoteFileData.close();
                    hashFile.delete();
                    ciphertextFile.delete();
                } catch (RemoteException ex) {
                    System.gc();
                    File f = new File("encrypt_" + selectedFile.getName());
                    File f1 = new File("hash_" + selectedFile.getName());
                    f.delete();
                    f1.delete();
                } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
                    System.gc();
                    File f = new File("encrypt_" + selectedFile.getName());
                    File f1 = new File("hash_" + selectedFile.getName());
                    f.delete();
                    f1.delete();
                } catch (NoSuchProviderException ex) {
                }
            }
        } else {
            System.out.println("Can't Update: You don't have any file in your PBOX with that name");
            System.out.println();
        }
    }

    void unShareFile(List<String> filesID) {
        System.out.print("• File Name:");
        Scanner in = new Scanner(System.in);
        String fileName = in.nextLine();
        System.out.println("");
        if (filesID.contains(findNameFile(fileName, filesID))) {
            String y = fileName + "_" + email;
            if (filesID.contains(y)) {
                try {
                    System.out.print("• Client Email to remove access:");
                    String emailshare = in.nextLine();
                    System.out.println("");
                    verifyToken();
                    String t = generateRandomToken();
                    byte[] makeHash = applyHash(("unshareFile" + findNameFile(fileName, filesID) + email + emailshare + tokenSession + t).getBytes());
                    makeHash = chipherPhase(makeHash);
                    byte[] tcipher = chipherWithSessionKey(t.getBytes());
                    stub.unshareFile(findNameFile(fileName, filesID), email, emailshare, chipherToken(), makeHash, tcipher);
                    System.out.println(emailshare + " lost is access to file " + fileName);
                } catch (RemoteException ex) {
                }
            } else {
                try {
                    verifyToken();
                    String t = generateRandomToken();
                    byte[] makeHash = applyHash(("unshareFile" + findNameFile(fileName, filesID) + email + email + tokenSession + t).getBytes());
                    makeHash = chipherWithSessionKey(makeHash);
                    byte[] tcipher = chipherWithSessionKey(t.getBytes());
                    stub.unshareFile(findNameFile(fileName, filesID), email, email, chipherToken(), makeHash, tcipher);
                    System.out.println("Your access was remove from the file");
                } catch (RemoteException ex) {
                }
            }
        } else {
            System.out.println("Wrong name - You file must have the same name as the file you want to update in PBOX ");
            System.out.println();
        }
    }

    public boolean createSessionKey(byte[] pkServer, BigInteger p, BigInteger g) {
        try {
            byte[] publicKeyDH = generatePrivateKeyDH(p, g, pkServer);
            String t = generateRandomToken();
            byte[] applyHash = applyHash(("sendPublicKeyDH" + Arrays.toString(publicKeyDH) + email + t).getBytes());
            message = stub.sendPublicKeyDH(publicKeyDH, email, applyHash, t);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                System.out.println("Error HD");
                return false;
            }
        } catch (RemoteException ex) {
            System.out.println("Error HD Algoritmo :" + ex);
            return false;
        }
        return true;
    }

    private X509Certificate[] getCertificatesCC() {
        JFrame f = new JFrame("JProgressBar Sample");
        f.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        f.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // do whatever else
            }
        });
        f.setLocationRelativeTo(null);
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        f.setLocation(dim.width / 2 - f.getSize().width / 2, dim.height / 2 - f.getSize().height / 2);
        Container content = f.getContentPane();
        JProgressBar progressBar = new JProgressBar();
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        Border border = BorderFactory.createTitledBorder("Reading Citizen Card...");
        progressBar.setBorder(border);
        content.add(progressBar, BorderLayout.NORTH);
        f.setSize(300, 100);
        f.setAlwaysOnTop(true);
        f.setVisible(true);

        String library = null, conf;
        KeyStore ks = null;
        if (System.getProperty("os.name").contains("Windows")) {
            library = "C:/WINDOWS/system32/pteidpkcs11.dll";
        } else if (System.getProperty("os.name").contains("Linux")) {
            library = "/usr/local/lib/libpteidpkcs11.so";
        }
        try {
            conf = "name = PortugueseEId\nlibrary = " + library + "\n";
            SunPKCS11 provider = new SunPKCS11(new ByteArrayInputStream(conf.getBytes()));
            int i = 0;
            do {
                try {
                    ks = KeyStore.getInstance("PKCS11", provider);
                } catch (KeyStoreException ex) {
                    if (i == 0) {
                        //System.out.println("Insert your Citizen Card (you have 20 seconds)");
                    }
                    if (i != 10) {
                        try {
                            //System.out.println((20-i*2)+"s");
                            progressBar.setValue(i * 10 + 5);
                            Thread.sleep(1000);
                            progressBar.setValue(i * 10 + 10);
                            Thread.sleep(1000);
                        } catch (InterruptedException ex1) {
                        }
                    }
                }
                i++;
            } while (i != 11 && ks == null);
            System.out.println("");

            progressBar.setValue(100);
            try {
                Thread.sleep(500);
            } catch (InterruptedException ex) {
            }
            f.setVisible(false);
            if (ks == null) {
                return null;
            }
            // Initialize the PKCS#11 token
            ks.load(null, null);

            pkCC = (X509Certificate) ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");

            X509Certificate[] chain = new X509Certificate[4];
            chain[0] = getCertificate(ks, "CITIZEN AUTHENTICATION CERTIFICATE");
            chain[1] = getCertificate(ks, "AUTHENTICATION SUB CA");
            chain[2] = getCertificate(ks, "CITIZEN SIGNATURE CERTIFICATE");
            chain[3] = getCertificate(ks, "SIGNATURE SUB CA");

            String subjectDN = pkCC.getSubjectDN().getName();
            userName = subjectDN.substring(subjectDN.indexOf("CN=") + 3, subjectDN.indexOf(","));
            return chain;

        } catch (NoSuchAlgorithmException | CertificateException e) {
            System.out.println("Error reading card");
        } catch (IOException ex) {
            System.out.println("Card Reader undetected");
        } catch (KeyStoreException ex) {
            System.out.println("Card Removed");
        }
        return null;
    }

    private X509Certificate getCertificate(KeyStore token, String certLabel) {
        X509Certificate cert = null;
        try {
            cert = (X509Certificate) token.getCertificate(certLabel);

        } catch (KeyStoreException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cert;
    }

    public int choseMenu() {
        JFrame frame1 = new JFrame("Menu");
        frame1.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame1.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                Component frame = null;
                JOptionPane.showMessageDialog(frame, "Exit Programe", "Inane warning", JOptionPane.WARNING_MESSAGE);
                System.exit(1);
            }
        });
        frame1.setSize(150, 110);
        frame1.setLocationRelativeTo(null);
        JPanel panel = new JPanel();
        frame1.setResizable(false);
        frame1.add(panel);
        JButton loginButton = new JButton("Register");
        loginButton.setBounds(20, 10, 80, 25);
        panel.add(loginButton);
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonReg = true;
            }
        });

        JButton registerButton = new JButton("LogIn");
        registerButton.setBounds(10, 20, 80, 25);
        panel.add(registerButton);
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonLogInClick = true;
            }
        });

        frame1.setVisible(true);
        panel.setLayout(null);
        while (!buttonReg && !buttonLogInClick) {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException ex) {
                Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        frame1.setVisible(false);
        int op = 2;
        if (buttonReg) {
            op = 1;
        }
        buttonLogInClick = false;
        buttonReg = false;
        return op;
    }

    private int iniciateS() {
        JFrame frame3 = new JFrame("Register");
        frame3.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame3.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // do whatever else
            }
        });
        buttonCancelClick = false;
        buttonClick = false;
        buttonReg = false;
        frame3.setSize(350, 140);
        frame3.setLocationRelativeTo(null);
        JPanel panel = new JPanel();
        frame3.add(panel);
        frame3.setResizable(false);
        JLabel userLabel = new JLabel("     Email     ");
        userLabel.setBounds(10, 10, 80, 25);
        panel.add(userLabel);

        JTextField userText = new JTextField(20);
        userText.setBounds(210, 10, 160, 25);
        panel.add(userText);

        JButton loginButton = new JButton("Card");
        loginButton.setBounds(10, 180, 80, 25);
        panel.add(loginButton);
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonClick = true;
            }
        });

        JButton registerButton = new JButton("Password");
        registerButton.setBounds(180, 180, 80, 25);
        panel.add(registerButton);
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonReg = true;
            }
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.setBounds(180, 180, 80, 25);
        panel.add(cancelButton);
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonCancelClick = true;
            }
        });
        frame3.setVisible(true);
        panel.setLayout(null);

        boolean state;
        int op = 0;
        do {
            state = false;
            if ((buttonReg && !"".equals(userText.getText())) || (buttonClick && !"".equals(userText.getText())) || buttonCancelClick) {
                state = true;
            }
            if (buttonReg && !"".equals(userText.getText())) {
                op = 1;
            }
            if (buttonClick && !"".equals(userText.getText())) {
                op = 2;
            }
            if (buttonCancelClick) {
                op = 0;
            }
            buttonCancelClick = false;
            buttonClick = false;
            buttonReg = false;
            try {
                Thread.sleep(2000);
            } catch (InterruptedException ex) {
                Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
            }

        } while (!state);
        frame3.setVisible(false);
        if (op == 1 || op == 2) {
            email = userText.getText();
        }

        return op;
    }

    public boolean createAccount() {
        try {
            String name;

            JFrame frame = new JFrame("Register");
            frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            frame.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    // do whatever else
                }
            });
            frame.setSize(350, 140);
            frame.setLocationRelativeTo(null);
            JPanel panel = new JPanel();
            frame.add(panel);
            frame.setResizable(false);
            JLabel userLabel = new JLabel("     Email     ");
            userLabel.setBounds(10, 10, 80, 25);
            panel.add(userLabel);

            JTextField userText = new JTextField(20);
            userText.setBounds(210, 10, 160, 25);
            panel.add(userText);

            JLabel passwordLabel = new JLabel(" Password ");
            passwordLabel.setBounds(10, 150, 80, 25);
            panel.add(passwordLabel);

            JTextField passwordText = new JPasswordField(20);
            passwordText.setBounds(210, 150, 160, 25);
            panel.add(passwordText);

            JButton loginButton = new JButton("Register");
            loginButton.setBounds(10, 180, 80, 25);
            panel.add(loginButton);
            loginButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    buttonClick = true;
                }
            });

            JButton registerButton = new JButton("Cancel");
            registerButton.setBounds(180, 180, 80, 25);
            panel.add(registerButton);
            registerButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    buttonCancelClick = true;
                }
            });

            frame.setVisible(true);
            panel.setLayout(null);
            while (!buttonCancelClick && !(buttonClick && passwordText.getText().length() > 7 && !"".equals(passwordText.getText()) && !"".equals(userText.getText()) && !"".equals(userText.getText()))) {
                try {
                    Component frame2 = null;
                    if (passwordText.getText().length() < 8 && buttonClick) {
                        JOptionPane.showMessageDialog(frame2, "Password must have 8 characters!");
                    }
                    if (("".equals(userText.getText()) || "".equals(userText.getText())) && buttonClick) {
                        JOptionPane.showMessageDialog(frame, "Invalid email");
                    }
                    buttonCancelClick = false;
                    buttonClick = false;
                    Thread.sleep(2000);
                } catch (InterruptedException ex) {
                    Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            email = userText.getText();
            userPass = applyHash(passwordText.getText().getBytes());
            frame.setVisible(false);

            if (!buttonCancelClick) {

                X509Certificate[] certs = getCertificatesCC();
                if (pkCC != null && certs != null) {
                    generateAssimetricKey();
                    if (passwordText.getText().length() > 7 && !"".equals(email) && email != null && !" ".equals(email) && email.contains("@") && email.indexOf("@") == email.lastIndexOf("@") && email.contains(".") && email.indexOf(".") == email.lastIndexOf(".") && !"".equals(userName) && !" ".equals(userName)) {
                        String t = generateRandomToken();
                        byte[] testUnsigned = (new BigInteger(130, randomr).toString(32)).getBytes();
                        byte[] testSigned = chipherWithCC(testUnsigned);
                        byte[] messageIntegraty = applyHash((email + userName + pubKey + AssimAlgorithm + pkCC + Arrays.toString(userPass) + t + Arrays.toString(testUnsigned) + Arrays.toString(testSigned)).getBytes());
                        message = stub.register(email, userName, pubKey, AssimAlgorithm, pkCC, userPass, certs, t, testUnsigned, testSigned, messageIntegraty);
                        if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                            System.out.println("Not valid value of Name or Email - 1");
                            return false;
                        }
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.DECRYPT_MODE, key);
                        if (!Arrays.toString(cipher.doFinal(message.getRandomTokenChipher())).equals(Arrays.toString(applyHash(t.getBytes())))) {
                            System.out.println("Not valid value of Name or Email - 2");
                            return false;
                        }

                        if (message.getAnswerBol()) {
                            createSecretKey();
                            System.out.println("Account Sucesseful Created");
                            return true;
                        } else {
                            System.out.println("Email already exist");
                        }
                    } else {
                        System.out.println("Not valid value of Name or Email - 3 ");
                        if (passwordText.getText().length() < 8) {
                            System.out.println("Password must have 8 characters!");
                        }
                    }
                    deleteSecretKey();
                    email = null;
                    pubKey = null;
                    key = null;
                    userPass = null;
                    tokenSession = "";
                    key = null;
                    usingCard = false;
                    System.out.println("Error in register");
                    System.out.println();
                    return false;
                }
                System.out.println("Error Reading Card");
            }
            buttonCancelClick = false;
            buttonClick = false;
        } catch (RemoteException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private byte[] chipherWithPassword(byte[] challenge) {
        if (userPass != null) {
            try {
                Cipher desCipher;
                // Create the cipher
                desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                DESKeySpec keySpec = new DESKeySpec(userPass);
                SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
                SecretKey passwordKey = kf.generateSecret(keySpec);
                // Initialize the cipher for encryption
                desCipher.init(Cipher.ENCRYPT_MODE, passwordKey);

                // Encrypt the text
                byte[] textEncrypted = desCipher.doFinal(challenge);
                return textEncrypted;
            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException ex) {
                Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    private byte[] chipherWithCC(byte[] challenge) {
        String pin = "";
        /*System.out.println("Insert your pin");
         Scanner in = new Scanner(System.in);
         int num = in.nextInt();
         pin+=num;
         if (pin.length() != 4) {
         System.out.println("Invalide pin");
         }*/
        PrivateKey keyCC;
        String keyLabel = "CITIZEN AUTHENTICATION CERTIFICATE";
        Signature signature; // the object to compute the signature
        try {
            KeyStore token = getKeyStore();

            keyCC = (PrivateKey) token.getKey(keyLabel, pin.toCharArray());
            signature = Signature.getInstance("SHA1withRSA", token.getProvider());
            signature.initSign(keyCC);
            signature.update(challenge);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException (SHA1withRSA) for token:" + e);
        } catch (InvalidKeyException e) {
            System.out.println("InvalidKeyException while computing signature:" + e);
        } catch (SignatureException e) {
            System.out.println("SignatureException while computing signature:" + e);
        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (key == null) {
            System.out.println("Could not get private key with label " + keyLabel);
        }
        return null;
    }

    private KeyStore getKeyStore() {
        JFrame f = new JFrame("JProgressBar Sample");
        f.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        f.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // do whatever else
            }
        });
        f.setLocationRelativeTo(null);
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        f.setLocation(dim.width / 2 - f.getSize().width / 2, dim.height / 2 - f.getSize().height / 2);
        Container content = f.getContentPane();
        JProgressBar progressBar = new JProgressBar();
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        Border border = BorderFactory.createTitledBorder("Reading Citizen Card...");
        progressBar.setBorder(border);
        content.add(progressBar, BorderLayout.NORTH);
        f.setSize(300, 100);
        f.setAlwaysOnTop(true);
        f.setVisible(true);

        String library = null, conf;
        KeyStore ks = null;
        if (System.getProperty("os.name").contains("Windows")) {
            library = "C:/WINDOWS/system32/pteidpkcs11.dll";
        } else if (System.getProperty("os.name").contains("Linux")) {
            library = "/usr/local/lib/libpteidpkcs11.so";
        }
        try {
            conf = "name = PortugueseEId\nlibrary = " + library + "\n";
            SunPKCS11 provider = new SunPKCS11(new ByteArrayInputStream(conf.getBytes()));
            int i = 0;
            do {
                try {
                    ks = KeyStore.getInstance("PKCS11", provider);
                } catch (KeyStoreException ex) {
                    if (i == 0) {
                        //System.out.println("Insert your Citizen Card (you have 20 seconds)");
                    }
                    if (i != 10) {
                        try {
                            //System.out.println((20-i*2)+"s");
                            progressBar.setValue(i * 10 + 5);
                            Thread.sleep(1000);
                            progressBar.setValue(i * 10 + 10);
                            Thread.sleep(1000);
                        } catch (InterruptedException ex1) {
                        }
                    }
                }
                i++;
            } while (i != 11 && ks == null);
            System.out.println("");

            progressBar.setValue(100);
            try {
                Thread.sleep(500);
            } catch (InterruptedException ex) {
            }
            f.setVisible(false);
            if (ks == null) {
                return null;
            }
            // Initialize the PKCS#11 token
            ks.load(null, null);

            return ks;

        } catch (NoSuchAlgorithmException | CertificateException e) {
            System.out.println("Exception while initializing PKCS#11 token:" + e);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private void getPass() {
        JFrame frame = new JFrame("Pass");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // do whatever else
            }
        });
        frame.setSize(350, 140);
        frame.setLocationRelativeTo(null);
        JPanel panel = new JPanel();
        frame.add(panel);
        frame.setResizable(false);

        JLabel passwordLabel = new JLabel(" Password ");
        passwordLabel.setBounds(10, 150, 80, 25);
        panel.add(passwordLabel);

        JTextField passwordText = new JPasswordField(20);
        passwordText.setBounds(210, 150, 160, 25);
        panel.add(passwordText);

        JButton loginButton = new JButton("Continue");
        loginButton.setBounds(10, 180, 80, 25);
        panel.add(loginButton);
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonClick = true;
            }
        });

        JButton registerButton = new JButton("Cancel");
        registerButton.setBounds(180, 180, 80, 25);
        panel.add(registerButton);
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buttonCancelClick = true;
            }
        });

        frame.setVisible(true);
        panel.setLayout(null);
        while (!buttonCancelClick && !(buttonClick && !"".equals(passwordText.getText()))) {
            try {
                buttonCancelClick = false;
                buttonClick = false;
                Thread.sleep(2000);
            } catch (InterruptedException ex) {
                Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (buttonClick) {
            userPass = applyHash(passwordText.getText().getBytes());
        }
        frame.setVisible(false);
    }

    private void verifyToken() {
        try {
            String t;

            t = generateRandomToken();
            byte[] makeHash = applyHash(("verifyToken" + email + t).getBytes());
            makeHash = chipherWithSessionKey(makeHash);
            byte[] tcipher = chipherWithSessionKey(t.getBytes());
            message = stub.getTokenNewOperation(email, makeHash, tcipher);
            if (message == null || message.getMessageIntegrity() != message.hashCode()) {
                return;
            }
            String s = Arrays.toString(applyHash(t.getBytes()));
            String x = Arrays.toString(message.getRandomTokenChipher());
            if (s.equals(x)) {
                return;
            }
            byte[] tokenEncrp = dechipherWithSessionKey(message.getAnswerByte());
            if (!buttonCancelClick) {
                t = new String(tokenEncrp, "UTF-8");
                if (!tokenSession.equals(t)) {
                    tokenSession = t;
                }
            }

        } catch (RemoteException | UnsupportedEncodingException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);

        }
    }

    private byte[] applyHash(byte[] response) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            return digest.digest(response);
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    private byte[] chipherPhase(byte[] response) {
        if (usingCard) {
            return chipherWithCC(response);
        } else {
            if (userPass == null) {
                getPass();
            }
            return chipherWithPassword(response);
        }
    }

    private synchronized byte[] generatePrivateKeyDH(BigInteger p, BigInteger g, byte[] pKOther) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            kpg.initialize(dhSpec);
            KeyPair kp = kpg.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kp.getPrivate());
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pKOther);
            PublicKey pk = kf.generatePublic(x509Spec);
            ka.doPhase(pk, true);
            byte secret[] = ka.generateSecret();
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            DESKeySpec desSpec = new DESKeySpec(secret);
            keySession = skf.generateSecret(desSpec);
            return kp.getPublic().getEncoded();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException | IllegalStateException e) {
        }
        return null;
    }

    private byte[] chipherWithSessionKey(byte[] challenge) {
        try {
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, keySession);
            return c.doFinal(challenge);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
        }
        return null;
    }

    private byte[] dechipherWithSessionKey(byte[] challenge) {
        try {
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, keySession);
            return c.doFinal(challenge);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(ClientActions.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private byte[] chipherToken() {
        return chipherWithSessionKey(tokenSession.getBytes());
    }

    private String generateRandomToken() {
        return new BigInteger(130, randomr).toString(32);
    }
}
