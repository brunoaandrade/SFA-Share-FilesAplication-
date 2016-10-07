package ServerSide;

import Interface.IOperations;
import JPAControllers.ClientsJpaController;
import JPAControllers.FilesJpaController;
import JPAControllers.PboxJpaController;
import JPAControllers.PermissionsJpaController;
import JPAControllers.SessionJpaController;
import JPAControllers.exceptions.IllegalOrphanException;
import JPAControllers.exceptions.NonexistentEntityException;
import JPAEntities.Clients;
import JPAEntities.Files;
import JPAEntities.Pbox;
import JPAEntities.Permissions;
import JPAEntities.Session;
import com.healthmarketscience.rmiio.RemoteInputStream;
import com.healthmarketscience.rmiio.RemoteInputStreamClient;
import com.healthmarketscience.rmiio.RemoteOutputStream;
import com.healthmarketscience.rmiio.RemoteOutputStreamClient;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.persistence.TypedQuery;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Set;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import message.Message;
import pam_testapp.main.java.org.jvnet.libpam.PAM;
import pam_testapp.main.java.org.jvnet.libpam.PAMException;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Bruno
 */
public class Operations implements IOperations {

    protected EntityManagerFactory emf;
    private final SecureRandom random = new SecureRandom();

    @Override
    public synchronized Message getTokenNewOperation(String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = email + clientRandomToken;
            if (checkMessageIntegraty(email, "verifyToken", x, messageIntegrity)) {
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    SessionJpaController sescontr = new SessionJpaController(emf);

                    EntityManager maneg = sescontr.getEntityManager();
                    //Get Session from email user
                    String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                            + "WHERE cl.email = '" + email + "'";
                    if (!checkSqlString(email)) {
                        return null;
                    }
                    TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);
                    Session sessions = querys.getSingleResult();
                    String token = new BigInteger(130, random).toString(32);
                    //return token from data base
                    sessions.setSessiontoken(token);
                    sescontr.edit(sessions);

                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerByte(chipherWithSessionKey(token.getBytes(), email));
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message getChalange(String email, boolean usecard, byte[] messageIntegrity, String clientRandomToken) {
        String x = "getChalange" + email + usecard + clientRandomToken;
        byte[] applyHash = applyHash(x.getBytes());
        if (compareCipherUsingCardOrPass(email, messageIntegrity, applyHash, usecard)) {
            try {
                byte[] b = new byte[64];
                new Random().nextBytes(b);

                MessageDigest digest = MessageDigest.getInstance("SHA-1");
                byte[] hashedByteschallanger = digest.digest(b);

                emf = Persistence.createEntityManagerFactory("segPU");
                SessionJpaController clint = new SessionJpaController(emf);
                EntityManager ents = clint.getEntityManager();

                String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                        + "WHERE cl.email = '" + email + "'";
                if (!checkSqlString(email)) {
                    return null;
                }
                TypedQuery<Session> querys = ents.createQuery(quers, Session.class);

                List<Session> sessions = querys.getResultList();

                Clients client;
                ClientsJpaController cli = new ClientsJpaController(emf);
                EntityManager em = cli.getEntityManager();

                client = em.createNamedQuery("Clients.findByEmail", Clients.class).
                        setParameter("email", email).getSingleResult();
                SessionJpaController cjc = new SessionJpaController(emf);

                if (sessions.isEmpty()) {

                    Session sess = new Session();

                    sess.setCardusing(usecard);
                    sess.setSessionchalleger(hashedByteschallanger);
                    Date currentTimeStamp = new Timestamp(Calendar.getInstance().getTime().getTime());
                    sess.setTimeCreation(currentTimeStamp);
                    sess.setClientsidClients(client);
                    try {
                        cjc.create(sess);
                    } catch (Exception ex) {
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } else {

                    Session sess = sessions.get(0);
                    sess.setCardusing(usecard);
                    sess.setSessionchalleger(hashedByteschallanger);
                    try {
                        cjc.edit(sess);
                    } catch (Exception ex) {
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                Cipher cipher;
                byte[] encodedkey = client.getPublicKey();
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedkey));

                cipher = Cipher.getInstance(client.getKeyAlgorythm() + "/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                Message message = new Message(cipher.doFinal(applyHash(clientRandomToken.getBytes())));
                message.setAnswerByte(cipher.doFinal(b));
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
                Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
            }

            return null;
        } else {
            return null;
        }
    }

    @Override
    public synchronized Message isLoggedIn(String emails, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emails);
            String token = new String(dechipherWithSessionKey(tokenB, emails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emails + token + clientRandomToken;
            if (checkMessageIntegraty(emails, "isLoggedIn", x, messageIntegrity)) {
                boolean valid = checkToken(token, emails);
                if (!valid) {
                    return null;
                }
                try {
                    boolean ret;
                    emf = Persistence.createEntityManagerFactory("segPU");
                    ClientsJpaController cjc = new ClientsJpaController(emf);
                    EntityManager ent = cjc.getEntityManager();

                    String teste = "SELECT res FROM Clients res WHERE res.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        return null;
                    }
                    TypedQuery<Clients> query = ent.createQuery(teste, Clients.class);
                    Clients cl = query.getSingleResult();
                    ret = cl.getIsloggedin();

                    ent.close();
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerBol(ret);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message logIn(String emails, byte[] response, boolean usingCard, byte[] messageIntegrity, String clientRandomToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] nowToken = digest.digest(("logIn" + emails + Arrays.toString(response) + usingCard + clientRandomToken).getBytes());
            if (compareCipherUsingCardOrPass(emails, messageIntegrity, nowToken, usingCard)) {
                if (authentication(emails, response, usingCard)) {
                    int numlogins;

                    emf = Persistence.createEntityManagerFactory("segPU");
                    JPAControllers.ClientsJpaController cjc = new JPAControllers.ClientsJpaController(emf);

                    EntityManager enti = cjc.getEntityManager();
                    String q = "SELECT res FROM Clients res WHERE res.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        return null;
                    }

                    TypedQuery<Clients> query = enti.createQuery(q, Clients.class);

                    Clients c = query.getSingleResult();

                    c.setIsloggedin(TRUE);
                    numlogins = c.getNLogins();
                    c.setNLogins(numlogins + 1);
                    byte[] encodedkey = c.getPublicKey();
                    String keyAlgorythm = c.getKeyAlgorythm();
                    try {
                        cjc.edit(c);
                    } catch (NonexistentEntityException ex) {
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (Exception ex) {
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    enti.close();
                    emf.close();
                    Cipher cipher;

                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedkey));

                    cipher = Cipher.getInstance(keyAlgorythm + "/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    Message message = new Message(cipher.doFinal(applyHash(clientRandomToken.getBytes())));
                    Message generateDHKey = generateDHKey(emails);
                    if (generateDHKey != null) {
                        message.setAnswerByte(generateDHKey.getRandomTokenChipher());
                        message.setAnswerListBigInt(generateDHKey.getAnswerListBigInt());
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    return null;
                }
                emf.close();
                return null;
            }
            return null;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            emf.close();
            return null;
        }
    }

    @Override
    public synchronized Message register(String emails, String name, PublicKey pubKey, String algoritmo, X509Certificate pubKeyCC, byte[] password, X509Certificate[] certs, String clientRandomToken, byte[] testUnsigned, byte[] testSigned, byte[] messageIntegraty) throws RemoteException {
        byte[] messageInt = applyHash((emails + name + pubKey + algoritmo + pubKeyCC + Arrays.toString(password) + clientRandomToken + Arrays.toString(testUnsigned) + Arrays.toString(testSigned)).getBytes());
        if (Arrays.equals(applyHash(messageInt), messageIntegraty)) {

            return null;
        }
        if (!validateChain(certs)) {
            return null;
        }
        try {
            emf = Persistence.createEntityManagerFactory("segPU");
            JPAControllers.ClientsJpaController cjc = new JPAControllers.ClientsJpaController(emf);

            EntityManager ent = cjc.getEntityManager();
            String teste = "SELECT res FROM Clients res WHERE res.email = '" + emails + "'";
            if (!checkSqlString(emails)) {

                Message m = new Message(applyHash(clientRandomToken.getBytes()));
                m.setAnswerBol(false);
                return m;
            }
            TypedQuery<Clients> query = ent.createQuery(teste, Clients.class);
            if (!(testSigned != null && testUnsigned != null && validateResponse(pubKeyCC.getPublicKey(), testUnsigned, testSigned))) {
                Message m = new Message(applyHash(clientRandomToken.getBytes()));
                m.setAnswerBol(false);
                return m;
            }
            if (query.getResultList().isEmpty()) {
                Clients cliente = new Clients();
                cliente.setEmail(emails);
                cliente.setKeyAlgorythm(algoritmo);
                cliente.setName(name);
                cliente.setNLogins(0);
                cliente.setIsloggedin(FALSE);
                cliente.setPublicKey(pubKey.getEncoded());
                cliente.setUserPassword(password);
                cliente.setCardPublickey(pubKeyCC.getPublicKey().getEncoded());
                cjc.create(cliente);

                PboxJpaController pbs = new PboxJpaController(emf);

                Pbox pb = new Pbox();

                pb.setClientsidClients(cliente);
                pb.setSize((float) 0.0);
                pbs.create(pb);

                ent.close();
                emf.close();
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, getpK(emails));
                Message m = new Message(cipher.doFinal(applyHash(clientRandomToken.getBytes())));
                m.setAnswerBol(true);
                m.setMessageIntegrity(m.hashCode());
                return m;
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);

            emf.close();
            Message m = new Message(applyHash(clientRandomToken.getBytes()));
            m.setAnswerBol(false);
            return m;
        }
        emf.close();
        Message m = new Message(applyHash(clientRandomToken.getBytes()));
        m.setAnswerBol(false);
        return m;
    }

    @Override
    public synchronized Message terminateSession(String emails, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emails);

            String token = new String(dechipherWithSessionKey(tokenB, emails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emails + token + clientRandomToken;
            if (checkMessageIntegraty(emails, "terminateSession", x, messageIntegrity)) {
                boolean valid = checkToken(token, emails);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    JPAControllers.ClientsJpaController cjc = new JPAControllers.ClientsJpaController(emf);

                    EntityManager enti = cjc.getEntityManager();
                    String q = "SELECT res FROM Clients res WHERE res.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                        message.setAnswerBol(false);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }

                    TypedQuery<Clients> query = enti.createQuery(q, Clients.class);

                    Clients c = query.getSingleResult();

                    c.setIsloggedin(FALSE);

                    cjc.edit(c);
                    enti.close();
                } catch (Exception ex) {
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                emf.close();
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                message.setAnswerBol(true);
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
            message.setAnswerBol(false);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
        message.setAnswerBol(false);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message listAllPbox(byte[] tokenB, String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = token + email + clientRandomToken;
            if (checkMessageIntegraty(email, "listAllPbox", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    return null;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    PboxJpaController pboxs = new PboxJpaController(emf);
                    List<Pbox> listpb = pboxs.findPboxEntities();
                    if (!listpb.isEmpty()) {

                        emf.close();
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerListPbox(listpb);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    emf.close();
                    return null;
                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message listAllFiles(String emails, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emails);
            String token = new String(dechipherWithSessionKey(tokenB, emails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emails + token + clientRandomToken;
            if (checkMessageIntegraty(emails, "listAllFiles", x, messageIntegrity)) {
                boolean valid = checkToken(token, emails);
                if (!valid) {
                    return null;
                }
                try {
                    List<Files> filelist = new ArrayList<>();
                    int fileid;
                    String querys;

                    // Persistency inicializations
                    emf = Persistence.createEntityManagerFactory("segPU");
                    FilesJpaController f = new FilesJpaController(emf);
                    PermissionsJpaController pjc = new PermissionsJpaController(emf);
                    EntityManager em = pjc.getEntityManager();

                    querys = "SELECT res FROM Permissions res JOIN "
                            + "res.pboxidPbox pid JOIN pid.clientsidClients c WHERE c.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        return null;
                    }
                    //Get List of permitions that a given user has
                    TypedQuery<Permissions> querey = em.createQuery(querys, Permissions.class);
                    List<Permissions> auxlist = querey.getResultList();

                    for (Permissions permition : auxlist) {
                        fileid = permition.getFilesidFiles().getIdFiles();
                        filelist.add(f.findFiles(fileid));
                    }

                    if (!filelist.isEmpty()) {
                        emf.close();
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                        message.setAnswerListFiles(filelist);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                } catch (Exception ex) {
                    emf.close();
                }
                emf.close();
                return null;
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message setPublicKey(String emails, PublicKey key, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emails);
            String token = new String(dechipherWithSessionKey(tokenB, emails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emails + key + token + clientRandomToken;
            if (checkMessageIntegraty(emails, "setPublicKey", x, messageIntegrity)) {
                boolean valid = checkToken(token, emails);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    ClientsJpaController setkey = new ClientsJpaController(emf);
                    EntityManager manage = setkey.getEntityManager();

                    String querys = "SELECT res FROM Clients res WHERE res.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                        message.setAnswerBol(false);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    TypedQuery<Clients> query = manage.createQuery(querys, Clients.class);

                    Clients clienttoset = query.getSingleResult();
                    clienttoset.setPublicKey(key.getEncoded());

                    setkey.edit(clienttoset);
                    manage.close();

                } catch (Exception ex) {
                    Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                message.setAnswerBol(true);
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
            message.setAnswerBol(false);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
        message.setAnswerBol(false);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message findPublicKey(String emailAsk, String emailOther, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emailAsk);
            String token = new String(dechipherWithSessionKey(tokenB, emailAsk), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String nowToken = emailAsk + emailOther + token + clientRandomToken;
            if (checkMessageIntegraty(emailAsk, "findPublicKey", nowToken, messageIntegrity)) {
                boolean valid = checkToken(token, emailAsk);
                if (!valid) {
                    return null;
                }
                byte[] encodedkey;
                Clients client;

                emf = Persistence.createEntityManagerFactory("segPU");
                ClientsJpaController findkey = new ClientsJpaController(emf);

                EntityManager ent = findkey.getEntityManager();

                String quer = "SELECT res FROM Clients res WHERE res.email = '" + emailOther + "'";
                if (!checkSqlString(emailOther)) {
                    return null;
                }
                TypedQuery<Clients> query = ent.createQuery(quer, Clients.class);

                client = query.getSingleResult();
                encodedkey = client.getPublicKey();
                ent.close();
                emf.close();
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                message.setAnswerByte(chipherWithSessionKey(encodedkey, emailAsk));
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    // Return Convention  -1 file corrupted, -2 file name already exists, -3 generic exception 0 end with Success
    @Override
    public synchronized Message uploadFile(String myFile, String mails, String alg, RemoteInputStream remoteFileData, byte[] keyEncrypted, String fileExtension, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, mails);
            String token = new String(dechipherWithSessionKey(tokenB, mails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = myFile + mails + alg + Arrays.toString(keyEncrypted) + fileExtension + token + clientRandomToken;
            if (checkMessageIntegraty(mails, "uploadFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, mails);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                    message.setAnswerInt(-4);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                InputStream fileData = null;
                OutputStream outputStream = null;
                String quer, hashedname = null;
                byte[] hashedBytes;
                byte[] hash = new byte[20];
                String hexhashsent, hexconfirm;

                try {
                    // adding file owner mail identifier
                    myFile = myFile.concat("_" + mails + "");
                    // Hashing file name for storage
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    hashedBytes = digest.digest(myFile.getBytes("UTF-8"));
                    hashedname = convertByteArrayToHexString(hashedBytes);

                    fileData = RemoteInputStreamClient.wrap(remoteFileData);
                    // write the inputStream to a FileOutputStream
                    outputStream = new FileOutputStream(new File("PBOX/" + hashedname));

                    //Instiation of persistance unit
                    emf = Persistence.createEntityManagerFactory("segPU");
                    ClientsJpaController findpbox = new ClientsJpaController(emf);

                    //Get Files list from certain user
                    EntityManager man = findpbox.getEntityManager();
                    quer = "SELECT res FROM Files res JOIN  res.pboxidPbox p "
                            + " JOIN p.clientsidClients c WHERE c.email = '" + mails + "'";
                    if (!checkSqlString(mails)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                        message.setAnswerInt(-5);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    TypedQuery<Files> query = man.createQuery(quer, Files.class);

                    List<Files> listfil = query.getResultList();

                    Iterator itr = listfil.iterator();  //Iterator for looping over Files list

                    Files tofind;
                    while (itr.hasNext()) //Iteratig over Files list
                    {
                        tofind = (Files) itr.next();
                        if (tofind.getName().equals(myFile)) //Verifying Files with the same name
                        {
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                            message.setAnswerInt(-2);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;  //Return file already exists code error
                        }
                    }

                    int read;
                    byte[] bytes = new byte[1024];
                    boolean dateCurrupt = false;

                    while ((read = fileData.read(bytes)) != -1) {
                        if (read != 1024) {
                            byte[] newblock = new byte[read];
                            System.arraycopy(bytes, 0, newblock, 0, read);
                            bytes = newblock;
                        }
                        // byte array treatment to process the check
                        System.arraycopy(bytes, 0, hash, 0, 20);
                        hexhashsent = convertByteArrayToHexString(hash);
                        byte[] res = new byte[read - 20];

                        System.arraycopy(bytes, 20, res, 0, read - 20);
                        // Performing hash
                        digest = MessageDigest.getInstance("SHA-1");
                        byte[] confirm = digest.digest(res);

                        hexconfirm = convertByteArrayToHexString(confirm);

                        if (!hexhashsent.equals(hexconfirm)) //check if hash is ok
                        {
                            dateCurrupt = true;
                        }

                        outputStream.write(bytes, 0, bytes.length); // forming file

                        if (dateCurrupt) // Case file or hash corrupted
                        {
                            File f = new File("PBOX/" + hashedname);
                            System.gc();
                            f.delete();
                            fileData.close();
                            outputStream.close();
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                            message.setAnswerInt(-1);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;             //returning file corrupted code error
                        }
                    }

                    System.out.println("Done!");   //Packets all processed

                } catch (IOException | NoSuchAlgorithmException ex) {
                    // If any error is catched  eliminate File and close operations
                    File f = new File("PBOX/" + hashedname);
                    System.gc();
                    f.delete();
                    outputStream = null;
                    System.out.println(" return 5");
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                    message.setAnswerInt(-3);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } finally {
                    if (fileData != null && outputStream != null) {
                        try {
                            outputStream.close();
                            fileData.close();   // closing remote Stream
                        } catch (IOException ex) {
                            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                            System.out.println(" return 4");
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                            message.setAnswerInt(-3);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;
                        }
                    }
                }
                if (outputStream != null) {

                    try {
                        // outputStream.flush();
                        outputStream.close();

                        PboxJpaController pbcontrol = new PboxJpaController(emf);
                        EntityManager maneg = pbcontrol.getEntityManager();

                        //Get Pbox associated with certain user email
                        String quers = "SELECT res FROM Pbox res JOIN  res.clientsidClients cl "
                                + "WHERE cl.email = '" + mails + "'";
                        if (!checkSqlString(mails)) {
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                            message.setAnswerInt(-5);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;
                        }
                        TypedQuery<Pbox> querys = maneg.createQuery(quers, Pbox.class);

                        Pbox pbo = querys.getSingleResult();

                        FilesJpaController flcontrol = new FilesJpaController(emf);

                        //Generating new Files instance
                        Files fil = new Files();

                        // Filling fields up
                        fil.setExtension(fileExtension);
                        fil.setPboxidPbox(pbo);
                        fil.setName(myFile);
                        fil.setFilepath("PBOX/" + hashedname);
                        fil.setKeyAlgorythm(alg);
                        // Creating File registry in the database
                        flcontrol.create(fil);

                        PermissionsJpaController percontrol = new PermissionsJpaController(emf);
                        //Generating new permissions instance
                        Permissions per = new Permissions();

                        //Filling fields up
                        per.setEncryptedsymkey(keyEncrypted);
                        per.setPboxidPbox(pbo);
                        per.setFilesidFiles(fil);

                        //Creating entry in permissions table
                        percontrol.create(per);

                        if (fileData != null) {
                            fileData.close();
                        }
                        outputStream.close();
                    } catch (Exception ex) {
                        emf.close();
                        System.out.println(" return 2");
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                        message.setAnswerInt(-3);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                    message.setAnswerInt(-0);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                emf.close();
                System.out.println(" return 1");
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
                message.setAnswerInt(-3);
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
            message.setAnswerInt(-4);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mails));
        message.setAnswerInt(-4);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message deleteFile(String filename, byte[] tokenB, String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = filename + token + email + clientRandomToken;
            if (checkMessageIntegraty(email, "deleteFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                try {
                    String quer, hashedname;
                    Files auxfile;
                    int idfil;

                    // JPA inicialiasions
                    emf = Persistence.createEntityManagerFactory("segPU");
                    FilesJpaController fileid = new FilesJpaController(emf);
                    PermissionsJpaController perid = new PermissionsJpaController(emf);

                    //Get file by name
                    EntityManager ent = fileid.getEntityManager();
                    quer = "SELECT res FROM Files res WHERE res.name = '" + filename + "'";
                    if (!checkSqlString(filename)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerBol(false);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    TypedQuery<Files> q = ent.createQuery(quer, Files.class);
                    auxfile = q.getSingleResult();
                    // Get file ID for destruction
                    idfil = auxfile.getIdFiles();
                    hashedname = auxfile.getFilepath();

                    try {
                        // Deleting file from filesystem
                        File f = new File(hashedname);
                        System.gc();
                        boolean del = f.delete();
                        System.out.println(del);
                        for (Permissions permition : auxfile.getPermissionsCollection()) {
                            perid.destroy(permition.getIdPermissions());
                        }
                        fileid.destroy(idfil);  // Destroying file database registrys and dependencies
                        ent.close();
                        emf.close();
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerBol(true);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    } catch (IllegalOrphanException | NonexistentEntityException ex) {
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerBol(false);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                } catch (Exception ex) {
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
            message.setAnswerBol(false);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
        message.setAnswerBol(false);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message shareFile(String fileId, String emailAsk, String emailOther, byte[] key, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emailAsk);
            String token = new String(dechipherWithSessionKey(tokenB, emailAsk), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = fileId + emailAsk + emailOther + Arrays.toString(key) + token + clientRandomToken;
            if (checkMessageIntegraty(emailAsk, "shareFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, emailAsk);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    PermissionsJpaController pers = new PermissionsJpaController(emf);

                    // Create new instane of Permissons
                    Permissions per = new Permissions();
                    per.setEncryptedsymkey(key);

                    FilesJpaController getf = new FilesJpaController(emf);
                    EntityManager manage = getf.getEntityManager();

                    // Get file by name
                    Files filetoget = (Files) manage.createNamedQuery("Files.findByName")
                            .setParameter("name", fileId).getSingleResult();

                    per.setFilesidFiles(filetoget);

                    PboxJpaController pbcontrol = new PboxJpaController(emf);
                    EntityManager maneg = pbcontrol.getEntityManager();

                    //Get Pbox associated with certain user email
                    String quers = "SELECT res FROM Pbox res JOIN res.clientsidClients cl "
                            + "WHERE cl.email = '" + emailOther + "'";
                    if (!checkSqlString(emailOther)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                        message.setAnswerBol(false);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    TypedQuery<Pbox> querys = maneg.createQuery(quers, Pbox.class);

                    Pbox pbotoget = querys.getSingleResult();

                    per.setPboxidPbox(pbotoget);

                    // Creating new entry in permissions
                    pers.create(per);
                    // pbcontrol.edit(pbotoget);
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerBol(true);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
            message.setAnswerBol(false);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
        message.setAnswerBol(false);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message shareTableFile(String Filename, byte[] tokenB, String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = Filename + token + email + clientRandomToken;
            if (checkMessageIntegraty(email, "shareTableFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    return null;
                }
                try {
                    List<Permissions> ls;
                    String perquer;

                    emf = Persistence.createEntityManagerFactory("segPU");
                    PermissionsJpaController fileids = new PermissionsJpaController(emf);

                    EntityManager manage = fileids.getEntityManager();
                    // getting all permission for a specific filename
                    perquer = "SELECT per FROM Permissions per JOIN per.filesidFiles idf "
                            + "WHERE idf.name = '" + Filename + "'";
                    if (!checkSqlString(Filename)) {
                        return null;
                    }
                    TypedQuery<Permissions> query = manage.createQuery(perquer, Permissions.class);
                    // Result List
                    ls = query.getResultList();
                    System.out.println(ls);

                    if (!ls.isEmpty()) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerListPerm(ls);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }

                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
                emf.close();
                return null;

            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message getEncrySymetricKey(String emails, String filename, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emails);
            String token = new String(dechipherWithSessionKey(tokenB, emails), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emails + filename + token + clientRandomToken;
            if (checkMessageIntegraty(emails, "getEncrySymetricKey", x, messageIntegrity)) {
                boolean valid = checkToken(token, emails);
                if (!valid) {
                    return null;
                }
                try {
                    String query;
                    byte[] ret;

                    emf = Persistence.createEntityManagerFactory("segPU");

                    PermissionsJpaController get = new PermissionsJpaController(emf);
                    EntityManager mn = get.getEntityManager();

                    query = "SELECT res FROM Permissions res JOIN res.filesidFiles fid JOIN "
                            + "res.pboxidPbox pid JOIN pid.clientsidClients c WHERE fid.name = '" + filename + "' "
                            + "AND c.email = '" + emails + "'";
                    if (!checkSqlString(emails)) {
                        return null;
                    }
                    TypedQuery<Permissions> querys = mn.createQuery(query, Permissions.class);
                    ret = querys.getSingleResult().getEncryptedsymkey();

                    emf.close();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emails));
                    message.setAnswerByte(chipherWithSessionKey(ret, emails));
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message getMyAlgorithm(String emailAsk, String emailOther, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emailAsk);
            String token = new String(dechipherWithSessionKey(tokenB, emailAsk), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = emailAsk + emailOther + token + clientRandomToken;
            if (checkMessageIntegraty(emailAsk, "getMyAlgorithm", x, messageIntegrity)) {
                boolean valid = checkToken(token, emailAsk);
                if (!valid) {
                    return null;
                }
                try {
                    String ret;

                    emf = Persistence.createEntityManagerFactory("segPU");
                    ClientsJpaController fileids = new ClientsJpaController(emf);

                    EntityManager manages = fileids.getEntityManager();

                    Clients client = manages.createNamedQuery("Clients.findByEmail", Clients.class)
                            .setParameter("email", emailOther).getSingleResult();

                    ret = client.getKeyAlgorythm();

                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerByte(chipherWithSessionKey(ret.getBytes(), emailAsk));
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    /* return code errors -1 the given filename doesn't exist or you can't access it 
     -2 generic exception 0 Success*/

    public synchronized Message getFile(RemoteOutputStream outFile, String filename, String email, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = filename + email + token + clientRandomToken;
            if (checkMessageIntegraty(email, "getFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerInt(-4);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                try {
                    String querys;
                    Pbox clientpb;
                    Files retfile;
                    int fileid;
                    List<Files> filelist = new ArrayList<>();

                    //Inicializations persistency
                    emf = Persistence.createEntityManagerFactory("segPU");
                    PermissionsJpaController pjc = new PermissionsJpaController(emf);
                    FilesJpaController f = new FilesJpaController(emf);
                    EntityManager em = pjc.getEntityManager();

                    querys = "SELECT res FROM Permissions res JOIN "
                            + "res.pboxidPbox pid JOIN pid.clientsidClients c WHERE c.email = '" + email + "'";
                    if (!checkSqlString(email)) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerInt(-5);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    //Get List of permitions that a given user has
                    TypedQuery<Permissions> querey = em.createQuery(querys, Permissions.class);
                    List<Permissions> auxlist = querey.getResultList();
                    // looping over permissions list
                    for (Permissions permition : auxlist) {
                        fileid = permition.getFilesidFiles().getIdFiles();
                        filelist.add(f.findFiles(fileid));
                    }

                    Iterator itr = filelist.iterator();
                    String path = null;

                    while (itr.hasNext()) //looping over filesList
                    {
                        retfile = (Files) itr.next();
                        if (retfile.getName().equals(filename)) {
                            path = retfile.getFilepath();   //Getting filepath by filename
                            break;
                        }
                    }

                    if (path == null) {
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                        message.setAnswerInt(-1);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }

                    File file = new File(path);

                    byte[] send;
                    int packetSize = 1024;
                    byte[] bFile = new byte[(int) file.length()];

                    //convert file into array of bytes
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        fileInputStream.read(bFile);
                    }

                    OutputStream istream = RemoteOutputStreamClient.wrap(outFile);
                    // ... write file here using normal OutputStream code ...
                    for (int i = 0; i < bFile.length; i += packetSize) {
                        if (bFile.length < i + packetSize) {
                            send = Arrays.copyOfRange(bFile, i, i + bFile.length - i);

                        } else {
                            send = Arrays.copyOfRange(bFile, i, i + packetSize);
                        }
                        istream.write(send);
                        istream.flush();
                    }

                } catch (Exception ex) {
                    Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerInt(-2);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                message.setAnswerInt(0);
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
            message.setAnswerInt(-4);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
        message.setAnswerInt(-4);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public synchronized Message getExtensionFile(String fileName, byte[] tokenB, String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = fileName + token + email + clientRandomToken;
            if (checkMessageIntegraty(email, "getExtensionFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    return null;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    FilesJpaController fcontrol = new FilesJpaController(emf);
                    EntityManager manage = fcontrol.getEntityManager();
                    // Getting File by name
                    Files filetoget = (Files) manage.createNamedQuery("Files.findByName")
                            .setParameter("name", fileName).getSingleResult();

                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerByte(chipherWithSessionKey(filetoget.getExtension().getBytes(), email));
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Message getAlgorithmFile(String fileName, byte[] tokenB, String email, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, email);
            String token = new String(dechipherWithSessionKey(tokenB, email), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = fileName + token + email + clientRandomToken;
            if (checkMessageIntegraty(email, "getAlgorithmFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, email);
                if (!valid) {
                    return null;
                }
                try {
                    emf = Persistence.createEntityManagerFactory("segPU");
                    FilesJpaController fcontrol = new FilesJpaController(emf);
                    EntityManager manage = fcontrol.getEntityManager();

                    //Getting file Algorythm by name
                    Files filetoget = (Files) manage.createNamedQuery("Files.findByName")
                            .setParameter("name", fileName).getSingleResult();
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), email));
                    message.setAnswerByte(chipherWithSessionKey(filetoget.getKeyAlgorythm().getBytes(), email));
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;

                } catch (Exception ex) {
                    emf.close();
                    return null;
                }
            }
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    // Return Convention  -1 file corrupted, -2 file name already exists, -3 generic exception 0 end with Success
    @Override
    public synchronized Message modifyFile(String myFile, String mailPersonSend, String alg, RemoteInputStream remoteFileData, String fileExtension, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, mailPersonSend);
            String token = new String(dechipherWithSessionKey(tokenB, mailPersonSend), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = myFile + mailPersonSend + alg + fileExtension + token + clientRandomToken;
            if (checkMessageIntegraty(mailPersonSend, "modifyFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, mailPersonSend);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                    message.setAnswerInt(-4);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                InputStream fileData = null;
                OutputStream outputStream = null;
                String quer, hashedname = null;
                byte[] hashedBytes;
                byte[] hash = new byte[20];
                String hexhashsent, hexconfirm;

                try {
                    // adding file owner mail identifier
                    //myFile = myFile.concat("_" + ownerFile + "");
                    // Hashing file name for storage
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    hashedBytes = digest.digest(myFile.getBytes("UTF-8"));
                    hashedname = convertByteArrayToHexString(hashedBytes);

                    fileData = RemoteInputStreamClient.wrap(remoteFileData);
                    // write the inputStream to a FileOutputStream

                    outputStream = new FileOutputStream(new File("PBOX/" + hashedname + "_"));

                    int read;
                    byte[] bytes = new byte[1024];
                    boolean dateCurrupt = false;

                    while ((read = fileData.read(bytes)) != -1) {
                        if (read != 1024) {
                            byte[] newblock = new byte[read];
                            System.arraycopy(bytes, 0, newblock, 0, read);
                            bytes = newblock;
                        }
                        // byte array treatment to process the check
                        System.arraycopy(bytes, 0, hash, 0, 20);
                        hexhashsent = convertByteArrayToHexString(hash);
                        byte[] res = new byte[read - 20];

                        System.arraycopy(bytes, 20, res, 0, read - 20);
                        // Performing hash
                        digest = MessageDigest.getInstance("SHA-1");
                        byte[] confirm = digest.digest(res);

                        hexconfirm = convertByteArrayToHexString(confirm);

                        if (!hexhashsent.equals(hexconfirm)) //check if hash is ok
                        {
                            dateCurrupt = true;
                        }

                        outputStream.write(bytes, 0, bytes.length); // forming file

                        if (dateCurrupt) // Case file or hash corrupted
                        {
                            File f = new File("PBOX/" + hashedname + "_");
                            System.gc();
                            f.delete();
                            fileData.close();
                            outputStream.close();
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                            message.setAnswerInt(-1);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;//returning file corrupted code error
                        }
                    }

                    System.out.println("Done!");   //Packets all processed

                } catch (IOException | NoSuchAlgorithmException ex) {
                    // If any error is catched  eliminate File and close operations
                    File f = new File("PBOX/" + hashedname);
                    System.gc();
                    f.delete();
                    outputStream = null;
                    System.out.println(" return 5");
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                    message.setAnswerInt(-3);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                } finally {
                    if (fileData != null && outputStream != null) {
                        try {
                            outputStream.close();
                            fileData.close();   // closing remote Stream
                        } catch (IOException ex) {
                            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                            System.out.println(" return 4");
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                            message.setAnswerInt(-3);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;
                        }
                    }
                }
                if (outputStream != null) {
                    try {
                        // outputStream.flush();
                        outputStream.close();
                        if (fileData != null) {
                            fileData.close();
                        }
                        outputStream.close();
                    } catch (IOException ex) {
                        System.out.println(" return 2");
                        Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                        message.setAnswerInt(-3);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    File oldfile = new File("PBOX/" + hashedname + "_");
                    File newfile = new File("PBOX/" + hashedname);
                    newfile.delete();

                    if (oldfile.renameTo(newfile)) {
                        System.out.println("Rename succesful");
                        oldfile.delete();
                    } else {
                        System.out.println("Rename failed");
                        oldfile.delete();
                        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                        message.setAnswerInt(-3);
                        int hashCode = message.hashCode();
                        message.setMessageIntegrity(hashCode);
                        return message;
                    }
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                    message.setAnswerInt(0);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                System.out.println(" return -3");
                Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
                message.setAnswerInt(-3);
                int hashCode = message.hashCode();
                message.setMessageIntegrity(hashCode);
                return message;
            }
            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
            message.setAnswerInt(-3);
            int hashCode = message.hashCode();
            message.setMessageIntegrity(hashCode);
            return message;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), mailPersonSend));
        message.setAnswerInt(-3);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    @Override
    public Message unshareFile(String findNameFile, String emailAsk, String emailOther, byte[] tokenB, byte[] messageIntegrity, byte[] clientRandomT) {
        try {
            clientRandomT = dechipherWithSessionKey(clientRandomT, emailAsk);
            String token = new String(dechipherWithSessionKey(tokenB, emailAsk), "UTF-8");
            String clientRandomToken = new String(clientRandomT, "UTF-8");
            String x = findNameFile + emailAsk + emailOther + token + clientRandomToken;
            if (checkMessageIntegraty(emailAsk, "unshareFile", x, messageIntegrity)) {
                boolean valid = checkToken(token, emailAsk);
                if (!valid) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                String fileid;
                String querys;
                List<Files> filelist = new ArrayList<>();

                //Inicializations persistency
                emf = Persistence.createEntityManagerFactory("segPU");
                PermissionsJpaController pjc = new PermissionsJpaController(emf);
                FilesJpaController f = new FilesJpaController(emf);
                EntityManager em = pjc.getEntityManager();

                querys = "SELECT res FROM Permissions res JOIN "
                        + "res.pboxidPbox pid JOIN pid.clientsidClients c WHERE c.email = '" + emailOther + "'";
                if (!checkSqlString(emailOther)) {
                    Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                    message.setAnswerBol(false);
                    int hashCode = message.hashCode();
                    message.setMessageIntegrity(hashCode);
                    return message;
                }
                //Get List of permitions that a given user has
                TypedQuery<Permissions> querey = em.createQuery(querys, Permissions.class);
                List<Permissions> auxlist = querey.getResultList();

                // looping over permissions list
                for (Permissions permition : auxlist) {
                    fileid = permition.getFilesidFiles().getName();
                    if (fileid.equals(findNameFile)) {
                        try {
                            pjc.destroy(permition.getIdPermissions());
                            Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
                            message.setAnswerBol(true);
                            int hashCode = message.hashCode();
                            message.setMessageIntegrity(hashCode);
                            return message;

                        } catch (NonexistentEntityException ex) {
                            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        Message message = new Message(chipherWithSessionKey(applyHash(clientRandomT), emailAsk));
        message.setAnswerBol(false);
        int hashCode = message.hashCode();
        message.setMessageIntegrity(hashCode);
        return message;
    }

    private synchronized String convertByteArrayToHexString(byte[] arrayBytes) {

        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < arrayBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    private synchronized boolean authentication(String email, byte[] responsechallenger, boolean usingCard) {

        try {
            Clients client;
            byte[] cckey;
            emf = Persistence.createEntityManagerFactory("segPU");

            SessionJpaController clint = new SessionJpaController(emf);
            EntityManager ents = clint.getEntityManager();

            String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                    + "WHERE cl.email = '" + email + "'";
            if (!checkSqlString(email)) {
                return false;
            }
            TypedQuery<Session> querys = ents.createQuery(quers, Session.class);
            Session sessions = querys.getSingleResult();
            byte[] challenger = sessions.getSessionchalleger();
            client = sessions.getClientsidClients();

            if (usingCard) {
                cckey = client.getCardPublickey();
                PublicKey pubKeyCC = KeyFactory.getInstance(client.getKeyAlgorythm()).generatePublic(new X509EncodedKeySpec(cckey));
                //get challenge
                return responsechallenger != null && validateResponse(pubKeyCC, challenger, responsechallenger);

            } else {
                //get from database
                byte[] password = client.getUserPassword();
                Cipher desCipher;
                desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                DESKeySpec keySpec = new DESKeySpec(password);
                SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
                SecretKey passwordKey = kf.generateSecret(keySpec);
                desCipher.init(Cipher.DECRYPT_MODE, passwordKey);
                // Decrypt the text
                byte[] textDecrypted = desCipher.doFinal(responsechallenger);
                MessageDigest digest = MessageDigest.getInstance("SHA-1");
                byte[] hashedBytes = digest.digest(textDecrypted);
                sessions.setChallengeresponse(hashedBytes);
                //save hashedBytes in DB
                try {
                    clint.edit(sessions);
                } catch (Exception ex) {
                    Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
                }
                //call Pam
                PAM pmt;

                try {
                    pmt = new PAM("safebox-pamconf");
                    pmt.authenticate(email, "0");

                } catch (PAMException ex) {
                    System.out.println("Your Authentication failed, try again");
                    return false;
                }
                return true;
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | KeyStoreException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private synchronized boolean checkMessageIntegraty(String email, String funcionName, String messageIntegraty, byte[] hash) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] nowToken = digest.digest((funcionName + messageIntegraty).getBytes());

            byte[] dechipherWithSessionKey = dechipherWithSessionKey(hash, email);
            return Arrays.equals(nowToken, dechipherWithSessionKey);
        } catch (Exception ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private synchronized boolean compareCipherUsingCardOrPass(String email, byte[] textEncrypted, byte[] original, boolean usingCard) {
        try {
            emf = Persistence.createEntityManagerFactory("segPU");
            if (!checkSqlString(email)) {
                return false;
            }
            ClientsJpaController cjpa = new ClientsJpaController(emf);
            EntityManager ent = cjpa.getEntityManager();
            Clients client = (Clients) ent.createNamedQuery("Clients.findByEmail")
                    .setParameter("email", email).getSingleResult();

            if (usingCard) {
                byte[] ccPubKey = client.getCardPublickey();
                PublicKey pubKeyCC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(ccPubKey));
                return textEncrypted != null && validateResponse(pubKeyCC, original, textEncrypted);
            } else {
                byte[] passwordUser = client.getUserPassword();
                Cipher desCipher;
                desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                DESKeySpec keySpec = new DESKeySpec(passwordUser);
                SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
                SecretKey passwordKey = kf.generateSecret(keySpec);
                desCipher.init(Cipher.DECRYPT_MODE, passwordKey);
                byte[] textDecrypted = desCipher.doFinal(textEncrypted);
                return Arrays.equals(textDecrypted, original);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private synchronized byte[] chipherWithSessionKey(byte[] challenge, String email) {

        emf = Persistence.createEntityManagerFactory("segPU");
        SessionJpaController sescontr = new SessionJpaController(emf);

        EntityManager maneg = sescontr.getEntityManager();

        //Get Session from email user
        String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                + "WHERE cl.email = '" + email + "'";
        if (!checkSqlString(email)) {
            return new byte[1];
        }
        TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);

        Session sessions = querys.getSingleResult();

        byte[] keySess = sessions.getSessionkey();

        SecretKey Keysession = new SecretKeySpec(keySess, 0, keySess.length, "DES");

        //from DB
        try {
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, Keysession);
            return c.doFinal(challenge);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private synchronized byte[] dechipherWithSessionKey(byte[] challenge, String email) {
        try {
            emf = Persistence.createEntityManagerFactory("segPU");
            SessionJpaController sescontr = new SessionJpaController(emf);

            EntityManager maneg = sescontr.getEntityManager();

            //Get Session from email user
            String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                    + "WHERE cl.email = '" + email + "'";
            if (!checkSqlString(email)) {
                return new byte[1];
            }
            TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);

            Session sessions = querys.getSingleResult();

            byte[] keySess = sessions.getSessionkey();

            SecretKey Keysession = new SecretKeySpec(keySess, 0, keySess.length, "DES");

            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");

            c.init(Cipher.DECRYPT_MODE, Keysession);
            return c.doFinal(challenge);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);

        }
        return null;
    }

    private boolean validateResponse(PublicKey pk, byte[] challenge, byte[] response) throws KeyStoreException {
        try {
            Signature signature; // signature validator
            signature = Signature.getInstance("SHA1withRSA"); // Create a signature object for verifying the signature 
            signature.initVerify(pk);// Setup the verification element (the certificate of the signer)
            signature.update(challenge);// Provide the data that was signed
            // Verify the signature

            return signature.verify(response);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private synchronized Message generateDHKey(String email) {

        emf = Persistence.createEntityManagerFactory("segPU");
        SessionJpaController sescontr = new SessionJpaController(emf);

        EntityManager maneg = sescontr.getEntityManager();

        //Get Session from email user
        String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                + "WHERE cl.email = '" + email + "'";
        if (!checkSqlString(email)) {
            return null;
        }
        TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);

        Session sessions = querys.getSingleResult();

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            DHParameterSpec dhSpec = ((DHPublicKey) kp.getPublic()).getParams();

            BigInteger g = dhSpec.getG();
            BigInteger h = dhSpec.getP();
            PrivateKey serverPrivK = kp.getPrivate();

            sessions.setSessionkey(serverPrivK.getEncoded());
            sescontr.edit(sessions);
            Message m = new Message(kp.getPublic().getEncoded());
            BigInteger[] s = new BigInteger[2];
            s[0] = h;
            s[1] = g;
            m.setAnswerListBigInt(s);
            return m;
        } catch (Exception ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);

        }
        return null;
    }

    @Override
    public synchronized Message sendPublicKeyDH(byte[] generatePrivateKeyDH, String email, byte[] messageIntegrity, String clientRandomToken) {
        String x = "sendPublicKeyDH" + Arrays.toString(generatePrivateKeyDH) + email + clientRandomToken;
        byte[] applyHash = applyHash(x.getBytes());
        if (Arrays.toString(applyHash).equals(Arrays.toString(messageIntegrity))) {
            try {
                emf = Persistence.createEntityManagerFactory("segPU");
                SessionJpaController sescontr = new SessionJpaController(emf);

                EntityManager maneg = sescontr.getEntityManager();
                //Get Session from email user
                String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                        + "WHERE cl.email = '" + email + "'";
                if (!checkSqlString(email)) {
                    return null;
                }
                TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);
                Session sessions = querys.getSingleResult();

                byte[] serverPrivK = sessions.getSessionkey();
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(serverPrivK);
                PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(privateKey2);
                KeyFactory kf = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(generatePrivateKeyDH);
                PublicKey pk = kf.generatePublic(x509Spec);
                ka.doPhase(pk, true);
                byte secret[] = ka.generateSecret();
                SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
                DESKeySpec desSpec = new DESKeySpec(secret);

                SecretKey key = skf.generateSecret(desSpec);

                sessions.setSessionkey(key.getEncoded());

                sescontr.edit(sessions);

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, getpK(email));
                Message m = new Message(cipher.doFinal(applyHash(clientRandomToken.getBytes())));
                m.setAnswerBol(true);
                m.setMessageIntegrity(m.hashCode());
                return m;
            } catch (Exception ex) {
                Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return null;
    }

    private synchronized boolean checkSqlString(String x) {
        String result = x.replaceAll("[-+^:,'\"]", "");
        x = x.toLowerCase();
        return !(x.contains("from") || x.contains("select") || x.contains("drop") || !result.equals(x));
    }

    private byte[] applyHash(byte[] response) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            return digest.digest(response);
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    private synchronized boolean checkToken(String token, String email) {
        try {
            emf = Persistence.createEntityManagerFactory("segPU");
            SessionJpaController sescontr = new SessionJpaController(emf);

            EntityManager maneg = sescontr.getEntityManager();

            //Get Session from email user
            String quers = "SELECT res FROM Session res JOIN res.clientsidClients cl "
                    + "WHERE cl.email = '" + email + "'";
            if (!checkSqlString(email)) {
                return false;
            }
            TypedQuery<Session> querys = maneg.createQuery(quers, Session.class);

            Session sessions = querys.getSingleResult();

            //return token from data base
            String nowToken = sessions.getSessiontoken();
            if (nowToken.equals(token)) {
                return true;
            }
        } catch (Exception ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    private synchronized PublicKey getpK(String email) {
        try {
            emf = Persistence.createEntityManagerFactory("segPU");
            ClientsJpaController cjc = new ClientsJpaController(emf);
            EntityManager ent = cjc.getEntityManager();

            String teste = "SELECT res FROM Clients res WHERE res.email = '" + email + "'";
            if (!checkSqlString(email)) {
                return null;
            }
            TypedQuery<Clients> query = ent.createQuery(teste, Clients.class);
            Clients cl = query.getSingleResult();

            byte[] keySess = cl.getPublicKey();
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keySess));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(Operations.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private boolean validateChain(X509Certificate[] chain) {
        boolean validate = false;
        if (validate) {
            boolean c = validateCertificate(chain[0], chain[1]);
            boolean v = validateCertificate(chain[2], chain[3]);
            if (!c || !v) {
                return false;
            }
        }
        return true;
    }

    private long getTokenCertificate(PKCS11 module, long sessHandle, String label)
            throws PKCS11Exception {
        long[] certificates;
        CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];

        // Prepare only 1 search attributes: LABEL (the last function argument)
        attrs[0] = new CK_ATTRIBUTE();
        attrs[0].type = PKCS11Constants.CKA_LABEL;
        attrs[0].pValue = label.toCharArray();

        // Find objects with those attributes (should be only 1, in our case)
        module.C_FindObjectsInit(sessHandle, attrs);
        certificates = module.C_FindObjects(sessHandle, 1);
        module.C_FindObjectsFinal(sessHandle);

        System.out.println("Found " + certificates.length + " certificate objects with label \"" + label + "\"");
        return certificates[0];
    }

    private X509Certificate loadCertFromFile(String fileName) {
        FileInputStream fis;
        CertificateFactory cf;
        X509Certificate cert;

        try {

            fis = new FileInputStream(fileName);
            cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(fis);

        } catch (FileNotFoundException | CertificateException e) {
            return null;
        }

        return cert;
    }

    private ArrayList<X509Certificate> loadCertPath(String certsPath) {
        ArrayList<X509Certificate> certs = new ArrayList<>();
        String[] fileNames = {
            //"GTEGlobalRoot.der",
            "ECRaizEstado_novo_assinado_GTE.der",
            "CartaoDeCidadao001.der"};

        for (String fileName : fileNames) {
            String path = certsPath + "/" + fileName;
            X509Certificate cert = loadCertFromFile(path);
            if (cert != null) {
                certs.add(0, cert);
            } else {
                System.out.println("Could not load certificate from " + path);
            }
        }

        return certs;
    }

    private X509Certificate loadCertPathRoot(String certsPath) {
        String path = certsPath + "/GTEGlobalRoot.der";
        X509Certificate cert = loadCertFromFile(path);
        if (cert == null) {
            System.out.println("Could not load root certificate from " + path);
        }

        return cert;
    }

    private X509CRL getCRL(String crlUrl, X509Certificate issuer) {
        X509CRL crl = null;
        CertificateFactory cf;
        URL url;

        try {

            url = new URL(crlUrl);
            try (InputStream crlStream = url.openStream()) {
                cf = CertificateFactory.getInstance("X.509");
                crl = (X509CRL) cf.generateCRL(crlStream);
            }

            crl.verify(issuer.getPublicKey());

        } catch (MalformedURLException e) {
            System.out.println("Invalid URL for getting a CRL:" + e);
        } catch (IOException e) {
            System.out.println("Cannot access URL for getting a CRL:" + e);
        } catch (CertificateException e) {
            System.out.println("Cannot create a certificate factory:" + e);
        } catch (CRLException e) {
            System.out.println("Cannot build a local CRL:" + e);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid algorithm for validating the CRL:" + e);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key for validating the CRL:" + e);
        } catch (NoSuchProviderException e) {
            System.out.println("Invalid provider for validating the CRL:" + e);
        } catch (SignatureException e) {
            System.out.println("Invalid signature in CRL:" + e);
        }

        return crl;
    }

    private boolean validateCRL(List<X509Certificate> certs) {
        X509Certificate cert, issuer;
        Set<String> extensions;
        byte[] extension;
        String crlUrl = null, deltaUrl = null;
        X509CRL crl;
        X509CRLEntry entry;

        if (certs.size() > 2) {
            List<X509Certificate> reduced = certs.subList(1, certs.size() - 1);
            validateCRL(reduced);
        }

        cert = certs.get(0);
        issuer = certs.get(1);

        // Get non-critical extensions
        extensions = cert.getNonCriticalExtensionOIDs();
        for (String oid : extensions) {
            switch (oid) {
                case "2.5.29.31":
                    System.out.println("CRL Distribution Points:");
                    extension = cert.getExtensionValue(oid);
                    crlUrl = (new String(extension)).substring(12);
                    System.out.println("\t" + crlUrl);
                    break;
                case "2.5.29.46":
                    System.out.println("FreshestCRL:");
                    extension = cert.getExtensionValue(oid);
                    deltaUrl = (new String(extension)).substring(12);
                    System.out.println("\t" + deltaUrl);
                    break;
            }
        }

        // Check CRL and Delta CRL
        if (crlUrl != null) {
            crl = getCRL(crlUrl, issuer);
            if (crl == null) {
                return false;
            }

            entry = crl.getRevokedCertificate(cert);
            if (entry != null) {
                System.out.println("Certificate " + cert.getSubjectX500Principal()
                        + " revoked: " + entry.getRevocationReason());
            }

            if (deltaUrl != null) {
                crl = getCRL(deltaUrl, issuer);
                if (crl == null) {
                    return false;
                }

                entry = crl.getRevokedCertificate(cert);
                if (entry != null) {
                    System.out.println("Certificate " + cert.getSubjectX500Principal()
                            + " revoked: " + entry.getRevocationReason());
                }
            }
        }

        return true;
    }

    private boolean validateCertificate(X509Certificate cert, X509Certificate issuer) {

        CertificateFactory cf;
        X509Certificate root;
        ArrayList<X509Certificate> certs;
        CertPath cp = null;
        CertPathValidator cpv;

        // Check validity
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            System.out.println("Certificate has already expired (at " + cert.getNotAfter() + ")");
        } catch (CertificateNotYetValidException e) {
            System.out.println("Certificate has not yet started (only at " + cert.getNotBefore() + ")");
        }

        root = loadCertPathRoot("eidstore/certs");
        certs = loadCertPath("eidstore/certs");
        certs.add(0, issuer);
        certs.add(0, cert);

        try {

            cf = CertificateFactory.getInstance("X.509");
            cp = cf.generateCertPath(certs);
            //System.out.println ( "Certificate validation path:" + cp );

        } catch (CertificateException e) {
            System.out.println("Problem while building certificate path:" + e);
        }

        try {

            cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor ta = new TrustAnchor(root, null);
            PKIXParameters vp = new PKIXParameters(Collections.singleton(ta));
            vp.setRevocationEnabled(false);

            cpv.validate(cp, vp);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            System.out.println("Certificate path validation error:" + e);
        }

        List<X509Certificate> certsList = (List<X509Certificate>) cp.getCertificates();
        return validateCRL(certsList);
    }
}
