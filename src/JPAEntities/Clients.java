/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAEntities;

import java.io.Serializable;
import java.util.Collection;
import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 *
 * @author wayman
 */
@Entity
@Table(name = "Clients")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Clients.findAll", query = "SELECT c FROM Clients c"),
    @NamedQuery(name = "Clients.findByIdClients", query = "SELECT c FROM Clients c WHERE c.idClients = :idClients"),
    @NamedQuery(name = "Clients.findByName", query = "SELECT c FROM Clients c WHERE c.name = :name"),
    @NamedQuery(name = "Clients.findByEmail", query = "SELECT c FROM Clients c WHERE c.email = :email"),
    @NamedQuery(name = "Clients.findByIdPbox", query = "SELECT c FROM Clients c WHERE c.idPbox = :idPbox"),
    @NamedQuery(name = "Clients.findByNLogins", query = "SELECT c FROM Clients c WHERE c.nLogins = :nLogins"),
    @NamedQuery(name = "Clients.findByIsloggedin", query = "SELECT c FROM Clients c WHERE c.isloggedin = :isloggedin"),
    @NamedQuery(name = "Clients.findByKeyAlgorythm", query = "SELECT c FROM Clients c WHERE c.keyAlgorythm = :keyAlgorythm")})
public class Clients implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "idClients")
    private Integer idClients;
    @Basic(optional = false)
    @Column(name = "name")
    private String name;
    @Basic(optional = false)
    @Column(name = "email")
    private String email;
    @Column(name = "idPbox")
    private Integer idPbox;
    @Column(name = "nLogins")
    private Integer nLogins;
    @Column(name = "isloggedin")
    private Boolean isloggedin;
    @Basic(optional = false)
    @Lob
    @Column(name = "publicKey")
    private byte[] publicKey;
    @Column(name = "keyAlgorythm")
    private String keyAlgorythm;
    @Lob
    @Column(name = "userPassword")
    private byte[] userPassword;
    @Lob
    @Column(name = "cardPublickey")
    private byte[] cardPublickey;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "clientsidClients")
    private Collection<Pbox> pboxCollection;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "clientsidClients")
    private Collection<Session> sessionCollection;

    public Clients() {
    }

    public Clients(Integer idClients) {
        this.idClients = idClients;
    }

    public Clients(Integer idClients, String name, String email, byte[] publicKey) {
        this.idClients = idClients;
        this.name = name;
        this.email = email;
        this.publicKey = publicKey;
    }

    public Integer getIdClients() {
        return idClients;
    }

    public void setIdClients(Integer idClients) {
        this.idClients = idClients;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Integer getIdPbox() {
        return idPbox;
    }

    public void setIdPbox(Integer idPbox) {
        this.idPbox = idPbox;
    }

    public Integer getNLogins() {
        return nLogins;
    }

    public void setNLogins(Integer nLogins) {
        this.nLogins = nLogins;
    }

    public Boolean getIsloggedin() {
        return isloggedin;
    }

    public void setIsloggedin(Boolean isloggedin) {
        this.isloggedin = isloggedin;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public String getKeyAlgorythm() {
        return keyAlgorythm;
    }

    public void setKeyAlgorythm(String keyAlgorythm) {
        this.keyAlgorythm = keyAlgorythm;
    }

    public byte[] getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(byte[] userPassword) {
        this.userPassword = userPassword;
    }

    public byte[] getCardPublickey() {
        return cardPublickey;
    }

    public void setCardPublickey(byte[] cardPublickey) {
        this.cardPublickey = cardPublickey;
    }

    @XmlTransient
    public Collection<Pbox> getPboxCollection() {
        return pboxCollection;
    }

    public void setPboxCollection(Collection<Pbox> pboxCollection) {
        this.pboxCollection = pboxCollection;
    }

    @XmlTransient
    public Collection<Session> getSessionCollection() {
        return sessionCollection;
    }

    public void setSessionCollection(Collection<Session> sessionCollection) {
        this.sessionCollection = sessionCollection;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idClients != null ? idClients.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Clients)) {
            return false;
        }
        Clients other = (Clients) object;
        if ((this.idClients == null && other.idClients != null) || (this.idClients != null && !this.idClients.equals(other.idClients))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "JPAEntities.Clients[ idClients=" + idClients + " ]";
    }
    
}
