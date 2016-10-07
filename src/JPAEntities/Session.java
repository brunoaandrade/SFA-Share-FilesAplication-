/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAEntities;

import java.io.Serializable;
import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author wayman
 */
@Entity
@Table(name = "Session")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Session.findAll", query = "SELECT s FROM Session s"),
    @NamedQuery(name = "Session.findByIdSession", query = "SELECT s FROM Session s WHERE s.idSession = :idSession"),
    @NamedQuery(name = "Session.findBySessiontoken", query = "SELECT s FROM Session s WHERE s.sessiontoken = :sessiontoken"),
    @NamedQuery(name = "Session.findByCardusing", query = "SELECT s FROM Session s WHERE s.cardusing = :cardusing"),
    @NamedQuery(name = "Session.findByTimeCreation", query = "SELECT s FROM Session s WHERE s.timeCreation = :timeCreation")})
public class Session implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "idSession")
    private Integer idSession;
    @Column(name = "sessiontoken")
    private String sessiontoken;
    @Column(name = "cardusing")
    private Boolean cardusing;
    @Basic(optional = false)
    @Column(name = "timeCreation")
    @Temporal(TemporalType.TIMESTAMP)
    private Date timeCreation;
    @Basic(optional = false)
    @Lob
    @Column(name = "sessionchalleger")
    private byte[] sessionchalleger;
    @Lob
    @Column(name = "sessionkey")
    private byte[] sessionkey;
    @Lob
    @Column(name = "challengeresponse")
    private byte[] challengeresponse;
    @JoinColumn(name = "Clients_idClients", referencedColumnName = "idClients")
    @ManyToOne(optional = false)
    private Clients clientsidClients;

    public Session() {
    }

    public Session(Integer idSession) {
        this.idSession = idSession;
    }

    public Session(Integer idSession, Date timeCreation, byte[] sessionchalleger) {
        this.idSession = idSession;
        this.timeCreation = timeCreation;
        this.sessionchalleger = sessionchalleger;
    }

    public Integer getIdSession() {
        return idSession;
    }

    public void setIdSession(Integer idSession) {
        this.idSession = idSession;
    }

    public String getSessiontoken() {
        return sessiontoken;
    }

    public void setSessiontoken(String sessiontoken) {
        this.sessiontoken = sessiontoken;
    }

    public Boolean getCardusing() {
        return cardusing;
    }

    public void setCardusing(Boolean cardusing) {
        this.cardusing = cardusing;
    }

    public Date getTimeCreation() {
        return timeCreation;
    }

    public void setTimeCreation(Date timeCreation) {
        this.timeCreation = timeCreation;
    }

    public byte[] getSessionchalleger() {
        return sessionchalleger;
    }

    public void setSessionchalleger(byte[] sessionchalleger) {
        this.sessionchalleger = sessionchalleger;
    }

    public byte[] getSessionkey() {
        return sessionkey;
    }

    public void setSessionkey(byte[] sessionkey) {
        this.sessionkey = sessionkey;
    }

    public byte[] getChallengeresponse() {
        return challengeresponse;
    }

    public void setChallengeresponse(byte[] challengeresponse) {
        this.challengeresponse = challengeresponse;
    }

    public Clients getClientsidClients() {
        return clientsidClients;
    }

    public void setClientsidClients(Clients clientsidClients) {
        this.clientsidClients = clientsidClients;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idSession != null ? idSession.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Session)) {
            return false;
        }
        Session other = (Session) object;
        if ((this.idSession == null && other.idSession != null) || (this.idSession != null && !this.idSession.equals(other.idSession))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "JPAEntities.Session[ idSession=" + idSession + " ]";
    }
    
}
