/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAEntities;

import java.io.Serializable;
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
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author wayman
 */
@Entity
@Table(name = "Permissions")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Permissions.findAll", query = "SELECT p FROM Permissions p"),
    @NamedQuery(name = "Permissions.findByIdPermissions", query = "SELECT p FROM Permissions p WHERE p.idPermissions = :idPermissions")})
public class Permissions implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "idPermissions")
    private Integer idPermissions;
    @Basic(optional = false)
    @Lob
    @Column(name = "encryptedsymkey")
    private byte[] encryptedsymkey;
    @JoinColumn(name = "Files_idFiles", referencedColumnName = "idFiles")
    @ManyToOne(optional = false)
    private Files filesidFiles;
    @JoinColumn(name = "Pbox_idPbox", referencedColumnName = "idPbox")
    @ManyToOne(optional = false)
    private Pbox pboxidPbox;

    public Permissions() {
    }

    public Permissions(Integer idPermissions) {
        this.idPermissions = idPermissions;
    }

    public Permissions(Integer idPermissions, byte[] encryptedsymkey) {
        this.idPermissions = idPermissions;
        this.encryptedsymkey = encryptedsymkey;
    }

    public Integer getIdPermissions() {
        return idPermissions;
    }

    public void setIdPermissions(Integer idPermissions) {
        this.idPermissions = idPermissions;
    }

    public byte[] getEncryptedsymkey() {
        return encryptedsymkey;
    }

    public void setEncryptedsymkey(byte[] encryptedsymkey) {
        this.encryptedsymkey = encryptedsymkey;
    }

    public Files getFilesidFiles() {
        return filesidFiles;
    }

    public void setFilesidFiles(Files filesidFiles) {
        this.filesidFiles = filesidFiles;
    }

    public Pbox getPboxidPbox() {
        return pboxidPbox;
    }

    public void setPboxidPbox(Pbox pboxidPbox) {
        this.pboxidPbox = pboxidPbox;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idPermissions != null ? idPermissions.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Permissions)) {
            return false;
        }
        Permissions other = (Permissions) object;
        if ((this.idPermissions == null && other.idPermissions != null) || (this.idPermissions != null && !this.idPermissions.equals(other.idPermissions))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "JPAEntities.Permissions[ idPermissions=" + idPermissions + " ]";
    }
    
}
