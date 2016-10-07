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
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
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
@Table(name = "Pbox")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Pbox.findAll", query = "SELECT p FROM Pbox p"),
    @NamedQuery(name = "Pbox.findByIdPbox", query = "SELECT p FROM Pbox p WHERE p.idPbox = :idPbox"),
    @NamedQuery(name = "Pbox.findByNumfiles", query = "SELECT p FROM Pbox p WHERE p.numfiles = :numfiles"),
    @NamedQuery(name = "Pbox.findBySize", query = "SELECT p FROM Pbox p WHERE p.size = :size"),
    @NamedQuery(name = "Pbox.findByPboxpath", query = "SELECT p FROM Pbox p WHERE p.pboxpath = :pboxpath")})
public class Pbox implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "idPbox")
    private Integer idPbox;
    @Basic(optional = false)
    @Column(name = "numfiles")
    private int numfiles;
    // @Max(value=?)  @Min(value=?)//if you know range of your decimal fields consider using these annotations to enforce field validation
    @Column(name = "size")
    private Float size;
    @Column(name = "pboxpath")
    private String pboxpath;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "pboxidPbox")
    private Collection<Permissions> permissionsCollection;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "pboxidPbox")
    private Collection<Files> filesCollection;
    @JoinColumn(name = "Clients_idClients", referencedColumnName = "idClients")
    @ManyToOne(optional = false)
    private Clients clientsidClients;

    public Pbox() {
    }

    public Pbox(Integer idPbox) {
        this.idPbox = idPbox;
    }

    public Pbox(Integer idPbox, int numfiles) {
        this.idPbox = idPbox;
        this.numfiles = numfiles;
    }

    public Integer getIdPbox() {
        return idPbox;
    }

    public void setIdPbox(Integer idPbox) {
        this.idPbox = idPbox;
    }

    public int getNumfiles() {
        return numfiles;
    }

    public void setNumfiles(int numfiles) {
        this.numfiles = numfiles;
    }

    public Float getSize() {
        return size;
    }

    public void setSize(Float size) {
        this.size = size;
    }

    public String getPboxpath() {
        return pboxpath;
    }

    public void setPboxpath(String pboxpath) {
        this.pboxpath = pboxpath;
    }

    @XmlTransient
    public Collection<Permissions> getPermissionsCollection() {
        return permissionsCollection;
    }

    public void setPermissionsCollection(Collection<Permissions> permissionsCollection) {
        this.permissionsCollection = permissionsCollection;
    }

    @XmlTransient
    public Collection<Files> getFilesCollection() {
        return filesCollection;
    }

    public void setFilesCollection(Collection<Files> filesCollection) {
        this.filesCollection = filesCollection;
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
        hash += (idPbox != null ? idPbox.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Pbox)) {
            return false;
        }
        Pbox other = (Pbox) object;
        if ((this.idPbox == null && other.idPbox != null) || (this.idPbox != null && !this.idPbox.equals(other.idPbox))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "JPAEntities.Pbox[ idPbox=" + idPbox + " ]";
    }
    
}
