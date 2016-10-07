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
@Table(name = "Files")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Files.findAll", query = "SELECT f FROM Files f"),
    @NamedQuery(name = "Files.findByIdFiles", query = "SELECT f FROM Files f WHERE f.idFiles = :idFiles"),
    @NamedQuery(name = "Files.findByName", query = "SELECT f FROM Files f WHERE f.name = :name"),
    @NamedQuery(name = "Files.findByExtension", query = "SELECT f FROM Files f WHERE f.extension = :extension"),
    @NamedQuery(name = "Files.findByFilepath", query = "SELECT f FROM Files f WHERE f.filepath = :filepath"),
    @NamedQuery(name = "Files.findByKeyAlgorythm", query = "SELECT f FROM Files f WHERE f.keyAlgorythm = :keyAlgorythm")})
public class Files implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "idFiles")
    private Integer idFiles;
    @Basic(optional = false)
    @Column(name = "name")
    private String name;
    @Basic(optional = false)
    @Column(name = "extension")
    private String extension;
    @Column(name = "filepath")
    private String filepath;
    @Column(name = "keyAlgorythm")
    private String keyAlgorythm;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "filesidFiles")
    private Collection<Permissions> permissionsCollection;
    @JoinColumn(name = "Pbox_idPbox", referencedColumnName = "idPbox")
    @ManyToOne(optional = false)
    private Pbox pboxidPbox;

    public Files() {
    }

    public Files(Integer idFiles) {
        this.idFiles = idFiles;
    }

    public Files(Integer idFiles, String name, String extension) {
        this.idFiles = idFiles;
        this.name = name;
        this.extension = extension;
    }

    public Integer getIdFiles() {
        return idFiles;
    }

    public void setIdFiles(Integer idFiles) {
        this.idFiles = idFiles;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getExtension() {
        return extension;
    }

    public void setExtension(String extension) {
        this.extension = extension;
    }

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
    }

    public String getKeyAlgorythm() {
        return keyAlgorythm;
    }

    public void setKeyAlgorythm(String keyAlgorythm) {
        this.keyAlgorythm = keyAlgorythm;
    }

    @XmlTransient
    public Collection<Permissions> getPermissionsCollection() {
        return permissionsCollection;
    }

    public void setPermissionsCollection(Collection<Permissions> permissionsCollection) {
        this.permissionsCollection = permissionsCollection;
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
        hash += (idFiles != null ? idFiles.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Files)) {
            return false;
        }
        Files other = (Files) object;
        if ((this.idFiles == null && other.idFiles != null) || (this.idFiles != null && !this.idFiles.equals(other.idFiles))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "JPAEntities.Files[ idFiles=" + idFiles + " ]";
    }
    
}
