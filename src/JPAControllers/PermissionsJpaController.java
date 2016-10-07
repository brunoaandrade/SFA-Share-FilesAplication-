/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAControllers;

import JPAControllers.exceptions.NonexistentEntityException;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import JPAEntities.Files;
import JPAEntities.Pbox;
import JPAEntities.Permissions;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

/**
 *
 * @author wayman
 */
public class PermissionsJpaController implements Serializable {

    public PermissionsJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(Permissions permissions) {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Files filesidFiles = permissions.getFilesidFiles();
            if (filesidFiles != null) {
                filesidFiles = em.getReference(filesidFiles.getClass(), filesidFiles.getIdFiles());
                permissions.setFilesidFiles(filesidFiles);
            }
            Pbox pboxidPbox = permissions.getPboxidPbox();
            if (pboxidPbox != null) {
                pboxidPbox = em.getReference(pboxidPbox.getClass(), pboxidPbox.getIdPbox());
                permissions.setPboxidPbox(pboxidPbox);
            }
            em.persist(permissions);
            if (filesidFiles != null) {
                filesidFiles.getPermissionsCollection().add(permissions);
                filesidFiles = em.merge(filesidFiles);
            }
            if (pboxidPbox != null) {
                pboxidPbox.getPermissionsCollection().add(permissions);
                pboxidPbox = em.merge(pboxidPbox);
            }
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void edit(Permissions permissions) throws NonexistentEntityException, Exception {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Permissions persistentPermissions = em.find(Permissions.class, permissions.getIdPermissions());
            Files filesidFilesOld = persistentPermissions.getFilesidFiles();
            Files filesidFilesNew = permissions.getFilesidFiles();
            Pbox pboxidPboxOld = persistentPermissions.getPboxidPbox();
            Pbox pboxidPboxNew = permissions.getPboxidPbox();
            if (filesidFilesNew != null) {
                filesidFilesNew = em.getReference(filesidFilesNew.getClass(), filesidFilesNew.getIdFiles());
                permissions.setFilesidFiles(filesidFilesNew);
            }
            if (pboxidPboxNew != null) {
                pboxidPboxNew = em.getReference(pboxidPboxNew.getClass(), pboxidPboxNew.getIdPbox());
                permissions.setPboxidPbox(pboxidPboxNew);
            }
            permissions = em.merge(permissions);
            if (filesidFilesOld != null && !filesidFilesOld.equals(filesidFilesNew)) {
                filesidFilesOld.getPermissionsCollection().remove(permissions);
                filesidFilesOld = em.merge(filesidFilesOld);
            }
            if (filesidFilesNew != null && !filesidFilesNew.equals(filesidFilesOld)) {
                filesidFilesNew.getPermissionsCollection().add(permissions);
                filesidFilesNew = em.merge(filesidFilesNew);
            }
            if (pboxidPboxOld != null && !pboxidPboxOld.equals(pboxidPboxNew)) {
                pboxidPboxOld.getPermissionsCollection().remove(permissions);
                pboxidPboxOld = em.merge(pboxidPboxOld);
            }
            if (pboxidPboxNew != null && !pboxidPboxNew.equals(pboxidPboxOld)) {
                pboxidPboxNew.getPermissionsCollection().add(permissions);
                pboxidPboxNew = em.merge(pboxidPboxNew);
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = permissions.getIdPermissions();
                if (findPermissions(id) == null) {
                    throw new NonexistentEntityException("The permissions with id " + id + " no longer exists.");
                }
            }
            throw ex;
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void destroy(Integer id) throws NonexistentEntityException {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Permissions permissions;
            try {
                permissions = em.getReference(Permissions.class, id);
                permissions.getIdPermissions();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The permissions with id " + id + " no longer exists.", enfe);
            }
            Files filesidFiles = permissions.getFilesidFiles();
            if (filesidFiles != null) {
                filesidFiles.getPermissionsCollection().remove(permissions);
                filesidFiles = em.merge(filesidFiles);
            }
            Pbox pboxidPbox = permissions.getPboxidPbox();
            if (pboxidPbox != null) {
                pboxidPbox.getPermissionsCollection().remove(permissions);
                pboxidPbox = em.merge(pboxidPbox);
            }
            em.remove(permissions);
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public List<Permissions> findPermissionsEntities() {
        return findPermissionsEntities(true, -1, -1);
    }

    public List<Permissions> findPermissionsEntities(int maxResults, int firstResult) {
        return findPermissionsEntities(false, maxResults, firstResult);
    }

    private List<Permissions> findPermissionsEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(Permissions.class));
            Query q = em.createQuery(cq);
            if (!all) {
                q.setMaxResults(maxResults);
                q.setFirstResult(firstResult);
            }
            return q.getResultList();
        } finally {
            em.close();
        }
    }

    public Permissions findPermissions(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(Permissions.class, id);
        } finally {
            em.close();
        }
    }

    public int getPermissionsCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<Permissions> rt = cq.from(Permissions.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    
}
