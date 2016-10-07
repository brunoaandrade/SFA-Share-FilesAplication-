/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAControllers;

import JPAControllers.exceptions.IllegalOrphanException;
import JPAControllers.exceptions.NonexistentEntityException;
import JPAEntities.Files;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import JPAEntities.Pbox;
import JPAEntities.Permissions;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

/**
 *
 * @author wayman
 */
public class FilesJpaController implements Serializable {

    public FilesJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(Files files) {
        if (files.getPermissionsCollection() == null) {
            files.setPermissionsCollection(new ArrayList<Permissions>());
        }
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Pbox pboxidPbox = files.getPboxidPbox();
            if (pboxidPbox != null) {
                pboxidPbox = em.getReference(pboxidPbox.getClass(), pboxidPbox.getIdPbox());
                files.setPboxidPbox(pboxidPbox);
            }
            Collection<Permissions> attachedPermissionsCollection = new ArrayList<Permissions>();
            for (Permissions permissionsCollectionPermissionsToAttach : files.getPermissionsCollection()) {
                permissionsCollectionPermissionsToAttach = em.getReference(permissionsCollectionPermissionsToAttach.getClass(), permissionsCollectionPermissionsToAttach.getIdPermissions());
                attachedPermissionsCollection.add(permissionsCollectionPermissionsToAttach);
            }
            files.setPermissionsCollection(attachedPermissionsCollection);
            em.persist(files);
            if (pboxidPbox != null) {
                pboxidPbox.getFilesCollection().add(files);
                pboxidPbox = em.merge(pboxidPbox);
            }
            for (Permissions permissionsCollectionPermissions : files.getPermissionsCollection()) {
                Files oldFilesidFilesOfPermissionsCollectionPermissions = permissionsCollectionPermissions.getFilesidFiles();
                permissionsCollectionPermissions.setFilesidFiles(files);
                permissionsCollectionPermissions = em.merge(permissionsCollectionPermissions);
                if (oldFilesidFilesOfPermissionsCollectionPermissions != null) {
                    oldFilesidFilesOfPermissionsCollectionPermissions.getPermissionsCollection().remove(permissionsCollectionPermissions);
                    oldFilesidFilesOfPermissionsCollectionPermissions = em.merge(oldFilesidFilesOfPermissionsCollectionPermissions);
                }
            }
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void edit(Files files) throws IllegalOrphanException, NonexistentEntityException, Exception {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Files persistentFiles = em.find(Files.class, files.getIdFiles());
            Pbox pboxidPboxOld = persistentFiles.getPboxidPbox();
            Pbox pboxidPboxNew = files.getPboxidPbox();
            Collection<Permissions> permissionsCollectionOld = persistentFiles.getPermissionsCollection();
            Collection<Permissions> permissionsCollectionNew = files.getPermissionsCollection();
            List<String> illegalOrphanMessages = null;
            for (Permissions permissionsCollectionOldPermissions : permissionsCollectionOld) {
                if (!permissionsCollectionNew.contains(permissionsCollectionOldPermissions)) {
                    if (illegalOrphanMessages == null) {
                        illegalOrphanMessages = new ArrayList<String>();
                    }
                    illegalOrphanMessages.add("You must retain Permissions " + permissionsCollectionOldPermissions + " since its filesidFiles field is not nullable.");
                }
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            if (pboxidPboxNew != null) {
                pboxidPboxNew = em.getReference(pboxidPboxNew.getClass(), pboxidPboxNew.getIdPbox());
                files.setPboxidPbox(pboxidPboxNew);
            }
            Collection<Permissions> attachedPermissionsCollectionNew = new ArrayList<Permissions>();
            for (Permissions permissionsCollectionNewPermissionsToAttach : permissionsCollectionNew) {
                permissionsCollectionNewPermissionsToAttach = em.getReference(permissionsCollectionNewPermissionsToAttach.getClass(), permissionsCollectionNewPermissionsToAttach.getIdPermissions());
                attachedPermissionsCollectionNew.add(permissionsCollectionNewPermissionsToAttach);
            }
            permissionsCollectionNew = attachedPermissionsCollectionNew;
            files.setPermissionsCollection(permissionsCollectionNew);
            files = em.merge(files);
            if (pboxidPboxOld != null && !pboxidPboxOld.equals(pboxidPboxNew)) {
                pboxidPboxOld.getFilesCollection().remove(files);
                pboxidPboxOld = em.merge(pboxidPboxOld);
            }
            if (pboxidPboxNew != null && !pboxidPboxNew.equals(pboxidPboxOld)) {
                pboxidPboxNew.getFilesCollection().add(files);
                pboxidPboxNew = em.merge(pboxidPboxNew);
            }
            for (Permissions permissionsCollectionNewPermissions : permissionsCollectionNew) {
                if (!permissionsCollectionOld.contains(permissionsCollectionNewPermissions)) {
                    Files oldFilesidFilesOfPermissionsCollectionNewPermissions = permissionsCollectionNewPermissions.getFilesidFiles();
                    permissionsCollectionNewPermissions.setFilesidFiles(files);
                    permissionsCollectionNewPermissions = em.merge(permissionsCollectionNewPermissions);
                    if (oldFilesidFilesOfPermissionsCollectionNewPermissions != null && !oldFilesidFilesOfPermissionsCollectionNewPermissions.equals(files)) {
                        oldFilesidFilesOfPermissionsCollectionNewPermissions.getPermissionsCollection().remove(permissionsCollectionNewPermissions);
                        oldFilesidFilesOfPermissionsCollectionNewPermissions = em.merge(oldFilesidFilesOfPermissionsCollectionNewPermissions);
                    }
                }
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = files.getIdFiles();
                if (findFiles(id) == null) {
                    throw new NonexistentEntityException("The files with id " + id + " no longer exists.");
                }
            }
            throw ex;
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void destroy(Integer id) throws IllegalOrphanException, NonexistentEntityException {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Files files;
            try {
                files = em.getReference(Files.class, id);
                files.getIdFiles();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The files with id " + id + " no longer exists.", enfe);
            }
            List<String> illegalOrphanMessages = null;
            Collection<Permissions> permissionsCollectionOrphanCheck = files.getPermissionsCollection();
            for (Permissions permissionsCollectionOrphanCheckPermissions : permissionsCollectionOrphanCheck) {
                if (illegalOrphanMessages == null) {
                    illegalOrphanMessages = new ArrayList<String>();
                }
                illegalOrphanMessages.add("This Files (" + files + ") cannot be destroyed since the Permissions " + permissionsCollectionOrphanCheckPermissions + " in its permissionsCollection field has a non-nullable filesidFiles field.");
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            Pbox pboxidPbox = files.getPboxidPbox();
            if (pboxidPbox != null) {
                pboxidPbox.getFilesCollection().remove(files);
                pboxidPbox = em.merge(pboxidPbox);
            }
            em.remove(files);
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public List<Files> findFilesEntities() {
        return findFilesEntities(true, -1, -1);
    }

    public List<Files> findFilesEntities(int maxResults, int firstResult) {
        return findFilesEntities(false, maxResults, firstResult);
    }

    private List<Files> findFilesEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(Files.class));
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

    public Files findFiles(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(Files.class, id);
        } finally {
            em.close();
        }
    }

    public int getFilesCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<Files> rt = cq.from(Files.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    
}
