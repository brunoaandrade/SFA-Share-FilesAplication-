/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAControllers;

import JPAControllers.exceptions.IllegalOrphanException;
import JPAControllers.exceptions.NonexistentEntityException;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import JPAEntities.Clients;
import JPAEntities.Permissions;
import java.util.ArrayList;
import java.util.Collection;
import JPAEntities.Files;
import JPAEntities.Pbox;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

/**
 *
 * @author wayman
 */
public class PboxJpaController implements Serializable {

    public PboxJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(Pbox pbox) {
        if (pbox.getPermissionsCollection() == null) {
            pbox.setPermissionsCollection(new ArrayList<Permissions>());
        }
        if (pbox.getFilesCollection() == null) {
            pbox.setFilesCollection(new ArrayList<Files>());
        }
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Clients clientsidClients = pbox.getClientsidClients();
            if (clientsidClients != null) {
                clientsidClients = em.getReference(clientsidClients.getClass(), clientsidClients.getIdClients());
                pbox.setClientsidClients(clientsidClients);
            }
            Collection<Permissions> attachedPermissionsCollection = new ArrayList<Permissions>();
            for (Permissions permissionsCollectionPermissionsToAttach : pbox.getPermissionsCollection()) {
                permissionsCollectionPermissionsToAttach = em.getReference(permissionsCollectionPermissionsToAttach.getClass(), permissionsCollectionPermissionsToAttach.getIdPermissions());
                attachedPermissionsCollection.add(permissionsCollectionPermissionsToAttach);
            }
            pbox.setPermissionsCollection(attachedPermissionsCollection);
            Collection<Files> attachedFilesCollection = new ArrayList<Files>();
            for (Files filesCollectionFilesToAttach : pbox.getFilesCollection()) {
                filesCollectionFilesToAttach = em.getReference(filesCollectionFilesToAttach.getClass(), filesCollectionFilesToAttach.getIdFiles());
                attachedFilesCollection.add(filesCollectionFilesToAttach);
            }
            pbox.setFilesCollection(attachedFilesCollection);
            em.persist(pbox);
            if (clientsidClients != null) {
                clientsidClients.getPboxCollection().add(pbox);
                clientsidClients = em.merge(clientsidClients);
            }
            for (Permissions permissionsCollectionPermissions : pbox.getPermissionsCollection()) {
                Pbox oldPboxidPboxOfPermissionsCollectionPermissions = permissionsCollectionPermissions.getPboxidPbox();
                permissionsCollectionPermissions.setPboxidPbox(pbox);
                permissionsCollectionPermissions = em.merge(permissionsCollectionPermissions);
                if (oldPboxidPboxOfPermissionsCollectionPermissions != null) {
                    oldPboxidPboxOfPermissionsCollectionPermissions.getPermissionsCollection().remove(permissionsCollectionPermissions);
                    oldPboxidPboxOfPermissionsCollectionPermissions = em.merge(oldPboxidPboxOfPermissionsCollectionPermissions);
                }
            }
            for (Files filesCollectionFiles : pbox.getFilesCollection()) {
                Pbox oldPboxidPboxOfFilesCollectionFiles = filesCollectionFiles.getPboxidPbox();
                filesCollectionFiles.setPboxidPbox(pbox);
                filesCollectionFiles = em.merge(filesCollectionFiles);
                if (oldPboxidPboxOfFilesCollectionFiles != null) {
                    oldPboxidPboxOfFilesCollectionFiles.getFilesCollection().remove(filesCollectionFiles);
                    oldPboxidPboxOfFilesCollectionFiles = em.merge(oldPboxidPboxOfFilesCollectionFiles);
                }
            }
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void edit(Pbox pbox) throws IllegalOrphanException, NonexistentEntityException, Exception {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Pbox persistentPbox = em.find(Pbox.class, pbox.getIdPbox());
            Clients clientsidClientsOld = persistentPbox.getClientsidClients();
            Clients clientsidClientsNew = pbox.getClientsidClients();
            Collection<Permissions> permissionsCollectionOld = persistentPbox.getPermissionsCollection();
            Collection<Permissions> permissionsCollectionNew = pbox.getPermissionsCollection();
            Collection<Files> filesCollectionOld = persistentPbox.getFilesCollection();
            Collection<Files> filesCollectionNew = pbox.getFilesCollection();
            List<String> illegalOrphanMessages = null;
            for (Permissions permissionsCollectionOldPermissions : permissionsCollectionOld) {
                if (!permissionsCollectionNew.contains(permissionsCollectionOldPermissions)) {
                    if (illegalOrphanMessages == null) {
                        illegalOrphanMessages = new ArrayList<String>();
                    }
                    illegalOrphanMessages.add("You must retain Permissions " + permissionsCollectionOldPermissions + " since its pboxidPbox field is not nullable.");
                }
            }
            for (Files filesCollectionOldFiles : filesCollectionOld) {
                if (!filesCollectionNew.contains(filesCollectionOldFiles)) {
                    if (illegalOrphanMessages == null) {
                        illegalOrphanMessages = new ArrayList<String>();
                    }
                    illegalOrphanMessages.add("You must retain Files " + filesCollectionOldFiles + " since its pboxidPbox field is not nullable.");
                }
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            if (clientsidClientsNew != null) {
                clientsidClientsNew = em.getReference(clientsidClientsNew.getClass(), clientsidClientsNew.getIdClients());
                pbox.setClientsidClients(clientsidClientsNew);
            }
            Collection<Permissions> attachedPermissionsCollectionNew = new ArrayList<Permissions>();
            for (Permissions permissionsCollectionNewPermissionsToAttach : permissionsCollectionNew) {
                permissionsCollectionNewPermissionsToAttach = em.getReference(permissionsCollectionNewPermissionsToAttach.getClass(), permissionsCollectionNewPermissionsToAttach.getIdPermissions());
                attachedPermissionsCollectionNew.add(permissionsCollectionNewPermissionsToAttach);
            }
            permissionsCollectionNew = attachedPermissionsCollectionNew;
            pbox.setPermissionsCollection(permissionsCollectionNew);
            Collection<Files> attachedFilesCollectionNew = new ArrayList<Files>();
            for (Files filesCollectionNewFilesToAttach : filesCollectionNew) {
                filesCollectionNewFilesToAttach = em.getReference(filesCollectionNewFilesToAttach.getClass(), filesCollectionNewFilesToAttach.getIdFiles());
                attachedFilesCollectionNew.add(filesCollectionNewFilesToAttach);
            }
            filesCollectionNew = attachedFilesCollectionNew;
            pbox.setFilesCollection(filesCollectionNew);
            pbox = em.merge(pbox);
            if (clientsidClientsOld != null && !clientsidClientsOld.equals(clientsidClientsNew)) {
                clientsidClientsOld.getPboxCollection().remove(pbox);
                clientsidClientsOld = em.merge(clientsidClientsOld);
            }
            if (clientsidClientsNew != null && !clientsidClientsNew.equals(clientsidClientsOld)) {
                clientsidClientsNew.getPboxCollection().add(pbox);
                clientsidClientsNew = em.merge(clientsidClientsNew);
            }
            for (Permissions permissionsCollectionNewPermissions : permissionsCollectionNew) {
                if (!permissionsCollectionOld.contains(permissionsCollectionNewPermissions)) {
                    Pbox oldPboxidPboxOfPermissionsCollectionNewPermissions = permissionsCollectionNewPermissions.getPboxidPbox();
                    permissionsCollectionNewPermissions.setPboxidPbox(pbox);
                    permissionsCollectionNewPermissions = em.merge(permissionsCollectionNewPermissions);
                    if (oldPboxidPboxOfPermissionsCollectionNewPermissions != null && !oldPboxidPboxOfPermissionsCollectionNewPermissions.equals(pbox)) {
                        oldPboxidPboxOfPermissionsCollectionNewPermissions.getPermissionsCollection().remove(permissionsCollectionNewPermissions);
                        oldPboxidPboxOfPermissionsCollectionNewPermissions = em.merge(oldPboxidPboxOfPermissionsCollectionNewPermissions);
                    }
                }
            }
            for (Files filesCollectionNewFiles : filesCollectionNew) {
                if (!filesCollectionOld.contains(filesCollectionNewFiles)) {
                    Pbox oldPboxidPboxOfFilesCollectionNewFiles = filesCollectionNewFiles.getPboxidPbox();
                    filesCollectionNewFiles.setPboxidPbox(pbox);
                    filesCollectionNewFiles = em.merge(filesCollectionNewFiles);
                    if (oldPboxidPboxOfFilesCollectionNewFiles != null && !oldPboxidPboxOfFilesCollectionNewFiles.equals(pbox)) {
                        oldPboxidPboxOfFilesCollectionNewFiles.getFilesCollection().remove(filesCollectionNewFiles);
                        oldPboxidPboxOfFilesCollectionNewFiles = em.merge(oldPboxidPboxOfFilesCollectionNewFiles);
                    }
                }
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = pbox.getIdPbox();
                if (findPbox(id) == null) {
                    throw new NonexistentEntityException("The pbox with id " + id + " no longer exists.");
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
            Pbox pbox;
            try {
                pbox = em.getReference(Pbox.class, id);
                pbox.getIdPbox();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The pbox with id " + id + " no longer exists.", enfe);
            }
            List<String> illegalOrphanMessages = null;
            Collection<Permissions> permissionsCollectionOrphanCheck = pbox.getPermissionsCollection();
            for (Permissions permissionsCollectionOrphanCheckPermissions : permissionsCollectionOrphanCheck) {
                if (illegalOrphanMessages == null) {
                    illegalOrphanMessages = new ArrayList<String>();
                }
                illegalOrphanMessages.add("This Pbox (" + pbox + ") cannot be destroyed since the Permissions " + permissionsCollectionOrphanCheckPermissions + " in its permissionsCollection field has a non-nullable pboxidPbox field.");
            }
            Collection<Files> filesCollectionOrphanCheck = pbox.getFilesCollection();
            for (Files filesCollectionOrphanCheckFiles : filesCollectionOrphanCheck) {
                if (illegalOrphanMessages == null) {
                    illegalOrphanMessages = new ArrayList<String>();
                }
                illegalOrphanMessages.add("This Pbox (" + pbox + ") cannot be destroyed since the Files " + filesCollectionOrphanCheckFiles + " in its filesCollection field has a non-nullable pboxidPbox field.");
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            Clients clientsidClients = pbox.getClientsidClients();
            if (clientsidClients != null) {
                clientsidClients.getPboxCollection().remove(pbox);
                clientsidClients = em.merge(clientsidClients);
            }
            em.remove(pbox);
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public List<Pbox> findPboxEntities() {
        return findPboxEntities(true, -1, -1);
    }

    public List<Pbox> findPboxEntities(int maxResults, int firstResult) {
        return findPboxEntities(false, maxResults, firstResult);
    }

    private List<Pbox> findPboxEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(Pbox.class));
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

    public Pbox findPbox(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(Pbox.class, id);
        } finally {
            em.close();
        }
    }

    public int getPboxCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<Pbox> rt = cq.from(Pbox.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    
}
