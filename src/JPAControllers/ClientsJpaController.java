/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JPAControllers;

import JPAControllers.exceptions.IllegalOrphanException;
import JPAControllers.exceptions.NonexistentEntityException;
import JPAEntities.Clients;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import JPAEntities.Pbox;
import java.util.ArrayList;
import java.util.Collection;
import JPAEntities.Session;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

/**
 *
 * @author wayman
 */
public class ClientsJpaController implements Serializable {

    public ClientsJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(Clients clients) {
        if (clients.getPboxCollection() == null) {
            clients.setPboxCollection(new ArrayList<Pbox>());
        }
        if (clients.getSessionCollection() == null) {
            clients.setSessionCollection(new ArrayList<Session>());
        }
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Collection<Pbox> attachedPboxCollection = new ArrayList<Pbox>();
            for (Pbox pboxCollectionPboxToAttach : clients.getPboxCollection()) {
                pboxCollectionPboxToAttach = em.getReference(pboxCollectionPboxToAttach.getClass(), pboxCollectionPboxToAttach.getIdPbox());
                attachedPboxCollection.add(pboxCollectionPboxToAttach);
            }
            clients.setPboxCollection(attachedPboxCollection);
            Collection<Session> attachedSessionCollection = new ArrayList<Session>();
            for (Session sessionCollectionSessionToAttach : clients.getSessionCollection()) {
                sessionCollectionSessionToAttach = em.getReference(sessionCollectionSessionToAttach.getClass(), sessionCollectionSessionToAttach.getIdSession());
                attachedSessionCollection.add(sessionCollectionSessionToAttach);
            }
            clients.setSessionCollection(attachedSessionCollection);
            em.persist(clients);
            for (Pbox pboxCollectionPbox : clients.getPboxCollection()) {
                Clients oldClientsidClientsOfPboxCollectionPbox = pboxCollectionPbox.getClientsidClients();
                pboxCollectionPbox.setClientsidClients(clients);
                pboxCollectionPbox = em.merge(pboxCollectionPbox);
                if (oldClientsidClientsOfPboxCollectionPbox != null) {
                    oldClientsidClientsOfPboxCollectionPbox.getPboxCollection().remove(pboxCollectionPbox);
                    oldClientsidClientsOfPboxCollectionPbox = em.merge(oldClientsidClientsOfPboxCollectionPbox);
                }
            }
            for (Session sessionCollectionSession : clients.getSessionCollection()) {
                Clients oldClientsidClientsOfSessionCollectionSession = sessionCollectionSession.getClientsidClients();
                sessionCollectionSession.setClientsidClients(clients);
                sessionCollectionSession = em.merge(sessionCollectionSession);
                if (oldClientsidClientsOfSessionCollectionSession != null) {
                    oldClientsidClientsOfSessionCollectionSession.getSessionCollection().remove(sessionCollectionSession);
                    oldClientsidClientsOfSessionCollectionSession = em.merge(oldClientsidClientsOfSessionCollectionSession);
                }
            }
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void edit(Clients clients) throws IllegalOrphanException, NonexistentEntityException, Exception {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Clients persistentClients = em.find(Clients.class, clients.getIdClients());
            Collection<Pbox> pboxCollectionOld = persistentClients.getPboxCollection();
            Collection<Pbox> pboxCollectionNew = clients.getPboxCollection();
            Collection<Session> sessionCollectionOld = persistentClients.getSessionCollection();
            Collection<Session> sessionCollectionNew = clients.getSessionCollection();
            List<String> illegalOrphanMessages = null;
            for (Pbox pboxCollectionOldPbox : pboxCollectionOld) {
                if (!pboxCollectionNew.contains(pboxCollectionOldPbox)) {
                    if (illegalOrphanMessages == null) {
                        illegalOrphanMessages = new ArrayList<String>();
                    }
                    illegalOrphanMessages.add("You must retain Pbox " + pboxCollectionOldPbox + " since its clientsidClients field is not nullable.");
                }
            }
            for (Session sessionCollectionOldSession : sessionCollectionOld) {
                if (!sessionCollectionNew.contains(sessionCollectionOldSession)) {
                    if (illegalOrphanMessages == null) {
                        illegalOrphanMessages = new ArrayList<String>();
                    }
                    illegalOrphanMessages.add("You must retain Session " + sessionCollectionOldSession + " since its clientsidClients field is not nullable.");
                }
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            Collection<Pbox> attachedPboxCollectionNew = new ArrayList<Pbox>();
            for (Pbox pboxCollectionNewPboxToAttach : pboxCollectionNew) {
                pboxCollectionNewPboxToAttach = em.getReference(pboxCollectionNewPboxToAttach.getClass(), pboxCollectionNewPboxToAttach.getIdPbox());
                attachedPboxCollectionNew.add(pboxCollectionNewPboxToAttach);
            }
            pboxCollectionNew = attachedPboxCollectionNew;
            clients.setPboxCollection(pboxCollectionNew);
            Collection<Session> attachedSessionCollectionNew = new ArrayList<Session>();
            for (Session sessionCollectionNewSessionToAttach : sessionCollectionNew) {
                sessionCollectionNewSessionToAttach = em.getReference(sessionCollectionNewSessionToAttach.getClass(), sessionCollectionNewSessionToAttach.getIdSession());
                attachedSessionCollectionNew.add(sessionCollectionNewSessionToAttach);
            }
            sessionCollectionNew = attachedSessionCollectionNew;
            clients.setSessionCollection(sessionCollectionNew);
            clients = em.merge(clients);
            for (Pbox pboxCollectionNewPbox : pboxCollectionNew) {
                if (!pboxCollectionOld.contains(pboxCollectionNewPbox)) {
                    Clients oldClientsidClientsOfPboxCollectionNewPbox = pboxCollectionNewPbox.getClientsidClients();
                    pboxCollectionNewPbox.setClientsidClients(clients);
                    pboxCollectionNewPbox = em.merge(pboxCollectionNewPbox);
                    if (oldClientsidClientsOfPboxCollectionNewPbox != null && !oldClientsidClientsOfPboxCollectionNewPbox.equals(clients)) {
                        oldClientsidClientsOfPboxCollectionNewPbox.getPboxCollection().remove(pboxCollectionNewPbox);
                        oldClientsidClientsOfPboxCollectionNewPbox = em.merge(oldClientsidClientsOfPboxCollectionNewPbox);
                    }
                }
            }
            for (Session sessionCollectionNewSession : sessionCollectionNew) {
                if (!sessionCollectionOld.contains(sessionCollectionNewSession)) {
                    Clients oldClientsidClientsOfSessionCollectionNewSession = sessionCollectionNewSession.getClientsidClients();
                    sessionCollectionNewSession.setClientsidClients(clients);
                    sessionCollectionNewSession = em.merge(sessionCollectionNewSession);
                    if (oldClientsidClientsOfSessionCollectionNewSession != null && !oldClientsidClientsOfSessionCollectionNewSession.equals(clients)) {
                        oldClientsidClientsOfSessionCollectionNewSession.getSessionCollection().remove(sessionCollectionNewSession);
                        oldClientsidClientsOfSessionCollectionNewSession = em.merge(oldClientsidClientsOfSessionCollectionNewSession);
                    }
                }
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = clients.getIdClients();
                if (findClients(id) == null) {
                    throw new NonexistentEntityException("The clients with id " + id + " no longer exists.");
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
            Clients clients;
            try {
                clients = em.getReference(Clients.class, id);
                clients.getIdClients();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The clients with id " + id + " no longer exists.", enfe);
            }
            List<String> illegalOrphanMessages = null;
            Collection<Pbox> pboxCollectionOrphanCheck = clients.getPboxCollection();
            for (Pbox pboxCollectionOrphanCheckPbox : pboxCollectionOrphanCheck) {
                if (illegalOrphanMessages == null) {
                    illegalOrphanMessages = new ArrayList<String>();
                }
                illegalOrphanMessages.add("This Clients (" + clients + ") cannot be destroyed since the Pbox " + pboxCollectionOrphanCheckPbox + " in its pboxCollection field has a non-nullable clientsidClients field.");
            }
            Collection<Session> sessionCollectionOrphanCheck = clients.getSessionCollection();
            for (Session sessionCollectionOrphanCheckSession : sessionCollectionOrphanCheck) {
                if (illegalOrphanMessages == null) {
                    illegalOrphanMessages = new ArrayList<String>();
                }
                illegalOrphanMessages.add("This Clients (" + clients + ") cannot be destroyed since the Session " + sessionCollectionOrphanCheckSession + " in its sessionCollection field has a non-nullable clientsidClients field.");
            }
            if (illegalOrphanMessages != null) {
                throw new IllegalOrphanException(illegalOrphanMessages);
            }
            em.remove(clients);
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public List<Clients> findClientsEntities() {
        return findClientsEntities(true, -1, -1);
    }

    public List<Clients> findClientsEntities(int maxResults, int firstResult) {
        return findClientsEntities(false, maxResults, firstResult);
    }

    private List<Clients> findClientsEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(Clients.class));
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

    public Clients findClients(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(Clients.class, id);
        } finally {
            em.close();
        }
    }

    public int getClientsCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<Clients> rt = cq.from(Clients.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    
}
