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
import JPAEntities.Clients;
import JPAEntities.Session;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

/**
 *
 * @author wayman
 */
public class SessionJpaController implements Serializable {

    public SessionJpaController(EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(Session session) {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Clients clientsidClients = session.getClientsidClients();
            if (clientsidClients != null) {
                clientsidClients = em.getReference(clientsidClients.getClass(), clientsidClients.getIdClients());
                session.setClientsidClients(clientsidClients);
            }
            em.persist(session);
            if (clientsidClients != null) {
                clientsidClients.getSessionCollection().add(session);
                clientsidClients = em.merge(clientsidClients);
            }
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public void edit(Session session) throws NonexistentEntityException, Exception {
        EntityManager em = null;
        try {
            em = getEntityManager();
            em.getTransaction().begin();
            Session persistentSession = em.find(Session.class, session.getIdSession());
            Clients clientsidClientsOld = persistentSession.getClientsidClients();
            Clients clientsidClientsNew = session.getClientsidClients();
            if (clientsidClientsNew != null) {
                clientsidClientsNew = em.getReference(clientsidClientsNew.getClass(), clientsidClientsNew.getIdClients());
                session.setClientsidClients(clientsidClientsNew);
            }
            session = em.merge(session);
            if (clientsidClientsOld != null && !clientsidClientsOld.equals(clientsidClientsNew)) {
                clientsidClientsOld.getSessionCollection().remove(session);
                clientsidClientsOld = em.merge(clientsidClientsOld);
            }
            if (clientsidClientsNew != null && !clientsidClientsNew.equals(clientsidClientsOld)) {
                clientsidClientsNew.getSessionCollection().add(session);
                clientsidClientsNew = em.merge(clientsidClientsNew);
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = session.getIdSession();
                if (findSession(id) == null) {
                    throw new NonexistentEntityException("The session with id " + id + " no longer exists.");
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
            Session session;
            try {
                session = em.getReference(Session.class, id);
                session.getIdSession();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The session with id " + id + " no longer exists.", enfe);
            }
            Clients clientsidClients = session.getClientsidClients();
            if (clientsidClients != null) {
                clientsidClients.getSessionCollection().remove(session);
                clientsidClients = em.merge(clientsidClients);
            }
            em.remove(session);
            em.getTransaction().commit();
        } finally {
            if (em != null) {
                em.close();
            }
        }
    }

    public List<Session> findSessionEntities() {
        return findSessionEntities(true, -1, -1);
    }

    public List<Session> findSessionEntities(int maxResults, int firstResult) {
        return findSessionEntities(false, maxResults, firstResult);
    }

    private List<Session> findSessionEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(Session.class));
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

    public Session findSession(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(Session.class, id);
        } finally {
            em.close();
        }
    }

    public int getSessionCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<Session> rt = cq.from(Session.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    
}
