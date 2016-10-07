package ServerSide;

import Interface.IOperations;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class Server {

    public static void main(String args[]) {

        try {
            System.err.println("Server Starting:");
            Operations obj = new Operations();
            IOperations stub = (IOperations) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the remote object's stub in the registry
            Registry registry = LocateRegistry.createRegistry(2020);
            try {
                System.out.println("-Bind");
                registry.bind("SafeBox", stub);
            } catch (AlreadyBoundException e) {
                System.out.println("-Rebind");
                registry.rebind("SafeBox", stub);
            }

            System.out.println("-Working");
        } catch (RemoteException e) {
            System.err.println("Server exception: " + e.toString());
        }
    }

}
