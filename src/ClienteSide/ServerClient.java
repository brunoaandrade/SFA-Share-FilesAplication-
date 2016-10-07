package ClienteSide;

import Interface.IOperations;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerClient {

    private static IOperations stub;
    private static Registry registry;

    public static void main(String[] args) {
        try {
            String host = "127.0.0.1";
            //host= (args.length < 1) ? null : args[0];
            registry = LocateRegistry.getRegistry(host, 2020);
            stub = (IOperations) registry.lookup("SafeBox");
            Client m = new Client(stub);
            m.menu();
        } catch (RemoteException | NotBoundException ex) {
            Logger.getLogger(ServerClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
