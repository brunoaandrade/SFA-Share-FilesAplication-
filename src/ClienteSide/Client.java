/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ClienteSide;

import Interface.IOperations;
import JPAEntities.Files;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 * @author Bruno
 */
public class Client {

    private final IOperations stub;
    private ClientActions ca;
    private final File dir = new File("Keys");

    Client(IOperations stub) {
        this.stub = stub;
        if (!dir.exists()) {
            try {
                dir.mkdir();
            } catch (SecurityException se) {
                //handle it
            }

        }
    }

    public void menu() {
        ca = new ClientActions(stub);
        int num = ca.choseMenu();
        switch (num) {
            case 1:
                ca.createAccount();
                menu();
                break;
            case 2:
                if (ca.iniciateSession()) {
                    menu1();
                } else {
                    menu();
                }
                break;
            default:
                System.out.println("Not a valid option!");
                menu();
        }
    }

    private void menu1() {

        System.out.println("• 1 List the existing PBoxes.");
        System.out.println("• 2 List my PBox files.");
        System.out.println("• 3 Add a protected file to my PBox.");
        System.out.println("• 4 Terminate a session with my PBox.");
        System.out.println("");
        System.out.print("• option:");
        Scanner in = new Scanner(System.in);
        int num = in.nextInt();
        System.out.println("");
        switch (num) {
            case 1:
                ca.listAllPbox();
                menu1();
                break;
            case 3:
                ca.addFile();
                menu1();
                break;
            case 2:
                List<Files> lf = ca.listFiles();
                if (lf.isEmpty()) {
                    menu1();
                } else {
                    List<String> filesID = new ArrayList<>();
                    for (Files lf1 : lf) {
                        filesID.add(lf1.getName());
                    }
                    menu2(filesID);
                }
                break;
            case 4:
                if(ca.terminateSession())
                    menu();
                menu1();
                break;
            default:
                System.out.println("Not a valid option!");
                menu1();
        }
    }

    private void menu2(List<String> filesID) {
        System.out.println("• 1 Download File       - Get the original file contents of a protected file in my PBox.");
        System.out.println("• 2 File sharing Table  - List the PBoxes sharing a file of my PBox.");
        System.out.println("• 3 Share a file        - Share a file in my PBox with other PBoxes.");
        System.out.println("• 4 UnShare a file      - Unshare a file in my PBox.");
        System.out.println("• 5 Delete              - Delete a file from my PBoxa file from my PBox.");
        System.out.println("• 6 Update File         - Upload a file to replace a file that you already have");
        System.out.println("• 7 Menu                - Go back");
        System.out.println("");

        System.out.print("• option:");
        Scanner in = new Scanner(System.in);
        int num = in.nextInt();
        System.out.println("");
        switch (num) {
            case 1:
                ca.getFile(filesID);
                menu1();
                break;
            case 2:
                ca.shareTableFile(filesID);
                menu1();
                break;
            case 3:
                ca.shareFile(filesID);
                menu1();
                break;
            case 4:
                ca.unShareFile(filesID);
                menu1();
                break;
            case 5:
                ca.deleteFile(filesID);
                menu1();
                break;
            case 6:
                ca.updateFile(filesID);
                menu1();
                break;
            case 7:
                menu1();
                break;

            default:
                System.out.println("Not a valid option!");
                menu2(filesID);
        }
    }
}
