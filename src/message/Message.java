/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package message;

import JPAEntities.Files;
import JPAEntities.Pbox;
import JPAEntities.Permissions;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author andrade
 */
public class Message implements Serializable{

    private int messageIntegrity;
    private final byte[] randomTokenChipher;
    private boolean answerBol;
    private byte[] answerByte;

    private int answerInt;
    private BigInteger[] answerListBigInt;
    private List<Pbox> answerListPbox;
    private List<Files> answerListFiles;
    private List<Permissions> answerListPerm;

    public Message(byte[] randomTokenChipher) {
        this.randomTokenChipher = randomTokenChipher;
    }

    public int getMessageIntegrity() {
        return messageIntegrity;
    }

    public void setMessageIntegrity(int messageIntegrity) {
        this.messageIntegrity = messageIntegrity;
    }

    public byte[] getRandomTokenChipher() {
        return randomTokenChipher;
    }

    public boolean isAnswerBol() {
        return answerBol;
    }

    public byte[] getAnswerByte() {
        return answerByte;
    }

    public List<Pbox> getAnswerListPbox() {
        return answerListPbox;
    }

    public List<Files> getAnswerListFiles() {
        return answerListFiles;
    }

    public List<Permissions> getAnswerListPerm() {
        return answerListPerm;
    }

    public int getAnswerInt() {
        return answerInt;
    }

    public BigInteger[] getAnswerListBigInt() {
        return answerListBigInt;
    }

    public void setAnswerBol(boolean answerBol) {
        this.answerBol = answerBol;
    }

    public void setAnswerByte(byte[] answerByte) {
        this.answerByte = answerByte;
    }

    public void setAnswerListPbox(List<Pbox> answerListPbox) {
        this.answerListPbox = answerListPbox;
    }

    public void setAnswerListFiles(List<Files> answerListFiles) {
        this.answerListFiles = answerListFiles;
    }

    public void setAnswerListPerm(List<Permissions> answerListPerm) {
        this.answerListPerm = answerListPerm;
    }

    public void setAnswerInt(int answerInt) {
        this.answerInt = answerInt;
    }

    public void setAnswerListBigInt(BigInteger[] answerListBigInt) {
        this.answerListBigInt = answerListBigInt;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Arrays.hashCode(this.randomTokenChipher);
        hash = 53 * hash + (this.answerBol ? 1 : 0);
        hash = 53 * hash + Arrays.hashCode(this.answerByte);
        hash = 53 * hash + Objects.hashCode(this.answerListPbox);
        hash = 53 * hash + Objects.hashCode(this.answerListFiles);
        hash = 53 * hash + Objects.hashCode(this.answerListPerm);
        hash = 53 * hash + this.answerInt;
        hash = 53 * hash + Arrays.deepHashCode(this.answerListBigInt);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Message other = (Message) obj;
        return true;
    }

    public boolean getAnswerBol() {
        return answerBol;
    }
}
