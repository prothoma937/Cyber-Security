/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.securekeyexchangedh;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.Base64;

public class ClientApp extends JFrame {
    private JTextField hostField, portField;
    private JButton connectBtn;
    private JTextArea logArea;
    private JTextField inputField;
    private JButton sendBtn;

    private volatile Socket socket;
    private DataInputStream in;
    private DataOutputStream out;

    private KeyPair myKeyPair;
    private SecretKey aesKey;

    public ClientApp() {
        super("DH Client — Secure Key Exchange");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        buildUI();
        setSize(700, 500);
        setLocationRelativeTo(null);
    }

    private void buildUI() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Host:"));
        hostField = new JTextField("127.0.0.1", 10);
        top.add(hostField);
        top.add(new JLabel("Port:"));
        portField = new JTextField("5000", 6);
        top.add(portField);
        connectBtn = new JButton("Connect");
        top.add(connectBtn);

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);

        JPanel bottom = new JPanel(new BorderLayout());
        inputField = new JTextField();
        sendBtn = new JButton("Send (Encrypted)");
        sendBtn.setEnabled(false);
        bottom.add(inputField, BorderLayout.CENTER);
        bottom.add(sendBtn, BorderLayout.EAST);

        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        connectBtn.addActionListener(e -> onConnect());
        sendBtn.addActionListener(e -> onSend());
        inputField.addActionListener(e -> onSend());
    }

    private void onConnect() {
        connectBtn.setEnabled(false);
        new Thread(() -> {
            try {
                append("Generating DH key pair...");
                myKeyPair = CryptoUtils.generateDHKeyPair();
                String host = hostField.getText().trim();
                int port = Integer.parseInt(portField.getText().trim());
                socket = new Socket(host, port);
                append("Connected to server: " + socket.getRemoteSocketAddress());
                in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                out.flush();

                String line = in.readUTF();
                if (!line.startsWith("PUB:")) throw new IOException("Expected PUB from server");
                String serverPubB64 = line.substring(4);
                PublicKey serverPub = CryptoUtils.decodeDHPublicKey(Base64.getDecoder().decode(serverPubB64));
                append("← Received server DH public key.");

                String myPubB64 = Base64.getEncoder().encodeToString(CryptoUtils.encodePublicKey(myKeyPair.getPublic()));
                out.writeUTF("PUB:" + myPubB64);
                out.flush();
                append("→ Sent client DH public key.");

                byte[] shared = CryptoUtils.agreeSharedSecret(myKeyPair.getPrivate(), serverPub);
                aesKey = CryptoUtils.deriveAESKey(shared);
                append("✓ Shared AES key established. Fingerprint: " + CryptoUtils.shortKeyFingerprint(aesKey));
                sendBtn.setEnabled(true);

                new Thread(this::listenLoop).start();
            } catch (Exception ex) {
                append("ERROR: " + ex.getMessage());
                connectBtn.setEnabled(true);
                closeAll();
            }
        }).start();
    }

    private void listenLoop() {
        try {
            while (!Thread.currentThread().isInterrupted() && socket != null && socket.isConnected()) {
                String line = in.readUTF();
                if (line.startsWith("MSG:")) {
                    String payload = line.substring(4);
                    String msg = CryptoUtils.decryptAESGCM(payload, aesKey);
                    append("Server: " + msg);
                } else {
                    append("[Unknown] " + line);
                }
            }
        } catch (Exception ex) {
            append("Connection closed: " + ex.getMessage());
            closeAll();
        }
    }

    private void onSend() {
        String text = inputField.getText().trim();
        if (text.isEmpty()) return;
        inputField.setText("");
        try {
            String payload = CryptoUtils.encryptAESGCM(text, aesKey);
            out.writeUTF("MSG:" + payload);
            out.flush();
            append("You: " + text);
        } catch (Exception ex) {
            append("Send error: " + ex.getMessage());
        }
    }

    private void append(String s) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(s + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void closeAll() {
        try { if (in != null) in.close(); } catch (IOException ignored) {}
        try { if (out != null) out.close(); } catch (IOException ignored) {}
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
        SwingUtilities.invokeLater(() -> sendBtn.setEnabled(false));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ClientApp().setVisible(true));
    }
}
