/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.securekeyexchange;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Server GUI:
 * 1) Generates DH key pair.
 * 2) Listens on a TCP port, accepts a client.
 * 3) Sends its DH public key first ("PUB:...").
 * 4) Receives client's public key, derives AES key.
 * 5) Sends/receives encrypted messages ("MSG:iv:ciphertext").
 */
public class ServerGUI extends JFrame {
    private JTextField portField;
    private JButton startBtn;
    private JTextArea logArea;

    private JTextField inputField;
    private JButton sendBtn;

    private volatile ServerSocket serverSocket;
    private volatile Socket socket;
    private DataInputStream in;
    private DataOutputStream out;

    private KeyPair myKeyPair;
    private SecretKey aesKey;

    public ServerGUI() {
        super("DH Server — Secure Key Exchange (AES-GCM)");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        buildUI();
        setSize(760, 520);
        setLocationRelativeTo(null);
    }

    private void buildUI() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Port:"));
        portField = new JTextField("5000", 8);
        top.add(portField);
        startBtn = new JButton("Start Server");
        top.add(startBtn);

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);

        JPanel bottom = new JPanel(new BorderLayout(8, 8));
        inputField = new JTextField();
        sendBtn = new JButton("Send (Encrypted)");
        sendBtn.setEnabled(false);
        bottom.add(inputField, BorderLayout.CENTER);
        bottom.add(sendBtn, BorderLayout.EAST);

        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        startBtn.addActionListener(e -> onStart());
        sendBtn.addActionListener(e -> onSend());
        inputField.addActionListener(e -> onSend());
    }

    private void onStart() {
        startBtn.setEnabled(false);
        new Thread(() -> {
            try {
                append("Generating DH key pair...");
                myKeyPair = CryptoUtils.generateDHKeyPair();

                int port = Integer.parseInt(portField.getText().trim());
                serverSocket = new ServerSocket(port);
                append("Server started on port " + port + ". Waiting for client...");

                socket = serverSocket.accept();
                append("Client connected: " + socket.getRemoteSocketAddress());

                in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                out.flush();

                // Send our DH public key first
                String myPubB64 = Base64.getEncoder().encodeToString(
                        CryptoUtils.encodePublicKey(myKeyPair.getPublic()));
                out.writeUTF("PUB:" + myPubB64);
                out.flush();
                append("→ Sent DH public key to client.");

                // Receive client's DH public key
                String line = in.readUTF();
                if (!line.startsWith("PUB:")) throw new IOException("Expected PUB from client");
                String clientPubB64 = line.substring(4);
                PublicKey clientPub = CryptoUtils.decodeDHPublicKey(
                        Base64.getDecoder().decode(clientPubB64));

                // Derive shared AES key
                byte[] shared = CryptoUtils.agreeSharedSecret(myKeyPair.getPrivate(), clientPub);
                aesKey = CryptoUtils.deriveAESKey(shared);
                append("✓ Shared AES key established. Fingerprint: " +
                        CryptoUtils.shortKeyFingerprint(aesKey));
                sendBtn.setEnabled(true);

                // Start a background reader
                new Thread(this::listenLoop, "Server-Listen").start();

            } catch (Exception ex) {
                append("ERROR: " + ex.getMessage());
                startBtn.setEnabled(true);
                closeAll();
            }
        }, "Server-Start").start();
    }

    private void listenLoop() {
        try {
            while (!Thread.currentThread().isInterrupted() && socket != null && socket.isConnected()) {
                String line = in.readUTF();
                if (line.startsWith("MSG:")) {
                    String payload = line.substring(4);
                    String msg = CryptoUtils.decryptAESGCM(payload, aesKey);
                    append("Client: " + msg);
                } else {
                    append("[Unknown] " + line);
                }
            }
        } catch (Exception ex) {
            append("Connection closed: " + ex.getMessage());
        } finally {
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
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        SwingUtilities.invokeLater(() -> sendBtn.setEnabled(false));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ServerGUI().setVisible(true));
    }
}
