/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Users.GUI;

import Users.User;
import java.awt.HeadlessException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.xml.sax.SAXException;

/**
 *
 * @author Quang Dai
 */
public class AddContact_GUI extends javax.swing.JFrame {

    /**
     * Creates new form CreateAccount_GUI
     */
    public AddContact_GUI(String pathdir) {
        initComponents();
        this.path = pathdir;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel7 = new javax.swing.JLabel();
        AccountInfoPane = new javax.swing.JPanel();
        Name = new javax.swing.JLabel();
        NameField = new javax.swing.JTextField();
        PublicKey = new javax.swing.JLabel();
        Email = new javax.swing.JLabel();
        EmailField = new javax.swing.JTextField();
        DoB = new javax.swing.JLabel();
        DoBField = new javax.swing.JTextField();
        Phone = new javax.swing.JLabel();
        PhoneField = new javax.swing.JTextField();
        Address = new javax.swing.JLabel();
        AddressField = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        PublicKeyTextArea = new javax.swing.JTextArea();
        ButtonsPane = new javax.swing.JPanel();
        CreateAccountButton = new javax.swing.JButton();
        CancelButton = new javax.swing.JButton();

        jLabel7.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel7.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel7.setText("Add Contact");

        AccountInfoPane.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        Name.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Name.setText("Name:");

        PublicKey.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        PublicKey.setText("Public Key:");

        Email.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Email.setText("Email:");

        EmailField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                EmailFieldActionPerformed(evt);
            }
        });

        DoB.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        DoB.setText("Date Of Birth:");

        DoBField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DoBFieldActionPerformed(evt);
            }
        });

        Phone.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Phone.setText("Phone:");

        Address.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Address.setText("Address:");

        jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        PublicKeyTextArea.setColumns(20);
        PublicKeyTextArea.setLineWrap(true);
        PublicKeyTextArea.setRows(5);
        jScrollPane1.setViewportView(PublicKeyTextArea);

        javax.swing.GroupLayout AccountInfoPaneLayout = new javax.swing.GroupLayout(AccountInfoPane);
        AccountInfoPane.setLayout(AccountInfoPaneLayout);
        AccountInfoPaneLayout.setHorizontalGroup(
            AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                        .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(Email)
                            .addComponent(Name))
                        .addGap(58, 58, 58)
                        .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(NameField)
                            .addComponent(EmailField)))
                    .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                        .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(PublicKey)
                            .addComponent(DoB)
                            .addComponent(Phone)
                            .addComponent(Address))
                        .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                                .addGap(22, 22, 22)
                                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(PhoneField, javax.swing.GroupLayout.DEFAULT_SIZE, 179, Short.MAX_VALUE)
                                    .addComponent(AddressField)))
                            .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(DoBField, javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jScrollPane1))))))
                .addContainerGap())
        );
        AccountInfoPaneLayout.setVerticalGroup(
            AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Name)
                    .addComponent(NameField, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(EmailField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(Email))
                .addGap(8, 8, 8)
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(AccountInfoPaneLayout.createSequentialGroup()
                        .addComponent(PublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 12, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(DoBField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(DoB))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(PhoneField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(Phone))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(AccountInfoPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(AddressField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(Address))
                .addContainerGap())
        );

        ButtonsPane.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        CreateAccountButton.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        CreateAccountButton.setText("Add");
        CreateAccountButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CreateAccountButtonActionPerformed(evt);
            }
        });

        CancelButton.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        CancelButton.setText("Cancel");
        CancelButton.setToolTipText("");
        CancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout ButtonsPaneLayout = new javax.swing.GroupLayout(ButtonsPane);
        ButtonsPane.setLayout(ButtonsPaneLayout);
        ButtonsPaneLayout.setHorizontalGroup(
            ButtonsPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ButtonsPaneLayout.createSequentialGroup()
                .addContainerGap(20, Short.MAX_VALUE)
                .addComponent(CreateAccountButton, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(30, 30, 30)
                .addComponent(CancelButton, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(20, 20, 20))
        );
        ButtonsPaneLayout.setVerticalGroup(
            ButtonsPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ButtonsPaneLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(ButtonsPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(CancelButton, javax.swing.GroupLayout.DEFAULT_SIZE, 40, Short.MAX_VALUE)
                    .addComponent(CreateAccountButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(AccountInfoPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ButtonsPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(17, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(102, 102, 102))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(AccountInfoPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(ButtonsPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CreateAccountButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CreateAccountButtonActionPerformed
        // TODO add your handling code here:
        
        User user = new User();
        
        String email = "";
        email = this.EmailField.getText();
        
        String pub = "";
        pub = this.PublicKeyTextArea.getText();
        
        try 
        {
            if (!(email.equals("")))
            {
                String name = this.NameField.getText();
                String dateofbirth = this.DoBField.getText();
                String phone = this.PhoneField.getText();
                String add = this.AddressField.getText();
                user.Add_Account(path, name, email, pub, dateofbirth, phone, add);
                JOptionPane.showMessageDialog(null, "Add Successful!!!", "ADD", JOptionPane.WARNING_MESSAGE);
            }
            else
            {
                JOptionPane.showMessageDialog(null, "Add Unsuccessful!!!", "ADD", JOptionPane.WARNING_MESSAGE);
            }
        } 
        catch (HeadlessException | IOException | NoSuchAlgorithmException | InvalidKeySpecException | ParserConfigurationException | TransformerException | SAXException ex) 
        {
            Logger.getLogger(AddContact_GUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_CreateAccountButtonActionPerformed

    private void CancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelButtonActionPerformed
        // TODO add your handling code here:
        this.hide();
    }//GEN-LAST:event_CancelButtonActionPerformed

    private void DoBFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DoBFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_DoBFieldActionPerformed

    private void EmailFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_EmailFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_EmailFieldActionPerformed

    
    private String path;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel AccountInfoPane;
    private javax.swing.JLabel Address;
    private javax.swing.JTextField AddressField;
    private javax.swing.JPanel ButtonsPane;
    private javax.swing.JButton CancelButton;
    private javax.swing.JButton CreateAccountButton;
    private javax.swing.JLabel DoB;
    private javax.swing.JTextField DoBField;
    private javax.swing.JLabel Email;
    private javax.swing.JTextField EmailField;
    private javax.swing.JLabel Name;
    private javax.swing.JTextField NameField;
    private javax.swing.JLabel Phone;
    private javax.swing.JTextField PhoneField;
    private javax.swing.JLabel PublicKey;
    private javax.swing.JTextArea PublicKeyTextArea;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}