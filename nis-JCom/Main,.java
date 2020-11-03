
import java.awt.*;
import java.awt.image.*;
import java.awt.event.*;
import javax.swing.*;
import javax.imageio.ImageIO;
import java.io.File;
import java.util.Random;
import javax.crypto.*;	
import javax.crypto.spec.*;
class Main extends JFrame implements ActionListener{

    private ImageRead panel; 
    private ImageEncrypt encrypter; 
    private File fileName;

    public Main(){

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setTitle("NIS-PROJECT");
        setLayout(new BorderLayout());
        panel = new ImageRead(); 
        getContentPane().add(panel); 
        pack(); 
        setJMenuBar(MainMenu()); 

        setSize(new Dimension(550, 550));
        encrypter = new ImageEncrypt();
    }

   //Main function
    private JMenuBar MainMenu(){

        JMenuBar menuBar = new JMenuBar();
	
        JMenu file, menu, help;
        JMenuItem open, save, saveas, close,		//menu items 
                setkey, Encrypt, Decrypt, content, about;
 
        file = new JMenu("File");
        menu = new JMenu("JCrypt");
        help = new JMenu("Help");

        open = new JMenuItem("Open  ..", new ImageIcon("./icon/folder.png"));
        save = new JMenuItem("Save", new ImageIcon("./icon/save.png"));
        saveas = new JMenuItem("Save as   ..");
        close = new JMenuItem("Close ", new ImageIcon("./icon/close.png"));

        setkey = new JMenuItem("Set Pass Key", new ImageIcon("./icon/key.png"));
        Encrypt = new JMenuItem("Encrypt Image", new ImageIcon("./icon/lock.png"));
        Decrypt = new JMenuItem("Decrypt Image", new ImageIcon("./icon/unlock.png"));

        about = new JMenuItem("About", new ImageIcon("./icon/info.png"));

            
        file.add(open); file.addSeparator(); file.add(save); file.add(saveas); file.addSeparator();file.add(close);
        menu.add(setkey); menu.addSeparator(); menu.add(Encrypt); menu.add(Decrypt);
        help.add(about);
        
       
        menuBar.add(file);      menuBar.add(menu);      menuBar.add(help);

       
        open.addActionListener(this);       setkey.addActionListener(this);     close.addActionListener(this);
        save.addActionListener(this);       Encrypt.addActionListener(this);    about.addActionListener(this);
        saveas.addActionListener(this);     Decrypt.addActionListener(this);    
            return menuBar;
    }

    
    public void setFile(File file){
        fileName = file;
    }

   
    public void actionPerformed(ActionEvent action) {

        String text = action.getActionCommand();

        try{
            
            if(text == "Open  .."){ actionLoadImage(null); } 
            else if(text == "Save"){ actionSaveImage(fileName); } 
            else if(text == "Save as   .."){ actionSaveImage(null);} 
            else if(text == "Close "){ System.exit(0);} 
            else if(text == "Set Pass Key"){  
              actionKeyDialog(); 
            }
            else if(text == "Encrypt Image"){
                panel.setImage(encrypter.map(panel.getImage(),true,false)); 
            }
            else if(text == "Decrypt Image"){
                panel.setImage(encrypter.map(panel.getImage(),false,false)); 
            }
            else if(text == "About"){
				DisplayContactinfo();
				}

        }catch(Exception err)
        { System.out.println("ERROR:" + err);}
    }
   
    public void actionKeyDialog(){
        String key = new String(encrypter.getKey());

        key = (String)JOptionPane.showInputDialog(this,
                "Enter a 16 bit key (current key= " +
                        key.getBytes().length + " bytes)",key);

        while(key != null && key.getBytes().length != 16){

            key = (String)JOptionPane.showInputDialog(this,
                    "Enter a 16 bit key (current key= " +
                            key.getBytes().length + " bytes)",key);
        }

        if(key != null) encrypter.setKey(key.getBytes());
    }

  
    public void actionLoadImage(File imageFile){

        if(imageFile == null){
            JFileChooser fc = new JFileChooser(fileName);
            fc.setControlButtonsAreShown(false);
            fc.showOpenDialog(this);
            imageFile = fc.getSelectedFile();
        }
	
        if(imageFile != null){

            panel.setImage(imageFromFile(imageFile));
            setFile(imageFile);
        }
    }

 
    private BufferedImage imageFromFile(File file){

        BufferedImage img = null;
        try{
            img = ImageIO.read(file);
        }catch(Exception e){
            System.out.println("Error:" + e);
        }
        return img;
    }

    public void actionSaveImage(File imageFile){

        if(imageFile == null){
            JFileChooser filechooser = new JFileChooser(fileName);
            filechooser.showSaveDialog(this);
            imageFile = filechooser.getSelectedFile();
        }

        if(imageFile != null){
            try{
                ImageIO.write(panel.getImage(), "png", imageFile);
            }catch(Exception e){
                System.out.println("Error:" + e);
            }
            setFile(imageFile);
        }
    }





    public void DisplayContactinfo(){

        JFrame contact = new JFrame("Contact info");
        contact.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        contact.setSize(new Dimension(500, 430));
        contact.setLayout(new BorderLayout());
        contact.setDefaultCloseOperation(3);
        contact.setResizable(false);
      
        String About = 
        "\tITE-4001\n\n\n"+
    "\tFall-Semester-2020\n\n"+
    "\tNETWORK  AND  INFORMATION  SECURITY\n\n"+
    "\tProject By: \n"+
    "\tHARIDA PK\n"+
    "\tAYUSHI GUPTA\n\n"+
    "\t18BIT0411\n" +  
    "\t18BIT0367\n"+          
    "\tProject on Enhancing Data Security using Multi-Key algorithm in Cloud\n\n";
  	
  	
JTextArea cont1 = new JTextArea(About);
contact.add(new JScrollPane(cont1), BorderLayout.CENTER);
cont1.setEditable(false);

contact.setVisible(true);

    }
    public static void main(String args[])
    {
        Main win = new Main();
        win.setVisible(true);

        if(args.length > 0){
            win.actionLoadImage(new File(args[0]));
        }
    }
}


class ImageRead extends JPanel{

    private BufferedImage image;

    public ImageRead()
    {
        this.image = null;

        setFocusable(true);

        setLayout(null);
        setOpaque(true);

    }

    public void setImage(BufferedImage image){

        this.image = image;
        repaint();
    }

   
    public BufferedImage getImage(){
        return image;
    }
    public void paintComponent(Graphics g) {
        g.setColor(new Color(34, 33, 33));
        g.fillRect(0,0,getSize().width,getSize().height);

        if(image != null){

            int center_x = getSize().width/2 - image.getWidth() /2;
            int center_y = getSize().height/2 - image.getHeight() /2;

            if(center_x < 10){ center_x = 10;}
            if(center_y < 10){ center_y = 10;}

            g.drawImage(image,center_x,center_y,null);
        }
    }
}

class ImageEncrypt{

    private boolean verbose=false;
    private Random generator;

    private Cipher cipher;
    private SecretKeySpec skeySpec;

  
 
    ImageEncrypt() {

        try{
            
            generator = new Random();

            KeyGenerator kgen = KeyGenerator.getInstance("AES"); 
            kgen.init(128);
          

            SecretKey skey = kgen.generateKey();
            byte[] raw = skey.getEncoded();
            skeySpec = new SecretKeySpec(raw, "AES");

            cipher = Cipher.getInstance("AES/ECB");

        }catch(Exception e){ System.out.println("ERROR: " + e);}else{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC"); 
            ECNamedCurveParameterSpec curveParameterSpec = ECNamedCurveTable.getParameterSpec(" "); 
            keyPairGenerator.initialize(curveParameterSpec, new SecureRandom());
            KeyPair KeyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey publicKey = (ECPublicKey) KeyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) KeyPair.getPrivate();
            javax.crypto.Cipher c1 = javax.crypto.Cipher.getInstance("EC", "BC","RSA");
            javax.crypto.Cipher c2 = javax.crypto.Cipher.getInstance("EC", "BC","RSA");    //ECC and RSA encryption on AES key
            c1.init(ENCRYPT_MODE, publicKey,  new SecureRandom());
            c2.init(DECRYPT_MODE, privateKey, new SecureRandom());

   try{
        File bmpFile = new File("C:\\Users\\Desktop\\imageFile");
        BufferedImage image = ImageIO.read(bmpFile);
      
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ImageIO.write(image, "bmp", baos );

        byte[] b = baos.toByteArray(); 
        byte[] cipherimage = c1.doFinal(b, 0, b.length); 
        byte[] plainimage = c2.doFinal(cipherimage, 0, cipherimage.length);
        bmpFile=new File("C:\\Users\\Desktop\\imageFile");
        FileOutputStream fos = new FileOutputStream(bmpFile);
        fos.write(cipherimage);
        fos.flush();
        fos.close();
        bmpFile=new File("C:\\Users\\acer\\Desktop\\py\\decryptedimage.bmp");
        FileOutputStream fos1 = new FileOutputStream(bmpFile);
        fos1.write(plainimage);
        fos1.flush();
        fos1.close();
   } catch (IOException e){
     System.out.println(e.getMessage());
   }
        }

    }

    
    public void setKey(byte [] key){

        skeySpec = new SecretKeySpec(key,"AES");
    }

    byte [] getKey(){ return skeySpec.getEncoded();}

   
    public BufferedImage map(BufferedImage image,boolean encrypt,boolean trick) throws Exception{


        // Test if the image is devisible by 2
        if(image.getWidth() % 2 != 0 || image.getHeight() % 2 != 0){
            throw(new Exception("Image size not multiple of 2 :("));
        }

        BufferedImage encImage = new BufferedImage(image.getWidth(),image.getHeight(),
                BufferedImage.TYPE_4BYTE_ABGR);

        if(encrypt){
            System.out.println("Encrypting Your Image ... trick=" + trick);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        }
        else{
            System.out.println("Decrypting Image ... trick=" + trick);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        }

        for(int x=0;x<image.getWidth(); x+=2){
            for(int y=0;y<image.getHeight(); y+=2){
                if(verbose) System.out.println("Block: (" + x+","+y+") -----");

                int counter =0;
                byte [] pixelBytes = new byte[16];
              
                for (int i=0;i<2;i++){
                    for (int j=0;j<2;j++){
                        int val = image.getRGB(x+i,y+j);
                       if(trick && encrypt) val +=x*y;
                        byte [] sub  = intToByteArray(val);

                        if(verbose){
                            System.out.println("Val: " + val + " Bytes: ");
                            printByteArray(sub);
                        }
                        for(int k=0;k<4;k++) pixelBytes[(counter)*4+k] = sub[k];
                        counter++;
                   }
                }

               
                byte [] enc = cipher.doFinal(pixelBytes);
                if(verbose){
				    printByteArray(pixelBytes);
					printByteArray(enc);
                }
                counter =0;
       
                for (int i=0;i<2;i++){
                  for (int j=0;j<2;j++){
                     byte [] sub = new byte[4];
					for(int k=0;k<4;k++) 
					sub[k] = enc[(counter)*4+k];

                int val = byteArrayToInt(sub);
                if(trick && !encrypt) val -=x*y;

                encImage.setRGB(x+i,y+j,val);

                counter++;
                    }
                }
            }
        }
        return encImage;
    }

    public static final byte[] intToByteArray(int value)
    {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
    }

    public static final int byteArrayToInt(byte [] b)
    {
        return (b[0] << 24)
                + ((b[1] & 0xFF) << 16)
                + ((b[2] & 0xFF) << 8)
                + (b[3] & 0xFF);
    }

    public static void printByteArray(byte [] array)
    {
        System.out.print("{");
        for(int i=0;i<array.length;i++)
            System.out.print(" " + array[i]);
        System.out.println(" }");
    }
}
