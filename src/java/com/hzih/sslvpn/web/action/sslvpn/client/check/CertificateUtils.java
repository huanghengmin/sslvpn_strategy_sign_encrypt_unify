/*
package com.hzih.sslvpn.web.action.sslvpn.client.check;

import com.hzih.sslvpn.sm.HexUtil;
import com.hzih.sslvpn.sm2.SM3Digest;
import org.apache.log4j.Logger;
import org.apache.struts2.views.xslt.StringAdapter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.x509.X509Key;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PSSParameterSpec;
import java.util.Date;

*/
/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-7-3
 * Time: 下午9:33
 * To change this template use File | Settings | File Templates.
 *//*

public class CertificateUtils {
    private Logger logger = Logger.getLogger(CertificateUtils.class);

    */
/**
     * 国家
     *//*

    private String C = "C";
    */
/**
     * 通用名
     *//*

    private String CN = "CN";
    */
/**
     *部门u
     *//*

    private String OU = "OU";
    */
/**
     * 单位
     *//*

    private String O = "O";
    */
/**
     * 省
     *//*

    private String ST = "ST";
    */
/**
     * 市
     *//*

    private String L = "L";
    */
/**
     * Email
     *//*

    private String E = "E";



    public String getSubject(String subject,String t){
           if(subject.contains(t)){

           }
        return null;
    }



    public static final DERNull INSTANCE = new DERNull();


    public static byte[] SubByte(byte[] input, int startIndex, int length) {
        byte[] bt = new byte[length];
        for (int i = 0; i < length; i++) {
            bt[i] = input[i + startIndex];
        }
        return bt;
    }

    //正式参数
    public static String[] ecc_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
//            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
//            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
//            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };



    public static void main(String args[])throws Exception{
        File file3 = new File("D:\\TEST\\SM2\\sm2\\ca.der.cer");
//        File file4 = new File("D:\\TEST\\SM2\\client.der.cer");
//        File file5 = new File("D:\\TEST\\SM2\\server.der.cer");
//        File file6 = new File("D:\\TEST\\SM2\\PublicKey.der");


//        X509Certificate x509Certificate1 =  get_x509_certificate(file1);
//        X509Certificate x509Certificate2 = get_x509_certificate(file4);

        X509CertificateStructure CA =  getX509CertificateStructure(file3);

//        X509CertificateStructure client =  getX509CertificateStructure(file4);
//        AlgorithmIdentifier algorithmIdentifier = certificateStructure.getSignatureAlgorithm();
//        System.out.println(algorithmIdentifier.getAlgorithm());
        byte[] signature = getSignature(CA);

        System.out.println( HexUtil.byteToHex(getSignature(CA)));

//        System.out.println( HexUtil.byteToHex(getSignature(client)));
//        System.out.println( "client:" +HexUtil.byteToHex(getSignature(client)));

//        System.out.println( HexUtil.byteToHex(getPubKey(CA)));
//        System.out.println( "client:"+HexUtil.byteToHex(getPubKey(client)));

//        String privatekey = "MCUCAQEEIIouSCKRd4I4HVMwPSKQ5p4Pgp207vWBpppW8RWVmjgU";

//        String md1 = "hello world";
//        byte[] bytes =  Base64.encode(CA.getTBSCertificate().getSignature().getEncoded());

//        byte[] signature = Base64.encode(getSignature(CA));
//        System.out.println(new String(signature));

        byte[] pk = Base64.encode(getPubKey(CA));
        System.out.println(new String(pk));

        DERBitString publicKeyData = CA.getTBSCertificate().getSubjectPublicKeyInfo().getPublicKeyData();
        byte[] publicKey = publicKeyData.getEncoded();
        byte[] encodedPublicKey = publicKey;
        byte[] eP = new byte[64];
        System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);


        String hex = "30818d300f0603551d130101ff040530030101ff300b0603551d0f0404030201"+
                "06306d0603551d250466306406082b0601050507030206082b06010505070304"+
                "06082b0601050507030906082b0601050507030806082b060105050703030608"+
                "2b0601050507030106082b0601050507030506082b0601050507030606082b06" +
                "01050507030706082b06010505070305";

 String hex2 = "3081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100"+
                "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff" +
                "30440420fffffffeffffffffffffffffffffffffffffffff00000000ffffffff"+
                "fffffffc042028e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbc" +
                "bd414d940e9304410432c4ae2c1f1981195f9904466a39c9948fe30bbff2660b"+
                "e1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a47"+
                "4002df32e52139f0a0022100fffffffeffffffffffffffffffffffff7203df6b"+
                "21c6052b53bbf40939d541230201010342000493a37a641c4bde97110309e103"+
                "245bfd5441cfdb145c5d0ba1dce1e152237b5ed5e7c522ef4188137b49b47e5a"+
                "6acc3f70953663cedcf030e15fe6cca14844f4";

        String hex3 ="3082029AA003020102020100300A06082A811CCF55018375304C3112301006035504030C09534D32524F4F544341310B300906035504061302434E310B3009060355040A0C024C5A310D300B060355040B0C0448414841310D300B06035504080C045A484F4E301E170D3136303732303131353834335A170D3236303731383131353834335A304C3112301006035504030C09534D32524F4F544341310B300906035504061302434E310B3009060355040A0C024C5A310D300B060355040B0C0448414841310D300B06035504080C045A484F4E308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF30440420FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC042028E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E9304410432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0022100FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D541230201010342000493A37A641C4BDE97110309E103245BFD5441CFDB145C5D0BA1DCE1E152237B5ED5E7C522EF4188137B49B47E5A6ACC3F70953663CEDCF030E15FE6CCA14844F4A3819030818D300F0603551D130101FF040530030101FF300B0603551D0F040403020106306D0603551D250466306406082B0601050507030206082B0601050507030406082B0601050507030906082B0601050507030806082B0601050507030306082B0601050507030106082B0601050507030506082B0601050507030606082B0601050507030706082B06010505070305";

        byte[] hexbyte = HexUtil.hexStringToBytes(hex);
        byte[] hex2byte = HexUtil.hexStringToBytes(hex2);
        byte[] hex3byte = HexUtil.hexStringToBytes(hex3);

//        String hex3 ="";

        System.out.println("getTBSCertificate().getEncoded:::::::::::::::"+ HexUtil.byteToHex(CA.getTBSCertificate().getEncoded()));
        System.out.println("publicKeyData::::::"+ HexUtil.byteToHex(publicKey));
        System.out.println("eP:::::::::::"+ HexUtil.byteToHex(eP));
//        System.out.println("CA.getTBSCertificate().toASN1Primitive().getEncoded():::::"+ HexUtil.byteToHex(CA.getTBSCertificate().toASN1Primitive().getEncoded()));

//        return eP;

        BigInteger ecc_p = new BigInteger(ecc_param[0], 16);
        BigInteger ecc_a = new BigInteger(ecc_param[1], 16);
        BigInteger ecc_b = new BigInteger(ecc_param[2], 16);
        BigInteger ecc_n = new BigInteger(ecc_param[3], 16);
        BigInteger ecc_gx = new BigInteger(ecc_param[4], 16);
        BigInteger ecc_gy = new BigInteger(ecc_param[5], 16);

        ECFieldElement ecc_gx_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gx);
        ECFieldElement ecc_gy_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gy);

        ECCurve ecc_curve = new ECCurve.Fp(ecc_p, ecc_a, ecc_b);
        ECPoint ecc_point_g = new ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);
        byte[] pkX = SubByte(pk, 0, 32);
        byte[] pkY = SubByte(pk, 32, 32);
        BigInteger biX = new BigInteger(1, pkX);
        BigInteger biY = new BigInteger(1, pkY);
        ECFieldElement x = new ECFieldElement.Fp(ecc_p, biX);
        ECFieldElement y = new ECFieldElement.Fp(ecc_p, biY);
        ECPoint userKey = new ECPoint.Fp(ecc_curve, x, y);
        //
        SM3Digest sm3 = new SM3Digest();
        //第一步，组建数据ZA并计算HASH值
        byte[] sm2Za = sm3.getSM2Za(pkX, pkY, "1234567812345678".getBytes());
        sm3.update(sm2Za, 0, sm2Za.length);

//        System.out.println("Sm2Za:"+HexUtil.byteToHex(sm2Za));

        sm3.update(hex3byte,0,hex3byte.length);
        System.out.println("hex3byte:"+HexUtil.byteToHex(hex3byte));

//        byte[] msg = new byte[1024];

//        System.arraycopy(getPubKey(CA), 0, msg, getPubKey(CA).length, getPubKey(CA).length);
//        System.arraycopy(signature, 0, msg, 0, getPubKey(CA).length);

//        sm3.update(msg,0,msg.length);

        byte[] md = new byte[32];

        sm3.doFinal(md, 0);

        System.out.println("md:"+HexUtil.byteToHex(md));

        byte[] btRS = signature;
        byte[] btR = SubByte(btRS, 0, btRS.length / 2);
        byte[] btS = SubByte(btRS, btR.length, btRS.length - btR.length);

        BigInteger r = new BigInteger(1, btR);
        BigInteger s = new BigInteger(1, btS);

        // e_
        BigInteger e = new BigInteger(1, md);

        // t
        BigInteger t = r.add(s).mod(ecc_n);

        if (t.equals(BigInteger.ZERO))
            System.out.println(Boolean.valueOf(false));

        // x1y1
        ECPoint x1y1 = ecc_point_g.multiply(s);
        x1y1 = x1y1.add(userKey.multiply(t));

        // R
        BigInteger R = e.add(x1y1.getX().toBigInteger()).mod(ecc_n);

        System.out.println(r.equals(R));

//        System.out.println("USERID:"+HexUtil.byteToHex(sm2Za));

//        String pri = "8kDdnOTQIb2I5dUgdsK57olAvL0xNjl4nxp1VxSHqjM=";

//        k6N6ZBxL3pcRAwnhAyRb/VRBz9sUXF0Lodzh4VIje17V58Ui70GIE3tJtH5aasw/cJU2Y87c8DDhX+bMoUhE9A==  公钥
//                8kDdnOTQIb2I5dUgdsK57olAvL0xNjl4nxp1VxSHqjM=   //私钥

//        String signature = Sm2Sign(md1.getBytes(),pk,privatekey.getBytes());

//        String plaintext = "hello world!qwqeqweqwewq";

        // 签名
       */
/* String signStr = Sm2Sign(signature, Base64.decode(pk), Base64.decode(pri));
        System.out.println("signStr:"+signStr);
        // 验签
        boolean verify = Verify(signature, Base64.decode(signature), Base64.decode(pk));
        System.out.println(verify + "");*//*


    }

    public static String Sm2Sign(byte[] md, byte[] pk, byte[] privatekey) {
        BigInteger ecc_p = new BigInteger(ecc_param[0], 16);
        BigInteger ecc_a = new BigInteger(ecc_param[1], 16);
        BigInteger ecc_b = new BigInteger(ecc_param[2], 16);
        BigInteger ecc_n = new BigInteger(ecc_param[3], 16);
        BigInteger ecc_gx = new BigInteger(ecc_param[4], 16);
        BigInteger ecc_gy = new BigInteger(ecc_param[5], 16);

        ECFieldElement ecc_gx_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gx);
        ECFieldElement ecc_gy_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gy);

        ECCurve ecc_curve = new ECCurve.Fp(ecc_p, ecc_a, ecc_b);
        ECPoint ecc_point_g = new ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

        SM3Digest sm3 = new SM3Digest();

        byte[] pkX = SubByte(pk, 0, 32);
        byte[] pkY = SubByte(pk, 32, 32);

        byte[] z = sm3.getSM2Za(pkX, pkY, "1234567812345678".getBytes());

        sm3.update(z, 0, z.length);

        byte[] p = md;
        sm3.update(p, 0, p.length);

        byte[] hashData = new byte[32];
        sm3.doFinal(hashData, 0);

        // e
        BigInteger e = new BigInteger(1, hashData);
        // k
        BigInteger k = null;
        BigInteger r = null;
        BigInteger s = null;
        BigInteger userD = null;
        BigInteger x = new BigInteger(1, pkX);
        BigInteger pr = new BigInteger(1, privatekey);
        do {
            do {

                // ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)
                // keypair
                // .getPrivate();
                k = pr;
                // ecpriv.getD().toString(16);//私钥
                // kp = ecpub.getQ();//pk

                userD = pr;

                // r
                r = e.add(x);
                r = r.mod(ecc_n);
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(ecc_n));

            // (1 + dA)~-1
            BigInteger da_1 = userD.add(BigInteger.ONE);
            da_1 = da_1.modInverse(ecc_n);
            // s
            s = r.multiply(userD);
            s = k.subtract(s).mod(ecc_n);
            s = da_1.multiply(s).mod(ecc_n);
        } while (s.equals(BigInteger.ZERO));

        byte[] btRS = new byte[64];
        byte[] btR = r.toByteArray();
        byte[] btS = s.toByteArray();
        System.arraycopy(btR, btR.length - 32, btRS, 0, 32);
        System.arraycopy(btS, btS.length - 32, btRS, 32, 32);
        r.toByteArray();
        s.toByteArray();
        byte[] encode = Base64.encode(btRS);
        System.out.println("sssssss-------r" + r.toString(16));
        System.out.println("sssssss-------s" + s.toString(16));
        return new String(encode);
    }

    public static boolean Verify(byte[] msg, byte[] signData, byte[] certPK) {
        BigInteger ecc_p = new BigInteger(ecc_param[0], 16);
        BigInteger ecc_a = new BigInteger(ecc_param[1], 16);
        BigInteger ecc_b = new BigInteger(ecc_param[2], 16);
        BigInteger ecc_n = new BigInteger(ecc_param[3], 16);
        BigInteger ecc_gx = new BigInteger(ecc_param[4], 16);
        BigInteger ecc_gy = new BigInteger(ecc_param[5], 16);

        ECFieldElement ecc_gx_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gx);
        ECFieldElement ecc_gy_fieldelement = new ECFieldElement.Fp(ecc_p, ecc_gy);

        ECCurve ecc_curve = new ECCurve.Fp(ecc_p, ecc_a, ecc_b);
        ECPoint ecc_point_g = new ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

//        System.out.println("\n");
        // printHexString(signData);
//        System.out.println("\n");
        // printHexString(msg);
//        System.out.println("\n");
        byte[] pkX = SubByte(certPK, 0, 32);
//        System.out.println("\n");
        // printHexString(pkX);
        byte[] pkY = SubByte(certPK, 32, 32);
//        System.out.println("\n");
        // printHexString(pkY);
        BigInteger biX = new BigInteger(1, pkX);
        BigInteger biY = new BigInteger(1, pkY);
        ECFieldElement x = new ECFieldElement.Fp(ecc_p, biX);
        ECFieldElement y = new ECFieldElement.Fp(ecc_p, biY);
        ECPoint userKey = new ECPoint.Fp(ecc_curve, x, y);
        //
        SM3Digest sm3 = new SM3Digest();
        //第一步，组建数据ZA并计算HASH值
        byte[] sm2Za = sm3.getSM2Za(pkX, pkY, "1234567812345678".getBytes());
//        System.out.println("\n");
        // printHexString(sm2Za);
        sm3.update(sm2Za, 0, sm2Za.length);
//        System.out.println("\n");
        // printHexString(sm2Za);
//        System.out.println("\n");
        byte[] p = msg;
        sm3.update(p, 0, p.length);



//        printHexString(p);
//        System.out.println("\n");
        byte[] md = new byte[32];
        sm3.doFinal(md, 0);





//        printHexString(md);
        byte[] btRS = signData;
        byte[] btR = SubByte(btRS, 0, btRS.length / 2);
        byte[] btS = SubByte(btRS, btR.length, btRS.length - btR.length);

        BigInteger r = new BigInteger(1, btR);
        BigInteger s = new BigInteger(1, btS);

        // e_
        BigInteger e = new BigInteger(1, md);

        // t
        BigInteger t = r.add(s).mod(ecc_n);

        if (t.equals(BigInteger.ZERO))
            return false;

        // x1y1
        ECPoint x1y1 = ecc_point_g.multiply(s);
        x1y1 = x1y1.add(userKey.multiply(t));

        // R
        BigInteger R = e.add(x1y1.getX().toBigInteger()).mod(ecc_n);

        return r.equals(R);

    }


    public static byte[] getSignature(X509CertificateStructure cert)throws Exception
    {
        DERBitString derBitString = cert.getSignature();
        return derBitString.getBytes();
    }
    public static void setSignatureParameters(Signature var0, ASN1Encodable var1) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if(var1 != null */
/*&& !derNull.equals(var1)*//*
) {
            AlgorithmParameters var2 = AlgorithmParameters.getInstance(var0.getAlgorithm(), var0.getProvider());

            try {
                var2.init(var1.toASN1Primitive().getEncoded());
            } catch (IOException var5) {
                throw new SignatureException("IOException decoding parameters: " + var5.getMessage());
            }

            if(var0.getAlgorithm().endsWith("MGF1")) {
                try {
                    var0.setParameter(var2.getParameterSpec(PSSParameterSpec.class));
                } catch (GeneralSecurityException var4) {
                    throw new SignatureException("Exception extracting parameters: " + var4.getMessage());
                }
            }
        }

    }

    private boolean isAlgIdEqual(AlgorithmIdentifier var1, AlgorithmIdentifier var2) {
        return !var1.getAlgorithm().equals(var2.getAlgorithm())?false:(var1.getParameters() == null?var2.getParameters() == null || var2.getParameters().equals(DERNull.INSTANCE):(var2.getParameters() == null?var1.getParameters() == null || var1.getParameters().equals(DERNull.INSTANCE):var1.getParameters().equals(var2.getParameters())));
    }
  */
/*  public void verity(PublicKey publicKey, Signature signature, Certificate certificate) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if(!this.isAlgIdEqual(certificate.getSignatureAlgorithm(), certificate.getTBSCertificate().getSignature())) {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        } else {
            ASN1Encodable var3 = certificate.getSignatureAlgorithm().getParameters();
            setSignatureParameters(signature, var3);
            signature.initVerify(publicKey);
            signature.update(certificate.getTBSCertificate());
            if(!signature.verify(certificate.getSignature())) {
                throw new SignatureException("certificate does not verify with supplied key");
            }
        }
    }*//*


    public static byte[] getPubKey(X509CertificateStructure cert)throws Exception{
        SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
        DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
        byte[] publicKey = publicKeyData.getEncoded();
        byte[] encodedPublicKey = publicKey;
        byte[] eP = new byte[64];
        System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);
        return eP;
    }

    public static X509CertificateStructure getX509CertificateStructure(File file)throws Exception
    {
        InputStream inStream = new FileInputStream(file);
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try{
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }



    public void checkValidity(X509CertificateStructure certificateStructure) throws CertificateExpiredException, CertificateNotYetValidException {
        Date date = new Date();
        if(date.getTime() > certificateStructure.getEndDate().getDate().getTime()) {
            throw new CertificateExpiredException("certificate expired on " + certificateStructure.getEndDate().getTime());
        } else if(date.getTime() < certificateStructure.getStartDate().getDate().getTime()) {
            throw new CertificateNotYetValidException("certificate not valid till " + certificateStructure.getStartDate().getTime());
        }
    }

    public static void getX509KeyStructure(File file)throws Exception
    {
        InputStream inStream = new FileInputStream(file);
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try{
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);

        }
        catch (Exception e){
            e.printStackTrace();
        }
    }



    */
/*public static X509Certificate get_x509_certificate(File cerFile){
        CertificateFactory certificatefactory = null;
        try {
            certificatefactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
//            logger.error(e.getMessage(),e);
        }
        FileInputStream cerIs = null;
        X509Certificate cert = null;
        try {
            cerIs = new FileInputStream(cerFile);
            cert = (X509Certificate) certificatefactory.generateCertificate(cerIs);
        } catch (Exception e) {
//            logger.error(e.getMessage(),e);
        }finally {
            try {
                cerIs.close();
            } catch (IOException e) {
//                logger.error(e.getMessage(),e);
            }
        }
        return cert;
    }*//*


    public static  X509CertificateStructure get_x509_certificate(File cerFile) {
        try{
            InputStream inStream = new FileInputStream(cerFile);
            ASN1InputStream aIn = new ASN1InputStream(inStream);
            ASN1Sequence seq  = (ASN1Sequence) aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            return null;
        }
    }

    public static PKCS10CertificationRequest getPKCS10CertificationRequest(File file)throws Exception{
        byte[] b64Encoded = readFiletoBuffer(file);
        byte[] buffer;
        try {
            String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
            String endKey = "-----END CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        } catch (IOException e) {
            e.printStackTrace();
            String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
            String endKey = "-----END NEW CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        }
        PKCS10CertificationRequest pkcs10 = createCertificate(buffer);
        return pkcs10;
    }

    public static PKCS10CertificationRequest getPKCS10CertificationRequest(byte[] b64Encoded)throws Exception{
        byte[] buffer;
        try {
            String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
            String endKey = "-----END CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        } catch (IOException e) {
            e.printStackTrace();
            String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
            String endKey = "-----END NEW CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        }
        PKCS10CertificationRequest pkcs10 = createCertificate(buffer);
        return pkcs10;
    }

    */
/**
     * Helpfunction to read a file to a byte array.
     *
     *@param file filename of file.
     *@return byte[] containing the contents of the file.
     *@exception IOException if the file does not exist or cannot be read.
     **//*

    public static byte[] readFiletoBuffer(File file) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        InputStream in = new FileInputStream(file);
        int len = 0;
        byte buf[] = new byte[1024];
        while ((len = in.read(buf)) > 0)
            os.write(buf, 0, len);
        in.close();
        os.close();
        return os.toByteArray();
    }


    */
/**
     *
     * @param inbuf
     * @param beginKey
     * @param endKey
     * @return
     * @throws IOException
     *//*

    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)throws IOException {
        ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        PrintStream opstr = new PrintStream(ostr);
        String temp;
        while ((temp = bufRdr.readLine()) != null &&
                !temp.equals(beginKey))
            continue;
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
        while ((temp = bufRdr.readLine()) != null &&
                !temp.equals(endKey))
            opstr.print(temp);
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + endKey + " boundary");
        opstr.close();

        byte[] bytes = Base64.decode(ostr.toByteArray());

        return bytes;
    }


    */
/**
     *
     * @param pkcs10req
     * @return
     * @throws IOException
     *//*

    public static PKCS10CertificationRequest createCertificate(byte[] pkcs10req) throws IOException {
        */
/*DERObject derobj  = new DERInputStream(new ByteArrayInputStream(pkcs10req)).readObject();
        DERConstructedSequence seq = (DERConstructedSequence)derobj;
        PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(seq);
        return pkcs10;*//*


//        pkcs10 = new JcaPKCS10CertificationRequest(p10msg);

        return new PKCS10CertificationRequest(pkcs10req);
    }
}
*/
