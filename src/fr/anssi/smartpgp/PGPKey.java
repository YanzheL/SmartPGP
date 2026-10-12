/*
  SmartPGP : JavaCard implementation of OpenPGP card v3 specification
  https://github.com/ANSSI-FR/SmartPGP
  Copyright (C) 2016 ANSSI

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package fr.anssi.smartpgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacardx.crypto.Cipher;

import org.suut.javacard.pki.curve25519.Curve25519KeyAgreement;
import org.suut.javacard.pki.curve25519.Curve25519Signature;
import org.suut.javacard.pki.curve25519.Curve25519Key;
import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;

public final class PGPKey {

    protected final Fingerprint fingerprint;

    protected final byte[] generation_date;

    protected final byte[] certificate;
    protected short certificate_length;

    protected final byte[] attributes;
    protected byte attributes_length;

    protected final boolean is_secure_messaging_key;

    private boolean has_been_generated;
    private byte keyIndex;

    private KeyPair keys;
    private Curve25519PublicKey cv25519public;
    private Curve25519PrivateKey cv25519private;
    boolean isEd25519 = false;
    boolean isX25519 = false;

    protected PGPKey(final boolean for_secure_messaging, byte keyIndex) {

        is_secure_messaging_key = for_secure_messaging;

        if(is_secure_messaging_key) {
            fingerprint = null;
            generation_date = null;
        } else {
            fingerprint = new Fingerprint();
            generation_date = new byte[Constants.GENERATION_DATE_SIZE];
        }

        certificate = new byte[Constants.cardholderCertificateMaxLength()];
        certificate_length = 0;

        attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];
        attributes_length = 0;

        this.keyIndex = keyIndex;
        reset(true);
    }

    private final void resetKeys(final boolean isRegistering) {
        if (isX25519 || isEd25519) {
            cv25519private.clearKey();
            cv25519private = null;
            cv25519public.clearKey();
            cv25519public = null;
            isX25519 = false;
            isEd25519 = false;
            if(!isRegistering) {
                Common.requestDeletion();
            }
        } else {
            if(keys != null) {
                keys.getPrivate().clearKey();
                keys.getPublic().clearKey();
                keys = null;
            }
            if(!isRegistering) {
                Common.requestDeletion();
            }
        }

        if(certificate_length > 0) {
            certificate_length = (short)0;
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }

        if(!is_secure_messaging_key) {
            fingerprint.reset(isRegistering);

            Util.arrayFillNonAtomic(generation_date, (short)0, Constants.GENERATION_DATE_SIZE, (byte)0);
        }

        has_been_generated = false;
    }

    protected final void reset(final boolean isRegistering) {
        resetKeys(isRegistering);

        Common.beginTransaction(isRegistering);
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
            attributes_length = (byte)0;
        }

        if(is_secure_messaging_key) {
            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
        } else {
            switch (keyIndex) {
            case Persistent.PGP_KEYS_OFFSET_SIG:
                Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_SIGN_DEFAULT, (short)0,
                    attributes, (short)0,
                    (short)Constants.ALGORITHM_ATTRIBUTES_SIGN_DEFAULT.length);
                attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_SIGN_DEFAULT.length;
                break;

            case Persistent.PGP_KEYS_OFFSET_DEC:
                Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_ENCR_DEFAULT, (short)0,
                    attributes, (short)0,
                    (short)Constants.ALGORITHM_ATTRIBUTES_ENCR_DEFAULT.length);
                attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_ENCR_DEFAULT.length;
                break;

            case Persistent.PGP_KEYS_OFFSET_AUT:
                Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_AUTH_DEFAULT, (short)0,
                    attributes, (short)0,
                    (short)Constants.ALGORITHM_ATTRIBUTES_AUTH_DEFAULT.length);
                attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_AUTH_DEFAULT.length;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        Common.commitTransaction(isRegistering);
    }

    protected final boolean isInitialized() {
        if (isX25519 || isEd25519) {
            return (cv25519public != null) && (cv25519public.isInitialized()) && (cv25519private != null) && (cv25519private.isInitialized());
        } else {
            return (keys != null) && keys.getPrivate().isInitialized() && keys.getPublic().isInitialized();
        }
    }

    protected final byte keyInformation() {
        byte res = (byte)0x0;
        if(isInitialized()) {
            if(has_been_generated) {
                res = (byte)0x01;
            } else {
                res = (byte)0x02;
            }
        }
        return res;
    }

    protected final void setCertificate(final byte[] buf, final short off, final short len) {
        if((len < 0) ||
           (len > Constants.cardholderCertificateMaxLength())) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        JCSystem.beginTransaction();
        if(certificate_length > 0) {
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, certificate, (short)0, len);
        certificate_length = len;
        JCSystem.commitTransaction();
    }

    protected final void setGenerationDate(final byte[] buf, final short off, final short len) {
        if(len != Constants.GENERATION_DATE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }
        Util.arrayCopy(buf, off, generation_date, (short)0, len);
    }

    protected final void setAttributes(final ECCurves ec,
                                       final byte[] buf, final short off, short len) {
        if((len < Constants.ALGORITHM_ATTRIBUTES_MIN_LENGTH) ||
           (len > Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        switch(buf[off]) {
        case 0x01:
            if((len != 6) || is_secure_messaging_key) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if((Util.getShort(buf, (short)(off + 1)) < 2048) ||
               (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
               (buf[(short)(off + 5)] < 0) || (buf[(short)(off + 5)] > 3)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            break;

        case 0x12:
        case 0x13:
        case 0x16:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if(buf[(short)(len - 1)] != (byte)0xff) {
                buf[len] = (byte)0xff;
                len++;
            }
            final ECParams params = ec.findByOid(buf, (short)(off + 1), (byte)(len - 1 - 1));
            if(params == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if((buf[0] != 0x12) && is_secure_messaging_key) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        JCSystem.beginTransaction();
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, attributes, (short)0, len);
        attributes_length = (byte)len;
        JCSystem.commitTransaction();
    }


    protected final boolean isRsa() {
        return (attributes[0] == 1);
    }

    protected final short rsaModulusBitSize() {
        return Util.getShort(attributes, (short)1);
    }

    protected final short rsaExponentBitSize() {
        return Util.getShort(attributes, (short)3);
    }

    protected final boolean isEc() {
        return ((attributes[0] == (byte)0x12) ||
                (attributes[0] == (byte)0x13) ||
                (attributes[0] == (byte)0x16));
    }

    protected final boolean isCurve25519(final ECCurves ec) {
        final ECParams params = ecParams(ec);
        if(params != null) {
            return params.isCurve25519;
        }
        return false;
    }

    protected final ECParams ecParams(final ECCurves ec) {
        final byte delta = (attributes[(short)(attributes_length - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
        return ec.findByOid(attributes, (short)1, (byte)(attributes_length - 1 - delta));
    }


    private final KeyPair generateRSA() {
        PrivateKey priv = (PrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, rsaModulusBitSize(), false);
        RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rsaModulusBitSize(), false);

        if((priv == null) || (pub == null)) {
            priv = null;
            pub = null;
            Common.requestDeletion();
            return null;
        }

        pub.setExponent(Constants.RSA_EXPONENT, (short)0, (byte)Constants.RSA_EXPONENT.length);

        return new KeyPair(pub, priv);
    }


    private final KeyPair generateEC(final ECCurves ec, ECParams params) {
        ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, params.nb_bits, false);
        ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, params.nb_bits, false);

        if((priv == null) || (pub == null)) {
            params = null;
            priv = null;
            pub = null;
            Common.requestDeletion();
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        return new KeyPair(pub, priv);
    }


    protected final void generate(final ECCurves ec) {
        resetKeys(false);

        if(isRsa()) {
            keys = generateRSA();
        } else if(isEc()) {
            ECParams params = ecParams(ec);
            if (isCurve25519(ec)) {
                if (params.matchOid(ECConstants.x25519_oid, (short)0, (short)ECConstants.x25519_oid.length)) {
                    cv25519public = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
                    cv25519private = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
                    isX25519 = true;
                } else if (params.matchOid(ECConstants.ed25519_oid, (short)0, (short)ECConstants.ed25519_oid.length)) {
                    cv25519public = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
                    cv25519private = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
                    isEd25519 = true;
                } else {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Curve25519KeyBuilder.genKeyPair(cv25519private, cv25519public);
                has_been_generated = true;
                return;
            } else {
                keys = generateEC(ec, params);
            }
        }

        if(keys == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        keys.genKeyPair();

        if(!keys.getPublic().isInitialized() || !keys.getPrivate().isInitialized()) {
            keys = null;
            Common.requestDeletion();
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        has_been_generated = true;
    }


    private final KeyPair importRSAKey(final byte[] buf,
                                       final short boff, final short len,
                                       final byte tag_count, final byte[] tag_val, final short[] tag_len) {

        final short attr_modulus_bit_size = rsaModulusBitSize();
        final short attr_modulus_byte_size = Common.bitsToBytes(attr_modulus_bit_size);

        final RSAPrivateCrtKey priv = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, attr_modulus_bit_size, false);
        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, attr_modulus_bit_size, false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x91:
                if(tag_len[i] != Common.bitsToBytes(rsaExponentBitSize())) {
                    return null;
                }
                pub.setExponent(buf, off, tag_len[i]);
                break;

            case (byte)0x92:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setP(buf, off, tag_len[i]);
                break;

            case (byte)0x93:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setQ(buf, off, tag_len[i]);
                break;

            case (byte)0x94:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setPQ(buf, off, tag_len[i]);
                break;

            case (byte)0x95:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDP1(buf, off, tag_len[i]);
                break;

            case (byte)0x96:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDQ1(buf, off, tag_len[i]);
                break;

            case (byte)0x97:
                if(tag_len[i] != attr_modulus_byte_size) {
                    return null;
                }
                pub.setModulus(buf, off, tag_len[i]);
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if(!priv.isInitialized() || !pub.isInitialized()) {
            return null;
        }

        return new KeyPair(pub, priv);
    }

    private final KeyPair importECKey(final ECCurves ec,
                                      final byte[] buf,
                                      final short boff, final short len,
                                      final byte tag_count, final byte[] tag_val, final short[] tag_len) {
        final ECParams params = ecParams(ec);
        ECPrivateKey priv = null;
        ECPublicKey pub = null;

        if (isCurve25519(ec)) {
            if (params.matchOid(ECConstants.x25519_oid, (short)0, (short)ECConstants.x25519_oid.length)) {
                cv25519public = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
                cv25519private = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
                isX25519 = true;
            } else if (params.matchOid(ECConstants.ed25519_oid, (short)0, (short)ECConstants.ed25519_oid.length)) {
                cv25519public = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
                cv25519private = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
                isEd25519 = true;
            } else {
                return null;
            }
        } else {
            priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                                        params.nb_bits,
                                                                        false);
            pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                                                                     params.nb_bits,
                                                                     false);
        }

        if (isX25519 || isEd25519) {
            if ((cv25519public == null) || (cv25519private == null)) {
                return null;
            }
        } else {
            if((priv == null) || (pub == null)) {
                return null;
            }

            params.setParams(priv);
            params.setParams(pub);
        }

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x92:
                if (isX25519 || isEd25519) {
                    if(tag_len[i] != 32) {
                        return null;
                    }
                    cv25519private.setS(buf, off, tag_len[i]);
                } else {
                    if(tag_len[i] > Common.bitsToBytes(params.nb_bits)) {
                        return null;
                    }
                    priv.setS(buf, off, tag_len[i]);
                }
                break;

            case (byte)0x99:
                if (isX25519 || isEd25519) {
                    if((tag_len[i] == (short)(Common.bitsToBytes(params.nb_bits) + 1) && (buf[off] == (byte)0x40))) {
                        off +=(short)1;
                        tag_len[i] -= (short)1;
                    }
                    if (tag_len[i] != 32) {
                        return null;
                    }
                    cv25519public.setW(buf, off, tag_len[i]);
                } else {
                    if(tag_len[i] > (short)(2 * Common.bitsToBytes(params.nb_bits) + 1)) {
                        return null;
                    }
                    if(((byte)(tag_len[i] - 1) & (byte)0x1) != 0) {
                        return null;
                    }
                    pub.setW(buf, off, tag_len[i]);
                }
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if (isX25519 || isEd25519) {
            return null;
        } else {
            if(!priv.isInitialized() || !pub.isInitialized()) {
                return null;
            }
            return new KeyPair(pub, priv);
        }
    }

    protected final void importKey(final ECCurves ec,
                                   final byte[] buf, final short boff, final short len) {
        short off = boff;

        short template_len = 0;
        short template_off = 0;

        short data_len = 0;
        short data_off = 0;

        byte data_tag_count = 0;
        byte[] data_tag_val = new byte[7];
        short[] data_tag_len = new short[7];

        while((short)(len - (short)(off - boff)) > 2) {
            switch(Util.getShort(buf, off)) {

            case (short)0x7f48:
                off += 2;
                template_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                template_off = off;

                if(template_len > (short)(len - (short)(off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                while((short)(template_len - (short)(off - template_off)) > 1) {
                    if((buf[off] < (byte)0x91) ||
                       (buf[off] > (byte)0x99)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    if(data_tag_count >= data_tag_val.length) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    data_tag_val[data_tag_count] = buf[off];
                    ++off;

                    data_tag_len[data_tag_count] = Common.readLength(buf, off, (short)(template_len - (short)(off - template_off)));
                    off = Common.skipLength(buf, off, (short)(template_len - (short)(off - template_off)));

                    ++data_tag_count;
                }
                break;

            case (short)0x5f48:
                off += 2;
                data_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                data_off = off;

                if(data_len > (short)(len - (short)(off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                off += data_len;

                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
        }

        resetKeys(false);

        if(isRsa()) {
            keys = importRSAKey(buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
        } else if(isEc()) {
            keys = importECKey(ec, buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
            if (isX25519 || isEd25519) {
                if (!cv25519public.isInitialized() || !cv25519private.isInitialized()) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                return;
            }
        }

        if(keys == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        if(!keys.getPrivate().isInitialized() || !keys.getPublic().isInitialized()) {
            keys = null;
            Common.requestDeletion();
            return;
        }
    }


    protected final short writePublicKeyDo(final byte[] buf, short off) {
        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        off = Util.setShort(buf, off, (short)0x7f49);

        if(isRsa()) {
            final RSAPublicKey rsapub = (RSAPublicKey)keys.getPublic();
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());
            final short exponent_size = Common.bitsToBytes(rsaExponentBitSize());

            final short mlensize = (short)((modulus_size > (short)0xff) ? 3 : 2);

            final short flen =
                (short)(1 + mlensize + modulus_size +
                        1 + 1 + exponent_size);

            off = Common.writeLength(buf, off, flen);

            buf[off++] = (byte)0x81;
            off = Common.writeLength(buf, off, modulus_size);
            off += rsapub.getModulus(buf, off);

            buf[off++] = (byte)0x82;
            off = Common.writeLength(buf, off, exponent_size);
            off += rsapub.getExponent(buf, off);

            return off;
        } else if(isEc()) {
            ECPublicKey ecpub = null;
            short rsize = 0;
            short qsize = 0;
            if (isX25519 || isEd25519) {
                rsize = 32;
                qsize = 32;
            } else {
                ecpub = (ECPublicKey)keys.getPublic();
                qsize = (short)(1 + 2 * (short)((ecpub.getSize() / 8) + (((ecpub.getSize() % 8) == 0) ? 0 : 1)));
                rsize = qsize;
            }

            if(rsize > 0x7f) {
                rsize = (short)(rsize + 2);
            } else {
                rsize = (short)(rsize + 1);
            }

            rsize += (short)1;

            off = Common.writeLength(buf, off, rsize);

            buf[off++] = (byte)0x86;

            off = Common.writeLength(buf, off, qsize);

            if (isX25519 || isEd25519) {
                off += cv25519public.getW(buf, off);
            } else {
                off += ecpub.getW(buf, off);
            }

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return off;
    }




    protected final short sign(final Common common,
                               final byte[] buf, final short lc,
                               final boolean forAuth) {
        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        PrivateKey priv = null;

        short off = 0;

        byte[] sha_header = null;

        if(isRsa()) {
            priv = keys.getPrivate();
            if(!forAuth) {
                if(lc == (short)(2 + Constants.DSI_SHA256_HEADER[1])) {
                    sha_header = Constants.DSI_SHA256_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA384_HEADER[1])) {
                    sha_header = Constants.DSI_SHA384_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA512_HEADER[1])) {
                    sha_header = Constants.DSI_SHA512_HEADER;
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }

                if(Util.arrayCompare(buf, (short)0, sha_header, (short)0, (byte)sha_header.length) != 0) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }
            }

            if(lc > (short)(((short)(Common.bitsToBytes(rsaModulusBitSize()) * 2)) / 5)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            common.cipher_rsa_pkcs1.init(priv, Cipher.MODE_ENCRYPT);

            off = common.cipher_rsa_pkcs1.doFinal(buf, (short)0, lc,
                                                  buf, lc);

            return Util.arrayCopyNonAtomic(buf, lc,
                                           buf, (short)0,
                                           off);

        } else if(isEc()) {
            short sig_size = 0;
            if (isEd25519) {
                Curve25519Signature sig = common.sign_eddsa;

                sig_size = sig.sign(cv25519private, buf, (short)0, lc, buf, lc);
                off = Util.arrayCopyNonAtomic(buf, lc,
                                              buf, (short)0, sig_size);
                return off;
            } else if (isX25519) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            } else {
                priv = keys.getPrivate();
                Signature sig;

                if(lc == MessageDigest.LENGTH_SHA) {
                    sig = common.sign_ecdsa_sha;
                } else if(lc == MessageDigest.LENGTH_SHA_224) {
                    sig = common.sign_ecdsa_sha_224;
                } else if(lc == MessageDigest.LENGTH_SHA_256) {
                    sig = common.sign_ecdsa_sha_256;
                } else if(lc == MessageDigest.LENGTH_SHA_384) {
                    sig = common.sign_ecdsa_sha_384;
                } else if(lc == MessageDigest.LENGTH_SHA_512) {
                    sig = common.sign_ecdsa_sha_512;
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }

                sig.init(priv, Signature.MODE_SIGN);

                sig_size = sig.signPreComputedHash(buf, (short)0, lc,
                                                               buf, lc);
            }

            off = (short)(lc + 1);
            if((buf[off] & (byte)0x80) != (byte)0) {
                ++off;
            }
            ++off;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short r_size = Util.makeShort((byte)0, buf[off++]);
            final short r_off = off;

            off += r_size;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short s_size = Util.makeShort((byte)0, buf[off++]);
            final short s_off = off;

            off = (short)(lc + sig_size);

            if(r_size < s_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(s_size - r_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, r_off,
                                          buf, off, r_size);

            if(s_size < r_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(r_size - s_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, s_off,
                                          buf, off, s_size);

            off = Util.arrayCopyNonAtomic(buf, (short)(lc + sig_size),
                                          buf, (short)0,
                                          (short)(off - lc - sig_size));

            Util.arrayFillNonAtomic(buf, off, (short)(lc + sig_size - off), (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }


    protected final short decipher(final Common common, final ECCurves ec,
                                   final byte[] buf, final short lc) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        PrivateKey priv = null;

        short off = 0;

        if(isRsa()) {
            priv = keys.getPrivate();
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());

            if(lc != (short)(modulus_size + 1)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[0] != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            common.cipher_rsa_pkcs1.init(priv, Cipher.MODE_DECRYPT);

            final short len = common.cipher_rsa_pkcs1.doFinal(buf, (short)1, (short)(lc - 1),
                                                              buf, lc);

            off = Util.arrayCopyNonAtomic(buf, lc,
                                          buf, (short)0,
                                          len);

            Util.arrayFillNonAtomic(buf, lc, len, (byte)0);

            return off;

        } else if(isEc()) {

            final ECParams params = ecParams(ec);
            short elc = (short)7;
            short factor = 2;
            if (isX25519) {
                factor = (short)1;
            } else if (isEd25519) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            } else if (params.nb_bits >= (short)512) {
                elc = (short)11;
            } else {
                elc = (short)8;
            }

            if(lc != (short)(elc + (short)(factor * Common.bitsToBytes(params.nb_bits)))) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if(buf[off] != (byte)0xA6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(Util.getShort(buf, off) != (short)(0x7f49)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            off += 2;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[off] != (byte)0x86) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if (isX25519) {
                common.ka_xdh_pub.setW(buf, off, (short)(lc - off));
                final short len = common.ka_xdh.keyExchange(cv25519private, common.ka_xdh_pub, buf, lc);
                off = Util.arrayCopyNonAtomic(buf, lc, buf, (short)0, len);
            } else {
                priv = keys.getPrivate();
                common.ka_ec_dh.init(priv);
                final short len  = common.ka_ec_dh.generateSecret(buf, off, (short)(lc - off),
                                                                  buf, lc);
                off = Util.arrayCopyNonAtomic(buf, lc,
                                              buf, (short)0,
                                              len);

                Util.arrayFillNonAtomic(buf, lc, len, (byte)0);
            }

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    protected final void initKeyAgreement(final KeyAgreement ka) { // only used for SM
        if(!isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        ka.init(keys.getPrivate());
    }

}
