/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import jdk.crypto.jniprovider.NativeCrypto;

public final class NativeECDHKeyAgreement extends KeyAgreementSpi {

    /* private key, if initialized */
    private ECPrivateKeyImpl privateKey;

    /* public key, non-null between doPhase() & generateSecret() only */
    private ECPublicKeyImpl publicKey;

    /* length of the secret to be derived */
    private int secretLen;

    private static final NativeCrypto nativeCrypto = NativeCrypto.getNativeCrypto();

    /**
     * Constructs a new NativeECDHKeyAgreement.
     */
    public NativeECDHKeyAgreement() {
    }

    @Override
    protected void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {
        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException
                        ("Key must be instance of PrivateKey");
        }
        this.privateKey = (ECPrivateKeyImpl) ECKeyFactory.toECKey(key);
        this.publicKey = null;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException
                        ("Parameters not supported");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (this.privateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (this.publicKey != null) {
            throw new IllegalStateException("Phase already executed");
        }
        if (!lastPhase) {
            throw new IllegalStateException
                ("Only two party agreement supported, lastPhase must be true");
        }
        if (!(key instanceof ECPublicKeyImpl)) {
            throw new InvalidKeyException
                ("Key must be a ECPublicKeyImpl");
        }

        this.publicKey = (ECPublicKeyImpl) key;

        ECParameterSpec params = this.publicKey.getParams();
        int keyLenBits = params.getCurve().getField().getFieldSize();
        this.secretLen = (keyLenBits + 7) >> 3;

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        byte[] secret = new byte[this.secretLen];
        try {
            engineGenerateSecret(secret, 0);
        } catch (ShortBufferException e) {
            /* should not happen */
        }
        return secret;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if ((offset + this.secretLen) > sharedSecret.length) {
            throw new ShortBufferException("Need " + this.secretLen
                + " bytes, only " + (sharedSecret.length - offset)
                + " available");
        }
        if ((this.privateKey == null) || (this.publicKey == null)) {
            throw new IllegalStateException("Not initialized correctly");
        }
        long nativePublicKey = this.publicKey.getNativePtr();
        long nativePrivateKey = this.privateKey.getNativePtr();
        if ((nativePublicKey < 0) || (nativePrivateKey < 0)) {
            throw new ProviderException("Could not convert keys to native format");
        }
        int ret;
        synchronized (this.privateKey) {
            ret = nativeCrypto.ECDeriveKey(nativePublicKey, nativePrivateKey, sharedSecret, offset, this.secretLen);
        }
        if (ret < 0) {
            throw new ProviderException("Could not derive key");
        }
        return this.secretLen;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }
        if (!(algorithm.equals("TlsPremasterSecret"))) {
            throw new NoSuchAlgorithmException
                ("Only supported for algorithm TlsPremasterSecret");
        }
        return new SecretKeySpec(engineGenerateSecret(), "TlsPremasterSecret");
    }
}
