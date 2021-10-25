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
 * (c) Copyright IBM Corp. 2018, 2021 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Optional;

import javax.crypto.*;
import javax.crypto.spec.*;

import sun.security.util.ArrayUtil;
import sun.security.util.ECUtil;
import sun.security.util.math.*;
import sun.security.ec.point.*;

import jdk.crypto.jniprovider.NativeCrypto;

public final class NativeECDHKeyAgreement extends KeyAgreementSpi {

    /* private key, if initialized */
    private ECPrivateKey privateKey;

    /* public key, non-null between doPhase() & generateSecret() only */
    private ECPublicKey publicKey;

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
        privateKey = (ECPrivateKey) ECKeyFactory.toECKey(key);
        publicKey = null;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException
                        ("Parameters not supported");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (privateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (publicKey != null) {
            throw new IllegalStateException("Phase already executed");
        }
        if (!lastPhase) {
            throw new IllegalStateException
                ("Only two party agreement supported, lastPhase must be true");
        }
        if (!(key instanceof ECPublicKey)) {
            throw new InvalidKeyException
                ("Key must be a PublicKey with algorithm EC");
        }

        this.publicKey = (ECPublicKey) key;

        ECParameterSpec params = publicKey.getParams();
        int keyLenBits = params.getCurve().getField().getFieldSize();
        secretLen = (keyLenBits + 7) >> 3;

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if ((privateKey == null) || (publicKey == null)) {
            throw new IllegalStateException("Not initialized correctly");
        }

        byte[] secret = new byte[secretLen];

        long nativePublicKey = publicKey.getNativePtr();
        long nativePrivateKey = privateKey.getNativePtr();
        if ((nativePublicKey < 0) || (nativePrivateKey < 0)) {
            throw new ProviderException("Could not convert keys to native format");
        } else if (nativeCrypto.ECDeriveKey(nativePublicKey, nativePrivateKey, secret, secretLen) < 0) {
            throw new ProviderException("Could not derive key");
        }

        return secret;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int
            offset) throws IllegalStateException, ShortBufferException {
        if (offset + secretLen > sharedSecret.length) {
            throw new ShortBufferException("Need " + secretLen
                + " bytes, only " + (sharedSecret.length - offset)
                + " available");
        }
        byte[] secret = engineGenerateSecret();
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
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
