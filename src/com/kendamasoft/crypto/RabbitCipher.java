package com.kendamasoft.crypto;

import java.util.Arrays;

/**
 * Rabbit stream cipher implementation.
 * @link http://tools.ietf.org/rfc/rfc4503.txt
 * Currently IV usage not implemented.
 *
 * Usage:
 *
 *  byte[] msg = "Hello World!".getBytes();
 *
 *  RabbitCipher cipher = new RabbitCipher();
 *  cipher.setupKey(key);
 *  cipher.crypt(msg);
 *
 *
 * Created by Nikita Timofeev on 20.04.15.
 */
public final class RabbitCipher {

    private final static int[] A = {
            0x4D34D34D, 0xD34D34D3,
            0x34D34D34, 0x4D34D34D,
            0xD34D34D3, 0x34D34D34,
            0x4D34D34D, 0xD34D34D3
    };
    private final int[] X = new int[8];
    private final int[] C = new int[8];
    private int b;

    private boolean ready = false;

    private final int[] G = new int[8];
    private final byte[] S = new byte[16];

    private static final int BLOCK_LENGTH = 16;

    /**
     * Original byte array used to return encrypted bytes
     * @param message (encrypted) message to be (de-)encrypted
     */
    public void crypt(byte[] message) {
        if(!ready) {
            throw new IllegalStateException("Key is not setup. You need to call setupKey() prior encrypting data.");
        }

        for(int i=0; i<message.length; i++) {
            if(i % BLOCK_LENGTH == 0) {
                nextBlock();
            }
            message[i] ^= S[i % BLOCK_LENGTH];
        }
    }

    /**
     * @param key 128 bit key (16 bytes)
     */
    public void setupKey(byte[] key) {
        assert key.length >= BLOCK_LENGTH;

        int[] K = new int[8];
        for(int i=0; i<8; i++) {
            K[i] = (key[2*i+1] << 8) | (key[2*i] & 0xff);
        }

        for(int i=0; i<8; i++) {
            if((i & 1) == 0) {
                X[i] = (K[(i+1) % 8] << 16) | (K[i]         & 0xFFFF);
                C[i] = (K[(i+4) % 8] << 16) | (K[(i+5) % 8] & 0xFFFF);
            } else {
                X[i] = (K[(i+5) % 8] << 16) | (K[(i+4) % 8] & 0xFFFF);
                C[i] = (K[i]         << 16) | (K[(i+1) % 8] & 0xFFFF);
            }
        }

        nextState();
        nextState();
        nextState();
        nextState();

        for(int i=0; i<8; i++) {
            C[i] = C[i] ^ X[(i+4) % 8];
        }

        ready = true;
    }

    public void setupIV(byte[] IV) {
        // TODO
        /*
        C0 = C0 ^ IV[31..0]
        C1 = C1 ^ (IV[63..48] || IV[31..16])
        C2 = C2 ^ IV[63..32]
        C3 = C3 ^ (IV[47..32] || IV[15..0])
        C4 = C4 ^ IV[31..0]
        C5 = C5 ^ (IV[63..48] || IV[31..16])
        C6 = C6 ^ IV[63..32]
        C7 = C7 ^ (IV[47..32] || IV[15..0])
        */
    }

    /**
     * After reset key must be setup again
     */
    public void reset() {
        Arrays.fill(X, 0);
        Arrays.fill(C, 0);
        Arrays.fill(S, (byte)0);
        b = 0;
        ready = false;
    }

    /**
     * Package private access for tests
     */
    byte[] nextBlock() {
        nextState();

        int x = X[0] ^ X[5] >>> 16;
        S[0] = (byte) x;
        S[1] = (byte)(x >> 8);

        x = X[0] >>> 16 ^ X[3];
        S[2] = (byte) x;
        S[3] = (byte)(x >> 8);

        x = X[2] ^ X[7] >>> 16;
        S[4] = (byte) x;
        S[5] = (byte)(x >> 8);

        x = X[2] >> 16 ^ X[5];
        S[6] = (byte) x;
        S[7] = (byte)(x >> 8);

        x = X[4] ^ X[1] >>> 16;
        S[8] = (byte) x;
        S[9] = (byte)(x >> 8);

        x = X[4] >>> 16 ^ X[7];
        S[10] = (byte) x;
        S[11] = (byte)(x >> 8);

        x = X[6] ^ X[3] >>> 16;
        S[12] = (byte) x;
        S[13] = (byte)(x >> 8);

        x = X[6] >>> 16 ^ X[1];
        S[14] = (byte) x;
        S[15] = (byte)(x >> 8);

        return S;
    }

    private void nextState() {
        long temp;
        for(int i=0; i<8; i++) {
            temp = (C[i] & 0xFFFFFFFFl) + (A[i] & 0xFFFFFFFFl) + b;
            b = (int) (temp >>> 32);
            C[i] = (int) (temp & 0xFFFFFFFFl);
        }

        for(int i=0; i<8; i++) {
            G[i] = g(X[i], C[i]);
        }

        X[0] = G[0] + rotate(G[7], 16) + rotate(G[6], 16);
        X[1] = G[1] + rotate(G[0],  8) + G[7];
        X[2] = G[2] + rotate(G[1], 16) + rotate(G[0], 16);
        X[3] = G[3] + rotate(G[2],  8) + G[1];
        X[4] = G[4] + rotate(G[3], 16) + rotate(G[2], 16);
        X[5] = G[5] + rotate(G[4],  8) + G[3];
        X[6] = G[6] + rotate(G[5], 16) + rotate(G[4], 16);
        X[7] = G[7] + rotate(G[6],  8) + G[5];
    }

    private int g(int u, int v) {
        long square = u + v & 0xFFFFFFFFl;
        square *= square;
        return (int)(square ^ square >>> 32);
    }

    /**
     * Left circular bit shift
     * @param value
     * @param shift
     * @return
     */
    static private int rotate(int value, int shift) {
        return value << shift | value >>> (32 - shift);
    }
}
