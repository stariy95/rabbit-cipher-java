package com.kendamasoft.crypto;

import org.hamcrest.core.IsEqual;
import org.hamcrest.core.IsNot;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RabbitCypherTest {

    RabbitCypher cypher;

    /**
     * Conformance testing
     * @link http://tools.ietf.org/rfc/rfc4503.txt
     *
     * @throws Exception
     */
    @Test
    public void testSetupKey1() throws Exception {
        byte[] key = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] S0 = os2ip((byte)0xB1, (byte)0x57, (byte)0x54, (byte)0xF0, (byte)0x36, (byte)0xA5, (byte)0xD6, (byte)0xEC, (byte)0xF5, (byte)0x6B, (byte)0x45, (byte)0x26, (byte)0x1C, (byte)0x4A, (byte)0xF7, (byte)0x02);
        byte[] S1 = os2ip((byte)0x88, (byte)0xE8, (byte)0xD8, (byte)0x15, (byte)0xC5, (byte)0x9C, (byte)0x0C, (byte)0x39, (byte)0x7B, (byte)0x69, (byte)0x6C, (byte)0x47, (byte)0x89, (byte)0xC6, (byte)0x8A, (byte)0xA7);
        byte[] S2 = os2ip((byte)0xF4, (byte)0x16, (byte)0xA1, (byte)0xC3, (byte)0x70, (byte)0x0C, (byte)0xD4, (byte)0x51, (byte)0xDA, (byte)0x68, (byte)0xD1, (byte)0x88, (byte)0x16, (byte)0x73, (byte)0xD6, (byte)0x96);

        cypher.setupKey(key);

        byte[] s = cypher.nextBlock();
        Assert.assertArrayEquals(S0, s);

        s = cypher.nextBlock();
        Assert.assertArrayEquals(S1, s);

        s = cypher.nextBlock();
        Assert.assertArrayEquals(S2, s);
    }

    /**
     * Conformance testing
     * @link http://tools.ietf.org/rfc/rfc4503.txt
     *
     * @throws Exception
     */
    @Test
    public void testSetupKey2() throws Exception {
        byte[] key = os2ip((byte)0x91, (byte)0x28, (byte)0x13, (byte)0x29, (byte)0x2E, (byte)0x3D, (byte)0x36, (byte)0xFE, (byte)0x3B, (byte)0xFC, (byte)0x62, (byte)0xF1, (byte)0xDC, (byte)0x51, (byte)0xC3, (byte)0xAC);
        byte[] S0 = os2ip((byte)0x3D, (byte)0x2D, (byte)0xF3, (byte)0xC8, (byte)0x3E, (byte)0xF6, (byte)0x27, (byte)0xA1, (byte)0xE9, (byte)0x7F, (byte)0xC3, (byte)0x84, (byte)0x87, (byte)0xE2, (byte)0x51, (byte)0x9C);
        byte[] S1 = os2ip((byte)0xF5, (byte)0x76, (byte)0xCD, (byte)0x61, (byte)0xF4, (byte)0x40, (byte)0x5B, (byte)0x88, (byte)0x96, (byte)0xBF, (byte)0x53, (byte)0xAA, (byte)0x85, (byte)0x54, (byte)0xFC, (byte)0x19);
        byte[] S2 = os2ip((byte)0xE5, (byte)0x54, (byte)0x74, (byte)0x73, (byte)0xFB, (byte)0xDB, (byte)0x43, (byte)0x50, (byte)0x8A, (byte)0xE5, (byte)0x3B, (byte)0x20, (byte)0x20, (byte)0x4D, (byte)0x4C, (byte)0x5E);

        cypher.setupKey(key);

        byte[] s = cypher.nextBlock();
        Assert.assertArrayEquals(S0, s);

        s = cypher.nextBlock();
        Assert.assertArrayEquals(S1, s);

        s = cypher.nextBlock();
        Assert.assertArrayEquals(S2, s);
    }

    @Test
    public void testCrypt() throws Exception {
        byte[] key = os2ip((byte)0x91, (byte)0x28, (byte)0x13, (byte)0x29, (byte)0x2E, (byte)0x3D, (byte)0x36, (byte)0xFE, (byte)0x3B, (byte)0xFC, (byte)0x62, (byte)0xF1, (byte)0xDC, (byte)0x51, (byte)0xC3, (byte)0xAC);
        byte[] key2 = os2ip((byte)0x92, (byte)0x28, (byte)0x13, (byte)0x29, (byte)0x2E, (byte)0x3D, (byte)0x36, (byte)0xFE, (byte)0x3B, (byte)0xFC, (byte)0x62, (byte)0xF1, (byte)0xDC, (byte)0x51, (byte)0xC3, (byte)0xAC);
        byte[] msg = {1, 3, 5, 7, 9, 11, 13, 17, 27, 31, 51};
        byte[] msg2 = {1, 3, 5, 7, 9, 11, 13, 17, 27, 31, 51};
        byte[] msgOriginal = msg.clone();

        cypher.setupKey(key);
        byte[] encrypted = msg.clone();
        cypher.crypt(encrypted);
        byte[] encrypted_next = msg.clone();
        cypher.crypt(encrypted_next);

        Assert.assertEquals(msgOriginal.length, encrypted.length);
        Assert.assertThat(msgOriginal, IsNot.not(IsEqual.equalTo(encrypted)));
        Assert.assertThat(encrypted, IsNot.not(IsEqual.equalTo(encrypted_next)));

        cypher = new RabbitCypher();
        cypher.setupKey(key);
        cypher.crypt(encrypted);
        Assert.assertArrayEquals(msgOriginal, encrypted);

        cypher = new RabbitCypher();
        cypher.setupKey(key2);
        byte[] encrypted2 = msg.clone();
        cypher.crypt(encrypted2);
        Assert.assertThat(encrypted, IsNot.not(IsEqual.equalTo(encrypted2)));
    }

    @Before
    public void setUp() throws Exception {
        cypher = new RabbitCypher();
    }

    @Test(expected=IllegalStateException.class)
    public void testCryptWoKey() throws Exception {
        cypher.crypt(new byte[]{0});
    }

    @Test
    public void testOs2ip() {
        byte[] in = {1, 4, 7, 9};
        byte[] out = {9, 7, 4, 1};
        byte[] test = os2ip(in);
        Assert.assertArrayEquals(out, test);
    }

    private byte[] os2ip(byte ... bytes) {
        List<Byte> test = new ArrayList<Byte>();
        for(byte b : bytes) {
            test.add(b);
        }
        Collections.reverse(test);
        byte[] result = new byte[bytes.length];
        for(int i=0; i<bytes.length; i++) {
            result[i] = test.get(i);
        }

        return result;
    }

    @Test(expected=IllegalStateException.class)
    public void testReset1() throws Exception {
        byte[] key = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] msg = {1, 3, 5, 7, 9, 11, 13, 17, 27, 31, 51};

        cypher.setupKey(key);
        cypher.crypt(msg);

        cypher.reset();
        cypher.crypt(msg);
    }

    @Test
    public void testReset() throws Exception {
        byte[] key = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] msg = {1, 2, 3};

        cypher.setupKey(key);
        byte[] encrypted = msg.clone();
        cypher.crypt(encrypted);

        cypher.reset();

        cypher.setupKey(key);
        byte[] encrypted2 = msg.clone();
        cypher.crypt(encrypted2);

        Assert.assertArrayEquals(encrypted, encrypted2);
    }
}