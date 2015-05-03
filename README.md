Rabbit stream cypher implementation http://tools.ietf.org/rfc/rfc4503.txt
Currently IV usage not implemented.
Usage:

    byte[] msg = "Hello World!".getBytes();
    RabbitCypher cypher = new RabbitCypher();
    cypher.setupKey(key);
    cypher.crypt(msg);
