Rabbit stream cypher implementation http://tools.ietf.org/rfc/rfc4503.txt   
> Rabbit is a stream cipher algorithm that has been designed for high
> performance in software implementations.  Both key setup and
> encryption are very fast, making the algorithm particularly suited
> for all applications where large amounts of data or large numbers of
> data packages have to be encrypted.
Currently IV usage not implemented.   
Usage:

    byte[] msg = "Hello World!".getBytes();
    RabbitCypher cypher = new RabbitCypher();
    cypher.setupKey(key);
    cypher.crypt(msg);

