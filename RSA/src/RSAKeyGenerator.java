import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

final class ProbablePrime {
	final BigInteger n, p, q;
	public ProbablePrime(BigInteger n, BigInteger p, BigInteger q) {
		this.p = p;
		this.n = n;
		this.q = q;
	}
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		final String lineSep = System.getProperty("line.separator");
		sb.append(this.p);
		sb.append(lineSep);
		sb.append(lineSep);
		sb.append(this.q);
		sb.append(lineSep);
		return sb.toString();
	}
}
final class Key {
	final BigInteger f, n;
	public Key(BigInteger f, BigInteger n) {
		this.f = f;
		this.n = n;
	}
	public BigInteger n() {
		return this.n;
	}
	public BigInteger f() {
		return this.f;
	}
	public String cipher(String m) {
		final byte[] bytes = m.getBytes();
		final BigInteger M = new BigInteger(bytes);
		return M.modPow(this.f, this.n).toString();
	}
}

public class RSAKeyGenerator {
	private final static HashMap<BigInteger, ArrayList<BigInteger>> composites = 
			new HashMap<BigInteger, ArrayList<BigInteger>>();
	private final BigInteger TWO = BigInteger.ONE.add(BigInteger.ONE);
	private final Key privateKey;
	private final Key publicKey;
	public RSAKeyGenerator(int numBitsInKey) {
		assert numBitsInKey >= 1024;
		final StringBuilder sb = new StringBuilder();
	    final String lineSep = System.getProperty("line.separator");
	    final ProbablePrime N = generateBigPrime(numBitsInKey);
	    final Key[] K = generateRSAKeyPair(N);
	    assert K.length == 2;
	    assert K[0].n.equals(N.n) && K[1].n.equals(N.n);
	    this.privateKey = K[0];
	    this.publicKey = K[1];
	}
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		final String lineSep = System.getProperty("line.separator");
		sb.append(this.privateKey.n);
		sb.append(lineSep);
		sb.append(this.privateKey);
		sb.append(lineSep);
		sb.append(this.publicKey);
		sb.append(lineSep);
		return sb.toString();
	}
	public Key[] getK() {
		return new Key[] {this.publicKey, this.privateKey};
	}
	private Key[] generateRSAKeyPair(ProbablePrime P) {
		final Key privateKey, publicKey;
		BigInteger e, d;
		final BigInteger z = 
				(P.p.subtract(BigInteger.ONE)).multiply(P.q.subtract(BigInteger.ONE)); // z = (q-1)(p-1)
		do {
			e = generateBigIntInclusive(BigInteger.ONE, z);
		} while (!e.gcd(z).equals(BigInteger.ONE));
		assert e.compareTo(P.n) < 0;
		
		d = e.modInverse(z);
		assert e.multiply(d).mod(z).equals(BigInteger.ONE);
		assert !d.equals(e);
		
		assert !d.equals(e);
		privateKey = new Key(e, P.n);
		publicKey = new Key(d, P.n);
		return new Key[] {privateKey, publicKey};
	}
	private ProbablePrime generateBigPrime(final int bitLength) {
		assert bitLength >= 1024;
		BigInteger n;
		BigInteger p, q;
		//the next two while loops ensure that the primes generated
		//are at least 512 bits
		do { //check to verify gcd(p,q) == 1
			while ((p = generatePrime(bitLength/2)).bitLength() < 512) {
				p = generatePrime(bitLength/2);
			}
			assert p.bitLength() >= 512;
			while ((q = generatePrime(bitLength/2)).bitLength() < 512) {
				q = generatePrime(bitLength/2);
			}
			assert q.bitLength() >= 512;
			//System.out.println(p + "\n" + q);
			n = p.multiply(q);
			//System.out.println(n.bitLength());
		} while (!p.gcd(q).equals(BigInteger.ONE) ||
				 n.bitLength() < 1024 ||
				 p.equals(q));
		//verify 1024 bits and that p != q
		assert p.gcd(q).equals(BigInteger.ONE);
		assert n.bitLength() >= 1024;
		assert !p.equals(q);
		
		final ProbablePrime P = new ProbablePrime(n, p, q);
		outputPQ(P);
		
		return P;
	}
	private BigInteger generatePrime(final int bitLength) {
		assert bitLength >= 512;	//assure our p q are at least 512 bits as to specification
		final BigInteger n = generateOddBigInt(bitLength);
		assert n.bitLength() >= 512;
		
		final BigInteger m = n.subtract(BigInteger.ONE);
		
		//represent m as 2^s * d
		BigInteger s = BigInteger.ZERO;
		BigInteger d = m;
		while (!testOdd(d)) {
			d = d.shiftRight(1); //divide by factors of two maybe make this smaller
			s = s.add(BigInteger.ONE);
		}
		//System.out.println("2^" + s.toString() + "*" + d.toString());
		boolean RabinMillerCheck = true;
		//System.out.println("Predicted failures: " + possibleRMFailures);
		//chance of failure is (1/4)^k where k is the number of rounds,
		//we can make this really small be choosing a reasonable k.
		for (int k = 0; k < 400; k++) {
			BigInteger a = generateBigIntInclusive(TWO, m);
			while(composites.get(n).contains(a)) {
				a = generateBigIntInclusive(TWO, m);
			}
			addPrimeEntry(n, a);
			//if (a.mod(TWO) == BigInteger.ZERO) {
				//RabinMillerCheck = false; //simple check for evens
				//System.out.println("Is Even");
				//return TWO;
			//}
			if (testComposite(a, d, n, s, m)) {
				RabinMillerCheck = false;
				//System.out.println("Is composite");
				break;
			}
		}
		if (RabinMillerCheck) {
			//System.out.println(n.bitLength());
			assert n.bitLength() >= 512;
			//System.out.println("Probably is prime");
			return n;
		}
		return TWO;
	}
	private BigInteger generateOddBigInt(final int bitLength) {
		final Random rnd = new Random();
		BigInteger x = new BigInteger(bitLength, rnd);
		while( !testOdd(x) || x.bitLength() < bitLength ||
				composites.containsKey(x)) {	
			// loop until we generate an odd;
			// ensure that the bitLength is kept, sometimes rnd will generate somethign smaller
			x = new BigInteger(bitLength, rnd); 
		}
		assert x.bitLength() >= bitLength;
		addPrime(x); //install into hashmap
		return x;
	}
	private BigInteger generateBigIntInclusive(final BigInteger a, final BigInteger b) {
		final Random rnd = new Random();
		BigInteger x = new BigInteger(b.bitLength(), rnd);
		while( !(x.compareTo(a) >= 0 && x.compareTo(b) <= 0) ) {
			//randomly generate until we hit one between the given intervals
			//it might be better to use a long returned from a Random method.
			x = new BigInteger(b.bitLength(), rnd); 
		}
		return x;
	}
	private boolean testComposite(final BigInteger a, final BigInteger d, 
			final BigInteger n, final BigInteger s, final BigInteger m) {
		assert n.subtract(m).equals(BigInteger.ONE);
		BigInteger x  = a.modPow(d, n);
		//System.out.println(x);
		for (int r = 1; BigInteger.valueOf(r).compareTo(s.subtract(BigInteger.ONE)) < 0; r++) {
			/*if (x.modPow(TWO.pow(r).multiply(d),  n).equals(m)) {
				return false;
			}*/
			//System.out.println(r + ": x^2*i = " + x);
			x = x.modPow(TWO, n);
			if (x.equals(BigInteger.ONE)) {
				return true;
			}
			if (x.equals(m)) {
				return false;
			}
		}
		return false;
	}
	protected void addPrime(BigInteger n) {
		composites.put(n, new ArrayList<BigInteger>());
	}
	protected void addPrimeEntry(BigInteger p, BigInteger a) {
		composites.get(p).add(a);
	}
	private boolean testOdd(final BigInteger i) {
		if (i.mod(TWO).equals(BigInteger.ZERO))	return false;
		else return true;
	}
	public void outputPQ(ProbablePrime p) {
		final File f = new File("./PandQ.txt");
		final BufferedWriter bw;
		try {
			bw = new BufferedWriter(new FileWriter(f));
			bw.write(p.toString());
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		} 
	}
	
}
