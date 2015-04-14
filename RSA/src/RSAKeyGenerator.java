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
	public String cipher(BigInteger M) {
		return M.modPow(this.f, this.n).toString(16);
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
			e = generateBigIntInclusive(BigInteger.ONE, z.subtract(BigInteger.ONE)); //1 <= e <= z-1
		} while (!e.gcd(z).equals(BigInteger.ONE));
		assert e.compareTo(z) < 0;
		
		d = e.modInverse(z);
		assert e.multiply(d).mod(z).equals(BigInteger.ONE);
		assert !d.equals(e);
		
		privateKey = new Key(d, P.n);
		publicKey = new Key(e, P.n);
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
				
		// n - 1 = 2^k * m
		final BigInteger o = n.subtract(BigInteger.ONE);
		int k = 0;
		BigInteger m = o.shiftRight(1);
		while (!testOdd(m)) {
			m = m.shiftRight(1);
		}
		while (!o.equals(TWO.pow(k).multiply(m))) {
			k = k + 1;
		}
		//System.out.println("2^" + k + "*" + m.toString());
		boolean RabinMillerCheck = true;
		//chance of failure is (1/4)^k where k is the number of rounds,
		//we can make this really small be choosing a reasonable k.
		for (int s = 0; s < 4000; s++) { //Rabin Miller tests
			BigInteger a = generateBigIntInclusive(BigInteger.ONE, o);
			while(composites.get(n).contains(a)) {
				a = generateBigIntInclusive(BigInteger.ONE, o);
			}
			addPrimeEntry(n, a);
			final BigInteger b = a.modPow(m, n);
			if (b.equals(BigInteger.ONE.mod(n))) {
				RabinMillerCheck = true; //prime
				break;
			}			
			else if (testComposite(b, n, k)) {
				RabinMillerCheck = false; //composite
			}
		}
		if (RabinMillerCheck) {
			assert n.bitLength() >= 512;
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
		while(x.compareTo(a) < 0 || x.compareTo(b) > 0 ) {
			//randomly generate until we hit one between the given intervals
			//it might be better to use a long returned from a Random method.
			x = new BigInteger(b.bitLength(), rnd); 
		}
		return x;
	}
	private boolean testComposite(BigInteger b, final BigInteger n, 
			final int k) {
		for (int i = 0; i < k; i=i+1) {
			if (b.equals(BigInteger.ONE.negate().mod(n))) {
				return false;
			}
			b = b.pow(2);
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
