import java.math.BigInteger;
import java.util.Random;


public class RSAKeyPair {
	private BigInteger privateKey;
	public RSAKeyPair(final int numBitsInKey) {
		final Random bigIntGenerator = new Random();
		privateKey = new BigInteger(numBitsInKey, bigIntGenerator);
	}

}
