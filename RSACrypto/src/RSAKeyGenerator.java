
public class RSAKeyGenerator {
	public RSAKeyGenerator(int numBitsInKey) {
		final StringBuilder sb = new StringBuilder();
	    final String lineSep = System.getProperty("line.separator");
		final RSAKeyPair keypair = new RSAKeyPair(numBitsInKey);
		sb.append(numBitsInKey);
		sb.append(lineSep);
		sb.append(generatePublicKey());
		sb.append(generatePrivateKey());
		System.out.println(sb);
	}

	private RSAKeyPair generateKeyPair() {
		// TODO Auto-generated method stub
		return null;
	}
	
	
}
