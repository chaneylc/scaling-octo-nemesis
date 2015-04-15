
public class RSACrypto {
	
	public static void main(String[] args) {
		final RSAKeyGenerator gen = new RSAKeyGenerator(2048);
		final Key[] K = gen.getK();
		final StringBuilder sb = new StringBuilder();
		final String lineSep = System.getProperty("line.separator");
		sb.append(K[0].n.toString(16));
		sb.append(lineSep);
		sb.append(lineSep);
		sb.append(K[1].f.toString(16)); //private key e
		sb.append(lineSep);
		sb.append(lineSep);
		sb.append(K[0].f.toString(16)); //public key d
		sb.append(lineSep);
		sb.append(lineSep);
		System.out.println(sb);
	}	
}
